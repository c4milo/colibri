//! The stream table of one h2 connection: one record per stream that holds a slot in core's slot
//! pool (decision 14). The pool keeps the live records and one watermark per identifier parity. An
//! identifier at or below its parity's watermark with no record is closed, whether its stream
//! closed here or by the implicit close of RFC 9113 §5.1.1, and nothing records it (invariant 13).
//! This file adds the h2 rules: which endpoint opens which stream (§5.1, §5.1.1), the concurrency
//! limit (§5.1.2), the two GOAWAY limits (§6.8, invariant 16) and the settings sweep (§6.9.2,
//! invariant 15). The connection that calls it is decision 39's.
//!
//! §5.1 opens a stream on a HEADERS a client sends or a server receives, and a server's own stream
//! starts with a PUSH_PROMISE, which decision 17 refuses. So a server holds only the streams its
//! peer opens (`open_peer`), and a client only its own (`open_local`). A client records a promised
//! stream with `reserve_peer` and resets it (decision 17). `streams_open.zig` holds the three with
//! their check order, and `streams_goaway.zig` the GOAWAY values with theirs.
//!
//! The state machine of `stream.zig` decides every frame. `lookup` names what a peer frame's
//! identifier finds, and `transition` applies a verdict of `.state`. A stream that closes leaves
//! the pool at once, except one closed by a RST_STREAM colibri sent: §5.1 says frames can keep
//! arriving for it and must be discarded, and the record's `closed` tells the state machine so.
//! That record stays until an open needs its slot, and the record that closed first goes first.
//! `sequence` counts the closes, so the order needs no clock (non-negotiable 3).
//!
//! A refused stream, a promised stream and a dropped record are streams colibri reset and holds no
//! record for. Each raises `highest_forgotten_reset_id` of its parity, and `lookup` discards frames
//! on every closed identifier at or below it. The kept records hold that value low, so most closed
//! streams colibri did not reset keep their STREAM_CLOSED error.
//!
//! `peer_active` and `local_active` count the streams each endpoint opened that are open or
//! half-closed (§5.1.2), asserted after every change. One function checks a peer's value, once,
//! before anything moves (invariant 7): `adjust_send_windows` keeps every send window colibri keeps
//! at most `window_max`, or returns `error.Overflow` (§6.9.2). Every assertion reads colibri's own
//! bookkeeping, never a peer's value (invariant 24).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const Role = @import("../role.zig").Role;
const stream = @import("stream.zig");
const window = @import("../window.zig");
const open = @import("streams_open.zig");
const goaway = @import("streams_goaway.zig");
const window_sweep = @import("streams_window.zig");

/// The record of one stream, and the pool's entry. Every field but `id` has a default because the
/// pool writes a fresh entry whole (invariant 5). `open_peer` and `open_local` set the state, the
/// initiator and both windows.
pub const Stream = struct {
    /// The stream identifier (RFC 9113 §5.1.1). The pool keys every protocol's streams by a u64,
    /// and an h2 identifier is at most `stream_id_max`.
    id: u64,
    /// The state of RFC 9113 §5.1.
    state: stream.State = .idle,
    /// How the stream closed. Set exactly when `state` is closed.
    closed: ?stream.Closed = null,
    /// The space the peer advertised for the DATA colibri sends on this stream (RFC 9113 §6.9.1).
    send_window: window.Window = .{ .available = 0 },
    /// The space colibri advertised for the DATA the peer sends on this stream.
    receive: window.Receiver = .{ .window = .{ .available = 0 }, .unreleased = 0, .released = 0 },
    /// Whether the peer opened the stream: its identifier has the peer's parity (RFC 9113 §5.1.1).
    peer_initiated: bool = false,
    /// The content-length the message declared, which the connection compares with the DATA
    /// octets received (RFC 9113 §8.1.1). This table only stores it.
    content_length: ?u64 = null,
    /// The DATA payload octets received on the stream, for the same comparison. This table only
    /// stores it.
    data_received_len: u64 = 0,
    /// The value of `Streams.sequence` when the stream closed. The lowest is the oldest.
    closed_at: u64 = 0,
};

/// The slot pool the table keeps its records in: `concurrent_streams_max` slots, the
/// SETTINGS_MAX_CONCURRENT_STREAMS colibri advertises, and one watermark per parity.
const Pool = core.Pool(Stream, constants.concurrent_streams_max, constants.stream_id_parity_count, open.class_of);

/// What a peer frame's stream identifier finds in the table.
pub const Lookup = union(enum) {
    /// A record the table holds: an open or half-closed stream, or a closed stream whose record
    /// the table still keeps. The state machine decides a frame on it from `state` and `closed`.
    live: *Stream,
    /// An identifier above its parity's watermark, whose stream is idle (RFC 9113 §5.1). The
    /// payload is true when the identifier has the peer's parity, and it is the state machine's
    /// `peer_initiated`.
    idle: bool,
    /// An identifier at or below `highest_forgotten_reset_id` for its parity: colibri reset the
    /// stream and the table dropped the record. RFC 9113 §5.1 discards the frames that arrive
    /// after a RST_STREAM colibri sent, because the peer sent them before it read the reset.
    reset_and_dropped,
    /// An identifier at or below its parity's watermark with no record and no reset to its name:
    /// the peer never opened it, which RFC 9113 §5.1.1 closes implicitly, or it closed long enough
    /// ago that the table dropped the record. §5.1 lets an endpoint treat any frame but PRIORITY
    /// on a closed stream as a connection error of PROTOCOL_ERROR once a signal says the peer has
    /// seen the close, and a later identifier is such a signal.
    forgotten,
};

/// Why `open_peer` refused a stream. `streams_open.zig` names the error each is.
pub const OpenPeerError = open.OpenPeerError;

/// Why `open_local` refused a stream. `streams_open.zig` names what each means.
pub const OpenLocalError = open.OpenLocalError;

/// Why `reserve_peer` refused a promised stream. `streams_open.zig` names the error.
pub const ReservePeerError = open.ReservePeerError;

/// The streams of one connection, in storage the caller places (decision 35).
pub const Streams = struct {
    /// The records, and one watermark per parity.
    pool: Pool,
    /// This endpoint's role, which names the parity each endpoint opens (RFC 9113 §5.1.1).
    role: Role,
    /// The identifier `open_local` opens next: `stream_id_client_first` or `stream_id_server_first`
    /// at `init`, then `stream_id_step` more after each open. Past `stream_id_max`, none is left.
    next_local_id: u32,
    /// Streams the peer opened that are open or half-closed (RFC 9113 §5.1.2).
    peer_active: u32,
    /// Streams colibri opened that are open or half-closed (RFC 9113 §5.1.2).
    local_active: u32,
    /// The highest identifier `open_peer` opened, or 0 before the first. A GOAWAY colibri sends
    /// never names a lower one (RFC 9113 §8.7).
    highest_peer_opened_id: u32,
    /// For each parity, the highest identifier of a stream colibri reset and holds no record for,
    /// or null when there is none. It never decreases.
    highest_forgotten_reset_id: [constants.stream_id_parity_count]?u32,
    /// The last stream identifier of the latest GOAWAY colibri sent, or null before the first.
    goaway_sent_last_id: ?u32,
    /// The last stream identifier of the latest GOAWAY the peer sent, or null before the first.
    goaway_received_last_id: ?u32,
    /// A counter advanced by one on every close, which orders closes.
    sequence: u64,

    /// Empties the table for an endpoint in `role`.
    pub fn init(streams: *Streams, role: Role) void {
        streams.pool.init();
        streams.role = role;
        // RFC 9113 §5.1.1: a client opens odd identifiers and a server even ones.
        streams.next_local_id = open.first_stream_id(role);
        streams.peer_active = 0;
        streams.local_active = 0;
        streams.highest_peer_opened_id = 0;
        streams.highest_forgotten_reset_id = @splat(null);
        streams.goaway_sent_last_id = null;
        streams.goaway_received_last_id = null;
        streams.sequence = 0;
        assert(streams.len() == 0);
        assert(!open.initiated_by_peer(streams, streams.next_local_id));
    }

    /// Records in the pool: the open and half-closed streams, and the streams closed by a
    /// RST_STREAM colibri sent that the pool still holds.
    pub fn len(streams: *const Streams) u32 {
        open.assert_counts(streams);
        return streams.pool.len();
    }

    /// The records in the pool, in slot order, for a sweep over every one (invariant 15).
    pub fn iterator(streams: *Streams) Pool.Iterator {
        open.assert_counts(streams);
        return streams.pool.iterator();
    }

    /// What the identifier of a frame the peer sent finds. The frame codec refused identifier 0,
    /// and 31 bits hold at most `stream_id_max`. `.live` is valid until the record leaves the pool.
    /// A peer identifier above `goaway_sent_last_id` is idle here, and ignored (RFC 9113 §6.8).
    pub fn lookup(streams: *Streams, id: u32) Lookup {
        assert(id != constants.connection_stream_id);
        assert(id <= constants.stream_id_max);
        if (streams.pool.get(id)) |record| return .{ .live = record };
        if (streams.pool.is_above_watermark(id)) return .{ .idle = open.initiated_by_peer(streams, id) };
        return if (was_reset_and_dropped(streams, id)) .reset_and_dropped else .forgotten;
    }

    /// Opens a stream, at a server, for a HEADERS the peer sent on an idle identifier, with a send
    /// window of the peer's SETTINGS_INITIAL_WINDOW_SIZE. See `streams_open.zig`.
    pub fn open_peer(streams: *Streams, id: u32, initial_send_window: u32) OpenPeerError!*Stream {
        return open.open_peer(streams, id, initial_send_window);
    }

    /// Opens the next stream colibri initiates, under the peer's SETTINGS_MAX_CONCURRENT_STREAMS
    /// (null is unlimited) and with a send window of `initial_send_window`, the peer's
    /// SETTINGS_INITIAL_WINDOW_SIZE. A client's operation. See `streams_open.zig`.
    pub fn open_local(
        streams: *Streams,
        peer_max_concurrent_streams: ?u32,
        initial_send_window: u32,
    ) OpenLocalError!*Stream {
        return open.open_local(streams, peer_max_concurrent_streams, initial_send_window);
    }

    /// Records the stream a PUSH_PROMISE the peer sent promises, which colibri resets. A client's
    /// operation. See `streams_open.zig`.
    pub fn reserve_peer(streams: *Streams, id: u32) ReservePeerError!void {
        return open.reserve_peer(streams, id);
    }

    /// Applies the state machine's verdict of `.state` on a frame to `record`, which the pool
    /// holds. `direction`, `kind` and `end_stream` are the frame's, as the state machine saw them.
    /// Any other verdict is the connection's to act on. When the stream closes, `closed` names how,
    /// its initiator's active count drops by one and `closed_at` takes `sequence`. The record stays
    /// in the pool, where `lookup` finds it until an open needs its slot.
    pub fn transition(
        streams: *Streams,
        record: *Stream,
        verdict: stream.Verdict,
        direction: stream.Direction,
        kind: stream.Kind,
        end_stream: bool,
    ) void {
        assert(verdict == .state);
        assert(streams.pool.get(record.id) == record);
        assert(record.peer_initiated == open.initiated_by_peer(streams, record.id));
        // The table opens every record open, because decision 17 refuses push and so no stream is
        // ever reserved, and the state machine gives a closed stream no verdict of `.state`.
        assert(is_active(record.state));
        assert(verdict.state == .closed or is_active(verdict.state));
        record.state = verdict.state;
        if (verdict.state == .closed) streams.close(record, stream.closed_kind_after(direction, kind, end_stream));
        open.assert_counts(streams);
    }

    /// Adds `delta`, the change in the peer's SETTINGS_INITIAL_WINDOW_SIZE, to the send window of
    /// every stream colibri may still send DATA on (RFC 9113 §6.9.2). See `streams_window.zig`.
    pub fn adjust_send_windows(streams: *Streams, delta: i64) error{Overflow}!void {
        return window_sweep.adjust_send_windows(streams, delta);
    }

    /// Records the last stream identifier of a GOAWAY colibri sends. See `streams_goaway.zig`.
    pub fn record_goaway_sent(streams: *Streams, last_stream_id: u32) void {
        goaway.record_goaway_sent(streams, last_stream_id);
    }

    /// Records the last stream identifier of a GOAWAY the peer sent. See `streams_goaway.zig`.
    pub fn record_goaway_received(streams: *Streams, last_stream_id: u32) error{LastStreamIdIncreased}!void {
        return goaway.record_goaway_received(streams, last_stream_id);
    }

    /// The last stream identifier colibri puts in its next GOAWAY. See `streams_goaway.zig`.
    pub fn last_peer_stream_id(streams: *const Streams) u32 {
        return goaway.last_peer_stream_id(streams);
    }

    /// Closes `record`, whose state is now closed, by `closed`.
    fn close(streams: *Streams, record: *Stream, closed: ?stream.Closed) void {
        assert(closed != null);
        assert(record.state == .closed and record.closed == null);
        record.closed = closed;
        if (record.peer_initiated) {
            assert(streams.peer_active > 0);
            streams.peer_active -= 1;
        } else {
            assert(streams.local_active > 0);
            streams.local_active -= 1;
        }
        record.closed_at = streams.sequence;
        streams.sequence += 1;
        // The record stays in the pool: RFC 9113 §5.1 decides a frame on a closed stream by how the
        // stream closed, and the state machine reads the record to do it. `streams_open.zig` drops
        // the oldest closed record when an open needs the slot.
    }
};

/// Whether an identifier at or below its watermark with no record names a stream colibri reset and
/// the table dropped, as `Lookup.reset_and_dropped` describes it.
fn was_reset_and_dropped(streams: *const Streams, id: u32) bool {
    assert(!streams.pool.is_above_watermark(id));
    const highest = streams.highest_forgotten_reset_id[open.class_of(id)] orelse return false;
    return id <= highest;
}

/// Whether a stream in `state` counts toward SETTINGS_MAX_CONCURRENT_STREAMS: open and both
/// half-closed states do, and reserved ones do not (RFC 9113 §5.1.2).
fn is_active(state: stream.State) bool {
    return switch (state) {
        .open, .half_closed_local, .half_closed_remote => true,
        .idle, .reserved_local, .reserved_remote, .closed => false,
    };
}

// Tests. `streams_open.zig` tests the opens and `streams_goaway.zig` the GOAWAY values; these test
// what the table does with its records.

const testing = std.testing;

/// The table the tests run in, placed outside any stack frame. Test-only, and
/// `streams_window.zig` runs its tests on it too.
pub var test_streams: Streams = undefined;

/// The peer's SETTINGS_INITIAL_WINDOW_SIZE in the tests. Test-only.
pub const test_send_window: u32 = 1000;

/// Asks the state machine for its verdict on a frame on `record`, and applies it. Test-only.
pub fn apply_frame(record: *Stream, direction: stream.Direction, kind: stream.Kind, end_stream: bool) !void {
    const role = test_streams.role;
    const verdict = switch (direction) {
        .receive => stream.on_receive(record.state, record.closed, kind, end_stream, role, record.peer_initiated),
        .send => stream.on_send(record.state, record.closed, kind, end_stream, role, record.peer_initiated),
    };
    try testing.expect(verdict == .state);
    test_streams.transition(record, verdict, direction, kind, end_stream);
}

/// The record `lookup` finds for `id`, which must be live. Test-only.
fn expect_live(id: u32) !*Stream {
    const found = test_streams.lookup(id);
    try testing.expect(found == .live);
    return found.live;
}

test "init: a client opens identifier 1 first and a server 2, and each table starts empty" {
    for ([_]Role{ .client, .server }, [_]u32{ 1, 2 }) |role, first| {
        test_streams.init(role);
        try testing.expectEqual(first, test_streams.next_local_id);
        try testing.expectEqual(0, test_streams.len());
        try testing.expectEqual(0, test_streams.peer_active + test_streams.local_active);
        try testing.expectEqual(0, test_streams.highest_peer_opened_id);
        try testing.expectEqual([_]?u32{ null, null }, test_streams.highest_forgotten_reset_id);
        try testing.expectEqual(null, test_streams.goaway_sent_last_id);
        try testing.expectEqual(null, test_streams.goaway_received_last_id);
    }
}

test "lookup at a server: 1 is live, 2 idle and its own, 7 idle and the peer's, and 3 closed once it closes" {
    test_streams.init(.server);
    for ([_]u32{ 1, 3, 5 }) |id| _ = try test_streams.open_peer(id, test_send_window);
    try testing.expectEqual(1, (try expect_live(1)).id);
    try testing.expectEqual(Lookup{ .idle = false }, test_streams.lookup(2));
    try testing.expectEqual(Lookup{ .idle = true }, test_streams.lookup(7));
    const record = try expect_live(3);
    try apply_frame(record, .receive, .data, true);
    try apply_frame(record, .send, .data, true);
    const closed = try expect_live(3);
    try testing.expectEqual(stream.State.closed, closed.state);
    try testing.expectEqual(stream.Closed.end_stream, closed.closed.?);
    try testing.expectEqual(1, (try expect_live(1)).id);
}

test "lookup: opening 9 closes the skipped 7 by the implicit close of §5.1.1, and a client reads parity the other way" {
    test_streams.init(.server);
    _ = try test_streams.open_peer(9, test_send_window);
    try testing.expectEqual(Lookup.forgotten, test_streams.lookup(7));
    try testing.expectEqual(Lookup.forgotten, test_streams.lookup(1));
    try testing.expectEqual(Lookup{ .idle = true }, test_streams.lookup(11));
    test_streams.init(.client);
    try testing.expectEqual(Lookup{ .idle = true }, test_streams.lookup(2));
    try testing.expectEqual(Lookup{ .idle = false }, test_streams.lookup(1));
    const local = try test_streams.open_local(null, test_send_window);
    try testing.expectEqual(local, try expect_live(1));
    try testing.expectEqual(Lookup{ .idle = false }, test_streams.lookup(3));
}

test "http2/5.1/11 to /13: END_STREAM received, then sent, closes the stream and keeps its record" {
    test_streams.init(.server);
    const record = try test_streams.open_peer(1, test_send_window);
    try apply_frame(record, .receive, .data, true);
    try testing.expectEqual(stream.State.half_closed_remote, record.state);
    try testing.expectEqual(null, record.closed);
    try testing.expectEqual(1, test_streams.peer_active);
    try testing.expectEqual(1, test_streams.len());
    try apply_frame(record, .send, .data, true);
    try testing.expectEqual(0, test_streams.peer_active);
    try testing.expectEqual(1, test_streams.len());
    const closed = try expect_live(1);
    try testing.expectEqual(stream.Closed.end_stream, closed.closed.?);
    const late = stream.on_receive(closed.state, closed.closed, .data, false, .server, true);
    try testing.expectEqual(stream.stream_closed_connection_error, late);
}

test "http2/5.1.1/2: an identifier the peer never opened, below the watermark, is forgotten and not closed" {
    test_streams.init(.server);
    const record = try test_streams.open_peer(5, test_send_window);
    try apply_frame(record, .receive, .data, true);
    try apply_frame(record, .send, .data, true);
    // http2/5.1/12 sends a second HEADERS on the stream that closed: the record answers it.
    const closed = try expect_live(5);
    try testing.expectEqual(stream.State.closed, closed.state);
    try testing.expectEqual(stream.Closed.end_stream, closed.closed.?);
    // http2/5.1.1/2 sends HEADERS on the lower identifier 3, which was never opened.
    try testing.expectEqual(Lookup.forgotten, test_streams.lookup(3));
    try testing.expectEqual(Lookup.forgotten, test_streams.lookup(1));
}

test "http2/5.1/8 to /10: a RST_STREAM received closes a half-closed stream, and a late HEADERS is STREAM_CLOSED" {
    test_streams.init(.server);
    const record = try test_streams.open_peer(1, test_send_window);
    try apply_frame(record, .receive, .data, true);
    try apply_frame(record, .receive, .rst_stream, false);
    try testing.expectEqual(0, test_streams.peer_active);
    try testing.expectEqual(1, test_streams.len());
    const closed = try expect_live(1);
    try testing.expectEqual(stream.Closed.rst_stream_received, closed.closed.?);
    const late = stream.on_receive(closed.state, closed.closed, .headers, false, .server, true);
    try testing.expectEqual(stream.stream_closed_connection_error, late);
}

test "a RST_STREAM colibri sends closes the stream and keeps its record, which discards late frames (§5.1)" {
    test_streams.init(.server);
    const first = try test_streams.open_peer(1, test_send_window);
    const second = try test_streams.open_peer(3, test_send_window);
    try apply_frame(second, .send, .rst_stream, false);
    try testing.expectEqual(1, test_streams.peer_active);
    try testing.expectEqual(2, test_streams.len());
    const kept = try expect_live(3);
    try testing.expectEqual(second, kept);
    try testing.expectEqual(stream.State.closed, kept.state);
    try testing.expectEqual(stream.Closed.rst_stream_sent, kept.closed.?);
    const late = stream.on_receive(kept.state, kept.closed, .data, false, .server, kept.peer_initiated);
    try testing.expectEqual(stream.Verdict.ignore, late);
    try apply_frame(first, .send, .rst_stream, false);
    try testing.expect(second.closed_at < first.closed_at);
    try testing.expectEqual(0, test_streams.peer_active);
    try testing.expectEqual(2, test_streams.len());
}

test "a RST_STREAM colibri sends on a half-closed stream lowers the active count at a server and a client, as END_STREAM does" {
    test_streams.init(.server);
    const peer = try test_streams.open_peer(1, test_send_window);
    try apply_frame(peer, .receive, .data, true);
    try testing.expectEqual(stream.State.half_closed_remote, peer.state);
    try testing.expectEqual(1, test_streams.peer_active);
    try apply_frame(peer, .send, .rst_stream, false);
    try testing.expectEqual(0, test_streams.peer_active);
    try testing.expectEqual(1, test_streams.len());
    test_streams.init(.client);
    const local = try test_streams.open_local(null, test_send_window);
    try apply_frame(local, .receive, .window_update, false);
    try apply_frame(local, .send, .data, true);
    try testing.expectEqual(stream.State.half_closed_local, local.state);
    try testing.expectEqual(1, test_streams.local_active);
    const other = try test_streams.open_local(null, test_send_window);
    try apply_frame(other, .send, .headers, true);
    try apply_frame(local, .send, .rst_stream, false);
    try testing.expectEqual(1, test_streams.local_active);
    try apply_frame(other, .receive, .data, true);
    try testing.expectEqual(0, test_streams.local_active);
    try testing.expectEqual(0, test_streams.peer_active);
    try testing.expectEqual(2, test_streams.len());
}

test "the iterator visits every record the pool holds, the closed streams included" {
    test_streams.init(.server);
    for ([_]u32{ 1, 3, 5 }) |id| _ = try test_streams.open_peer(id, test_send_window);
    try apply_frame(try expect_live(3), .send, .rst_stream, false);
    try apply_frame(try expect_live(5), .receive, .rst_stream, false);
    var visited: [3]u64 = @splat(0);
    var count: u32 = 0;
    var records = test_streams.iterator();
    while (records.next()) |record| : (count += 1) visited[count] = record.id;
    try testing.expectEqualSlices(u64, &.{ 1, 3, 5 }, &visited);
    try testing.expectEqual(3, test_streams.len());
    try testing.expectEqual(1, test_streams.peer_active);
}
