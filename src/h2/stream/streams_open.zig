//! Opening and reserving streams in the table of `streams.zig`. `open_peer` opens a stream the peer
//! opens with HEADERS, at a server. `open_local` opens a stream colibri opens, at a client.
//! `reserve_peer` records the stream a PUSH_PROMISE promises, at a client, which colibri resets
//! (decision 17). An open gives the record the state open, a send window of the peer's
//! SETTINGS_INITIAL_WINDOW_SIZE, a receive window of `window_initial`, and one more in its
//! initiator's active count. An open into a full pool first drops the oldest record closed by a
//! RST_STREAM colibri sent. This serves decision 14 and invariants 13 and 16.
//!
//! Each operation asserts its role, because §5.1 gives it to one role and the connection calls it
//! only after the state machine permits the frame. `open_peer` checks in this order (invariant 7):
//!   1. the contract, asserted: colibri is the server, and the identifier is not 0, which the
//!      frame codec refused, and at most `stream_id_max`, which its 31 bits make it;
//!   2. the identifier has the peer's parity, or `error.WrongParity` (§5.1.1, §5.1);
//!   3. the identifier is above its parity's watermark, or `error.IdentifierNotIncreasing`
//!      (§5.1.1);
//!   4. the identifier is not above a GOAWAY colibri sent, or `error.AfterGoaway` (§6.8), and the
//!      watermark stays where it was;
//!   5. `peer_active` is below `concurrent_streams_max`, or `error.Refused` (§5.1.2, §8.7), which
//!      moves the watermark to the identifier, because the peer used it (§5.1.1);
//!   6. the pool has a free slot after the drop, asserted: the pool holds `concurrent_streams_max`
//!      records and a server opens none of its own, so a full pool below step 5's limit holds a
//!      closed record to drop.
//!
//! `open_local` checks in this order:
//!   1. the contract, asserted: colibri is the client;
//!   2. the peer has sent no GOAWAY, or `error.AfterGoawayReceived` (§6.8);
//!   3. an identifier is left, or `error.IdentifiersExhausted` (§5.1.1);
//!   4. `local_active` is below the peer's SETTINGS_MAX_CONCURRENT_STREAMS, or
//!      `error.PeerLimitReached` (§5.1.2);
//!   5. the pool has a free slot after the drop, or `error.Full`.
//!
//! The slot machinery those steps use — the drop of the oldest closed record and the two markers
//! an identifier without a record is read by — is `streams_slot.zig`.
//!
//! `reserve_peer` asserts the client role and an even identifier other than 0, which the frame
//! codec checked (§6.6), then checks that the identifier is above the even watermark, or
//! `error.IdentifierNotIncreasing` (§5.1.1, §6.6). A refusal at step 5, a reservation and a
//! dropped record each raise `highest_forgotten_reset_id` of the identifier's parity.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Role = @import("../role.zig").Role;
const stream = @import("stream.zig");
const window = @import("../window.zig");
const table = @import("streams.zig");
const goaway = @import("streams_goaway.zig");
const slot = @import("streams_slot.zig");

const Stream = table.Stream;
const Streams = table.Streams;

/// Why `open_peer` refused a peer's HEADERS on an idle identifier.
pub const OpenPeerError = error{
    /// The identifier is at or below the highest the peer opened: a connection error of
    /// PROTOCOL_ERROR (RFC 9113 §5.1.1).
    IdentifierNotIncreasing,
    /// The identifier has this endpoint's parity: a connection error of PROTOCOL_ERROR (RFC 9113
    /// §5.1.1, §5.1).
    WrongParity,
    /// Opening the stream would pass the limit colibri advertised: a stream error of
    /// REFUSED_STREAM (RFC 9113 §5.1.2, §8.7).
    Refused,
    /// colibri has sent a GOAWAY whose last stream identifier is below this one: the frame is
    /// ignored, not an error (RFC 9113 §6.8).
    AfterGoaway,
};

/// Why `open_local` refused to open a stream. Each is reported to the caller, and no frame is
/// sent.
pub const OpenLocalError = error{
    /// The streams colibri opened that are open or half-closed have reached the peer's
    /// SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §5.1.2). One may open once one of them closes.
    PeerLimitReached,
    /// The peer has sent a GOAWAY (RFC 9113 §6.8). A new stream needs a new connection.
    AfterGoawayReceived,
    /// colibri has opened its largest identifier (RFC 9113 §5.1.1). A new stream needs a new
    /// connection.
    IdentifiersExhausted,
    /// Every slot holds an open or half-closed stream. One may open once one of them closes.
    Full,
};

/// Why `reserve_peer` refused the promised stream of a PUSH_PROMISE.
pub const ReservePeerError = error{
    /// The promised identifier is at or below the highest the server opened or reserved, so its
    /// stream is not idle: a connection error of PROTOCOL_ERROR (RFC 9113 §5.1.1, §6.6).
    IdentifierNotIncreasing,
};

/// Opens a stream for a HEADERS the peer sent on the idle identifier `id`, with a send window of
/// `initial_send_window`. The header gives the check order. The state machine has already found
/// that the identifier's stream may receive HEADERS (RFC 9113 §5.1).
pub fn open_peer(streams: *Streams, id: u32, initial_send_window: u32) OpenPeerError!*Stream {
    // RFC 9113 §5.1: only a server opens a stream on a HEADERS it receives.
    assert(streams.role == .server);
    assert(id != constants.connection_stream_id);
    assert(id <= constants.stream_id_max);
    assert(initial_send_window <= constants.window_max);
    assert_counts(streams);
    // RFC 9113 §5.1.1: a client opens odd identifiers and a server even ones, so a HEADERS on this
    // endpoint's parity opens nothing, and §5.1 makes it a connection error of PROTOCOL_ERROR.
    if (!initiated_by_peer(streams, id)) return error.WrongParity;
    // RFC 9113 §5.1.1: a new stream's identifier MUST be greater than all the initiator opened,
    // and an unexpected identifier is a connection error of PROTOCOL_ERROR.
    if (!streams.pool.is_above_watermark(id)) return error.IdentifierNotIncreasing;
    // RFC 9113 §6.8: once the GOAWAY is sent, its sender ignores frames on streams the receiver
    // initiated above the last stream identifier.
    if (goaway.is_above_goaway_sent(streams, id)) return error.AfterGoaway;
    if (streams.peer_active == constants.concurrent_streams_max) {
        slot.forget_reset(streams, id);
        // RFC 9113 §5.1.2: a HEADERS that exceeds the advertised concurrent stream limit is a
        // stream error of PROTOCOL_ERROR or REFUSED_STREAM, and RFC 9113 §8.7 makes REFUSED_STREAM
        // the code for a stream no application saw.
        return error.Refused;
    }
    const slot_free = slot.ensure_free_slot(streams);
    assert(slot_free);
    const record = streams.pool.open(id) catch unreachable;
    fill(streams, record, true, initial_send_window);
    streams.peer_active += 1;
    streams.highest_peer_opened_id = id;
    assert_counts(streams);
    assert(streams.pool.watermark[class_of(id)] == id);
    return record;
}

/// Opens the next stream colibri initiates, with a send window of `initial_send_window`.
/// `peer_max_concurrent_streams` is the peer's SETTINGS_MAX_CONCURRENT_STREAMS, null while the
/// peer has set none. The header gives the check order.
pub fn open_local(
    streams: *Streams,
    peer_max_concurrent_streams: ?u32,
    initial_send_window: u32,
) OpenLocalError!*Stream {
    // RFC 9113 §5.1: a client opens a stream with the HEADERS it sends, and a server's own stream
    // starts with a PUSH_PROMISE, which decision 17 refuses.
    assert(streams.role == .client);
    assert(initial_send_window <= constants.window_max);
    assert(!initiated_by_peer(streams, streams.next_local_id));
    assert_counts(streams);
    // RFC 9113 §6.8: receivers of a GOAWAY frame MUST NOT open additional streams.
    if (streams.goaway_received_last_id != null) return error.AfterGoawayReceived;
    // RFC 9113 §5.1.1: identifiers cannot be reused, and an endpoint that cannot establish a new
    // identifier needs a new connection.
    if (streams.next_local_id > constants.stream_id_max) return error.IdentifiersExhausted;
    // RFC 9113 §5.1.2: endpoints MUST NOT exceed the limit set by their peer. The initial value
    // is unlimited (§6.5.2), and a peer may lower the limit below the streams already open.
    if (at_limit(streams.local_active, peer_max_concurrent_streams)) return error.PeerLimitReached;
    if (!slot.ensure_free_slot(streams)) return error.Full;
    const record = streams.pool.open(streams.next_local_id) catch unreachable;
    fill(streams, record, false, initial_send_window);
    streams.local_active += 1;
    // RFC 9113 §5.1.1: the next identifier is numerically greater than every one opened.
    streams.next_local_id += constants.stream_id_step;
    assert_counts(streams);
    return record;
}

/// Records the stream `id` that a PUSH_PROMISE the peer sent promises. §5.1 moves it from idle to
/// reserved (remote), and the RST_STREAM the connection sends at once moves it to closed (decision
/// 17). It takes no slot and no active count (§5.1.2 counts no reserved stream), and `lookup`
/// finds it closed by `rst_stream_sent`. The header gives the check order.
pub fn reserve_peer(streams: *Streams, id: u32) ReservePeerError!void {
    // RFC 9113 §8.4: a client cannot push, so only a client receives a PUSH_PROMISE.
    assert(streams.role == .client);
    assert(id != constants.connection_stream_id and id <= constants.stream_id_max);
    assert(initiated_by_peer(streams, id));
    assert_counts(streams);
    // RFC 9113 §6.6: a PUSH_PROMISE that promises a stream not in the idle state is a connection
    // error of PROTOCOL_ERROR, and §5.1.1: the identifier MUST be greater than every one the
    // server opened or reserved.
    if (!streams.pool.is_above_watermark(id)) return error.IdentifierNotIncreasing;
    slot.forget_reset(streams, id);
    assert_counts(streams);
}

/// The identifier class of a stream identifier in the pool: its parity, 1 for the odd identifiers
/// a client opens and 0 for the even ones a server opens (RFC 9113 §5.1.1).
pub fn class_of(id: u64) u32 {
    return @intCast(id % constants.stream_id_parity_count);
}

/// The first identifier an endpoint in `role` opens (RFC 9113 §5.1.1).
pub fn first_stream_id(role: Role) u32 {
    return if (role.initiates_odd()) constants.stream_id_client_first else constants.stream_id_server_first;
}

/// Whether `id` has the parity of the identifiers the peer opens (RFC 9113 §5.1.1).
pub fn initiated_by_peer(streams: *const Streams, id: u64) bool {
    return class_of(id) == class_of(first_stream_id(streams.role.peer()));
}

/// Each active count is within the pool's capacity and belongs to the one endpoint that opens
/// streams in this role, and together they count at most the records the pool holds.
pub fn assert_counts(streams: *const Streams) void {
    assert(streams.peer_active <= constants.concurrent_streams_max);
    assert(streams.local_active <= constants.concurrent_streams_max);
    assert(streams.peer_active + streams.local_active <= streams.pool.len());
    assert(streams.role == .server or streams.peer_active == 0);
    assert(streams.role == .client or streams.local_active == 0);
}

/// Gives a fresh record the state open, its initiator and both windows.
fn fill(streams: *const Streams, record: *Stream, peer_initiated: bool, initial_send_window: u32) void {
    assert(record.state == .idle and record.closed == null);
    assert(peer_initiated == initiated_by_peer(streams, record.id));
    record.state = .open;
    record.peer_initiated = peer_initiated;
    record.send_window = window.Window.init(initial_send_window);
    record.receive = window.Receiver.init(constants.window_initial);
}

/// Whether `active` streams have reached `limit`. Null is unlimited.
fn at_limit(active: u32, limit: ?u32) bool {
    const value = limit orelse return false;
    return active >= value;
}

// Tests.

const testing = std.testing;
const Lookup = table.Lookup;

/// The table the tests run in, placed outside any stack frame. Test-only, and
/// `streams_slot.zig` runs its tests on it too.
pub var test_table: Streams = undefined;

/// The peer's SETTINGS_INITIAL_WINDOW_SIZE in the tests. Test-only.
pub const test_send_window: u32 = 1000;

/// The `index`th identifier a client opens, counting from 0. Test-only.
pub fn client_id(index: u32) u32 {
    return constants.stream_id_client_first + constants.stream_id_step * index;
}

/// The record `lookup` finds for `id`, which must be live. Test-only.
pub fn expect_live(id: u32) !*Stream {
    const found = test_table.lookup(id);
    try testing.expect(found == .live);
    return found.live;
}

/// Asks the state machine for its verdict on a frame on `record`, and applies it. Test-only.
pub fn apply_frame(record: *Stream, direction: stream.Direction, kind: stream.Kind, end_stream: bool) !void {
    const role = test_table.role;
    const verdict = switch (direction) {
        .receive => stream.on_receive(record.state, record.closed, kind, end_stream, role, record.peer_initiated),
        .send => stream.on_send(record.state, record.closed, kind, end_stream, role, record.peer_initiated),
    };
    try testing.expect(verdict == .state);
    test_table.transition(record, verdict, direction, kind, end_stream);
}

/// Closes `record` with a RST_STREAM colibri sends, as the state machine decides it. Test-only.
pub fn reset(record: *Stream) !void {
    try apply_frame(record, .send, .rst_stream, false);
    try testing.expectEqual(stream.Closed.rst_stream_sent, record.closed.?);
}

/// Opens every slot with a stream the client opens, at a server. Test-only.
pub fn fill_with_peer_streams() !void {
    for (0..constants.concurrent_streams_max) |index| {
        _ = try test_table.open_peer(client_id(@intCast(index)), test_send_window);
    }
    try testing.expectEqual(constants.concurrent_streams_max, test_table.len());
}

test "http2/5.1.1/2: a server opens peer streams 1, 3 and 5, then refuses 3 and 5 as IdentifierNotIncreasing" {
    test_table.init(.server);
    for ([_]u32{ 1, 3, 5 }, 1..) |id, count| {
        const record = try test_table.open_peer(id, test_send_window);
        try testing.expectEqual(id, record.id);
        try testing.expectEqual(stream.State.open, record.state);
        try testing.expect(record.peer_initiated);
        try testing.expectEqual(test_send_window, record.send_window.available);
        try testing.expectEqual(constants.window_initial, record.receive.window.available);
        try testing.expectEqual(count, test_table.peer_active);
    }
    try testing.expectError(error.IdentifierNotIncreasing, test_table.open_peer(3, test_send_window));
    try testing.expectError(error.IdentifierNotIncreasing, test_table.open_peer(5, test_send_window));
    try testing.expectEqual(3, test_table.peer_active);
    try testing.expectEqual(5, test_table.highest_peer_opened_id);
    try testing.expectEqual(5, test_table.last_peer_stream_id());
    try testing.expectEqual(7, (try test_table.open_peer(7, test_send_window)).id);
}

test "http2/5.1.1/1: a server refuses HEADERS on its own even parity as WrongParity, and the even identifiers stay idle" {
    test_table.init(.server);
    try testing.expectError(error.WrongParity, test_table.open_peer(2, test_send_window));
    _ = try test_table.open_peer(5, test_send_window);
    try testing.expectError(error.WrongParity, test_table.open_peer(4, test_send_window));
    try testing.expectError(error.WrongParity, test_table.open_peer(6, test_send_window));
    try testing.expectEqual(1, test_table.len());
    try testing.expectEqual(null, test_table.pool.watermark[0]);
    try testing.expectEqual(Lookup{ .idle = false }, test_table.lookup(4));
}

test "http2/5.1.2/1: the stream past concurrent_streams_max is Refused, the watermark moves past it, and its late frames are discarded" {
    test_table.init(.server);
    try fill_with_peer_streams();
    try testing.expectEqual(constants.concurrent_streams_max, test_table.peer_active);
    const refused = client_id(constants.concurrent_streams_max);
    try testing.expectError(error.Refused, test_table.open_peer(refused, test_send_window));
    try testing.expectEqual(refused, test_table.last_peer_stream_id());
    try testing.expectEqual(client_id(constants.concurrent_streams_max - 1), test_table.highest_peer_opened_id);
    const found = test_table.lookup(refused);
    try testing.expectEqual(Lookup.reset_and_dropped, found);
    try testing.expectEqual(Lookup.reset_and_dropped, found);
    try testing.expectError(error.IdentifierNotIncreasing, test_table.open_peer(refused, test_send_window));
    try apply_frame(try expect_live(1), .receive, .rst_stream, false);
    const next = client_id(constants.concurrent_streams_max + 1);
    try testing.expectEqual(next, (try test_table.open_peer(next, test_send_window)).id);
    try testing.expectEqual(constants.concurrent_streams_max, test_table.peer_active);
}

test "open_peer checks the watermark, then colibri's GOAWAY, then the concurrency limit (invariant 7)" {
    test_table.init(.server);
    try fill_with_peer_streams();
    const last_opened = client_id(constants.concurrent_streams_max - 1);
    const above = client_id(constants.concurrent_streams_max);
    test_table.record_goaway_sent(last_opened);
    try testing.expectError(error.AfterGoaway, test_table.open_peer(above, test_send_window));
    try testing.expectEqual(Lookup{ .idle = true }, test_table.lookup(above));
    try testing.expectEqual(last_opened, test_table.pool.watermark[1]);
    try testing.expectEqual(null, test_table.highest_forgotten_reset_id[1]);
    // A refusal before the GOAWAY uses the identifier, which a GOAWAY need not name (§8.7).
    test_table.init(.server);
    try fill_with_peer_streams();
    try testing.expectError(error.Refused, test_table.open_peer(above, test_send_window));
    test_table.record_goaway_sent(last_opened);
    try testing.expectError(error.IdentifierNotIncreasing, test_table.open_peer(above, test_send_window));
    try testing.expectEqual(last_opened, test_table.last_peer_stream_id());
}

test "a client opens local streams 1, 3 and 5, and PeerLimitReached at a peer limit of 3 (§5.1.2)" {
    test_table.init(.client);
    for ([_]u32{ 1, 3, 5 }, 1..) |id, count| {
        const record = try test_table.open_local(3, test_send_window);
        try testing.expectEqual(id, record.id);
        try testing.expectEqual(stream.State.open, record.state);
        try testing.expect(!record.peer_initiated);
        try testing.expectEqual(test_send_window, record.send_window.available);
        try testing.expectEqual(constants.window_initial, record.receive.window.available);
        try testing.expectEqual(count, test_table.local_active);
    }
    try testing.expectError(error.PeerLimitReached, test_table.open_local(3, test_send_window));
    try testing.expectError(error.PeerLimitReached, test_table.open_local(2, test_send_window));
    try testing.expectEqual(7, test_table.next_local_id);
    try testing.expectEqual(3, test_table.len());
    try testing.expectEqual(0, test_table.peer_active);
    try testing.expectEqual(7, (try test_table.open_local(null, test_send_window)).id);
    try testing.expectEqual(9, (try test_table.open_local(5, test_send_window)).id);
    test_table.init(.client);
    try testing.expectError(error.PeerLimitReached, test_table.open_local(0, test_send_window));
}

test "a client that received a GOAWAY opens no further stream, whatever its last stream identifier (§6.8)" {
    for ([_]u32{ 0, constants.stream_id_max }) |last_stream_id| {
        test_table.init(.client);
        _ = try test_table.open_local(null, test_send_window);
        try test_table.record_goaway_received(last_stream_id);
        try testing.expectError(error.AfterGoawayReceived, test_table.open_local(null, test_send_window));
        try testing.expectEqual(3, test_table.next_local_id);
        try testing.expectEqual(1, test_table.len());
        try testing.expectEqual(1, test_table.local_active);
    }
}

test "open_local checks the peer's GOAWAY, the identifiers left, the peer's limit, then the pool, which a reset stream gives way in" {
    test_table.init(.client);
    for (0..constants.concurrent_streams_max) |_| _ = try test_table.open_local(null, test_send_window);
    const limit = constants.concurrent_streams_max;
    try testing.expectError(error.Full, test_table.open_local(null, test_send_window));
    try reset(try expect_live(client_id(0)));
    try testing.expectEqual(client_id(limit), (try test_table.open_local(null, test_send_window)).id);
    try testing.expectEqual(Lookup.reset_and_dropped, test_table.lookup(client_id(0)));
    try testing.expectError(error.PeerLimitReached, test_table.open_local(limit, test_send_window));
    test_table.next_local_id = constants.stream_id_max + constants.stream_id_step;
    try testing.expectError(error.IdentifiersExhausted, test_table.open_local(limit, test_send_window));
    try test_table.record_goaway_received(constants.stream_id_max);
    try testing.expectError(error.AfterGoawayReceived, test_table.open_local(limit, test_send_window));
    try testing.expectEqual(constants.concurrent_streams_max, test_table.local_active);
}

test "IdentifiersExhausted: a client opens stream_id_max, and then has no identifier left" {
    test_table.init(.client);
    test_table.next_local_id = constants.stream_id_max;
    try testing.expectEqual(constants.stream_id_max, (try test_table.open_local(null, test_send_window)).id);
    try testing.expectError(error.IdentifiersExhausted, test_table.open_local(null, test_send_window));
    try testing.expectEqual(1, test_table.local_active);
}

test "a client records promised streams 2 and 6 closed by its reset, and a promise at or below 6 is IdentifierNotIncreasing (§5.1.1, §6.6)" {
    test_table.init(.client);
    try test_table.reserve_peer(2);
    try testing.expectEqual(Lookup.reset_and_dropped, test_table.lookup(2));
    try test_table.reserve_peer(6);
    try testing.expectEqual(Lookup.reset_and_dropped, test_table.lookup(4));
    try testing.expectEqual(Lookup{ .idle = true }, test_table.lookup(8));
    try testing.expectError(error.IdentifierNotIncreasing, test_table.reserve_peer(4));
    try testing.expectError(error.IdentifierNotIncreasing, test_table.reserve_peer(6));
    try testing.expectEqual(6, test_table.last_peer_stream_id());
    try testing.expectEqual(0, test_table.len());
    try testing.expectEqual(0, test_table.peer_active);
    try testing.expectEqual(stream.Verdict.ignore, stream.on_receive(.closed, .rst_stream_sent, .headers, false, .client, true));
    try testing.expectEqual(1, (try test_table.open_local(null, test_send_window)).id);
}
