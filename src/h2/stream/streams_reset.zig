//! The RST_STREAM frames the caller asked for that colibri has not yet written, held by the records
//! of the stream table of `streams.zig` (decision 113). A caller may reset every stream it holds at
//! any time, and nothing stops it, so each reset needs storage that exists for every such stream:
//! the stream's own record. The reply queue of `connection/connection_reply.zig` holds the frames
//! colibri owes for the frames it reads, and it stops the reading when it is full; it could not
//! stop a caller.
//!
//! A reset closes the stream at once (RFC 9113 §5.1), and the record keeps the error code until
//! `write_pending` writes the frame. Three rules write each owed frame, and write it once:
//!   1. a record that owes a frame is not dropped (`streams_slot.zig`). An open that finds every
//!      slot held by an active stream or by one that owes a frame waits for the caller to write:
//!      a server reads no HEADERS frame (`open_waits_for_write`), and a client's `open_local`
//!      returns `error.Full`;
//!   2. a stream owes at most one frame: the reset closes it, and §5.1 lets colibri send nothing
//!      more on a closed stream;
//!   3. a record owes its frame until the frame is written whole.
//!
//! `resets_owed` counts the records that owe a frame, so a write with none owed walks no record,
//! and the counts are asserted after every change.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const table = @import("streams.zig");

const Stream = table.Stream;
const Streams = table.Streams;

/// Owes the RST_STREAM carrying `error_code` that closed `record`, a reset the caller asked for.
pub fn owe(streams: *Streams, record: *Stream, error_code: u32) void {
    assert(streams.pool.get(record.id) == record);
    // Rule 2: the reset closed the stream, which owes no frame yet.
    assert(record.state == .closed and record.closed == .rst_stream_sent);
    assert(record.reset_owed == null);
    record.reset_owed = error_code;
    streams.resets_owed += 1;
    assert_counts(streams);
}

/// `record`'s RST_STREAM is written whole, so it owes nothing more (rule 3).
pub fn written(streams: *Streams, record: *Stream) void {
    assert(record.reset_owed != null);
    assert(streams.resets_owed > 0);
    record.reset_owed = null;
    streams.resets_owed -= 1;
    assert_counts(streams);
}

/// Whether an open would find no slot: the pool is full, and every closed record in it owes a
/// RST_STREAM not yet written, so none may be dropped (rule 1). Once the caller writes them, the
/// oldest closed record is dropped as before. A server at `peer_active_max` refuses the stream,
/// which takes no slot, so it waits for nothing.
pub fn open_waits_for_write(streams: *const Streams) bool {
    assert_counts(streams);
    if (streams.resets_owed == 0) return false;
    // The pool's capacity is `concurrent_streams_max` (`streams.zig`'s `Pool`).
    if (streams.pool.len() < constants.concurrent_streams_max) return false;
    // RFC 9113 §5.1.2: a stream past the limit colibri advertised is refused, not opened.
    if (streams.peer_active >= streams.peer_active_max) return false;
    return streams.resets_owed == closed_records(streams);
}

/// Each record that owes a frame is a closed record the pool holds.
pub fn assert_counts(streams: *const Streams) void {
    assert(streams.resets_owed <= closed_records(streams));
}

/// The closed records the pool holds: every record but the open and half-closed ones, because
/// decision 17 refuses push and so the pool holds no reserved stream.
fn closed_records(streams: *const Streams) u32 {
    const active = streams.peer_active + streams.local_active;
    assert(active <= streams.pool.len());
    return streams.pool.len() - active;
}

// Tests. `streams_open.zig` holds the table these run on, and its test helpers.

const testing = std.testing;
const open = @import("streams_open.zig");

test "a reset owed holds its record, and the count follows each owed frame until it is written" {
    open.test_table.init(.server);
    const first = try open.test_table.open_peer(open.client_id(0), open.test_send_window);
    const second = try open.test_table.open_peer(open.client_id(1), open.test_send_window);
    try open.reset(first);
    open.test_table.owe_reset(first, constants.error_cancel);
    try testing.expectEqual(constants.error_cancel, first.reset_owed.?);
    try testing.expectEqual(1, open.test_table.resets_owed);
    try testing.expectEqual(null, second.reset_owed);
    // The pool has free slots, so an open need not wait.
    try testing.expect(!open.test_table.open_waits_for_write());
    open.test_table.reset_written(first);
    try testing.expectEqual(null, first.reset_owed);
    try testing.expectEqual(0, open.test_table.resets_owed);
}

test "an open waits for a write only when the pool is full and every closed record owes a reset" {
    open.test_table.init(.server);
    try open.fill_with_peer_streams();
    // Every slot holds an active stream: an open is refused at the concurrency limit, and needs no
    // slot for it.
    try testing.expect(!open.test_table.open_waits_for_write());
    const first = try open.expect_live(open.client_id(0));
    try open.reset(first);
    open.test_table.owe_reset(first, constants.error_cancel);
    try testing.expect(open.test_table.open_waits_for_write());
    // A second closed record, which owes nothing, is one an open may drop.
    const second = try open.expect_live(open.client_id(1));
    try open.apply_frame(second, .receive, .rst_stream, false);
    try testing.expect(!open.test_table.open_waits_for_write());
    const third = try open.test_table.open_peer(open.client_id(constants.concurrent_streams_max), open.test_send_window);
    try testing.expect(open.test_table.lookup(open.client_id(1)) != .live);
    try testing.expectEqual(first, try open.expect_live(open.client_id(0)));
    try testing.expectEqual(open.client_id(constants.concurrent_streams_max), third.id);
}

test "a server at its peer limit refuses the next stream without waiting for a write" {
    open.test_table.init(.server);
    const half = constants.concurrent_streams_max / 2;
    open.test_table.peer_active_max = half;
    // Half the slots hold streams closed with a reset still owed, and the other half open ones.
    for (0..half) |index| {
        const record = try open.test_table.open_peer(open.client_id(@intCast(index)), open.test_send_window);
        try open.reset(record);
        open.test_table.owe_reset(record, constants.error_cancel);
    }
    for (half..2 * half) |index| _ = try open.test_table.open_peer(open.client_id(@intCast(index)), open.test_send_window);
    try testing.expectEqual(constants.concurrent_streams_max, open.test_table.len());
    // The next stream is refused at the limit, and a refusal takes no slot (RFC 9113 §5.1.2).
    try testing.expect(!open.test_table.open_waits_for_write());
    try testing.expectError(error.Refused, open.test_table.open_peer(open.client_id(2 * half), open.test_send_window));
}

test "an open waits for no write while no reset is owed, even with every slot held" {
    open.test_table.init(.client);
    for (0..constants.concurrent_streams_max) |_| _ = try open.test_table.open_local(null, open.test_send_window);
    // Every slot holds an open stream, so an open fails, and a write would free no slot.
    try testing.expectError(error.Full, open.test_table.open_local(null, open.test_send_window));
    try testing.expect(!open.test_table.open_waits_for_write());
}
