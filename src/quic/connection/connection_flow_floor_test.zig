//! The tests of the credit floor of `connection_flow.zig` (decision 49 as amended on 2026-11-06):
//! a connection with a receive pool owes MAX_DATA once the credit left to its peer is below one
//! stream's reserve and the application consumed one octet since the last MAX_DATA. A held stream
//! whose window grew to its cap thus leaves the other streams credit (RFC 9000 §4.1, §4.2).
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const frame_module = @import("../frame/frame.zig");
const stream_module = @import("../stream/stream.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const flow_frames = @import("connection_flow.zig");

const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const testing = std.testing;
const assert = std.debug.assert;

var server: Connection align(@alignOf(Connection)) = undefined;

/// One stream's starting window, of `window_blocks` blocks, and a receive pool of
/// `pool_windows` of them, which is also the connection's window. Test-only.
const window_blocks: u64 = 4;
const stream_window: u64 = window_blocks * stream_module.stream_incoming.block_len;
const pool_windows: u64 = 4;
const pool_capacity: usize = pool_windows * stream_window;
var pool: stream_module.stream_incoming.Pool(pool_capacity) align(@alignOf(stream_module.stream_incoming.Pool(pool_capacity))) = .{};

/// What the other streams consumed before the held stream filled its window: a window and a
/// half, which is below `flow_credit_fraction`'s half of the connection's window. Test-only.
const consumed_before_hold: u64 = stream_window + stream_window / half;
const half: u64 = 2;
/// The largest window the held stream grows to. Test-only.
const held_window_max: u64 = pool_capacity - constants.limits.stream_window_reserve_windows * stream_window;

comptime {
    // The probe needs credit that the rule of the fraction alone never gives back.
    assert(consumed_before_hold < pool_capacity / constants.policy.flow_credit_fraction);
}

const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

/// The parameters of a server whose streams start at `window`. Test-only.
fn parameters(window: u64) Parameters {
    var held = Parameters.initial();
    held.initial_max_data = pool_capacity;
    held.initial_max_stream_data_bidi_local = window;
    held.initial_max_stream_data_bidi_remote = window;
    held.initial_max_stream_data_uni = window;
    return held;
}

fn open_server(receive: ?stream_module.stream_incoming.Storage, window: u64) void {
    server.init(.{
        .role = .server,
        .local_parameters = parameters(window),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
        .receive = receive,
    });
    keys.on_keys_installed(&server, .application, .read);
    keys.on_keys_installed(&server, .application, .write);
    server.handshake_complete = true;
}

/// The MAX_DATA frame `write_limits` writes now, or null when it writes none. Test-only.
fn max_data_written() !?u64 {
    var room: [constants.protocol.datagram_len_min]u8 = undefined;
    var writer = Writer.init(&room);
    if (!flow_frames.write_limits(&server, .application, &writer, 0, test_now_ns)) return null;
    var reader = core.Reader.init(writer.written());
    return switch (try frame_module.read(&reader)) {
        .max_data => |frame| frame.maximum,
        else => error.TestExpectedFrame,
    };
}

/// The peer's octets arrive up to `reached` on the connection, and the application takes
/// `consumed` more of them. Test-only.
fn arrive(reached: u64, consumed: u64) !void {
    try server.receive_flow.use(reached, error.FlowControlExceeded);
    server.receive_flow.consume(consumed);
}

test "decision 49 as amended: a held stream at its cap leaves the other streams credit" {
    open_server(pool.storage(), stream_window);
    try testing.expectEqual(stream_window, connection_module.receive_credit_floor(&server));
    try testing.expectEqual(held_window_max, connection_module.stream_receive_window_max(&server, stream_window));
    // The other streams take a window and a half, and the held stream fills the rest of the
    // connection's credit. Nothing of it is consumed.
    try arrive(consumed_before_hold, consumed_before_hold);
    try testing.expect(!flow_frames.data_credit_owed(&server));
    try arrive(pool_capacity, 0);
    try testing.expectEqual(0, server.receive_flow.available());
    // RFC 9000 §4.2: credit below the floor with octets consumed is worth a MAX_DATA frame.
    try testing.expect(flow_frames.data_credit_owed(&server));
    try testing.expectEqual(consumed_before_hold + pool_capacity, (try max_data_written()).?);
    // The held stream reaches its cap. What is left is one reserve, which the other streams get.
    const held_end = pool_capacity + (held_window_max - (pool_capacity - consumed_before_hold));
    try arrive(held_end, 0);
    try testing.expectEqual(stream_window, server.receive_flow.available());
    try testing.expectEqual(null, try max_data_written());
    // The other streams use the reserve and consume it, and the credit comes back each time.
    for (0..pool_windows) |_| {
        const reached = server.receive_flow.limit;
        try arrive(reached, stream_window);
        const limit = (try max_data_written()).?;
        try testing.expectEqual(server.receive_flow.consumed + pool_capacity, limit);
        try testing.expectEqual(stream_window, limit - reached);
        // RFC 9000 §4.1: the limit never grants more than the pool holds.
        try testing.expect(limit - server.receive_flow.consumed <= pool_capacity);
    }
}

test "decision 49 as amended: a connection with no receive pool keeps no credit floor" {
    open_server(null, stream_window);
    try testing.expectEqual(0, connection_module.receive_credit_floor(&server));
    try arrive(stream_window / half, stream_window / half);
    try arrive(pool_capacity, 0);
    try testing.expectEqual(null, try max_data_written());
}

test "decision 49 as amended: the floor is what the cap leaves free, and none when a stream can fill the pool" {
    // A stream that starts with the whole pool leaves no reserve, so no octet is worth a frame.
    open_server(pool.storage(), pool_capacity);
    try testing.expectEqual(0, connection_module.receive_credit_floor(&server));
    try arrive(stream_window / half, stream_window / half);
    try arrive(pool_capacity, 0);
    try testing.expectEqual(null, try max_data_written());
    // A stream that starts past half the pool leaves the rest of the pool.
    const wide_window = pool_capacity - stream_window;
    open_server(pool.storage(), wide_window);
    try testing.expectEqual(stream_window, connection_module.receive_credit_floor(&server));
}
