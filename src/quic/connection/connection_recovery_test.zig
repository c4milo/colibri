//! The tests of `connection_recovery.zig`: one batch of acknowledged or lost packets reaches every
//! piece that keeps a record of what it sent. Each piece's own rules are tested where it lives;
//! these check only that the batch arrives.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_id = @import("../connection_id.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const stream_module = @import("../stream/stream.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const id_frames = @import("connection_id_frames.zig");
const recovery = @import("connection_recovery.zig");
const stream_send = @import("connection_stream/connection_stream_send.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const Record = recovery_sent.Record;
const StreamId = stream_module.StreamId;
const testing = std.testing;

var server: Connection = undefined;

const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const test_max_data: u64 = 1_048_576;
const generous_limit: u64 = 4;
const issued_octet: u8 = 0x6a;
const issued_id: [id_len]u8 = @splat(issued_octet);
const token_octet: u8 = 0x9d;
const token: [constants.stateless_reset_token_len]u8 = @splat(token_octet);
/// The packet every piece says it last carried its frame in. Test-only.
const carrying: u64 = 5;
/// Octets of the stream range the packet carried. Test-only.
const range_len: u16 = 100;
const completed_max: usize = 2;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    held.initial_max_stream_data_bidi_remote = test_max_data;
    held.initial_max_streams_bidi = generous_limit;
    held.active_connection_id_limit = generous_limit;
    return held;
}

fn open_server() void {
    server.init(.{
        .role = .server,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        keys.on_keys_installed(&server, level, .read);
        keys.on_keys_installed(&server, level, .write);
    }
    server.apply_peer_parameters(parameters());
}

/// A stream the server opened and framed `range_len` octets and its FIN on, as one packet would.
fn framed_stream() !StreamId {
    const id = try stream_send.open(&server, .bidirectional);
    try stream_send.supply(&server, id, range_len, true);
    const stream = server.streams.lookup(id).live;
    _ = stream.sending.on(.sent_fin);
    stream.outgoing.on_framed(range_len, true);
    return id;
}

fn carried_range(id: StreamId) Record {
    return .{
        .number = carrying,
        .sent_at_ns = test_now_ns,
        .sent_len = range_len,
        .ack_eliciting = true,
        .in_flight = true,
        .carries = .stream_fin,
        .data_offset = 0,
        .data_len = range_len,
        .stream_id = id.value,
    };
}

test "decision 59: a lost packet reaches every piece that sent what it carried" {
    open_server();
    const id = try framed_stream();
    server.handshake_done.sent_in = carrying;
    server.max_data.on_sent(carrying);
    _ = try id_frames.issue(&server, &issued_id, &token);
    server.local_ids.active_ids()[1].new_frame.on_sent(carrying);

    try recovery.on_packets_lost(&server, .application, &.{carried_range(id)});
    try testing.expectEqual(1, server.streams.lost.count);
    try testing.expect(server.handshake_done.owed);
    try testing.expect(server.max_data.owed);
    try testing.expect(server.local_ids.active_ids()[1].new_frame.owed);
}

test "decision 59: a lost packet whose CRYPTO octets are forgotten, or a full table, ends the connection" {
    open_server();
    // A window that forgot what it framed, which `connection_crypto.on_packets_lost` reports.
    server.crypto_at(.initial).send_base = 1;
    var crypto: Record = .{ .number = 0, .sent_at_ns = test_now_ns, .sent_len = range_len, .ack_eliciting = true, .in_flight = true };
    crypto.carries = .crypto;
    try testing.expectError(error.CryptoForgotten, recovery.on_packets_lost(&server, .initial, &.{crypto}));

    open_server();
    const id = try framed_stream();
    const gap: u64 = 2;
    for (0..constants.stream_lost_ranges_max) |index| {
        try server.streams.lost.add(.{ .stream_id = id.value + 4, .offset = gap * index, .len = 1, .fin = false });
    }
    try testing.expectError(error.LostRangesFull, recovery.on_packets_lost(&server, .application, &.{carried_range(id)}));
    // RFC 9000 §20.1: INTERNAL_ERROR is 0x01.
    try testing.expectEqual(0x01, recovery.connection_error_code(error.LostRangesFull));
}

test "decision 59: an acknowledged packet reaches every piece that waits on one" {
    open_server();
    const id = try framed_stream();
    server.handshake_done.sent_in = carrying;
    // A retirement whose frame the packet carried.
    const offered: connection_id.Entry = .{ .sequence_number = 1, .len = id_len, .octets = @splat(peer_octet), .stateless_reset_token = token };
    try server.remote_ids.offer(offered, 0, generous_limit);
    const later: connection_id.Entry = .{ .sequence_number = 2, .len = id_len, .octets = @splat(issued_octet), .stateless_reset_token = token };
    try server.remote_ids.offer(later, 2, generous_limit);
    server.remote_ids.retirements()[0].frame.on_sent(carrying);

    var completed: [completed_max]StreamId = undefined;
    const held = recovery.on_packets_acknowledged(&server, .application, &.{carried_range(id)}, &completed);
    try testing.expectEqual(1, held.written);
    try testing.expectEqual(id.value, completed[0].value);
    try testing.expectEqual(null, server.handshake_done.sent_in);
    try testing.expectEqual(0, server.remote_ids.retirements().len);
}
