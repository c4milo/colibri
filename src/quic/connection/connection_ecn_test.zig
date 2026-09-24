//! The tests of decision 68: a caller says whether it reads received ECN codepoints and whether it
//! sets them on what it sends. With `ecn_reads` an ACK frame carries the counts (RFC 9000
//! §13.4.1); with `ecn_marks` a datagram is ECT(0) until validation fails (§13.4.2). Each side
//! reads the other's packets, so a mark is checked where the peer counts it.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const frame_module = @import("../frame/frame.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const send = @import("connection_send.zig");
const connection_recovery = @import("connection_recovery.zig");
const datagram_module = @import("connection_datagram.zig");
const build_test = @import("packet_build/packet_build_test.zig");
const stream_module = @import("../stream/stream.zig");

const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const Ecn = send.Ecn;
const testing = std.testing;

var client: Connection = undefined;
var server: Connection = undefined;
var scratch: send.DefaultScratch = .{};
var datagram: [constants.datagram_len_min]u8 = undefined;
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;
var datagram_scratch: datagram_module.Scratch = undefined;
var recovery_scratch: connection_recovery.Scratch = undefined;

const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const application: usize = @intFromEnum(core.Level.application);
/// The connection's data limit, which RFC 9000 §4.1 needs above zero. No stream opens here.
const test_max_data: u64 = 1_000;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// What each side of a test pair can do with codepoints (decision 68).
const Flags = struct { reads: bool, marks: bool };

const both: Flags = .{ .reads = true, .marks = true };
const neither: Flags = .{ .reads = false, .marks = false };
const reads_only: Flags = .{ .reads = true, .marks = false };

fn open_pair(client_flags: Flags, server_flags: Flags) void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client, client_flags);
    open_one(&server, .server, server_flags);
    client.apply_peer_parameters(parameters());
    server.apply_peer_parameters(parameters());
}

fn open_one(connection: *Connection, role: connection_module.Role, flags: Flags) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
        .ecn_reads = flags.reads,
        .ecn_marks = flags.marks,
    });
    keys.on_keys_installed(connection, .application, .read);
    keys.on_keys_installed(connection, .application, .write);
    connection.handshake_complete = true;
    // RFC 9000 §8.1: a server sends only after it has received.
    if (role == .server) connection.path.on_datagram_received(constants.datagram_len_min);
}

var nothing_context: u8 = 0;
const nothing_vtable: stream_module.stream_provider.VTable = .{ .read = read_nothing };

fn read_nothing(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    _ = offset;
    _ = output;
    return 0;
}

fn send_from(connection: *Connection) !send.Sent {
    const streams: stream_module.StreamProvider = .{ .context = &nothing_context, .vtable = &nothing_vtable };
    return try send.send(connection, suite_holder.suite(), provider_holder.provider(), streams, &scratch, &datagram, test_now_ns) orelse error.NothingSent;
}

/// The next datagram from `sender`, which `reader` takes whole with the codepoint the network
/// delivered it under. Test-only.
fn deliver(sender: *Connection, reader: *Connection, arrived: Ecn) !send.Sent {
    const sent = try send_from(sender);
    const datagram_in: receive.Datagram = .{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = arrived };
    _ = try datagram_module.receive(reader, suite_holder.suite(), provider_holder.provider(), datagram_in, &datagram_scratch);
    return sent;
}

/// One ack-eliciting packet from `sender` to `reader`. Test-only.
fn ping(sender: *Connection, reader: *Connection, arrived: Ecn) !send.Sent {
    send.owe_probes(sender, .application, 1);
    return deliver(sender, reader, arrived);
}

fn ping_server(arrived: Ecn) !send.Sent {
    return ping(&client, &server, arrived);
}

/// The ACK frame `sender` writes first, which `reader` takes. Test-only.
fn acknowledge(sender: *Connection, reader: *Connection) !frame_module.frame_ack.Ack {
    const sent = try send_from(sender);
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const opened = (try receive.next(&walk, reader, suite_holder.suite())).?.opened;
    _ = try frames.process(reader, opened, test_now_ns, &recovery_scratch);
    var payload = core.Reader.init(opened.payload);
    return switch (try frame_module.read(&payload)) {
        .ack => |ack| ack,
        else => error.NoAck,
    };
}

fn acknowledge_client() !frame_module.frame_ack.Ack {
    return acknowledge(&server, &client);
}

test "decision 68: a connection opened without the flags neither marks nor reports ECN" {
    open_pair(neither, neither);
    const first = try ping_server(.not_ect);
    try testing.expectEqual(Ecn.not_ect, first.ecn);
    _ = try ping_server(.not_ect);
    try testing.expectEqual(0, client.recovery.ecn[application].sent_ect_0);
    // RFC 9000 §13.4.1: an endpoint without the codepoints "does not process or report ECN".
    try testing.expectEqual(null, (try acknowledge_client()).ecn);
}

test "RFC 9000 §13.4.2: with ecn_marks each datagram is ECT(0), and the record says so" {
    open_pair(both, both);
    const first = try ping_server(.ect_0);
    try testing.expectEqual(Ecn.ect_0, first.ecn);
    try testing.expectEqual(1, client.recovery.ecn[application].sent_ect_0);
    // A server that reads codepoints but marks none sends Not-ECT.
    open_pair(both, reads_only);
    _ = try ping_server(.ect_0);
    _ = try ping_server(.ect_0);
    _ = try acknowledge_client();
    try testing.expectEqual(0, server.recovery.ecn[application].sent_ect_0);
}

test "RFC 9000 §13.4.1: with ecn_reads an ACK carries the count of each codepoint received" {
    open_pair(both, reads_only);
    _ = try ping_server(.ect_0);
    // §13.2.1: a packet marked ECN-CE is acknowledged at once.
    _ = try ping_server(.ecn_ce);
    const counts = (try acknowledge_client()).ecn orelse return error.NoCounts;
    try testing.expectEqual(1, counts.ect_0);
    try testing.expectEqual(0, counts.ect_1);
    try testing.expectEqual(1, counts.ecn_ce);
}

test "RFC 9000 §13.4.2.2: counts that pass keep the marks, and a peer that reports none stops them" {
    open_pair(both, reads_only);
    _ = try ping_server(.ect_0);
    _ = try ping_server(.ect_0);
    _ = try acknowledge_client();
    try testing.expect(!client.recovery.ecn_failed());
    try testing.expectEqual(Ecn.ect_0, (try ping_server(.ect_0)).ecn);
    // A server that reads no codepoint passes Not-ECT and reports no counts, so the ACK of a
    // packet sent ECT(0) fails validation (§13.4.2.1) and the client stops marking.
    open_pair(both, neither);
    _ = try ping_server(.not_ect);
    _ = try ping_server(.not_ect);
    try testing.expectEqual(null, (try acknowledge_client()).ecn);
    try testing.expect(client.recovery.ecn_failed());
    try testing.expectEqual(Ecn.not_ect, (try ping_server(.not_ect)).ecn);
}

test "RFC 9000 §13.4.2.1: a packet of ACK frames alone counts among the packets sent ECT(0)" {
    open_pair(both, both);
    _ = try ping_server(.ect_0);
    _ = try ping_server(.ect_0);
    // The server's ACK stands alone, so no record keeps it, and the client counts it.
    const lone = try deliver(&server, &client, .ect_0);
    try testing.expect(!lone.packets[0].ack_eliciting);
    try testing.expectEqual(Ecn.ect_0, lone.ecn);
    _ = try ping(&server, &client, .ect_0);
    _ = try ping(&server, &client, .ect_0);
    // The client reports three ECT(0) packets, and the server sent three.
    try testing.expectEqual(3, ((try acknowledge(&client, &server)).ecn orelse return error.NoCounts).ect_0);
    try testing.expect(!server.recovery.ecn_failed());
}

test "decision 69: past ten marked packets a datagram is Not-ECT until an ACK shows a marked one arrived" {
    open_pair(both, reads_only);
    // Bounded by the test's packet count.
    for (0..constants.ecn_testing_packets) |_| {
        try testing.expectEqual(Ecn.ect_0, (try ping_server(.ect_0)).ecn);
    }
    try testing.expectEqual(Ecn.not_ect, (try ping_server(.not_ect)).ecn);
    // The server's ACK reports ten ECT(0) packets, which passes and makes the path capable.
    try testing.expectEqual(constants.ecn_testing_packets, ((try acknowledge_client()).ecn orelse return error.NoCounts).ect_0);
    try testing.expectEqual(Ecn.ect_0, (try ping_server(.ect_0)).ecn);
}
