//! The tests of a handshake flight longer than `crypto_send_buffer_len`, as a server with an
//! ML-DSA-87 identity sends (design §8 step 33e). RFC 9000 §13.3 resends CRYPTO data "until all
//! data has been acknowledged", so the level's send window keeps every octet a packet in flight
//! carried, and forgets only what the peer acknowledged.
const std = @import("std");
const core = @import("core");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const space_module = @import("../space/space.zig");
const frame_module = @import("../frame/frame.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const connection_crypto = @import("connection_crypto.zig");
const recovery = @import("connection_recovery.zig");
const frames = @import("connection_frames.zig");

const Connection = connection_module.Connection;
const Level = core.Level;
const testing = std.testing;

var endpoint: Connection align(@alignOf(Connection)) = undefined;
var scratch: recovery.Scratch align(@alignOf(recovery.Scratch)) = undefined;

const test_now_ns: u64 = 1_000_000;
const round_trip_ns: u64 = 10_000_000;
const test_max_data: u64 = 1_048_576;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
/// A server's Handshake flight with the ML-DSA-87 identity of `src/testing/testdata/`: two
/// certificates of about 7,500 octets and a CertificateVerify of 4,631 (step 33c). Test-only.
const flight_len: usize = 20_000;
/// Octets of one packet's room for its CRYPTO frame, as a datagram of 1,200 leaves. Test-only.
const frame_room_len: usize = 1_100;
/// A flight longer than two windows, so the window fills twice. Test-only.
const long_flight_len: usize = flight_len + flight_len;
/// Fewer octets than any CRYPTO frame below carries. Test-only.
const frame_payload_min_len: usize = 500;
/// More frames than the longer flight needs, which bounds each loop below. Test-only.
const frames_max: usize = long_flight_len / frame_payload_min_len;
/// The flight's octets cycle through this many values, so an octet sent from the wrong place in
/// the window shows. A prime does not divide the window. Test-only.
const pattern_period: usize = 251;

var output: [frame_room_len]u8 = undefined;

/// A provider that owes `len` octets at the Handshake level and gives them up once, as RFC 9001
/// §4.1.3's `write_handshake` does. Test-only.
const Flight = struct {
    len: usize = flight_len,
    written: usize = 0,

    fn provider(self: *Flight) tls_provider.QuicProvider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    fn set_params(context: *anyopaque, body: []const u8) tls_provider.quic_provider.TransportParamsError!void {
        _ = .{ context, body };
    }
    fn peer_params(context: *const anyopaque) ?[]const u8 {
        _ = context;
        return null;
    }
    fn provide(context: *anyopaque, level: Level, data: []const u8) tls_provider.quic_provider.ProvideError!void {
        _ = .{ context, level, data };
    }
    fn write(context: *anyopaque, level: Level, room: []u8) tls_provider.quic_provider.WriteError!usize {
        const self: *Flight = @ptrCast(@alignCast(context));
        if (level != .handshake) return 0;
        const len = @min(room.len, self.len - self.written);
        for (room[0..len], self.written..) |*octet, offset| octet.* = pattern_at(offset);
        self.written += len;
        return len;
    }
    fn alpn(context: *const anyopaque) ?[]const u8 {
        _ = context;
        return &tls_provider.constants.protocol.alpn_h3;
    }
    fn complete(context: *const anyopaque) bool {
        _ = context;
        return false;
    }
    fn alert_of(context: *anyopaque) ?tls_provider.Alert {
        _ = context;
        return null;
    }
    fn exported(context: *anyopaque, label: []const u8, value: ?[]const u8, into: []u8) tls_provider.quic_provider.ExportError!void {
        _ = .{ context, label, value, into };
        // RFC 9846 §7.5 standardises the exporter without obliging a stack to offer it, and no
        // test below needs one.
        return error.Unsupported;
    }

    const table: tls_provider.QuicVTable = .{
        .set_transport_params = set_params,
        .peer_transport_params = peer_params,
        .provide_handshake = provide,
        .write_handshake = write,
        .negotiated_alpn = alpn,
        .handshake_complete = complete,
        .take_alert = alert_of,
        .export_keying_material = exported,
    };
};

fn pattern_at(offset: usize) u8 {
    return @intCast(offset % pattern_period);
}

/// A server that holds Initial and Handshake keys and has received one datagram of the client's.
fn open_server() void {
    var parameters = transport_parameters.Parameters.initial();
    parameters.initial_max_data = test_max_data;
    endpoint.init(.{
        .role = .server,
        .local_parameters = parameters,
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for ([_]Level{ .initial, .handshake }) |level| {
        keys.on_keys_installed(&endpoint, level, .read);
        keys.on_keys_installed(&endpoint, level, .write);
    }
    // RFC 9000 §8.1: the client's datagram lets the server send, and arms its PTO.
    endpoint.path.on_datagram_received(constants.protocol.datagram_len_min);
}

/// What `send_until_held` sent. Test-only.
const Sent = struct {
    packets: usize = 0,
    /// The Offset of the last CRYPTO frame.
    last_offset: u64 = 0,
};

/// Writes CRYPTO frames at the Handshake level, each in a packet in flight, until the window has
/// nothing more to send. Each frame's octets must be the flight's own at its offset.
fn send_until_held(flight: *Flight) !Sent {
    var sent: Sent = .{};
    // Bounded by `frames_max`, which is more frames than one flight needs.
    while (sent.packets < frames_max) : (sent.packets += 1) {
        const written = try connection_crypto.write_crypto(&endpoint, flight.provider(), .handshake, &output);
        if (written.len == 0) return sent;
        sent.last_offset = written.offset;
        try expect_flight_octets(output[0..written.len]);
        const number = try connection_module.space_at(&endpoint, .handshake).next_number();
        try endpoint.recovery.on_packet_sent(space_module.Kind.handshake, .{
            .number = number,
            .sent_at_ns = test_now_ns,
            .sent_len = constants.protocol.datagram_len_min,
            .ack_eliciting = true,
            .in_flight = true,
            .carries = .crypto,
            .data_offset = written.offset,
            .data_len = written.payload_len,
        }, test_now_ns);
    }
    // The window holds less than a flight, so the loop above returns before its bound.
    try testing.expect(sent.packets < frames_max);
    return sent;
}

/// The frame in `octets` carries the flight's own octets at the offset it names.
fn expect_flight_octets(octets: []const u8) !void {
    var reader = core.Reader.init(octets);
    const read = try frame_module.read(&reader);
    const offset: usize = @intCast(read.crypto.offset);
    for (read.crypto.data, offset..) |octet, at| try testing.expectEqual(pattern_at(at), octet);
}

/// The server reads an ACK frame at the Handshake level for `smallest` to `largest`.
fn take_ack(smallest: u64, largest: u64) !void {
    var payload: [constants.protocol.datagram_len_min]u8 = undefined;
    var writer = core.Writer.init(&payload);
    const ack: frame_module.Ack = .{
        .ranges = .{ .largest_acknowledged = largest, .first_range = largest - smallest, .octets = &.{}, .count = 0 },
        .delay = 0,
        .ecn = null,
    };
    try frame_module.write(&writer, .{ .ack = ack });
    _ = try frames.process(&endpoint, .{ .level = .handshake, .payload = writer.written() }, test_now_ns + round_trip_ns, &scratch);
}

test "RFC 9000 §13.3: a PTO before any acknowledgment sends a long flight again from its first octet" {
    open_server();
    var flight: Flight = .{};
    _ = try send_until_held(&flight);
    // Decision 64: the PTO declares every Handshake packet in flight lost, the first included.
    const at_ns = recovery.loss_deadline_ns(&endpoint) orelse return error.NoTimer;
    try testing.expect(try recovery.on_loss_timer(&endpoint, at_ns, &scratch));
    // No acknowledgment arrived, so the window held every octet in flight and the provider
    // keeps the rest of its flight.
    const stream = connection_module.crypto_at(&endpoint, .handshake);
    try testing.expect(flight.written < flight_len);
    try testing.expectEqual(0, stream.sent_len);
    try testing.expectEqual(constants.limits.crypto_send_buffer_len, stream.unsent().len);
    // The probe carries the flight from its first octet.
    const probe = try connection_crypto.write_crypto(&endpoint, flight.provider(), .handshake, &output);
    try testing.expectEqual(0, probe.offset);
    try expect_flight_octets(output[0..probe.len]);
}

test "RFC 9000 §13.3: an acknowledgment frees the window, and the rest of the flight follows" {
    open_server();
    var flight: Flight = .{ .len = long_flight_len };
    const first = try send_until_held(&flight);
    // Every packet but the last is acknowledged. The last still holds its octets in the window.
    try take_ack(0, first.packets - 2);
    const second = try send_until_held(&flight);
    try testing.expect(second.packets > 0);
    const stream = connection_module.crypto_at(&endpoint, .handshake);
    try testing.expectEqual(first.last_offset, stream.send_base);
    try testing.expect(stream.send_full());
    // Every packet is acknowledged, so nothing is in flight and the window forgets all it framed.
    try take_ack(0, first.packets + second.packets - 1);
    _ = try send_until_held(&flight);
    try testing.expectEqual(long_flight_len, flight.written);
    try testing.expectEqual(long_flight_len, stream.sent_len);
    try testing.expectEqual(0, stream.unsent().len);
}

test "RFC 9000 §13.3: a resend of a lost packet keeps its octets while older packets are in flight" {
    open_server();
    var flight: Flight = .{};
    const first = try send_until_held(&flight);
    // RFC 9002 §6.1.1: an ACK of packets 4 to 6 declares packets 0 to 3 lost. Packets 7 and up
    // stay in flight, and each has a lower number and a higher Offset than any resend.
    try testing.expect(first.packets > 7);
    try take_ack(4, 6);
    const stream = connection_module.crypto_at(&endpoint, .handshake);
    try testing.expectEqual(0, stream.sent_len);
    // The resends fill the window again from offset 0. The resend at offset 0 is in flight, so
    // the window keeps its octets.
    const resent = try send_until_held(&flight);
    try testing.expect(resent.packets > 0);
    try testing.expectEqual(0, stream.send_base);
    // An ACK of the last resend alone declares the resend at offset 0 lost, so the next frame
    // carries the flight from its first octet again.
    const last = first.packets + resent.packets - 1;
    try take_ack(last, last);
    const again = try connection_crypto.write_crypto(&endpoint, flight.provider(), .handshake, &output);
    try testing.expectEqual(0, again.offset);
    try expect_flight_octets(output[0..again.len]);
}
