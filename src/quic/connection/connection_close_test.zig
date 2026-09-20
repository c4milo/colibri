//! The tests of `connection_close.zig`: RFC 9000 §10.2.3's levels, §12.5's confinement of an
//! application close, and §19.19's frame.
//!
//! The end-to-end tests send a real datagram and walk it back through `connection_receive.zig`
//! and `connection_frames.zig`, so what the peer reads is what proves the writer, rather than an
//! expected byte string this file also wrote.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const send = @import("connection_send.zig");
const close_module = @import("connection_close.zig");
const build_test = @import("packet_build_test.zig");

const testing = std.testing;
const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var client: Connection = undefined;
var server: Connection = undefined;
const datagram_buffer_len: usize = 2000;
var scratch: send.Scratch(datagram_buffer_len) = .{};
var datagram: [datagram_buffer_len]u8 = undefined;
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

/// A code and a triggering frame type that are not colibri's defaults, so a test that reads them
/// back is reading what was written. Test-only.
const test_error_code: u64 = error_code.protocol_violation;
const test_frame_type: u64 = constants.frame_ping;
/// A reason phrase, which RFC 9000 §19.19 makes diagnostic and optional. Test-only.
const test_reason = "no";
/// Handshake octets a fake provider owes, so a packet would carry a CRYPTO frame if it could.
/// Test-only.
const handshake_flight_octet: u8 = 0x6d;
const handshake_flight_len: usize = 40;
const handshake_flight: [handshake_flight_len]u8 = @splat(handshake_flight_octet);

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// A pair of connections with Initial and Handshake keys, as after the first flight. Test-only.
fn open_pair() void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client);
    open_one(&server, .server);
}

fn open_one(connection: *Connection, role: connection_module.Role) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for ([_]Level{ .initial, .handshake }) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
    // RFC 9000 §8.1: a server may send three times what it received, and §10.2.1 has it close in
    // response to an incoming packet, so one datagram has always arrived by the time it closes.
    if (role == .server) connection.path.on_datagram_received(constants.datagram_len_min);
}

/// Installs the application keys on both sides, which is what lets a 1-RTT packet be sealed.
fn install_application() void {
    for ([_]*Connection{ &client, &server }) |connection| {
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
    }
}

fn send_from(connection: *Connection) !?send.Sent {
    return send.send(
        connection,
        suite_holder.suite(),
        provider_holder.provider(),
        &scratch,
        &datagram,
        test_now_ns,
    );
}

/// Walks a datagram back as `reader`, and answers what its frames amounted to per level.
/// Test-only.
const Read = struct {
    packets: usize,
    closes: usize,
    levels: [core.levels_count]bool = @splat(false),
    last: ?frames.Close = null,
};

fn walk_back(reader: *Connection, sent: send.Sent) !Read {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    var seen: Read = .{ .packets = 0, .closes = 0 };
    // Bounded by what one datagram can hold (RFC 9000 §12.2).
    while (seen.packets < constants.coalesced_packets_max) {
        const outcome = receive.next(&walk, reader, suite_holder.suite()) orelse break;
        const opened = switch (outcome) {
            .opened => |one| one,
            .discarded => continue,
        };
        seen.packets += 1;
        const report = try frames.process(reader, opened.level, opened.payload, test_now_ns, null);
        if (report.close) |close| {
            seen.closes += 1;
            seen.levels[@intFromEnum(opened.level)] = true;
            seen.last = close;
        }
    }
    return seen;
}

test "RFC 9000 §10.2.3: before confirmation a server closes at Initial, Handshake and 1-RTT" {
    open_pair();
    install_application();
    close_module.owe(&server, close_module.transport(test_error_code, test_frame_type));
    // "A server SHOULD also send a CONNECTION_CLOSE frame in an Initial packet", and "an endpoint
    // SHOULD send a CONNECTION_CLOSE frame in both Handshake and 1-RTT packets".
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        try testing.expect(close_module.carries(&server, level));
    }
    const sent = (try send_from(&server)).?;
    // RFC 9000 §12.2 coalesces the three into one datagram, so the server pays for one.
    try testing.expectEqual(3, sent.count);
    const read = try walk_back(&client, sent);
    // RFC 9001 §5.7: the client cannot open a 1-RTT packet before its own handshake completes,
    // which is the very reason §10.2.3 sends the frame at more than one level. The two it can
    // open both carry it, so the close arrives whichever keys the client turned out to hold.
    try testing.expectEqual(2, read.closes);
    try testing.expect(read.levels[@intFromEnum(Level.initial)]);
    try testing.expect(read.levels[@intFromEnum(Level.handshake)]);
    try testing.expectEqual(.transport, read.last.?.layer);
    try testing.expectEqual(test_error_code, read.last.?.error_code);
}

test "RFC 9000 §10.2.3: a client closes at Handshake and 1-RTT but not at Initial" {
    open_pair();
    install_application();
    close_module.owe(&client, close_module.transport(test_error_code, null));
    // "A client will always know whether the server has Handshake keys", so it owes the server no
    // second copy in an Initial packet.
    try testing.expect(!close_module.carries(&client, .initial));
    try testing.expect(close_module.carries(&client, .handshake));
    try testing.expect(close_module.carries(&client, .application));
    const sent = (try send_from(&client)).?;
    try testing.expectEqual(2, sent.count);
    const read = try walk_back(&server, sent);
    // The server opens the Handshake copy; §5.7 holds off the 1-RTT one as it does for a client.
    try testing.expectEqual(1, read.closes);
    try testing.expect(!read.levels[@intFromEnum(Level.initial)]);
    try testing.expect(read.levels[@intFromEnum(Level.handshake)]);
}

test "RFC 9000 §10.2.3: a client with no Handshake keys closes in an Initial packet" {
    open_pair();
    // "An endpoint can send a CONNECTION_CLOSE frame in an Initial packet. This might be in
    // response to unauthenticated information received in Initial or Handshake packets."
    // Take the client's Handshake keys away and the Initial becomes the one packet it can send.
    client.keys.state[@intFromEnum(Level.handshake)][@intFromEnum(crypto.suite.Direction.write)] = .none;
    close_module.owe(&client, close_module.transport(test_error_code, null));
    try testing.expect(close_module.carries(&client, .initial));
    const read = try walk_back(&server, (try send_from(&client)).?);
    try testing.expectEqual(1, read.closes);
    try testing.expect(read.levels[@intFromEnum(Level.initial)]);
}

test "RFC 9000 §10.2.3: after the handshake is confirmed the close goes in a 1-RTT packet alone" {
    open_pair();
    install_application();
    server.confirm_handshake();
    server.termination.state = .active;
    close_module.owe(&server, close_module.transport(test_error_code, test_frame_type));
    // "After the handshake is confirmed ... an endpoint MUST send any CONNECTION_CLOSE frames in
    // a 1-RTT packet", so the two handshake levels carry none although their keys are still here.
    try testing.expect(!close_module.carries(&server, .initial));
    try testing.expect(!close_module.carries(&server, .handshake));
    try testing.expect(close_module.carries(&server, .application));
}

test "RFC 9000 §10.2.3, §12.5: an application close becomes a transport close below 1-RTT" {
    const application: close_module.Close = .{
        .layer = .application,
        .error_code = test_error_code,
        .frame_type = null,
        .reason = test_reason,
    };
    // "A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE of type 0x1c when
    // sending the frame in Initial or Handshake packets ... Endpoints MUST clear the value of the
    // Reason Phrase field and SHOULD use the APPLICATION_ERROR code".
    for ([_]Level{ .initial, .handshake }) |level| {
        const shaped = close_module.frame_for(application, level);
        try testing.expectEqual(.transport, shaped.layer);
        try testing.expectEqual(error_code.application_error, shaped.error_code);
        try testing.expectEqual(0, shaped.reason.len);
        // §19.19: a transport close carries the Frame Type field, and 0 says it is unknown.
        try testing.expectEqual(constants.frame_padding, shaped.frame_type.?);
        // §12.5: what goes out is permitted at the level it goes out at, which the original
        // frame was not.
        try testing.expect(frame_module.Frame.permitted_at(.{ .connection_close = shaped }, level));
        try testing.expect(!frame_module.Frame.permitted_at(.{ .connection_close = application }, level));
    }
    // At the application level it goes out as the caller stated it, reason and all.
    const kept = close_module.frame_for(application, .application);
    try testing.expectEqual(.application, kept.layer);
    try testing.expectEqual(test_error_code, kept.error_code);
    try testing.expectEqualSlices(u8, test_reason, kept.reason);
}

test "RFC 9000 §10.2.3: an application close reaches the peer as a transport close at Handshake" {
    open_pair();
    close_module.owe(&client, .{
        .layer = .application,
        .error_code = test_error_code,
        .frame_type = null,
        .reason = test_reason,
    });
    const read = try walk_back(&server, (try send_from(&client)).?);
    try testing.expectEqual(1, read.closes);
    // The peer reads a transport close carrying APPLICATION_ERROR, never the code the
    // application chose, because §10.2.3 forbids revealing application state below 1-RTT.
    try testing.expectEqual(.transport, read.last.?.layer);
    try testing.expectEqual(error_code.application_error, read.last.?.error_code);
}

test "RFC 9000 §10.2: sending the close enters the closing state and then sends nothing else" {
    open_pair();
    close_module.owe(&client, close_module.transport(test_error_code, null));
    try testing.expectEqual(.active, client.termination.state);
    _ = (try send_from(&client)).?;
    // "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state."
    try testing.expectEqual(.closing, client.termination.state);
    try testing.expectEqual(.closed_locally, client.termination.reason.?);
    // §10.2.1: "An endpoint in the closing state sends a packet containing a CONNECTION_CLOSE
    // frame in response to any incoming packet that it attributes to the connection", and it
    // "SHOULD limit the rate at which it generates packets", so nothing goes out until one
    // arrives.
    try testing.expectEqual(null, try send_from(&client));
    client.termination.on_packet_received(test_now_ns);
    const again = (try send_from(&client)).?;
    try testing.expectEqual(1, (try walk_back(&server, again)).closes);
}

test "RFC 9000 §10.2.1: a closing endpoint sends the close and nothing else" {
    open_pair();
    // Give the client handshake octets to send, so a packet would otherwise carry a CRYPTO frame.
    provider_holder.owed = &handshake_flight;
    provider_holder.owed_level = .handshake;
    close_module.owe(&client, close_module.transport(test_error_code, null));
    const read = try walk_back(&server, (try send_from(&client)).?);
    // "In the closing state, an endpoint retains only enough information to generate a packet
    // containing a CONNECTION_CLOSE frame": every packet holds one frame and it is the close.
    try testing.expect(read.closes > 0);
    try testing.expectEqual(read.packets, read.closes);
}

test "RFC 9000 §10.2.2: a draining endpoint sends nothing, and owes no close" {
    open_pair();
    // "an endpoint in the draining state MUST NOT send any packets".
    client.termination.on_close_received(test_now_ns, 1);
    close_module.owe(&client, close_module.transport(test_error_code, null));
    // §10.2.2's MAY — a single close before entering draining — is declined, so nothing is owed.
    try testing.expectEqual(null, client.pending_close);
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9000 §10.2.1: the first close is the one kept, and a later error does not replace it" {
    open_pair();
    close_module.owe(&client, close_module.transport(test_error_code, test_frame_type));
    // "an endpoint retains only enough information to generate a packet containing a
    // CONNECTION_CLOSE frame", which is the first one and not the latest.
    close_module.owe(&client, close_module.transport(error_code.internal_error, null));
    try testing.expectEqual(test_error_code, client.pending_close.?.error_code);
    try testing.expectEqual(test_frame_type, client.pending_close.?.frame_type.?);
}

test "RFC 9000 §19.19: a reason phrase that will not fit gives way rather than the frame" {
    open_pair();
    const long_reason: [datagram_buffer_len]u8 = @splat('r');
    close_module.owe(&client, .{
        .layer = .transport,
        .error_code = test_error_code,
        // §19.19: a 0x1c frame always carries the field, and 0 says the frame is unknown.
        .frame_type = constants.frame_padding,
        .reason = &long_reason,
    });
    // "Because a CONNECTION_CLOSE frame cannot be split between packets, any limits on packet
    // size will also limit the space available for a reason phrase." A buffer that holds the
    // frame but not the reason still gets the frame, with the code the peer acts on.
    var small: [16]u8 = undefined;
    const written = close_module.write(&client, .handshake, &small);
    try testing.expect(written > 0);
    var reader = core.Reader.init(small[0..written]);
    const read_back = (try frame_module.read(&reader)).connection_close;
    try testing.expectEqual(test_error_code, read_back.error_code);
    try testing.expectEqual(0, read_back.reason.len);
    // A buffer too small for even the bare frame gets nothing, rather than a split one.
    var tiny: [1]u8 = undefined;
    try testing.expectEqual(0, close_module.write(&client, .handshake, &tiny));
}

test "RFC 9000 §10.2.3: a connection owing no close writes none, at any level" {
    open_pair();
    install_application();
    try testing.expect(!close_module.owes(&client));
    var buffer: [64]u8 = undefined;
    // Bounded by the levels, of which RFC 9001 §4.1.4 names three.
    for (0..core.levels_count) |index| {
        const level: Level = @enumFromInt(index);
        try testing.expect(!close_module.carries(&client, level));
        try testing.expectEqual(0, close_module.write(&client, level, &buffer));
    }
    // And a level with no keys carries none even once one is owed (RFC 9001 §4.9).
    close_module.owe(&client, close_module.transport(test_error_code, null));
    try testing.expect(close_module.owes(&client));
    client.keys.state[@intFromEnum(Level.application)][@intFromEnum(crypto.suite.Direction.write)] = .discarded;
    try testing.expect(!close_module.carries(&client, .application));
}

test "RFC 9000 §19.19: a transport close with no triggering frame names frame type 0" {
    open_pair();
    // "A value of 0 (equivalent to the mention of the PADDING frame) is used when the frame type
    // is unknown", and unlike a 0x1d frame a 0x1c frame always carries the field.
    const unknown = close_module.transport(test_error_code, null);
    try testing.expectEqual(constants.frame_padding, unknown.frame_type.?);
    try testing.expectEqual(
        test_frame_type,
        close_module.transport(test_error_code, test_frame_type).frame_type.?,
    );
    // It reaches the peer that way, read back through the frame layer rather than trusted here.
    close_module.owe(&client, unknown);
    var buffer: [32]u8 = undefined;
    const written = close_module.write(&client, .handshake, &buffer);
    var reader = core.Reader.init(buffer[0..written]);
    const read_back = (try frame_module.read(&reader)).connection_close;
    try testing.expectEqual(constants.frame_padding, read_back.frame_type.?);
    try testing.expectEqual(test_error_code, read_back.error_code);
}

test "RFC 9000 §13.2.1: a packet carrying only a close elicits no acknowledgment" {
    open_pair();
    close_module.owe(&client, close_module.transport(test_error_code, null));
    const sent = (try send_from(&client)).?;
    // Table 3 marks CONNECTION_CLOSE N, because there is no longer a connection to acknowledge
    // it on. RFC 9002 §2 then keeps the packet out of flight, having no padding either.
    try testing.expect(sent.count > 0);
    for (sent.written()) |packet| {
        try testing.expect(!packet.ack_eliciting);
        try testing.expect(!packet.in_flight);
    }
}

test "RFC 9000 §8.1, §10.2.1: a server that has received nothing sends no close" {
    open_pair();
    // §10.2.1: a closing endpoint "MUST either discard packets received from an unvalidated
    // address or limit the cumulative size of packets it sends to an unvalidated address to
    // three times the size of packets it receives from that address". Three times nothing is
    // nothing, and that bounds the datagram rather than tripping an assertion.
    server.path.init(.unvalidated);
    try testing.expectEqual(0, server.path.send_allowance());
    close_module.owe(&server, close_module.transport(test_error_code, null));
    try testing.expectEqual(null, try send_from(&server));
    // One datagram in and the close goes out, inside what §8.1 allows.
    server.path.on_datagram_received(constants.datagram_len_min);
    const allowance = server.path.send_allowance();
    const sent = (try send_from(&server)).?;
    try testing.expect(sent.len <= allowance);
    try testing.expect(sent.count > 0);
}
