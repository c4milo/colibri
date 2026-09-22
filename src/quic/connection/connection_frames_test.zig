//! The tests of `connection_frames.zig`: RFC 9000 §12.4's walk over one packet's payload, and
//! every rule that closes the connection rather than discarding.
//!
//! The frames are written by `frame.write`, which step 9a already proved round-trips, so what
//! these cases pin is what the connection does with them and not how they are encoded.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const identity_module = @import("connection_identity.zig");
const frames = @import("connection_frames.zig");

const testing = std.testing;

/// RFC 9000 §19.16's rule turns on which connection ID a packet was addressed to, and a case
/// that is not about that rule says the packet named none this endpoint issued.
const addressed_to_none: ?u64 = null;
const Level = core.Level;
const Writer = core.Writer;
const Frame = frame_module.Frame;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
const payload_len: usize = 256;
var payload: [payload_len]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

fn open_as(role: connection_module.Role) void {
    test_connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
}

/// Writes `list` into `payload` and returns the octets, which is what one opened packet holds.
fn frames_of(list: []const Frame) []const u8 {
    var writer = Writer.init(&payload);
    for (list) |held| frame_module.write(&writer, held) catch unreachable;
    return writer.written();
}

fn run(level: Level, list: []const Frame) frames.Error!frames.Report {
    return frames.process(&test_connection, .{ .level = level, .payload = frames_of(list) }, test_now_ns);
}

/// A CONNECTION_CLOSE of each layer (RFC 9000 §19.19). The transport one carries a Frame Type
/// and the application one does not: "an endpoint that uses this frame type to signal an
/// application error does not include this field", and §19.19 makes 0 the value "used when the
/// frame type is unknown".
const close_code: u64 = 0x0a;
const frame_type_unknown: u64 = 0;
fn close_frame(layer: frame_module.CloseLayer) Frame {
    return .{ .connection_close = .{
        .layer = layer,
        .error_code = close_code,
        .frame_type = if (layer == .transport) frame_type_unknown else null,
        .reason = &.{},
    } };
}

test "RFC 9000 §12.4: a packet with no frames is a connection error" {
    open_as(.client);
    // "An endpoint MUST treat receipt of a packet containing no frames as a connection error of
    // type PROTOCOL_VIOLATION."
    try testing.expectError(frames.Error.EmptyPayload, frames.process(&test_connection, .{ .level = .initial, .payload = &.{} }, test_now_ns));
    try testing.expectEqual(
        error_code.protocol_violation,
        frames.connection_error_code(frames.Error.EmptyPayload),
    );
}

test "RFC 9000 §12.4: a frame the level does not permit closes the connection" {
    open_as(.client);
    // HANDSHAKE_DONE is marked ___1 in Table 3, so it may appear in a 1-RTT packet alone.
    const held = [_]Frame{.handshake_done};
    try testing.expectError(frames.Error.FrameNotPermitted, run(.initial, &held));
    try testing.expectError(frames.Error.FrameNotPermitted, run(.handshake, &held));
    try testing.expectEqual(
        error_code.protocol_violation,
        frames.connection_error_code(frames.Error.FrameNotPermitted),
    );
    // And at the application level the same frame is taken, which is what makes the refusal
    // about the level rather than about the frame.
    open_as(.client);
    const report = try run(.application, &held);
    try testing.expect(report.ack_eliciting);
    try testing.expect(test_connection.handshake_confirmed);
}

test "RFC 9000 §19.20: a server that receives HANDSHAKE_DONE closes the connection" {
    open_as(.server);
    // "A server MUST treat receipt of a HANDSHAKE_DONE frame as a connection error of type
    // PROTOCOL_VIOLATION", because only a server sends one.
    try testing.expectError(frames.Error.HandshakeDoneFromClient, run(.application, &.{.handshake_done}));
    try testing.expect(!test_connection.handshake_confirmed);
}

test "RFC 9000 §13.2.1: PADDING and ACK elicit nothing and PING does" {
    open_as(.client);
    // Table 3 marks PADDING and ACK N, so a packet of only those is not ack-eliciting.
    const quiet = [_]Frame{ .{ .padding = .{ .len = 3 } }, .{ .ack = ack_of(0) } };
    _ = test_connection.space_at(.initial).next_number() catch unreachable;
    const first = try run(.initial, &quiet);
    try testing.expect(!first.ack_eliciting);

    // PING exists for no other purpose (§19.2).
    const loud = [_]Frame{ .{ .padding = .{ .len = 3 } }, .ping };
    const second = try run(.initial, &loud);
    try testing.expect(second.ack_eliciting);
}

test "RFC 9000 §13.1: an ACK for a packet never sent closes the connection" {
    open_as(.client);
    // Nothing has been sent in this space, so every number an ACK could name is one this
    // endpoint did not send.
    try testing.expectError(frames.Error.AcknowledgedUnsentPacket, run(.initial, &.{.{ .ack = ack_of(0) }}));
    try testing.expectEqual(
        error_code.protocol_violation,
        frames.connection_error_code(frames.Error.AcknowledgedUnsentPacket),
    );
}

test "RFC 9000 §19.9, §4.1: MAX_DATA raises the send limit and never lowers it" {
    open_as(.client);
    // §18.2 leaves what colibri may send at zero until the peer says otherwise, which is the
    // state a connection begins in.
    try testing.expectEqual(0, test_connection.send_flow.available());
    _ = try run(.application, &.{.{ .max_data = .{ .maximum = test_max_data } }});
    try testing.expectEqual(test_max_data, test_connection.send_flow.available());
    // §4.1: "an endpoint MUST NOT send a MAX_DATA frame with a smaller value", and a receiver
    // ignores one rather than closing, because a reordered frame is not an error.
    _ = try run(.application, &.{.{ .max_data = .{ .maximum = 1 } }});
    try testing.expectEqual(test_max_data, test_connection.send_flow.available());
}

test "RFC 9000 §10.2.2: a CONNECTION_CLOSE puts the connection in draining" {
    open_as(.client);
    const report = try run(.application, &.{close_frame(.application)});
    try testing.expectEqual(close_code, report.close.?.error_code);
    try testing.expectEqual(frame_module.CloseLayer.application, report.close.?.layer);
    // §10.2.2: an endpoint that receives one enters the draining state and sends nothing more.
    try testing.expectEqual(.draining, test_connection.termination.state);

    // §12.5 admits only the transport layer's below the application level, which `permitted_at`
    // already refuses; the transport one is taken at the Initial level.
    open_as(.client);
    const early = try run(.initial, &.{close_frame(.transport)});
    try testing.expectEqual(frame_module.CloseLayer.transport, early.close.?.layer);
    try testing.expectError(frames.Error.FrameNotPermitted, run(.initial, &.{close_frame(.application)}));
}

test "RFC 9000 §12.4: every frame of the packet is read, not only the first" {
    open_as(.client);
    const held = [_]Frame{
        .{ .padding = .{ .len = 2 } },
        .ping,
        .{ .max_data = .{ .maximum = test_max_data } },
        .{ .data_blocked = .{ .limit = 0 } },
    };
    const report = try run(.application, &held);
    // A run of PADDING is one frame to the reader (§19.1), so four written are four read.
    try testing.expectEqual(4, report.frames);
    try testing.expectEqual(test_max_data, test_connection.send_flow.available());
    try testing.expect(report.ack_eliciting);
}

test "RFC 9000 §19: a frame that will not parse is a FRAME_ENCODING_ERROR" {
    open_as(.client);
    // §12.4: "An endpoint MUST treat the receipt of a frame of unknown type as a connection
    // error of type FRAME_ENCODING_ERROR." 0x40 is a two-octet varint of 0, so it reads as a
    // type this version does not define rather than as PADDING.
    const unknown = [_]u8{ 0x3f, 0x00 };
    try testing.expectError(
        frames.Error.FrameEncoding,
        frames.process(&test_connection, .{ .level = .application, .payload = &unknown }, test_now_ns),
    );
    try testing.expectEqual(
        error_code.frame_encoding_error,
        frames.connection_error_code(frames.Error.FrameEncoding),
    );
}

/// One 1-RTT packet's frames under a named key set (RFC 9001 §6.5), which §6.2's last rule reads.
fn run_with(key_set: crypto.suite.KeySet, list: []const Frame) frames.Error!frames.Report {
    return frames.process(
        &test_connection,
        .{ .level = .application, .payload = frames_of(list), .key_set = key_set },
        test_now_ns,
    );
}

/// Spends `count` packet numbers in `level`'s space, so an ACK naming one of them is not
/// RFC 9000 §13.1's acknowledgment of a packet that was never sent.
fn spend_numbers(level: Level, count: usize) void {
    for (0..count) |_| _ = test_connection.space_at(level).next_number() catch unreachable;
}

test "RFC 9001 §6.2: an ACK under old keys naming a new-keys packet closes the connection" {
    open_as(.client);
    spend_numbers(.application, 5);
    // RFC 9001 §6.1: packet 4 and every number above it went out under the current key phase.
    test_connection.key_phase.lowest_sent = 4;

    // An ACK naming only the phase before is what §6.5 keeps the old read keys for.
    _ = try run_with(.previous, &.{.{ .ack = ack_of(3) }});
    // One naming a packet of the current phase says the peer "received and acknowledged a packet
    // that initiates a key update, but has not updated keys in response".
    try testing.expectError(
        frames.Error.OldKeysAcknowledgeNew,
        run_with(.previous, &.{.{ .ack = ack_of(4) }}),
    );
    // RFC 9001 §6.7: KEY_UPDATE_ERROR is 0x0e.
    try testing.expectEqual(
        error_code.key_update_error,
        frames.connection_error_code(frames.Error.OldKeysAcknowledgeNew),
    );
}

test "RFC 9001 §6.2: the same ACK under keys that are not old is legal" {
    open_as(.client);
    spend_numbers(.application, 5);
    test_connection.key_phase.lowest_sent = 4;
    // §6.2's rule is about the keys the acknowledgment arrived under, so the same frame under the
    // current keys is a peer that answered the update, and under the next it is one updating now.
    _ = try run_with(.current, &.{.{ .ack = ack_of(4) }});
    _ = try run_with(.next, &.{.{ .ack = ack_of(4) }});
}

test "RFC 9001 §6.2: an old-keys ACK is legal before the phase has sent anything" {
    open_as(.client);
    spend_numbers(.application, 5);
    // Nothing has gone out under the current keys, so no packet the ACK names was protected with
    // them and §6.2's rule cannot be met.
    try testing.expectEqual(null, test_connection.key_phase.lowest_sent);
    _ = try run_with(.previous, &.{.{ .ack = ack_of(4) }});
}

/// An ACK naming one packet and nothing else (RFC 9000 §19.3).
fn ack_of(largest: u64) frame_module.Ack {
    return .{
        .ranges = .{ .largest_acknowledged = largest, .first_range = 0, .octets = &.{}, .count = 0 },
        .delay = 0,
        .ecn = null,
    };
}
