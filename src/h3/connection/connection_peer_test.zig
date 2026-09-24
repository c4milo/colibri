//! The tests of `connection_peer.zig` and `connection_local.zig`: the peer's unidirectional
//! streams (RFC 9114 §6.2), its control stream (§6.2.1, §7.2) and QPACK's streams (RFC 9204
//! §4.2), each rule broken by a peer that writes raw octets. The harness is `connection_test.zig`'s.
const std = @import("std");
const core = @import("core");
const quic = @import("quic");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const harness = @import("connection_test.zig");

const Event = connection_module.Event;
const StreamId = quic.stream.StreamId;
const testing = std.testing;

const client = &harness.client;
const server = &harness.server;
const exchange = harness.exchange;
const next = harness.next;

/// A client whose h3 is not started, so a test writes its control stream itself, and a server
/// that is.
fn pair_raw_client() !void {
    harness.pair_unstarted(.{ .role = .client }, .{ .role = .server });
    try server.h3.start(&server.transport);
}

/// Opens a unidirectional stream at the client and writes `octets` on it.
fn client_stream(octets: []const u8, fin: bool) !u64 {
    const id = try quic.connection_stream_send.open(&client.transport, .unidirectional);
    try client.send_raw(id.value, octets, fin);
    return id.value;
}

/// Room for what a test writes on a raw control stream. Test-only.
const control_len_max: usize = 64;

/// A control stream's type and an empty SETTINGS frame, which open every raw control stream.
const control_start = [_]u8{ constants.stream_control, constants.frame_settings, 0x00 };

fn expect_failure(endpoint: *harness.Endpoint, code: u64) !void {
    try testing.expectError(error.ConnectionFailed, next(endpoint));
    try testing.expectEqual(code, endpoint.h3.failure.?);
}

/// Opens a raw control stream at the client carrying `after` past its SETTINGS, and reads it at
/// the server until the server fails with `code`.
fn expect_control_failure(after: []const u8, code: u64) !void {
    try pair_raw_client();
    var octets: [control_len_max]u8 = undefined;
    @memcpy(octets[0..control_start.len], &control_start);
    @memcpy(octets[control_start.len..][0..after.len], after);
    _ = try client_stream(octets[0 .. control_start.len + after.len], false);
    try exchange();
    try testing.expectEqual(Event.settings, (try next(server)).?);
    try expect_failure(server, code);
}

test "§6.2.1: a control stream whose first frame is not SETTINGS is H3_MISSING_SETTINGS" {
    try pair_raw_client();
    // A GOAWAY naming stream 0.
    _ = try client_stream(&.{ constants.stream_control, constants.frame_goaway, 0x01, 0x00 }, false);
    try exchange();
    try expect_failure(server, constants.error_missing_settings);
}

test "§6.2.1, RFC 9204 §4.2: a second stream of a critical kind is H3_STREAM_CREATION_ERROR" {
    for ([_]u8{ constants.stream_control, constants.stream_qpack_encoder, constants.stream_qpack_decoder }) |kind| {
        try harness.pair(.{ .role = .client }, .{ .role = .server });
        _ = try client_stream(&.{kind}, false);
        try exchange();
        try expect_failure(server, constants.error_stream_creation);
    }
}

test "§6.2.1: a control stream that ends after its SETTINGS fails at once, reporting nothing" {
    try pair_raw_client();
    _ = try client_stream(&control_start, true);
    try exchange();
    // §6.2.1: "If either control stream is closed at any point, this MUST be treated as a
    // connection error", so the SETTINGS it carried are never reported.
    try expect_failure(server, constants.error_closed_critical_stream);
}

test "§6.2.1, RFC 9204 §4.2: a critical stream that ends is H3_CLOSED_CRITICAL_STREAM" {
    for ([_]u8{ constants.stream_control, constants.stream_qpack_encoder, constants.stream_qpack_decoder }) |kind| {
        try pair_raw_client();
        if (kind != constants.stream_control) _ = try client_stream(&control_start, false);
        _ = try client_stream(&.{kind}, true);
        try exchange();
        var event = next(server);
        if (event) |held| {
            try testing.expectEqual(Event.settings, held.?);
            event = next(server);
        } else |_| {}
        try testing.expectError(error.ConnectionFailed, event);
        try testing.expectEqual(constants.error_closed_critical_stream, server.h3.failure.?);
    }
}

test "§7.2.4: a second SETTINGS frame is H3_FRAME_UNEXPECTED" {
    try expect_control_failure(&.{ constants.frame_settings, 0x00 }, constants.error_frame_unexpected);
}

test "§7.2.1, §7.2.2, §7.2.8: DATA, HEADERS or an HTTP/2 type on the control stream is H3_FRAME_UNEXPECTED" {
    for ([_]u8{ constants.frame_data, constants.frame_headers, 0x06 }) |frame_type| {
        try expect_control_failure(&.{ frame_type, 0x00 }, constants.error_frame_unexpected);
    }
}

test "§7.2.4.1: an HTTP/2 setting is H3_SETTINGS_ERROR" {
    try pair_raw_client();
    // SETTINGS_ENABLE_PUSH, 0x02, which HTTP/3 reserves.
    _ = try client_stream(&.{ constants.stream_control, constants.frame_settings, 0x02, 0x02, 0x00 }, false);
    try exchange();
    try expect_failure(server, constants.error_settings_error);
}

test "§10.5: a control frame longer than colibri holds is H3_EXCESSIVE_LOAD" {
    // A GOAWAY whose Length, 0x5000 in four octets, is past the connection's scratch.
    try expect_control_failure(&.{ constants.frame_goaway, 0x80, 0x00, 0x50, 0x00 }, constants.error_excessive_load);
}

test "§6.2.1: a peer that stops colibri's control stream has closed it" {
    // Once with room in the control stream's buffer, and once with the buffer so full that h3
    // asks `quic` what was acknowledged first.
    for ([_]bool{ false, true }) |full| {
        try harness.pair(.{ .role = .client }, .{ .role = .server });
        const control = &server.h3.local.control;
        if (full) try control.write(filler[0 .. control.free().remaining_len() - 1]);
        // §6.2.1: "the receiver MUST NOT request that the sender close the control stream".
        try quic.connection_stream_send.stop_sending(&client.transport, .{ .value = server.h3.local.control_id.? }, 0);
        try exchange();
        try testing.expectError(error.ConnectionFailed, server.h3.shutdown(&server.transport));
        try testing.expectEqual(constants.error_closed_critical_stream, server.h3.failure.?);
    }
}

/// Octets that fill a buffer. Test-only.
var filler: [constants.control_buffer_len]u8 = @splat(0);

test "§6.2: a unidirectional stream that ends before its type is tolerated, and forgotten" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    _ = try client_stream(&.{}, true);
    try exchange();
    try testing.expectEqual(null, try next(server));
    for (server.h3.peer.slots) |slot| try testing.expectEqual(null, slot);
}

test "§7.2.4.1: colibri's SETTINGS carry a reserved setting drawn from the grease value" {
    harness.pair_unstarted(.{ .role = .client, .grease = 5 }, .{ .role = .server });
    try client.h3.start(&client.transport);
    // Identifier 0x1f * 5 + 0x21 = 0xbc, a two-octet varint, and the value 5.
    const control = &client.h3.local.control;
    try testing.expect(std.mem.indexOf(u8, control.octets[0..control.len], &.{ 0x40, 0xbc, 0x05 }) != null);
}

test "§7.2.3: a CANCEL_PUSH is H3_ID_ERROR, colibri having promised and allowed nothing" {
    try expect_control_failure(&.{ constants.frame_cancel_push, 0x01, 0x00 }, constants.error_id_error);
}

test "§7.2.7: a MAX_PUSH_ID that falls is H3_ID_ERROR at a server" {
    try expect_control_failure(&.{ constants.frame_max_push_id, 0x01, 0x05, constants.frame_max_push_id, 0x01, 0x04 }, constants.error_id_error);
}

test "§7.2.7: a MAX_PUSH_ID at a client is H3_FRAME_UNEXPECTED" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = server.h3.local.control_id.?;
    // The server's control stream octets are h3's, so the raw frame goes into its buffer.
    try server.h3.local.control.write(&.{ constants.frame_max_push_id, 0x01, 0x00 });
    try quic.connection_stream_send.supply(&server.transport, .{ .value = id }, server.h3.local.control.end_offset(), false);
    try exchange();
    try expect_failure(client, constants.error_frame_unexpected);
}

test "§5.2, §7.2.6: GOAWAY is reported, and one that rises is H3_ID_ERROR" {
    try pair_raw_client();
    _ = try client_stream(&(control_start ++ [_]u8{ constants.frame_goaway, 0x01, 0x04, constants.frame_goaway, 0x01, 0x08 }), false);
    try exchange();
    try testing.expectEqual(Event.settings, (try next(server)).?);
    try testing.expectEqual(Event{ .goaway = 4 }, (try next(server)).?);
    try expect_failure(server, constants.error_id_error);
}

test "§7.2.6: a client refuses a GOAWAY naming a stream that is not a client's bidirectional one" {
    // Stream 2 is a client's unidirectional stream, and stream 1 a server's bidirectional one.
    for ([_]u8{ 0x02, 0x01 }) |named| {
        try harness.pair(.{ .role = .client }, .{ .role = .server });
        const id = server.h3.local.control_id.?;
        try server.h3.local.control.write(&.{ constants.frame_goaway, 0x01, named });
        try quic.connection_stream_send.supply(&server.transport, .{ .value = id }, server.h3.local.control.end_offset(), false);
        try exchange();
        try expect_failure(client, constants.error_id_error);
    }
}

test "§9: a frame of unknown type on the control stream is skipped" {
    try pair_raw_client();
    _ = try client_stream(&(control_start ++ [_]u8{ 0x21, 0x02, 'a', 'b', constants.frame_goaway, 0x01, 0x00 }), false);
    try exchange();
    try testing.expectEqual(Event.settings, (try next(server)).?);
    try testing.expectEqual(Event{ .goaway = 0 }, (try next(server)).?);
}

test "§6.2: a stream of unknown type is stopped with H3_STREAM_CREATION_ERROR, and means nothing" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    // §6.2.3's reserved stream type 0x21, and a few octets.
    const id = try client_stream(&.{ 0x21, 'x', 'y' }, false);
    try exchange();
    try testing.expectEqual(null, try next(server));
    const stream = server.transport.streams.lookup(.{ .value = id }).live;
    try testing.expect(stream.stop_sending.owed);
    try testing.expectEqual(constants.error_stream_creation, stream.stop_error_code);
    // What arrives later is taken and dropped, and the stream ends.
    try client.send_raw(id, "zz", true);
    try exchange();
    try testing.expectEqual(null, try next(server));
    try testing.expect(server.transport.streams.lookup(.{ .value = id }) != .live);
    for (server.h3.peer.slots) |slot| try testing.expectEqual(null, slot);
}

test "§4.6, §6.2.2: a push stream is H3_ID_ERROR at a client and H3_STREAM_CREATION_ERROR at a server" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    _ = try client_stream(&.{ constants.stream_push, 0x00 }, false);
    try exchange();
    try expect_failure(server, constants.error_stream_creation);
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = try quic.connection_stream_send.open(&server.transport, .unidirectional);
    try server.send_raw(id.value, &.{ constants.stream_push, 0x00 }, false);
    try exchange();
    try expect_failure(client, constants.error_id_error);
}

test "§6.1: a server-initiated bidirectional stream is H3_STREAM_CREATION_ERROR at a client" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = try quic.connection_stream_send.open(&server.transport, .bidirectional);
    try server.send_raw(id.value, &.{ constants.frame_headers, 0x00 }, false);
    try exchange();
    try expect_failure(client, constants.error_stream_creation);
}

test "RFC 9204 §4.3, §6: an encoder instruction the decoder refuses is QPACK_ENCODER_STREAM_ERROR" {
    try pair_raw_client();
    _ = try client_stream(&control_start, false);
    // An insert naming static entry 99, which Appendix A does not have.
    _ = try client_stream(&.{ constants.stream_qpack_encoder, 0xff, 0x24, 0x00 }, false);
    try exchange();
    // The QPACK streams are read before the control stream, so the failure comes first.
    try expect_failure(server, 0x201);
}

test "RFC 9204 §4.4, §6: a decoder instruction the encoder refuses is QPACK_DECODER_STREAM_ERROR" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    // An Insert Count Increment of zero (§4.4.3).
    try client.h3.local.decoder.write(&.{0x00});
    const id = client.h3.local.decoder_id.?;
    try quic.connection_stream_send.supply(&client.transport, .{ .value = id }, client.h3.local.decoder.end_offset(), false);
    try exchange();
    try expect_failure(server, 0x202);
}

test "§6.2: a peer that allows fewer than three unidirectional streams fails h3's start" {
    harness.pair_unstarted(.{ .role = .client }, .{ .role = .server });
    client.transport.streams.local_limit[@intFromEnum(quic.stream.Directionality.unidirectional)] = .init(2);
    try testing.expectError(error.ConnectionFailed, client.h3.start(&client.transport));
    try testing.expectEqual(constants.error_general_protocol, client.h3.failure.?);
}

test "§8.1: colibri sends a reserved code in place of H3_NO_ERROR every other time" {
    harness.pair_unstarted(.{ .role = .client, .grease = 7 }, .{ .role = .server });
    const first = client.h3.no_error_code();
    const second = client.h3.no_error_code();
    try testing.expectEqual(constants.error_no_error, first);
    try testing.expect(constants.is_reserved(second));
    _ = core;
    _ = StreamId;
}
