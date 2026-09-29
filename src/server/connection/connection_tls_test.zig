//! The tests of the server's TLS half (`connection_tls.zig`): a colibri client runs the handshake
//! against the connection in memory, and ALPN's choice serves h2 or h11 over the records.
const std = @import("std");
const h2 = @import("h2");
const tls = @import("tls");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
/// The client connection preface, then an empty SETTINGS frame (RFC 9113 §3.4).
const client_preface = h2.constants.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
/// A HEADERS frame on stream 1 ending it, whose block is the static table's `:method: GET` (2),
/// `:scheme: https` (7) and `:path: /` (4), each an indexed field line (RFC 7541 §6.1, Appendix A).
const get_frame = "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";

/// A frame's header: a length of three octets, big-endian, then its type and its flags (RFC 9113
/// §4.1).
const length_len: usize = 3;
const type_index: usize = length_len;
const flags_index: usize = length_len + 1;

/// The first DATA frame of `frames`, or null. Test-only.
fn data_frame(frames: []const u8) ?[]const u8 {
    var rest = frames;
    // Bounded: each pass drops a frame's header at least.
    for (0..frames.len) |_| {
        if (rest.len < h2.constants.frame_header_len) return null;
        const frame_len = h2.constants.frame_header_len + std.mem.readInt(u24, rest[0..length_len], .big);
        if (rest[type_index] == h2.constants.frame_type_data) return rest[0..frame_len];
        rest = rest[frame_len..];
    }
    return null;
}

test "RFC 7301 §3.2: ALPN's h2 serves the connection, and a response comes back sealed" {
    try support.start_tls(&support.protocols_both, &support.protocols_h2);
    try testing.expectEqual(.h2, connection.protocol().?);
    try testing.expectEqualStrings("localhost", connection.server_name().?);
    const received = try support.receive_sealed(client_preface ++ get_frame);
    const head = received.event.?.request;
    try testing.expectEqual(1, head.id);
    try testing.expectEqualStrings("https", head.scheme.?);
    try connection.respond(1, .{ .status = ok, .end = false });
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    const data = data_frame(try support.open_sent()).?;
    // The connection goes on, so no close_notify follows the response.
    try testing.expect(!support.client_saw_alert);
    try testing.expectEqual(h2.constants.flag_end_stream, data[flags_index]);
    try testing.expectEqualStrings("hello", data[h2.constants.frame_header_len..]);
}

test "decision 88: ALPN's http/1.1 serves h11, and the close_notify follows the last response" {
    try support.start_tls(&support.protocols_both, &support.protocols_h11);
    try testing.expectEqual(.h11, connection.protocol().?);
    const received = try support.receive_sealed("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const head = received.event.?.request;
    // RFC 9112 §3.3: a secured connection's target URI has the https scheme.
    try testing.expectEqualStrings("https", head.scheme.?);
    try connection.respond(head.id, .{ .status = ok, .end = true });
    const opened = try support.open_sent();
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-length: 0\r\nConnection: close\r\n\r\n", opened);
    // RFC 9112 §9.8, RFC 9846 §6.1: the server closes after the exchange of closure alerts starts.
    try testing.expect(support.client_saw_alert);
    try testing.expect(connection.should_close());
}

test "RFC 9846 §6.1: the peer's close_notify ends its data, and this side's follows" {
    try support.start_tls(&support.protocols_both, &support.protocols_h11);
    const provider = support.client.provider();
    const close_len = try provider.vtable.send_close_notify(provider.context, &support.input);
    const received = try connection.receive(support.input[0..close_len], support.now_ns);
    try testing.expectEqual(close_len, received.consumed);
    try testing.expectEqual(null, received.event);
    try testing.expect(!connection.should_close());
    _ = try support.open_sent();
    try testing.expect(support.client_saw_alert);
    try testing.expect(connection.should_close());
}

test "RFC 7301 §3.2: a handshake with no protocol in common ends with the server's alert" {
    try support.server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols_h2,
    });
    try support.client_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = "localhost" } },
        .alpn = &support.protocols_h11,
    });
    support.config = .{ .tls = &support.server_config };
    try connection.init(&support.config, support.stream.random(), support.now_seconds);
    try support.client.start(&support.client_config, support.stream.random(), support.now_seconds, null);
    const hello = try support.client.handshake(&.{}, &support.input);
    try testing.expectError(error.ConnectionFailed, connection.receive(support.input[0..hello.written], support.now_ns));
    try testing.expectEqual(null, connection.protocol());
    try testing.expect(!connection.should_close());
    const sent = connection.send(&support.output, support.now_ns);
    // RFC 9846 §6.2: the alert is the last record, and nothing follows it.
    try testing.expect(sent > support.record_header_len);
    try testing.expectEqual(support.content_alert, support.output[0]);
    try testing.expect(connection.should_close());
}

test "RFC 9846 §6: a record the provider refuses ends the connection with no data after it" {
    try support.start_tls(&support.protocols_both, &support.protocols_h2);
    // Octets that are no record chapulin will open: an application_data header over garbage.
    const forged = "\x17\x03\x03\x00\x20" ++ "\x00" ** 32;
    @memcpy(support.input[0..forged.len], forged);
    try testing.expectError(error.ConnectionFailed, connection.receive(support.input[0..forged.len], support.now_ns));
    // What goes out is the alert chapulin owes, and the connection closes after it.
    _ = connection.send(&support.output, support.now_ns);
    try testing.expect(connection.should_close());
    try testing.expectError(error.ConnectionClosed, connection.respond(1, .{ .status = ok, .end = true }));
    // RFC 9846 §6: nothing more is read after the failure.
    const after = try connection.receive(support.input[0..forged.len], support.now_ns);
    try testing.expectEqual(0, after.consumed);
}

test "RFC 9846 §9.2: a configuration chapulin cannot serve from is refused at the start" {
    try support.server_config.init(.{ .cookie_key = &support.cookie_key, .alpn = &support.protocols_h2 });
    support.config = .{ .tls = &support.server_config };
    try testing.expectError(error.TlsRefused, connection.init(&support.config, support.stream.random(), support.now_seconds));
}

test "RFC 9846 §4.1: the handshake waits for room for a whole flight, and answers before a request" {
    try support.server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols_both,
    });
    try support.client_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = "localhost" } },
        .alpn = &support.protocols_h11,
    });
    support.config = .{ .tls = &support.server_config };
    try connection.init(&support.config, support.stream.random(), support.now_seconds);
    // RFC 9110 §3.4: no request has arrived, so there is none to answer.
    try testing.expectError(error.RequestUnknown, connection.respond(1, .{ .status = ok, .end = true }));
    try testing.expectError(error.RequestUnknown, connection.write_body(1, .{ .octets = "x", .end = true }));
    try testing.expectError(error.RequestUnknown, connection.write_trailers(1, &.{}));
    try support.client.start(&support.client_config, support.stream.random(), support.now_seconds, null);
    const hello = try support.client.handshake(&.{}, &support.input);
    connection.output_len = support.server_constants.output_len - support.server_constants.flight_len_max + 1;
    const waiting = try connection.receive(support.input[0..hello.written], support.now_ns);
    try testing.expectEqual(0, waiting.consumed);
    connection.output_len = 0;
    const flight = try connection.receive(support.input[0..hello.written], support.now_ns);
    try testing.expectEqual(hello.written, flight.consumed);
    try testing.expect(connection.output_len > 0);
}

test "RFC 9846 §6.1: a transport that closed ends the connection, and its secrets are wiped" {
    try support.start_tls(&support.protocols_both, &support.protocols_h11);
    _ = try support.receive_sealed("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expect(!connection.should_close());
    // Idempotent: the second call leaves the connection as the first did.
    for (0..2) |_| {
        connection.transport_closed();
        try testing.expect(connection.should_close());
        try testing.expectEqual(null, (try connection.receive(&.{}, support.now_ns)).event);
        try testing.expectEqual(0, connection.send(&support.output, support.now_ns));
        try testing.expectEqual(.closed, connection.tls_server.session.recordState());
        try testing.expectError(error.ConnectionClosed, connection.respond(1, .{ .status = ok, .end = true }));
    }
}

/// A request with content, then DATA frames of the largest payload colibri advertises, which
/// straddle the client's records, each of the largest plaintext. Test-only.
const upload_frames: usize = 3;
var upload: [upload_len]u8 = undefined;
const upload_len: usize = upload_frames * (h2.constants.frame_header_len + h2.constants.frame_size_max);
/// A HEADERS frame on stream 1 that leaves it open, whose block is the static table's
/// `:method: POST` (3), `:scheme: https` (7) and `:path: /` (4) (RFC 7541 Appendix A).
const post_frame = "\x00\x00\x03\x01\x04\x00\x00\x00\x01\x83\x87\x84";

test "RFC 9846 §5.2: records open while a frame waits for its last octets, so content arrives whole" {
    try support.start_tls(&support.protocols_both, &support.protocols_h2);
    // The DATA frames start a record, so a whole record holds all of a frame but its last 9
    // octets, and the next record opens only into room for what follows its header.
    var sealed_len = try support.seal_all(0, client_preface ++ post_frame);
    var writer = h2.core.Writer.init(&upload);
    var content: [h2.constants.frame_size_max]u8 = @splat('u');
    for (0..upload_frames) |index| try h2.frame.write_data(&writer, 1, &content, index + 1 == upload_frames, 0);
    sealed_len = try support.seal_all(sealed_len, writer.written());
    var consumed: usize = 0;
    var received_len: usize = 0;
    var ended = false;
    // Bounded: each pass takes a record or reports an event, or the connection is stuck.
    for (0..sealed_len) |_| {
        const received = try connection.receive(support.input[consumed..sealed_len], support.now_ns);
        consumed += received.consumed;
        _ = connection.send(&support.output, support.now_ns);
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        if (event == .body) {
            received_len += event.body.octets.len;
            ended = event.body.end;
        }
    }
    try testing.expectEqual(sealed_len, consumed);
    try testing.expectEqual(upload_frames * h2.constants.frame_size_max, received_len);
    try testing.expect(ended);
}
