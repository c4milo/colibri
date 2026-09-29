//! The tests of the h3 advertisement a TCP connection makes when its configuration names an
//! alternative (`alt_svc.zig`): an Alt-Svc line on each final h11 response over TLS (RFC 7838 §3),
//! one ALTSVC frame per h2 connection over TLS (RFC 7838 §4), and nothing in cleartext (RFC 9114
//! §3.1.2).
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
const early_hints: u16 = 103;
/// The h3 endpoint the tests advertise: its UDP port and its max age in seconds. Test-only.
const h3_port: u16 = 8443;
const max_age_seconds: u32 = 60;
const alternative: support.Alternative = .{ .port = h3_port, .max_age_seconds = max_age_seconds };

/// The client connection preface, then an empty SETTINGS frame (RFC 9113 §3.4).
const client_preface = h2.constants.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
/// HEADERS frames on streams 1 and 3, each ending its stream, whose block is the static table's
/// `:method: GET` (2), `:scheme: https` (7) and `:path: /` (4), each an indexed field line (RFC
/// 7541 §6.1, Appendix A).
const get_stream_1 = "\x00\x00\x03\x01\x05\x00\x00\x00\x01\x82\x87\x84";
const get_stream_3 = "\x00\x00\x03\x01\x05\x00\x00\x00\x03\x82\x87\x84";

/// A frame's Length is three octets, then its type, its flags and its stream (RFC 9113 §4.1).
const length_len: usize = 3;
const type_index: usize = length_len;
const stream_index: usize = type_index + @sizeOf(u8) + @sizeOf(u8);

/// Where each frame of `frames` starts, and its type and stream. Test-only.
const Found = struct { offset: usize, type: u8, stream_id: u32 };

/// The frames of `frames` in order, into `into`. Test-only.
fn walk(frames: []const u8, into: []Found) ![]const Found {
    var offset: usize = 0;
    var count: usize = 0;
    // Bounded: each pass moves past a frame's header at least.
    for (0..frames.len) |_| {
        if (offset == frames.len) break;
        if (frames.len - offset < h2.constants.frame_header_len or count == into.len) return error.TestUnexpectedResult;
        const rest = frames[offset..];
        const payload_len = std.mem.readInt(u24, rest[0..length_len], .big);
        const stream_id = std.mem.readInt(u32, rest[stream_index..][0..@sizeOf(u32)], .big);
        into[count] = .{ .offset = offset, .type = rest[type_index], .stream_id = stream_id };
        count += 1;
        offset += h2.constants.frame_header_len + payload_len;
    }
    return into[0..count];
}

/// Where in `found` the first frame of type `frame_type` is. Test-only.
fn index_of(found: []const Found, frame_type: u8) ?usize {
    for (found, 0..) |entry, index| {
        if (entry.type == frame_type) return index;
    }
    return null;
}

/// The frames of `found` that are of type `frame_type`. Test-only.
fn count_of(found: []const Found, frame_type: u8) usize {
    var count: usize = 0;
    for (found) |entry| count += @intFromBool(entry.type == frame_type);
    return count;
}

/// Room for the frames the tests walk. Test-only.
const frames_max: usize = 16;

test "RFC 7838 §3: each final h11 response over TLS carries Alt-Svc, and an interim one does not" {
    support.alternative = alternative;
    defer support.alternative = null;
    try support.start_tls(&support.protocols_both, &support.protocols_h11);
    const received = try support.receive_sealed("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const id = received.event.?.request.id;
    try connection.respond(id, .{ .status = early_hints, .end = false });
    try connection.respond(id, .{ .status = ok, .end = true });
    try testing.expectEqualStrings(
        "HTTP/1.1 103 \r\n\r\n" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nalt-svc: h3=\":8443\"; ma=60\r\n\r\n",
        try support.open_sent(),
    );
}

test "RFC 9114 §3.1.2: a cleartext h11 response advertises no h3" {
    support.alternative = alternative;
    defer support.alternative = null;
    try support.start_cleartext(.h11);
    const received = try support.receive_copy("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try connection.respond(received.event.?.request.id, .{ .status = ok, .end = true });
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", support.drain());
}

test "RFC 7838 §3, §4: an h2 connection over TLS sends one ALTSVC frame, before its first final response" {
    support.alternative = alternative;
    defer support.alternative = null;
    try support.start_tls(&support.protocols_both, &support.protocols_h2);
    _ = try support.receive_sealed(client_preface ++ get_stream_1);
    try connection.respond(1, .{ .status = early_hints, .end = false });
    try connection.respond(1, .{ .status = ok, .end = true });
    var found_storage: [frames_max]Found = undefined;
    const sent = try support.open_sent();
    const found = try walk(sent, &found_storage);
    try testing.expectEqual(1, count_of(found, h2.constants.frame_type_altsvc));
    // The interim HEADERS, the ALTSVC frame and the final HEADERS, in that order, on stream 1.
    const at = index_of(found, h2.constants.frame_type_altsvc).?;
    try testing.expect(at > 0 and at + 1 < found.len);
    try testing.expectEqual(h2.constants.frame_type_headers, found[at - 1].type);
    try testing.expectEqual(h2.constants.frame_type_headers, found[at + 1].type);
    for (found[at - 1 .. at + 2]) |entry| try testing.expectEqual(1, entry.stream_id);
    // RFC 7838 §4: no Origin on a request's stream, then the field value.
    const payload = sent[found[at].offset + h2.constants.frame_header_len .. found[at + 1].offset];
    try testing.expectEqualStrings("\x00\x00h3=\":8443\"; ma=60", payload);
    // RFC 7838 §3: "A single ALTSVC frame can be sent for a connection".
    try support.expect_done(1);
    try testing.expectEqual(3, (try support.receive_sealed(get_stream_3)).event.?.request.id);
    try connection.respond(3, .{ .status = ok, .end = true });
    try testing.expectEqual(0, count_of(try walk(try support.open_sent(), &found_storage), h2.constants.frame_type_altsvc));
}

test "RFC 9114 §3.1.2: an h2 connection in cleartext, or one naming no alternative, sends no ALTSVC" {
    support.alternative = alternative;
    try support.start_cleartext(.h2);
    support.alternative = null;
    _ = try support.receive_copy(client_preface ++ get_stream_1);
    try connection.respond(1, .{ .status = ok, .end = true });
    var found_storage: [frames_max]Found = undefined;
    try testing.expectEqual(0, count_of(try walk(support.drain(), &found_storage), h2.constants.frame_type_altsvc));
    try support.start_tls(&support.protocols_both, &support.protocols_h2);
    _ = try support.receive_sealed(client_preface ++ get_stream_1);
    try connection.respond(1, .{ .status = ok, .end = true });
    try testing.expectEqual(0, count_of(try walk(try support.open_sent(), &found_storage), h2.constants.frame_type_altsvc));
}
