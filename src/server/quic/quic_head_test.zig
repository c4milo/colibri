//! The tests of a response to HEAD over h3 (RFC 9110 §9.3.2): the program writes the answer it
//! writes for GET, and the connection takes the content and writes no DATA frame. The stream
//! ends once the program ends the content.
const std = @import("std");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const Field = support.Field;

const ok: u16 = 200;
const content = "hello";
/// Where the program cuts `content` in two calls.
const cut: usize = 3;
const head_fields = [_]Field{
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-length", .value = "5" },
};
const accepts_gzip = [_]Field{.{ .name = "accept-encoding", .value = "gzip" }};
const encoders_all: usize = 2;

/// A connected pair, and one HEAD from the client whose head and end the server read.
fn head(fields: []const Field) !*support.Fetch {
    try support.connect();
    const fetch = try support.request_with_fields("HEAD", "/", fields);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.request, 0).?.id);
    return fetch;
}

/// Writes the answer the program writes for GET, and expects the client to read its head, no
/// content and the stream's end, and the server to report the request done.
fn answer(fetch: *const support.Fetch, codable: bool) !void {
    // RFC 9114 §4.1: DATA frames follow the final response's HEADERS frame.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(fetch.id, .{ .octets = content, .end = true }));
    try connection.respond(fetch.id, .{ .status = ok, .fields = &head_fields, .end = false, .codable = codable });
    try testing.expectEqual(cut, try connection.write_body(fetch.id, .{ .octets = content[0..cut], .end = false }));
    try testing.expectEqual(content.len - cut, try connection.write_body(fetch.id, .{ .octets = content[cut..], .end = true }));
    try support.pump(support.rounds_default);
    try testing.expectEqual(ok, fetch.status);
    try testing.expectEqual(0, fetch.received_len);
    try testing.expect(fetch.ended);
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
}

test "RFC 9114 §4.1.2: h3 takes the content of a response to HEAD and writes no DATA frame" {
    try support.start();
    try answer(try head(&.{}), false);
}

test "RFC 9110 §9.3.2: an h3 connection that codes content takes the content of a response to HEAD and writes none" {
    try support.start_coding();
    try answer(try head(&accepts_gzip), true);
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}
