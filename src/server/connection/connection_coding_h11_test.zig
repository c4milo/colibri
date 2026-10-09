//! The tests of content codings over h11 (`connection_coding.zig`, decision 101): a response the
//! caller marks goes out coded and chunked when its request accepts a coding, and its encoder goes
//! back to the pool once the response ends or the connection does.
const std = @import("std");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const Field = support.Field;

const early_hints: u16 = 103;
const ok: u16 = 200;
const partial_content: u16 = 206;
const not_modified: u16 = 304;
const encoders_all: usize = 2;

const gzip_request = "GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip, deflate\r\n\r\n";
const plain_request = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";

/// Where a test gathers what the connection sent, and the content it de-chunks from it. Test-only.
threadlocal var test_sent: [support.coded_len_max]u8 = undefined;
threadlocal var test_content: [support.coded_len_max]u8 = undefined;

/// Reads `request` and expects its head, with the id `id`.
fn expect_request(request: []const u8, id: u64) !void {
    const received = try support.receive_copy(request);
    try testing.expectEqual(request.len, received.consumed);
    try testing.expectEqual(id, received.event.?.request.id.number);
}

/// A response's head and its chunked content, joined.
const Parsed = struct {
    head: []const u8,
    content: []const u8,
};

/// Splits `octets`, one chunked response (RFC 9112 §7.1), into its head and its content.
fn parse_chunked(octets: []const u8) !Parsed {
    const head_len = (std.mem.indexOf(u8, octets, head_end) orelse return error.TestUnexpectedResult) + head_end.len;
    var content_len: usize = 0;
    var at = head_len;
    // Bounded: each pass reads a chunk's size line at least.
    for (0..octets.len) |_| {
        const line_end = std.mem.indexOfPos(u8, octets, at, crlf) orelse return error.TestUnexpectedResult;
        const size = try std.fmt.parseInt(usize, octets[at..line_end], hex_base);
        at = line_end + crlf.len;
        if (size == 0) break;
        @memcpy(test_content[content_len..][0..size], octets[at..][0..size]);
        content_len += size;
        at += size + crlf.len;
    }
    return .{ .head = octets[0..head_len], .content = test_content[0..content_len] };
}

const head_end = "\r\n\r\n";
const crlf = "\r\n";
const hex_base: u8 = 16;

test "decision 101: a marked response to a request that accepts gzip goes out coded, chunked and whole" {
    try support.start_coding(.h11);
    try expect_request(gzip_request, 1);
    const fields = [_]Field{ .{ .name = "content-length", .value = "11" }, .{ .name = "etag", .value = "\"v1\"" } };
    try connection.respond(1, .{ .status = ok, .fields = &fields, .end = false, .codable = true });
    try testing.expectEqual(encoders_all - 1, support.pool.free_count());
    try testing.expectEqual(11, try connection.write_body(1, .{ .octets = "hello world", .end = true }));
    const parsed = try parse_chunked(support.drain());
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\netag: W/\"v1\"\r\ncontent-encoding: gzip\r\n" ++
        "vary: accept-encoding\r\ntransfer-encoding: chunked\r\n\r\n", parsed.head);
    try testing.expectEqualStrings("hello world", try support.decode(.gzip, parsed.content));
    try support.expect_done(1);
    try testing.expectEqual(encoders_all, support.pool.free_count());
    // RFC 9110 §6.4.1: the content ended, and nothing follows it.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(1, .{ .octets = "x", .end = true }));
}

test "decision 101: an unmarked response goes uncoded, and a marked one Accept-Encoding chose varies" {
    try support.start_coding(.h11);
    try expect_request(gzip_request, 1);
    try connection.respond(1, .{ .status = ok, .end = false });
    // An uncoded response keeps nothing of its request.
    try testing.expectEqual(0, connection.coding.used);
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", support.drain());
    try support.expect_done(1);
    // Decision 101: a request with no Accept-Encoding gets no coding.
    try expect_request(plain_request, 2);
    try connection.respond(2, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(5, try connection.write_body(2, .{ .octets = "hello", .end = true }));
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nvary: accept-encoding\r\ntransfer-encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n0\r\n\r\n", support.drain());
    try support.expect_done(2);
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

test "decision 101: an HTTP/1.0 request and a 206 get no coding" {
    try support.start_coding(.h11);
    try expect_request("GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\nRange: bytes=0-4\r\n\r\n", 1);
    try connection.respond(1, .{ .status = partial_content, .end = false, .codable = true });
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    try testing.expectEqualStrings("HTTP/1.1 206 Partial Content\r\ntransfer-encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n0\r\n\r\n", support.drain());
    try support.expect_done(1);
    try support.start_coding(.h11);
    try expect_request("GET / HTTP/1.0\r\nAccept-Encoding: gzip\r\n\r\n", 1);
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    // RFC 9112 §6.3 rule 8: an HTTP/1.0 response of unknown length runs until the close.
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nvary: accept-encoding\r\nConnection: close\r\n\r\nhello", support.drain());
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

test "RFC 9110 §9.3.2, §15.4.5: HEAD names the coding and a 304 keeps a weak ETag, and neither takes an encoder" {
    try support.start_coding(.h11);
    try expect_request("HEAD / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n", 1);
    const length = [_]Field{.{ .name = "content-length", .value = "11" }};
    try connection.respond(1, .{ .status = ok, .fields = &length, .end = false, .codable = true });
    try testing.expectEqual(encoders_all, support.pool.free_count());
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\nvary: accept-encoding\r\n\r\n", support.drain());
    try support.expect_done(1);
    try expect_request(gzip_request, 2);
    const tag = [_]Field{.{ .name = "etag", .value = "\"v1\"" }};
    try connection.respond(2, .{ .status = not_modified, .fields = &tag, .end = true, .codable = true });
    try testing.expectEqualStrings("HTTP/1.1 304 Not Modified\r\netag: W/\"v1\"\r\nvary: accept-encoding\r\n\r\n", support.drain());
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

test "decision 101: with every encoder taken, a marked response goes uncoded" {
    try support.start_coding(.h11);
    const encoders = support.pool.encoders();
    const first = encoders.take(.gzip).?;
    const second = encoders.take(.gzip).?;
    try expect_request(gzip_request, 1);
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nvary: accept-encoding\r\ntransfer-encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n0\r\n\r\n", support.drain());
    encoders.give_back(first);
    encoders.give_back(second);
}

test "decision 101: content past the ring waits, `send` moves the coded octets on, and the end follows" {
    support.fill_incompressible();
    try support.start_coding(.h11);
    try expect_request(gzip_request, 1);
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    const content = support.incompressible[0..];
    // The ring holds less than the content coded, so the first call takes part of it.
    var taken = try connection.write_body(1, .{ .octets = content, .end = true });
    try testing.expect(taken > 0 and taken < content.len);
    // With the output and the ring full, a call takes nothing until `send` moves octets out.
    const blocked = for (0..writes_until_full_max) |_| {
        taken += connection.write_body(1, .{ .octets = content[taken..], .end = true }) catch |failure| {
            try testing.expectEqual(error.Blocked, failure);
            break true;
        };
    } else false;
    try testing.expect(blocked);
    var sent_len: usize = 0;
    // Bounded: each round's `send` moves coded octets out, which lets the encoder go on.
    for (0..support.coded_len_max) |_| {
        sent_len += connection.send(test_sent[sent_len..], support.now_ns);
        if (taken == content.len and support.pool.free_count() == encoders_all) break;
        if (taken == content.len) continue;
        taken += connection.write_body(1, .{ .octets = content[taken..], .end = true }) catch 0;
        if (taken == content.len) try expect_ended(1);
    }
    try testing.expectEqual(encoders_all, support.pool.free_count());
    const parsed = try parse_chunked(test_sent[0..sent_len]);
    try testing.expectEqualSlices(u8, content, try support.decode(.gzip, parsed.content));
    try support.expect_done(1);
}

/// Calls that fill the output and then the ring: one copies what the ring holds out, and the
/// next codes into the room that left.
const writes_until_full_max: usize = 4;

/// With the content of request `id`'s coded response ended and its last coded octets still in
/// the ring, neither content nor a trailer section follows (RFC 9110 §6.4.1, §6.5).
fn expect_ended(id: u64) !void {
    try testing.expect(support.pool.free_count() < encoders_all);
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(id, .{ .octets = "x", .end = true }));
    try testing.expectError(error.SectionOutOfOrder, connection.write_trailers(id, &.{}));
}

test "decision 101: trailers follow the coded content, and the end of the connection gives back its encoder" {
    try support.start_coding(.h11);
    try expect_request(gzip_request, 1);
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = false }));
    const trailer = [_]Field{.{ .name = "checksum", .value = "1" }};
    try connection.write_trailers(1, &trailer);
    const sent = support.drain();
    try testing.expect(std.mem.endsWith(u8, sent, "0\r\nchecksum: 1\r\n\r\n"));
    try testing.expectEqualStrings("hello", try support.decode(.gzip, (try parse_chunked(sent)).content));
    try support.expect_done(1);
    try testing.expectEqual(encoders_all, support.pool.free_count());
    // A coded response the connection ends midway gives its encoder back.
    try expect_request(gzip_request, 2);
    try connection.respond(2, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(encoders_all - 1, support.pool.free_count());
    connection.transport_closed();
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

test "RFC 9110 §15.2: an interim response goes out as it is, and the final one coded" {
    try support.start_coding(.h11);
    try expect_request(gzip_request, 1);
    try connection.respond(1, .{ .status = early_hints, .end = false, .codable = true });
    try connection.respond(1, .{ .status = ok, .end = true, .codable = true });
    // RFC 9112 §4: the reason phrase is optional, and colibri writes none for a 103.
    try testing.expectEqualStrings("HTTP/1.1 103 \r\n\r\nHTTP/1.1 200 OK\r\n" ++
        "vary: accept-encoding\r\ncontent-length: 0\r\n\r\n", support.drain());
}

test "RFC 9110 §6.5: a trailer section waits for the coded octets the ring holds, then ends the response" {
    support.fill_incompressible();
    try support.start_coding(.h11);
    try expect_request(gzip_request, 1);
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    const taken = try connection.write_body(1, .{ .octets = support.incompressible[0..], .end = false });
    const trailer = [_]Field{.{ .name = "checksum", .value = "1" }};
    try testing.expectError(error.Blocked, connection.write_trailers(1, &trailer));
    var sent_len: usize = 0;
    // Bounded: each round's `send` moves coded octets out, until the trailer section goes.
    const written = for (0..support.coded_len_max) |_| {
        sent_len += connection.send(test_sent[sent_len..], support.now_ns);
        connection.write_trailers(1, &trailer) catch |failure| {
            try testing.expectEqual(error.Blocked, failure);
            continue;
        };
        break true;
    } else false;
    try testing.expect(written);
    sent_len += connection.send(test_sent[sent_len..], support.now_ns);
    try testing.expect(std.mem.endsWith(u8, test_sent[0..sent_len], "0\r\nchecksum: 1\r\n\r\n"));
    const parsed = try parse_chunked(test_sent[0..sent_len]);
    try testing.expectEqualSlices(u8, support.incompressible[0..taken], try support.decode(.gzip, parsed.content));
    try testing.expectEqual(encoders_all, support.pool.free_count());
}
