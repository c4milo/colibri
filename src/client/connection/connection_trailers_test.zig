//! The tests of a request's trailer section on a TCP connection (decision 152, design §8 step
//! 38b). Over h11 the request goes chunked, names each trailer field in a Trailer header field, and
//! ends with the section after its last chunk (RFC 9112 §7.1.2, RFC 9110 §6.6.2). Over h2 the
//! section ends the stream in a HEADERS frame after the last DATA frame (RFC 9113 §8.1). A
//! response with a trailer buffer asks for trailers with `te: trailers` (RFC 9110 §10.1.4).
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;
const Header = support.Header;

const ok: u16 = 200;
/// RFC 9110 §8.6: a response that states it has no content, which ends with its head.
const empty_length: []const Header = &.{.{ .name = "Content-Length", .value = "0" }};
/// The request's trailer section, as a gRPC client sends its own checksum. Test-only.
const trailers = [_]Header{ .{ .name = "x-checksum", .value = "abc" }, .{ .name = "grpc-status", .value = "0" } };
const content = "hello";
/// RFC 9112 §7.1 and §7.1.2: the content as one chunk, then the last chunk with the section.
const chunked_with_trailers = "5\r\nhello\r\n0\r\nx-checksum: abc\r\ngrpc-status: 0\r\n\r\n";
/// The end of a request head (RFC 9112 §2.1).
const head_end = "\r\n\r\n";

var body: [body_len]u8 = undefined;
var trailer_buffer: [body_len]u8 = undefined;
const body_len: usize = 256;

/// A POST of `content` with `trailers`, whose response keeps a trailer section when `reads`.
fn post(reads: bool) Exchange {
    return .{
        .request = .{ .method = "POST", .path = "/upload", .body = content, .trailers = &trailers },
        .response = .{ .body = &body, .trailers = .{ .buffer = if (reads) &trailer_buffer else &.{} } },
    };
}

/// The octets of the request head in what the client sent, its end included.
fn head_of(octets: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, octets, head_end).?;
    return octets[0 .. end + head_end.len];
}

fn contains(octets: []const u8, part: []const u8) bool {
    return std.mem.indexOf(u8, octets, part) != null;
}

/// The h11 server reads the request in `octets`, its body and its end. Returns the times the body
/// ended.
fn h11_server_read(octets: []const u8) !usize {
    var ends: usize = 0;
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..octets.len + support.events_max) |_| {
        const received = try support.peer_h11.receive(octets[consumed..], &.{});
        consumed += received.consumed;
        const got = received.event orelse break;
        if (got == .end) ends += 1;
    }
    try testing.expectEqual(octets.len, consumed);
    return ends;
}

/// Checks that the h11 server read `trailers` as the request's trailer section, apart from its
/// head.
fn expect_h11_trailers() !void {
    const section = &support.peer_h11.trailers;
    try testing.expectEqual(trailers.len, section.len());
    for (trailers) |field| try testing.expectEqualStrings(field.value, section.find(field.name).?.value);
}

test "RFC 9112 §7.1.2: a request with trailers goes chunked, names them in Trailer, and sends them last" {
    try support.start_cleartext(.h11);
    var exchange = post(false);
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    const sent = support.to_peer[0..support.to_peer_len];
    const head = head_of(sent);
    try testing.expect(contains(head, "Transfer-Encoding: chunked\r\n"));
    // RFC 9112 §7.1.2: a body with a trailer section states no Content-Length.
    try testing.expect(!contains(head, "Content-Length"));
    // RFC 9110 §6.6.2: each trailer field is named in the head.
    try testing.expect(contains(head, "Trailer: x-checksum\r\n"));
    try testing.expect(contains(head, "Trailer: grpc-status\r\n"));
    // A response with no trailer buffer asks for none.
    try testing.expect(!contains(head, "TE:"));
    try testing.expectEqualStrings(chunked_with_trailers, sent[head.len..]);
    try testing.expectEqual(1, try h11_server_read(sent));
    try expect_h11_trailers();
    try support.peer_h11_answer(ok, empty_length, "");
    try support.client_receive();
    try testing.expectEqual(.response, exchange.response.result);
    try testing.expectEqual(content.len, exchange.response.body_sent);
}

test "RFC 9112 §7.1.2: a request with trailers and no content sends the last chunk with the section" {
    try support.start_cleartext(.h11);
    var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/", .trailers = &trailers }, .response = .{ .body = &body } };
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    const sent = support.to_peer[0..support.to_peer_len];
    try testing.expectEqualStrings("0\r\nx-checksum: abc\r\ngrpc-status: 0\r\n\r\n", sent[head_of(sent).len..]);
    try testing.expectEqual(1, try h11_server_read(sent));
    try expect_h11_trailers();
}

test "decision 152: a streamed request's trailer section follows its last piece over h11" {
    try support.start_cleartext(.h11);
    var exchange = post(false);
    exchange.request.body = "";
    exchange.request.streamed = .{ .request = true };
    const id = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    try connection.write_body(id, "hel", false);
    support.client_send();
    try support.client_receive();
    try connection.write_body(id, "lo", true);
    support.client_send();
    try support.client_receive();
    try testing.expectEqual(2, support.count(.body_taken));
    const sent = support.to_peer[0..support.to_peer_len];
    try testing.expectEqualStrings("3\r\nhel\r\n2\r\nlo\r\n0\r\nx-checksum: abc\r\ngrpc-status: 0\r\n\r\n", sent[head_of(sent).len..]);
    try testing.expectEqual(1, try h11_server_read(sent));
    try expect_h11_trailers();
}

test "RFC 9110 §10.1.4: a response with a trailer buffer sends TE: trailers with its connection option" {
    try support.start_cleartext(.h11);
    var exchange = post(true);
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    const head = head_of(support.to_peer[0..support.to_peer_len]);
    try testing.expect(contains(head, "\r\nTE: trailers\r\n"));
    try testing.expect(contains(head, "\r\nConnection: TE\r\n"));
    // The program's own TE stands, and the client adds no second one.
    try support.start_cleartext(.h11);
    const own = [_]Header{.{ .name = "TE", .value = "trailers" }};
    var named: Exchange = .{ .request = .{ .method = "GET", .path = "/", .headers = &own }, .response = .{ .trailers = .{ .buffer = &trailer_buffer } } };
    _ = try connection.request(&named.request, &named.response);
    support.client_send();
    const named_head = head_of(support.to_peer[0..support.to_peer_len]);
    const first = std.mem.indexOf(u8, named_head, "TE: trailers").?;
    try testing.expect(!contains(named_head[first + 1 ..], "TE: trailers"));
    try testing.expect(contains(named_head, "\r\nConnection: TE\r\n"));
}

/// What the h2 server read of the request: whether its head asked for trailers and named them,
/// the content, and the trailer section that ended the stream. Test-only.
const H2Read = struct {
    te: bool = false,
    named: usize = 0,
    data_len: usize = 0,
    data_ends: usize = 0,
    head_ends: bool = false,
    trailers_found: usize = 0,
    trailer_sections: usize = 0,
};

/// The h2 server reads every whole frame the client sent.
fn h2_server_read(read: *H2Read) !void {
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or writes what the server owes, and both are finite.
    for (0..support.to_peer_len + support.events_max) |_| {
        const received = try support.peer_h2.receive(support.to_peer[consumed..support.to_peer_len], support.now_ns);
        if (received.consumed == 0) {
            if (!support.peer_h2.has_pending()) break;
            support.peer_h2_owe();
            continue;
        }
        consumed += received.consumed;
        h2_note(read, received.event orelse continue);
    }
    support.to_peer_len = 0;
    support.peer_h2_owe();
}

fn h2_note(read: *H2Read, got: h2.Event) void {
    const section = support.peer_h2.field_section();
    switch (got) {
        .request => |request| {
            read.head_ends = request.end_stream;
            read.te = section.find("te") != null;
            for (0..section.len()) |index| read.named += @intFromBool(std.mem.eql(u8, section.get(@intCast(index)).name, "trailer"));
        },
        .data => |data| {
            read.data_len += data.payload.len;
            read.data_ends += @intFromBool(data.end_stream);
        },
        .trailers => {
            read.trailer_sections += 1;
            for (trailers) |field| {
                const found = section.find(field.name) orelse continue;
                read.trailers_found += @intFromBool(std.mem.eql(u8, found.value, field.value));
            }
        },
        else => {},
    }
}

/// Checks that the h2 server read the content whole and then the trailer section, which alone
/// ended the stream (RFC 9113 §8.1).
fn expect_h2_trailers(read: *const H2Read, data_len: usize) !void {
    try testing.expect(!read.head_ends);
    try testing.expectEqual(data_len, read.data_len);
    try testing.expectEqual(0, read.data_ends);
    try testing.expectEqual(1, read.trailer_sections);
    try testing.expectEqual(trailers.len, read.trailers_found);
    try testing.expectEqual(trailers.len, read.named);
}

test "RFC 9113 §8.1: a request's trailer section ends its stream in a HEADERS frame after its DATA" {
    try support.start_cleartext(.h2);
    try support.pump_h2();
    var exchange = post(true);
    _ = try connection.request(&exchange.request, &exchange.response);
    var read: H2Read = .{};
    support.client_send();
    try h2_server_read(&read);
    try expect_h2_trailers(&read, content.len);
    // RFC 9113 §8.2.2: "trailers" is the one TE value h2 allows.
    try testing.expect(read.te);
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.client_receive();
    try testing.expectEqual(.response, exchange.response.result);
}

test "RFC 9113 §8.1: a request with trailers and no content sends its section after its head" {
    try support.start_cleartext(.h2);
    try support.pump_h2();
    var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/", .trailers = &trailers }, .response = .{ .body = &body } };
    _ = try connection.request(&exchange.request, &exchange.response);
    var read: H2Read = .{};
    support.client_send();
    try h2_server_read(&read);
    try expect_h2_trailers(&read, 0);
    // A response with no trailer buffer asks for none.
    try testing.expect(!read.te);
}

test "decision 152: a streamed request's trailer section follows its last piece over h2" {
    try support.start_cleartext(.h2);
    try support.pump_h2();
    var exchange = post(false);
    exchange.request.body = "";
    exchange.request.streamed = .{ .request = true };
    const id = try connection.request(&exchange.request, &exchange.response);
    var read: H2Read = .{};
    support.client_send();
    try connection.write_body(id, "hel", false);
    support.client_send();
    try h2_server_read(&read);
    try support.client_receive();
    try testing.expectEqual(0, read.trailer_sections);
    try connection.write_body(id, "lo", true);
    support.client_send();
    try h2_server_read(&read);
    try support.client_receive();
    try testing.expectEqual(2, support.count(.body_taken));
    try expect_h2_trailers(&read, content.len);
}

test "decision 152: a streamed request whose only piece is an empty last one ends with its trailers" {
    try support.start_cleartext(.h2);
    try support.pump_h2();
    var exchange = post(false);
    exchange.request.body = "";
    exchange.request.streamed = .{ .request = true };
    const id = try connection.request(&exchange.request, &exchange.response);
    try connection.write_body(id, "", true);
    var read: H2Read = .{};
    support.client_send();
    try h2_server_read(&read);
    try support.client_receive();
    try testing.expectEqual(1, support.count(.body_taken));
    try expect_h2_trailers(&read, 0);
}

/// The value of each line of the largest trailer section: two lines of a one-octet name, each of
/// size half of `field_section_size_max` as RFC 9113 §6.5.2 counts it. Test-only.
const largest_value: [largest_value_len]u8 = @splat('v');
const largest_value_len: usize = h2.core.constants.limits.field_section_size_max / largest_lines - 1 - h2.core.constants.protocol.field_line_overhead;
const largest_lines: usize = 2;
const largest = [_]Header{ .{ .name = "a", .value = &largest_value }, .{ .name = "b", .value = &largest_value } };

/// A POST with the trailer section `section`.
fn post_with(section: []const Header) Exchange {
    return .{
        .request = .{ .method = "POST", .path = "/upload", .body = content, .trailers = section },
        .response = .{ .body = &body },
    };
}

test "RFC 9113 §6.5.2: the largest trailer section goes out whole over h11 and h2, and one octet more is refused" {
    try support.start_cleartext(.h11);
    var exchange = post_with(&largest);
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    try testing.expectEqual(1, try h11_server_read(support.to_peer[0..support.to_peer_len]));
    try testing.expectEqual(largest.len, support.peer_h11.trailers.len());
    try testing.expectEqual(.pending, exchange.response.result);
    try support.start_cleartext(.h2);
    try support.pump_h2();
    exchange = post_with(&largest);
    _ = try connection.request(&exchange.request, &exchange.response);
    var read: H2Read = .{};
    support.client_send();
    try h2_server_read(&read);
    try testing.expectEqual(content.len, read.data_len);
    try testing.expectEqual(1, read.trailer_sections);
    try testing.expectEqual(largest.len, support.peer_h2.field_section().len());
    // One octet past the size refuses the request before it takes a slot, over any protocol.
    const longer_value: [largest_value_len + 1]u8 = @splat('v');
    const longer = [_]Header{ largest[0], .{ .name = "b", .value = &longer_value } };
    exchange = post_with(&longer);
    try testing.expectError(error.InvalidTrailer, connection.request(&exchange.request, &exchange.response));
}
