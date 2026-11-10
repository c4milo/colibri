//! The tests of decision 160 in a server connection over TCP: a response written before the h11
//! request's body was read whole is followed by the discard of the body's rest, which keeps the
//! connection for the next request (RFC 9112 §9.3), under decision 110's deadlines.
const std = @import("std");
const http = @import("http");
const support = @import("connection_test_support.zig");
const deadline_support = @import("connection_deadline_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const early_ns = deadline_support.early_ns;
const send_at = deadline_support.send_at;

/// RFC 9110 §15.5.6: 405 (Method Not Allowed), as a router answers a method a route lacks.
const method_not_allowed: http.Status = .method_not_allowed;

/// Octets of the body each test's client sends after the head: 10 KiB, under the bound.
const body_len: usize = 10_240;

const next_request = "GET /b HTTP/1.1\r\nHost: h\r\n\r\n";

/// The octets a test's client sends, outside any stack frame.
var wire: [support.input_len]u8 = undefined;

/// Writes the head of a POST whose body is `body_len` octets, chunked or with a Content-Length,
/// into `wire`, and returns its octets.
fn post_head(chunked: bool) []const u8 {
    const head = if (chunked) chunked_head else length_head;
    @memcpy(wire[0..head.len], head);
    return wire[0..head.len];
}

const chunked_head = "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
const length_head = std.fmt.comptimePrint("POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n", .{body_len});

/// Writes the body after `at` in `wire`, framed as the head said, and returns where it ends.
fn post_body(at: usize, chunked: bool) usize {
    var length = at;
    if (chunked) {
        const size_line = std.fmt.comptimePrint("{x}\r\n", .{body_len});
        @memcpy(wire[length..][0..size_line.len], size_line);
        length += size_line.len;
    }
    @memset(wire[length..][0..body_len], 'x');
    length += body_len;
    if (chunked) {
        const last = "\r\n0\r\n\r\n";
        @memcpy(wire[length..][0..last.len], last);
        length += last.len;
    }
    return length;
}

/// Hands `octets` to the connection at `now_ns` until it reports an event or reads nothing, and
/// returns the octets it read and the event.
fn receive_until_event(octets: []const u8, now_ns: u64) !struct { consumed: usize, event: ?support.ConnectionResult } {
    var offset: usize = 0;
    // Bounded: each pass that reports nothing takes an octet at least.
    for (0..octets.len + 1) |_| {
        const received = try deadline_support.receive_at(octets[offset..], now_ns);
        offset += received.consumed;
        if (received.event != null) return .{ .consumed = offset, .event = received };
        if (received.consumed == 0) return .{ .consumed = offset, .event = null };
    }
    return error.TestUnexpectedResult;
}

/// Reads the POST's head at `early_ns`, answers it 405 before its body, sends the answer, and
/// reads the request's `done`. Returns what was sent.
fn answer_early(head: []const u8) ![]const u8 {
    const received = try deadline_support.receive_at(head, early_ns);
    const request = received.event.?.request;
    try testing.expect(!request.end);
    try connection.respond(request.id.number, .{ .status = method_not_allowed, .end = true });
    const sent = send_at(early_ns);
    try support.expect_done(request.id.number);
    return sent;
}

test "decision 160: a 405 to a POST with a 10 KiB body keeps the connection, which serves the next request" {
    for ([_]bool{ false, true }) |chunked| {
        try support.start_cleartext(.h11);
        const head = post_head(chunked);
        const sent = try answer_early(head);
        try testing.expect(std.mem.startsWith(u8, sent, "HTTP/1.1 405 Method Not Allowed\r\n"));
        // RFC 9112 §9.6: the connection stays open, so the head carries no close option.
        try testing.expect(std.mem.indexOf(u8, sent, "Connection: close") == null);
        const end = post_body(head.len, chunked);
        @memcpy(wire[end..][0..next_request.len], next_request);
        // RFC 9112 §9.3: the body's rest is read and reported to no one, and the next request
        // follows it on the same connection.
        const read = try receive_until_event(wire[head.len .. end + next_request.len], early_ns);
        try testing.expectEqual(end + next_request.len - head.len, read.consumed);
        const next = read.event.?.event.?.request;
        try testing.expectEqual(2, next.id.number);
        try testing.expectEqualStrings("/b", next.path.?);
        try testing.expect(!connection.should_close());
        // Decision 110: the discarded body's deadlines ended with it, and the next request has none.
        try testing.expectEqual(0, connection.bodies.used);
    }
}

test "decision 160: a peer that drips the discarded body is cut by decision 110's body deadline" {
    for ([_]bool{ false, true }) |chunked| {
        try support.start_cleartext(.h11);
        const head = post_head(chunked);
        _ = try answer_early(head);
        _ = try deadline_support.receive_at(wire[head.len .. head.len + 3], early_ns);
        // Decision 110: the body still waits on its peer, so its rate deadline runs.
        const cut_ns = connection.deadline_ns().?;
        connection.on_instant(cut_ns - 1);
        try testing.expect(!connection.should_close());
        connection.on_instant(cut_ns);
        try testing.expectEqual(.body_rate, connection.close_reason().?.timeout);
        // RFC 9110 §15.5.9: the request was answered, so no 408 follows the 405.
        try testing.expectEqual(0, send_at(cut_ns).len);
        try testing.expect(connection.should_close());
    }
}

test "decision 160: the octets of a discarded body count for decision 110's rate, so a fair peer is not cut" {
    try support.start_cleartext(.h11);
    const head = "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 30000\r\n\r\n";
    @memcpy(wire[0..head.len], head);
    _ = try answer_early(wire[0..head.len]);
    // More than the first window's quota arrives after the response.
    const policy = support.server_constants.policy;
    const quota = policy.body_rate_min * (policy.rate_window_ns / support.server_constants.nanoseconds_per_second);
    @memset(wire[head.len..][0 .. quota + 1], 'x');
    const read = try receive_until_event(wire[head.len..][0 .. quota + 1], early_ns);
    try testing.expectEqual(quota + 1, read.consumed);
    // Decision 110: the first window, the grace period with it, brought its quota.
    const first_end_ns = early_ns + policy.rate_grace_ns + policy.rate_window_ns;
    try testing.expectEqual(first_end_ns + policy.rate_window_ns, connection.deadline_ns().?);
    connection.on_instant(first_end_ns);
    try testing.expect(!connection.should_close());
    try testing.expectEqual(null, connection.close_reason());
}

test "decision 160: a Content-Length at discard_len_max is discarded, and one octet past it is not" {
    const bound = support.server_constants.limits.discard_len_max;
    var buffer: [128]u8 = undefined;
    for ([_]u64{ bound, bound + 1 }) |content_len| {
        try support.start_cleartext(.h11);
        const head = try std.fmt.bufPrint(&buffer, "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n", .{content_len});
        const sent = try answer_early(head);
        // RFC 9112 §9.3: a body that fits the bound is read, and h11 closes after any other.
        const phase = connection.session.h11.phase;
        try testing.expectEqual(content_len <= bound, phase == .discard);
        try testing.expectEqual(content_len > bound, phase == .closed);
        // RFC 9110 §10.1.1: the 405 says whether the connection closes.
        const says_close = std.mem.indexOf(u8, sent, "Connection: close\r\n") != null;
        try testing.expectEqual(content_len > bound, says_close);
    }
}
