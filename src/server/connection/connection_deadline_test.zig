//! The tests of decision 110's deadlines in a server connection over TCP
//! (`connection_deadline.zig`): each passes at its instant and not a nanosecond before, ends the
//! connection as decision 110 says, and runs only while the connection waits on the peer.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const server_constants = support.server_constants;

const first_request_ns = server_constants.first_request_timeout_ns;
const idle_ns = server_constants.idle_timeout_ns;
const head_ns = server_constants.head_timeout_ns;

/// An instant well inside every deadline, at which a test's peer sends its first octets.
const early_ns: u64 = 1_000_000;

/// The request a test's h11 peer sends whole, and the status each answer carries: 204 (No
/// Content), RFC 9110 §15.3.5.
const whole_request = "GET / HTTP/1.1\r\nHost: h\r\n\r\n";
const no_content: u16 = 204;

/// Reads `octets` at `now_ns`.
fn receive_at(octets: []const u8, now_ns: u64) !support.Received {
    @memcpy(support.input[0..octets.len], octets);
    return connection.receive(support.input[0..octets.len], now_ns);
}

/// What the connection sends at `now_ns`.
fn send_at(now_ns: u64) []const u8 {
    const written = connection.send(&support.output, now_ns);
    return support.output[0..written];
}

/// Answers the request `receive_at` read with a 204, sends the answer at `now_ns`, and reads the
/// request's `done` event (decision 103).
fn answer_at(received: support.Received, now_ns: u64) !void {
    const id = received.event.?.request.id;
    try connection.respond(id, .{ .status = no_content, .end = true });
    _ = send_at(now_ns);
    const done = try connection.receive(&.{}, now_ns);
    try testing.expectEqual(id, done.event.?.done.id);
}

/// The error code of the GOAWAY frame in `sent`, which a test requires to be there.
fn goaway_code(sent: []const u8) !u32 {
    var offset: usize = 0;
    // Bounded: each pass skips one whole frame.
    for (0..sent.len) |_| {
        if (offset + h2.constants.frame_header_len > sent.len) break;
        const frame = sent[offset..];
        const payload = frame[h2.constants.frame_header_len..];
        if (frame[h2_support.type_index] == h2.constants.frame_type_goaway) {
            return std.mem.readInt(u32, payload[goaway_code_start..][0..@sizeOf(u32)], .big);
        }
        offset += h2_support.frame_len(frame);
    }
    return error.TestUnexpectedResult;
}

/// Where a GOAWAY's error code lies, after its last stream identifier (RFC 9113 §6.8).
const goaway_code_start: usize = 4;

/// A PING frame that asks for an acknowledgment (RFC 9113 §6.7).
fn ping_frame() ![h2.constants.frame_header_len + h2.constants.ping_len]u8 {
    var frame: [h2.constants.frame_header_len + h2.constants.ping_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_ping(&writer, @splat(0), false);
    return frame;
}

test "decision 110: a connection that sends nothing ends at the first-request deadline, with nothing sent" {
    try support.start_cleartext(.h11);
    try testing.expectEqual(first_request_ns, connection.deadline_ns().?);
    connection.on_instant(first_request_ns - 1);
    try testing.expectEqual(null, connection.timed_out());
    try testing.expect(!connection.should_close());
    connection.on_instant(first_request_ns);
    try testing.expectEqual(.first_request, connection.timed_out().?);
    try testing.expectEqual(0, send_at(first_request_ns).len);
    try testing.expect(connection.should_close());
    try testing.expectEqual(null, connection.deadline_ns());
}

test "decision 110: send fires a deadline its instant has passed, as receive and on_instant do" {
    try support.start_cleartext(.h11);
    try testing.expectEqual(0, send_at(first_request_ns).len);
    try testing.expectEqual(.first_request, connection.timed_out().?);
    try testing.expect(connection.should_close());
}

test "decision 110: the idle deadline runs only after a first request" {
    try support.start_cleartext(.h11);
    try connection.set_deadlines(.{ .first_request_ns = null });
    connection.on_instant(early_ns);
    connection.on_instant(early_ns + 2 * idle_ns);
    try testing.expectEqual(null, connection.timed_out());
    try testing.expectEqual(null, connection.deadline_ns());
}

test "decision 110: octets that arrive at the deadline's instant are not read" {
    try support.start_cleartext(.h11);
    const received = try receive_at(whole_request, first_request_ns);
    try testing.expectEqual(null, received.event);
    try testing.expectEqual(.first_request, connection.timed_out().?);
}

test "RFC 9110 §15.5.9: a request head that began and did not end gets a 408 at the deadline" {
    try support.start_cleartext(.h11);
    _ = try receive_at("GET / HT", early_ns);
    // The first request's deadline counts from the open, before the head's.
    try testing.expectEqual(first_request_ns, connection.deadline_ns().?);
    connection.on_instant(first_request_ns);
    const sent = send_at(first_request_ns);
    try testing.expect(std.mem.startsWith(u8, sent, "HTTP/1.1 408 Request Timeout\r\n"));
    try testing.expect(std.mem.indexOf(u8, sent, "Connection: close\r\n") != null);
    try testing.expect(connection.should_close());
}

test "decision 110: no deadline runs while the application holds a request, and idle runs after it" {
    try support.start_cleartext(.h11);
    const received = try receive_at(whole_request, early_ns);
    try testing.expectEqual(null, connection.deadline_ns());
    // Far past every limit, and the application still has the request.
    const answered_ns = early_ns + first_request_ns + idle_ns + head_ns;
    connection.on_instant(answered_ns);
    try testing.expectEqual(null, connection.timed_out());
    try answer_at(received, answered_ns);
    try testing.expectEqual(answered_ns + idle_ns, connection.deadline_ns().?);
    connection.on_instant(answered_ns + idle_ns - 1);
    try testing.expectEqual(null, connection.timed_out());
    connection.on_instant(answered_ns + idle_ns);
    try testing.expectEqual(.idle, connection.timed_out().?);
    // RFC 9112 §9.5: an idle connection closes without a 408.
    try testing.expectEqual(0, send_at(answered_ns + idle_ns).len);
    try testing.expect(connection.should_close());
}

test "decision 110: no deadline runs while an h2 request is open, and idle runs after it" {
    try h2_support.start();
    const received = try receive_at(try h2_support.request_frame(1, "/", true), early_ns);
    try testing.expectEqual(null, connection.deadline_ns());
    const answered_ns = early_ns + first_request_ns + idle_ns + head_ns;
    connection.on_instant(answered_ns);
    try testing.expectEqual(null, connection.timed_out());
    try answer_at(received, answered_ns);
    try testing.expectEqual(answered_ns + idle_ns, connection.deadline_ns().?);
}

test "decision 110: a wait that begins in respond starts at the instant of the next call, send's or on_instant's" {
    try support.start_cleartext(.h11);
    var received = try receive_at(whole_request, early_ns);
    try connection.respond(received.event.?.request.id, .{ .status = no_content, .end = true });
    try testing.expectEqual(null, connection.deadline_ns());
    _ = send_at(early_ns + 1);
    try testing.expectEqual(early_ns + 1 + idle_ns, connection.deadline_ns().?);
    try support.start_cleartext(.h11);
    received = try receive_at(whole_request, early_ns);
    try connection.respond(received.event.?.request.id, .{ .status = no_content, .end = true });
    connection.on_instant(early_ns + 2);
    try testing.expectEqual(early_ns + 2 + idle_ns, connection.deadline_ns().?);
}

test "decision 110: a later head's deadline runs from its first octet, and its end stops it" {
    try support.start_cleartext(.h11);
    try answer_at(try receive_at(whole_request, early_ns), early_ns);
    const began_ns = early_ns + idle_ns / 2;
    _ = try receive_at("GET /b HTTP/1.1\r\nHo", began_ns);
    try testing.expectEqual(began_ns + head_ns, connection.deadline_ns().?);
    // More of the head does not move its deadline.
    _ = try receive_at("GET /b HTTP/1.1\r\nHost: ", began_ns + 1);
    try testing.expectEqual(began_ns + head_ns, connection.deadline_ns().?);
    connection.on_instant(began_ns + head_ns - 1);
    try testing.expectEqual(null, connection.timed_out());
    const rest = "GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    const whole = try receive_at(rest, began_ns + head_ns - 1);
    try testing.expectEqualStrings("/b", whole.event.?.request.target);
    try testing.expectEqual(null, connection.deadline_ns());
}

test "decision 110: a later head that does not end in time gets a 408" {
    try support.start_cleartext(.h11);
    try answer_at(try receive_at(whole_request, early_ns), early_ns);
    const began_ns = early_ns + idle_ns / 2;
    _ = try receive_at("GET /b HTTP/1.1\r\nHo", began_ns);
    connection.on_instant(began_ns + head_ns);
    try testing.expectEqual(.head, connection.timed_out().?);
    try testing.expect(std.mem.startsWith(u8, send_at(began_ns + head_ns), "HTTP/1.1 408 "));
}

test "decision 110: an h2 peer that sends only PINGs gets a GOAWAY with NO_ERROR at the first-request deadline" {
    try h2_support.start();
    _ = try receive_at(&(try ping_frame()), first_request_ns / 2);
    _ = send_at(first_request_ns / 2);
    _ = try receive_at(&(try ping_frame()), first_request_ns - 1);
    try testing.expectEqual(first_request_ns, connection.deadline_ns().?);
    connection.on_instant(first_request_ns);
    try testing.expectEqual(.first_request, connection.timed_out().?);
    try testing.expectEqual(h2.constants.error_no_error, try goaway_code(send_at(first_request_ns)));
    try testing.expect(connection.should_close());
}

test "RFC 9113 §6.10: an h2 field block left unfinished ends the connection with ENHANCE_YOUR_CALM" {
    try h2_support.start();
    try answer_at(try receive_at(try h2_support.request_frame(1, "/", true), early_ns), early_ns);
    // A HEADERS frame whose block continues in CONTINUATION frames that never come.
    const frame = try h2_support.request_frame(3, "/b", true);
    var open_block: [h2_support.frames.len]u8 = undefined;
    @memcpy(open_block[0..frame.len], frame);
    open_block[h2_support.flags_index] &= ~h2.constants.flag_end_headers;
    const began_ns = early_ns + idle_ns / 2;
    _ = try receive_at(open_block[0..frame.len], began_ns);
    try testing.expectEqual(began_ns + head_ns, connection.deadline_ns().?);
    connection.on_instant(began_ns + head_ns);
    try testing.expectEqual(.head, connection.timed_out().?);
    try testing.expectEqual(h2.constants.error_enhance_your_calm, try goaway_code(send_at(began_ns + head_ns)));
}

test "decision 110: an idle h2 connection gets a GOAWAY with NO_ERROR at the idle deadline" {
    try h2_support.start();
    try answer_at(try receive_at(try h2_support.request_frame(1, "/", true), early_ns), early_ns);
    try testing.expectEqual(early_ns + idle_ns, connection.deadline_ns().?);
    // A PING is not a request, so it does not move the deadline.
    _ = try receive_at(&(try ping_frame()), early_ns + idle_ns / 2);
    _ = send_at(early_ns + idle_ns / 2);
    try testing.expectEqual(early_ns + idle_ns, connection.deadline_ns().?);
    connection.on_instant(early_ns + idle_ns);
    try testing.expectEqual(.idle, connection.timed_out().?);
    try testing.expectEqual(h2.constants.error_no_error, try goaway_code(send_at(early_ns + idle_ns)));
}

test "decision 110: a TLS handshake that does not end in time closes the connection with nothing sent" {
    try support.begin_tls(&support.protocols_both, &support.protocols_both);
    connection.on_instant(first_request_ns);
    try testing.expectEqual(.first_request, connection.timed_out().?);
    try testing.expectEqual(0, send_at(first_request_ns).len);
    try testing.expect(connection.should_close());
}

test "decision 110: a caller changes one connection's limits, null turns one off, and 0 is refused" {
    try support.start_cleartext(.h11);
    try testing.expectError(error.DeadlineInvalid, connection.set_deadlines(.{ .idle_ns = 0 }));
    try connection.set_deadlines(.{ .first_request_ns = null });
    try testing.expectEqual(null, connection.deadline_ns());
    // A shorter limit counts from the start the deadline already has.
    try connection.set_deadlines(.{ .first_request_ns = early_ns });
    try testing.expectEqual(early_ns, connection.deadline_ns().?);
    support.config = .{ .cleartext = .h11, .deadlines = .{ .head_ns = 0 } };
    try testing.expectError(error.DeadlineInvalid, connection.init(&support.config, support.stream.random(), 0, 0));
}

test "decision 110: the configuration's limits apply from the instant init is given" {
    support.config = .{ .cleartext = .h11, .deadlines = .{ .first_request_ns = early_ns } };
    try connection.init(&support.config, support.stream.random(), 0, idle_ns);
    try testing.expectEqual(idle_ns + early_ns, connection.deadline_ns().?);
}
