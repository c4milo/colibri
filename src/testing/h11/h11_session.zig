//! One h11 connection of the test-only server, with no socket in it: octets in, octets out, and a
//! 200 response to every request once it is read whole (design §9). `server.zig` is the socket
//! around it, and these tests drive the same code the socket does.
//!
//! `step` repeats two things, each bounded by the caller's buffers:
//!   1. writes what the connection owes: the error response to a request it refused
//!      (decision 92), or what is left of the response to the request read last;
//!   2. reads the next event of the input.
//! It stops when the input runs out, when the output has no room for what is owed, or when the
//! connection waits for a response to be written. The connection reads one request at a time
//! (decision 92), so at most one response is owed.
//!
//! The server answers every request the same way, whatever its method or target, as the h2
//! session does: 200 and `response_body`. A HEAD request gets the same head and no body
//! (RFC 9112 §6.3 rule 1), which the connection decides. The connection closes after the response
//! when either side asked for it (RFC 9112 §9.6), and the session is then done.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const constants = @import("../constants.zig");
const h11_echo = @import("h11_echo.zig");

const Connection = h11.connection.Connection;
const Field = h11.http.field.Field;

/// What one step did.
pub const Step = struct {
    /// Octets of the caller's input the connection consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// Whether the connection is finished and everything it owes is written.
    done: bool,
};

/// What is left to write of the response to the request read last: a 100 (Continue) the client
/// waits for before it sends the content, then the final response's head, body and end.
const Owed = enum { nothing, interim, head, body, end };

/// The fields every response carries (RFC 9110 §8.3, §8.6).
const response_fields = [_]Field{
    .{ .name = "Content-Type", .value = constants.response_content_type },
    .{ .name = "Content-Length", .value = constants.response_content_length },
};

/// The reason phrase of `response_status` (RFC 9110 §15.3.1).
const response_reason = "OK";

/// 413 (Content Too Large) and its reason phrase (RFC 9110 §15.5.14).
const too_large_status: u16 = 413;
const too_large_reason = "Content Too Large";

/// The media type of an echo (RFC 9110 §8.3).
const echo_content_type = "application/json";

/// 100 (Continue) and its reason phrase (RFC 9110 §15.2.1).
const continue_status: u16 = 100;
const continue_reason = "Continue";

/// Passes of `step` per octet of input: one that consumes it, and one that ends its request.
const passes_per_octet = 2;

/// Passes of `step` that consume nothing and end no request: the one after a refusal, which
/// writes its error response, and the last, which finds nothing more to read.
const passes_after_input = 2;

/// One connection's server state, in storage the caller places.
pub const Session = struct {
    connection: Connection,
    owed: Owed,
    /// Where the `--echo` mode keeps the request it returns, or null in every other mode. The
    /// server places it apart from the session, so the mode costs the other sessions nothing.
    echo: ?*h11_echo.Echo,
    /// Octets of the response's content written so far.
    content_sent: usize,

    /// Makes a server connection that has read nothing and written nothing.
    pub fn init(session: *Session) void {
        session.connection.init(.server, .{});
        session.owed = .nothing;
        session.echo = null;
        session.content_sent = 0;
        assert(session.connection.phase == .head);
    }

    /// Consumes what it can of `input` and writes what it can into `output`. See the header.
    pub fn step(session: *Session, input: []const u8, output: []u8) Step {
        var consumed: usize = 0;
        var written: usize = 0;
        // Every pass consumes an octet, ends a request, or is one of `passes_after_input`, and a
        // request takes at least one octet, so n octets take at most 2n passes and those.
        for (0..passes_per_octet * input.len + passes_after_input) |_| {
            written += session.write_owed(output[written..]);
            // A connection waiting for its response to be written reads nothing, so a response
            // the output has no room for ends the step here.
            const received = session.connection.receive(input[consumed..]) catch |failure| {
                // Decision 92: the refusal's error response is owed, and the next pass writes it.
                assert(failure == error.ConnectionFailed);
                continue;
            };
            consumed += received.consumed;
            // `should_close` waits for the error response a refusal owes, too.
            const event = received.event orelse return .{ .consumed = consumed, .written = written, .done = session.connection.should_close() };
            session.on_event(event);
        }
        unreachable;
    }

    /// Writes as much of what is owed as `output` holds, and returns the octets written.
    fn write_owed(session: *Session, output: []u8) usize {
        if (session.connection.has_pending()) {
            return session.connection.write_pending(output) catch |failure| return no_room(failure);
        }
        var written: usize = 0;
        // Bounded: each pass moves `owed` one state on, or stops.
        for (0..@typeInfo(Owed).@"enum".fields.len) |_| {
            const step_written = session.write_part(output[written..]) catch |failure| return written + no_room(failure);
            written += step_written;
            if (session.owed == .nothing) return written;
        }
        unreachable;
    }

    /// Notes what one event says about the response owed, and keeps what an echo returns.
    fn on_event(session: *Session, event: h11.connection.Event) void {
        if (session.echo) |echo| switch (event) {
            // The head's octets are valid until the next read, so the echo copies them now.
            .request => |request| echo.begin(request.line, &session.connection.section),
            .data => |data| echo.add(data),
            else => {},
        };
        // The request is read whole once the connection waits, and its `end` is not owed.
        if (session.connection.phase == .waiting and event != .data) {
            if (session.echo) |echo| echo.finish();
            session.owed = .head;
            session.content_sent = 0;
        }
        if (event == .request and session.expects_continue(event.request)) session.owed = .interim;
    }

    /// Whether the request asks for a 100 (Continue) before its content. RFC 9110 §10.1.1: an
    /// origin server MUST send one at once when an HTTP/1.1 request's Expect field holds
    /// "100-continue" and content will follow, and MUST ignore the expectation in HTTP/1.0.
    fn expects_continue(session: *const Session, request: h11.connection.Request) bool {
        if (request.line.version.minor == 0) return false;
        // RFC 9110 §10.1.1: the server MAY omit it when the framing says no content follows.
        if (session.connection.phase != .body) return false;
        const expect = session.connection.section.find("expect") orelse return false;
        var expectations = std.mem.splitScalar(u8, expect.value, ',');
        // Bounded: a value of n octets holds at most n + 1 members.
        for (0..expect.value.len + 1) |_| {
            const expectation = expectations.next() orelse return false;
            // RFC 9110 §10.1.1: the Expect field value is case-insensitive.
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, expectation, " \t"), "100-continue")) return true;
        }
        return false;
    }

    /// The content of the response owed: the request's echo in the `--echo` mode, and
    /// `response_body` otherwise.
    fn content(session: *const Session) []const u8 {
        const echo = session.echo orelse return constants.response_body;
        return echo.written();
    }

    /// Writes the head of the response owed: 200 with its content, or, when the echo could not
    /// keep the request's content, 413 with none (RFC 9110 §15.5.14).
    fn write_head(session: *Session, output: []u8) h11.connection.SendError!usize {
        const connection = &session.connection;
        const echo = session.echo orelse return connection.write_response(output, constants.response_status, response_reason, &response_fields);
        if (echo.body_too_long) return connection.write_response(output, too_large_status, too_large_reason, &.{.{ .name = "Content-Length", .value = "0" }});
        var digits: [constants.content_length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&digits, "{d}", .{echo.written().len}) catch unreachable;
        const fields = [_]Field{
            .{ .name = "Content-Type", .value = echo_content_type },
            .{ .name = "Content-Length", .value = length },
        };
        return connection.write_response(output, constants.response_status, response_reason, &fields);
    }

    /// Writes the next part of the response, and moves `owed` past it.
    fn write_part(session: *Session, output: []u8) h11.connection.SendError!usize {
        const connection = &session.connection;
        switch (session.owed) {
            .nothing => return 0,
            .interim => {
                const written = try connection.write_response(output, continue_status, continue_reason, &.{});
                session.owed = .nothing;
                return written;
            },
            .head => {
                const written = try session.write_head(output);
                // RFC 9112 §6.3 rule 1: a response to HEAD has no body, and is written whole.
                session.owed = if (connection.writer.open()) .body else .nothing;
                return written;
            },
            .body => {
                // The content goes out as far as the room allows, and the rest in a later step.
                const left = session.content()[session.content_sent..];
                const slice = left[0..@min(left.len, output.len)];
                if (slice.len == 0) return error.OutputTooSmall;
                const written = try connection.write_body(output, slice);
                session.content_sent += slice.len;
                if (session.content_sent == session.content().len) session.owed = .end;
                return written;
            },
            .end => {
                const written = try connection.write_end(output, &.{});
                session.owed = .nothing;
                return written;
            },
        }
    }
};

/// A write that failed for want of room writes nothing, and waits for the socket to drain. Any
/// other failure is this file's defect: the response is the same valid one every time.
fn no_room(failure: anyerror) usize {
    assert(failure == error.OutputTooSmall);
    return 0;
}

const testing = std.testing;

/// The session and buffer the tests use, outside any stack frame. Test-only.
var test_session: Session = undefined;
var test_output: [test_output_len]u8 = undefined;
const test_output_len = 1024;

/// The response every request gets. Test-only.
const response = "HTTP/1.1 200 OK\r\nContent-Type: " ++ constants.response_content_type ++
    "\r\nContent-Length: " ++ constants.response_content_length ++ "\r\n\r\n";

fn fresh_session() *Session {
    test_session.init();
    return &test_session;
}

test "every request is answered with 200 and the body, pipelined ones in order" {
    const target = fresh_session();
    const input = "GET / HTTP/1.1\r\nHost: a\r\n\r\nPOST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
    const stepped = target.step(input, &test_output);
    try testing.expectEqual(input.len, stepped.consumed);
    try testing.expectEqualStrings(response ++ constants.response_body ++ response ++ constants.response_body, test_output[0..stepped.written]);
    try testing.expect(!stepped.done);
}

test "a request split anywhere is answered once it is whole" {
    const target = fresh_session();
    const input = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
    var consumed: usize = 0;
    var written: usize = 0;
    for (1..input.len + 1) |end| {
        const stepped = target.step(input[consumed..end], test_output[written..]);
        consumed += stepped.consumed;
        written += stepped.written;
        // Nothing is written before the last octet arrives.
        if (end < input.len) try testing.expectEqual(0, written);
    }
    try testing.expectEqual(input.len, consumed);
    try testing.expectEqualStrings(response ++ constants.response_body, test_output[0..written]);
}

test "RFC 9112 §6.3 rule 1 and §9.6: HEAD gets no body, and the close option ends the session" {
    const target = fresh_session();
    const input = "HEAD / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n";
    const stepped = target.step(input, &test_output);
    const closed = "HTTP/1.1 200 OK\r\nContent-Type: " ++ constants.response_content_type ++
        "\r\nContent-Length: " ++ constants.response_content_length ++ "\r\nConnection: close\r\n\r\n";
    try testing.expectEqualStrings(closed, test_output[0..stepped.written]);
    try testing.expect(stepped.done);
    // The request after the close is never read.
    try testing.expect(stepped.consumed < input.len);
}

test "decision 92: a refused request gets its error response, and then the session is done" {
    const target = fresh_session();
    // No room for the error response: the session is not done until it is written.
    const first = target.step("GET / HTTP/1.1\r\n\r\n", test_output[0..1]);
    try testing.expectEqual(0, first.written);
    try testing.expect(!first.done);
    const stepped = target.step(&.{}, &test_output);
    try testing.expectEqualStrings("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", test_output[0..stepped.written]);
    try testing.expect(stepped.done);
}

test "a response the output has no room for waits for a later step" {
    const target = fresh_session();
    const input = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    const first = target.step(input, test_output[0 .. response.len - 1]);
    try testing.expectEqual(input.len, first.consumed);
    try testing.expectEqual(0, first.written);
    // The head fits and the body does not: the head goes out alone, and the body next.
    const second = target.step(&.{}, test_output[0..response.len]);
    try testing.expectEqualStrings(response, test_output[0..second.written]);
    const third = target.step(&.{}, &test_output);
    try testing.expectEqualStrings(constants.response_body, test_output[0..third.written]);
    try testing.expect(!third.done);
}

test "RFC 9110 §10.1.1: an HTTP/1.1 request expecting 100-continue gets it before its content" {
    const target = fresh_session();
    const head = "POST / HTTP/1.1\r\nHost: a\r\nExpect: token, 100-Continue\r\nContent-Length: 3\r\n\r\n";
    const first = target.step(head, &test_output);
    try testing.expectEqual(head.len, first.consumed);
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", test_output[0..first.written]);
    const second = target.step("abc", &test_output);
    try testing.expectEqualStrings(response ++ constants.response_body, test_output[0..second.written]);
    // No content follows, or the request is HTTP/1.0: no 100 goes out.
    for ([_][]const u8{
        "GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
        "POST / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\nx",
        "POST / HTTP/1.1\r\nHost: a\r\nExpect: other\r\nContent-Length: 1\r\n\r\nx",
    }) |input| {
        const plain = fresh_session().step(input, &test_output);
        try testing.expect(std.mem.startsWith(u8, test_output[0..plain.written], "HTTP/1.1 200 OK\r\n"));
    }
}

/// The echo the `--echo` tests attach, outside any stack frame. Test-only.
var test_echo: h11_echo.Echo = undefined;

fn echo_session() *Session {
    const target = fresh_session();
    target.echo = &test_echo;
    return target;
}

test "the echo mode answers each request with the JSON of what h11 read" {
    const target = echo_session();
    const input = "POST /p HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    const stepped = target.step(input, &test_output);
    const written = test_output[0..stepped.written];
    const json = "{\"method\":\"UE9TVA==\",\"uri\":\"L3A=\",\"version\":\"SFRUUC8xLjE=\"," ++
        "\"headers\":[[\"SG9zdA==\",\"YQ==\"],[\"VHJhbnNmZXItRW5jb2Rpbmc=\",\"Y2h1bmtlZA==\"]],\"body\":\"aGVsbG8=\"}";
    const head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " ++
        std.fmt.comptimePrint("{d}", .{json.len}) ++ "\r\n\r\n";
    try testing.expectEqualStrings(head ++ json, written);
}

test "the echo mode answers content past its limit with 413, and writes a long echo in slices" {
    var target = echo_session();
    var input: [test_long_input_len]u8 = undefined;
    const head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: " ++
        std.fmt.comptimePrint("{d}", .{constants.echo_body_len_max + 1}) ++ "\r\n\r\n";
    @memcpy(input[0..head.len], head);
    @memset(input[head.len..][0 .. constants.echo_body_len_max + 1], 'x');
    const refused = target.step(input[0 .. head.len + constants.echo_body_len_max + 1], &test_output);
    try testing.expect(std.mem.startsWith(u8, test_output[0..refused.written], "HTTP/1.1 413 Content Too Large\r\n"));
    // A GET whose echo is longer than the output: the content goes out over several steps.
    target = echo_session();
    const get = "GET /" ++ "a" ** 1200 ++ " HTTP/1.1\r\nHost: a\r\n\r\n";
    var steps: usize = 0;
    var content_len: usize = 0;
    for (0..test_output.len) |_| {
        const stepped = target.step(if (steps == 0) get else "", test_output[0..test_small_output_len]);
        steps += 1;
        content_len += stepped.written;
        if (target.owed == .nothing and steps > 1) break;
    }
    try testing.expect(steps > 2);
    try testing.expect(content_len > test_output.len);
}

/// Room for a request whose content is one past the echo's limit: the content and a head of at
/// most `test_head_len_max` octets. Test-only.
const test_long_input_len = constants.echo_body_len_max + test_head_len_max;
const test_head_len_max = 128;
/// An output smaller than any echo, so an echo goes out in slices. Test-only.
const test_small_output_len = 128;
