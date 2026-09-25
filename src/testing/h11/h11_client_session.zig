//! One h11 connection of the test-only client, with no socket in it: octets in, octets out, and a
//! plan of exchanges it runs to the end (design §9). `client/client_loop.zig` is its socket, and
//! these tests drive the same code the socket does, against `h11_session.zig` in one process.
//!
//! `step` does two things in order, each bounded by the caller's buffers:
//!   1. reads responses until the input runs out or the connection fails, and gives each to the
//!      oldest exchange whose request is written and unanswered (RFC 9112 §9.3.2);
//!   2. writes requests in plan order, each head, content and end whole before the next head,
//!      while the connection lets it: it pipelines as decision 88 rules, so a request after a
//!      POST waits for the POST's final response.
//! The last request carries `Connection: close` (RFC 9112 §9.6), so the connection ends after its
//! response. When the connection closes first, every exchange still pending is abandoned. The
//! session is done once no exchange is pending, or the connection failed.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const constants = @import("../constants.zig");
const client_exchange = @import("../client/client_exchange.zig");

const Connection = h11.connection.Connection;
const Field = h11.http.field.Field;
const Exchange = client_exchange.Exchange;
const Plan = client_exchange.Plan;

/// What one step did.
pub const Step = struct {
    /// Octets of the caller's input the connection consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// Whether the session is finished: every octet it will ever write has been written.
    done: bool,
};

/// Passes of the reading per octet of input: one that consumes it, and one that ends a response.
const passes_per_octet = 2;

/// The field lines a request carries at most: Host, User-Agent, Content-Length and the close.
const request_fields_max = 4;

/// One connection's client state, in storage the caller places.
pub const Session = struct {
    connection: Connection,
    /// The authority every request names in Host (RFC 9112 §3.2).
    authority: []const u8,
    exchanges: [constants.exchanges_max]Exchange,
    exchanges_count: u32,
    /// The next exchange whose request is written, and whether its head is out already.
    sending: u32,
    head_sent: bool,
    /// Where the search for the exchange a response answers starts.
    reading: u32,
    /// Whether the connection failed: the peer sent what h11 refuses, or cut a message short.
    failed: bool,

    /// Makes a client connection that has read nothing and written nothing. The slices of `plans`
    /// and `authority` must outlive the session.
    pub fn init(session: *Session, authority: []const u8, plans: []const Plan) void {
        assert(plans.len > 0 and plans.len <= constants.exchanges_max);
        assert(authority.len > 0);
        session.connection.init(.client, .{});
        session.authority = authority;
        session.exchanges_count = @intCast(plans.len);
        session.sending = 0;
        session.head_sent = false;
        session.reading = 0;
        session.failed = false;
        for (plans, 0..) |plan, index| session.exchanges[index] = .init(plan);
    }

    /// Consumes what it can of `input` and writes what it can into `output`. See the header.
    pub fn step(session: *Session, input: []const u8, output: []u8) Step {
        const consumed = if (session.failed) 0 else session.read_responses(input);
        const written = if (session.failed) 0 else session.write_requests(output);
        // RFC 9112 §9.6: nothing more is read or written once the connection closes.
        if (session.connection.phase == .closed) session.abandon_pending();
        return .{ .consumed = consumed, .written = written, .done = session.failed or session.settled() };
    }

    /// Whether every exchange ended the way a working peer ends one: a final response read whole,
    /// with the request content sent whole and the connection intact.
    pub fn succeeded(session: *const Session) bool {
        if (session.failed) return false;
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.outcome != .ended) return false;
            // RFC 9112 §9.2: an exchange ends with its final response, never before one.
            assert(exchange.status != 0);
            if (exchange.content_sent != exchange.plan.content_len) return false;
        }
        return true;
    }

    /// The peer closed the transport. A body that runs until the close ends with it (RFC 9112
    /// §6.3 rule 8), a message cut short fails the connection (§8), and the requests left
    /// unanswered are abandoned (§9.6).
    pub fn transport_closed(session: *Session) void {
        const closed = session.connection.transport_closed();
        if (closed.ended_body) session.finish(session.oldest_unanswered() orelse unreachable);
        if (closed.incomplete) session.failed = true;
        session.abandon_pending();
    }

    /// Whether no exchange is still pending.
    fn settled(session: *const Session) bool {
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.outcome == .pending) return false;
        }
        return true;
    }

    fn abandon_pending(session: *Session) void {
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.outcome == .pending) exchange.outcome = .abandoned;
        }
    }

    /// Reads responses until the input runs out or the connection fails.
    fn read_responses(session: *Session, input: []const u8) usize {
        var consumed: usize = 0;
        // Every pass consumes an octet or ends a response, and a response takes at least one
        // octet, so n octets take at most 2n passes, and one more finds them short.
        for (0..passes_per_octet * input.len + 1) |_| {
            const received = session.connection.receive(input[consumed..]) catch {
                session.failed = true;
                return consumed;
            };
            consumed += received.consumed;
            session.record(received.event orelse return consumed);
        }
        unreachable;
    }

    /// Records what one event meant for the exchange it answers.
    fn record(session: *Session, event: h11.connection.Event) void {
        // The connection gives every response to its oldest outstanding request, and requests
        // go out in plan order, so the event answers the oldest exchange sent and pending.
        const index = session.oldest_unanswered() orelse unreachable;
        const exchange = &session.exchanges[index];
        switch (event) {
            // RFC 9110 §15.2: any number of interim responses precede the final one.
            .interim => exchange.interim_count += 1,
            .response => |response| {
                exchange.status = response.line.status.code;
                // A response without a body is read whole with its head.
                if (session.connection.phase != .body) session.finish(index);
            },
            .data => |data| {
                exchange.content_received += data.len;
                exchange.received_crc32.update(data);
            },
            .end => session.finish(index),
            // A client reads no request, and sends no CONNECT to be tunnelled.
            .request, .tunnel => unreachable,
        }
    }

    /// The oldest exchange whose request is written and whose response has not ended. The search
    /// starts where the last one found it, since the exchanges before it have all settled.
    fn oldest_unanswered(session: *Session) ?u32 {
        for (session.reading..session.sending + @intFromBool(session.head_sent)) |index| {
            if (session.exchanges[index].outcome == .pending) {
                session.reading = @intCast(index);
                return session.reading;
            }
        }
        return null;
    }

    fn finish(session: *Session, index: u32) void {
        session.exchanges[index].outcome = .ended;
    }

    /// Writes requests in plan order while the connection and the room allow.
    fn write_requests(session: *Session, output: []u8) usize {
        // RFC 9112 §9.6: a client that read the close option sends nothing more, not even the rest
        // of a request's content.
        if (session.connection.phase == .closed) return 0;
        var written: usize = 0;
        // Bounded: every pass finishes a request, or stops.
        for (0..constants.exchanges_max) |_| {
            if (session.sending == session.exchanges_count) return written;
            const progress = session.write_request(output[written..]);
            written += progress.written;
            if (!progress.whole) return written;
        }
        return written;
    }

    /// What `write_request` wrote, and whether the request is whole.
    const Progress = struct { written: usize, whole: bool };

    /// Writes what is left of the request of `sending`: its head, its content and its end.
    fn write_request(session: *Session, output: []u8) Progress {
        const exchange = &session.exchanges[session.sending];
        var written: usize = 0;
        if (!session.head_sent) {
            written = session.write_head(exchange, output) orelse return .{ .written = 0, .whole = false };
            if (exchange.outcome != .pending) return session.next(written);
        }
        written += session.write_content(exchange, output[written..]);
        if (exchange.content_sent < exchange.plan.content_len) return .{ .written = written, .whole = false };
        // A fixed body ends with no octets, and the next head may follow (RFC 9112 §6.2).
        if (session.connection.writer.open()) written += session.connection.write_end(output[written..], &.{}) catch unreachable;
        return session.next(written);
    }

    /// Moves on to the next exchange's request, after `written` octets of this one.
    fn next(session: *Session, written: usize) Progress {
        session.sending += 1;
        session.head_sent = false;
        return .{ .written = written, .whole = true };
    }

    /// Writes the head of `exchange`'s request, or returns null when it must wait. A request
    /// colibri refuses settles the exchange.
    fn write_head(session: *Session, exchange: *Exchange, output: []u8) ?usize {
        var digits: [constants.content_length_digits_max]u8 = undefined;
        var fields: [request_fields_max]Field = undefined;
        const count = session.request_fields(exchange.plan, &digits, &fields);
        const written = session.connection.write_request(output, exchange.plan.method, exchange.plan.path, fields[0..count]) catch |failure| {
            exchange.outcome = switch (failure) {
                // Decision 88 holds the request back, or the room is short: it waits.
                error.OutputTooSmall, error.PipelineBlocked, error.PipelineFull => return null,
                // `write_requests` writes nothing once the connection closed.
                error.ConnectionClosed => unreachable,
                else => .invalid,
            };
            return 0;
        };
        session.head_sent = true;
        return written;
    }

    /// The field lines of a request for `plan` written into `fields`, and how many there are.
    fn request_fields(session: *const Session, plan: Plan, digits: []u8, fields: []Field) usize {
        var count: usize = 0;
        fields[count] = .{ .name = "Host", .value = session.authority };
        count += 1;
        fields[count] = .{ .name = "User-Agent", .value = constants.user_agent };
        count += 1;
        // RFC 9110 §8.6: a user agent sends Content-Length when the method defines a meaning
        // for content, even for none.
        if (plan.content_len > 0 or std.mem.eql(u8, plan.method, "POST")) {
            const length = std.fmt.bufPrint(digits, "{d}", .{plan.content_len}) catch unreachable;
            fields[count] = .{ .name = "Content-Length", .value = length };
            count += 1;
        }
        // RFC 9112 §9.6: the last request says the client closes after its response.
        if (session.sending + 1 == session.exchanges_count) {
            fields[count] = .{ .name = "Connection", .value = "close" };
            count += 1;
        }
        return count;
    }

    /// Writes as much of the request content as the room allows, in slices of the pattern.
    fn write_content(session: *Session, exchange: *Exchange, output: []u8) usize {
        var written: usize = 0;
        for (0..exchange.plan.content_len / constants.request_content_period + 1) |_| {
            const left = exchange.plan.content_len - exchange.content_sent;
            const room = output.len - written;
            if (left == 0 or room == 0) return written;
            const slice = client_exchange.content_from(exchange.content_sent, @intCast(@min(left, room)));
            const sent = session.connection.write_body(output[written..], slice) catch unreachable;
            exchange.sent_crc32.update(slice);
            exchange.content_sent += @intCast(slice.len);
            written += sent;
        }
        return written;
    }
};

const testing = std.testing;
const h11_session = @import("h11_session.zig");
const Crc32 = std.hash.Crc32;

/// The two sessions the tests run, and the octets each has written that the other has not read.
/// Placed outside any stack frame. Test-only.
var test_client: Session = undefined;
var test_server: h11_session.Session = undefined;
var test_to_server: [constants.write_buffer_len]u8 = @splat(0);
var test_to_client: [constants.write_buffer_len]u8 = @splat(0);

/// Most rounds a test exchanges octets for, which bounds its loop. Test-only.
const test_rounds_max: u32 = 4096;

/// Drops the first `consumed` of `len` octets and returns how many are left. Test-only.
fn test_drop(buffer: []u8, len: usize, consumed: usize) usize {
    std.mem.copyForwards(u8, buffer[0 .. len - consumed], buffer[consumed..len]);
    return len - consumed;
}

/// Runs `test_client` against `test_server` until the client is done or neither side moves, and
/// returns whether the server finished too. Test-only.
fn test_run() !bool {
    var to_server_len: usize = 0;
    var to_client_len: usize = 0;
    var server_done = false;
    for (0..test_rounds_max) |_| {
        const client = test_client.step(test_to_client[0..to_client_len], test_to_server[to_server_len..]);
        to_client_len = test_drop(&test_to_client, to_client_len, client.consumed);
        to_server_len += client.written;
        const server = test_server.step(test_to_server[0..to_server_len], test_to_client[to_client_len..]);
        to_server_len = test_drop(&test_to_server, to_server_len, server.consumed);
        to_client_len += server.written;
        server_done = server_done or server.done;
        const moved = client.consumed + client.written + server.consumed + server.written;
        if (client.done or moved == 0) return server_done;
    }
    return error.TestUnexpectedResult;
}

/// Steps `test_client` once over `input` with all of `test_to_server` to write into. Test-only.
fn test_feed(input: []const u8) Step {
    return test_client.step(input, &test_to_server);
}

const test_get: Plan = .{ .method = "GET", .path = "/", .content_len = 0 };

test "pipelined exchanges are answered in order, and the last one closes the connection" {
    test_server.init();
    // Past the buffers several times over, so the content goes out over many steps.
    const content_len = 3 * constants.write_buffer_len;
    test_client.init("localhost", &.{ test_get, .{ .method = "POST", .path = "/upload", .content_len = content_len }, test_get });
    try testing.expect(try test_run());
    try testing.expect(test_client.succeeded());
    const upload = &test_client.exchanges[1];
    try testing.expectEqual(content_len, upload.content_sent);
    try testing.expectEqual(client_exchange.content_crc32(content_len), upload.sent_crc32.final());
    for (test_client.exchanges[0..3]) |*exchange| {
        try testing.expectEqual(constants.response_status, exchange.status);
        try testing.expectEqual(Crc32.hash(constants.response_body), exchange.received_crc32.final());
    }
    // RFC 9112 §9.6: the client asked for the close, and both sides took it.
    try testing.expectEqual(.closed, test_client.connection.phase);
}

test "decision 88: no request follows a POST until the POST's response has arrived" {
    test_client.init("localhost", &.{ test_get, .{ .method = "POST", .path = "/", .content_len = 0 }, test_get });
    const first = test_feed("");
    const heads = std.mem.count(u8, test_to_server[0..first.written], " HTTP/1.1\r\n");
    try testing.expectEqual(2, heads);
    try testing.expect(std.mem.indexOf(u8, test_to_server[0..first.written], "Content-Length: 0\r\n") != null);
    const ok = "HTTP/1.1 204 \r\n\r\n";
    _ = test_feed(ok);
    // The GET's response alone leaves the POST outstanding, so the last request still waits.
    try testing.expectEqual(2, test_client.sending);
    const last = test_feed(ok);
    try testing.expectEqual(3, test_client.sending);
    try testing.expect(std.mem.endsWith(u8, test_to_server[0..last.written], "Connection: close\r\n\r\n"));
}

test "RFC 9112 §9.6: a response carrying the close abandons the exchanges after it" {
    // The POST holds the last request back, so the close arrives before it is written.
    test_client.init("localhost", &.{ test_get, .{ .method = "POST", .path = "/", .content_len = 0 }, test_get });
    _ = test_feed("");
    try testing.expectEqual(2, test_client.sending);
    const step = test_feed("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok");
    try testing.expectEqual(0, step.written);
    try testing.expectEqual(.ended, test_client.exchanges[0].outcome);
    try testing.expectEqual(.abandoned, test_client.exchanges[1].outcome);
    try testing.expectEqual(.abandoned, test_client.exchanges[2].outcome);
    try testing.expect(step.done and !test_client.succeeded());
}

test "a response that arrives before the content is sent whole ends its exchange, short" {
    const content_len = 3 * constants.write_buffer_len;
    test_client.init("localhost", &.{.{ .method = "POST", .path = "/", .content_len = content_len }});
    _ = test_feed("");
    try testing.expect(test_client.exchanges[0].content_sent < content_len);
    // RFC 9112 §9.3: a server may answer before it has read the whole request, and close.
    const step = test_feed("HTTP/1.1 413 \r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    // RFC 9112 §9.6: nothing more is sent, the rest of the content included.
    try testing.expectEqual(0, step.written);
    try testing.expectEqual(413, test_client.exchanges[0].status);
    try testing.expectEqual(.ended, test_client.exchanges[0].outcome);
    try testing.expect(step.done and !test_client.succeeded());
}

test "RFC 9112 §6.3 rule 8 and §8: the close ends a body that runs until it, and cuts any other" {
    test_client.init("localhost", &.{test_get});
    _ = test_feed("");
    _ = test_feed("HTTP/1.1 200 OK\r\n\r\nuntil the close");
    test_client.transport_closed();
    try testing.expect(test_client.succeeded());
    try testing.expectEqual("until the close".len, test_client.exchanges[0].content_received);
    test_client.init("localhost", &.{test_get});
    _ = test_feed("");
    _ = test_feed("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ncut");
    test_client.transport_closed();
    try testing.expect(test_client.failed and !test_client.succeeded());
}

test "a malformed response fails the session, and a refused request settles as invalid" {
    test_client.init("localhost", &.{test_get});
    _ = test_feed("");
    const step = test_feed("HTTP/1.1 200 OK\nContent-Length: 0\n\n");
    try testing.expect(test_client.failed and step.done);
    try testing.expectEqual(0, test_feed("HTTP/1.1 204 \r\n\r\n").consumed);
    test_client.init("localhost", &.{ .{ .method = "G ET", .path = "/", .content_len = 0 }, test_get });
    const written = test_feed("").written;
    try testing.expectEqual(.invalid, test_client.exchanges[0].outcome);
    try testing.expect(std.mem.startsWith(u8, test_to_server[0..written], "GET / HTTP/1.1\r\n"));
}

test "RFC 9112 §9.2: interim responses are counted, and the final one after them gives the status" {
    test_client.init("localhost", &.{test_get});
    _ = test_feed("");
    const step = test_feed("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 204 \r\n\r\n");
    try testing.expectEqual(2, test_client.exchanges[0].interim_count);
    try testing.expectEqual(204, test_client.exchanges[0].status);
    try testing.expect(step.done and test_client.succeeded());
}
