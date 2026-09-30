//! One connection of design §9's server, over colibri's `server` module (design §8 step 17a): the
//! octets the socket read go in, the octets it sends come out, and every request is answered with
//! 200 and `response_body` once it is read whole. `server.zig` is the socket around it. In the
//! `--echo` mode, an h11 request is answered with its echo (`h11/h11_echo.zig`) instead. The
//! server opens no tunnel, so a CONNECT is answered 501 in every mode.
//!
//! `step` repeats three things until none moves, each bounded by the caller's buffers:
//!   1. reads events until the input runs out, the connection waits, or `responses_owed_max`
//!      requests are owed;
//!   2. writes as much of the owed responses as the connection takes, oldest first;
//!   3. sends what the connection owes into the caller's output.
//! h11 reads a pipelined request only once the one before it is answered (decision 92), so the
//! answer to one request is what lets the next be read.
//!
//! The connection runs TLS itself when its configuration names it, so this file holds no record
//! and no protocol rule: it answers requests through the calls every program uses.
const std = @import("std");
const assert = std.debug.assert;
pub const server = @import("server");
const h2 = @import("h2");
const constants = @import("constants.zig");
const h11_echo = @import("h11/h11_echo.zig");

const http = h2.http;

/// What one step did.
pub const Step = struct {
    /// Octets of the caller's input the connection consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// Whether the connection is finished and everything it owes is written.
    done: bool,
};

/// A request read or being read, and whether its response carries content: a response to HEAD
/// has the same fields and none (RFC 9110 §9.3.2), and a CONNECT gets a refusal with none.
const Request = struct {
    id: server.Id,
    head: bool,
    connect: bool,
};

/// The fields every response carries (RFC 9110 §8.3, §8.6).
const response_fields = [_]server.Field{
    .{ .name = "content-type", .value = constants.response_content_type },
    .{ .name = "content-length", .value = constants.response_content_length },
};

/// The media type of an echo (RFC 9110 §8.3), and the status of one too large to keep (RFC 9110
/// §15.5.14).
const echo_content_type = "application/json";
const too_large_status: u16 = 413;

/// The answer to CONNECT, a tunnel the server does not implement (RFC 9110 §9.3.6, §15.6.2).
const not_implemented_status: u16 = 501;

/// Events one step reads at most. Each takes an octet of input, or reports what the connection
/// already holds, so a step that reaches the bound leaves the rest to the next.
const events_per_step_max: usize = 1024;

pub const Session = struct {
    connection: server.Connection,
    /// Requests whose head arrived and whose end has not, and requests owed a response, oldest
    /// first.
    reading: [constants.responses_owed_max]Request,
    reading_count: u32,
    owed: [constants.responses_owed_max]Request,
    owed_count: u32,
    /// Whether the oldest owed response's head is written, and octets of its content sent.
    head_written: bool,
    content_sent: usize,
    /// Where the `--echo` mode keeps the request it returns, or null in every other mode.
    echo: ?*h11_echo.Echo,
    /// The instant the next step reports (design §4.2).
    now_ns: u64,

    /// Prepares a connection the listener accepted, under `config`.
    pub fn init(session: *Session, config: *const server.Config, random: std.Random, echo: ?*h11_echo.Echo) server.StartError!void {
        session.reading_count = 0;
        session.owed_count = 0;
        session.head_written = false;
        session.content_sent = 0;
        session.echo = echo;
        session.now_ns = 0;
        // The server issues no ticket, so it judges none at a clock: chapulin's 0 for none.
        try session.connection.init(config, random, 0, session.now_ns);
        assert(session.connection.output_len == 0);
    }

    /// Consumes what it can of `input` and writes what it can into `output`. See the header.
    pub fn step(session: *Session, input: []u8, output: []u8) Step {
        session.now_ns += constants.tick_ns;
        var consumed: usize = 0;
        var written: usize = 0;
        // Bounded: a pass that neither reads nor finishes a response ends the loop.
        for (0..events_per_step_max) |_| {
            const read_len = session.read(input[consumed..]);
            consumed += read_len;
            const finished = session.write_responses();
            written += session.connection.send(output[written..], session.now_ns);
            if (read_len == 0 and finished == 0) break;
        }
        return .{ .consumed = consumed, .written = written, .done = session.connection.should_close() };
    }

    /// Reads events until the input runs out, the connection waits, or the owed queue is full.
    fn read(session: *Session, input: []u8) usize {
        var consumed: usize = 0;
        for (0..events_per_step_max) |_| {
            if (session.owed_count == session.owed.len or session.reading_count == session.reading.len) return consumed;
            // A failed connection reads nothing more, and `send` writes what it owes.
            const received = session.connection.receive(input[consumed..], session.now_ns) catch return consumed;
            consumed += received.consumed;
            const event = received.event orelse {
                if (received.consumed == 0) return consumed;
                continue;
            };
            session.on_event(event);
        }
        return consumed;
    }

    /// Notes what one event says about the responses owed, and keeps what an echo returns. The
    /// event's octets are valid until the next read, so the echo copies them now.
    fn on_event(session: *Session, event: server.Event) void {
        switch (event) {
            .request => |request| {
                if (session.echo) |echo| echo.begin(.{
                    .method = request.method,
                    .target = request.target,
                    .version = .{ .major = request.version.major, .minor = request.version.minor },
                }, request.fields.section);
                const method = http.method.standard(request.method);
                const read_request: Request = .{ .id = request.id, .head = method == .head, .connect = method == .connect };
                if (request.end) session.owe(read_request) else session.start_reading(read_request);
            },
            .body => |body| {
                if (session.echo) |echo| echo.add(body.octets);
                if (body.end) session.finish_reading(body.id);
            },
            .trailers => |trailers| session.finish_reading(trailers.id),
            .cancelled => |cancelled| session.forget(cancelled.id),
            // Every response body is a constant or the echo's own copy, so nothing waits for it.
            .done => {},
        }
    }

    fn start_reading(session: *Session, request: Request) void {
        assert(session.reading_count < session.reading.len);
        session.reading[session.reading_count] = request;
        session.reading_count += 1;
    }

    /// The request `id` ended, so its response is owed.
    fn finish_reading(session: *Session, id: server.Id) void {
        const index = find(session.reading[0..session.reading_count], id) orelse return;
        const request = session.reading[index];
        remove(&session.reading, &session.reading_count, index);
        session.owe(request);
    }

    fn owe(session: *Session, request: Request) void {
        assert(session.owed_count < session.owed.len);
        if (session.echo) |echo| echo.finish();
        session.owed[session.owed_count] = request;
        session.owed_count += 1;
    }

    /// The request `id` ended before its response: the peer reset it, or the connection refused it.
    fn forget(session: *Session, id: server.Id) void {
        if (find(session.reading[0..session.reading_count], id)) |index| remove(&session.reading, &session.reading_count, index);
        const index = find(session.owed[0..session.owed_count], id) orelse return;
        if (index == 0) {
            session.finish_oldest();
            return;
        }
        remove(&session.owed, &session.owed_count, index);
    }

    /// Writes as much of the owed responses as the connection takes, oldest first, and returns how
    /// many it finished.
    fn write_responses(session: *Session) usize {
        var finished: usize = 0;
        for (0..constants.responses_owed_max) |_| {
            if (session.owed_count == 0) return finished;
            if (!session.write_oldest()) return finished;
            finished += 1;
        }
        return finished;
    }

    /// Writes what is left of the oldest owed response, and returns whether it is written whole.
    fn write_oldest(session: *Session) bool {
        const oldest = session.owed[0];
        if (!session.head_written) {
            session.write_head(oldest) catch |failure| return session.write_failed(failure);
            session.head_written = true;
            if (oldest.head or oldest.connect or session.echo_refused()) {
                session.finish_oldest();
                return true;
            }
        }
        const octets = session.content();
        const taken = session.connection.write_body(oldest.id, .{ .octets = octets[session.content_sent..], .end = true }) catch |failure| {
            return session.write_failed(failure);
        };
        session.content_sent += taken;
        if (session.content_sent < octets.len) return false;
        session.finish_oldest();
        return true;
    }

    /// Writes the head of the response owed: 200 with its content's fields, or, when the echo could
    /// not keep the request's content, 413 with none (RFC 9110 §15.5.14), or 501 with none to a
    /// CONNECT.
    fn write_head(session: *Session, request: Request) server.SendError!void {
        const connection = &session.connection;
        if (request.connect) return connection.respond(request.id, .{ .status = not_implemented_status, .end = true });
        // Decision 101: the fixed answer may be coded, and an echo goes out as it arrived.
        const echo = session.echo orelse return connection.respond(request.id, .{ .status = constants.response_status, .fields = &response_fields, .end = request.head, .codable = true });
        if (echo.body_too_long) return connection.respond(request.id, .{ .status = too_large_status, .end = true });
        var digits: [constants.content_length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&digits, "{d}", .{echo.written().len}) catch unreachable;
        const fields = [_]server.Field{
            .{ .name = "content-type", .value = echo_content_type },
            .{ .name = "content-length", .value = length },
        };
        return connection.respond(request.id, .{ .status = constants.response_status, .fields = &fields, .end = request.head });
    }

    fn echo_refused(session: *const Session) bool {
        const echo = session.echo orelse return false;
        return echo.body_too_long;
    }

    /// The content of the response owed: the request's echo in the `--echo` mode, and
    /// `response_body` otherwise.
    fn content(session: *const Session) []const u8 {
        const echo = session.echo orelse return constants.response_body;
        return echo.written();
    }

    /// What a write that failed means for the oldest response: it waits for room or a window, or
    /// the request is gone and so is its response.
    fn write_failed(session: *Session, failure: server.SendError) bool {
        switch (failure) {
            error.NoSpaceLeft, error.Blocked => return false,
            error.RequestUnknown, error.ConnectionClosed, error.SectionOutOfOrder => {
                session.finish_oldest();
                return true;
            },
            // The response is the same valid one every time.
            else => unreachable,
        }
    }

    /// Drops the oldest owed response, written or gone, and makes the next one the oldest.
    fn finish_oldest(session: *Session) void {
        remove(&session.owed, &session.owed_count, 0);
        session.head_written = false;
        session.content_sent = 0;
    }
};

fn find(requests: []const Request, id: server.Id) ?usize {
    for (requests, 0..) |request, index| {
        if (request.id == id) return index;
    }
    return null;
}

fn remove(requests: *[constants.responses_owed_max]Request, count: *u32, index: usize) void {
    assert(index < count.*);
    for (index + 1..count.*) |next| requests[next - 1] = requests[next];
    count.* -= 1;
}

test {
    _ = @import("server_session_test.zig");
}
