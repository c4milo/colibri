//! The responses one connection of the test-only server owes (`server_session.zig`): each request
//! is answered with 200 and `response_body` once it is read whole, oldest first. In the `--echo`
//! mode an h11 request is answered with its echo (`../h11/h11_echo.zig`) instead. The server opens
//! no tunnel, so a CONNECT is answered 501 in every mode.
//!
//! `write` answers through the calls every program makes on the server's endpoint, by the
//! request's id. One response waits for the one before it, so a response the connection has no
//! room or window for holds every later one of its connection, and no other connection's. Split
//! off `server_session.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const h2 = @import("h2");
const constants = @import("../constants.zig");
const h11_echo = @import("../h11/h11_echo.zig");

const http = h2.http;

comptime {
    // The endpoint holds `tcp_requests_max` open requests of a connection and refuses one more
    // itself, so the queues below, which hold the open requests alone, always have room.
    assert(constants.responses_owed_max > server.constants.tcp_requests_max);
}

/// A request read or being read, and whether its response carries content: a response to HEAD
/// has the same fields and none (RFC 9110 §9.3.2), and a CONNECT gets a refusal with none.
const Request = struct {
    number: u64,
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

/// What one `write` did: the responses it finished, and whether the endpoint took anything, which
/// the connection then owes its socket.
pub const Written = struct {
    finished: usize,
    wrote: bool,
};

pub const Answers = struct {
    /// Requests whose head arrived and whose end has not, and requests owed a response, oldest
    /// first.
    reading: [constants.responses_owed_max]Request,
    reading_count: u32,
    owed: [constants.responses_owed_max]Request,
    owed_count: u32,
    /// Whether the oldest owed response's head is written, and octets of its content sent.
    head_written: bool,
    content_sent: usize,
    /// Whether the endpoint took a head or content since `write` began.
    wrote: bool,
    /// Where the `--echo` mode keeps the request it returns, or null in every other mode.
    echo: ?*h11_echo.Echo,

    /// Owes nothing, for a connection the listener just accepted.
    pub fn reset(answers: *Answers, echo: ?*h11_echo.Echo) void {
        answers.reading_count = 0;
        answers.owed_count = 0;
        answers.head_written = false;
        answers.content_sent = 0;
        answers.wrote = false;
        answers.echo = echo;
    }

    /// A request's head arrived. Its octets are valid until the endpoint's next call, so the echo
    /// copies them now.
    pub fn on_request(answers: *Answers, request: server.Request) void {
        if (answers.echo) |echo| echo.begin(.{
            .method = request.method,
            .target = request.target,
            .version = .{ .major = request.version.major, .minor = request.version.minor },
        }, request.fields.section);
        const method = http.method.standard(request.method);
        const read: Request = .{ .number = request.id.number, .head = method == .head, .connect = method == .connect };
        if (request.end) answers.owe(read) else answers.start_reading(read);
    }

    /// Octets of a request's content arrived, which the echo keeps.
    pub fn on_body(answers: *Answers, body: server.Body) void {
        if (answers.echo) |echo| echo.add(body.octets);
        if (body.end) answers.finish_reading(body.id.number);
    }

    fn start_reading(answers: *Answers, request: Request) void {
        assert(answers.reading_count < answers.reading.len);
        answers.reading[answers.reading_count] = request;
        answers.reading_count += 1;
    }

    /// The request `number` ended, so its response is owed.
    pub fn finish_reading(answers: *Answers, number: u64) void {
        const index = find(answers.reading[0..answers.reading_count], number) orelse return;
        const request = answers.reading[index];
        remove(&answers.reading, &answers.reading_count, index);
        answers.owe(request);
    }

    fn owe(answers: *Answers, request: Request) void {
        assert(answers.owed_count < answers.owed.len);
        if (answers.echo) |echo| echo.finish();
        answers.owed[answers.owed_count] = request;
        answers.owed_count += 1;
    }

    /// The request `number` ended before its response: the peer reset it, the connection refused
    /// it, or the connection stopped first.
    pub fn forget(answers: *Answers, number: u64) void {
        if (find(answers.reading[0..answers.reading_count], number)) |index| remove(&answers.reading, &answers.reading_count, index);
        const index = find(answers.owed[0..answers.owed_count], number) orelse return;
        if (index == 0) {
            answers.finish_oldest();
            return;
        }
        remove(&answers.owed, &answers.owed_count, index);
    }

    /// Writes as much of the owed responses as `endpoint` takes for `connection`, oldest first.
    pub fn write(answers: *Answers, endpoint: anytype, connection: server.ConnectionHandle) Written {
        answers.wrote = false;
        var finished: usize = 0;
        for (0..constants.responses_owed_max) |_| {
            if (answers.owed_count == 0) break;
            if (!answers.write_oldest(endpoint, connection)) break;
            finished += 1;
        }
        return .{ .finished = finished, .wrote = answers.wrote };
    }

    /// Writes what is left of the oldest owed response, and returns whether it is written whole.
    fn write_oldest(answers: *Answers, endpoint: anytype, connection: server.ConnectionHandle) bool {
        const oldest = answers.owed[0];
        const id: server.Id = .{ .connection = connection, .number = oldest.number };
        if (!answers.head_written) {
            answers.write_head(endpoint, id, oldest) catch |failure| return answers.write_failed(failure);
            answers.head_written = true;
            answers.wrote = true;
            if (oldest.head or oldest.connect or answers.echo_refused()) {
                answers.finish_oldest();
                return true;
            }
        }
        const octets = answers.content();
        const taken = endpoint.write_body(id, .{ .octets = octets[answers.content_sent..], .end = true }) catch |failure| {
            return answers.write_failed(failure);
        };
        answers.content_sent += taken;
        answers.wrote = true;
        if (answers.content_sent < octets.len) return false;
        answers.finish_oldest();
        return true;
    }

    /// Writes the head of the response owed: 200 with its content's fields, or, when the echo could
    /// not keep the request's content, 413 with none (RFC 9110 §15.5.14), or 501 with none to a
    /// CONNECT.
    fn write_head(answers: *Answers, endpoint: anytype, id: server.Id, request: Request) server.SendError!void {
        if (request.connect) return endpoint.respond(id, .{ .status = not_implemented_status, .end = true });
        // Decision 101: the fixed answer may be coded, and an echo goes out as it arrived.
        const echo = answers.echo orelse return endpoint.respond(id, .{ .status = constants.response_status, .fields = &response_fields, .end = request.head, .codable = true });
        if (echo.body_too_long) return endpoint.respond(id, .{ .status = too_large_status, .end = true });
        var digits: [constants.content_length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&digits, "{d}", .{echo.written().len}) catch unreachable;
        const fields = [_]server.Field{
            .{ .name = "content-type", .value = echo_content_type },
            .{ .name = "content-length", .value = length },
        };
        return endpoint.respond(id, .{ .status = constants.response_status, .fields = &fields, .end = request.head });
    }

    fn echo_refused(answers: *const Answers) bool {
        const echo = answers.echo orelse return false;
        return echo.body_too_long;
    }

    /// The content of the response owed: the request's echo in the `--echo` mode, and
    /// `response_body` otherwise.
    fn content(answers: *const Answers) []const u8 {
        const echo = answers.echo orelse return constants.response_body;
        return echo.written();
    }

    /// What a write that failed means for the oldest response: it waits for room or a window,
    /// which the endpoint reports with `writable`, or the request is gone and so is its response.
    fn write_failed(answers: *Answers, failure: server.SendError) bool {
        switch (failure) {
            error.NoSpaceLeft, error.Blocked => return false,
            error.RequestUnknown, error.ConnectionClosed, error.SectionOutOfOrder => {
                answers.finish_oldest();
                return true;
            },
            // The response is the same valid one every time.
            else => unreachable,
        }
    }

    /// Drops the oldest owed response, written or gone, and makes the next one the oldest.
    fn finish_oldest(answers: *Answers) void {
        remove(&answers.owed, &answers.owed_count, 0);
        answers.head_written = false;
        answers.content_sent = 0;
    }
};

fn find(requests: []const Request, number: u64) ?usize {
    for (requests, 0..) |request, index| {
        if (request.number == number) return index;
    }
    return null;
}

fn remove(requests: *[constants.responses_owed_max]Request, count: *u32, index: usize) void {
    assert(index < count.*);
    for (index + 1..count.*) |next| requests[next - 1] = requests[next];
    count.* -= 1;
}
