//! The tests of `server.Router`'s stream routes (decision 127 ruling 2, decision 163 ruling 6,
//! design §8 step 25.3). Such a route has a state, reads the request body through a
//! `server.RequestBodyStream`, and may write its `server.Response` over many `writable` events. A
//! function route beside them reads the whole body in one call (decision 163 ruling 4).
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const Response = @import("../response/response.zig").Response;
const RequestBodyStream = @import("../request_body_stream.zig").RequestBodyStream;
const RequestContext = @import("../request_context.zig").RequestContext;
const Router = @import("router.zig").Router;
const support = @import("router_handle_test_support.zig");
const Recorder = support.Recorder;

const testing = std.testing;

/// Octets of the lines and the body a test's state keeps. Test-only.
const kept_len = 64;

const App = struct {
    heads: usize = 0,
    bodies: usize = 0,
    finished: usize = 0,
    result: ?event.Result = null,
    fail_body: bool = false,
    /// Calls of `on_data` that found the body's end.
    ends: usize = 0,
    /// Calls of `next`, and whether each writes one byte.
    nexts: usize = 0,
    write_on_next: bool = false,
    /// The lines the error function counted in its request's headers, and what a read of its
    /// request's body gave.
    error_lines: ?u32 = null,
    error_read: ?anyerror = null,
};

/// Keeps each whole line of the body, one call of `on_data` at a time. The octets after a piece's
/// last line stay unread, and start the next piece.
const Lines = struct {
    pub const State = struct { kept: [kept_len]u8 = undefined, len: usize = 0 };

    pub fn on_request(app: *App, _: *RequestContext, _: *State, _: *const event.Request, _: *Response) !void {
        app.heads += 1;
    }

    pub fn on_data(app: *App, _: *RequestContext, state: *State, body: *RequestBodyStream, _: *Response) !void {
        app.bodies += 1;
        if (app.fail_body) return error.TestRefused;
        // Bounded: each pass takes one piece of the bytes that arrived.
        for (0..kept_len) |_| {
            const piece = body.next() orelse break;
            const lines_len = if (std.mem.lastIndexOfScalar(u8, piece, '\n')) |last| last + 1 else 0;
            @memcpy(state.kept[state.len..][0..lines_len], piece[0..lines_len]);
            state.len += lines_len;
            body.keep(piece.len - lines_len);
        }
        if (body.ended()) app.ends += 1;
    }

    pub fn on_finished(app: *App, _: *RequestContext, state: *State, result: event.Result) void {
        _ = state;
        app.finished += 1;
        app.result = result;
    }
};

/// A function route that answers with the whole body, which it reads in its one call after the
/// body's last byte.
fn whole(app: *App, _: *RequestContext, request: *const event.Request, response: *Response) !void {
    app.bodies += 1;
    var bytes: [body_bytes]u8 = undefined;
    const len = try request.body.readSliceShort(&bytes);
    try response.body().writeAll(bytes[0..len]);
    try response.end();
}

/// Writes one byte of `digits` for each call of `next`: more calls than the runs a response
/// holds, so a call while the engine is full would overflow it.
const Counter = struct {
    pub const State = struct { written: u8 = 0 };
    const digits = "0123456789abcdefghij";

    pub fn on_request(_: *App, _: *RequestContext, _: *State, _: *const event.Request, _: *Response) !void {}

    pub fn next(_: *App, _: *RequestContext, state: *State, response: *Response) !void {
        if (state.written == digits.len) return response.end();
        try response.write_kept(digits[state.written..][0..1]);
        state.written += 1;
    }
};

/// Echoes each piece of the body from `on_data`, and counts its calls of `next`, which write one
/// byte when the test asks and nothing otherwise: a route that answers while the client still
/// sends.
const Duplex = struct {
    pub fn on_request(_: *App, _: *RequestContext, _: *void, _: *const event.Request, _: *Response) !void {}

    pub fn on_data(app: *App, _: *RequestContext, _: *void, body: *RequestBodyStream, response: *Response) !void {
        app.bodies += 1;
        // Bounded: each pass writes one piece.
        for (0..kept_len) |_| {
            const piece = body.next() orelse break;
            try response.body().writeAll(piece);
        }
        try response.body().flush();
    }

    pub fn next(app: *App, _: *RequestContext, _: *void, response: *Response) !void {
        app.nexts += 1;
        if (app.write_on_next) try response.write_kept("w");
    }
};

/// The query of `Needs`, which its entry names as `.query` (decision 163 ruling 3). Test-only.
const Id = struct { id: []const u8 };

/// Requires the query pair `id`, and counts its calls of `on_data`.
const Needs = struct {
    pub fn on_request(_: *App, _: *RequestContext, _: *void, _: *const event.Request, _: *Response) !void {}

    pub fn on_data(app: *App, _: *RequestContext, _: *void, _: *RequestBodyStream, _: *Response) !void {
        app.bodies += 1;
    }
};

fn on_error(app: *App, _: *RequestContext, request: *const event.Request, _: anyerror, response: *Response) void {
    response.status = unprocessable;
    app.error_lines = request.headers.len();
    if (request.body.takeByte()) |_| {
        app.error_read = null;
    } else |failure| app.error_read = failure;
}

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .post, "/lines", Lines },
        .{ .post, "/whole", whole },
        .{ .get, "/count", Counter },
        .{ .post, "/needs", Needs, .{ .query = Id } },
        .{ .post, "/duplex", Duplex },
    },
};

const Pool = Router(App, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = body_bytes, .header_bytes = header_bytes });

/// Octets of each entry's response, body and header memory, and the status the error function
/// chooses. Test-only.
const response_bytes = 128;
const body_bytes = 16;
const header_bytes = 64;
const unprocessable: http.Status = .unprocessable_content;

const Fixture = struct {
    app: App = .{},
    recorder: Recorder = .{},
    pool: Pool = .{},

    fn head(fixture: *Fixture, method: []const u8, target: []const u8, end: bool) void {
        fixture.handle(.{ .request = support.request_of(1, method, target, end) });
    }

    fn body(fixture: *Fixture, bytes: []const u8, end: bool) void {
        fixture.handle(.{ .body = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data, .bytes = bytes, .end = end } });
    }

    fn handle(fixture: *Fixture, received: event.Event) void {
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, received);
        std.debug.assert(handled == .taken);
    }

    fn state(fixture: *Fixture) *Lines.State {
        return @ptrCast(&fixture.pool.entries[0].state);
    }
};

test "decision 163 ruling 6: on_data reads what arrived, and the octets it keeps come first next time" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/lines", false);
    fixture.body("ab\ncd", false);
    try testing.expectEqualStrings("ab\n", fixture.state().kept[0..fixture.state().len]);
    // The octets that arrived ran out, and the body has not ended.
    try testing.expectEqual(0, fixture.app.ends);
    fixture.body("e\nf", true);
    try testing.expectEqual(1, fixture.app.ends);
    try testing.expectEqualStrings("ab\ncde\n", fixture.state().kept[0..fixture.state().len]);
    try testing.expectEqual(2, fixture.app.bodies);
    // The router ends a response the route left open once the body ended.
    try testing.expectEqual(200, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expect(fixture.recorder.ended);
    fixture.handle(.{ .finished = .{ .id = @bitCast(@as(u128, 1)), .user_data = 1, .result = .sent } });
    try testing.expectEqual(1, fixture.app.finished);
    try testing.expectEqual(event.Result.sent, fixture.app.result.?);
}

test "a route's State starts from its defaults at each request on the entry" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/lines", false);
    fixture.body("ab\n", true);
    try testing.expectEqual(3, fixture.state().len);
    fixture.handle(.{ .finished = .{ .id = @bitCast(@as(u128, 1)), .user_data = 1, .result = .sent } });
    fixture.recorder = .{};
    fixture.head("POST", "/lines", false);
    try testing.expectEqual(0, fixture.state().len);
}

test "decision 163 ruling 6: a head that ends the request still runs on_data once, at the body's end" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/lines", true);
    try testing.expectEqual(1, fixture.app.heads);
    try testing.expectEqual(1, fixture.app.bodies);
    try testing.expectEqual(1, fixture.app.ends);
    try testing.expect(fixture.recorder.ended);
}

test "decision 163 ruling 4: a function route gets one call, after the body's last byte" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/whole", false);
    fixture.body("abc", false);
    fixture.body("def", false);
    try testing.expectEqual(0, fixture.app.bodies);
    fixture.body("g", true);
    try testing.expectEqual(1, fixture.app.bodies);
    try testing.expectEqualStrings("abcdefg", fixture.recorder.body_bytes());
}

test "RFC 9110 §15.5.14: a body larger than body_bytes gets 413" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/whole", false);
    fixture.body("0123456789abcdef!", false);
    try testing.expectEqual(413, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(0, fixture.app.bodies);
}

test "decision 127 ruling 4: an error of on_data before the head goes to the error function" {
    var fixture: Fixture = .{};
    fixture.app.fail_body = true;
    fixture.head("POST", "/lines", false);
    fixture.body("a\n", false);
    try testing.expectEqual(422, @intFromEnum(fixture.recorder.heads[0].status));
    // Decision 163: the request the error function gets after the head holds no line, and its
    // body has no byte to read.
    try testing.expectEqual(0, fixture.app.error_lines.?);
    try testing.expectEqual(error.ReadFailed, fixture.app.error_read.?);
    // A later body event of the request calls nothing more.
    fixture.body("b\n", true);
    try testing.expectEqual(1, fixture.app.bodies);
}

test "decision 163 ruling 6: next writes a response over many events, and ends it itself" {
    var fixture: Fixture = .{};
    fixture.recorder.room = 1;
    fixture.head("GET", "/count", true);
    try testing.expectEqualStrings("0", fixture.recorder.body_bytes());
    // Bounded: each writable event lets the engine take one byte more.
    for (0..Counter.digits.len + 1) |_| {
        if (fixture.recorder.ended) break;
        fixture.recorder.room = 1;
        fixture.handle(.{ .writable = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data } });
    }
    try testing.expectEqualStrings(Counter.digits, fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
    try testing.expectEqual(0, fixture.recorder.cancelled);
}

test "RFC 9110 §15.5.1: a stream route whose query lacks a required pair gets 400, and no on_data" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/needs", true);
    try testing.expectEqual(400, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(0, fixture.app.bodies);
}

/// Reports the `writable` the recorder owes once it takes every byte again.
fn writable_after_room(fixture: *Fixture) void {
    fixture.recorder.room = std.math.maxInt(usize);
    fixture.handle(.{ .writable = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data } });
}

test "decision 127 as amended: next runs while the request body is open" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/duplex", false);
    // The engine takes two of the four bytes, and the rest waits for `writable`.
    fixture.recorder.room = 2;
    fixture.body("abcd", false);
    try testing.expectEqual(0, fixture.app.nexts);
    writable_after_room(&fixture);
    try testing.expectEqualStrings("abcd", fixture.recorder.body_bytes());
    // The call wrote nothing while the body is open: no second call, and no cancel.
    try testing.expectEqual(1, fixture.app.nexts);
    try testing.expectEqual(0, fixture.recorder.cancelled);
    // Once the body ended, a route that neither ends its response nor fills the engine holds
    // the request, and the router cancels it.
    fixture.body("", true);
    try testing.expectEqual(1, fixture.recorder.cancelled);
}

test "decision 127 as amended: calls that write while the body is open do not cancel" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/duplex", false);
    fixture.recorder.room = 2;
    fixture.body("abcd", false);
    fixture.app.write_on_next = true;
    writable_after_room(&fixture);
    // Each call wrote a byte that the engine took, so the router calls the route as often as one
    // event allows, and waits for the next event with the body open.
    try testing.expect(fixture.app.nexts > 1);
    try testing.expectEqual(0, fixture.recorder.cancelled);
}

test "decision 163 ruling 4: a writable event before the body's end calls no function route" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/whole", false);
    fixture.body("ab", false);
    writable_after_room(&fixture);
    try testing.expectEqual(0, fixture.app.bodies);
    try testing.expectEqual(0, fixture.recorder.head_count);
    fixture.body("c", true);
    try testing.expectEqual(1, fixture.app.bodies);
    try testing.expectEqualStrings("abc", fixture.recorder.body_bytes());
}
