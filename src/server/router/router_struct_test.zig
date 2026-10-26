//! The tests of `server.router`'s struct routes (decision 127 ruling 2, design §8 step 25.3): a
//! route with a state, which reads the request body through a `std.Io.Reader` and may write its
//! response over many `writable` events.
const std = @import("std");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const router = @import("router.zig").router;
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
    /// Reads that found the body's end.
    ends: usize = 0,
};

/// Echoes each line of the body, one call of `body` at a time.
const Lines = struct {
    pub const State = struct { kept: [kept_len]u8 = undefined, len: usize = 0 };

    pub fn head(app: *App, _: *State, _: *const event.Request, _: void, _: void, _: *ResponseWriter) !void {
        app.heads += 1;
    }

    pub fn body(app: *App, state: *State, reader: *std.Io.Reader, _: *ResponseWriter) !void {
        app.bodies += 1;
        if (app.fail_body) return error.TestRefused;
        // Bounded: each pass takes one line of the bytes that arrived.
        for (0..kept_len) |_| {
            const line = reader.takeDelimiterInclusive('\n') catch |failure| switch (failure) {
                error.EndOfStream => {
                    app.ends += 1;
                    return;
                },
                else => |other| return other,
            };
            @memcpy(state.kept[state.len..][0..line.len], line);
            state.len += line.len;
        }
    }

    pub fn finished(app: *App, state: *State, result: event.Result) void {
        _ = state;
        app.finished += 1;
        app.result = result;
    }
};

/// Answers with the whole body after its last byte.
const Whole = struct {
    pub fn head(_: *App, _: *void, _: *const event.Request, _: void, _: void, _: *ResponseWriter) !void {}

    pub fn body(app: *App, _: *void, reader: *std.Io.Reader, response: *ResponseWriter) !void {
        app.bodies += 1;
        try response.body().writeAll(reader.buffered());
        try response.end();
    }
};

/// Writes one byte of `digits` for each call of `writable`: more calls than the runs a writer
/// holds, so a call while the endpoint is full would overflow it.
const Counter = struct {
    pub const State = struct { next: u8 = 0 };
    const digits = "0123456789abcdefghij";

    pub fn head(_: *App, _: *State, _: *const event.Request, _: void, _: void, _: *ResponseWriter) !void {}

    pub fn writable(_: *App, state: *State, response: *ResponseWriter) !void {
        if (state.next == digits.len) return response.end();
        try response.write_kept(digits[state.next..][0..1]);
        state.next += 1;
    }
};

fn on_error(_: *App, _: *const event.Request, _: anyerror, response: *ResponseWriter) void {
    response.status = unprocessable;
}

const routes = router(App, .{
    .error_handler = on_error,
    .routes = .{
        .{ .post, "/lines", Lines },
        .{ .post, "/whole", Whole, .{ .whole_body = true } },
        .{ .get, "/count", Counter },
    },
});

const Pool = @TypeOf(routes).Of(.{ .requests = 1, .response_bytes = response_bytes, .body_bytes = body_bytes });

/// Octets of each entry's response and body memory, and the status the error function chooses.
/// Test-only.
const response_bytes = 128;
const body_bytes = 16;
const unprocessable = 422;

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

test "decision 127: body reads what arrived, and the bytes it leaves unread come first next time" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/lines", false);
    fixture.body("ab\ncd", false);
    try testing.expectEqualStrings("ab\n", fixture.state().kept[0..fixture.state().len]);
    // The bytes that arrived ran out, and the body has not ended.
    try testing.expectEqual(0, fixture.app.ends);
    fixture.body("e\nf", true);
    try testing.expectEqual(1, fixture.app.ends);
    try testing.expectEqualStrings("ab\ncde\n", fixture.state().kept[0..fixture.state().len]);
    try testing.expectEqual(2, fixture.app.bodies);
    // The router ends a response the route left open once the body ended.
    try testing.expectEqual(200, fixture.recorder.heads[0].status);
    try testing.expect(fixture.recorder.ended);
    fixture.handle(.{ .finished = .{ .id = @bitCast(@as(u128, 1)), .user_data = 1, .result = .sent } });
    try testing.expectEqual(1, fixture.app.finished);
    try testing.expectEqual(event.Result.sent, fixture.app.result.?);
}

test "decision 127: a head that ends the request still runs body once, with an empty reader" {
    var fixture: Fixture = .{};
    fixture.head("POST", "/lines", true);
    try testing.expectEqual(1, fixture.app.heads);
    try testing.expectEqual(1, fixture.app.bodies);
    try testing.expect(fixture.recorder.ended);
}

test "decision 127: whole_body runs body once, after the last byte" {
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
    try testing.expectEqual(413, fixture.recorder.heads[0].status);
    try testing.expectEqual(0, fixture.app.bodies);
}

test "decision 127 ruling 4: an error of body before the head goes to the error function" {
    var fixture: Fixture = .{};
    fixture.app.fail_body = true;
    fixture.head("POST", "/lines", false);
    fixture.body("a\n", false);
    try testing.expectEqual(422, fixture.recorder.heads[0].status);
    // A later body event of the request calls nothing more.
    fixture.body("b\n", true);
    try testing.expectEqual(1, fixture.app.bodies);
}

test "decision 127: writable writes a response over many events, and ends it itself" {
    var fixture: Fixture = .{};
    fixture.recorder.room = 1;
    fixture.head("GET", "/count", true);
    try testing.expectEqualStrings("0", fixture.recorder.body_bytes());
    // Bounded: each writable event lets the endpoint take one byte more.
    for (0..Counter.digits.len + 1) |_| {
        if (fixture.recorder.ended) break;
        fixture.recorder.room = 1;
        fixture.handle(.{ .writable = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data } });
    }
    try testing.expectEqualStrings(Counter.digits, fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
    try testing.expectEqual(0, fixture.recorder.cancelled);
}
