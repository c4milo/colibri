//! The tests of a router's middleware (decision 127 ruling 5, design §8 step 25.5): the route
//! table's middleware run first, then the route entry's, in table order, and one that answers
//! stops the rest.
const std = @import("std");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const Next = @import("../middleware.zig").Next;
const router = @import("router.zig").router;
const support = @import("router_handle_test_support.zig");
const Recorder = support.Recorder;

const testing = std.testing;

/// The calls a test reads back, in order. Test-only.
const calls_max = 8;

const App = struct {
    calls: [calls_max]u8 = undefined,
    count: usize = 0,
    /// Whether `Guard` answers, and whether it returns an error.
    refuse: bool = false,
    fail: bool = false,

    fn add(app: *App, call: u8) void {
        app.calls[app.count] = call;
        app.count += 1;
    }

    fn order(app: *const App) []const u8 {
        return app.calls[0..app.count];
    }
};

/// The status `Guard` answers with, and the one the error function chooses. Test-only.
const unauthorized = 401;
const unavailable = 503;

/// The route table's middleware: it notes its call.
const Log = struct {
    pub fn on_request(app: *App, _: *const event.Request, _: *ResponseWriter) Next {
        app.add('l');
        return .next;
    }

    pub fn on_finished(app: *App, _: event.RequestId, _: event.Result) void {
        app.add('L');
    }
};

/// A route entry's middleware: it answers 401 when the test says, or fails.
const Guard = struct {
    pub fn on_request(app: *App, _: *const event.Request, response: *ResponseWriter) !Next {
        app.add('g');
        if (app.fail) return error.TestGuardFailed;
        if (!app.refuse) return .next;
        response.status = unauthorized;
        try response.end();
        return .answered;
    }

    pub fn on_finished(app: *App, _: event.RequestId, _: event.Result) void {
        app.add('G');
    }
};

/// A route entry's middleware after `Guard`, with `on_finished` alone: it runs only when the
/// chain reached it.
const Late = struct {
    pub fn on_finished(app: *App, _: event.RequestId, _: event.Result) void {
        app.add('T');
    }
};

fn route(app: *App, _: *const event.Request, _: void, _: void, response: *ResponseWriter) !void {
    app.add('r');
    try response.end();
}

fn on_error(_: *App, _: *const event.Request, _: anyerror, response: *ResponseWriter) void {
    response.status = unavailable;
}

const routes = router(App, .{
    .error_handler = on_error,
    .middleware = .{Log},
    .routes = .{
        .{ .get, "/open", route },
        .{ .get, "/guarded", route, .{ .middleware = .{ Guard, Late } } },
    },
});

const response_bytes = 64;
const Pool = @TypeOf(routes).Of(.{ .requests = 1, .response_bytes = response_bytes });

const Fixture = struct {
    app: App = .{},
    recorder: Recorder = .{},
    pool: Pool = .{},

    fn get(fixture: *Fixture, target: []const u8) void {
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, .{ .request = support.request_of(1, "GET", target, true) });
        std.debug.assert(handled == .taken);
    }

    fn finish(fixture: *Fixture) void {
        const finished: event.Finished = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data, .result = .sent };
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, .{ .finished = finished });
        std.debug.assert(handled == .taken);
    }
};

test "decision 127 ruling 5: the route table's middleware runs first, then the route entry's, then the route" {
    var fixture: Fixture = .{};
    fixture.get("/open");
    try testing.expectEqualStrings("lr", fixture.app.order());
    fixture = .{};
    fixture.get("/guarded");
    try testing.expectEqualStrings("lgr", fixture.app.order());
    try testing.expectEqual(200, fixture.recorder.heads[0].status);
}

test "decision 127 ruling 5: a middleware that answers stops the route" {
    var fixture: Fixture = .{};
    fixture.app.refuse = true;
    fixture.get("/guarded");
    try testing.expectEqualStrings("lg", fixture.app.order());
    try testing.expectEqual(unauthorized, fixture.recorder.heads[0].status);
    try testing.expect(fixture.recorder.ended);
}

test "decision 127 ruling 4: a middleware's error goes to the error function" {
    var fixture: Fixture = .{};
    fixture.app.fail = true;
    fixture.get("/guarded");
    try testing.expectEqualStrings("lg", fixture.app.order());
    try testing.expectEqual(unavailable, fixture.recorder.heads[0].status);
}

test "decision 127 ruling 5: on_finished runs in the reverse order, for each middleware the chain reached" {
    var fixture: Fixture = .{};
    fixture.get("/guarded");
    fixture.finish();
    try testing.expectEqualStrings("lgrTGL", fixture.app.order());
    // Guard answers, so the chain never reached Late, and Late's on_finished does not run.
    fixture = .{};
    fixture.app.refuse = true;
    fixture.get("/guarded");
    fixture.finish();
    try testing.expectEqualStrings("lgGL", fixture.app.order());
}
