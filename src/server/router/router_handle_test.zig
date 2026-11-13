//! The tests of `server.Router`'s `handle` (decision 127, design §8 step 25.3), against an
//! engine that records each call.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const RequestContext = @import("../request_context.zig").RequestContext;
const Router = @import("router.zig").Router;

const testing = std.testing;

const support = @import("router_handle_test_support.zig");
const Recorder = support.Recorder;

const App = struct {
    calls: usize = 0,
    fail_after_head: bool = false,
};

/// The path and the query of each route, which its entry names as `.path` and `.query` (decision
/// 163 ruling 3). Test-only.
const Name = struct { name: []const u8 };
const Mark = struct { mark: ?[]const u8 = null, times: []const u8 = "1" };
const Id = struct { id: []const u8 };
const Rest = struct { rest: []const u8 };

fn greet(app: *App, ctx: *RequestContext, _: *const event.Request, response: *ResponseWriter) !void {
    const path = ctx.path(Name);
    const query = ctx.query(Mark);
    app.calls += 1;
    try response.header("content-type", "text/plain");
    try response.body().print("hello, {s}{s} x{s}", .{ path.name, query.mark orelse "", query.times });
    try response.end();
}

fn need(_: *App, ctx: *RequestContext, _: *const event.Request, response: *ResponseWriter) !void {
    try response.body().writeAll(ctx.query(Id).id);
}

fn files(_: *App, ctx: *RequestContext, _: *const event.Request, response: *ResponseWriter) !void {
    const query = ctx.query(http.QueryParameters);
    try response.body().print("{s}?{s}", .{ ctx.path(Rest).rest, query.get("v") orelse "" });
    try response.end();
}

fn broken(app: *App, _: *RequestContext, _: *const event.Request, response: *ResponseWriter) !void {
    if (app.fail_after_head) {
        try response.write_kept("partial");
    }
    return error.TestUserUnknown;
}

fn on_error(_: *App, _: *RequestContext, _: *const event.Request, failure: anyerror, response: *ResponseWriter) void {
    response.status = if (failure == error.TestUserUnknown) not_found else server_error;
}

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greetings/:name", greet, .{ .path = Name, .query = Mark } },
        .{ .post, "/greetings/:name", greet, .{ .path = Name, .query = Mark } },
        .{ .get, "/need", need, .{ .query = Id } },
        .{ .get, "/files/*", files, .{ .path = Rest, .query = http.QueryParameters } },
        .{ .get, "/broken", broken },
    },
};

/// A pool of two entries, so a third request at once finds none.
const Pool = Router(App, routes, .{ .requests = requests, .response_bytes = response_bytes });

/// The entries of the pool, octets of each entry's response memory, and the statuses the error
/// function chooses. Test-only.
const requests = 2;
const response_bytes = 128;
const not_found: http.Status = .not_found;
const server_error: http.Status = .internal_server_error;

const Fixture = struct {
    app: App = .{},
    recorder: Recorder = .{},
    pool: Pool = .{},
    number: u64 = 0,

    fn request(fixture: *Fixture, method: []const u8, target: []const u8) event.RequestId {
        fixture.number += 1;
        const head = support.request_of(fixture.number, method, target, true);
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, .{ .request = head });
        std.debug.assert(handled == .taken);
        return head.id;
    }

    fn finished(fixture: *Fixture, id: event.RequestId) void {
        const done: event.Finished = .{ .id = id, .user_data = fixture.recorder.user_data, .result = .sent };
        _ = fixture.pool.handle(&fixture.app, &fixture.recorder, .{ .finished = done });
    }
};

test "decision 158: a router exports its calls, and match names each route by its tag" {
    try @import("core").public_names.expect(Pool, &.{ "Route", "Match", "match", "memory_bytes", "handle" });
    try testing.expectEqual(@sizeOf(Pool), Pool.memory_bytes);
    var parameters: @import("../path_parameters.zig").PathParameters = .{};
    const found = Pool.match("POST", "/greetings/x", &parameters).found;
    try testing.expectEqualStrings("POST /greetings/:name", @tagName(found));
}

test "decision 127: a route's function gets its path and query as structs, and answers" {
    var fixture: Fixture = .{};
    _ = fixture.request("GET", "/greetings/col%69bri?mark=%21");
    try testing.expectEqual(1, fixture.app.calls);
    try testing.expectEqual(200, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqualStrings("hello, colibri! x1", fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
}

test "decision 127: the wildcard is rest, and http.QueryParameters reads the pairs by name" {
    var fixture: Fixture = .{};
    _ = fixture.request("GET", "/files/a/b%20c?v=2");
    try testing.expectEqualStrings("a/b c?2", fixture.recorder.body_bytes());
}

test "RFC 9110 §15.5.1: a query that lacks a required pair gets 400, with no call" {
    var fixture: Fixture = .{};
    _ = fixture.request("GET", "/need?other=1");
    try testing.expectEqual(400, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(0, fixture.recorder.body_len);
    // A function that leaves its response open has it ended by the router.
    fixture = .{};
    _ = fixture.request("GET", "/need?id=7");
    try testing.expectEqualStrings("7", fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
}

test "RFC 9110 §15.5.15: a query of more pairs than the router reads gets 414, with no call" {
    var fixture: Fixture = .{};
    const pairs = "a&" ** (http.constants.limits.query_parameters_max + 1);
    _ = fixture.request("GET", "/greetings/x?" ++ pairs);
    try testing.expectEqual(414, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(0, fixture.app.calls);
}

test "RFC 9110 §15.5.5, §15.5.6, §15.6.2: the router answers 404, 405 with Allow, and 501" {
    var fixture: Fixture = .{};
    _ = fixture.request("GET", "/nothing");
    _ = fixture.request("POST", "/need");
    // RFC 9110 §9.1: a method no route of the table names gets 501 on every path.
    _ = fixture.request("DELETE", "/greetings/x");
    try testing.expectEqual(404, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(405, @intFromEnum(fixture.recorder.heads[1].status));
    try testing.expectEqualStrings("GET, HEAD", fixture.recorder.allow[1]);
    try testing.expectEqual(501, @intFromEnum(fixture.recorder.heads[2].status));
    try testing.expectEqual(0, fixture.app.calls);
}

test "RFC 9110 §15.6.4: a request that finds no free entry gets 503, until a finished frees one" {
    var fixture: Fixture = .{};
    fixture.recorder.room = 0;
    const first = fixture.request("GET", "/greetings/a");
    _ = fixture.request("GET", "/greetings/b");
    _ = fixture.request("GET", "/greetings/c");
    try testing.expectEqual(503, @intFromEnum(fixture.recorder.heads[2].status));
    try testing.expectEqual(2, fixture.app.calls);
    fixture.recorder.user_data = 1;
    fixture.finished(first);
    _ = fixture.request("GET", "/greetings/d");
    try testing.expectEqual(3, fixture.app.calls);
}

test "decision 127: a writable sends what the engine did not take" {
    var fixture: Fixture = .{};
    fixture.recorder.room = 4;
    const id = fixture.request("GET", "/greetings/x");
    try testing.expectEqualStrings("hell", fixture.recorder.body_bytes());
    fixture.recorder.room = std.math.maxInt(usize);
    const writable: event.Writable = .{ .id = id, .user_data = fixture.recorder.user_data };
    try testing.expect(fixture.pool.handle(&fixture.app, &fixture.recorder, .{ .writable = writable }) == .taken);
    try testing.expectEqualStrings("hello, x x1", fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
}

test "decision 127 ruling 4: the error function chooses the status, and an error after the head cancels" {
    var fixture: Fixture = .{};
    _ = fixture.request("GET", "/broken");
    try testing.expectEqual(404, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(0, fixture.recorder.cancelled);
    fixture = .{};
    fixture.app.fail_after_head = true;
    _ = fixture.request("GET", "/broken");
    try testing.expectEqual(200, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(1, fixture.recorder.cancelled);
}

test "decision 127: handle hands back the events of connections" {
    var fixture: Fixture = .{};
    const handle: event.ConnectionHandle = @bitCast(@as(u64, 3));
    try testing.expect(fixture.pool.handle(&fixture.app, &fixture.recorder, .{ .send = handle }) == .event);
    try testing.expect(fixture.pool.handle(&fixture.app, &fixture.recorder, .{ .close = handle }) == .event);
    try testing.expect(fixture.pool.handle(&fixture.app, &fixture.recorder, .closed) == .event);
}
