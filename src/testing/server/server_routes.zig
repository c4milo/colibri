//! The `--routes github` mode of the test-only server (design §8 step 13f): the GitHub API's 203
//! routes of `bench/router/competitors/github_routes.txt`, which the compiler builds into a route
//! table through `server.Router`, and one answer for every route, 200 with `ok\n`. Step 13f's
//! competitors serve the same routes with the same answer. Split off `server_session.zig`.
const std = @import("std");
const server = @import("server");
const http = @import("h2").http;
const constants = @import("../constants.zig");

/// The routes, one "METHOD /path" on each line, which the build hands this module.
const lines = @embedFile("github_routes");

/// The answer of every route, and its media type (RFC 9110 §8.3).
pub const answer_body = "ok\n";
const answer_content_type = "text/plain; charset=utf-8";

fn answer(_: *void, _: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    try response.header("content-type", answer_content_type);
    try response.body().writeAll(answer_body);
    try response.end();
}

/// The route of each POST line: it reads the request's whole body, then answers as `answer` does.
/// So the judge counts what a request with a body costs through the router (design §8 step 50b).
const Body = struct {
    pub fn on_request(_: *void, _: *server.RequestContext, _: *void, _: *const server.Request, _: *server.Response) !void {}

    pub fn on_body(_: *void, _: *server.RequestContext, _: *void, content: *std.Io.Reader, response: *server.Response) !void {
        // With `whole_body`, the reader holds every octet of the body.
        content.toss(content.buffered().len);
        try response.header("content-type", answer_content_type);
        try response.body().writeAll(answer_body);
        try response.end();
    }
};

/// No route returns an error, so the status this chooses is never sent.
fn on_error(_: *void, _: *server.RequestContext, _: *const server.Request, _: anyerror, response: *server.Response) void {
    response.status = .internal_server_error;
}

/// A route that answers at the header, and a POST route, which reads its whole body first.
const Entry = struct { http.method.Standard, []const u8, *const @TypeOf(answer) };
const BodyEntry = struct { http.method.Standard, []const u8, type, struct { whole_body: bool } };

const route_count = count: {
    @setEvalBranchQuota(constants.routes_quota);
    break :count std.mem.count(u8, lines, "\n");
};

/// The method of a line, "METHOD /path".
fn method_of(comptime line: []const u8) http.method.Standard {
    const space = std.mem.indexOfScalar(u8, line, ' ').?;
    var method: [space]u8 = undefined;
    _ = std.ascii.lowerString(&method, line[0..space]);
    return @field(http.method.Standard, &method);
}

/// The type of each line's entry, in the lines' order.
const entry_types: [route_count]type = build: {
    @setEvalBranchQuota(constants.routes_quota);
    var held: [route_count]type = undefined;
    var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
    var index: usize = 0;
    while (iterator.next()) |line| : (index += 1) {
        held[index] = if (method_of(line) == .post) BodyEntry else Entry;
    }
    break :build held;
};

const entries: std.meta.Tuple(&entry_types) = build: {
    @setEvalBranchQuota(constants.routes_quota);
    var held: std.meta.Tuple(&entry_types) = undefined;
    var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
    var index: usize = 0;
    while (iterator.next()) |line| : (index += 1) {
        const path = line[std.mem.indexOfScalar(u8, line, ' ').? + 1 ..];
        held[index] = if (method_of(line) == .post)
            BodyEntry{ .post, path, Body, .{ .whole_body = true } }
        else
            Entry{ method_of(line), path, &answer };
    }
    break :build held;
};

pub const routes = .{ .error_handler = on_error, .routes = entries };

/// One worker's pool of request entries.
pub const Pool = server.Router(void, routes, .{
    .requests = constants.routes_requests_max,
    .response_bytes = constants.routes_response_bytes,
    .body_bytes = constants.routes_body_bytes,
});

const testing = std.testing;

test "design §8 step 13f: the GitHub API's routes build, and a GET route matches" {
    try testing.expectEqual(203, route_count);
    var parameters: server.PathParameters = .{};
    const found = Pool.match("GET", "/repos/colibri/hummingbird/events", &parameters);
    try testing.expectEqualStrings("GET /repos/:owner/:repo/events", @tagName(found.found));
    try testing.expectEqualStrings("hummingbird", parameters.get("repo").?);
}

/// An engine that takes every call and records the status of the head. Test-only.
const Engine = struct {
    status: u16 = 0,
    user_data: usize = 0,

    pub fn respond(engine: *Engine, _: server.RequestId, response: server.ResponseHeader) server.SendError!void {
        engine.status = @intFromEnum(response.status);
    }

    pub fn write_body(_: *Engine, _: server.RequestId, body: server.ResponseBody) server.SendError!usize {
        return body.bytes.len;
    }

    pub fn write_trailers(_: *Engine, _: server.RequestId, _: []const server.Header) server.SendError!void {}

    pub fn set_user_data(engine: *Engine, _: server.RequestId, user_data: usize) error{RequestUnknown}!void {
        engine.user_data = user_data;
    }

    pub fn cancel(_: *Engine, _: server.RequestId) void {}
};

test "design §8 step 13f: the router's handle compiles over the 203 routes, and answers one" {
    const pool = try testing.allocator.create(Pool);
    defer testing.allocator.destroy(pool);
    pool.* = .{};
    var engine: Engine = .{};
    var context: void = {};
    const path = "/repos/colibri/hummingbird/events";
    const head: server.Request = .{
        .id = @bitCast(@as(u128, 1)),
        .method = "GET",
        .version = .{ .major = 1, .minor = 1 },
        .target = path,
        .scheme = "http",
        .authority = "example.com",
        .path = path,
        .query = null,
        .headers = undefined,
        .end = true,
    };
    try testing.expect(pool.handle(&context, &engine, .{ .request = head }) == .taken);
    try testing.expectEqual(200, engine.status);
    const finished: server.Finished = .{ .id = head.id, .user_data = engine.user_data, .result = .sent };
    try testing.expect(pool.handle(&context, &engine, .{ .finished = finished }) == .taken);
}

test "design §8 step 50b: a POST route answers once its whole body arrived" {
    const pool = try testing.allocator.create(Pool);
    defer testing.allocator.destroy(pool);
    pool.* = .{};
    var engine: Engine = .{};
    var context: void = {};
    const path = "/user/repos";
    const head: server.Request = .{
        .id = @bitCast(@as(u128, 2)),
        .method = "POST",
        .version = .{ .major = 2, .minor = 0 },
        .target = path,
        .scheme = "http",
        .authority = "example.com",
        .path = path,
        .query = null,
        .headers = undefined,
        .end = false,
    };
    try testing.expect(pool.handle(&context, &engine, .{ .request = head }) == .taken);
    // The route reads its body whole, so neither the header nor the first piece gets an answer.
    try testing.expectEqual(0, engine.status);
    const piece = [_]u8{'x'} ** (constants.routes_body_bytes / 2);
    const first: server.RequestBody = .{ .id = head.id, .user_data = engine.user_data, .bytes = &piece, .end = false };
    try testing.expect(pool.handle(&context, &engine, .{ .body = first }) == .taken);
    try testing.expectEqual(0, engine.status);
    const last: server.RequestBody = .{ .id = head.id, .user_data = engine.user_data, .bytes = &piece, .end = true };
    try testing.expect(pool.handle(&context, &engine, .{ .body = last }) == .taken);
    try testing.expectEqual(200, engine.status);
}
