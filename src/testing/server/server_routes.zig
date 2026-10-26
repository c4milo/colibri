//! The `--routes github` mode of the test-only server (design §8 step 13f): the GitHub API's 203
//! routes of `bench/router/competitors/github_routes.txt`, which the compiler builds into a route
//! table through `server.router`, and one answer for every route, 200 with `ok\n`. Step 13f's
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

fn answer(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", answer_content_type);
    try response.body().writeAll(answer_body);
    try response.end();
}

/// No route returns an error, so the status this chooses is never sent.
fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = @intFromEnum(http.status.Code.internal_server_error);
}

const Entry = struct { http.method.Standard, []const u8, *const @TypeOf(answer) };

const route_count = count: {
    @setEvalBranchQuota(constants.routes_quota);
    break :count std.mem.count(u8, lines, "\n");
};

const entries: [route_count]Entry = build: {
    @setEvalBranchQuota(constants.routes_quota);
    var held: [route_count]Entry = undefined;
    var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
    var index: usize = 0;
    while (iterator.next()) |line| : (index += 1) {
        const space = std.mem.indexOfScalar(u8, line, ' ').?;
        var method: [space]u8 = undefined;
        _ = std.ascii.lowerString(&method, line[0..space]);
        held[index] = .{ @field(http.method.Standard, &method), line[space + 1 ..], &answer };
    }
    break :build held;
};

pub const routes = server.router(void, .{ .error_handler = on_error, .routes = entries });

/// One worker's pool of request entries.
pub const Pool = @TypeOf(routes).Of(.{
    .requests = constants.routes_requests_max,
    .response_bytes = constants.routes_response_bytes,
});

const testing = std.testing;

test "design §8 step 13f: the GitHub API's routes build, and a GET route matches" {
    try testing.expectEqual(203, route_count);
    var parameters: server.PathParameters = .{};
    const found = routes.match("GET", "/repos/colibri/hummingbird/events", &parameters);
    try testing.expectEqualStrings("GET /repos/:owner/:repo/events", @tagName(found.found));
    try testing.expectEqualStrings("hummingbird", parameters.get("repo").?);
}

/// An endpoint that takes every call and records the status of the head. Test-only.
const Endpoint = struct {
    status: u16 = 0,
    user_data: usize = 0,

    pub fn respond(endpoint: *Endpoint, _: server.RequestId, response: server.Response) server.SendError!void {
        endpoint.status = response.status;
    }

    pub fn write_body(_: *Endpoint, _: server.RequestId, body: server.ResponseBody) server.SendError!usize {
        return body.bytes.len;
    }

    pub fn write_trailers(_: *Endpoint, _: server.RequestId, _: []const server.Header) server.SendError!void {}

    pub fn set_user_data(endpoint: *Endpoint, _: server.RequestId, user_data: usize) error{RequestUnknown}!void {
        endpoint.user_data = user_data;
    }

    pub fn cancel(_: *Endpoint, _: server.RequestId) void {}
};

test "design §8 step 13f: the router's handle compiles over the 203 routes, and answers one" {
    const pool = try testing.allocator.create(Pool);
    defer testing.allocator.destroy(pool);
    pool.* = .{};
    var endpoint: Endpoint = .{};
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
    try testing.expect(pool.handle(&context, &endpoint, .{ .request = head }) == .taken);
    try testing.expectEqual(200, endpoint.status);
    const finished: server.Finished = .{ .id = head.id, .user_data = endpoint.user_data, .result = .sent };
    try testing.expect(pool.handle(&context, &endpoint, .{ .finished = finished }) == .taken);
}
