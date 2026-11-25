//! The `--routes` mode of the test-only server: a route table of `bench/router/competitors/`,
//! which the compiler builds through `server.Router`, and one answer for every route, 200 with
//! `ok\n`. `github` holds the GitHub API's 203 routes (design §8 step 13f), whose answer step 13f's
//! competitors give too. `kubernetes` holds 463 of the Kubernetes API's 1,172 routes, every method
//! of 235 of its 587 paths, whose segments are longer (design §8 step 13l). Split off
//! `server_session.zig`.
const std = @import("std");
const server = @import("server");
const http = @import("h2").http;
const constants = @import("../constants.zig");

/// The GitHub API's routes, one "METHOD /path" on each line, which the build hands this module.
pub const github = Table(@embedFile("github_routes"));
/// A sample of the Kubernetes API's routes, in the same form
/// (`bench/router/competitors/kubernetes_sample_routes.LICENSE` names how it was taken).
pub const kubernetes = Table(@embedFile("kubernetes_sample_routes"));

/// The answer of every route, and its media type (RFC 9110 §8.3).
pub const answer_body = "ok\n";
const answer_content_type = "text/plain; charset=utf-8";

fn answer(_: *void, _: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    try response.header("content-type", answer_content_type);
    try response.body().writeAll(answer_body);
    try response.end();
}

/// The function of each POST line: it reads the request's whole body, then answers as `answer`
/// does. So the judge counts what a request with a body costs through the router (design §8 step
/// 50b). The router calls it once the body ended, and `request.body` reads each octet of the body
/// (decision 163 ruling 4).
fn read_and_answer(_: *void, _: *server.RequestContext, request: *const server.Request, response: *server.Response) !void {
    // The reader holds every octet of the body, as the struct route that this replaced read them.
    request.body.toss(request.body.buffered().len);
    try response.header("content-type", answer_content_type);
    try response.body().writeAll(answer_body);
    try response.end();
}

/// No route returns an error, so the status this chooses is never sent.
fn on_error(_: *void, _: *server.RequestContext, _: *const server.Request, _: anyerror, response: *server.Response) void {
    response.status = .internal_server_error;
}

/// The token of the one method whose routes read their whole body first.
const post_token = "POST";

/// The method of a line, "METHOD /path", as its token.
fn token_of(comptime line: []const u8) []const u8 {
    return line[0..std.mem.indexOfScalar(u8, line, ' ').?];
}

/// The type a route table takes a method as: one of RFC 9110's eight as `http.method.Standard`, and
/// any other, such as PATCH, as its token (decision 122 ruling 4).
fn MethodOf(comptime token: []const u8) type {
    var lower: [token.len]u8 = undefined;
    _ = std.ascii.lowerString(&lower, token);
    return if (@hasField(http.method.Standard, &lower)) http.method.Standard else []const u8;
}

fn method_of(comptime token: []const u8) MethodOf(token) {
    var lower: [token.len]u8 = undefined;
    _ = std.ascii.lowerString(&lower, token);
    if (comptime MethodOf(token) == http.method.Standard) return @field(http.method.Standard, &lower);
    return token;
}

/// The entry of a line: its method, its path, and the function that answers it.
fn EntryOf(comptime token: []const u8) type {
    const Function = if (std.mem.eql(u8, token, post_token)) @TypeOf(read_and_answer) else @TypeOf(answer);
    return struct { MethodOf(token), []const u8, *const Function };
}

/// The router of the routes of `lines`, one "METHOD /path" on each line, and its pool of request
/// entries for one worker.
fn Table(comptime lines: []const u8) type {
    return struct {
        pub const route_count = count: {
            @setEvalBranchQuota(constants.routes_quota);
            break :count std.mem.count(u8, lines, "\n");
        };

        /// The type of each line's entry, in the lines' order.
        const entry_types: [route_count]type = build: {
            @setEvalBranchQuota(constants.routes_quota);
            var held: [route_count]type = undefined;
            var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
            var index: usize = 0;
            while (iterator.next()) |line| : (index += 1) held[index] = EntryOf(token_of(line));
            break :build held;
        };

        const entries: std.meta.Tuple(&entry_types) = build: {
            @setEvalBranchQuota(constants.routes_quota);
            var held: std.meta.Tuple(&entry_types) = undefined;
            var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
            var index: usize = 0;
            while (iterator.next()) |line| : (index += 1) {
                const token = token_of(line);
                const path = line[token.len + 1 ..];
                const function = if (std.mem.eql(u8, token, post_token)) &read_and_answer else &answer;
                held[index] = .{ method_of(token), path, function };
            }
            break :build held;
        };

        pub const routes = .{ .error_handler = on_error, .routes = entries };

        /// One worker's pool of request entries.
        pub const Pool = server.Router(void, routes, .{
            .requests = constants.routes_requests_max,
            .response_bytes = constants.routes_response_bytes,
            .body_bytes = constants.routes_body_bytes,
            .header_bytes = constants.routes_header_bytes,
        });
    };
}

const testing = std.testing;

/// The field section of each request of these tests, which holds no line. Test-only.
const no_lines: http.FieldSection.Slice = .{ .octets = &.{}, .lines = &.{} };

test "design §8 step 13f: the GitHub API's routes build, and a GET route matches" {
    try testing.expectEqual(203, github.route_count);
    var parameters: server.PathParameters = .{};
    const found = github.Pool.match("GET", "/repos/colibri/hummingbird/events", &parameters);
    try testing.expectEqualStrings("GET /repos/:owner/:repo/events", @tagName(found.found));
    try testing.expectEqualStrings("hummingbird", parameters.get("repo").?);
}

test "design §8 step 13l: the Kubernetes API's sampled routes build, and a GET and a PATCH route match" {
    try testing.expectEqual(463, kubernetes.route_count);
    var parameters: server.PathParameters = .{};
    const path = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/colibri";
    const found = kubernetes.Pool.match("GET", path, &parameters);
    try testing.expectEqualStrings("GET /apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/:name", @tagName(found.found));
    try testing.expectEqualStrings("colibri", parameters.get("name").?);
    const patched = kubernetes.Pool.match("PATCH", path, &parameters);
    try testing.expectEqualStrings("PATCH /apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/:name", @tagName(patched.found));
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
    const pool = try testing.allocator.create(github.Pool);
    defer testing.allocator.destroy(pool);
    pool.init();
    var engine: Engine = .{};
    var context: void = {};
    // A request that ended at its head gives a body that ends at once (decision 163 ruling 4).
    var no_body: std.Io.Reader = .fixed(&.{});
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
        .headers = .init(&no_lines),
        .body = &no_body,
        .end = true,
    };
    try testing.expect(pool.handle(&context, &engine, &.{ .request = head }) == .taken);
    try testing.expectEqual(200, engine.status);
    const finished: server.Finished = .{ .id = head.id, .user_data = engine.user_data, .result = .sent };
    try testing.expect(pool.handle(&context, &engine, &.{ .finished = finished }) == .taken);
}

test "design §8 step 50b: a POST route answers once its whole body arrived" {
    const pool = try testing.allocator.create(github.Pool);
    defer testing.allocator.destroy(pool);
    pool.init();
    var engine: Engine = .{};
    var context: void = {};
    // A request whose body is still to come gives a body that no read can read (decision 163
    // ruling 4).
    var no_body: std.Io.Reader = .failing;
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
        .headers = .init(&no_lines),
        .body = &no_body,
        .end = false,
    };
    try testing.expect(pool.handle(&context, &engine, &.{ .request = head }) == .taken);
    // The route reads its body whole, so neither the header nor the first piece gets an answer.
    try testing.expectEqual(0, engine.status);
    const piece = [_]u8{'x'} ** (constants.routes_body_bytes / 2);
    const first: server.RequestBody = .{ .id = head.id, .user_data = engine.user_data, .bytes = &piece, .end = false };
    try testing.expect(pool.handle(&context, &engine, &.{ .body = first }) == .taken);
    try testing.expectEqual(0, engine.status);
    const last: server.RequestBody = .{ .id = head.id, .user_data = engine.user_data, .bytes = &piece, .end = true };
    try testing.expect(pool.handle(&context, &engine, &.{ .body = last }) == .taken);
    try testing.expectEqual(200, engine.status);
}
