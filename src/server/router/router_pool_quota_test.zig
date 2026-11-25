//! The test of the router's comptime branch quota on a table of many routes (design §8 step 54).
//!
//! Each function of the pool that switches over every route makes one prong for each route, so it
//! raises Zig's default quota of 1,000 backwards branches by `branch_quota_per_route` for each
//! route. `on_body` and `on_writable` raised none, and connect-zig's table of 256 struct routes
//! did not compile. Whether a table passes the default quota depends on more than its count of
//! routes: some tables of 256 and of 512 routes compiled with it. This table fails without the
//! quota in `on_body`, and without the one in `on_writable`, because its routes declare `next`.
//! The test sends each event that reaches a switch, so every one of them compiles. Keep its code
//! as it is: tables of other shapes did not find the fault.
const std = @import("std");
const event = @import("../event.zig");
const Response = @import("../response/response.zig").Response;
const RequestContext = @import("../request_context.zig").RequestContext;
const Router = @import("router.zig").Router;
const support = @import("router_handle_test_support.zig");

const testing = std.testing;

/// The services of the API, and the methods of each: 256 routes, past the 225 that connect-zig's
/// table compiled with.
const services = 16;
const methods = 16;
const route_count = services * methods;

/// The entries of the pool, octets of each entry's response memory, and the requests the test
/// sends. Test-only.
const requests = 2;
const response_bytes = 64;
const sent = 2;

/// The table builds an even route and an odd route on two paths of its code. Test-only.
const parity = 2;

const App = struct { heads: usize = 0 };

/// A struct route type, which answers at the head. Its `next`, which never runs, makes the prong
/// of `on_writable` call the stream's `run_next`.
fn StreamOf(comptime index: usize) type {
    return struct {
        pub const State = struct {};
        pub const route_index = index;

        pub fn on_request(app: *App, _: *RequestContext, _: *State, _: *const event.Request, response: *Response) !void {
            app.heads += 1;
            try response.end();
        }

        pub fn next(_: *App, _: *RequestContext, _: *State, _: *Response) !void {}
    };
}

fn on_error(_: *App, _: *RequestContext, _: *const event.Request, _: anyerror, response: *Response) void {
    response.status = .internal_server_error;
}

/// The comptime branches that the build of one route's entry takes, at most: its path's print.
const build_quota_per_route = 2_000;

/// Each method of each service, a struct route.
const routes = routes: {
    @setEvalBranchQuota(route_count * build_quota_per_route);
    var types: [route_count]type = undefined;
    for (0..route_count) |index| {
        types[index] = struct { @TypeOf(.post), []const u8, type };
    }
    var list: std.meta.Tuple(&types) = undefined;
    for (0..route_count) |index| {
        if (index % parity == 0) {
            list[index] = .{ .post, std.fmt.comptimePrint("/api.v1.Service{d:0>2}/Method{d:0>2}", .{ index / methods, index % methods }), StreamOf(0) };
        } else {
            list[index] = .{ .post, std.fmt.comptimePrint("/api.v1.Service{d:0>2}/Method{d:0>2}", .{ index / methods, index % methods }), StreamOf(0) };
        }
    }
    break :routes list;
};

const table = .{ .error_handler = on_error, .routes = routes };

const Pool = Router(App, table, .{ .requests = requests, .response_bytes = response_bytes, .body_bytes = 0, .header_bytes = 0 });

test "design §8 step 54: a table of 256 struct routes compiles, and each event reaches its route" {
    var app: App = .{};
    var recorder: support.Recorder = .{};
    var pool: Pool = .{};
    for ([_][]const u8{ "/api.v1.Service00/Method00", "/api.v1.Service15/Method15" }, 1..) |path, number| {
        recorder.user_data = 0;
        // The head carries no end, so the body event reaches `on_body`.
        const head = support.request_of(number, "POST", path, false);
        try testing.expect(pool.handle(&app, &recorder, &.{ .request = head }) == .taken);
        const user_data = recorder.user_data;
        const body: event.RequestBody = .{ .id = head.id, .user_data = user_data, .bytes = "", .end = true };
        try testing.expect(pool.handle(&app, &recorder, &.{ .body = body }) == .taken);
        const writable: event.Writable = .{ .id = head.id, .user_data = user_data };
        try testing.expect(pool.handle(&app, &recorder, &.{ .writable = writable }) == .taken);
        const finished: event.Finished = .{ .id = head.id, .user_data = user_data, .result = .sent };
        try testing.expect(pool.handle(&app, &recorder, &.{ .finished = finished }) == .taken);
    }
    try testing.expectEqual(sent, app.heads);
    try testing.expectEqual(sent, recorder.head_count);
}
