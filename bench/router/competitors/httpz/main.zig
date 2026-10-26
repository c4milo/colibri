//! http.zig's router in colibri's router benchmark, with Zig 0.17. It registers the routes of
//! github_routes.txt, then matches every route's path, the given number of rounds, and prints
//! the nanoseconds of one match. Its parameters are reset before each match, as its server does.
//!   router-bench <routes file> <rounds>
const std = @import("std");
const httpz = @import("httpz");

const Action = httpz.Action(void);
const RouterType = httpz.Router(void, Action);
/// http.zig's root exports no `Params`, so the type comes from `route`'s parameter.
const Params = @typeInfo(@typeInfo(@TypeOf(RouterType.route)).@"fn".param_types[4].?).pointer.child;

fn dispatch(_: Action, _: *httpz.Request, _: *httpz.Response) anyerror!void {}
fn nothing(_: *httpz.Request, _: *httpz.Response) anyerror!void {}

/// The parameters one route holds at most, as http.zig's default `params` configuration.
const params_max = 10;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) return error.Usage;
    const rounds = try std.fmt.parseInt(usize, args[2], 10);
    const text = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], arena, .limited(1 << 20));
    var methods: std.ArrayList(httpz.Method) = .empty;
    var paths: std.ArrayList([]const u8) = .empty;
    var router = try RouterType.init(arena, dispatch, {});
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const space = std.mem.indexOfScalar(u8, line, ' ').?;
        const method = std.meta.stringToEnum(httpz.Method, line[0..space]).?;
        const path = line[space + 1 ..];
        switch (method) {
            .GET => router.get(path, nothing, .{}),
            .POST => router.post(path, nothing, .{}),
            .PUT => router.put(path, nothing, .{}),
            .DELETE => router.delete(path, nothing, .{}),
            else => return error.MethodUnknown,
        }
        try methods.append(arena, method);
        try paths.append(arena, path);
    }
    var params = try Params.init(arena, params_max);
    for (methods.items, paths.items) |method, path| {
        params.reset();
        if (router.route(method, "", path, &params) == null) {
            std.debug.print("httpz: no route for {s} {s}\n", .{ @tagName(method), path });
            return error.RouteMissing;
        }
    }
    const start = std.Io.Timestamp.now(init.io, .awake);
    var found: usize = 0;
    for (0..rounds) |_| {
        for (methods.items, paths.items) |method, path| {
            params.reset();
            const volatile_path: *const volatile []const u8 = &path;
            if (router.route(method, "", volatile_path.*, &params) != null) found += 1;
            std.mem.doNotOptimizeAway(&params);
        }
    }
    const elapsed = start.durationTo(std.Io.Timestamp.now(init.io, .awake)).nanoseconds;
    const matches = rounds * paths.items.len;
    const ns: f64 = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(@max(matches, 1)));
    std.debug.print("httpz matches={d} found={d} ns_per_match={d:.1}\n", .{ matches, found, ns });
}
