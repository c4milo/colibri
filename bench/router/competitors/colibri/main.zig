//! colibri's router in its own benchmark: the compiler builds the route table from
//! github_routes.txt, then the program matches every route's path, the given number of rounds,
//! and prints the nanoseconds of one match.
//!   router-bench <rounds>
const std = @import("std");
const http = @import("http");
const server = @import("server");

comptime {
    _ = @import("hook.zig");
}

fn route(_: *void, _: *const server.Request, _: void, _: void, _: *server.ResponseWriter) anyerror!void {}

fn on_error(_: *void, _: *const server.Request, _: anyerror, _: *server.ResponseWriter) void {}

const Entry = struct { http.method.Standard, []const u8, *const @TypeOf(route) };

/// The routes of github_routes.txt, one "METHOD /path" on each line.
const lines = @embedFile("github_routes.txt");

/// Each route's method as its request carries it, such as "GET".
const methods: [count_of(lines)][]const u8 = build: {
    @setEvalBranchQuota(1_000_000);
    var held: [count_of(lines)][]const u8 = undefined;
    var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
    var index: usize = 0;
    while (iterator.next()) |line| : (index += 1) held[index] = line[0..std.mem.indexOfScalar(u8, line, ' ').?];
    break :build held;
};

const entries: [count_of(lines)]Entry = build: {
    @setEvalBranchQuota(1_000_000);
    var held: [count_of(lines)]Entry = undefined;
    var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
    var index: usize = 0;
    while (iterator.next()) |line| : (index += 1) {
        const space = std.mem.indexOfScalar(u8, line, ' ').?;
        var method: [space]u8 = undefined;
        _ = std.ascii.lowerString(&method, line[0..space]);
        held[index] = .{ @field(http.method.Standard, &method), line[space + 1 ..], &route };
    }
    break :build held;
};

fn count_of(comptime text: []const u8) usize {
    @setEvalBranchQuota(1_000_000);
    return std.mem.count(u8, text, "\n");
}

const routes = server.router(void, .{ .error_handler = on_error, .routes = entries });

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.Usage;
    const rounds = try std.fmt.parseInt(usize, args[1], 10);
    var parameters: server.PathParameters = .{};
    for (methods, entries) |method, entry| {
        if (routes.match(method, entry[1], &parameters) != .found) return error.RouteMissing;
    }
    const start = std.Io.Timestamp.now(init.io, .awake);
    var found: usize = 0;
    for (0..rounds) |_| {
        for (methods, entries) |method, entry| {
            const path: *volatile []const u8 = @constCast(&entry[1]);
            if (routes.match(method, path.*, &parameters) == .found) found += 1;
            std.mem.doNotOptimizeAway(&parameters);
        }
    }
    const elapsed = start.durationTo(std.Io.Timestamp.now(init.io, .awake)).nanoseconds;
    const matches = rounds * entries.len;
    var buffer: [128]u8 = undefined;
    const ns: f64 = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(@max(matches, 1)));
    const text = try std.fmt.bufPrint(&buffer, "colibri matches={d} found={d} ns_per_match={d:.1}\n", .{ matches, found, ns });
    _ = std.posix.system.write(1, text.ptr, text.len);
}
