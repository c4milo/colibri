//! colibri's router in its own benchmark: the compiler builds the route table from
//! routes.txt, a copy of one table of bench/router/competitors/, then the program matches every
//! route's path, the given number of rounds,
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

/// The routes of routes.txt, one "METHOD /path" on each line.
const lines = @embedFile("routes.txt");

/// Each route's method as its request carries it, such as "GET".
const methods: [count_of(lines)][]const u8 = build: {
    @setEvalBranchQuota(10_000_000);
    var held: [count_of(lines)][]const u8 = undefined;
    var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
    var index: usize = 0;
    while (iterator.next()) |line| : (index += 1) held[index] = line[0..std.mem.indexOfScalar(u8, line, ' ').?];
    break :build held;
};

/// A route's method as a table names it: one of RFC 9110's eight as `http.method.Standard`, and
/// any other, such as PATCH, as its token (decision 122 ruling 4).
fn MethodOf(comptime method: []const u8) type {
    var lower: [method.len]u8 = undefined;
    _ = std.ascii.lowerString(&lower, method);
    return if (@hasField(http.method.Standard, &lower)) http.method.Standard else []const u8;
}

fn method_of(comptime method: []const u8) MethodOf(method) {
    var lower: [method.len]u8 = undefined;
    _ = std.ascii.lowerString(&lower, method);
    if (comptime MethodOf(method) == http.method.Standard) return @field(http.method.Standard, &lower);
    return method;
}

const Handler = *const @TypeOf(route);

const entries = build: {
    @setEvalBranchQuota(10_000_000);
    var types: [count_of(lines)]type = undefined;
    for (methods, 0..) |method, index| types[index] = std.meta.Tuple(&.{ MethodOf(method), []const u8, Handler });
    var held: std.meta.Tuple(&types) = undefined;
    var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
    var index: usize = 0;
    while (iterator.next()) |line| : (index += 1) {
        const space = std.mem.indexOfScalar(u8, line, ' ').?;
        held[index] = .{ method_of(line[0..space]), line[space + 1 ..], &route };
    }
    break :build held;
};

fn count_of(comptime text: []const u8) usize {
    @setEvalBranchQuota(1_000_000);
    return std.mem.count(u8, text, "\n");
}

const routes = server.router(void, .{ .error_handler = on_error, .routes = entries });

pub fn main(init: std.process.Init) !void {
    @setEvalBranchQuota(10_000_000);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.Usage;
    const rounds = try std.fmt.parseInt(usize, args[1], 10);
    var parameters: server.PathParameters = .{};
    inline for (methods, 0..) |method, index| {
        switch (routes.match(method, entries[index][1], &parameters)) {
            .found => |found| if (@intFromEnum(found) != index) return error.RouteOther,
            else => return error.RouteMissing,
        }
    }
    const start = std.Io.Timestamp.now(init.io, .awake);
    var found: usize = 0;
    for (0..rounds) |_| {
        inline for (methods, 0..) |method, index| {
            const path: *volatile []const u8 = @constCast(&entries[index][1]);
            if (routes.match(method, path.*, &parameters) == .found) found += 1;
            std.mem.doNotOptimizeAway(&parameters);
        }
    }
    const elapsed = start.durationTo(std.Io.Timestamp.now(init.io, .awake)).nanoseconds;
    const matches = rounds * methods.len;
    var buffer: [128]u8 = undefined;
    const ns: f64 = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(@max(matches, 1)));
    const text = try std.fmt.bufPrint(&buffer, "colibri matches={d} found={d} ns_per_match={d:.1}\n", .{ matches, found, ns });
    _ = std.posix.system.write(1, text.ptr, text.len);
}
