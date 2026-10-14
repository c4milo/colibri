//! The run-time probe: `match` on one path, a fixed number of times, against a table of k literal
//! edges of four octets at the root. callgrind counts its instructions (`run_time.sh`).
//!   probe <k> <first|middle|last|miss> <count>
//! k is one of `edge_counts`. The path is the first edge, the middle edge, the last edge, or
//! "/r999", which no edge holds.
const std = @import("std");
const server = @import("server");
const tables = @import("tables.zig");

comptime {
    _ = @import("hook.zig");
}

const edge_counts = [_]usize{ 1, 2, 4, 8, 16, 64, 256 };

/// The index that `literal` turns into "r999", which no table holds.
const miss_index = 999;

fn index_of(edges: usize, position: []const u8) usize {
    if (std.mem.eql(u8, position, "first")) return 0;
    if (std.mem.eql(u8, position, "middle")) return edges / 2;
    if (std.mem.eql(u8, position, "last")) return edges - 1;
    return miss_index;
}

fn run(comptime edges: usize, path: []const u8, count: usize) u64 {
    const table = comptime server.router(u16, tables.literals(edges, ""));
    // A volatile read, so the compiler does not move the match out of the loop.
    var held: []const u8 = path;
    const volatile_path: *volatile []const u8 = &held;
    var parameters: server.PathParameters = .{};
    var found: u64 = 0;
    for (0..count) |_| {
        if (table.match("GET", volatile_path.*, &parameters) == .found) found += 1;
        std.mem.doNotOptimizeAway(&parameters);
    }
    return found;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.Usage;
    const edges = try std.fmt.parseInt(usize, args[1], 10);
    const count = try std.fmt.parseInt(usize, args[3], 10);
    const index = index_of(edges, args[2]);
    var path_buffer: [5]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "/r{d:0>3}", .{index});
    var found: u64 = 0;
    inline for (edge_counts) |k| {
        if (k == edges) found = run(k, path, count);
    }
    std.mem.doNotOptimizeAway(found);
    var buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "found {d}\n", .{found});
    _ = std.posix.system.write(1, text.ptr, text.len);
}
