//! The compile-time probe: one table of `tables.zig`, which `-Dtable` names, in a Debug test
//! binary. `compile_time.sh` times `zig build compile` for each table.
const std = @import("std");
const server = @import("server");
const options = @import("options");
const tables = @import("tables.zig");

comptime {
    _ = @import("hook.zig");
}

const case = @field(tables, @tagName(options.table));

test "the table compiles and matches its path" {
    // The stamp changes the inputs of the build, so the compiler builds the table again.
    std.mem.doNotOptimizeAway(options.stamp);
    const table = server.router(void, tables.table_of(case.entries));
    var parameters: server.PathParameters = .{};
    try std.testing.expect(table.match("GET", case.path, &parameters) == .found);
}
