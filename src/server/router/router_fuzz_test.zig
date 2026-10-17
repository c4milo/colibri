//! The fuzz test and the sweep of `match` (decision 122, design §8 step 21e).
const std = @import("std");
const core = @import("core");
const router = @import("router.zig").router;
const PathParameters = @import("../path_parameters.zig").PathParameters;

const testing = std.testing;

/// The tables that the sweep reads. Each pattern is of one, two or three octets, so the sweep's
/// paths of up to two octets find each route. The parameter child of `swept` matches each path of
/// one segment before the wildcard can, so the wildcard has a table of its own.
const swept_patterns = [_][]const u8{ "/", "/a", "/:x" };
const swept_binding = 2;
const swept = router(u8, .{
    .{ .get, swept_patterns[0], 0 },
    .{ .get, swept_patterns[1], 1 },
    .{ .get, swept_patterns[swept_binding], swept_binding },
});
const swept_wildcard = router(u8, .{
    .{ .get, swept_patterns[0], 0 },
    .{ .get, swept_patterns[1], 1 },
    .{ .get, "/*", swept_binding },
});

/// Most octets a fuzz input carries. Test-only.
const fuzz_input_len_max = 64;

fn fuzz_match(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const target = input[0..smith.slice(&input)];
    try expect_match(swept, "x", target);
    try expect_match(swept_wildcard, "*", target);
}

fn expect_match(table: anytype, comptime name: []const u8, target: []const u8) !void {
    var parameters: PathParameters = .{};
    parameters.count = 1;
    switch (table.match("GET", target, &parameters)) {
        .found => |route| try expect_swept(route, name, target, &parameters),
        // Each path of the table names GET.
        .method_not_allowed, .not_implemented => return error.TestUnexpectedResult,
        .not_found => try testing.expectEqual(0, parameters.count),
    }
    // RFC 9110 §9.1: no route of the table names POST, so each target gives 501.
    parameters.count = 1;
    try testing.expect(table.match("POST", target, &parameters) == .not_implemented);
    try testing.expectEqual(0, parameters.count);
}

fn expect_swept(route: u8, comptime name: []const u8, target: []const u8, parameters: *const PathParameters) !void {
    const before_query = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    // RFC 9110 §4.2.3: a query alone has an empty path, which is the root.
    const path = if (before_query.len == 0) swept_patterns[0] else before_query;
    try testing.expect(path[0] == '/');
    try testing.expectEqual(null, std.mem.indexOfScalar(u8, path, '%'));
    if (route != swept_binding) {
        try testing.expectEqualStrings(swept_patterns[route], path);
        try testing.expectEqual(0, parameters.count);
        return;
    }
    // The value is the path after its first "/". A parameter's value holds no "/".
    const value = parameters.get(name).?;
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqual(path.ptr + 1, value.ptr);
    try testing.expectEqual(path.len - 1, value.len);
    if (comptime !std.mem.eql(u8, name, "*")) try testing.expectEqual(null, std.mem.indexOfScalar(u8, value, '/'));
    // Each segment of the value is not empty and not a dot segment.
    var segments = std.mem.splitScalar(u8, value, '/');
    for (0..value.len + 1) |_| {
        const segment = segments.next() orelse break;
        try testing.expect(segment.len > 0);
        try testing.expect(!std.mem.eql(u8, segment, ".") and !std.mem.eql(u8, segment, ".."));
    }
}

test "fuzz: a found path equals a pattern before its query, or binds segments that are not empty or a dot" {
    try testing.fuzz({}, fuzz_match, .{ .corpus = &.{
        core.fuzz.input("/"),
        core.fuzz.input("/a"),
        core.fuzz.input("/a?b"),
        core.fuzz.input("/?"),
        core.fuzz.input("/b"),
        core.fuzz.input("/b?c"),
        core.fuzz.input("/..."),
        core.fuzz.input("/a/"),
        core.fuzz.input("/."),
        core.fuzz.input("/%"),
        core.fuzz.input("//"),
        core.fuzz.input("/b/c"),
        core.fuzz.input("/b/c?d/e"),
        core.fuzz.input("/b//c"),
        core.fuzz.input("/b/../c"),
        core.fuzz.input("a"),
        core.fuzz.input("*"),
        core.fuzz.input("?a"),
        core.fuzz.input("?/a"),
    } });
}

test "sweep: every path of up to two octets that matches equals a pattern or binds its segment" {
    try core.fuzz.sweep(fuzz_match, null);
}
