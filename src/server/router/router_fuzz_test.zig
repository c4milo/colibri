//! The fuzz test and the sweep of `match` (decision 122, design §8 step 21e).
const std = @import("std");
const core = @import("core");
const router = @import("router_table.zig").table_of;
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
    var decoded_storage: [fuzz_input_len_max]u8 = undefined;
    // Decision 127: a route compares with the path decoded (RFC 3986 §2.1).
    const decoded = reference_decode(path[1..], &decoded_storage);
    if (route != swept_binding) {
        try testing.expectEqualStrings(swept_patterns[route][1..], decoded);
        try testing.expectEqual(0, parameters.count);
        return;
    }
    // The value is the path after its first "/", decoded. A parameter's encoded value holds no
    // "/", and a value with no "%" is the path's own octets.
    const value = parameters.get(name).?;
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqualStrings(decoded, value);
    if (std.mem.indexOfScalar(u8, path, '%') == null) try testing.expectEqual(path.ptr + 1, value.ptr);
    if (comptime !std.mem.eql(u8, name, "*")) try testing.expectEqual(null, std.mem.indexOfScalar(u8, path[1..], '/'));
    // Each encoded segment of the value is not empty, and decodes to no dot segment and to no
    // "/", "\\" or NUL (RFC 3986 §7.3).
    var segments = std.mem.splitScalar(u8, path[1..], '/');
    for (0..path.len + 1) |_| {
        const segment = segments.next() orelse break;
        try testing.expect(segment.len > 0);
        var segment_storage: [fuzz_input_len_max]u8 = undefined;
        const plain = reference_decode(segment, &segment_storage);
        try testing.expect(!std.mem.eql(u8, plain, ".") and !std.mem.eql(u8, plain, ".."));
        try testing.expectEqual(null, std.mem.indexOfAny(u8, plain, "/\\\x00"));
    }
}

/// `encoded` percent-decoded, the plain way: "%" and two hex digits give the octet they name, and
/// any other octet stays. It is written apart from the router's own decoder, so the two check
/// each other. Test-only.
fn reference_decode(encoded: []const u8, out: []u8) []const u8 {
    const radix = 16;
    const digits = 2;
    var len: usize = 0;
    var index: usize = 0;
    while (index < encoded.len) : (len += 1) {
        if (encoded[index] == '%' and index + digits < encoded.len) {
            const high = std.fmt.charToDigit(encoded[index + 1], radix) catch null;
            const low = std.fmt.charToDigit(encoded[index + digits], radix) catch null;
            if (high != null and low != null) {
                out[len] = high.? * radix + low.?;
                index += digits + 1;
                continue;
            }
        }
        out[len] = encoded[index];
        index += 1;
    }
    return out[0..len];
}

test "fuzz: a found path equals a pattern before its query, or binds segments that are not empty, a dot or a slash" {
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
        core.fuzz.input("/%61"),
        core.fuzz.input("/b/%2F"),
        core.fuzz.input("/b/%2f"),
        core.fuzz.input("/b%5C"),
        core.fuzz.input("/%00"),
        core.fuzz.input("/b/%252F"),
        core.fuzz.input("/%2E%2e"),
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
