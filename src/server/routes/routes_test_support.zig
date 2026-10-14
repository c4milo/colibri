//! The checks that the tests of `match` share (decision 122, design §8 step 21e). Test-only.
const std = @import("std");
const PathParameters = @import("../path_parameters.zig").PathParameters;

const testing = std.testing;

/// Requires `match` to give `found` with `expected` and no parameter.
pub fn expect_found(table: anytype, expected: anytype, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    const result = table.match(method, path, &parameters);
    try testing.expect(result == .found);
    try testing.expectEqual(expected, result.found);
    try testing.expectEqual(0, parameters.count);
}

/// Requires `match` to give `not_found` and no parameter.
pub fn expect_not_found(table: anytype, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    try testing.expect(table.match(method, path, &parameters) == .not_found);
    try testing.expectEqual(0, parameters.count);
}

/// Requires `match` to give `method_not_allowed` with the Allow value `allow`.
pub fn expect_allow(table: anytype, allow: []const u8, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    const result = table.match(method, path, &parameters);
    try testing.expect(result == .method_not_allowed);
    try testing.expectEqualStrings(allow, result.method_not_allowed);
}
