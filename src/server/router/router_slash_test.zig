//! The tests of a path that ends in "/" (decision 122 as amended on 2026-10-29). RFC 3986 §6.2.4
//! counts "/a/" equal to "/a" only when the server says so, so a route table keeps the two apart.
//! Only a pattern that ends in "/" matches a path that ends in "/". Test-only.
const std = @import("std");
const router = @import("router_table.zig").table_of;
const router_pattern = @import("router_pattern.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const support = @import("router_test_support.zig");

const testing = std.testing;
const expect_found = support.expect_found;
const expect_not_found = support.expect_not_found;
const expect_allow = support.expect_allow;

const Route = enum { item, items, item_child, any_items, files, items_put };

const slashes = router(Route, .{
    .{ .get, "/a", .item },
    .{ .get, "/a/", .items },
    .{ .get, "/a/:id", .item_child },
    .{ .get, "/:x/", .any_items },
    .{ .get, "/f/*", .files },
    .{ .put, "/b/", .items_put },
});

/// Requires `match` to give `found` with `expected` and the one parameter `name` of `value`.
fn expect_bound(expected: Route, path: []const u8, name: []const u8, value: []const u8) !void {
    var parameters: PathParameters = .{};
    const result = slashes.match("GET", path, &parameters);
    try testing.expect(result == .found);
    try testing.expectEqual(expected, result.found);
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqualStrings(value, parameters.get(name).?);
}

test "decision 122 as amended: \"/a\" and \"/a/\" are two routes, and each matches its own path" {
    try expect_found(slashes, Route.item, "GET", "/a");
    try expect_found(slashes, Route.items, "GET", "/a/");
    try expect_found(slashes, Route.items, "GET", "/a/?x=1");
    try expect_found(slashes, Route.items, "HEAD", "/a/");
    try expect_bound(.item_child, "/a/b", "id", "b");
    try expect_not_found(slashes, "GET", "/a/b/");
}

test "decision 122 as amended: a pattern may end in \"/\", but not after the wildcard" {
    try testing.expectEqual(null, comptime router_pattern.refusal_of("/a/b/"));
    try testing.expectEqual(router_pattern.Refusal.wildcard_not_last, comptime router_pattern.refusal_of("/*/"));
}

test "decision 122 as amended: an empty segment matches no route unless it is the last" {
    try expect_not_found(slashes, "GET", "/a//");
    try expect_not_found(slashes, "GET", "//");
    try expect_not_found(slashes, "GET", "//a");
    try expect_not_found(slashes, "GET", "/a//b");
}

test "decision 122 as amended: a parameter does not match the empty last segment" {
    try expect_bound(.any_items, "/z/", "x", "z");
    try expect_bound(.any_items, "/f/", "x", "f");
    try expect_bound(.any_items, "/z%41/", "x", "zA");
    // "/c/:id" does not take "/c/" with an empty "id".
    try expect_not_found(router(Route, .{.{ .get, "/c/:id", .item_child }}), "GET", "/c/");
    try expect_not_found(router(Route, .{.{ .get, "/:x/:y", .item_child }}), "GET", "/c/");
    try expect_not_found(slashes, "GET", "/z");
}

test "decision 122 as amended: the wildcard does not match a path that ends in \"/\"" {
    try expect_bound(.files, "/f/x", "*", "x");
    try expect_bound(.files, "/f/x/y", "*", "x/y");
    try expect_not_found(slashes, "GET", "/f/x/");
    try expect_not_found(slashes, "GET", "/f/x/y/");
    try expect_not_found(router(Route, .{.{ .get, "/*", .files }}), "GET", "/");
    try expect_not_found(router(Route, .{.{ .get, "/*", .files }}), "GET", "/x/");
}

test "decision 128: the walk backs up past \"/b/\" for a method, to \"/:x/\"" {
    try expect_found(slashes, Route.items_put, "PUT", "/b/");
    try expect_bound(.any_items, "/b/", "x", "b");
    // Each leaf that "/a/" and "/z/" reach serves GET alone.
    try expect_allow(slashes, "GET, HEAD", "PUT", "/a/");
    try expect_allow(slashes, "GET, HEAD", "PUT", "/z/");
}
