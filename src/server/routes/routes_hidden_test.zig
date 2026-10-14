//! The cross-check of the check of hidden routes (decision 122 ruling 12, design §8 step 21e).
//! It is the evidence for claims 4 and 5 of `routes_hidden.zig`.
//!
//! For each table of a family of small tables, a brute force decides each route's verdict from
//! every path of a few segments, and the test requires the check to give the same first
//! refusal. The brute force builds the layout with `routes_trie_layout.build`, because a refused
//! table cannot go through `server.routes`. It decides whether a route's pattern matches a path
//! with a matcher of its own, and it calls the real `match` for the result of each request:
//!   - a route is hidden when a path that its pattern matches gets `method_not_allowed` for its
//!     method;
//!   - a route is reachable when a path gives `found` with the route's value. Each route of a
//!     table has its index as its value.
const std = @import("std");
const http = @import("http");
const routes_trie = @import("routes_trie.zig");
const routes_trie_layout = @import("routes_trie_layout.zig");
const routes_hidden = @import("routes_hidden.zig");
const routes_match = @import("routes_match.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;

const testing = std.testing;
const Standard = http.method.Standard;
const Entry = struct { Standard, []const u8, u8 };

/// The methods of the family.
const methods = [_]Standard{ .get, .put };

/// The segments of a path that the brute force reads: the two literals of the family, and two
/// segments that equal no literal.
const path_segments = [_][]const u8{ "a", "b", "c", "d" };

/// The patterns of at most two segments over the literals "a" and "b", a parameter and the
/// wildcard. The parameter at each position has a name of its own, so no two names meet at one
/// node (refusal 19).
const pair_patterns = [_][]const u8{
    "/",      "/a",    "/b",    "/:x",   "/*",
    "/a/a",   "/a/b",  "/a/:y", "/a/*",  "/b/a",
    "/b/b",   "/b/:y", "/b/*",  "/:x/a", "/:x/b",
    "/:x/:y", "/:x/*",
};

/// The triples of the owner's example 8: a wildcard, a segment in its place, and a wildcard
/// after that segment, after each prefix.
const triple_prefixes = [_][]const u8{ "", "/a", "/:x" };
const triple_segments = [_][]const u8{ ":s", "a" };

/// The most segments of a path that the brute force reads: one more than the deepest pattern of
/// the family (claim 3).
const pair_path_segments = 3;
const triple_path_segments = 4;

/// The comptime branches of the cross-check of one table.
const branches_per_table = 400_000;

/// The verdict of the check, or of the brute force, on one table.
const Verdict = struct { route: ?usize, tag: ?std.meta.Tag(routes_trie.Reason) };

/// The count of tables that the cross-check read, by verdict, and the first table where the
/// check and the brute force differ.
const Census = struct {
    tables: usize = 0,
    hidden: usize = 0,
    unreached: usize = 0,
    compiled: usize = 0,
    differ: ?[]const u8 = null,
};

fn pattern_matches(pattern: []const u8, path: []const []const u8) bool {
    if (std.mem.eql(u8, pattern, "/")) return path.len == 0;
    var segments = std.mem.splitScalar(u8, pattern[1..], '/');
    for (0..path.len + 1) |position| {
        const segment = segments.next() orelse return position == path.len;
        if (std.mem.eql(u8, segment, "*")) return position < path.len;
        if (position == path.len) return false;
        if (segment[0] != ':' and !std.mem.eql(u8, segment, path[position])) return false;
    }
    return segments.next() == null;
}

/// Each path of `count` segments over `path_segments`, as segments and as text.
fn paths_of(comptime count: usize) []const Path {
    var paths: []const Path = &.{.{ .segments = &.{}, .text = "/" }};
    var last: []const Path = paths;
    for (0..count) |_| {
        var next: []const Path = &.{};
        for (last) |path| {
            for (path_segments) |segment| {
                const text = if (path.segments.len == 0) "/" ++ segment else path.text ++ "/" ++ segment;
                next = next ++ [_]Path{.{ .segments = path.segments ++ [_][]const u8{segment}, .text = text }};
            }
        }
        paths = paths ++ next;
        last = next;
    }
    return paths;
}

const Path = struct { segments: []const []const u8, text: []const u8 };

fn token(method: Standard) []const u8 {
    return if (method == .get) "GET" else "PUT";
}

/// The first refusal, in table order, that the brute force finds.
fn brute_verdict(comptime table: []const Entry, comptime paths: []const Path) Verdict {
    const layout = routes_trie_layout.build(u8, table[0..table.len].*);
    for (table, 0..) |entry, route| {
        var hidden = false;
        var reached = false;
        for (paths) |path| {
            if (!pattern_matches(entry[1], path.segments)) continue;
            var parameters: PathParameters = .{};
            switch (routes_match.match(u8, layout, token(entry[0]), path.text, &parameters)) {
                .found => |value| reached = reached or value == route,
                .method_not_allowed => hidden = true,
                .not_found, .not_implemented => unreachable,
            }
        }
        if (hidden) return .{ .route = route, .tag = .route_hidden };
        if (!reached) return .{ .route = route, .tag = .route_unreachable };
    }
    return .{ .route = null, .tag = null };
}

fn check_verdict(comptime table: []const Entry) Verdict {
    const array = table[0..table.len].*;
    const layout = routes_trie_layout.build(u8, array);
    const refusal = routes_hidden.refusal_of(u8, layout, array) orelse return .{ .route = null, .tag = null };
    return .{ .route = refusal.route, .tag = std.meta.activeTag(refusal.reason) };
}

fn cross_check(census: *Census, comptime table: []const Entry, comptime paths: []const Path) void {
    // Refusals 1 to 19 come first, and a table that one of them refuses gets no layout.
    if (routes_trie.refusal_of(table[0..table.len].*) != null) return;
    const brute = brute_verdict(table, paths);
    const check = check_verdict(table);
    census.tables += 1;
    if (brute.tag == null) census.compiled += 1;
    if (brute.tag == .route_hidden) census.hidden += 1;
    if (brute.tag == .route_unreachable) census.unreached += 1;
    if (census.differ != null) return;
    if (brute.route != check.route or brute.tag != check.tag) census.differ = describe(table);
}

fn describe(comptime table: []const Entry) []const u8 {
    var text: []const u8 = "";
    for (table) |entry| text = text ++ token(entry[0]) ++ " " ++ entry[1] ++ "; ";
    return text;
}

/// Every table of two routes over `pair_patterns` and `methods`, in each order.
fn pair_census() Census {
    const routes_count = pair_patterns.len * methods.len;
    @setEvalBranchQuota(branches_per_table * routes_count * routes_count);
    const paths = paths_of(pair_path_segments);
    var census: Census = .{};
    for (0..routes_count) |first| {
        for (0..routes_count) |second| {
            if (first == second) continue;
            cross_check(&census, &.{ pair_entry(first, 0), pair_entry(second, 1) }, paths);
        }
    }
    return census;
}

fn pair_entry(index: usize, value: u8) Entry {
    return .{ methods[index % methods.len], pair_patterns[index / methods.len], value };
}

/// Every triple of example 8's shape, with each method at each route. The tables of two routes
/// read each order, so the triples keep one.
fn triple_census() Census {
    const methods_count = methods.len * methods.len * methods.len;
    const tables = triple_prefixes.len * triple_segments.len * methods_count;
    @setEvalBranchQuota(branches_per_table * tables);
    const paths = paths_of(triple_path_segments);
    var census: Census = .{};
    for (triple_prefixes) |prefix| {
        for (triple_segments) |segment| {
            const patterns = [_][]const u8{ prefix ++ "/*", prefix ++ "/" ++ segment, prefix ++ "/" ++ segment ++ "/*" };
            for (0..methods_count) |choice| {
                var table: [patterns.len]Entry = undefined;
                for (&table, patterns, 0..) |*entry, pattern, route| {
                    const method = methods[(choice >> @intCast(route)) & 1];
                    entry.* = .{ method, pattern, route };
                }
                const fixed = table;
                cross_check(&census, &fixed, paths);
            }
        }
    }
    return census;
}

test "decision 122 ruling 12: the check gives the brute force's verdict on every table of two routes" {
    const census = comptime pair_census();
    if (census.differ) |table| std.debug.print("the check and the brute force differ on: {s}\n", .{table});
    try testing.expectEqual(null, census.differ);
    // In each table of two routes of the family, a request reaches each route.
    try testing.expectEqual(Census{ .tables = 1122, .hidden = 240, .unreached = 0, .compiled = 882 }, census);
}

test "decision 122 ruling 12: the check gives the brute force's verdict on each triple of example 8" {
    const census = comptime triple_census();
    if (census.differ) |table| std.debug.print("the check and the brute force differ on: {s}\n", .{table});
    try testing.expectEqual(null, census.differ);
    try testing.expectEqual(Census{ .tables = 48, .hidden = 36, .unreached = 6, .compiled = 6 }, census);
}
