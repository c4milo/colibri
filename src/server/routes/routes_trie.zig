//! The checks on a whole route table at compile time, and the trie of its path segments
//! (decision 122, design §8 step 21e). `routes_trie_layout.zig` writes the trie into the arrays
//! that `match` reads.
//!
//! A table is a tuple, or an array, of entries. An entry is a tuple of a method, a pattern and a
//! value. `refusal_of` checks a table in this order (invariant 7):
//!   1. The table holds one entry at least, or `table_empty`.
//!   2. Each entry, from the first, is a tuple of three parts whose pattern is text, or
//!      `entry_shape`. Then its method passes `routes_method.refusal_of`, and its pattern passes
//!      `routes_pattern.refusal_of`.
//!   3. No two routes give two names to one parameter node, or `parameter_names_differ`.
//!   4. No two routes name one method at one leaf, or `route_repeated`.
//!
//! `routes.zig` then builds the layout and checks it in this order: each Allow value fits
//! `core.constants.field_value_len_max`, or `allow_too_long` (`routes_trie_layout.zig`), and no
//! route is hidden, or `route_hidden` or `route_unreachable` (`routes_hidden.zig`).
//!
//! `merge` writes the trie of a table's patterns. It gives each segment of a pattern a node, and
//! two patterns with the same first segments share their nodes.
const std = @import("std");
const assert = std.debug.assert;
const routes_pattern = @import("routes_pattern.zig");
const routes_method = @import("routes_method.zig");

/// The node of the path "/", where each walk starts.
pub const root = 0;

/// The parts of an entry, in order: its method, its pattern and its value.
const method_part = 0;
const pattern_part = 1;
pub const value_part = 2;
const entry_parts = 3;

/// The comptime branches that the checks and the build take, at most: a fixed part, a part for
/// each octet of the patterns and of the method tokens times the count of routes, and a part for
/// each pair of routes. The trie's lookups and sorts compare each segment with the segments of
/// the other routes, and the check of repeated routes compares each pair of routes. A table of
/// 256 routes of 64 octets each needs a quarter of this quota (`routes_test.zig`).
const quota_branches_base = 4_096;
const quota_branches_per_octet_route = 8;
const quota_branches_per_route_pair = 16;

/// The comptime branches that the check of hidden routes (`routes_hidden.zig`) takes, at most,
/// beside `quota_of`. It has two parts:
///   - It compares each pair of leaves at each length of a path, segment by segment, so a part
///     for each pair, each length and each segment.
///   - It walks each canonical path once. A walk takes `routes_match.walk_steps_max` passes at
///     most, and each pass costs a fixed part. A walk reads the literal edges of each node once at
///     most, and each octet of its path once, so a part for each octet of the table and the path.
pub const quota_branches_per_pair_length_segment = 32;
pub const quota_branches_per_walk_step = 32;
pub const quota_branches_per_walk_octet = 16;

/// The quota of the check of hidden routes: `quota_of(table)`, the part for `pairs` pairs of
/// leaves at `lengths` lengths of `segments` segments, and the part for `walks` walks of
/// `walk_steps` passes each over `octets` octets. The value stops at the largest `u32`, which
/// `@setEvalBranchQuota` takes.
pub fn hidden_quota_of(comptime table: anytype, comptime counts: HiddenCounts) u32 {
    const compared: u64 = @as(u64, quota_branches_per_pair_length_segment) * counts.pairs * counts.lengths * counts.segments;
    const walked: u64 = @as(u64, counts.walks) *
        (quota_branches_per_walk_step * counts.walk_steps + quota_branches_per_walk_octet * counts.octets);
    return @intCast(@min(std.math.maxInt(u32), quota_of(table) + compared + walked));
}

/// The counts that bound the work of the check of hidden routes.
pub const HiddenCounts = struct {
    pairs: usize,
    lengths: usize,
    segments: usize,
    walks: usize = 0,
    walk_steps: usize = 0,
    octets: usize = 0,
};

/// Why a table does not compile.
pub const Reason = union(enum) {
    pattern: routes_pattern.Refusal,
    method: routes_method.Refusal,
    table_empty,
    entry_shape,
    parameter_names_differ,
    route_repeated,
    allow_too_long,
    route_hidden: Hidden,
    route_unreachable: Unreachable,

    /// The name that the compile error writes, which `zig build routes-check` reads.
    pub fn name(reason: Reason) []const u8 {
        return switch (reason) {
            .pattern => |refusal| @tagName(refusal),
            .method => |refusal| @tagName(refusal),
            else => @tagName(reason),
        };
    }

    /// The sentence that the compile error writes after the name. Comptime-only.
    pub fn sentence(comptime reason: Reason) []const u8 {
        return switch (reason) {
            .pattern => |refusal| refusal.reason(),
            .method => |refusal| refusal.reason(),
            .table_empty => "a table holds one route at least",
            .entry_shape => "an entry is a tuple of a method, a pattern and a value",
            .parameter_names_differ => "two routes with the same segments before a parameter give the parameter one name",
            .route_repeated => "two routes name one method and one path",
            .allow_too_long => "the Allow value of the routes of one pattern holds " ++
                "core.constants.field_value_len_max octets at most, because a 405 sends it as a field value",
            .route_hidden => |hidden| hidden.sentence(),
            .route_unreachable => |never| never.sentence(),
        };
    }
};

/// A request that a route matches, which gets 405 from the routes of another pattern (decision
/// 122 ruling 12).
pub const Hidden = struct {
    /// The route's method token.
    method: []const u8,
    /// A path that the route matches.
    path: []const u8,
    /// The pattern that the walk on the path finds first.
    pattern: []const u8,

    fn sentence(comptime hidden: Hidden) []const u8 {
        // RFC 9110 §9.3.2: a HEAD request finds a GET route too.
        const methods = if (std.mem.eql(u8, hidden.method, routes_method.head_token)) "HEAD or GET" else hidden.method;
        return std.fmt.comptimePrint(
            "a request that this route matches gets 405 from another pattern: {s} \"{s}\" matches " ++
                "\"{s}\" first, and no route of that pattern names {s}",
            .{ hidden.method, hidden.path, hidden.pattern, methods },
        );
    }
};

/// Why no request reaches a route (decision 122 ruling 12).
pub const Unreachable = struct {
    /// The patterns that the walk finds first on the paths of the route, each in quotes and
    /// joined by ", ", or "" when there is none.
    patterns: []const u8,
    /// Whether a path of the route is longer than `server.constants.path_len_max`.
    too_long: bool,

    fn sentence(comptime never: Unreachable) []const u8 {
        const prefix = "no request reaches this route, because ";
        const long = "server.constants.path_len_max";
        if (never.patterns.len == 0) return prefix ++ "each of its paths is longer than " ++ long;
        const first = "another pattern matches each of its paths first";
        if (!never.too_long) return prefix ++ first ++ ": " ++ never.patterns;
        return prefix ++ first ++ ", or the path is longer than " ++ long ++ ": " ++ never.patterns;
    }
};

/// The first entry of a table that does not compile, and why.
pub const Refusal = struct {
    /// The entry's index in the table.
    route: usize,
    /// The entry's pattern, or "" when the entry has no pattern.
    pattern: []const u8,
    reason: Reason,
};

/// The text of the compile error for `refusal`. Comptime-only.
pub fn message(comptime refusal: Refusal) []const u8 {
    const name = refusal.reason.name();
    const sentence = refusal.reason.sentence();
    if (refusal.reason == .table_empty) return std.fmt.comptimePrint("server.routes: {s}: {s}", .{ name, sentence });
    return std.fmt.comptimePrint("server.routes: route {d}, \"{s}\": {s}: {s}", .{ refusal.route, refusal.pattern, name, sentence });
}

/// The first refusal of `table`, or null when the table compiles. Comptime-only.
pub fn refusal_of(comptime table: anytype) ?Refusal {
    @setEvalBranchQuota(quota_of(table));
    // Decision 122: a table with no route matches nothing.
    if (table.len == 0) return .{ .route = 0, .pattern = "", .reason = .table_empty };
    inline for (0..table.len) |index| {
        if (entry_refusal(table[index])) |reason| {
            return .{ .route = index, .pattern = pattern_or_empty(table[index]), .reason = reason };
        }
    }
    if (names_refusal(table)) |refusal| return refusal;
    return repeated_refusal(table);
}

fn entry_refusal(comptime entry: anytype) ?Reason {
    // Decision 122: an entry is a tuple of a method, a pattern and a value.
    if (!is_entry(@TypeOf(entry))) return .entry_shape;
    if (routes_method.refusal_of(entry[method_part])) |refusal| return .{ .method = refusal };
    if (routes_pattern.refusal_of(entry[pattern_part])) |refusal| return .{ .pattern = refusal };
    return null;
}

fn is_entry(comptime Entry: type) bool {
    const info = @typeInfo(Entry);
    if (info != .@"struct" or !info.@"struct".is_tuple) return false;
    if (info.@"struct".fields.len != entry_parts) return false;
    return routes_pattern.is_text(info.@"struct".fields[pattern_part].type);
}

fn pattern_or_empty(comptime entry: anytype) []const u8 {
    if (!is_entry(@TypeOf(entry))) return "";
    return entry[pattern_part];
}

fn names_refusal(comptime table: anytype) ?Refusal {
    var patterns: [table.len][]const u8 = undefined;
    var named: [table.len]bool = undefined;
    inline for (0..table.len) |index| {
        patterns[index] = table[index][pattern_part];
        // Only a pattern with a parameter can give a parameter node a name.
        named[index] = holds_parameter(patterns[index]);
    }
    for (0..table.len) |later| {
        if (!named[later]) continue;
        for (0..later) |earlier| {
            if (!named[earlier]) continue;
            // Decision 122 ruling 5: one parameter node has one name.
            if (names_differ(patterns[earlier], patterns[later])) {
                return .{ .route = later, .pattern = patterns[later], .reason = .parameter_names_differ };
            }
        }
    }
    return null;
}

/// Whether `pattern` holds a ":", which each parameter does. The loop reads each octet with no
/// call into `std.mem`, whose search costs many comptime branches.
fn holds_parameter(comptime pattern: []const u8) bool {
    for (pattern) |octet| {
        if (octet == routes_pattern.parameter_prefix) return true;
    }
    return false;
}

/// Whether the first segments of `left` and `right` that differ are two parameters. The trie
/// then holds both parameters at one node.
fn names_differ(comptime left: []const u8, comptime right: []const u8) bool {
    const differ = first_difference(left, right);
    // A pattern that ends where the other starts a segment has no segment that differs.
    if (differ == left.len and (differ == right.len or right[differ] == routes_pattern.separator)) return false;
    if (differ == right.len and left[differ] == routes_pattern.separator) return false;
    // The segment that holds the first difference starts at the same octet in both patterns.
    var first = differ;
    for (0..differ) |_| {
        if (left[first - 1] == routes_pattern.separator) break;
        first -= 1;
    }
    // The root's pattern "/" has no segment.
    if (first >= left.len or first >= right.len) return false;
    return left[first] == routes_pattern.parameter_prefix and right[first] == routes_pattern.parameter_prefix;
}

/// The index of the first octet where `left` and `right` differ, or the length of the shorter.
fn first_difference(comptime left: []const u8, comptime right: []const u8) usize {
    const shorter = @min(left.len, right.len);
    for (0..shorter) |index| {
        if (left[index] != right[index]) return index;
    }
    return shorter;
}

fn repeated_refusal(comptime table: anytype) ?Refusal {
    const routes = routes_of(table);
    const merged = merge(&routes.patterns);
    for (0..table.len) |later| {
        for (0..later) |earlier| {
            if (merged.route_node[earlier] != merged.route_node[later]) continue;
            // https://github.com/c4milo/colibri/issues/96: two routes that match one request do
            // not compile.
            if (std.mem.eql(u8, routes.tokens[earlier], routes.tokens[later])) {
                return .{ .route = later, .pattern = routes.patterns[later], .reason = .route_repeated };
            }
        }
    }
    return null;
}

pub fn quota_of(comptime table: anytype) u32 {
    // The loop below makes four calls for each route, and the part for each pair covers them.
    @setEvalBranchQuota(quota_branches_base + quota_branches_per_route_pair * table.len);
    var octets: usize = 0;
    inline for (0..table.len) |index| {
        if (is_entry(@TypeOf(table[index]))) octets += table[index][pattern_part].len + token_len(table[index][method_part]);
    }
    // The octets of the patterns and of the tokens bound the work of the checks and of the trie.
    const routes = table.len;
    return quota_branches_base + quota_branches_per_octet_route * octets * (routes + 1) +
        quota_branches_per_route_pair * routes * routes;
}

/// The octets of `method` when it is text, or 0. The check of a token and the Allow value read
/// each octet of it.
fn token_len(comptime method: anytype) usize {
    return if (routes_pattern.is_text(@TypeOf(method))) method.len else 0;
}

/// The method, the pattern and the place in an Allow value of each route of a table that
/// `refusal_of` passed.
fn Routes(comptime count: usize) type {
    return struct {
        patterns: [count][]const u8,
        tokens: [count][]const u8,
        ranks: [count]usize,
    };
}

pub fn routes_of(comptime table: anytype) Routes(table.len) {
    var routes: Routes(table.len) = undefined;
    inline for (0..table.len) |index| {
        routes.patterns[index] = table[index][pattern_part];
        routes.tokens[index] = routes_method.token_of(table[index][method_part]);
        routes.ranks[index] = routes_method.rank_of(table[index][method_part]);
    }
    return routes;
}

/// The trie as the build first writes it: each node's segment, depth, first child and next
/// sibling, and the node where each route ends.
fn Merged(comptime nodes_max: usize, comptime routes_count: usize) type {
    return struct {
        segment: [nodes_max][]const u8 = undefined,
        depth: [nodes_max]usize = undefined,
        first_child: [nodes_max]?usize = undefined,
        next_sibling: [nodes_max]?usize = undefined,
        node_count: usize = 0,
        route_node: [routes_count]usize = undefined,
    };
}

fn nodes_bound(comptime patterns: []const []const u8) usize {
    var count: usize = 1;
    for (patterns) |pattern| count += routes_pattern.segments_count(pattern);
    return count;
}

pub fn merge(comptime patterns: []const []const u8) Merged(nodes_bound(patterns), patterns.len) {
    var merged: Merged(nodes_bound(patterns), patterns.len) = .{};
    merged.segment[root] = "";
    merged.depth[root] = 0;
    merged.first_child[root] = null;
    merged.next_sibling[root] = null;
    merged.node_count = 1;
    for (patterns, 0..) |pattern, index| merged.route_node[index] = insert(&merged, pattern);
    return merged;
}

fn insert(merged: anytype, comptime pattern: []const u8) usize {
    if (std.mem.eql(u8, pattern, routes_pattern.root)) return root;
    var node: usize = root;
    var segments = std.mem.splitScalar(u8, pattern[1..], routes_pattern.separator);
    for (0..routes_pattern.segments_count(pattern) + 1) |_| {
        const segment = segments.next() orelse return node;
        node = child_of(merged, node, segment) orelse add_child(merged, node, segment);
    }
    unreachable;
}

fn child_of(merged: anytype, node: usize, segment: []const u8) ?usize {
    var child = merged.first_child[node];
    for (0..merged.node_count) |_| {
        const index = child orelse return null;
        if (std.mem.eql(u8, merged.segment[index], segment)) return index;
        child = merged.next_sibling[index];
    }
    unreachable;
}

fn add_child(merged: anytype, node: usize, segment: []const u8) usize {
    const added = merged.node_count;
    assert(added < merged.segment.len);
    merged.segment[added] = segment;
    merged.depth[added] = merged.depth[node] + 1;
    merged.first_child[added] = null;
    merged.next_sibling[added] = merged.first_child[node];
    merged.first_child[node] = added;
    merged.node_count += 1;
    return added;
}
