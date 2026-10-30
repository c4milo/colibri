//! The checks on a whole route table at compile time, and the trie of its path segments
//! (decision 122, design §8 step 21e). `router_trie_layout.zig` writes the trie into the arrays
//! that `match` reads.
//!
//! A table is a tuple, or an array, of entries. An entry is a tuple of a method, a pattern and a
//! value. `refusal_of` checks a table in this order (invariant 7):
//!   1. The table holds one entry at least, or `table_empty`.
//!   2. Each entry, from the first, is a tuple of three parts whose pattern is text, or
//!      `entry_shape`. Then its method passes `router_method.refusal_of`, and its pattern passes
//!      `router_pattern.refusal_of`.
//!   3. No two routes name one method at one leaf, or `route_repeated`. Two routes may name one
//!      parameter position differently (decision 129), so a pattern's names do not decide a leaf.
//!
//! `router.zig` then builds the layout and checks it in this order: each Allow value fits
//! `core.constants.limits.field_value_len_max`, or `allow_too_long` (`router_trie_layout.zig`), and no
//! route is unreachable, or `route_unreachable` (`router_hidden.zig`). A table names
//! `route_methods_max` methods at most, or `methods_too_many` (decision 128).
//!
//! `merge` writes the trie of a table's patterns. It gives each segment of a pattern a node, and
//! two patterns with the same first segments share their nodes.
//!
//! The compile time of a large table depends on the calls in its loops. With Zig 0.16, a comptime
//! call that gets a large constant, or a pointer to one, takes time in proportion to the size of
//! that constant. A call that gets a pointer to a comptime var takes a few steps. So the checks
//! and the build copy the trie, the routes and the layout into vars once, and their loops pass
//! pointers to the copies. Zig also does not keep the result of a comptime call, so
//! `server.router` merges the trie once and passes it to each check and to the build.
const std = @import("std");
const assert = std.debug.assert;
const router_pattern = @import("router_pattern.zig");
const router_method = @import("router_method.zig");

/// The node of the path "/", where each walk starts.
pub const root = 0;

/// The parts of an entry, in order: its method, its pattern and its value.
const method_part = 0;
const pattern_part = 1;
pub const value_part = 2;
const entry_parts = 3;

/// The comptime branches that the checks and the build use, at most: a fixed part, a part for
/// each octet of the patterns and of the method tokens times the count of routes, and a part for
/// each pair of routes. The lookups of the trie, its sorts and the check of repeated routes use
/// much less than the part for each pair. A test builds a table of 256 routes of 64 octets each
/// within this quota (`router_test.zig`).
const quota_branches_base = 4_096;
const quota_branches_per_octet_route = 8;
const quota_branches_per_route_pair = 16;

/// The comptime branches of the loop of `quota_of` for each route, at most. The loop makes four
/// calls for each route, and each call takes a few branches.
const quota_branches_per_route = 16;

/// The comptime branches that the check of hidden routes (`router_hidden.zig`) uses, at most,
/// beside `quota_of`. It has two parts:
///   - For each leaf it walks the trie, which holds `segments` nodes for each leaf at most, and it
///     writes a canonical path for each leaf that it finds at each length. So a part for each
///     pair of leaves, each length and each segment bounds it.
///   - It walks each canonical path once. A walk makes `router_match.walk_steps_max` passes at
///     most, and each pass costs a fixed part. Each pass also reads the segment of its frame to
///     find the end of the segment. The search of a literal edge then compares the segment with
///     `router_match.search_passes_max` edges at most. So each pass reads the longest segment
///     once for each comparison and once more. The walk also reads each octet of its path once
///     before its first pass. `octets` counts these reads for one walk.
const quota_branches_per_pair_length_segment = 32;
const quota_branches_per_walk_step = 32;
const quota_branches_per_walk_octet = 16;

/// The quota of the check of hidden routes: `quota_of(table)`, the part for `pairs` pairs of
/// leaves at `lengths` lengths of `segments` segments, and the part for `walks` walks of
/// `walk_steps` passes each that read `octets` octets each. The value is the largest `u32` at
/// most, which `@setEvalBranchQuota` takes.
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
    pattern: router_pattern.Refusal,
    method: router_method.Refusal,
    table_empty,
    entry_shape,
    route_repeated,
    allow_too_long,
    methods_too_many,
    route_unreachable: Unreachable,

    /// The name that the compile error writes, which `zig build router-check` reads.
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
            .route_repeated => "two routes name one method and one path",
            .allow_too_long => "the Allow value of the routes of one pattern holds " ++
                "core.constants.limits.field_value_len_max octets at most, because a 405 sends it as a field value",
            .methods_too_many => "the routes of a table name server.constants.limits.route_methods_max methods at most (decision 128)",
            .route_unreachable => |never| never.sentence(),
        };
    }
};

/// Why no request reaches a route (decision 122 ruling 12).
pub const Unreachable = struct {
    /// The patterns of the leaves that the walk stops at on the paths of the route, each in
    /// quotes and joined by ", ", or "" when there is none.
    patterns: []const u8,
    /// Whether a path of the route is longer than `server.constants.limits.path_len_max`.
    too_long: bool,

    fn sentence(comptime never: Unreachable) []const u8 {
        const prefix = "no request reaches this route, because ";
        const long = "server.constants.limits.path_len_max";
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
    if (refusal.reason == .table_empty) return std.fmt.comptimePrint("server.router: {s}: {s}", .{ name, sentence });
    return std.fmt.comptimePrint("server.router: route {d}, \"{s}\": {s}: {s}", .{ refusal.route, refusal.pattern, name, sentence });
}

/// The first refusal of `table`, or null when the table compiles: `entries_refusal`, then
/// `trie_refusal` on the trie of `trie_of`. Comptime-only.
pub fn refusal_of(comptime table: anytype) ?Refusal {
    if (entries_refusal(table)) |refusal| return refusal;
    const trie = trie_of(table);
    return trie_refusal(table, &trie);
}

/// The first refusal of checks 1 and 2, or null. Comptime-only.
pub fn entries_refusal(comptime table: anytype) ?Refusal {
    @setEvalBranchQuota(quota_of(table));
    // Decision 122: a table with no route matches nothing.
    if (table.len == 0) return .{ .route = 0, .pattern = "", .reason = .table_empty };
    inline for (0..table.len) |index| {
        if (entry_refusal(table[index])) |reason| {
            return .{ .route = index, .pattern = pattern_or_empty(table[index]), .reason = reason };
        }
    }
    return null;
}

/// The first refusal of check 3, or null. `trie` is a pointer to the value of
/// `trie_of(table)`, and `entries_refusal` passed `table`. Comptime-only.
pub fn trie_refusal(comptime table: anytype, trie: anytype) ?Refusal {
    @setEvalBranchQuota(quota_of(table));
    // The calls in the loop get pointers to copies in vars (see the top of this file).
    var routes = routes_of(table);
    var trie_copy = trie.*;
    return repeated_refusal(&routes, &trie_copy);
}

fn entry_refusal(comptime entry: anytype) ?Reason {
    // Decision 122: an entry is a tuple of a method, a pattern and a value.
    if (!is_entry(@TypeOf(entry))) return .entry_shape;
    if (router_method.refusal_of(entry[method_part])) |refusal| return .{ .method = refusal };
    if (router_pattern.refusal_of(entry[pattern_part])) |refusal| return .{ .pattern = refusal };
    return null;
}

fn is_entry(comptime Entry: type) bool {
    const info = @typeInfo(Entry);
    if (info != .@"struct" or !info.@"struct".is_tuple) return false;
    if (info.@"struct".fields.len != entry_parts) return false;
    return router_pattern.is_text(info.@"struct".fields[pattern_part].type);
}

fn pattern_or_empty(comptime entry: anytype) []const u8 {
    if (!is_entry(@TypeOf(entry))) return "";
    return entry[pattern_part];
}

fn repeated_refusal(routes: anytype, trie: anytype) ?Refusal {
    for (0..trie.route_node.len) |later| {
        // The routes of a node come in table order, so the routes before `later` come first.
        for (routes_at(trie, trie.route_node[later])) |earlier| {
            if (earlier >= later) break;
            // Decision 122: two routes that match one request do not compile
            // (https://github.com/c4milo/colibri/issues/96).
            if (std.mem.eql(u8, routes.tokens[earlier], routes.tokens[later])) {
                return .{ .route = later, .pattern = routes.patterns[later], .reason = .route_repeated };
            }
        }
    }
    return null;
}

pub fn quota_of(comptime table: anytype) u32 {
    @setEvalBranchQuota(quota_branches_base + quota_branches_per_route * table.len);
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
    return if (router_pattern.is_text(@TypeOf(method))) method.len else 0;
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
        routes.tokens[index] = router_method.token_of(table[index][method_part]);
        routes.ranks[index] = router_method.rank_of(table[index][method_part]);
    }
    return routes;
}

/// The trie as the build first writes it: each node's segment, parent, depth, first child, next
/// sibling and parameter child, and the node where each route ends. Two indexes give the build
/// each lookup in a few steps:
///   - `slots` finds the child of a node by its segment. A slot holds a node, or null.
///   - `route_order` holds the routes of each node, each node's run in table order. The run of
///     node n starts at `route_first[n]` and ends at `route_first[n + 1]`.
fn Merged(comptime nodes_max: usize, comptime routes_count: usize) type {
    return struct {
        segment: [nodes_max][]const u8 = undefined,
        parent: [nodes_max]usize = undefined,
        depth: [nodes_max]usize = undefined,
        first_child: [nodes_max]?usize = undefined,
        next_sibling: [nodes_max]?usize = undefined,
        parameter_child: [nodes_max]?usize = undefined,
        node_count: usize = 0,
        slots: [nodes_max * slots_per_node]?usize = @splat(null),
        route_node: [routes_count]usize = undefined,
        route_first: [nodes_max + 1]usize = @splat(0),
        route_order: [routes_count]usize = undefined,
    };
}

/// The slots of the index of children for each node. Half the slots or more stay empty, so a
/// lookup reads a few slots on average.
const slots_per_node = 2;

fn nodes_bound(comptime patterns: []const []const u8) usize {
    var count: usize = 1;
    for (patterns) |pattern| count += router_pattern.segments_count(pattern);
    return count;
}

/// The trie of the patterns of `table`, which `entries_refusal` passed. Comptime-only.
pub fn trie_of(comptime table: anytype) Merged(nodes_bound(&routes_of(table).patterns), table.len) {
    @setEvalBranchQuota(quota_of(table));
    const routes = routes_of(table);
    return merge(&routes.patterns);
}

/// The routes of `node`, in table order. `trie` is a pointer to the value of `trie_of`.
pub fn routes_at(trie: anytype, node: usize) []const usize {
    return trie.route_order[trie.route_first[node]..trie.route_first[node + 1]];
}

fn merge(comptime patterns: []const []const u8) Merged(nodes_bound(patterns), patterns.len) {
    var merged: Merged(nodes_bound(patterns), patterns.len) = .{};
    merged.segment[root] = "";
    merged.parent[root] = root;
    merged.depth[root] = 0;
    merged.first_child[root] = null;
    merged.next_sibling[root] = null;
    merged.parameter_child[root] = null;
    merged.node_count = 1;
    for (patterns, 0..) |pattern, index| merged.route_node[index] = insert(&merged, pattern);
    index_routes(&merged);
    return merged;
}

fn insert(merged: anytype, comptime pattern: []const u8) usize {
    if (std.mem.eql(u8, pattern, router_pattern.root)) return root;
    var node: usize = root;
    var segments = std.mem.splitScalar(u8, pattern[1..], router_pattern.separator);
    for (0..router_pattern.segments_count(pattern) + 1) |_| {
        const written = segments.next() orelse return node;
        // Decision 129: one parameter child at a node, whatever each route names it.
        const segment = if (router_pattern.is_parameter(written)) router_pattern.parameter_key else written;
        const slot = slot_of(merged, node, segment);
        node = merged.slots[slot] orelse add_child(merged, node, segment, slot);
    }
    unreachable;
}

/// The slot that holds the child of `node` with `segment`, or the empty slot where
/// `add_child` writes that child. The search starts at a hash of the segment's octets and of
/// `node`, and never reads a pointer (non-negotiable 5).
fn slot_of(merged: anytype, node: usize, segment: []const u8) usize {
    const start: usize = @intCast((std.hash.Fnv1a_64.hash(segment) ^ node) % merged.slots.len);
    // Bounded: the trie holds fewer nodes than slots, so the search finds an empty slot.
    for (0..merged.slots.len) |probe| {
        const slot = (start + probe) % merged.slots.len;
        const child = merged.slots[slot] orelse return slot;
        if (merged.parent[child] == node and std.mem.eql(u8, merged.segment[child], segment)) return slot;
    }
    unreachable;
}

fn add_child(merged: anytype, node: usize, segment: []const u8, slot: usize) usize {
    const added = merged.node_count;
    assert(added < merged.segment.len);
    assert(merged.slots[slot] == null);
    merged.segment[added] = segment;
    merged.parent[added] = node;
    merged.depth[added] = merged.depth[node] + 1;
    merged.first_child[added] = null;
    merged.next_sibling[added] = merged.first_child[node];
    merged.parameter_child[added] = null;
    merged.first_child[node] = added;
    merged.slots[slot] = added;
    merged.node_count += 1;
    if (router_pattern.is_parameter(segment)) {
        // Decision 129: the key of every parameter child is one segment, so a node has one.
        assert(merged.parameter_child[node] == null);
        merged.parameter_child[node] = added;
    }
    return added;
}

/// Writes `route_first` and `route_order` from `route_node`: a sort of the routes by node that
/// counts the routes of each node. It keeps the table order within each node.
fn index_routes(merged: anytype) void {
    for (merged.route_node) |node| merged.route_first[node + 1] += 1;
    for (1..merged.route_first.len) |node| merged.route_first[node] += merged.route_first[node - 1];
    var next: [merged.route_first.len]usize = merged.route_first;
    for (merged.route_node, 0..) |node, route| {
        merged.route_order[next[node]] = route;
        next[node] += 1;
    }
    assert(merged.route_first[merged.route_first.len - 1] == merged.route_node.len);
}
