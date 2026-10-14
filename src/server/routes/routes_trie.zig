//! The build of a route table at compile time (decision 122, design §8 step 21e): the checks on
//! the whole table, the trie of path segments, and the Allow value of each leaf.
//!
//! A table is a tuple, or an array, of entries. An entry is a tuple of a method, a pattern and a
//! value. `refusal_of` checks a table in this order (invariant 7):
//!   1. The table holds one entry at least, or `table_empty`.
//!   2. Each entry, from the first, is a tuple of three parts whose pattern is text, or
//!      `entry_shape`. Then its method passes `routes_method.refusal_of`, and its pattern passes
//!      `routes_pattern.refusal_of`.
//!   3. No two routes name one method at one leaf, or `route_repeated`.
//!
//! `build` then writes the trie into fixed arrays. Each node holds a run of edges, one for each
//! literal segment after it, sorted by length and then by octets. A node where a pattern ends
//! holds a leaf. A leaf holds a run of entries and its Allow value. The arrays index one array of
//! text, which holds every literal and every Allow value. The value that `build` returns holds no
//! pointer into the memory of the build, so a program can read it at run time.
const std = @import("std");
const assert = std.debug.assert;
const routes_pattern = @import("routes_pattern.zig");
const routes_method = @import("routes_method.zig");

/// The node of the path "/", where each walk starts.
pub const root = 0;

/// The parts of an entry, in order: its method, its pattern and its value.
const method_part = 0;
const pattern_part = 1;
const value_part = 2;
const entry_parts = 3;

/// The separator between the methods of an Allow value: RFC 9110 §10.2.1 makes Allow a list,
/// and RFC 9110 §5.6.1.1 writes a list as `element *( OWS "," OWS element )`.
const allow_separator = ", ";

/// The comptime branches that the checks and the build take, at most: a fixed part, a part for
/// each octet of the patterns times the count of routes, and a part for each pair of routes. The
/// trie's lookups and sorts compare each segment with the segments of the other routes, and the
/// check of repeated routes compares each pair of routes. A table of 256 routes of 64 octets each
/// needs a quarter of this quota (`routes_test.zig`).
const quota_branches_base = 4_096;
const quota_branches_per_octet_route = 8;
const quota_branches_per_route_pair = 16;

/// Why a table does not compile.
pub const Reason = union(enum) {
    pattern: routes_pattern.Refusal,
    method: routes_method.Refusal,
    table_empty,
    entry_shape,
    route_repeated,

    /// The name that the compile error writes, which `zig build routes-check` reads.
    pub fn name(reason: Reason) []const u8 {
        return switch (reason) {
            .pattern => |refusal| @tagName(refusal),
            .method => |refusal| @tagName(refusal),
            else => @tagName(reason),
        };
    }

    /// The sentence that the compile error writes after the name.
    pub fn sentence(reason: Reason) []const u8 {
        return switch (reason) {
            .pattern => |refusal| refusal.reason(),
            .method => |refusal| refusal.reason(),
            .table_empty => "a table holds one route at least",
            .entry_shape => "an entry is a tuple of a method, a pattern and a value",
            .route_repeated => "two routes name one method and one path",
        };
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

fn quota_of(comptime table: anytype) u32 {
    var octets: usize = 0;
    inline for (0..table.len) |index| {
        if (is_entry(@TypeOf(table[index]))) octets += table[index][pattern_part].len;
    }
    // The octets of the patterns bound the work of the checks and of the trie. The check of a
    // method's token reads each octet once, and the fixed part covers it.
    const routes = table.len;
    return quota_branches_base + quota_branches_per_octet_route * octets * (routes + 1) +
        quota_branches_per_route_pair * routes * routes;
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

fn routes_of(comptime table: anytype) Routes(table.len) {
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

fn merge(comptime patterns: []const []const u8) Merged(nodes_bound(patterns), patterns.len) {
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

/// The size of each array of a table's layout.
pub const Sizes = struct {
    nodes: usize,
    leaves: usize,
    routes: usize,
    text: usize,
    depth_max: usize,
};

fn sizes_of(comptime table: anytype) Sizes {
    @setEvalBranchQuota(quota_of(table));
    const routes = routes_of(table);
    const merged = merge(&routes.patterns);
    var sizes: Sizes = .{ .nodes = merged.node_count, .leaves = 0, .routes = table.len, .text = 0, .depth_max = 0 };
    for (1..merged.node_count) |node| {
        sizes.text += merged.segment[node].len;
        sizes.depth_max = @max(sizes.depth_max, merged.depth[node]);
    }
    for (0..merged.node_count) |node| {
        if (std.mem.indexOfScalar(usize, &merged.route_node, node) != null) sizes.leaves += 1;
    }
    // Each Allow value holds the tokens of its leaf's routes, with a separator between two.
    for (routes.tokens) |token| sizes.text += token.len;
    sizes.text += allow_separator.len * (table.len - sizes.leaves);
    return sizes;
}

/// The arrays of one table, sized by `sizes`. Every index is of the smallest type that holds it.
pub fn Layout(comptime Value: type, comptime sizes: Sizes) type {
    const Index = std.math.IntFittingRange(0, @max(sizes.nodes, sizes.routes, sizes.text));
    return struct {
        nodes: [sizes.nodes]Node,
        edges: [sizes.nodes - 1]Edge,
        leaves: [sizes.leaves]Leaf,
        entries: [sizes.routes]Entry,
        text: [sizes.text]u8,

        /// The most segments of a pattern of the table.
        pub const depth_max = sizes.depth_max;

        /// A run of `text`.
        pub const Range = struct { offset: Index, len: Index };
        /// The node's literal edges, a run of `edges`, and its leaf, an index of `leaves`.
        pub const Node = struct { edges_first: Index, edges_count: Index, leaf: ?Index };
        /// A literal segment, and the node after it.
        pub const Edge = struct { segment: Range, child: Index };
        /// The leaf's entries, a run of `entries`, and its Allow value.
        pub const Leaf = struct { entries_first: Index, entries_count: Index, allow: Range };
        /// A route's method token, a run of its leaf's Allow value, and its value.
        pub const Entry = struct { method: Range, value: Value };
    };
}

/// The layout of a table that `refusal_of` passed. Comptime-only.
pub fn build(comptime Value: type, comptime table: anytype) Layout(Value, sizes_of(table)) {
    @setEvalBranchQuota(quota_of(table));
    assert(refusal_of(table) == null);
    const sizes = sizes_of(table);
    const routes = routes_of(table);
    const merged = merge(&routes.patterns);
    var builder: Builder(Value, sizes) = .{ .values = values_of(Value, table) };
    for (0..merged.node_count) |node| {
        builder.layout.nodes[node] = .{ .edges_first = builder.edges_count, .edges_count = 0, .leaf = null };
        add_edges(&builder, &merged, node);
        add_leaf(&builder, &merged, &routes, node);
    }
    assert(builder.edges_count == sizes.nodes - 1 and builder.leaves_count == sizes.leaves);
    assert(builder.entries_count == sizes.routes and builder.text_len == sizes.text);
    return builder.layout;
}

fn Builder(comptime Value: type, comptime sizes: Sizes) type {
    return struct {
        layout: Layout(Value, sizes) = undefined,
        values: [sizes.routes]Value,
        edges_count: usize = 0,
        leaves_count: usize = 0,
        entries_count: usize = 0,
        text_len: usize = 0,
    };
}

fn values_of(comptime Value: type, comptime table: anytype) [table.len]Value {
    var values: [table.len]Value = undefined;
    inline for (0..table.len) |index| values[index] = @as(Value, table[index][value_part]);
    return values;
}

fn add_text(builder: anytype, text: []const u8) usize {
    const offset = builder.text_len;
    @memcpy(builder.layout.text[offset..][0..text.len], text);
    builder.text_len += text.len;
    return offset;
}

fn add_edges(builder: anytype, merged: anytype, node: usize) void {
    var children: [merged.segment.len]usize = undefined;
    var count: usize = 0;
    var child = merged.first_child[node];
    for (0..merged.node_count) |_| {
        const index = child orelse break;
        children[count] = index;
        count += 1;
        child = merged.next_sibling[index];
    }
    sort(children[0..count], merged, segment_less);
    for (children[0..count]) |index| {
        const segment = merged.segment[index];
        const offset = add_text(builder, segment);
        builder.layout.edges[builder.edges_count] = .{ .segment = .{ .offset = @intCast(offset), .len = @intCast(segment.len) }, .child = @intCast(index) };
        builder.edges_count += 1;
    }
    builder.layout.nodes[node].edges_count = @intCast(count);
}

/// Orders two nodes by their segments: the shorter first, then by octets. A lookup then compares
/// lengths first. The order reads octets, never a pointer (non-negotiable 5).
fn segment_less(merged: anytype, left: usize, right: usize) bool {
    const left_segment = merged.segment[left];
    const right_segment = merged.segment[right];
    if (left_segment.len != right_segment.len) return left_segment.len < right_segment.len;
    return std.mem.lessThan(u8, left_segment, right_segment);
}

fn add_leaf(builder: anytype, merged: anytype, routes: anytype, node: usize) void {
    var held: [merged.route_node.len]usize = undefined;
    var count: usize = 0;
    for (merged.route_node, 0..) |route_node, route| {
        if (route_node != node) continue;
        held[count] = route;
        count += 1;
    }
    if (count == 0) return;
    // RFC 9110 §10.2.1: Allow lists the methods of the target. The standard methods come in RFC
    // 9110 §9.1's order and the tokens after them by octets, so the table's order changes nothing.
    sort(held[0..count], routes, method_less);
    const allow_first = builder.text_len;
    const entries_first = builder.entries_count;
    for (held[0..count], 0..) |route, position| {
        if (position > 0) _ = add_text(builder, allow_separator);
        const token = routes.tokens[route];
        const offset = add_text(builder, token);
        builder.layout.entries[builder.entries_count] = .{ .method = .{ .offset = @intCast(offset), .len = @intCast(token.len) }, .value = builder.values[route] };
        builder.entries_count += 1;
    }
    builder.layout.nodes[node].leaf = @intCast(builder.leaves_count);
    builder.layout.leaves[builder.leaves_count] = .{
        .entries_first = @intCast(entries_first),
        .entries_count = @intCast(count),
        .allow = .{ .offset = @intCast(allow_first), .len = @intCast(builder.text_len - allow_first) },
    };
    builder.leaves_count += 1;
}

/// Sorts `items` by `less` in place, by insertion. Comptime-only, so the order reads no pointer.
fn sort(items: []usize, context: anytype, comptime less: anytype) void {
    if (items.len <= 1) return;
    for (1..items.len) |sorted| {
        var at = sorted;
        for (0..sorted) |_| {
            if (!less(context, items[at], items[at - 1])) break;
            std.mem.swap(usize, &items[at], &items[at - 1]);
            at -= 1;
            if (at == 0) break;
        }
    }
}

fn method_less(routes: anytype, left: usize, right: usize) bool {
    if (routes.ranks[left] != routes.ranks[right]) return routes.ranks[left] < routes.ranks[right];
    return std.mem.lessThan(u8, routes.tokens[left], routes.tokens[right]);
}
