//! The arrays of a route table that `match` reads at run time (decision 122, design §8 step 21e).
//! `build` writes the trie of `routes_trie.merge` into them, at compile time.
//!
//! Each node holds a run of edges, one for each literal segment after it, sorted by length and
//! then by octets. A node holds one parameter child at most, with the parameter's name, and one
//! wildcard child at most. A node where a pattern ends holds a leaf. A leaf holds a run of entries
//! and its Allow value. The arrays index one array of text, which holds every literal, every
//! parameter name and every Allow value. The value that `build` returns holds no pointer into the
//! memory of the build, so a program can read it at run time.
const std = @import("std");
const assert = std.debug.assert;
const routes_pattern = @import("routes_pattern.zig");
const routes_trie = @import("routes_trie.zig");

/// The separator between the methods of an Allow value: RFC 9110 §10.2.1 makes Allow a list,
/// and RFC 9110 §5.6.1.1 writes a list as `element *( OWS "," OWS element )`.
const allow_separator = ", ";

/// The size of each array of a table's layout.
pub const Sizes = struct {
    nodes: usize,
    parameters: usize,
    wildcards: usize,
    leaves: usize,
    routes: usize,
    text: usize,
    depth_max: usize,
};

fn sizes_of(comptime table: anytype) Sizes {
    @setEvalBranchQuota(routes_trie.quota_of(table));
    const routes = routes_trie.routes_of(table);
    const merged = routes_trie.merge(&routes.patterns);
    var sizes: Sizes = .{ .nodes = merged.node_count, .parameters = 0, .wildcards = 0, .leaves = 0, .routes = table.len, .text = 0, .depth_max = 0 };
    for (1..merged.node_count) |node| {
        const segment = merged.segment[node];
        sizes.depth_max = @max(sizes.depth_max, merged.depth[node]);
        // A wildcard has no text: `match` binds it to the name `routes_pattern.wildcard`.
        if (routes_pattern.is_wildcard(segment)) {
            sizes.wildcards += 1;
            continue;
        }
        // A literal's text is its segment, and a parameter's text is its name.
        if (routes_pattern.is_parameter(segment)) sizes.parameters += 1;
        sizes.text += if (routes_pattern.is_parameter(segment)) routes_pattern.parameter_name(segment).len else segment.len;
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
        edges: [sizes.nodes - 1 - sizes.parameters - sizes.wildcards]Edge,
        leaves: [sizes.leaves]Leaf,
        entries: [sizes.routes]Entry,
        text: [sizes.text]u8,

        /// The most segments of a pattern of the table.
        pub const depth_max = sizes.depth_max;

        /// A run of `text`.
        pub const Range = struct { offset: Index, len: Index };
        /// The node's literal edges, a run of `edges`, its parameter child, its wildcard child,
        /// and its leaf, an index of `leaves`.
        pub const Node = struct { edges_first: Index, edges_count: Index, parameter: ?Parameter, wildcard: ?Index, leaf: ?Index };
        /// A literal segment, and the node after it.
        pub const Edge = struct { segment: Range, child: Index };
        /// A parameter's name, and the node after it.
        pub const Parameter = struct { name: Range, child: Index };
        /// The leaf's entries, a run of `entries`, and its Allow value.
        pub const Leaf = struct { entries_first: Index, entries_count: Index, allow: Range };
        /// A route's method token, a run of its leaf's Allow value, and its value.
        pub const Entry = struct { method: Range, value: Value };
    };
}

/// The layout of a table that `routes_trie.refusal_of` passed. Comptime-only.
pub fn build(comptime Value: type, comptime table: anytype) Layout(Value, sizes_of(table)) {
    @setEvalBranchQuota(routes_trie.quota_of(table));
    assert(routes_trie.refusal_of(table) == null);
    const sizes = sizes_of(table);
    const routes = routes_trie.routes_of(table);
    const merged = routes_trie.merge(&routes.patterns);
    var builder: Builder(Value, sizes) = .{ .values = values_of(Value, table) };
    for (0..merged.node_count) |node| {
        builder.layout.nodes[node] = .{ .edges_first = builder.edges_count, .edges_count = 0, .parameter = null, .wildcard = null, .leaf = null };
        add_edges(&builder, &merged, node);
        add_leaf(&builder, &merged, &routes, node);
    }
    assert(builder.edges_count == sizes.nodes - 1 - sizes.parameters - sizes.wildcards);
    assert(builder.leaves_count == sizes.leaves);
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
    inline for (0..table.len) |index| values[index] = @as(Value, table[index][routes_trie.value_part]);
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
        child = merged.next_sibling[index];
        if (routes_pattern.is_parameter(merged.segment[index])) {
            add_parameter(builder, merged, node, index);
            continue;
        }
        if (routes_pattern.is_wildcard(merged.segment[index])) {
            add_wildcard(builder, merged, node, index);
            continue;
        }
        children[count] = index;
        count += 1;
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

fn add_parameter(builder: anytype, merged: anytype, node: usize, child: usize) void {
    // `names_refusal` passed the table, so the node has one parameter child at most.
    assert(builder.layout.nodes[node].parameter == null);
    const name = routes_pattern.parameter_name(merged.segment[child]);
    const offset = add_text(builder, name);
    builder.layout.nodes[node].parameter = .{ .name = .{ .offset = @intCast(offset), .len = @intCast(name.len) }, .child = @intCast(child) };
}

fn add_wildcard(builder: anytype, merged: anytype, node: usize, child: usize) void {
    // A node has one child for each segment, so it has one wildcard child at most.
    assert(builder.layout.nodes[node].wildcard == null);
    // `routes_pattern.refusal_of` passed each pattern, so the wildcard is the last segment of its
    // patterns and its node has no child.
    assert(merged.first_child[child] == null);
    builder.layout.nodes[node].wildcard = @intCast(child);
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
