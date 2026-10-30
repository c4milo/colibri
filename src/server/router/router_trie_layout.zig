//! The arrays of a route table that `match` reads at run time (decision 122, design §8 step 21e).
//! `build` writes the trie of `router_trie.trie_of` into them, at compile time.
//!
//! Each node holds a run of edges, one for each literal segment after it, sorted by length and
//! then by octets. A node holds one parameter child at most, with the parameter's name, and one
//! wildcard child at most. A node where a pattern ends holds a leaf. A leaf holds a run of entries
//! and its Allow value. The table's set of methods holds each method token of the table once. The
//! arrays index one array of text, which holds every literal, every parameter name and every Allow
//! value. The value that `build` returns holds no pointer into the
//! memory of the build, so a program can read it at run time.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const router_method = @import("router_method.zig");
const router_pattern = @import("router_pattern.zig");
const router_trie = @import("router_trie.zig");

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
    methods: usize,
    text: usize,
    depth_max: usize,
    /// The parameter names of every route's pattern, the wildcard's "*" included.
    names: usize,
};

pub fn sizes_of(comptime table: anytype, comptime trie: anytype) Sizes {
    @setEvalBranchQuota(router_trie.quota_of(table));
    // The calls in the loops get pointers to copies in vars (`router_trie.zig`).
    var routes = router_trie.routes_of(table);
    var trie_copy = trie.*;
    var sizes: Sizes = .{
        .nodes = trie_copy.node_count,
        .parameters = 0,
        .wildcards = 0,
        .leaves = 0,
        .routes = table.len,
        .methods = methods_count(&routes.tokens),
        .text = 0,
        .depth_max = 0,
        .names = 0,
    };
    // Decision 129: each route keeps the names of its own pattern, in the text.
    for (routes.patterns) |pattern| count_names(pattern, &sizes);
    for (1..trie_copy.node_count) |node| {
        const segment = trie_copy.segment[node];
        sizes.depth_max = @max(sizes.depth_max, trie_copy.depth[node]);
        // A wildcard has no text: `match` binds it to the name `router_pattern.wildcard`.
        if (router_pattern.is_wildcard(segment)) {
            sizes.wildcards += 1;
            continue;
        }
        // A literal's text is its segment, and a parameter's text is its name.
        if (router_pattern.is_parameter(segment)) sizes.parameters += 1;
        sizes.text += if (router_pattern.is_parameter(segment)) router_pattern.parameter_name(segment).len else segment.len;
    }
    for (0..trie_copy.node_count) |node| {
        if (router_trie.routes_at(&trie_copy, node).len == 0) continue;
        sizes.leaves += 1;
        if (head_added(&routes, &trie_copy, node)) sizes.text += allow_separator.len + router_method.head_token.len;
    }
    // Each Allow value holds the tokens of its leaf's routes, with a separator between two.
    for (routes.tokens) |token| sizes.text += token.len;
    sizes.text += allow_separator.len * (table.len - sizes.leaves);
    return sizes;
}

/// Counts the parameter names of `pattern`, the wildcard's included, and their octets.
fn count_names(pattern: []const u8, sizes: *Sizes) void {
    var segments = std.mem.splitScalar(u8, pattern[1..], router_pattern.separator);
    while (segments.next()) |segment| {
        const name = router_pattern.binding_name(segment) orelse continue;
        sizes.names += 1;
        sizes.text += name.len;
    }
}

/// The count of distinct tokens in `tokens`. Comptime-only.
fn methods_count(comptime tokens: []const []const u8) usize {
    var count: usize = 0;
    for (tokens, 0..) |token, index| {
        if (!holds_token(tokens[0..index], token)) count += 1;
    }
    return count;
}

fn holds_token(tokens: []const []const u8, token: []const u8) bool {
    for (tokens) |held| {
        if (std.mem.eql(u8, held, token)) return true;
    }
    return false;
}

/// The arrays of one table, sized by `sizes`. Every index is of the smallest type that holds it.
pub fn Layout(comptime Value: type, comptime sizes: Sizes) type {
    const Index = std.math.IntFittingRange(0, @max(sizes.nodes, sizes.routes, sizes.text, sizes.names));
    return struct {
        nodes: [sizes.nodes]Node,
        edges: [sizes.nodes - 1 - sizes.parameters - sizes.wildcards]Edge,
        leaves: [sizes.leaves]Leaf,
        entries: [sizes.routes]Entry,
        /// The table's set of methods: one run of `text` for each distinct method token.
        methods: [sizes.methods]Range,
        /// Each route's parameter names, a run for each entry (decision 129).
        names: [sizes.names]Range,
        text: [sizes.text]u8,

        /// The most segments of a pattern of the table.
        pub const depth_max = sizes.depth_max;

        /// A run of `text`.
        pub const Range = struct { offset: Index, len: Index };
        /// The node's literal edges, a run of `edges`, its parameter child, its wildcard child,
        /// and its leaf, an index of `leaves`.
        pub const Node = struct { edges_first: Index, edges_count: Index, parameter: ?Parameter, wildcard: ?Index, leaf: ?Index };
        /// A literal segment, and the node after it.
        /// A literal edge: its segment, its first octets as `head_of` gives them, and its child.
        pub const Edge = struct { segment: Range, head: u64, child: Index };
        /// A parameter's name, and the node after it.
        pub const Parameter = struct { name: Range, child: Index };
        /// The leaf's entries, a run of `entries`, and its Allow value.
        pub const Leaf = struct { entries_first: Index, entries_count: Index, allow: Range };
        /// A route's method token, a run of its leaf's Allow value, its value, and the run of
        /// `names` that holds its pattern's parameter names in order (decision 129).
        pub const Entry = struct { method: Range, value: Value, names_first: Index, names_count: Index };
    };
}

/// The layout of a table that `router_trie.refusal_of` passed. `trie` is a pointer to the value
/// of `router_trie.trie_of(table)`. Comptime-only.
pub fn build(comptime Value: type, comptime table: anytype, comptime trie: anytype) Layout(Value, sizes_of(table, trie)) {
    @setEvalBranchQuota(router_trie.quota_of(table));
    assert(router_trie.entries_refusal(table) == null and router_trie.trie_refusal(table, trie) == null);
    const sizes = sizes_of(table, trie);
    // The calls in the loop get pointers to copies in vars (`router_trie.zig`).
    var routes = router_trie.routes_of(table);
    var trie_copy = trie.*;
    var builder: Builder(Value, sizes) = .{ .values = values_of(Value, table) };
    for (0..trie_copy.node_count) |node| {
        builder.layout.nodes[node] = .{ .edges_first = builder.edges_count, .edges_count = 0, .parameter = null, .wildcard = null, .leaf = null };
        add_edges(&builder, &trie_copy, node);
        add_leaf(&builder, &trie_copy, &routes, node);
    }
    add_methods(&builder);
    assert(builder.edges_count == sizes.nodes - 1 - sizes.parameters - sizes.wildcards);
    assert(builder.leaves_count == sizes.leaves);
    assert(builder.entries_count == sizes.routes and builder.text_len == sizes.text);
    assert(builder.methods_count == sizes.methods);
    assert(builder.names_count == sizes.names);
    return builder.layout;
}

/// The first route, in table order, whose leaf has an Allow value longer than
/// `core.constants.limits.field_value_len_max`, or null. `layout` is the layout of `table`, and
/// `trie` is a pointer to the value of `router_trie.trie_of(table)`. Comptime-only.
pub fn allow_refusal(comptime layout: anytype, comptime table: anytype, comptime trie: anytype) ?router_trie.Refusal {
    @setEvalBranchQuota(router_trie.quota_of(table));
    for (layout.leaves) |leaf| {
        if (allow_too_long(leaf.allow.len)) break;
    } else return null;
    const routes = router_trie.routes_of(table);
    for (trie.route_node, 0..) |node, route| {
        const leaf = layout.nodes[node].leaf.?;
        if (allow_too_long(layout.leaves[leaf].allow.len)) {
            return .{ .route = route, .pattern = routes.patterns[route], .reason = .allow_too_long };
        }
    }
    unreachable;
}

/// Whether an Allow value of `allow_len` octets is too long. Both loops of `allow_refusal` call
/// it, so the two loops compare with one rule.
fn allow_too_long(allow_len: usize) bool {
    // RFC 9110 §10.2.1: a 405 carries the Allow value as a field value, which the endpoint
    // bounds at `core.constants.limits.field_value_len_max` (decision 122).
    return allow_len > core.constants.limits.field_value_len_max;
}

fn Builder(comptime Value: type, comptime sizes: Sizes) type {
    return struct {
        layout: Layout(Value, sizes) = undefined,
        values: [sizes.routes]Value,
        edges_count: usize = 0,
        leaves_count: usize = 0,
        entries_count: usize = 0,
        methods_count: usize = 0,
        names_count: usize = 0,
        text_len: usize = 0,
    };
}

fn values_of(comptime Value: type, comptime table: anytype) [table.len]Value {
    var values: [table.len]Value = undefined;
    inline for (0..table.len) |index| values[index] = @as(Value, table[index][router_trie.value_part]);
    return values;
}

fn add_text(builder: anytype, text: []const u8) usize {
    const offset = builder.text_len;
    @memcpy(builder.layout.text[offset..][0..text.len], text);
    builder.text_len += text.len;
    return offset;
}

fn add_edges(builder: anytype, trie: anytype, node: usize) void {
    var children: [trie.segment.len]usize = undefined;
    var count: usize = 0;
    var child = trie.first_child[node];
    for (0..trie.node_count) |_| {
        const index = child orelse break;
        child = trie.next_sibling[index];
        if (router_pattern.is_parameter(trie.segment[index])) {
            add_parameter(builder, trie, node, index);
            continue;
        }
        if (router_pattern.is_wildcard(trie.segment[index])) {
            add_wildcard(builder, trie, node, index);
            continue;
        }
        children[count] = index;
        count += 1;
    }
    sort(children[0..count], trie, segment_less);
    for (children[0..count]) |index| {
        const segment = trie.segment[index];
        const offset = add_text(builder, segment);
        builder.layout.edges[builder.edges_count] = .{
            .segment = .{ .offset = @intCast(offset), .len = @intCast(segment.len) },
            .head = head_of(segment),
            .child = @intCast(index),
        };
        builder.edges_count += 1;
    }
    builder.layout.nodes[node].edges_count = @intCast(count);
}

fn add_parameter(builder: anytype, trie: anytype, node: usize, child: usize) void {
    // `router_trie.trie_refusal` passed the table, so the node has one parameter child at most.
    assert(builder.layout.nodes[node].parameter == null);
    const name = router_pattern.parameter_name(trie.segment[child]);
    const offset = add_text(builder, name);
    builder.layout.nodes[node].parameter = .{ .name = .{ .offset = @intCast(offset), .len = @intCast(name.len) }, .child = @intCast(child) };
}

fn add_wildcard(builder: anytype, trie: anytype, node: usize, child: usize) void {
    // A node has one child for each segment, so it has one wildcard child at most.
    assert(builder.layout.nodes[node].wildcard == null);
    // `router_pattern.refusal_of` passed each pattern, so the wildcard is the last segment of its
    // patterns and its node has no child.
    assert(trie.first_child[child] == null);
    builder.layout.nodes[node].wildcard = @intCast(child);
}

/// Orders two nodes by their segments: the shorter first, then by octets. A lookup then compares
/// lengths first. The order reads octets, never a pointer (non-negotiable 5).
/// The octets of a segment that `head_of` reads.
pub const head_len = @sizeOf(u64);

/// The first `head_len` octets of `segment` as one integer, the first octet highest, and 0 for
/// each octet past its end. Two segments of one length order as their heads order, and then as
/// their octets past `head_len` order (`segment_less`), so `router_match.literal_child` compares
/// one integer where it compared octets.
pub fn head_of(segment: []const u8) u64 {
    if (segment.len >= head_len) return std.mem.readInt(u64, segment[0..head_len], .big);
    if (segment.len == 0) return 0;
    var head: u64 = 0;
    for (segment) |octet| head = (head << @bitSizeOf(u8)) | octet;
    // The octets past the end are 0, below the last one.
    return head << @intCast((head_len - segment.len) * @bitSizeOf(u8));
}

/// The order of the edges of a node, which `router_match.literal_child` searches in: the shorter
/// first, then the lower `head_of`, then by the octets past `head_len`. The search compares in
/// this one order, so the two agree whatever `head_of` maps a segment to.
fn segment_less(trie: anytype, left: usize, right: usize) bool {
    const left_segment = trie.segment[left];
    const right_segment = trie.segment[right];
    if (left_segment.len != right_segment.len) return left_segment.len < right_segment.len;
    const left_head = head_of(left_segment);
    const right_head = head_of(right_segment);
    if (left_head != right_head) return left_head < right_head;
    if (left_segment.len <= head_len) return false;
    return std.mem.lessThan(u8, left_segment[head_len..], right_segment[head_len..]);
}

/// Whether the leaf at `node` names GET and no HEAD. A HEAD request then finds the GET route
/// (RFC 9110 §9.1, §9.3.2), so the leaf's Allow value lists HEAD after GET.
fn head_added(routes: anytype, trie: anytype, node: usize) bool {
    var get = false;
    var head = false;
    for (router_trie.routes_at(trie, node)) |route| {
        if (routes.ranks[route] == router_method.rank_of(.get)) get = true;
        if (routes.ranks[route] == router_method.rank_of(.head)) head = true;
    }
    return get and !head;
}

fn add_leaf(builder: anytype, trie: anytype, routes: anytype, node: usize) void {
    const of_node = router_trie.routes_at(trie, node);
    const count = of_node.len;
    if (count == 0) return;
    var held: [trie.route_node.len]usize = undefined;
    @memcpy(held[0..count], of_node);
    // RFC 9110 §10.2.1: Allow lists the methods of the target. The standard methods come in RFC
    // 9110 §9.1's order and the tokens after them by octets, so the table's order changes nothing.
    sort(held[0..count], routes, method_less);
    // RFC 9110 §9.1's order puts GET first, so HEAD follows the first token.
    const head = head_added(routes, trie, node);
    assert(!head or routes.ranks[held[0]] == router_method.rank_of(.get));
    const allow_first = builder.text_len;
    const entries_first = builder.entries_count;
    for (held[0..count], 0..) |route, position| {
        if (position > 0) _ = add_text(builder, allow_separator);
        const token = routes.tokens[route];
        const offset = add_text(builder, token);
        const names_first = builder.names_count;
        add_names(builder, routes.patterns[route]);
        builder.layout.entries[builder.entries_count] = .{
            .method = .{ .offset = @intCast(offset), .len = @intCast(token.len) },
            .value = builder.values[route],
            .names_first = @intCast(names_first),
            .names_count = @intCast(builder.names_count - names_first),
        };
        builder.entries_count += 1;
        if (head and position == 0) _ = add_text(builder, allow_separator ++ router_method.head_token);
    }
    builder.layout.nodes[node].leaf = @intCast(builder.leaves_count);
    builder.layout.leaves[builder.leaves_count] = .{
        .entries_first = @intCast(entries_first),
        .entries_count = @intCast(count),
        .allow = .{ .offset = @intCast(allow_first), .len = @intCast(builder.text_len - allow_first) },
    };
    builder.leaves_count += 1;
}

/// Writes the names of `pattern`'s parameters, and "*" for its wildcard, in order (decision 129).
fn add_names(builder: anytype, pattern: []const u8) void {
    var segments = std.mem.splitScalar(u8, pattern[1..], router_pattern.separator);
    while (segments.next()) |segment| {
        const name = router_pattern.binding_name(segment) orelse continue;
        const offset = add_text(builder, name);
        builder.layout.names[builder.names_count] = .{ .offset = @intCast(offset), .len = @intCast(name.len) };
        builder.names_count += 1;
    }
}

/// Writes the table's set of methods: the method token of the first entry for each distinct
/// token. `match` reads it before the path (RFC 9110 §9.1, §15.6.2).
fn add_methods(builder: anytype) void {
    const layout = &builder.layout;
    for (layout.entries) |entry| {
        const token = layout.text[entry.method.offset..][0..entry.method.len];
        if (method_held(layout, builder.methods_count, token)) continue;
        layout.methods[builder.methods_count] = entry.method;
        builder.methods_count += 1;
    }
}

fn method_held(layout: anytype, count: usize, token: []const u8) bool {
    for (layout.methods[0..count]) |method| {
        if (std.mem.eql(u8, layout.text[method.offset..][0..method.len], token)) return true;
    }
    return false;
}

/// Sorts `items` by `less` in place: a merge sort that merges runs of 1, 2, 4 and more items,
/// so it makes about log2 of the count passes. It keeps the order of two items that `less` does
/// not order. Comptime-only, so the order reads no pointer.
fn sort(items: []usize, context: anytype, comptime less: anytype) void {
    var sorted: [items.len]usize = undefined;
    var width: usize = 1;
    // Bounded: each pass doubles `width`, so a count of `usize` needs fewer passes than its bits.
    for (0..@bitSizeOf(usize)) |_| {
        if (width >= items.len) return;
        // Bounded: each step merges the run at `start` with the next run, and moves `start` past
        // both runs.
        var start: usize = 0;
        for (0..items.len) |_| {
            if (start >= items.len) break;
            const end = @min(start + width + width, items.len);
            merge_runs(items[start..end], @min(width, end - start), sorted[start..end], context, less);
            start = end;
        }
        @memcpy(items, &sorted);
        width += width;
    }
    unreachable;
}

/// Writes the two sorted runs of `runs`, which meet at `split`, into `sorted` in order.
fn merge_runs(runs: []const usize, split: usize, sorted: []usize, context: anytype, comptime less: anytype) void {
    var left: usize = 0;
    var right = split;
    for (sorted) |*item| {
        // An item of the right run goes first only when `less` orders it first, so the sort
        // keeps the order of two equal items.
        if (left == split or (right < runs.len and less(context, runs[right], runs[left]))) {
            item.* = runs[right];
            right += 1;
        } else {
            item.* = runs[left];
            left += 1;
        }
    }
}

fn method_less(routes: anytype, left: usize, right: usize) bool {
    if (routes.ranks[left] != routes.ranks[right]) return routes.ranks[left] < routes.ranks[right];
    return std.mem.lessThan(u8, routes.tokens[left], routes.tokens[right]);
}
