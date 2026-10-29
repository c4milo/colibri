//! The shapes of the leaves of a table, and the canonical paths of each leaf, for the check of
//! hidden routes (`router_hidden.zig`, decision 122 ruling 12, design §8 step 21e).
//! Comptime-only.
//!
//! The canonical paths of a leaf T are x(T, L, n), for T and for each leaf L before T, at each n
//! that both match (claims 3, 5 and 6 of `router_hidden.zig`). A walk of the trie finds each leaf
//! L that matches a path of T, so the check compares no pair of leaves that match no common path.
//! The walk starts at the root, and at the position of each segment it follows:
//!   - the literal edge that equals T's literal, where T holds a literal;
//!   - each literal edge, where T holds a parameter or the wildcard;
//!   - the parameter child.
//! At each node that it reads, it adds the node's leaf and the leaf of its wildcard child to its
//! list. A path that L and T both match holds T's literal where T holds one, so the walk reads
//! each node on the paths of each such L. It may list a leaf that matches no path of T, which
//! costs walks and changes no verdict. Each node has one parent, so the walk reads each node
//! once at most.
const std = @import("std");
const assert = std.debug.assert;
const router_match = @import("router_match.zig");
const router_pattern = @import("router_pattern.zig");
const router_trie = @import("router_trie.zig");

/// A leaf as the walk reads it: its node, its pattern, the literal of each segment before the
/// wildcard, or null for a parameter, and whether the pattern ends in the wildcard.
pub const Shape = struct {
    node: usize,
    pattern: []const u8,
    literals: []const ?[]const u8,
    wildcard: bool,
};

/// One canonical path of a leaf T: the leaf L whose literals it holds beside T's, and its count
/// of segments.
pub const Canonical = struct { leaf: usize, segments: usize };

/// The kind of a segment, in the walk's order (claim 1).
const Kind = enum { literal, parameter, wildcard };

/// The arrays of a layout, each by a pointer. It has the fields and the `depth_max` of the layout,
/// so the check and the walk of `router_match.zig` read it as they read the layout. Its pointers
/// point to a copy of the layout in a var, so a call that gets the view costs a few steps
/// (`router_trie.zig`).
pub fn View(comptime Layout: type) type {
    return struct {
        nodes: *const @FieldType(Layout, "nodes"),
        edges: *const @FieldType(Layout, "edges"),
        leaves: *const @FieldType(Layout, "leaves"),
        entries: *const @FieldType(Layout, "entries"),
        methods: *const @FieldType(Layout, "methods"),
        names: *const @FieldType(Layout, "names"),
        text: *const @FieldType(Layout, "text"),

        pub const depth_max = Layout.depth_max;
    };
}

/// The view of the layout that `copy` points to, a var. Comptime-only.
pub fn view_of(copy: anytype) View(@TypeOf(copy.*)) {
    return .{
        .nodes = &copy.nodes,
        .edges = &copy.edges,
        .leaves = &copy.leaves,
        .entries = &copy.entries,
        .methods = &copy.methods,
        .names = &copy.names,
        .text = &copy.text,
    };
}

/// The shape of each leaf, in the order of `layout.leaves`. Each node's index is larger than
/// its parent's, so one pass in index order writes each node after its parent.
pub fn leaf_shapes(comptime layout: anytype) [layout.leaves.len]Shape {
    var nodes: [layout.nodes.len]Shape = undefined;
    nodes[router_trie.root] = .{ .node = router_trie.root, .pattern = "", .literals = &.{}, .wildcard = false };
    var leaves: [layout.leaves.len]Shape = undefined;
    for (layout.nodes, 0..) |at, node| {
        const shape = nodes[node];
        for (layout.edges[at.edges_first..][0..at.edges_count]) |edge| {
            const literal = text_of(layout, edge.segment);
            nodes[edge.child] = child_shape(shape, edge.child, literal, literal);
        }
        if (at.parameter) |parameter| {
            const name = text_of(layout, parameter.name);
            nodes[parameter.child] = child_shape(shape, parameter.child, [_]u8{router_pattern.parameter_prefix} ++ name, null);
        }
        if (at.wildcard) |child| {
            nodes[child] = child_shape(shape, child, router_pattern.wildcard, null);
            // The wildcard is no segment of `literals`: it matches each segment after them.
            nodes[child].literals = shape.literals;
            nodes[child].wildcard = true;
        }
        const leaf = at.leaf orelse continue;
        leaves[leaf] = shape;
        // Decision 129: a parameter node has no name, so the leaf's pattern takes the names of
        // its first route.
        leaves[leaf].pattern = named_pattern(layout, shape.pattern, layout.entries[layout.leaves[leaf].entries_first]);
        // Decision 122: the pattern "/" is the root, with no segment.
        if (node == router_trie.root) leaves[leaf].pattern = router_pattern.root;
    }
    return leaves;
}

/// `pattern` with the name of `entry`'s parameter at each parameter segment, in order.
fn named_pattern(comptime layout: anytype, pattern: []const u8, entry: anytype) []const u8 {
    var named: []const u8 = "";
    var index: usize = 0;
    var segments = std.mem.splitScalar(u8, pattern, router_pattern.separator);
    _ = segments.next();
    while (segments.next()) |segment| {
        named = named ++ [_]u8{router_pattern.separator};
        if (!router_pattern.is_parameter(segment)) {
            named = named ++ segment;
            if (router_pattern.is_wildcard(segment)) index += 1;
            continue;
        }
        named = named ++ [_]u8{router_pattern.parameter_prefix} ++ text_of(layout, layout.names[entry.names_first + index]);
        index += 1;
    }
    return named;
}

/// Whether `left` and `right` hold the same segments, a parameter of any name equal to another
/// (decision 129): the two patterns end at one leaf.
pub fn same_leaf(left: []const u8, right: []const u8) bool {
    var left_segments = std.mem.splitScalar(u8, left, router_pattern.separator);
    var right_segments = std.mem.splitScalar(u8, right, router_pattern.separator);
    while (left_segments.next()) |segment| {
        const other = right_segments.next() orelse return false;
        if (router_pattern.is_parameter(segment) and router_pattern.is_parameter(other)) continue;
        if (!std.mem.eql(u8, segment, other)) return false;
    }
    return right_segments.next() == null;
}

fn child_shape(parent: Shape, child: usize, segment: []const u8, literal: ?[]const u8) Shape {
    assert(child > parent.node);
    return .{
        .node = child,
        .pattern = parent.pattern ++ [_]u8{router_pattern.separator} ++ segment,
        .literals = parent.literals ++ [_]?[]const u8{literal},
        .wildcard = false,
    };
}

/// A copy of the run `range` of the layout's text. The compiler compares a slice of the large
/// `text` array much more slowly than a small array of its own, so the check reads copies.
pub fn text_of(comptime layout: anytype, range: anytype) []const u8 {
    var copy: [range.len]u8 = undefined;
    @memcpy(&copy, layout.text[range.offset..][0..range.len]);
    const final = copy;
    return &final;
}

/// The canonical paths of each leaf, in the order of `layout.leaves`.
pub fn all_canonicals_of(comptime layout: anytype, comptime shapes: []const Shape, depth_max: usize) [shapes.len][]const Canonical {
    var canonicals: [shapes.len][]const Canonical = undefined;
    for (&canonicals, 0..) |*list, leaf| list.* = canonicals_of(layout, shapes, leaf, depth_max);
    return canonicals;
}

fn literal_at(shape: Shape, position: usize) ?[]const u8 {
    if (position < shape.literals.len) return shape.literals[position];
    return null;
}

fn kind_at(shape: Shape, position: usize) Kind {
    if (position < shape.literals.len) return if (shape.literals[position] == null) .parameter else .literal;
    // A leaf that matches a path holds a segment at each position of the path.
    assert(shape.wildcard);
    return .wildcard;
}

/// Whether `shape` matches a path of `segments` segments.
fn matches_length(shape: Shape, segments: usize) bool {
    return if (shape.wildcard) segments > shape.literals.len else segments == shape.literals.len;
}

/// Whether `left` comes before `right` in the walk's order (claim 1). The two leaves differ, and
/// a path matches both.
fn precedes(left: Shape, right: Shape) bool {
    for (0..@as(usize, @max(left.literals.len, right.literals.len)) + 1) |position| {
        const left_kind = kind_at(left, position);
        const right_kind = kind_at(right, position);
        if (left_kind != right_kind) return @intFromEnum(left_kind) < @intFromEnum(right_kind);
        // Two leaves with the same kinds and literals up to one wildcard are one leaf.
        assert(left_kind != .wildcard);
    }
    unreachable;
}

/// The canonical paths of leaf `leaf`: x(T, L, n) for T, and for each L before T, at each n
/// that both match (claims 3, 5 and 6). They come in the order of the leaves, and then by n.
fn canonicals_of(comptime layout: anytype, shapes: []const Shape, leaf: usize, depth_max: usize) []const Canonical {
    const shape = shapes[leaf];
    const first = shape.literals.len + @intFromBool(shape.wildcard);
    // Claim 3: a path of `depth_max` + 1 segments stands for each longer path.
    const last = if (shape.wildcard) depth_max + 1 else first;
    const found = leaves_on_paths(layout, shape);
    var sorted: [found.len]usize = found[0..found.len].*;
    std.mem.sort(usize, &sorted, {}, std.sort.asc(usize));
    var list: []const Canonical = &.{};
    for (sorted) |other_leaf| {
        var lengths: []const Canonical = &.{};
        for (first..last + 1) |segments| {
            if (!matches_length(shapes[other_leaf], segments)) continue;
            lengths = lengths ++ [_]Canonical{.{ .leaf = other_leaf, .segments = segments }};
        }
        // Claim 6: the walk on a path of T never stops at a leaf after T. `precedes` compares
        // two leaves that match one path.
        if (lengths.len == 0) continue;
        if (other_leaf != leaf and !precedes(shapes[other_leaf], shape)) continue;
        list = list ++ lengths;
    }
    return list;
}

/// A node of the walk of the trie, and the count of segments before it.
const Visit = struct { node: usize, depth: usize };

/// The leaves that hold a literal of `shape` at each position where both hold a literal, each
/// once: T itself, and each leaf L that can match a path of T. A leaf of the list matches a path
/// of T when it also matches a path of T's length.
fn leaves_on_paths(comptime layout: anytype, shape: Shape) []const usize {
    var stack: [layout.nodes.len]Visit = undefined;
    stack[0] = .{ .node = router_trie.root, .depth = 0 };
    var count: usize = 1;
    var leaves: []const usize = &.{};
    // Each node has one parent, so the walk pushes each node once at most.
    for (0..layout.nodes.len) |_| {
        if (count == 0) break;
        count -= 1;
        const visit = stack[count];
        const at = layout.nodes[visit.node];
        if (at.leaf) |leaf| leaves = leaves ++ [_]usize{leaf};
        // Decision 122 ruling 6: the wildcard matches each segment from its position.
        if (at.wildcard) |child| leaves = leaves ++ [_]usize{layout.nodes[child].leaf.?};
        count = push_children(layout, shape, visit, &stack, count);
    }
    assert(count == 0);
    return leaves;
}

/// Pushes the children of `visit` that can match the segment of a path of `shape` at the
/// position of `visit`, and returns the new count of the stack.
fn push_children(comptime layout: anytype, shape: Shape, visit: Visit, stack: []Visit, count: usize) usize {
    const at = layout.nodes[visit.node];
    // A path of a leaf with no wildcard holds no segment after the leaf's segments.
    if (visit.depth >= shape.literals.len and !shape.wildcard) return count;
    var pushed = count;
    if (literal_at(shape, visit.depth)) |literal| {
        // Where T holds a literal, a path of T holds it, so only its literal edge matches.
        if (router_match.literal_child(layout, visit.node, literal)) |child| {
            stack[pushed] = .{ .node = child, .depth = visit.depth + 1 };
            pushed += 1;
        }
    } else {
        // Where T holds a parameter or the wildcard, each literal edge but the empty one matches
        // some path of T. The empty edge matches none (decision 122 as amended on 2026-10-29),
        // and its leaves only cost the check walks that claim 7 would save.
        for (layout.edges[at.edges_first..][0..at.edges_count]) |edge| {
            stack[pushed] = .{ .node = edge.child, .depth = visit.depth + 1 };
            pushed += 1;
        }
    }
    if (at.parameter) |parameter| {
        stack[pushed] = .{ .node = parameter.child, .depth = visit.depth + 1 };
        pushed += 1;
    }
    return pushed;
}

/// x(T, L, n): T's literal, else L's literal, else "other", at each position.
pub fn canonical_path(shape: Shape, other_shape: Shape, segments: usize, other: []const u8) []const u8 {
    // Decision 122: the path "/" is the root, with no segment.
    if (segments == 0) return router_pattern.root;
    var path: []const u8 = "";
    for (0..segments) |position| {
        const literal: ?[]const u8 = literal_at(shape, position) orelse literal_at(other_shape, position);
        path = path ++ [_]u8{router_pattern.separator} ++ (literal orelse other);
    }
    return path;
}
