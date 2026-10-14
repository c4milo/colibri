//! The match of a method and a path against a route table, at run time (decision 122, design §8
//! step 21e). It allocates nothing, calls no function of the program, and asserts nothing about
//! what the peer sent: each failure is a result.
//!
//! `match` reads the method and the path in this order (invariant 7):
//!   1. It sets `parameters.count` to 0, so no value of an earlier match is read.
//!   2. The path ends at the first "?". The query is not read.
//!   3. A path that does not start with "/" matches nothing: "*", "", and a query alone.
//!   4. The path "/" is the root, with no segment.
//!   5. Each segment, from the first, takes the literal edge of its node that equals it, octet for
//!      octet. A segment with no such edge matches nothing.
//!   6. The node after the last segment holds a leaf, or the path matches nothing.
//!   7. The method equals the token of one entry of the leaf, octet for octet, and the result is
//!      `found` with the entry's value. Otherwise it is `method_not_allowed` with the leaf's Allow
//!      value.
const std = @import("std");
const assert = std.debug.assert;
const PathParameters = @import("../path_parameters.zig").PathParameters;
const routes_pattern = @import("routes_pattern.zig");
const routes_trie = @import("routes_trie.zig");

/// The octet that ends a path and starts its query (RFC 3986 §3.3, §3.4).
const query_start = '?';

/// What `match` gives for a method and a path.
pub fn Match(comptime Value: type) type {
    return union(enum) {
        /// The value of the route that names the method and the path.
        found: Value,
        /// The path names a resource, and no route of the resource names the method. The value
        /// is the Allow field's value that a 405 carries (RFC 9110 §15.5.6). It is a constant of
        /// the table.
        method_not_allowed: []const u8,
        /// No route names the path (RFC 9110 §15.5.5).
        not_found,
    };
}

/// The route of `layout` that `method` and `target` name. `target` is a path, which may end in a
/// query. Each result but `found` leaves `parameters.count` at 0.
pub fn match(
    comptime Value: type,
    comptime layout: anytype,
    method: []const u8,
    target: []const u8,
    parameters: *PathParameters,
) Match(Value) {
    // Decision 122: no value of an earlier match is read.
    parameters.count = 0;
    // RFC 3986 §3.3: the first "?" ends the path, and RFC 9112 §3.2.1, RFC 9113 §8.3.1 and RFC
    // 9114 §4.3.1 put the query after it.
    const path = target[0 .. std.mem.indexOfScalar(u8, target, query_start) orelse target.len];
    // RFC 9110 §4.1: absolute-path = 1*( "/" segment ). So "*" (RFC 9112 §3.2.4), the "" of a
    // CONNECT request, and a query alone match nothing.
    if (path.len == 0 or path[0] != routes_pattern.separator) return .not_found;
    const node = walk(layout, path) orelse return .not_found;
    // RFC 9110 §15.5.5: a path whose node holds no leaf names no resource.
    const leaf = layout.nodes[node].leaf orelse return .not_found;
    return choose(Value, layout, leaf, method);
}

/// The node after the last segment of `path`, or null when a segment has no edge.
fn walk(comptime layout: anytype, path: []const u8) ?usize {
    assert(path.len > 0 and path[0] == routes_pattern.separator);
    // Decision 122: the path "/" is the root, with no segment.
    if (path.len == 1) return routes_trie.root;
    var node: usize = routes_trie.root;
    var segments = std.mem.splitScalar(u8, path[1..], routes_pattern.separator);
    // Bounded: each pass goes one level deeper, and a node at the depth of the deepest pattern
    // has no edge, so the pass after it returns.
    for (0..@TypeOf(layout).depth_max + 1) |_| {
        const segment = segments.next() orelse return node;
        node = literal_child(layout, node, segment) orelse return null;
    }
    unreachable;
}

fn literal_child(comptime layout: anytype, node: usize, segment: []const u8) ?usize {
    const at = layout.nodes[node];
    for (layout.edges[at.edges_first..][0..at.edges_count]) |edge| {
        // The edges are sorted by length first, so no later edge is as short as the segment.
        if (edge.segment.len > segment.len) return null;
        // RFC 9110 §4.2.3: a path compares case-sensitively, octet for octet.
        if (std.mem.eql(u8, text_of(layout, edge.segment), segment)) return edge.child;
    }
    return null;
}

fn choose(comptime Value: type, comptime layout: anytype, leaf: usize, method: []const u8) Match(Value) {
    const at = layout.leaves[leaf];
    assert(at.entries_count > 0);
    for (layout.entries[at.entries_first..][0..at.entries_count]) |entry| {
        // RFC 9110 §9.1: the method token is case-sensitive.
        if (std.mem.eql(u8, text_of(layout, entry.method), method)) return .{ .found = entry.value };
    }
    // RFC 9110 §15.5.6: a 405 carries an Allow field with the target's methods.
    return .{ .method_not_allowed = text_of(layout, at.allow) };
}

fn text_of(comptime layout: anytype, range: anytype) []const u8 {
    return layout.text[range.offset..][0..range.len];
}
