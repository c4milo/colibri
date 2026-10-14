//! The match of a method and a path against a route table, at run time (decision 122, design §8
//! step 21e). It allocates nothing, calls no function of the program, and asserts nothing about
//! what the peer sent: each failure is a result.
//!
//! `match` reads the method and the path in this order (invariant 7):
//!   1. It sets `parameters.count` to 0, so no value of an earlier match is read.
//!   2. A path of more than `path_len_max` octets, its query included, matches nothing.
//!   3. The path ends at the first "?". The query is not read.
//!   4. A path that does not start with "/" matches nothing: "*", "", and a query alone.
//!   5. One pass reads each octet of the path once, before the walk. A path matches nothing when
//!      a segment holds an octet outside `path_octets`, a "%" included, when a segment other than
//!      the root's is empty, or when a segment is "." or "..".
//!   6. The path "/" is the root, with no segment.
//!   7. The walk starts at the root. At each node it tries the literal edge that equals the
//!      segment, octet for octet, then the parameter child, then the wildcard child. The wildcard
//!      takes the segment and each segment after it.
//!   8. The walk backs up one level when a node has no child left to try for its segment, or when
//!      the walk read every segment and the node holds no leaf. It tries each child kind of a node
//!      once at most (INV-32). A walk that backs up from the root matches nothing.
//!   9. The first node that holds a leaf after the last segment decides. The walk does not back
//!      up for a method.
//!  10. The method equals the token of one entry of the leaf, octet for octet, and the result is
//!      `found` with the entry's value. A HEAD request finds the GET entry of a leaf with no HEAD
//!      entry. Otherwise the result is `method_not_allowed` with the leaf's Allow value, which
//!      lists HEAD after GET.
//!  11. `found` writes the name and the segment of each parameter of the walk into `parameters`,
//!      and for the wildcard the name "*" and the rest of the path, without its first "/". Each
//!      other result leaves `parameters.count` at 0.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const routes_method = @import("routes_method.zig");
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
    const path = path_of(target) orelse return .not_found;
    const walked = walk(layout, path, parameters) orelse return .not_found;
    // RFC 9110 §15.5.5: a path whose node holds no leaf names no resource.
    const leaf = layout.nodes[walked.node].leaf orelse return .not_found;
    const result = choose(Value, layout, leaf, method);
    // Decision 122: only `found` gives the program the values of the parameters.
    if (result == .found) parameters.count = @intCast(walked.count);
    return result;
}

/// The path of `target` before its query, or null when the path matches no route. It reads each
/// octet of the path once (INV-32).
fn path_of(target: []const u8) ?[]const u8 {
    // INV-8: `path_len_max` bounds the octets that one match reads.
    if (target.len > constants.path_len_max) return null;
    // RFC 9110 §4.1: absolute-path = 1*( "/" segment ). So "*" (RFC 9112 §3.2.4), the "" of a
    // CONNECT request, and a query alone match nothing.
    if (target.len == 0 or target[0] != routes_pattern.separator) return null;
    var segment_first: usize = 1;
    for (target[1..], 1..) |octet, index| {
        // RFC 3986 §3.3: the first "?" ends the path, and RFC 9112 §3.2.1, RFC 9113 §8.3.1 and
        // RFC 9114 §4.3.1 put the query after it.
        if (octet == query_start) return path_end(target[0..index], segment_first);
        if (octet == routes_pattern.separator) {
            if (!segment_matches(target[segment_first..index])) return null;
            segment_first = index + 1;
            continue;
        }
        // RFC 3986 §3.3: segment = *pchar. `path_octets` holds no "%", which starts a
        // pct-encoded octet (RFC 3986 §2.1), so a path with one matches nothing (decision 122).
        if (!routes_pattern.path_octets[octet]) return null;
    }
    return path_end(target, segment_first);
}

/// `path`, or null when its last segment matches no route.
fn path_end(path: []const u8, segment_first: usize) ?[]const u8 {
    assert(segment_first > 0 and segment_first <= path.len);
    // Decision 122: the path "/" is the root, with no segment.
    if (path.len == 1) return path;
    if (!segment_matches(path[segment_first..])) return null;
    return path;
}

/// Whether a route can match `segment`, which is not the root's.
fn segment_matches(segment: []const u8) bool {
    // Decision 122: an empty segment matches no route, though RFC 3986 §3.3 allows one.
    if (segment.len == 0) return false;
    // RFC 3986 §3.3, §6.2.2.3: "." and ".." are dot-segments, which match no route.
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    return true;
}

/// The node of a walk, and the count of parameters that it wrote.
const Walked = struct { node: usize, count: usize };

/// The child kind that a frame of the walk tried last, in the order of decision 122. A frame
/// with `none` has tried no child.
const Tried = enum { none, literal, parameter, wildcard };

/// One level of a walk: its node, the child kind it tried last, the first octet of its segment
/// in the path, and the count of parameters that the levels above it wrote.
const Frame = struct { node: usize, tried: Tried, segment_first: usize, count: usize };

/// What one pass of the walk does at its deepest frame.
const Step = union(enum) { push: Frame, found: Walked, back };

/// The passes of a walk's loop for each node, at most. A pass pushes a frame, backs up from a
/// frame, or returns. The walk pushes each node once at most and backs up from each frame once
/// at most (INV-32), and the last pass returns.
const passes_per_node = 2;

/// The passes of a walk's loop for a table of `nodes` nodes, at most (INV-32).
fn walk_steps_max(comptime nodes: usize) usize {
    return passes_per_node * nodes + 1;
}

/// The node after the last segment of `path` that holds a leaf, or null when no such node
/// exists. The walk writes each parameter's name and value into `parameters` and counts them in
/// `Walked`.
fn walk(comptime layout: anytype, path: []const u8, parameters: *PathParameters) ?Walked {
    assert(path.len > 0 and path[0] == routes_pattern.separator);
    const depth_max = @TypeOf(layout).depth_max;
    var frames: [depth_max + 1]Frame = undefined;
    // Decision 122: the path "/" is the root, with no segment.
    const segment_first: usize = if (path.len == 1) path.len + 1 else 1;
    frames[0] = .{ .node = routes_trie.root, .tried = .none, .segment_first = segment_first, .count = 0 };
    var depth: usize = 0;
    for (0..walk_steps_max(layout.nodes.len)) |_| {
        switch (step(layout, path, &frames[depth], parameters)) {
            .push => |frame| {
                // A node at the depth of the deepest pattern has no child.
                assert(depth < depth_max);
                depth += 1;
                frames[depth] = frame;
            },
            .found => |walked| return walked,
            // Decision 122: the walk backs up one level when a deeper level fails.
            .back => {
                if (depth == 0) return null;
                depth -= 1;
            },
        }
    }
    // INV-32: the walk pushes each node once at most, so the loop returns before its bound.
    unreachable;
}

/// One pass of the walk at `frame`. It tries the child kinds that `frame` has not tried, in
/// order. It pushes the first literal or parameter child that takes the segment, or it gives the
/// node of the wildcard.
fn step(comptime layout: anytype, path: []const u8, frame: *Frame, parameters: *PathParameters) Step {
    if (frame.segment_first > path.len) {
        // RFC 9110 §15.5.5: a node with no leaf names no resource, so the walk backs up.
        if (layout.nodes[frame.node].leaf == null) return .back;
        return .{ .found = .{ .node = frame.node, .count = frame.count } };
    }
    const segment_end = std.mem.indexOfScalarPos(u8, path, frame.segment_first, routes_pattern.separator) orelse path.len;
    const segment = path[frame.segment_first..segment_end];
    const at = layout.nodes[frame.node];
    const next_first = segment_end + 1;
    // Decision 122: the literal edge first, then the parameter child, then the wildcard. INV-32:
    // the frame records each kind it tries, so no kind is tried again after a back-up.
    if (frame.tried == .none) {
        frame.tried = .literal;
        if (literal_child(layout, frame.node, segment)) |child| {
            return .{ .push = .{ .node = child, .tried = .none, .segment_first = next_first, .count = frame.count } };
        }
    }
    if (frame.tried == .literal) {
        frame.tried = .parameter;
        if (at.parameter) |parameter| {
            bind(parameters, frame.count, text_of(layout, parameter.name), segment);
            return .{ .push = .{ .node = parameter.child, .tried = .none, .segment_first = next_first, .count = frame.count + 1 } };
        }
    }
    if (frame.tried == .parameter) {
        frame.tried = .wildcard;
        // Decision 122 ruling 6: the wildcard matches one segment or more, the rest of the path.
        if (at.wildcard) |wildcard| {
            bind(parameters, frame.count, routes_pattern.wildcard, path[frame.segment_first..]);
            return .{ .found = .{ .node = wildcard, .count = frame.count + 1 } };
        }
    }
    return .back;
}

/// Writes `name` and `value` as the parameter at `index` of a walk.
fn bind(parameters: *PathParameters, index: usize, name: []const u8, value: []const u8) void {
    // `routes_pattern.refusal_of` passed each pattern, so a walk meets `path_parameters_max`
    // parameters at most, the wildcard included.
    assert(index < constants.path_parameters_max);
    assert(value.len > 0);
    parameters.names[index] = name;
    parameters.values[index] = value;
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
    const entries = layout.entries[at.entries_first..][0..at.entries_count];
    for (entries) |entry| {
        // RFC 9110 §9.1: the method token is case-sensitive.
        if (std.mem.eql(u8, text_of(layout, entry.method), method)) return .{ .found = entry.value };
    }
    // RFC 9110 §9.1, §9.3.2: a HEAD request finds the GET entry of a leaf with no HEAD entry.
    // The entries come in RFC 9110 §9.1's order, so a GET entry is the first.
    const first = text_of(layout, entries[0].method);
    if (std.mem.eql(u8, method, routes_method.head_token) and std.mem.eql(u8, first, routes_method.get_token)) {
        return .{ .found = entries[0].value };
    }
    // RFC 9110 §15.5.6: a 405 carries an Allow field with the target's methods.
    return .{ .method_not_allowed = text_of(layout, at.allow) };
}

fn text_of(comptime layout: anytype, range: anytype) []const u8 {
    return layout.text[range.offset..][0..range.len];
}
