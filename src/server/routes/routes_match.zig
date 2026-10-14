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
//!   7. Each segment, from the first, takes the literal edge of its node that equals it, octet for
//!      octet, or else the node's parameter child, or else the node's wildcard child. The wildcard
//!      takes the segment and each segment after it. A segment with none of the three matches
//!      nothing.
//!   8. The node after the last segment holds a leaf, or the path matches nothing.
//!   9. The method equals the token of one entry of the leaf, octet for octet, and the result is
//!      `found` with the entry's value. Otherwise it is `method_not_allowed` with the leaf's Allow
//!      value.
//!  10. `found` writes the name and the segment of each parameter of the walk into `parameters`,
//!      and for the wildcard the name "*" and the rest of the path, without its first "/". Each
//!      other result leaves `parameters.count` at 0.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
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

/// The node after the last segment of `path`, or null when a segment has no child. The walk
/// writes each parameter's name and value into `parameters` and counts them in `Walked`.
fn walk(comptime layout: anytype, path: []const u8, parameters: *PathParameters) ?Walked {
    assert(path.len > 0 and path[0] == routes_pattern.separator);
    var walked: Walked = .{ .node = routes_trie.root, .count = 0 };
    // Decision 122: the path "/" is the root, with no segment.
    if (path.len == 1) return walked;
    var segments = std.mem.splitScalar(u8, path[1..], routes_pattern.separator);
    // Bounded: each pass goes one level deeper, and a node at the depth of the deepest pattern
    // has no child, so the pass after it returns.
    for (0..@TypeOf(layout).depth_max + 1) |_| {
        // The segment and each segment after it, which a wildcard takes.
        const rest = segments.rest();
        const segment = segments.next() orelse return walked;
        // Decision 122: the literal edge first, then the parameter child, then the wildcard.
        if (literal_child(layout, walked.node, segment)) |child| {
            walked.node = child;
            continue;
        }
        if (layout.nodes[walked.node].parameter) |parameter| {
            bind(parameters, &walked.count, text_of(layout, parameter.name), segment);
            walked.node = parameter.child;
            continue;
        }
        // Decision 122 ruling 6: the wildcard matches one segment or more, the rest of the path.
        walked.node = layout.nodes[walked.node].wildcard orelse return null;
        bind(parameters, &walked.count, routes_pattern.wildcard, rest);
        return walked;
    }
    unreachable;
}

/// Writes `name` and `value` as the next parameter of a walk.
fn bind(parameters: *PathParameters, count: *usize, name: []const u8, value: []const u8) void {
    // `routes_pattern.refusal_of` passed each pattern, so a walk meets `path_parameters_max`
    // parameters at most, the wildcard included.
    assert(count.* < constants.path_parameters_max);
    assert(value.len > 0);
    parameters.names[count.*] = name;
    parameters.values[count.*] = value;
    count.* += 1;
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
