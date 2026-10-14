//! The match of a method and a path against a route table, at run time (decision 122, design §8
//! step 21e). It allocates nothing, calls no function of the program, and asserts nothing about
//! what the peer sent: each failure is a result.
//!
//! `match` reads the method and the path in this order (invariant 7):
//!   1. It sets `parameters.count` to 0, so no value of an earlier match is read.
//!   2. A method that no route of the table names gives `not_implemented`, before the path is
//!      read. A table that names GET names HEAD too.
//!   3. A path of more than `path_len_max` octets, its query included, matches nothing.
//!   4. The path ends at the first "?". The query is not read.
//!   5. A path that does not start with "/" matches nothing: "*", "", and a query alone.
//!   6. One pass reads each octet of the path once, before the walk. A path matches nothing when
//!      a segment holds an octet outside `path_octets`, a "%" included, when a segment other than
//!      the root's is empty, or when a segment is "." or "..".
//!   7. The path "/" is the root, with no segment.
//!   8. The walk starts at the root. At each node it tries the literal edge that equals the
//!      segment, octet for octet, then the parameter child, then the wildcard child. The wildcard
//!      matches the segment and each segment after it.
//!   9. The walk backs up one level when a node has no child left to try for its segment, or when
//!      the walk read every segment and the node holds no leaf. It tries each child kind of a node
//!      once at most (INV-32). A walk that backs up from the root matches nothing.
//!  10. The first node that holds a leaf after the last segment decides. The walk does not back
//!      up for a method.
//!  11. The method equals the token of one entry of the leaf, octet for octet, and the result is
//!      `found` with the entry's value. A HEAD request finds the GET entry of a leaf with no HEAD
//!      entry. Otherwise the result is `method_not_allowed` with the leaf's Allow value, which
//!      lists HEAD after GET.
//!  12. `found` writes the name and the segment of each parameter of the walk into `parameters`,
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
        /// No route of the table names the method, whatever the path (RFC 9110 §9.1, §15.6.2).
        /// A table that names GET names HEAD too. So an `OPTIONS *` request gets
        /// `not_implemented` from a table with no OPTIONS route, and `not_found` from a table
        /// with one.
        not_implemented,
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
    // RFC 9110 §9.1, §15.6.2: a method that no route names gives 501, before the path is read.
    if (!implemented(layout, method)) return .not_implemented;
    const walked = stop(layout, target, parameters) orelse return .not_found;
    // RFC 9110 §15.5.5: a path whose node holds no leaf names no resource.
    const leaf = layout.nodes[walked.node].leaf orelse return .not_found;
    const result = choose(Value, layout, leaf, method);
    // Decision 122: only `found` gives the program the values of the parameters.
    if (result == .found) parameters.count = @intCast(walked.count);
    return result;
}

/// The node where the walk on the path of `target` stops, or null when the path matches no
/// route. `match` and the check of hidden routes (`routes_hidden.zig`) both call it, so the check
/// reads the walk that a request gets.
pub fn stop(comptime layout: anytype, target: []const u8, parameters: *PathParameters) ?Walked {
    const path = path_of(target) orelse return null;
    return walk(layout, path, parameters);
}

/// Whether a route of `layout` names `method`. A table that names GET names HEAD too. The loop
/// reads each method of the table's set once.
fn implemented(comptime layout: anytype, method: []const u8) bool {
    const head = std.mem.eql(u8, method, routes_method.head_token);
    for (layout.methods) |range| {
        const token = text_of(layout, range);
        // RFC 9110 §9.1: the method token is case-sensitive.
        if (std.mem.eql(u8, token, method)) return true;
        // RFC 9110 §9.1, §9.3.2: a HEAD request finds a GET route, so GET implements HEAD.
        if (head and std.mem.eql(u8, token, routes_method.get_token)) return true;
    }
    return false;
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
pub fn walk_steps_max(comptime nodes: usize) usize {
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
/// order. It pushes the first literal or parameter child that matches the segment, or it gives
/// the node of the wildcard.
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

/// The child of `node` after the literal edge that equals `segment`, or null. The edges of a node
/// are sorted by length and then by octets (`routes_trie_layout.segment_less`). So a binary search
/// in that order compares O(log k) edges of the k edges of the node.
pub fn literal_child(comptime layout: anytype, node: usize, segment: []const u8) ?usize {
    const at = layout.nodes[node];
    const edges = layout.edges[at.edges_first..][0..at.edges_count];
    var low: usize = 0;
    var high: usize = edges.len;
    for (0..search_passes_max(layout.edges.len)) |_| {
        if (low >= high) return null;
        const middle = low + ((high - low) >> 1);
        // RFC 9110 §4.2.3: a path compares case-sensitively, octet for octet.
        switch (segment_order(text_of(layout, edges[middle].segment), segment)) {
            .eq => return edges[middle].child,
            .lt => low = middle + 1,
            .gt => high = middle,
        }
    }
    // Each pass halves the run of edges, so the loop returns before its bound.
    unreachable;
}

/// The passes of the binary search of `literal_child` over a run of `edges` edges, at most.
pub fn search_passes_max(comptime edges: usize) usize {
    return std.math.log2_int(usize, edges + 1) + search_passes_past_log;
}

/// Each pass that compares an edge halves the run of edges. So floor(log2(k)) + 1 passes compare
/// for a run of k edges, and one more pass finds the run empty.
const search_passes_past_log = 2;

/// The order of `edge` and `segment` in the order of `routes_trie_layout.segment_less`: the
/// shorter first, then by octets.
fn segment_order(edge: []const u8, segment: []const u8) std.math.Order {
    if (edge.len != segment.len) return std.math.order(edge.len, segment.len);
    return std.mem.order(u8, edge, segment);
}

/// The result of `method` at `leaf`: `found` or `method_not_allowed`. The check of hidden routes
/// (`routes_hidden.zig`) calls it too, so a leaf serves a method for the check as it does for a
/// request.
pub fn choose(comptime Value: type, comptime layout: anytype, leaf: usize, method: []const u8) Match(Value) {
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

const testing = std.testing;
const routes_trie_layout = @import("routes_trie_layout.zig");

/// The search of `literal_child` before the binary search: it reads each edge of the node in turn.
/// The test compares the two searches.
fn literal_child_scan(comptime layout: anytype, node: usize, segment: []const u8) ?usize {
    const at = layout.nodes[node];
    for (layout.edges[at.edges_first..][0..at.edges_count]) |edge| {
        // The edges are sorted by length first, so no later edge is as short as the segment.
        if (edge.segment.len > segment.len) return null;
        if (std.mem.eql(u8, text_of(layout, edge.segment), segment)) return edge.child;
    }
    return null;
}

/// Tables whose nodes hold 0 to 20 literal edges, of one length or of several lengths. The test
/// reads no value, so each value is 0.
const search_tables = .{
    .{.{ .get, "/a", 0 }},
    .{ .{ .get, "/b", 0 }, .{ .get, "/aa", 0 } },
    .{ .{ .get, "/a", 0 }, .{ .get, "/b", 0 }, .{ .get, "/c", 0 } },
    .{
        .{ .get, "/e", 0 },    .{ .get, "/c", 0 },   .{ .get, "/a", 0 },   .{ .get, "/dd", 0 },
        .{ .get, "/bb", 0 },   .{ .get, "/ccc", 0 }, .{ .get, "/aaa", 0 }, .{ .get, "/eeee", 0 },
        .{ .get, "/x/mm", 0 }, .{ .get, "/x/n", 0 }, .{ .get, "/x/m", 0 }, .{ .get, "/p/:q", 0 },
        .{ .get, "/w/*", 0 },
    },
    .{
        .{ .get, "/s0", 0 },  .{ .get, "/s1", 0 },  .{ .get, "/s2", 0 },  .{ .get, "/s3", 0 },
        .{ .get, "/s4", 0 },  .{ .get, "/s5", 0 },  .{ .get, "/s6", 0 },  .{ .get, "/s7", 0 },
        .{ .get, "/s8", 0 },  .{ .get, "/s9", 0 },  .{ .get, "/t00", 0 }, .{ .get, "/t01", 0 },
        .{ .get, "/t02", 0 }, .{ .get, "/t03", 0 }, .{ .get, "/t04", 0 }, .{ .get, "/u", 0 },
        .{ .get, "/v", 0 },   .{ .get, "/zz", 0 },  .{ .get, "/Z", 0 },   .{ .get, "/0", 0 },
        .{ .get, "/:p", 0 },
    },
};

/// Segments beside the edges of each node: shorter and longer than each edge, before the first
/// edge, and after the last edge.
const outside_segments = [_][]const u8{ "", "!", "~", "!!", "~~", "~~~~~~~~", "aaaaaaaaaaaa" };

/// The octets of a segment that the test builds from an edge, at most.
const probe_len_max = 16;

/// Whether the two searches differ on `segment` at `node`. It prints the first difference.
fn searches_differ(comptime layout: anytype, node: usize, segment: []const u8) bool {
    const found = literal_child(layout, node, segment);
    const scanned = literal_child_scan(layout, node, segment);
    if (same_child(found, scanned)) return false;
    std.debug.print("first difference: node {d}, segment \"{s}\": {?d} against {?d}\n", .{ node, segment, found, scanned });
    return true;
}

/// Whether `left` and `right` are both null, or the same node. It compares the values, and not
/// the two optionals with `==`.
fn same_child(left: ?usize, right: ?usize) bool {
    const left_node = left orelse return right == null;
    const right_node = right orelse return false;
    return left_node == right_node;
}

/// Whether the two searches differ on `edge` at `node`, or on a segment that the test builds from
/// it: one octet shorter, one octet longer, and the last octet one lower and one higher.
fn edge_differs(comptime layout: anytype, node: usize, edge: []const u8) bool {
    var probe: [probe_len_max]u8 = undefined;
    @memcpy(probe[0..edge.len], edge);
    if (searches_differ(layout, node, edge)) return true;
    if (searches_differ(layout, node, edge[0 .. edge.len - 1])) return true;
    probe[edge.len] = '~';
    if (searches_differ(layout, node, probe[0 .. edge.len + 1])) return true;
    probe[edge.len - 1] = edge[edge.len - 1] - 1;
    if (searches_differ(layout, node, probe[0..edge.len])) return true;
    probe[edge.len - 1] = edge[edge.len - 1] + 1;
    return searches_differ(layout, node, probe[0..edge.len]);
}

/// Whether the two searches differ at a node of `layout`, on each edge and on `outside_segments`.
fn layout_differs(comptime layout: anytype) bool {
    for (layout.nodes, 0..) |at, node| {
        for (layout.edges[at.edges_first..][0..at.edges_count]) |edge| {
            if (edge_differs(layout, node, text_of(layout, edge.segment))) return true;
        }
        for (outside_segments) |segment| {
            if (searches_differ(layout, node, segment)) return true;
        }
    }
    return false;
}

/// The quota of the builds of `search_tables` in one test: one build's quota for each table.
fn search_tables_quota() u32 {
    var quota: u32 = 0;
    inline for (search_tables) |table| quota += routes_trie.quota_of(table);
    return quota;
}

test "decision 122: the binary search finds the literal edge that the scan of each edge finds" {
    @setEvalBranchQuota(comptime search_tables_quota());
    inline for (search_tables) |table| {
        const trie = comptime routes_trie.trie_of(table);
        const layout = comptime routes_trie_layout.build(u8, table, &trie);
        try testing.expect(!layout_differs(layout));
    }
}
