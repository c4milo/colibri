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
//!   5. A query alone, such as "?x", is the root with a query. Any other path that does not
//!      start with "/" matches nothing: "*" and "".
//!   6. One pass reads each octet of the path once, before the walk. A path matches nothing when
//!      a segment holds an octet outside `path_octets` and "%", when a segment other than the
//!      root's is empty, or when a segment is "." or "..", encoded or not (RFC 3986 §6.2.2.2).
//!   6a. A segment that encodes "/", "\\" or NUL matches nothing (RFC 3986 §7.3). The walk splits
//!      the path on "/", then percent-decodes each segment it reads (RFC 3986 §2.1, decision 127).
//!      A "%" that two hex digits do not follow stays as written.
//!   7. The path "/" is the root, with no segment.
//!   8. The walk starts at the root. At each node it tries the literal edge that equals the
//!      segment, octet for octet, then the parameter child, then the wildcard child. The wildcard
//!      matches the segment and each segment after it.
//!   9. The walk backs up one level when a node has no child left to try for its segment, or when
//!      the walk read every segment and the node holds no leaf. It tries each child kind of a node
//!      once at most (INV-32). A walk that backs up from the root matches nothing.
//!  10. The first node after the last segment whose leaf serves the method decides. A leaf serves
//!      a method that one of its entries names, octet for octet, and a HEAD request when it names
//!      GET (RFC 9110 §9.3.2). The walk backs up past a leaf that does not serve the method, as it
//!      backs up past a node with no leaf (decision 128).
//!  11. The result is `found` with the value of the leaf's entry for the method, or of its GET entry
//!      for a HEAD request with no HEAD entry. When no leaf that the path reaches serves the method,
//!      the result is `method_not_allowed` with the Allow value of their methods joined, which
//!      lists HEAD after GET (`router_allow.zig`).
//!  12. `found` writes the name and the decoded segment of each parameter of the walk into
//!      `parameters`, and for the wildcard the name "*" and the decoded rest of the path, without
//!      its first "/". Each other result leaves `parameters.count` at 0.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const router_method = @import("router_method.zig");
const router_pattern = @import("router_pattern.zig");
const router_trie = @import("router_trie.zig");
const router_trie_layout = @import("router_trie_layout.zig");
const router_path = @import("router_path.zig");
const router_allow = @import("router_allow.zig");
const percent = @import("http").uri_percent;

/// The octet that starts a percent-encoded octet (RFC 3986 §2.1).
const percent_sign = '%';

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
    const wanted = router_allow.wanted_of(layout, method);
    if (wanted == 0) return .not_implemented;
    var server: MaskServer = .{ .wanted = wanted };
    const walked = stop_for(layout, target, parameters, &server) orelse {
        const reached = server.reached;
        // RFC 9110 §15.5.5: a path that no leaf matches names no resource.
        if (reached == 0) return .not_found;
        // Decision 128: no leaf that the path reaches serves the method, and RFC 9110 §15.5.6's
        // Allow lists the methods of each of them.
        return .{ .method_not_allowed = router_allow.Allows(layout).values[reached] };
    };
    const leaf = layout.nodes[walked.node].leaf.?;
    const result = choose(Value, layout, leaf, method);
    // The walk stopped at a leaf that serves the method.
    assert(result == .found);
    // Decision 122: only `found` gives the program the values of the parameters.
    parameters.count = @intCast(walked.count);
    return result;
}

/// What decides whether a leaf serves a request, for `match`: the bits of the methods that serve
/// it, and the methods of each leaf the walk passed.
const MaskServer = struct {
    wanted: router_allow.Mask,
    reached: router_allow.Mask = 0,

    pub fn serves(server: *MaskServer, comptime layout: anytype, leaf: usize) bool {
        const mask = router_allow.Allows(layout).leaf_masks[leaf];
        if (mask & server.wanted != 0) return true;
        server.reached |= mask;
        return false;
    }
};

/// A leaf serves any method: the walk stops at the first leaf it reaches.
const AnyServer = struct {
    pub fn serves(_: *AnyServer, comptime _: anytype, _: usize) bool {
        return true;
    }
};

/// What decides whether a leaf serves a request of `method`, for the check of unreachable routes,
/// which runs at compile time on a view of the layout.
pub const MethodServer = struct {
    method: []const u8,

    pub fn serves(server: *MethodServer, comptime layout: anytype, leaf: usize) bool {
        return leaf_serves(layout, leaf, server.method);
    }
};

/// Whether `leaf` names `method`, or names GET when `method` is HEAD (RFC 9110 §9.1, §9.3.2).
pub fn leaf_serves(comptime layout: anytype, leaf: usize, method: []const u8) bool {
    const at = layout.leaves[leaf];
    const head = std.mem.eql(u8, method, router_method.head_token);
    for (layout.entries[at.entries_first..][0..at.entries_count]) |entry| {
        const token = text_of(layout, entry.method);
        if (std.mem.eql(u8, token, method)) return true;
        if (head and std.mem.eql(u8, token, router_method.get_token)) return true;
    }
    return false;
}

/// The node where the walk on the path of `target` stops, or null when the path matches no
/// route. `match` and the check of hidden routes (`router_hidden.zig`) both call it, so the check
/// reads the walk that a request gets.
pub fn stop(comptime layout: anytype, target: []const u8, parameters: *PathParameters) ?Walked {
    var server: AnyServer = .{};
    return stop_for(layout, target, parameters, &server);
}

/// The node where the walk on the path of `target` stops at a leaf that `server` says serves the
/// request, or null (decision 128). `server` is a pointer to a `MaskServer`, an `AnyServer` or a
/// `MethodServer`.
pub fn stop_for(comptime layout: anytype, target: []const u8, parameters: *PathParameters, server: anytype) ?Walked {
    var segments: SegmentsOf(layout) = undefined;
    if (!router_path.read(capacity_of(layout), target, &segments)) return null;
    return walk(layout, &segments, parameters, server);
}

/// The segments a walk on `layout` reads at most: one for each level, and the one a wildcard
/// starts at.
fn capacity_of(comptime layout: anytype) usize {
    return @TypeOf(layout).depth_max + 1;
}

fn SegmentsOf(comptime layout: anytype) type {
    return router_path.Segments(capacity_of(layout));
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
fn walk(comptime layout: anytype, segments: *const SegmentsOf(layout), parameters: *PathParameters, server: anytype) ?Walked {
    const path = segments.path;
    assert(path.len > 0 and path[0] == router_pattern.separator);
    const depth_max = @TypeOf(layout).depth_max;
    var frames: [depth_max + 1]Frame = undefined;
    // Decision 122: the path "/" is the root, with no segment.
    const segment_first: usize = if (path.len == 1) path.len + 1 else 1;
    frames[0] = .{ .node = router_trie.root, .tried = .none, .segment_first = segment_first, .count = 0 };
    var depth: usize = 0;
    for (0..walk_steps_max(layout.nodes.len)) |_| {
        switch (step(layout, segments, depth, &frames[depth], parameters, server)) {
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
/// the node of the wildcard. The frame at `depth` reads segment `depth` of `segments`.
fn step(comptime layout: anytype, segments: *const SegmentsOf(layout), depth: usize, frame: *Frame, parameters: *PathParameters, server: anytype) Step {
    const path = segments.path;
    if (frame.segment_first > path.len) return at_end(layout, frame, server);
    // The pass recorded each segment a frame reads: a walk is never deeper than `depth_max`.
    assert(depth < capacity_of(layout) and depth < segments.count);
    const segment_end: usize = segments.ends[depth];
    const plain = (segments.encoded >> @intCast(depth)) & 1 == 0;
    const segment = decoded(parameters, path, frame.segment_first, segment_end, plain);
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
        if (at.wildcard) |wildcard| return wildcard_step(layout, path, frame, wildcard, parameters, server);
    }
    return .back;
}

/// The frame after the last segment: its node decides when its leaf serves the request.
fn at_end(comptime layout: anytype, frame: *const Frame, server: anytype) Step {
    // RFC 9110 §15.5.5: a node with no leaf names no resource, so the walk backs up.
    const leaf = layout.nodes[frame.node].leaf orelse return .back;
    // Decision 128: a leaf that does not serve the method lets the walk back up too.
    if (!server.serves(layout, leaf)) return .back;
    return .{ .found = .{ .node = frame.node, .count = frame.count } };
}

/// Decision 122 ruling 6: the wildcard matches one segment or more, the rest of the path. Its
/// leaf decides when it serves the request (decision 128).
fn wildcard_step(comptime layout: anytype, path: []const u8, frame: *const Frame, wildcard: usize, parameters: *PathParameters, server: anytype) Step {
    if (!server.serves(layout, layout.nodes[wildcard].leaf.?)) return .back;
    bind(parameters, frame.count, router_pattern.wildcard, decoded(parameters, path, frame.segment_first, path.len, false));
    return .{ .found = .{ .node = wildcard, .count = frame.count + 1 } };
}

/// `path[first..end]` percent-decoded (RFC 3986 §2.1): the path's own octets when they hold no
/// "%", or else the decoded octets, written into `parameters.storage` at the same offset. A
/// decoded run is never longer than its encoded one, so it stays inside its own place. A "%" that
/// two hex digits do not follow stays as written (decision 127). `plain` says the pass found no
/// "%" there, so no octet is searched.
fn decoded(parameters: *PathParameters, path: []const u8, first: usize, end: usize, plain: bool) []const u8 {
    assert(first <= end and end <= path.len and path.len <= parameters.storage.len);
    const encoded = path[first..end];
    if (plain or std.mem.indexOfScalar(u8, encoded, percent_sign) == null) return encoded;
    const out = parameters.storage[first..end];
    var written: usize = 0;
    var index: usize = 0;
    // Bounded: each pass takes one octet of `encoded`, or three for a decoded "%".
    while (index < encoded.len) : (written += 1) {
        if (percent.decoded_at(encoded, index)) |value| {
            out[written] = value;
            index += percent.encoded_len;
            continue;
        }
        out[written] = encoded[index];
        index += 1;
    }
    return out[0..written];
}

/// Writes `name` and `value` as the parameter at `index` of a walk.
fn bind(parameters: *PathParameters, index: usize, name: []const u8, value: []const u8) void {
    // `router_pattern.refusal_of` passed each pattern, so a walk meets `path_parameters_max`
    // parameters at most, the wildcard included.
    assert(index < constants.path_parameters_max);
    assert(value.len > 0);
    parameters.names[index] = name;
    parameters.values[index] = value;
}

/// The child of `node` after the literal edge that equals `segment`, or null. The edges of a node
/// are sorted by length and then by octets (`router_trie_layout.segment_less`). So a binary search
/// in that order compares O(log k) edges of the k edges of the node.
pub fn literal_child(comptime layout: anytype, node: usize, segment: []const u8) ?usize {
    const at = layout.nodes[node];
    const edges = layout.edges[at.edges_first..][0..at.edges_count];
    const head = router_trie_layout.head_of(segment);
    var low: usize = 0;
    var high: usize = edges.len;
    for (0..search_passes_max(layout.edges.len)) |_| {
        if (low >= high) return null;
        const middle = low + ((high - low) >> 1);
        // RFC 9110 §4.2.3: a path compares case-sensitively, octet for octet.
        switch (edge_order(layout, edges[middle], segment, head)) {
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

/// The order of `edge` and `segment` in the order of `router_trie_layout.segment_less`: the
/// shorter first, then by octets. The first octets compare as one integer, `head`, which the
/// build wrote for each edge, so a segment of `head_len` octets or fewer compares no octet.
fn edge_order(comptime layout: anytype, edge: anytype, segment: []const u8, head: u64) std.math.Order {
    if (edge.segment.len != segment.len) return std.math.order(edge.segment.len, segment.len);
    if (edge.head != head) return std.math.order(edge.head, head);
    if (segment.len <= router_trie_layout.head_len) return .eq;
    return std.mem.order(u8, text_of(layout, edge.segment)[router_trie_layout.head_len..], segment[router_trie_layout.head_len..]);
}

/// The result of `method` at `leaf`: `found` or `method_not_allowed`. The check of hidden routes
/// (`router_hidden.zig`) calls it too, so a leaf serves a method for the check as it does for a
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
    if (std.mem.eql(u8, method, router_method.head_token) and std.mem.eql(u8, first, router_method.get_token)) {
        return .{ .found = entries[0].value };
    }
    // RFC 9110 §15.5.6: a 405 carries an Allow field with the target's methods.
    return .{ .method_not_allowed = text_of(layout, at.allow) };
}

fn text_of(comptime layout: anytype, range: anytype) []const u8 {
    return layout.text[range.offset..][0..range.len];
}

const testing = std.testing;

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
    // Literals of 8 octets and more, of one length: they differ in their first 8 octets, past
    // them, or in both, so the order of their heads and of their octets decides the search.
    .{
        .{ .get, "/subscriptions", 0 }, .{ .get, "/notifications", 0 }, .{ .get, "/subscriptionz", 0 },
        .{ .get, "/aaaaaaaabbbbb", 0 }, .{ .get, "/aaaaaaabbbbbb", 0 }, .{ .get, "/zaaaaaaaaaaaa", 0 },
        .{ .get, "/abcdefgh", 0 },      .{ .get, "/abcdefgi", 0 },      .{ .get, "/bbcdefgh", 0 },
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
    inline for (search_tables) |table| quota += router_trie.quota_of(table);
    return quota;
}

test "decision 122: the binary search finds the literal edge that the scan of each edge finds" {
    @setEvalBranchQuota(comptime search_tables_quota());
    inline for (search_tables) |table| {
        const trie = comptime router_trie.trie_of(table);
        const layout = comptime router_trie_layout.build(u8, table, &trie);
        try testing.expect(!layout_differs(layout));
    }
}
