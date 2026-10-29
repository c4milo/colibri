//! The tests of `router_match.zig`'s search of a node's literal edges: the binary search finds
//! the edge that a scan of each edge finds (decision 122). Split out for length. Test-only.
const std = @import("std");
const router_trie = @import("router_trie.zig");
const router_trie_layout = @import("router_trie_layout.zig");
const literal_child = @import("router_match.zig").literal_child;

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
