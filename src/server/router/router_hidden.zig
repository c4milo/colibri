//! The check of a route that other routes hide (decision 122 ruling 12, as decision 128 amends it,
//! design §8 step 21e). It runs at compile time on the layout of a table that
//! `router_trie.refusal_of` passed. It adds nothing at run time.
//!
//! A route R names a method m, and its pattern ends at the leaf T. Since decision 128 the walk of
//! a request of m backs up past each leaf that does not serve m, so no route is hidden by a 405.
//! R does not compile in one case, `route_unreachable`: the walk of m on each path that T's
//! pattern matches stops at a leaf other than T, which serves m. A leaf serves m when it names m,
//! or when m is HEAD and the leaf names GET (RFC 9110 §9.3.2). The check refuses the first route
//! of the table, in table order, that falls in the case.
//!
//! The check does not read each path. For each leaf it reads a few canonical paths, and it runs
//! the walk of `router_match.zig` on each one. The claims below show that these paths are enough.
//! A walk of the trie finds the leaves of the canonical paths of each leaf
//! (`router_hidden_canonical.zig`). `router_hidden_test.zig` compares the verdicts with a brute
//! force on small tables.
//!
//! Terms:
//!   - A segment of a pattern has a kind: a literal, a parameter, or the wildcard. The wildcard
//!     matches each segment from its position to the end of the path.
//!   - "other" is a segment of ALPHA and DIGIT octets that equals no literal segment of the
//!     table. The check uses the shortest such segment: one octet, when one is free.
//!   - A leaf T of k segments matches paths of n segments: n = k when T has no wildcard, and
//!     each n of k or more when T ends in the wildcard.
//!   - x(T, n) holds T's literal at each literal position of T, and "other" at each other
//!     position, with n segments.
//!   - x(T, L, n), for a leaf L that matches a path of n segments that T matches too, holds T's
//!     literal, else L's literal, else "other", at each position. x(T, T, n) is x(T, n).
//!
//! Each claim, with its proof:
//!   1. Order. The walk on a path x stops at the first leaf, in the walk's order, whose pattern
//!      matches x. Two patterns that both match x compare at the first segment where their kinds
//!      differ: the literal, then the parameter, then the wildcard. Proof: at each node the walk
//!      tries the literal edge, then the parameter child, then the wildcard child (rule 8 of
//!      `router_match.zig`). It backs up when a deeper level fails (rule 9), and the first node
//!      with a leaf after the last segment decides (rule 10). Where two patterns that match x
//!      both hold a literal, both literals equal the segment of x, so the kinds decide.
//!   2. Other. No literal edge matches "other". So at each position where x holds "other", a
//!      pattern that matches x holds a parameter or the wildcard.
//!   3. Lengths. No pattern holds more than `depth_max` segments. So only a pattern that ends in
//!      the wildcard matches a path of more than `depth_max` segments, and its literals all come
//!      before position `depth_max`. For n > `depth_max` + 1, x(T, L, n) holds "other" at each
//!      position from `depth_max`, so the same leaves match it as match x(T, L, `depth_max` + 1).
//!      The check reads each n from k to `depth_max` + 1 only.
//!   4. Reachable. R is reachable if and only if the walk of m on x(T, n) stops at T for some n.
//!      The proof below holds for the walk of m, which passes each leaf that does not serve m: a
//!      leaf L that serves m and stops the walk before T on x(T, n) matches each path of T and
//!      comes before T in the order of claim 1, which reads no method.
//!      Proof: let the walk on x(T, n) stop at a leaf L other than T. L comes before T in the
//!      order, and L matches x(T, n). By claim 2, L holds a parameter or the wildcard where
//!      x(T, n) holds "other", and T's literal, a parameter or the wildcard elsewhere. So L
//!      matches each path of n segments that T matches, and the walk on that path never stops
//!      at T.
//!   5. Hidden. (Decision 122 ruling 12 read claims 5 and 6 for `route_hidden`, which decision 128
//!      removed. They stay true, and the check no longer reads them.) Let the walk on a path x of
//!      n segments that T matches stop at a leaf F. Then the
//!      walk on x(T, F, n) stops at F too. Proof: T and F match x, so where both hold a literal,
//!      both equal the segment of x, and x(T, F, n) is a path that both match. Let a leaf L
//!      before F match x(T, F, n). Where x(T, F, n) holds "other", L holds a parameter or the
//!      wildcard. Where it holds a literal of T or F, x holds the same literal. So L matches x
//!      and comes before F, but the walk on x stops at F. So R is hidden if and only if a
//!      request of m on some canonical path x(T, L, n) gets 405. The walk on it then stops at a
//!      leaf other than T, and that leaf does not serve m. Each canonical path is a path that T
//!      matches, so each refusal names a request that gets 405.
//!   6. Leaves after T. The leaf F of claim 5 comes before T in the order, because T matches x
//!      and the walk stops at the first leaf that matches. So the check reads x(T, L, n) only for
//!      L = T and for each L before T.
//!   7. Alone. When no leaf before T matches a path of n segments that T matches, the walk on
//!      each path of T stops at T, by claims 1 and 6. The check then runs no walk for T.
//!   8. Long paths. `match` gives `not_found` for a path longer than `path_len_max`, so no walk
//!      runs on it. Each path of n segments that T and L both match holds the literals of
//!      x(T, L, n), and one octet at least at each other position. So when "other" has one
//!      octet, x(T, L, n) is the shortest such path. When it is longer than `path_len_max`, each
//!      such path gets `not_found` and hides nothing, and the check runs no walk on it. When each
//!      x(T, n) is longer, no request reaches T, which is `route_unreachable`.
//!   9. Long other. A table that holds each of the 62 one-octet literals of ALPHA and DIGIT gets
//!      an "other" of two octets or more. A literal that repeats counts once. A canonical path is
//!      then up to n octets longer than the shortest path of its kind. For such a table, claim 8
//!      holds only for patterns more than `depth_max` + 1 octets shorter than `path_len_max`.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const router_hidden_canonical = @import("router_hidden_canonical.zig");
const router_match = @import("router_match.zig");
const router_pattern = @import("router_pattern.zig");
const router_trie = @import("router_trie.zig");

const Shape = router_hidden_canonical.Shape;
const Canonical = router_hidden_canonical.Canonical;
const text_of = router_hidden_canonical.text_of;

/// The octets of "other": ALPHA and DIGIT, which are unreserved (RFC 3986 §2.3).
const other_octets = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// The first route of `table`, in table order, that ruling 12 refuses, or null. `layout` is the
/// layout of `table`, which `router_trie.refusal_of` passed. The check reads the layout's trie,
/// and it reads `table` only to name the route that it refuses. Comptime-only.
pub fn refusal_of(comptime Value: type, comptime layout: anytype, comptime table: anytype) ?router_trie.Refusal {
    // The calls in the loops get a view of a copy in a var (`router_trie.zig`).
    var copy = layout;
    return view_refusal(Value, router_hidden_canonical.view_of(&copy), table);
}

/// `refusal_of` on `layout`, a view of the layout (`router_hidden_canonical.View`).
fn view_refusal(comptime Value: type, comptime layout: anytype, comptime table: anytype) ?router_trie.Refusal {
    const depth_max = @TypeOf(layout).depth_max;
    const lengths = depth_max + lengths_past_depth;
    const pairs = layout.leaves.len * layout.leaves.len;
    @setEvalBranchQuota(router_trie.hidden_quota_of(table, .{ .pairs = pairs, .lengths = lengths, .segments = depth_max + 1 }));
    const shapes = router_hidden_canonical.leaf_shapes(layout);
    const other = other_of(&shapes);
    const canonicals = router_hidden_canonical.all_canonicals_of(layout, &shapes, depth_max);
    var walks: usize = 0;
    for (canonicals) |list| walks += list.len;
    const walk_steps = router_match.walk_steps_max(layout.nodes.len);
    // A canonical path holds a literal or "other" in each segment.
    var segment_len_max = other.len;
    for (layout.edges) |edge| segment_len_max = @max(segment_len_max, edge.segment.len);
    @setEvalBranchQuota(router_trie.hidden_quota_of(table, .{
        .pairs = pairs,
        .lengths = lengths,
        .segments = depth_max + 1,
        .walks = walks,
        .walk_steps = walk_steps,
        .octets = walk_octets(layout.text.len, lengths, walk_steps, router_match.search_passes_max(layout.edges.len), segment_len_max),
    }));
    var verdicts: [layout.entries.len]?router_trie.Reason = @splat(null);
    for (canonicals, 0..) |list, leaf| leaf_verdicts(Value, layout, &shapes, other, leaf, list, &verdicts);
    return first_refusal(layout, &shapes, table, &verdicts);
}

/// The quota of the check of `table`, known before the build: each pair of routes at each
/// length counts as a walk. A test that builds several tables in one function raises its quota
/// by this for each table. Comptime-only.
pub fn quota_bound_of(comptime table: anytype) u32 {
    @setEvalBranchQuota(router_trie.quota_of(table));
    const routes = router_trie.routes_of(table);
    var depth_max: usize = 0;
    var segments: usize = 0;
    var octets: usize = 0;
    // A segment of a pattern is no longer than the pattern.
    var segment_len_max: usize = other_len_bound;
    for (routes.patterns, routes.tokens) |pattern, token| {
        depth_max = @max(depth_max, router_pattern.segments_count(pattern));
        segments += router_pattern.segments_count(pattern);
        octets += pattern.len + token.len;
        segment_len_max = @max(segment_len_max, pattern.len);
    }
    const lengths = depth_max + lengths_past_depth;
    const pairs = table.len * table.len;
    // The trie holds the root and a node for each segment at most, and an edge for each segment
    // at most.
    const walk_steps = router_match.walk_steps_max(segments + 1);
    return router_trie.hidden_quota_of(table, .{
        .pairs = pairs,
        .lengths = lengths,
        .segments = depth_max + 1,
        .walks = pairs * lengths,
        .walk_steps = walk_steps,
        .octets = walk_octets(octets, lengths, walk_steps, router_match.search_passes_max(segments), segment_len_max),
    });
}

/// The octets that one walk of the check reads, at most (`router_trie.zig`): the text, the path
/// of `lengths` segments at most, and the segment of each pass once for each comparison of the
/// search and once more.
fn walk_octets(text_len: usize, lengths: usize, walk_steps: usize, search_passes: usize, segment_len_max: usize) usize {
    return octet_reads * text_len + lengths * (segment_len_max + 1) + walk_steps * (search_passes + 1) * segment_len_max;
}

/// A canonical path holds 0 to `depth_max` + 1 segments (claim 3), so `depth_max` + 2 counts.
const lengths_past_depth = 2;

/// The check reads each octet of the text twice at most: once to copy it, and once in a walk.
const octet_reads = 2;

/// The octets of "other" in a table that does not hold each of the 62 * 62 literals of two
/// octets.
const other_len_bound = 2;

/// The checks of each entry of leaf `leaf`: the walk of the entry's method on each canonical path
/// x(T, n) of the leaf (claim 4). An entry that no walk reaches is `route_unreachable`.
fn leaf_verdicts(
    comptime Value: type,
    comptime layout: anytype,
    shapes: []const Shape,
    other: []const u8,
    leaf: usize,
    canonicals: []const Canonical,
    verdicts: []?router_trie.Reason,
) void {
    _ = Value;
    const at = layout.leaves[leaf];
    const entries = verdicts[at.entries_first..][0..at.entries_count];
    var reached: [constants.route_methods_max]bool = @splat(false);
    var too_long = false;
    var first_patterns: []const u8 = "";
    // Claim 7: when no leaf before T matches a path of T, the walk on each path of T stops at T,
    // so the check runs no walk.
    const alone = for (canonicals) |canonical| {
        if (canonical.leaf != leaf) break false;
    } else true;
    for (canonicals) |canonical| {
        // Claim 4: the paths x(T, n) decide.
        if (canonical.leaf != leaf) continue;
        const path = router_hidden_canonical.canonical_path(shapes[leaf], shapes[leaf], canonical.segments, other);
        // Claim 8: `match` gives `not_found` for a longer path.
        if (path.len > constants.path_len_max) {
            too_long = true;
            continue;
        }
        walk_entries(layout, shapes, leaf, path, alone, &reached, &first_patterns);
    }
    for (entries, 0..) |*verdict, index| {
        // Decision 122 ruling 12: the walk of the method on each path of the route stops at
        // another leaf.
        if (!reached[index] and verdict.* == null) verdict.* = .{ .route_unreachable = .{ .patterns = first_patterns, .too_long = too_long } };
    }
}

/// The walk of each entry's method of `leaf` on the canonical path `path`. An entry whose walk
/// stops at the leaf is reached, and the pattern of each other leaf where a walk stops is noted.
fn walk_entries(
    comptime layout: anytype,
    shapes: []const Shape,
    leaf: usize,
    path: []const u8,
    alone: bool,
    reached: *[constants.route_methods_max]bool,
    first_patterns: *[]const u8,
) void {
    const at = layout.leaves[leaf];
    for (layout.entries[at.entries_first..][0..at.entries_count], 0..) |entry, index| {
        // Claim 7: a leaf alone is reached on each of its paths.
        if (alone) {
            reached[index] = true;
            continue;
        }
        const stop_leaf = stop_of(layout, path, text_of(layout, entry.method));
        if (stop_leaf == leaf) reached[index] = true else first_patterns.* = add_first_pattern(first_patterns.*, shapes[stop_leaf].pattern);
    }
}

/// The leaf where the walk of `method` on `path` stops. The leaf of the path's own pattern serves
/// the method, so the walk stops at it or at a leaf before it.
fn stop_of(comptime layout: anytype, path: []const u8, method: []const u8) usize {
    var parameters: PathParameters = .{};
    var server: router_match.MethodServer = .{ .method = method };
    const stop = (router_match.stop_for(layout, path, &parameters, &server) orelse unreachable).node;
    return layout.nodes[stop].leaf.?;
}

/// The refusal of the first route, in table order, whose entry has a verdict, or null.
fn first_refusal(comptime layout: anytype, shapes: []const Shape, comptime table: anytype, verdicts: []const ?router_trie.Reason) ?router_trie.Refusal {
    for (verdicts) |verdict| {
        if (verdict != null) break;
    } else return null;
    var routes = router_trie.routes_of(table);
    var first: ?router_trie.Refusal = null;
    for (layout.leaves, shapes) |at, shape| {
        for (layout.entries[at.entries_first..][0..at.entries_count], verdicts[at.entries_first..][0..at.entries_count]) |entry, verdict| {
            const reason = verdict orelse continue;
            const route = route_of(&routes.patterns, &routes.tokens, shape.pattern, text_of(layout, entry.method));
            if (first == null or route < first.?.route) first = .{ .route = route, .pattern = shape.pattern, .reason = reason };
        }
    }
    return first;
}

/// The index of the route of `pattern` and `token` in the table.
fn route_of(patterns: []const []const u8, tokens: []const []const u8, pattern: []const u8, token: []const u8) usize {
    for (patterns, tokens, 0..) |held_pattern, held_token, route| {
        if (std.mem.eql(u8, held_pattern, pattern) and std.mem.eql(u8, held_token, token)) return route;
    }
    unreachable;
}

/// `patterns` with `pattern` in quotes after it, once.
fn add_first_pattern(patterns: []const u8, pattern: []const u8) []const u8 {
    const quoted = "\"" ++ pattern ++ "\"";
    if (std.mem.indexOf(u8, patterns, quoted) != null) return patterns;
    if (patterns.len == 0) return quoted;
    return patterns ++ ", " ++ quoted;
}

/// The shortest segment of `other_octets` that equals no literal of `shapes` (claim 2). It reads
/// each length in turn, from one octet, and returns the first free segment of that length.
fn other_of(shapes: []const Shape) []const u8 {
    var literals: usize = 0;
    for (shapes) |shape| literals += shape.literals.len;
    var segments_of_length: usize = 1;
    // Bounded: a length whose segments outnumber the literals holds a free segment.
    for (0..literals + 1) |index| {
        const length = index + 1;
        segments_of_length *= other_octets.len;
        // `count` counts a literal that repeats each time, so the literals of this length are
        // `count` or fewer. One of the first `count` + 1 segments is free when that is fewer
        // than `segments_of_length`.
        const count = @min(literals_of_length(shapes, length), segments_of_length - 1);
        if (free_segment(shapes, length, count)) |segment| return segment;
    }
    unreachable;
}

fn literals_of_length(shapes: []const Shape, length: usize) usize {
    var count: usize = 0;
    for (shapes) |shape| {
        for (shape.literals) |literal| {
            if (literal != null and literal.?.len == length) count += 1;
        }
    }
    return count;
}

/// The first of the segments 0 to `count` of `length` octets that equals no literal, or null.
/// Segment i writes i in base 62 over `other_octets`.
fn free_segment(shapes: []const Shape, comptime length: usize, comptime count: usize) ?[]const u8 {
    var taken: [count + 1]bool = @splat(false);
    for (shapes) |shape| {
        for (shape.literals) |literal| {
            const index = segment_index(literal orelse continue, length) orelse continue;
            if (index <= count) taken[index] = true;
        }
    }
    const free = std.mem.indexOfScalar(bool, &taken, false) orelse return null;
    var segment: [length]u8 = undefined;
    var rest = free;
    for (0..length) |position| {
        segment[length - 1 - position] = other_octets[rest % other_octets.len];
        rest /= other_octets.len;
    }
    const final = segment;
    return &final;
}

/// The index of `literal` among the segments of `length` octets, or null when it is not one.
fn segment_index(literal: []const u8, length: usize) ?usize {
    if (literal.len != length) return null;
    var index: usize = 0;
    for (literal) |octet| {
        const digit = std.mem.indexOfScalar(u8, other_octets, octet) orelse return null;
        index = index * other_octets.len + digit;
    }
    return index;
}
