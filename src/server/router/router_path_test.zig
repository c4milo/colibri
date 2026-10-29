//! The tests of `router_path.zig`: a fuzz property, a sweep, and an exhaustive pass that hold the
//! one pass to the path checks it replaced, which this file keeps as the reference. Test-only.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const router_pattern = @import("router_pattern.zig");
const router_path = @import("router_path.zig");
const percent = @import("http").uri_percent;

const testing = std.testing;
const query_start = '?';
const percent_sign = '%';

/// The segments the tests record, past the depth of every table they build.
const capacity = 4;
const Segments = router_path.Segments(capacity);

/// Requires the pass to refuse what the reference refuses, and to record the reference's path,
/// segment ends and "%" bits for what it accepts.
fn expect_same(target: []const u8) !void {
    var segments: Segments = undefined;
    const accepted = router_path.read(capacity, target, &segments);
    const path = old_path_of(target) orelse return testing.expect(!accepted);
    try testing.expect(accepted);
    try testing.expectEqualStrings(path, segments.path);
    // The root has no segment.
    if (path.len == 1) return testing.expectEqual(0, segments.count);
    var iterator = std.mem.splitScalar(u8, path[1..], router_pattern.separator);
    var index: usize = 0;
    var end: usize = 0;
    // Bounded by the path's segments.
    while (iterator.next()) |segment| : (index += 1) {
        end += 1 + segment.len;
        if (index >= capacity) continue;
        try testing.expectEqual(end, segments.ends[index]);
        const encoded = std.mem.indexOfScalar(u8, segment, percent_sign) != null;
        try testing.expectEqual(encoded, (segments.encoded >> @intCast(index)) & 1 == 1);
    }
    try testing.expectEqual(index, segments.count);
}

/// The octets the exhaustive pass and the fuzz property build targets from: each class of the
/// pass, a dot, the hex digits of "%2E", "%2F", "%5C" and "%00", and an octet outside pchar.
const alphabet = "/?%.a2EeF5C0 x";
/// The longest target of the exhaustive pass: 14^5 targets.
const exhaustive_len_max = 5;
const fuzz_input_len_max = 32;

fn fuzz_read(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const len = smith.slice(&input);
    try expect_same(input[0..len]);
    // The same octets mapped onto the alphabet, so short inputs reach "%2e" and the dot-segments.
    var mapped: [fuzz_input_len_max]u8 = undefined;
    for (input[0..len], mapped[0..len]) |octet, *out| out.* = alphabet[octet % alphabet.len];
    try expect_same(mapped[0..len]);
}

test "fuzz: the one pass refuses and records what the checks it replaced do" {
    try testing.fuzz({}, fuzz_read, .{ .corpus = &.{
        core.fuzz.input("/repos/v1/v1/issues?state=open"),
        core.fuzz.input("/a/%2e%2E/b"),
        core.fuzz.input("/a/%2F/b"),
        core.fuzz.input("?x"),
        core.fuzz.input("/a/./b/../c//d"),
    } });
    try core.fuzz.sweep(fuzz_read, null);
}

test "every target of up to five octets of the alphabet reads as the replaced checks read it" {
    var target: [exhaustive_len_max]u8 = undefined;
    for (0..exhaustive_len_max + 1) |len| {
        var count: usize = 1;
        for (0..len) |_| count *= alphabet.len;
        for (0..count) |number| {
            var rest = number;
            for (target[0..len]) |*octet| {
                octet.* = alphabet[rest % alphabet.len];
                rest /= alphabet.len;
            }
            try expect_same(target[0..len]);
        }
    }
}

// The checks that the one pass replaced, as router_match.zig held them at 6f9ddaf6, with decision
// 122's amendment of 2026-10-29.

fn old_path_of(target: []const u8) ?[]const u8 {
    // INV-8: `path_len_max` bounds the octets that one match reads.
    if (target.len > constants.path_len_max) return null;
    // RFC 9110 §4.2.3: an empty path is "/". An h11 absolute-form target with an empty path
    // and a query gives the query alone (`Request.path`), so its path is the root.
    if (target.len > 0 and target[0] == query_start) return router_pattern.root;
    // RFC 9110 §4.1: absolute-path = 1*( "/" segment ). So "*" (RFC 9112 §3.2.4) and the "" of
    // a CONNECT request match nothing.
    if (target.len == 0 or target[0] != router_pattern.separator) return null;
    var segment_first: usize = 1;
    for (target[1..], 1..) |octet, index| {
        // RFC 3986 §3.3: the first "?" ends the path, and RFC 9112 §3.2.1, RFC 9113 §8.3.1 and
        // RFC 9114 §4.3.1 put the query after it.
        if (octet == query_start) return old_path_end(target[0..index], segment_first);
        if (octet == router_pattern.separator) {
            if (!old_segment_matches(target[segment_first..index])) return null;
            segment_first = index + 1;
            continue;
        }
        // RFC 3986 §3.3: segment = *pchar, and a pchar may be pct-encoded (§2.1), which the walk
        // decodes (decision 127).
        if (!old_path_octet(octet)) return null;
    }
    return old_path_end(target, segment_first);
}

/// Whether `octet` may stand in a path that a route matches: a pchar, or the "%" of a pct-encoded
/// octet (RFC 3986 §2.1, §3.3).
fn old_path_octet(octet: u8) bool {
    return router_pattern.path_octets[octet] or octet == percent_sign;
}

/// `path`, or null when its last segment matches no route.
fn old_path_end(path: []const u8, segment_first: usize) ?[]const u8 {
    assert(segment_first > 0 and segment_first <= path.len);
    // Decision 122: the path "/" is the root, with no segment.
    if (path.len == 1) return path;
    // Decision 122 as amended on 2026-10-29: the last segment may be empty, as in "/a/".
    if (segment_first == path.len) return path;
    if (!old_segment_matches(path[segment_first..])) return null;
    return path;
}

/// Whether a route can match `segment`, which is not the root's.
fn old_segment_matches(segment: []const u8) bool {
    // Decision 122: an empty segment matches no route, though RFC 3986 §3.3 allows one.
    if (segment.len == 0) return false;
    // RFC 3986 §3.3, §6.2.2.3: "." and ".." are dot-segments, which match no route. §6.2.2.2:
    // "%2E" is ".", so an encoded dot-segment matches none either.
    if (old_is_dot_segment(segment)) return false;
    // RFC 3986 §7.3: a decoded "/" or "\\" would let a parameter carry a path of its own, such
    // as "../x", past the check of dot-segments, and a NUL ends a C string early. So a segment
    // that encodes one matches no route (the owner's ruling of 2026-10-25).
    return !old_encodes_refused_octet(segment);
}

/// Whether `segment` holds a "%" whose two hex digits name "/", "\\" or NUL.
fn old_encodes_refused_octet(segment: []const u8) bool {
    var index: usize = 0;
    // Bounded: each pass takes one octet of the segment, or three for an encoded one.
    while (index < segment.len) {
        const octet = percent.decoded_at(segment, index) orelse {
            index += 1;
            continue;
        };
        if (octet == '/' or octet == '\\' or octet == 0) return true;
        index += percent.encoded_len;
    }
    return false;
}

/// Whether `segment` decodes to "." or "..".
fn old_is_dot_segment(segment: []const u8) bool {
    var dots: usize = 0;
    var index: usize = 0;
    // Bounded: each pass takes one octet of the segment, or three for an encoded dot.
    while (index < segment.len) {
        if (segment[index] == '.') {
            index += 1;
        } else if (std.ascii.startsWithIgnoreCase(segment[index..], "%2e")) {
            index += percent.encoded_len;
        } else return false;
        dots += 1;
    }
    return dots > 0 and dots <= old_dot_segment_len_max;
}

/// The dots of the longer dot-segment, ".." (RFC 3986 §3.3).
const old_dot_segment_len_max = 2;
