//! The one pass over a request's path that `match` makes before its walk (decision 122, design §8
//! step 13h). It reads each octet of the path once (INV-32), decides each one through a table of
//! classes that the compiler builds, and records where the first segments end and which of them
//! hold a "%". The walk then reads each segment's end from the record, so it searches for no "/"
//! and no "%". A path that ends in "/" has an empty last segment, which the record holds too. The pass refuses what `router_match.zig`'s header, rules 3 to 7, refuses.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const router_pattern = @import("router_pattern.zig");
const percent = @import("http").uri_percent;

/// The octet that ends a path and starts its query (RFC 3986 §3.3, §3.4).
const query_start = '?';
/// The octet that starts a percent-encoded octet (RFC 3986 §2.1).
const percent_sign = '%';

/// What one octet of a path is to the pass.
const Class = enum(u8) { pchar, percent, separator, query, refused };

/// Each octet's class: RFC 3986 §3.3's `pchar` but "%", the "%" of a pct-encoded octet, the "/"
/// between segments, the "?" that ends the path, and every other octet, which no route matches.
const classes: [std.math.maxInt(u8) + 1]Class = build: {
    var table: [std.math.maxInt(u8) + 1]Class = undefined;
    for (&table, 0..) |*class, octet| class.* = if (router_pattern.path_octets[octet]) .pchar else .refused;
    table[percent_sign] = .percent;
    table[router_pattern.separator] = .separator;
    table[query_start] = .query;
    break :build table;
};

comptime {
    // The three octets with classes of their own are not pchars.
    assert(!router_pattern.path_octets[percent_sign]);
    assert(!router_pattern.path_octets[router_pattern.separator]);
    assert(!router_pattern.path_octets[query_start]);
    // A segment's end fits a u16.
    assert(constants.path_len_max <= std.math.maxInt(u16));
}

/// The path of a target and the segments that the walk reads: the end of each of the first
/// `capacity` segments, and whether each holds a "%". A walk reads at most `depth_max` segments
/// before a wildcard takes the rest, so `match` passes `depth_max + 1`.
pub fn Segments(comptime capacity: usize) type {
    comptime assert(capacity > 0 and capacity <= @bitSizeOf(u64));
    return struct {
        path: []const u8 = router_pattern.root,
        /// One past the last octet of each of the first `capacity` segments, in `path`.
        ends: [capacity]u16 = undefined,
        /// Bit `i` is set when segment `i` holds a "%".
        encoded: u64 = 0,
        /// The segments of `path`, the ones past `capacity` included.
        count: usize = 0,
    };
}

/// Reads the path of `target`, before its query, into `segments`. False when the path matches
/// no route.
pub fn read(comptime capacity: usize, target: []const u8, segments: *Segments(capacity)) bool {
    segments.* = .{};
    // INV-8: `path_len_max` bounds the octets that one match reads.
    if (target.len > constants.path_len_max) return false;
    // RFC 9110 §4.2.3: an empty path is "/". An h11 absolute-form target with an empty path
    // and a query gives the query alone (`Request.path`), so its path is the root.
    if (target.len > 0 and target[0] == query_start) return true;
    // RFC 9110 §4.1: absolute-path = 1*( "/" segment ). So "*" (RFC 9112 §3.2.4) and the "" of
    // a CONNECT request match nothing.
    if (target.len == 0 or target[0] != router_pattern.separator) return false;
    var first: usize = 1;
    var encoded = false;
    var end = target.len;
    for (target[1..], 1..) |octet, index| switch (classes[octet]) {
        .pchar => {},
        // RFC 3986 §2.1: a pchar may be pct-encoded, which the walk decodes (decision 127).
        .percent => encoded = true,
        .separator => {
            if (!take(capacity, segments, target[first..index], index, encoded, false)) return false;
            first = index + 1;
            encoded = false;
        },
        // RFC 3986 §3.3: the first "?" ends the path, and RFC 9112 §3.2.1, RFC 9113 §8.3.1 and
        // RFC 9114 §4.3.1 put the query after it.
        .query => {
            end = index;
            break;
        },
        // RFC 3986 §3.3: segment = *pchar.
        .refused => return false,
    };
    // Decision 122: the path "/" is the root, with no segment.
    if (end == 1) return true;
    if (!take(capacity, segments, target[first..end], end, encoded, true)) return false;
    segments.path = target[0..end];
    return true;
}

/// Records `segment`, which ends at `end` in the target, or refuses it. `last` says it is the
/// path's last segment.
fn take(comptime capacity: usize, segments: *Segments(capacity), segment: []const u8, end: usize, encoded: bool, last: bool) bool {
    if (!segment_matches(segment, encoded, last)) return false;
    if (segments.count < capacity) {
        segments.ends[segments.count] = @intCast(end);
        if (encoded) segments.encoded |= @as(u64, 1) << @intCast(segments.count);
    }
    segments.count += 1;
    return true;
}

/// Whether a route can match `segment`, which is not the root's. `encoded` says it holds a "%",
/// and `last` says it is the path's last segment.
fn segment_matches(segment: []const u8, encoded: bool, last: bool) bool {
    // Decision 122 as amended on 2026-10-29: only the last segment may be empty, as in "/a/".
    // RFC 3986 §3.3 allows an empty segment anywhere.
    if (segment.len == 0) return last;
    // RFC 3986 §3.3: "." and ".." are dot-segments, which match no route.
    if (!encoded) return !all_dots(segment);
    // RFC 3986 §6.2.2.2: "%2E" is ".", so an encoded dot-segment matches none either.
    if (is_dot_segment(segment)) return false;
    // RFC 3986 §7.3: a decoded "/" or "\\" would let a parameter carry a path of its own, such
    // as "../x", past the check of dot-segments, and a NUL ends a C string early. So a segment
    // that encodes one matches no route (the owner's ruling of 2026-10-25).
    return !encodes_refused_octet(segment);
}

/// Whether `segment`, which holds no "%", is "." or "..".
fn all_dots(segment: []const u8) bool {
    if (segment.len > dot_segment_len_max) return false;
    for (segment) |octet| {
        if (octet != '.') return false;
    }
    return true;
}

/// Whether `segment` holds a "%" whose two hex digits name "/", "\\" or NUL.
fn encodes_refused_octet(segment: []const u8) bool {
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
fn is_dot_segment(segment: []const u8) bool {
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
    return dots > 0 and dots <= dot_segment_len_max;
}

/// The dots of the longer dot-segment, ".." (RFC 3986 §3.3).
const dot_segment_len_max = 2;

test {
    _ = @import("router_path_test.zig");
}
