//! The checks on the pattern of a route (decision 122, design §8 step 21e). They run at compile
//! time. A pattern that fails one of them matches no path, so the table does not compile.
//!
//! A pattern is checked in this order (invariant 7):
//!   1. It starts with "/", or `pattern_not_absolute`. The pattern "/" alone is the root, with no
//!      segment.
//!   2. Each segment, from the first, is checked in this order:
//!      1. not empty, or `segment_empty`;
//!      2. not "." or "..", or `segment_dot`;
//!      3. not a parameter or a wildcard, or `segment_unsupported`, until steps 21e.5 and 21e.6;
//!      4. each octet, from the first, is not "%", or `segment_encoded`, and is an octet of
//!         `path_octets`, or `octet_outside_path`.
const std = @import("std");
const assert = std.debug.assert;

/// Why a pattern does not compile.
pub const Refusal = enum {
    pattern_not_absolute,
    segment_empty,
    segment_dot,
    segment_encoded,
    octet_outside_path,
    segment_unsupported,

    /// The sentence that the compile error writes after the refusal's name.
    pub fn reason(refusal: Refusal) []const u8 {
        return switch (refusal) {
            .pattern_not_absolute => "a pattern starts with \"/\" (RFC 9110 §4.1)",
            .segment_empty => "a segment of a pattern is not empty, and only the pattern \"/\" ends in \"/\"",
            .segment_dot => "a segment of a pattern is not \".\" or \"..\" (RFC 3986 §3.3)",
            .segment_encoded => "a pattern holds no \"%\", because a path with one matches no route (RFC 3986 §2.1)",
            .octet_outside_path => "each octet of a segment is a pchar other than \"%\" (RFC 3986 §3.3)",
            .segment_unsupported => "a segment that starts with \":\", or the segment \"*\", has no meaning yet",
        };
    }
};

/// The octets that a segment of a path matches a route with: RFC 3986 §3.3's `pchar`, which is
/// `unreserved / pct-encoded / sub-delims / ":" / "@"`, other than "%". http's `uri.zig` holds
/// the same classes, and to share them would add a public name.
pub const path_octets: [std.math.maxInt(u8) + 1]bool = build: {
    var table: [std.math.maxInt(u8) + 1]bool = undefined;
    for (&table, 0..) |*allowed, octet| allowed.* = is_path_octet(octet);
    break :build table;
};

fn is_path_octet(octet: u8) bool {
    return switch (octet) {
        // RFC 3986 §2.3: unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~".
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_', '~' => true,
        // RFC 3986 §2.2: sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=".
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        // RFC 3986 §3.3: pchar adds ":" and "@".
        ':', '@' => true,
        else => false,
    };
}

/// The separator between the segments of a path (RFC 3986 §3.3).
pub const separator = '/';

/// The pattern of the root, which matches the path "/" alone.
pub const root = "/";

/// The verdict on a pattern, or null when the pattern can match a path. Comptime-only.
pub fn refusal_of(comptime pattern: []const u8) ?Refusal {
    // RFC 9110 §4.1: absolute-path = 1*( "/" segment ), and a path that does not start with "/"
    // matches no route.
    if (pattern.len == 0 or pattern[0] != separator) return .pattern_not_absolute;
    if (std.mem.eql(u8, pattern, root)) return null;
    var segments = std.mem.splitScalar(u8, pattern[1..], separator);
    // Bounded: the pattern holds one segment for each "/", and the pass after the last one ends.
    for (0..segments_count(pattern) + 1) |_| {
        const segment = segments.next() orelse return null;
        if (segment_refusal(segment)) |refusal| return refusal;
    }
    unreachable;
}

fn segment_refusal(comptime segment: []const u8) ?Refusal {
    // Decision 122: a path with an empty segment other than the root's matches no route, though
    // RFC 3986 §3.3 allows one.
    if (segment.len == 0) return .segment_empty;
    // RFC 3986 §3.3: "." and ".." are dot-segments, and a path with one matches no route.
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return .segment_dot;
    // Design §8 steps 21e.5 and 21e.6 give a meaning to a parameter and to a wildcard.
    if (segment[0] == ':' or std.mem.eql(u8, segment, "*")) return .segment_unsupported;
    for (segment) |octet| {
        // RFC 3986 §2.1: "%" starts a pct-encoded octet, and a path with one matches no route.
        if (octet == '%') return .segment_encoded;
        // RFC 3986 §3.3: segment = *pchar.
        if (!path_octets[octet]) return .octet_outside_path;
    }
    return null;
}

/// How many segments `pattern` holds: none for the root. Comptime-only.
pub fn segments_count(comptime pattern: []const u8) usize {
    assert(pattern.len > 0 and pattern[0] == separator);
    if (std.mem.eql(u8, pattern, root)) return 0;
    return std.mem.count(u8, pattern, &.{separator});
}

/// Whether a value of `T` is text: a slice of octets, or a pointer to an array of them.
pub fn is_text(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |pointer| switch (pointer.size) {
            .slice => pointer.child == u8,
            .one => @typeInfo(pointer.child) == .array and @typeInfo(pointer.child).array.child == u8,
            else => false,
        },
        else => false,
    };
}
