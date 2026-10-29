//! The checks on the pattern of a route (decision 122, design §8 step 21e). They run at compile
//! time. A pattern that fails one of them matches no path, so the table does not compile.
//!
//! A segment of a pattern is a literal, a parameter, or the wildcard. A parameter is ":" and the
//! parameter's name, and it matches one segment of a path. `match` writes the segment as the
//! parameter's value. The wildcard is the segment "*", which is the last segment of a pattern. It
//! matches one segment or more, and `match` writes the rest of the path as the value of the name
//! "*" (decision 122 ruling 6).
//!
//! A pattern is checked in this order (invariant 7):
//!   1. It starts with "/", or `pattern_not_absolute`. The pattern "/" alone is the root, with no
//!      segment.
//!   2. Each segment, from the first, is checked in this order:
//!      1. not empty, but for the last segment, or `segment_empty`;
//!      2. not "." or "..", or `segment_dot`;
//!      3. for the wildcard: it is the last segment, or `wildcard_not_last`;
//!      4. for a parameter: a name follows the ":", or `parameter_unnamed`, and each octet of the
//!         name is an octet of `name_octets`, or `parameter_name_invalid`;
//!      5. for a literal: each octet, from the first, is not "%", or `segment_encoded`, and is an
//!         octet of `path_octets`, or `octet_outside_path`;
//!      6. for a parameter or the wildcard: no earlier parameter of the pattern has the name, or
//!         `parameter_repeated`, and the pattern holds no more than `path_parameters_max`
//!         parameters, the wildcard included, or `parameters_too_many`.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// Why a pattern does not compile.
pub const Refusal = enum {
    pattern_not_absolute,
    segment_empty,
    segment_dot,
    segment_encoded,
    octet_outside_path,
    parameter_unnamed,
    parameter_name_invalid,
    parameter_repeated,
    parameters_too_many,
    wildcard_not_last,

    /// The sentence that the compile error writes after the refusal's name.
    pub fn reason(refusal: Refusal) []const u8 {
        return switch (refusal) {
            .pattern_not_absolute => "a pattern starts with \"/\" (RFC 9110 §4.1)",
            .segment_empty => "only the last segment of a pattern may be empty, as in \"/a/\"",
            .segment_dot => "a segment of a pattern is not \".\" or \"..\" (RFC 3986 §3.3)",
            .segment_encoded => "a pattern holds no \"%\", because a path with one matches no route (RFC 3986 §2.1)",
            .octet_outside_path => "each octet of a segment is a pchar other than \"%\" (RFC 3986 §3.3)",
            .parameter_unnamed => "a parameter has a name after its \":\"",
            .parameter_name_invalid => "a parameter name is 1*( ALPHA / DIGIT / \"_\" ), and a parameter is a whole segment",
            .parameter_repeated => "each parameter of a pattern has a name of its own",
            .parameters_too_many => "a pattern holds server.constants.path_parameters_max parameters at most",
            .wildcard_not_last => "the wildcard \"*\" is the last segment of its pattern",
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
        // RFC 3986 §2.2: sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
        //                           / "*" / "+" / "," / ";" / "=".
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

/// The octet that starts a parameter's segment. The name follows it.
pub const parameter_prefix = ':';
/// The segment that keys every parameter child in the trie, whatever its name: two routes may
/// name one position differently (decision 129).
pub const parameter_key: []const u8 = &.{parameter_prefix};

/// The segment of the wildcard, and the name that `match` binds the rest of the path to.
pub const wildcard = "*";

/// The octets of a parameter's name: `1*( ALPHA / DIGIT / "_" )` (decision 122).
pub const name_octets: [std.math.maxInt(u8) + 1]bool = build: {
    var table: [std.math.maxInt(u8) + 1]bool = undefined;
    for (&table, 0..) |*allowed, octet| allowed.* = std.ascii.isAlphanumeric(octet) or octet == '_';
    break :build table;
};

/// Whether `segment`, which `refusal_of` passed, is a parameter.
pub fn is_parameter(segment: []const u8) bool {
    return segment.len > 0 and segment[0] == parameter_prefix;
}

/// The name of the parameter `segment`.
pub fn parameter_name(segment: []const u8) []const u8 {
    assert(is_parameter(segment));
    return segment[1..];
}

/// Whether `segment` is the wildcard. A segment that holds "*" and other octets is a literal.
pub fn is_wildcard(segment: []const u8) bool {
    return std.mem.eql(u8, segment, wildcard);
}

/// The name that `match` writes for `segment`: the parameter's name, `wildcard` for the
/// wildcard, or null for a literal.
pub fn binding_name(segment: []const u8) ?[]const u8 {
    if (is_parameter(segment)) return parameter_name(segment);
    if (is_wildcard(segment)) return wildcard;
    return null;
}

/// The verdict on a pattern, or null when the pattern can match a path. Comptime-only.
pub fn refusal_of(comptime pattern: []const u8) ?Refusal {
    // RFC 9110 §4.1: absolute-path = 1*( "/" segment ), and a path that does not start with "/"
    // matches no route.
    if (pattern.len == 0 or pattern[0] != separator) return .pattern_not_absolute;
    if (std.mem.eql(u8, pattern, root)) return null;
    var names: [constants.path_parameters_max][]const u8 = undefined;
    var names_count: usize = 0;
    var segments = std.mem.splitScalar(u8, pattern[1..], separator);
    // Bounded: the pattern holds one segment for each "/", and the pass after the last one ends.
    for (0..segments_count(pattern) + 1) |_| {
        const segment = segments.next() orelse return null;
        if (segment_refusal(segment, segments.peek() == null)) |refusal| return refusal;
        const name = binding_name(segment) orelse continue;
        if (names_refusal(names[0..names_count], name)) |refusal| return refusal;
        names[names_count] = name;
        names_count += 1;
    }
    unreachable;
}

fn segment_refusal(comptime segment: []const u8, comptime last: bool) ?Refusal {
    // Decision 122 as amended on 2026-10-29: only the last segment may be empty. A path with an
    // empty segment elsewhere matches no route, though RFC 3986 §3.3 allows one. RFC 3986 §6.2.4
    // counts "/a/" equal to "/a" only when the server says so, so a pattern may end in "/".
    if (segment.len == 0) return if (last) null else .segment_empty;
    // RFC 3986 §3.3: "." and ".." are dot-segments, and a path with one matches no route.
    if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return .segment_dot;
    // Decision 122 ruling 6: the wildcard matches the rest of the path, so no segment follows it.
    if (is_wildcard(segment)) return if (last) null else .wildcard_not_last;
    if (is_parameter(segment)) return name_refusal(parameter_name(segment));
    return literal_refusal(segment);
}

fn literal_refusal(comptime segment: []const u8) ?Refusal {
    for (segment) |octet| {
        // RFC 3986 §2.1: "%" starts a pct-encoded octet, and a path with one matches no route.
        if (octet == '%') return .segment_encoded;
        // RFC 3986 §3.3: segment = *pchar.
        if (!path_octets[octet]) return .octet_outside_path;
    }
    return null;
}

fn name_refusal(comptime name: []const u8) ?Refusal {
    // Decision 122: a program reads a parameter by its name.
    if (name.len == 0) return .parameter_unnamed;
    for (name) |octet| {
        // Decision 122: a name is 1*( ALPHA / DIGIT / "_" ), and a parameter is a whole segment.
        if (!name_octets[octet]) return .parameter_name_invalid;
    }
    return null;
}

fn names_refusal(comptime names: []const []const u8, comptime name: []const u8) ?Refusal {
    assert(names.len <= constants.path_parameters_max);
    for (names) |held| {
        // Decision 122: `get` of the name would find two values.
        if (std.mem.eql(u8, held, name)) return .parameter_repeated;
    }
    // Decision 122 ruling 10: `path_parameters_max` sizes `PathParameters`, and the wildcard
    // fills one entry of it.
    if (names.len == constants.path_parameters_max) return .parameters_too_many;
    return null;
}

/// How many segments `pattern` holds: none for the root. Comptime-only. The loop reads each
/// octet with no call to `std.mem.count`, whose search costs many comptime branches.
pub fn segments_count(comptime pattern: []const u8) usize {
    assert(pattern.len > 0 and pattern[0] == separator);
    if (std.mem.eql(u8, pattern, root)) return 0;
    var count: usize = 0;
    for (pattern) |octet| {
        if (octet == separator) count += 1;
    }
    return count;
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
