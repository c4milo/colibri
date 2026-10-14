//! The route tables of the probes. Each table of `compile_time.zig` has a name that `build.zig`
//! lists, and a path that one of its routes matches.
const std = @import("std");
const http = @import("http");

pub const Entry = struct { http.method.Standard, []const u8, u16 };

/// One route.
pub const one = .{ .entries = literals(1, ""), .path = "/r000" };
/// 256 literal siblings at the root, and `/:x` beside them.
pub const literals_256_parameter = .{ .entries = literals(256, "/:x"), .path = "/r255" };
/// 512 literal siblings at the root, and `/:x` beside them.
pub const literals_512_parameter = .{ .entries = literals(512, "/:x"), .path = "/r511" };
/// 512 literal siblings at the root, and the literal `/zzz` beside them.
pub const literals_512_literal = .{ .entries = literals(512, "/zzz"), .path = "/zzz" };
/// The table of 256 routes of `src/server/router/router_test.zig`.
pub const router_test_256 = .{ .entries = large_table, .path = large_table[0][1] };
/// Five routes for each of ten resources.
pub const resources_50 = .{ .entries = resources(), .path = "/api/v1/users/7" };
/// 338 routes of mixed forms: literals, parameters, wildcards, HEAD and OPTIONS.
pub const mixed_338 = .{ .entries = mixed(), .path = "/users/b" };
/// 256 routes `/rNNN/:id`.
pub const named_256 = .{ .entries = named(256), .path = "/r255/7" };

/// "r" and three decimal digits.
pub fn literal(comptime index: usize) [4]u8 {
    var out: [4]u8 = "r000".*;
    out[1] = '0' + @as(u8, @intCast(index / 100 % 10));
    out[2] = '0' + @as(u8, @intCast(index / 10 % 10));
    out[3] = '0' + @as(u8, @intCast(index % 10));
    return out;
}

/// `count` literal siblings at the root, then `extra` when it is not empty.
pub fn literals(comptime count: usize, comptime extra: []const u8) [count + @intFromBool(extra.len > 0)]Entry {
    @setEvalBranchQuota(100_000);
    var table: [count + @intFromBool(extra.len > 0)]Entry = undefined;
    for (0..count) |index| table[index] = .{ .get, "/" ++ literal(index), @intCast(index) };
    if (extra.len > 0) table[count] = .{ .get, extra, @intCast(count) };
    return table;
}

const resource_names = [_][]const u8{ "users", "posts", "comments", "orders", "items", "carts", "tags", "files", "teams", "events" };

fn resources() [resource_names.len * 5]Entry {
    var table: [resource_names.len * 5]Entry = undefined;
    for (resource_names, 0..) |resource, index| {
        const collection = "/api/v1/" ++ resource;
        const member = collection ++ "/:id";
        table[index * 5 + 0] = .{ .get, collection, index * 5 + 0 };
        table[index * 5 + 1] = .{ .post, collection, index * 5 + 1 };
        table[index * 5 + 2] = .{ .get, member, index * 5 + 2 };
        table[index * 5 + 3] = .{ .put, member, index * 5 + 3 };
        table[index * 5 + 4] = .{ .delete, member, index * 5 + 4 };
    }
    return table;
}

fn named(comptime count: usize) [count]Entry {
    @setEvalBranchQuota(100_000);
    var table: [count]Entry = undefined;
    for (0..count) |index| table[index] = .{ .get, "/" ++ literal(index) ++ "/:id", @intCast(index) };
    return table;
}

const words = [_][]const u8{ "zeta", "a", "mm", "users", "b", "posts", "c4", "x", "yy", "longer_word", "q", "ab" };

fn mixed() [2 + words.len * (words.len * 2 + 4)]Entry {
    @setEvalBranchQuota(1_000_000);
    var entries: []const Entry = &.{ .{ .get, "/", 0 }, .{ .options, "/", 1 } };
    for (words) |first| {
        for (words) |second| {
            entries = entries ++ [_]Entry{.{ .get, "/" ++ first ++ "/" ++ second, @intCast(entries.len) }};
            entries = entries ++ [_]Entry{.{ .put, "/" ++ first ++ "/" ++ second, @intCast(entries.len) }};
        }
        entries = entries ++ [_]Entry{.{ .get, "/" ++ first ++ "/:id", @intCast(entries.len) }};
        entries = entries ++ [_]Entry{.{ .get, "/" ++ first ++ "/*", @intCast(entries.len) }};
        entries = entries ++ [_]Entry{.{ .head, "/" ++ first, @intCast(entries.len) }};
        entries = entries ++ [_]Entry{.{ .get, "/" ++ first, @intCast(entries.len) }};
    }
    return entries[0..entries.len].*;
}

/// The routes of the table of 256 routes of `src/server/router/router_test.zig`: each one has a
/// pattern of `large_segments` segments of `large_segment_len` octets. The last route names PUT,
/// and each other route names GET.
const large_routes = 256;
const large_segments = 4;
const large_segment_len = 15;
const decimal_radix = 10;

/// A segment of `large_segment_len` octets: "/s", then the route and the segment in decimal.
fn large_segment(comptime index: usize, comptime segment: usize) [large_segment_len + 1]u8 {
    const prefix = "/s";
    var octets: [large_segment_len + 1]u8 = @splat('0');
    octets[0..prefix.len].* = prefix.*;
    var rest = index * decimal_radix + segment;
    var at = octets.len;
    for (prefix.len..octets.len) |_| {
        at -= 1;
        octets[at] = '0' + @as(u8, @intCast(rest % decimal_radix));
        rest /= decimal_radix;
    }
    return octets;
}

fn large_pattern(comptime index: usize) []const u8 {
    var pattern: []const u8 = "";
    for (0..large_segments) |segment| pattern = pattern ++ large_segment(index, segment);
    return pattern;
}

const large_table: [large_routes]Entry = build: {
    @setEvalBranchQuota(large_routes * large_segments * large_segment_len * large_segment_len);
    var table: [large_routes]Entry = undefined;
    for (&table, 0..) |*entry, index| entry.* = .{ if (index == large_routes - 1) .put else .get, large_pattern(index), index };
    break :build table;
};
