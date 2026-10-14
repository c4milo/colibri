//! The tests of each check that refuses a table (decision 122, design §8 step 21e). Each test
//! calls a check at compile time on a refused case and on a valid case beside it, so a test
//! fails when a check goes and when a check refuses too much. `zig build routes-check` shows
//! that `server.routes` turns each refusal into a compile error.
const std = @import("std");
const http = @import("http");
const routes_pattern = @import("routes_pattern.zig");
const routes_method = @import("routes_method.zig");
const routes_trie = @import("routes_trie.zig");

const testing = std.testing;

fn expect_pattern(comptime expected: ?routes_pattern.Refusal, comptime pattern: []const u8) !void {
    try testing.expectEqual(expected, comptime routes_pattern.refusal_of(pattern));
}

fn expect_method(comptime expected: ?routes_method.Refusal, comptime method: anytype) !void {
    try testing.expectEqual(expected, comptime routes_method.refusal_of(method));
}

fn expect_table(comptime expected: ?routes_trie.Reason, comptime table: anytype) !void {
    const refusal = comptime routes_trie.refusal_of(table);
    if (expected) |reason| {
        const refused = refusal orelse return error.TestExpectedRefusal;
        try testing.expectEqual(reason, refused.reason);
    } else {
        try testing.expectEqual(null, refusal);
    }
}

test "refusal 1, pattern_not_absolute: RFC 9110 §4.1, a pattern starts with \"/\"" {
    try expect_pattern(.pattern_not_absolute, "users");
    try expect_pattern(.pattern_not_absolute, "");
    try expect_pattern(.pattern_not_absolute, "*");
    try expect_pattern(null, "/users");
    try expect_pattern(null, "/");
}

test "refusal 2, segment_empty: a pattern holds no empty segment but the root's" {
    try expect_pattern(.segment_empty, "/a//b");
    try expect_pattern(.segment_empty, "//a");
    try expect_pattern(.segment_empty, "/a/");
    try expect_pattern(.segment_empty, "//");
    try expect_pattern(null, "/a/b");
}

test "refusal 3, segment_dot: RFC 3986 §3.3, a pattern holds no dot-segment" {
    try expect_pattern(.segment_dot, "/a/./b");
    try expect_pattern(.segment_dot, "/..");
    try expect_pattern(.segment_dot, "/.");
    try expect_pattern(null, "/...");
    try expect_pattern(null, "/.well-known");
    try expect_pattern(null, "/a.b");
}

test "refusal 4, segment_encoded: RFC 3986 §2.1, a pattern holds no \"%\"" {
    try expect_pattern(.segment_encoded, "/caf%C3%A9");
    try expect_pattern(.segment_encoded, "/%");
    try expect_pattern(null, "/cafe");
}

test "refusal 5, octet_outside_path: RFC 3986 §3.3, a segment holds pchar alone" {
    try expect_pattern(.octet_outside_path, "/a b");
    try expect_pattern(.octet_outside_path, "/a?b");
    try expect_pattern(.octet_outside_path, "/a#b");
    try expect_pattern(.octet_outside_path, "/caf\xc3\xa9");
    try expect_pattern(.octet_outside_path, "/a\\b");
    // Each class of pchar but "%": unreserved, sub-delims, ":" and "@".
    try expect_pattern(null, "/aZ09-._~");
    try expect_pattern(null, "/!$&'()*+,;=");
    try expect_pattern(null, "/a:b@c");
}

test "decision 122: a parameter or a wildcard does not compile until steps 21e.5 and 21e.6" {
    try expect_pattern(.segment_unsupported, "/users/:id");
    try expect_pattern(.segment_unsupported, "/:");
    try expect_pattern(.segment_unsupported, "/files/*");
    // A segment that holds "*" or ":" after its first octet is a literal.
    try expect_pattern(null, "/a*b");
    try expect_pattern(null, "/**");
    try expect_pattern(null, "/a:b");
}

test "refusal 11, method_unknown: an enum literal names a member of http.method.Standard" {
    try expect_method(.method_unknown, .gte);
    try expect_method(.method_unknown, .GET);
    try expect_method(.method_unknown, .patch);
    try expect_method(null, .get);
    try expect_method(null, .trace);
}

test "refusal 12, method_not_token: RFC 9110 §9.1, a method is a token" {
    try expect_method(.method_not_token, "");
    try expect_method(.method_not_token, "GET ");
    try expect_method(.method_not_token, "PA(TCH");
    try expect_method(null, "PATCH");
    try expect_method(null, "M-SEARCH");
}

test "refusal 13, method_standard_as_token: a method of the eight is written as its member" {
    try expect_method(.method_standard_as_token, "GET");
    try expect_method(.method_standard_as_token, "OPTIONS");
    // RFC 9110 §9.1: the token is case-sensitive, so "get" is a method other than GET.
    try expect_method(null, "get");
    try expect_method(null, "Get");
}

test "refusal 14, method_connect: RFC 9110 §9.3.6 and decision 19, a CONNECT has no path" {
    try expect_method(.method_connect, .connect);
    try expect_method(.method_connect, http.method.Standard.connect);
    try expect_method(.method_standard_as_token, "CONNECT");
    try expect_method(null, .options);
}

test "refusal 15, method_type: a method is an enum literal, a Standard or a token" {
    try expect_method(.method_type, 42);
    try expect_method(.method_type, 'G');
    try expect_method(.method_type, true);
    try expect_method(.method_type, @as([]const u16, &.{}));
    // Decision 122 ruling 4: a value of `http.method.Standard` names its method.
    try expect_method(null, http.method.Standard.get);
    try expect_method(null, http.method.Standard.delete);
    try expect_method(null, @as([]const u8, "PATCH"));
}

test "decision 122: each method's token and its place in an Allow value" {
    try testing.expectEqualStrings("GET", comptime routes_method.token_of(.get));
    try testing.expectEqualStrings("OPTIONS", comptime routes_method.token_of(http.method.Standard.options));
    try testing.expectEqualStrings("PATCH", comptime routes_method.token_of("PATCH"));
    try testing.expectEqual(0, comptime routes_method.rank_of(.get));
    try testing.expectEqual(7, comptime routes_method.rank_of(.trace));
    try testing.expectEqual(8, comptime routes_method.rank_of("PATCH"));
}

const Route = enum { one, two };

test "refusal 16, table_empty: a table holds one route at least" {
    try expect_table(.table_empty, .{});
    try expect_table(null, .{.{ .get, "/", .one }});
}

test "refusal 17, entry_shape: an entry is a tuple of a method, a pattern and a value" {
    try expect_table(.entry_shape, .{.{ .get, "/a" }});
    try expect_table(.entry_shape, .{.{ .get, "/a", .one, .two }});
    try expect_table(.entry_shape, .{.{ .get, 42, .one }});
    try expect_table(.entry_shape, .{ .get, "/a", .one });
    try expect_table(null, .{.{ .get, "/a", .one }});
    try expect_table(null, [_]struct { http.method.Standard, []const u8, Route }{.{ .get, "/a", .one }});
}

test "refusal 18, route_repeated: two routes name one method and one path" {
    try expect_table(.route_repeated, .{ .{ .get, "/a", .one }, .{ .get, "/a", .two } });
    try expect_table(.route_repeated, .{ .{ .get, "/a", .one }, .{ http.method.Standard.get, "/a", .two } });
    try expect_table(.route_repeated, .{ .{ "PATCH", "/", .one }, .{ "PATCH", "/", .two } });
    try expect_table(null, .{ .{ .get, "/a", .one }, .{ .put, "/a", .two } });
    try expect_table(null, .{ .{ .get, "/a", .one }, .{ .get, "/a/a", .two } });
    try expect_table(null, .{ .{ "PATCH", "/", .one }, .{ "patch", "/", .two } });
}

test "decision 122: a table's checks run in order, and the first refusal names its entry" {
    // An entry's method is checked before its pattern, and the entries in table order.
    const refusal = comptime routes_trie.refusal_of(.{
        .{ .get, "/a", .one },
        .{ .gte, "a", .two },
        .{ .get, "b", .one },
    }).?;
    try testing.expectEqual(1, refusal.route);
    try testing.expectEqualStrings("a", refusal.pattern);
    try testing.expectEqual(routes_trie.Reason{ .method = .method_unknown }, refusal.reason);
    try expect_table(.{ .pattern = .pattern_not_absolute }, .{.{ .get, "a", .one }});
}

test "decision 122: the compile error names the entry, the refusal and its reason" {
    try testing.expectEqualStrings(
        "server.routes: route 1, \"/a//b\": segment_empty: a segment of a pattern is not empty, " ++
            "and only the pattern \"/\" ends in \"/\"",
        comptime routes_trie.message(.{ .route = 1, .pattern = "/a//b", .reason = .{ .pattern = .segment_empty } }),
    );
    try testing.expectEqualStrings(
        "server.routes: table_empty: a table holds one route at least",
        comptime routes_trie.message(.{ .route = 0, .pattern = "", .reason = .table_empty }),
    );
}
