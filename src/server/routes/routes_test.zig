//! The tests of `match` on tables that compile (decision 122, design §8 step 21e). Each table is a
//! constant, as a program declares one.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const routes = @import("routes.zig").routes;
const PathParameters = @import("../path_parameters.zig").PathParameters;
const constants = @import("../constants.zig");

const testing = std.testing;

const Route = enum { greeting, root, users, user_put, user_delete, user_patch, user_link };

const greetings = routes(Route, .{
    .{ .get, "/", .root },
    .{ .get, "/greeting", .greeting },
});

fn expect_found(table: anytype, expected: anytype, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    const result = table.match(method, path, &parameters);
    try testing.expect(result == .found);
    try testing.expectEqual(expected, result.found);
    try testing.expectEqual(0, parameters.count);
}

fn expect_not_found(table: anytype, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    try testing.expect(table.match(method, path, &parameters) == .not_found);
    try testing.expectEqual(0, parameters.count);
}

fn expect_allow(table: anytype, allow: []const u8, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    const result = table.match(method, path, &parameters);
    try testing.expect(result == .method_not_allowed);
    try testing.expectEqualStrings(allow, result.method_not_allowed);
}

test "RFC 9110 §4.2.3: a literal matches its whole segment, octet for octet and case-sensitively" {
    try expect_found(greetings, Route.greeting, "GET", "/greeting");
    try expect_not_found(greetings, "GET", "/greetings");
    try expect_not_found(greetings, "GET", "/greet");
    try expect_not_found(greetings, "GET", "/Greeting");
    try expect_not_found(greetings, "GET", "/greeting/");
    // A path deeper than every pattern matches nothing, at any depth.
    try expect_not_found(greetings, "GET", "/greeting/x");
    try expect_not_found(greetings, "GET", "/greeting" ** 64);
}

test "decision 122: a node's literals of each length are found, whatever the table's order" {
    const lengths = routes(u8, .{
        .{ .get, "/ccc", 3 },
        .{ .get, "/a", 1 },
        .{ .get, "/bb", 2 },
        .{ .get, "/ab", 4 },
        .{ .get, "/a/ccc", 5 },
        .{ .get, "/a/b", 6 },
    });
    inline for (.{ "/a", "/bb", "/ccc", "/ab", "/a/ccc", "/a/b" }, .{ 1, 2, 3, 4, 5, 6 }) |path, value| {
        try expect_found(lengths, @as(u8, value), "GET", path);
    }
    try expect_not_found(lengths, "GET", "/b");
    try expect_not_found(lengths, "GET", "/cc");
    try expect_not_found(lengths, "GET", "/a/bb");
}

test "RFC 3986 §3.3: the match stops at the first \"?\", and the query is not read" {
    try expect_found(greetings, Route.greeting, "GET", "/greeting?x=1");
    try expect_found(greetings, Route.greeting, "GET", "/greeting?q=a%20b");
    try expect_found(greetings, Route.greeting, "GET", "/greeting?");
    try expect_found(greetings, Route.root, "GET", "/?greeting");
    try expect_not_found(greetings, "GET", "/greet?ing");
}

test "RFC 9110 §4.1: the path \"/\" is the root, and a path that does not start with \"/\" matches nothing" {
    try expect_found(greetings, Route.root, "GET", "/");
    try expect_not_found(greetings, "GET", "");
    try expect_not_found(greetings, "GET", "*");
    try expect_not_found(greetings, "GET", "greeting");
    try expect_not_found(greetings, "GET", "?x");
    try expect_not_found(greetings, "GET", "//");
    try expect_not_found(greetings, "GET", "//greeting");
    // A table with no route at "/" does not match the root.
    try expect_not_found(routes(Route, .{.{ .get, "/greeting", .greeting }}), "GET", "/");
}

const users = routes(Route, .{
    .{ "PATCH", "/users/me", .user_patch },
    .{ .delete, "/users/me", .user_delete },
    .{ .get, "/users", .users },
    .{ "LINK", "/users/me", .user_link },
    .{ http.method.Standard.put, "/users/me", .user_put },
});

const users_reversed = routes(Route, .{
    .{ http.method.Standard.put, "/users/me", .user_put },
    .{ "LINK", "/users/me", .user_link },
    .{ .get, "/users", .users },
    .{ .delete, "/users/me", .user_delete },
    .{ "PATCH", "/users/me", .user_patch },
});

test "RFC 9110 §15.5.6: a known path and another method give the Allow value, in any table order" {
    inline for (.{ users, users_reversed }) |table| {
        // RFC 9110 §9.1's order, then the tokens by octets, joined by ", ".
        try expect_allow(table, "PUT, DELETE, LINK, PATCH", "GET", "/users/me");
        try expect_allow(table, "PUT, DELETE, LINK, PATCH", "POST", "/users/me?x");
        try expect_allow(table, "GET", "PUT", "/users");
        // RFC 9110 §9.1: the method is case-sensitive, so "put" is another method.
        try expect_allow(table, "PUT, DELETE, LINK, PATCH", "put", "/users/me");
        try expect_allow(table, "PUT, DELETE, LINK, PATCH", "patch", "/users/me");
        try expect_found(table, Route.user_put, "PUT", "/users/me");
        try expect_found(table, Route.user_delete, "DELETE", "/users/me");
        try expect_found(table, Route.user_patch, "PATCH", "/users/me");
        try expect_found(table, Route.user_link, "LINK", "/users/me");
        try expect_found(table, Route.users, "GET", "/users");
        // RFC 9110 §15.5.5: a path no route names is not found, whatever the method.
        try expect_not_found(table, "PUT", "/users/you");
        try expect_not_found(table, "GET", "/");
        try expect_not_found(table, "GET", "/user");
    }
}

fn greet() u8 {
    return 0;
}

fn part() u8 {
    return 1;
}

const Handler = *const fn () u8;

const Answer = struct { status: u16, content: []const u8 };

test "decision 122: a route's value is an enum, a pointer to a function or a struct" {
    const handlers = routes(Handler, .{
        .{ .get, "/greeting", greet },
        .{ .get, "/part", part },
    });
    var parameters: PathParameters = .{};
    const handler = handlers.match("GET", "/part", &parameters).found;
    try testing.expectEqual(@as(u8, 1), handler());
    const answers = routes(Answer, .{
        .{ .get, "/greeting", Answer{ .status = 200, .content = "hello" } },
        .{ .post, "/greeting", Answer{ .status = 201, .content = "made" } },
    });
    const answer = answers.match("POST", "/greeting", &parameters).found;
    try testing.expectEqual(@as(u16, 201), answer.status);
    try testing.expectEqualStrings("made", answer.content);
    try expect_found(greetings, Route.greeting, "GET", "/greeting");
}

test "decision 122: each match sets the count of parameters to 0 first" {
    var parameters: PathParameters = .{};
    parameters.names[0] = "id";
    parameters.values[0] = "42";
    inline for (.{ "/greeting", "/greetings", "*" }) |path| {
        parameters.count = 1;
        _ = greetings.match("GET", path, &parameters);
        try testing.expectEqual(0, parameters.count);
        try testing.expectEqual(null, parameters.get("id"));
    }
    parameters.count = 1;
    _ = users.match("GET", "/users/me", &parameters);
    try testing.expectEqual(0, parameters.count);
}

const Person = enum { user, posts, post };

const people = routes(Person, .{
    .{ .get, "/users/:id", .user },
    .{ .get, "/users/:id/posts", .posts },
    .{ .get, "/users/:id/posts/:post", .post },
});

test "decision 122: a parameter binds one segment, and its value is a slice of the path" {
    var parameters: PathParameters = .{};
    const one: []const u8 = "/users/42";
    try testing.expectEqual(.user, people.match("GET", one, &parameters).found);
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqualStrings("42", parameters.get("id").?);
    try testing.expectEqual(one.ptr + "/users/".len, parameters.get("id").?.ptr);
    try testing.expectEqual(null, parameters.get("post"));
    const two: []const u8 = "/users/42/posts/7";
    try testing.expectEqual(.post, people.match("GET", two, &parameters).found);
    try testing.expectEqual(2, parameters.count);
    try testing.expectEqualStrings("42", parameters.get("id").?);
    try testing.expectEqualStrings("7", parameters.get("post").?);
    try testing.expectEqual(two.ptr + "/users/42/posts/".len, parameters.get("post").?.ptr);
    try testing.expectEqual(.posts, people.match("GET", "/users/42/posts", &parameters).found);
    try testing.expectEqualStrings("42", parameters.get("id").?);
    // RFC 3986 §3.3: the checks of the path do not read the query.
    try testing.expectEqual(.user, people.match("GET", "/users/42?q=a%20b", &parameters).found);
    try testing.expectEqualStrings("42", parameters.get("id").?);
    try testing.expectEqual(.user, people.match("GET", "/users/42?a b#c", &parameters).found);
}

test "decision 122: a result other than found leaves no parameter" {
    var parameters: PathParameters = .{};
    // RFC 9110 §15.5.6: the walk reaches the leaf, and the method does not.
    try testing.expectEqualStrings("GET", people.match("PUT", "/users/42", &parameters).method_not_allowed);
    try testing.expectEqual(0, parameters.count);
    try testing.expectEqual(null, parameters.get("id"));
    // The walk binds `id`, and then a segment has no child.
    try testing.expect(people.match("GET", "/users/42/comments", &parameters) == .not_found);
    try testing.expectEqual(0, parameters.count);
    // The walk binds `id`, and then the node holds no leaf.
    const deep = routes(u8, .{.{ .get, "/users/:id/posts/all", 1 }});
    try testing.expect(deep.match("GET", "/users/42/posts", &parameters) == .not_found);
    try testing.expectEqual(0, parameters.count);
}

test "decision 122: each parameter takes the name of its own node" {
    const pairs = routes(u8, .{.{ .get, "/pairs/:left/:right", 1 }});
    var parameters: PathParameters = .{};
    try testing.expectEqual(1, pairs.match("GET", "/pairs/a/b", &parameters).found);
    try testing.expectEqualStrings("a", parameters.get("left").?);
    try testing.expectEqualStrings("b", parameters.get("right").?);
}

test "decision 122: the literal wins over the parameter, whatever the table's order" {
    const me_first = routes(u8, .{ .{ .get, "/users/me", 1 }, .{ .get, "/users/:id", 2 } });
    const id_first = routes(u8, .{ .{ .get, "/users/:id", 2 }, .{ .get, "/users/me", 1 } });
    inline for (.{ me_first, id_first }) |table| {
        var parameters: PathParameters = .{};
        try testing.expectEqual(1, table.match("GET", "/users/me", &parameters).found);
        try testing.expectEqual(0, parameters.count);
        inline for (.{ "/users/42", "/users/mee", "/users/m", "/users/Me" }) |path| {
            try testing.expectEqual(2, table.match("GET", path, &parameters).found);
            try testing.expectEqualStrings(path["/users/".len..], parameters.get("id").?);
        }
    }
}

const posts = routes(Person, .{
    .{ .get, "/users/:id", .user },
    .{ .get, "/users/:id/posts", .posts },
});

test "RFC 3986 §3.3: a path with a \"%\", an empty or dot segment, or an octet outside pchar matches nothing" {
    inline for (.{
        "/users/%6De",        "/users/42%2F", "/users/.",       "/users/..",       "/users/a b",
        "/users//posts",      "/users/42/",   "/users/./posts", "/users/../posts", "/users/a#b",
        "/users/caf\xc3\xa9", "/users/a\\b",  "/users/a\"b",    "/users/42//",     "/users/%",
    }) |path| try expect_not_found(posts, "GET", path);
    var parameters: PathParameters = .{};
    inline for (.{ "...", ".well-known", "a.b", ".a", "a..", "~!$&'()*+,;=:@" }) |segment| {
        try testing.expectEqual(.user, posts.match("GET", "/users/" ++ segment, &parameters).found);
        try testing.expectEqualStrings(segment, parameters.get("id").?);
    }
}

test "INV-8: a path of more than path_len_max octets matches nothing, its query included" {
    const any = routes(u8, .{.{ .get, "/:segment", 1 }});
    var target: [constants.path_len_max + 1]u8 = @splat('a');
    target[0] = '/';
    var parameters: PathParameters = .{};
    try testing.expectEqual(1, any.match("GET", target[0..constants.path_len_max], &parameters).found);
    try testing.expectEqual(constants.path_len_max - 1, parameters.get("segment").?.len);
    try testing.expect(any.match("GET", &target, &parameters) == .not_found);
    target[2] = '?';
    try testing.expectEqual(1, any.match("GET", target[0..constants.path_len_max], &parameters).found);
    try testing.expect(any.match("GET", &target, &parameters) == .not_found);
}

/// The routes of the largest table that the tests build: each one has a pattern of
/// `large_segments` segments of `large_segment_len` octets.
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

const Large = struct { http.method.Standard, []const u8, u16 };

const large_table: [large_routes]Large = build: {
    @setEvalBranchQuota(large_routes * large_segments * large_segment_len * large_segment_len);
    var table: [large_routes]Large = undefined;
    for (&table, 0..) |*entry, index| entry.* = .{ .get, large_pattern(index), index };
    break :build table;
};

test "decision 122: a table of 256 routes of four segments each compiles and matches" {
    const large = routes(u16, large_table);
    var parameters: PathParameters = .{};
    for (large_table) |entry| {
        try testing.expectEqual(entry[2], large.match("GET", entry[1], &parameters).found);
    }
    // The first segment of a pattern alone names no route.
    const first = comptime large_segment(0, 0);
    try testing.expect(large.match("GET", &first, &parameters) == .not_found);
    try testing.expectEqualStrings("GET", large.match("PUT", large_table[0][1], &parameters).method_not_allowed);
}

/// The table that the sweep reads. Each pattern is of one, two or three octets, so the sweep's
/// paths of up to two octets find each route.
const swept_patterns = [_][]const u8{ "/", "/a", "/:x" };
const swept_parameter = 2;
const swept = routes(u8, .{
    .{ .get, swept_patterns[0], 0 },
    .{ .get, swept_patterns[1], 1 },
    .{ .get, swept_patterns[swept_parameter], swept_parameter },
});

/// Most octets a fuzz input carries. Test-only.
const fuzz_input_len_max = 64;

fn fuzz_match(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const target = input[0..smith.slice(&input)];
    var parameters: PathParameters = .{};
    parameters.count = 1;
    switch (swept.match("GET", target, &parameters)) {
        .found => |route| try expect_swept(route, target, &parameters),
        // Each path of the table names GET.
        .method_not_allowed => return error.TestUnexpectedResult,
        .not_found => try testing.expectEqual(0, parameters.count),
    }
}

fn expect_swept(route: u8, target: []const u8, parameters: *const PathParameters) !void {
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    try testing.expect(path.len > 0 and path[0] == '/');
    try testing.expectEqual(null, std.mem.indexOfScalar(u8, path, '%'));
    if (route != swept_parameter) {
        try testing.expectEqualStrings(swept_patterns[route], path);
        try testing.expectEqual(0, parameters.count);
        return;
    }
    // The value is the path's one segment: not empty, not a dot segment, and with no "/".
    const value = parameters.get("x").?;
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqual(path.ptr + 1, value.ptr);
    try testing.expectEqual(path.len - 1, value.len);
    try testing.expect(value.len > 0 and std.mem.indexOfScalar(u8, value, '/') == null);
    try testing.expect(!std.mem.eql(u8, value, ".") and !std.mem.eql(u8, value, ".."));
}

test "fuzz: a found path equals a pattern before its query, or binds one segment that is not empty or a dot" {
    try testing.fuzz({}, fuzz_match, .{ .corpus = &.{
        core.fuzz.input("/"),
        core.fuzz.input("/a"),
        core.fuzz.input("/a?b"),
        core.fuzz.input("/?"),
        core.fuzz.input("/b"),
        core.fuzz.input("/b?c"),
        core.fuzz.input("/..."),
        core.fuzz.input("/a/"),
        core.fuzz.input("/."),
        core.fuzz.input("/%"),
        core.fuzz.input("//"),
        core.fuzz.input("a"),
        core.fuzz.input("*"),
    } });
}

test "sweep: every path of up to two octets that matches equals a pattern or binds one segment" {
    try core.fuzz.sweep(fuzz_match, null);
}
