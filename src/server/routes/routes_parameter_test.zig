//! The tests of `match` on routes with a parameter or the wildcard (decision 122, design §8 step
//! 21e).
const std = @import("std");
const routes = @import("routes.zig").routes;
const PathParameters = @import("../path_parameters.zig").PathParameters;
const constants = @import("../constants.zig");
const support = @import("routes_test_support.zig");

const testing = std.testing;
const expect_not_found = support.expect_not_found;

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
    try testing.expectEqualStrings("GET, HEAD", people.match("PUT", "/users/42", &parameters).method_not_allowed);
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

/// The kind of segment that a route of the wildcard's tests ends with.
const Last = enum { parameter, literal, wildcard };

const files = routes(Last, .{
    .{ .get, "/files/*", .wildcard },
    .{ .get, "/files/a*b", .literal },
});

test "decision 122 ruling 6: the wildcard matches one segment or more, the rest of the path" {
    var parameters: PathParameters = .{};
    const path: []const u8 = "/files/a/b";
    try testing.expectEqual(.wildcard, files.match("GET", path, &parameters).found);
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqualStrings("a/b", parameters.get("*").?);
    try testing.expectEqual(path.ptr + "/files/".len, parameters.get("*").?.ptr);
    try testing.expectEqual(.wildcard, files.match("GET", "/files/a", &parameters).found);
    try testing.expectEqualStrings("a", parameters.get("*").?);
    // RFC 3986 §3.3: the rest of the path stops at the first "?".
    try testing.expectEqual(.wildcard, files.match("GET", "/files/a/b?c/d", &parameters).found);
    try testing.expectEqualStrings("a/b", parameters.get("*").?);
    // A segment that holds "*" and other octets is a literal, and the literal wins.
    try testing.expectEqual(.literal, files.match("GET", "/files/a*b", &parameters).found);
    try testing.expectEqual(0, parameters.count);
    try testing.expectEqual(.wildcard, files.match("GET", "/files/axb", &parameters).found);
    // The wildcard needs one segment, and each segment of the rest passes the checks of the path.
    inline for (.{ "/files", "/files/", "/files/a/../b", "/files/a/./b", "/files/a//b", "/files/a/", "/files/%2F" }) |refused| {
        try expect_not_found(files, "GET", refused);
    }
}

/// Tables where the wildcard competes with a literal and a parameter. Each table is a constant of
/// the file, so each one has the comptime branch quota of its own build.
const parameter_first = routes(Last, .{ .{ .get, "/a/:x", .parameter }, .{ .get, "/a/b", .literal }, .{ .get, "/a/*", .wildcard } });
const wildcard_first = routes(Last, .{ .{ .get, "/a/*", .wildcard }, .{ .get, "/a/b", .literal }, .{ .get, "/a/:x", .parameter } });
const literal_and_wildcard = routes(Last, .{ .{ .get, "/a/*", .wildcard }, .{ .get, "/a/b", .literal } });

test "decision 122: the literal and the parameter win over the wildcard, whatever the table's order" {
    inline for (.{ parameter_first, wildcard_first }) |table| {
        var parameters: PathParameters = .{};
        try testing.expectEqual(.parameter, table.match("GET", "/a/c", &parameters).found);
        try testing.expectEqual(1, parameters.count);
        try testing.expectEqualStrings("c", parameters.get("x").?);
        try testing.expectEqual(null, parameters.get("*"));
        try testing.expectEqual(.literal, table.match("GET", "/a/b", &parameters).found);
        try testing.expectEqual(0, parameters.count);
    }
    var parameters: PathParameters = .{};
    try testing.expectEqual(.literal, literal_and_wildcard.match("GET", "/a/b", &parameters).found);
    try testing.expectEqual(.wildcard, literal_and_wildcard.match("GET", "/a/c", &parameters).found);
    try testing.expectEqualStrings("c", parameters.get("*").?);
}

/// The comptime branches that `most_parameters` takes for each parameter. Test-only.
const branches_per_parameter = 1_000;

/// A pattern of `path_parameters_max - 1` parameters and the wildcard, or a path that it matches
/// with `value_prefix` before each value. Comptime-only.
fn most_parameters(comptime parameter_prefix: []const u8, comptime value_prefix: []const u8) []const u8 {
    @setEvalBranchQuota(constants.path_parameters_max * branches_per_parameter);
    var text: []const u8 = "";
    for (0..constants.path_parameters_max - 1) |index| {
        text = text ++ std.fmt.comptimePrint("/{s}{s}{d}", .{ parameter_prefix, value_prefix, index });
    }
    return text;
}

test "decision 122 ruling 10: the parameters and the wildcard of a pattern fill path_parameters_max entries" {
    const most = routes(u8, .{.{ .get, comptime most_parameters(":", "p") ++ "/*", 1 }});
    const path = comptime most_parameters("", "v") ++ "/w/x";
    var parameters: PathParameters = .{};
    try testing.expectEqual(1, most.match("GET", path, &parameters).found);
    try testing.expectEqual(constants.path_parameters_max, parameters.count);
    try testing.expectEqualStrings("v0", parameters.get("p0").?);
    try testing.expectEqualStrings("w/x", parameters.get("*").?);
    inline for (0..constants.path_parameters_max - 1) |index| {
        const name = comptime std.fmt.comptimePrint("p{d}", .{index});
        const value = comptime std.fmt.comptimePrint("v{d}", .{index});
        try testing.expectEqualStrings(value, parameters.get(name).?);
    }
}
