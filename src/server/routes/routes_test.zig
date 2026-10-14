//! The tests of `match` on tables that compile (decision 122, design §8 step 21e). Each table is a
//! constant, as a program declares one.
const std = @import("std");
const http = @import("http");
const routes = @import("routes.zig").routes;
const routes_trie = @import("routes_trie.zig");
const routes_hidden = @import("routes_hidden.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const constants = @import("../constants.zig");
const support = @import("routes_test_support.zig");

const testing = std.testing;
const expect_found = support.expect_found;
const expect_not_found = support.expect_not_found;
const expect_allow = support.expect_allow;
const expect_not_implemented = support.expect_not_implemented;

const Route = enum { greeting, root, users, user_put, user_delete, user_patch, user_link };

const greetings = routes(Route, .{
    .{ .get, "/", .root },
    .{ .get, "/greeting", .greeting },
});

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
        try expect_allow(table, "PUT, DELETE, LINK, PATCH", "HEAD", "/users/me?x");
        // RFC 9110 §9.1: a HEAD request finds the GET route, so Allow lists HEAD after GET.
        try expect_allow(table, "GET, HEAD", "PUT", "/users");
        // RFC 9110 §9.1: the method is case-sensitive, so "put" is a method no route names.
        try expect_not_implemented(table, "put", "/users/me");
        try expect_not_implemented(table, "patch", "/users/me");
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

const Page = enum { page, page_head, notes, notes_patch, status, upload };

const pages = routes(Page, .{
    .{ .get, "/page", .page },
    .{ .head, "/page", .page_head },
    .{ .get, "/notes", .notes },
    .{ "PATCH", "/notes", .notes_patch },
    .{ .head, "/status", .status },
    .{ .put, "/upload", .upload },
});

const pages_reversed = routes(Page, .{
    .{ .put, "/upload", .upload },
    .{ .head, "/status", .status },
    .{ "PATCH", "/notes", .notes_patch },
    .{ .get, "/notes", .notes },
    .{ .head, "/page", .page_head },
    .{ .get, "/page", .page },
});

test "RFC 9110 §9.3.2: a HEAD request finds the GET route of a path that names no HEAD route" {
    inline for (.{ pages, pages_reversed }) |table| {
        try expect_found(table, Page.notes, "HEAD", "/notes");
        try expect_found(table, Page.notes, "HEAD", "/notes?x");
        try expect_found(table, Page.notes, "GET", "/notes");
        // A HEAD route wins over the GET route of its path.
        try expect_found(table, Page.page_head, "HEAD", "/page");
        try expect_found(table, Page.page, "GET", "/page");
        // RFC 9110 §9.1: the method is case-sensitive, so "head" is a method no route names.
        try expect_not_implemented(table, "head", "/notes");
        // A path with no GET route gives HEAD no route.
        try expect_allow(table, "PUT", "HEAD", "/upload");
        try expect_not_found(table, "HEAD", "/missing");
    }
}

test "RFC 9110 §10.2.1: Allow lists HEAD after GET once, and GET never finds a HEAD route" {
    inline for (.{ pages, pages_reversed }) |table| {
        // RFC 9110 §15.5.6: a 405 for PUT on a path with a GET route.
        try expect_allow(table, "GET, HEAD", "PUT", "/page");
        try expect_allow(table, "GET, HEAD, PATCH", "PUT", "/notes");
        try expect_allow(table, "GET, HEAD, PATCH", "PUT", "/notes?x");
        // A HEAD route does not answer GET.
        try expect_allow(table, "HEAD", "GET", "/status");
        try expect_found(table, Page.status, "HEAD", "/status");
    }
    try expect_allow(routes(u8, .{ .{ .get, "/", 0 }, .{ .post, "/a", 1 } }), "GET, HEAD", "POST", "/");
}

test "RFC 9110 §15.6.2: a method that no route names gives 501 before the path is read" {
    inline for (.{ users, users_reversed }) |table| {
        inline for (.{ "/users/me", "/users", "/missing", "*", "", "/users/caf%C3%A9", "/a//b" }) |path| {
            try expect_not_implemented(table, "POST", path);
            try expect_not_implemented(table, "OPTIONS", path);
            // RFC 9110 §9.1: the method is case-sensitive.
            try expect_not_implemented(table, "get", path);
        }
        // RFC 9110 §9.3.6: no route names CONNECT, and its request has no path.
        try expect_not_implemented(table, "CONNECT", "");
        // A method that another leaf names gives 405 at a leaf without it.
        try expect_allow(table, "PUT, DELETE, LINK, PATCH", "GET", "/users/me");
        try expect_allow(table, "GET, HEAD", "LINK", "/users");
        // Each method of the table is implemented, so an unknown path gives 404.
        inline for (.{ "GET", "HEAD", "PUT", "DELETE", "LINK", "PATCH" }) |method| {
            try expect_not_found(table, method, "/missing");
        }
    }
    inline for (.{ pages, pages_reversed }) |table| {
        // A token method that one leaf names gives 405 at another leaf.
        try expect_found(table, Page.notes_patch, "PATCH", "/notes");
        try expect_allow(table, "GET, HEAD", "PATCH", "/page");
        try expect_allow(table, "PUT", "PATCH", "/upload");
        try expect_not_implemented(table, "DELETE", "/page");
    }
}

test "RFC 9110 §9.1: a table that names GET implements HEAD" {
    try expect_found(greetings, Route.greeting, "HEAD", "/greeting");
    try expect_not_found(greetings, "HEAD", "/missing");
    try expect_not_found(greetings, "HEAD", "*");
    try expect_not_implemented(greetings, "PUT", "/greeting");
    // A table that names HEAD alone does not implement GET.
    try expect_not_implemented(routes(u8, .{.{ .head, "/", 0 }}), "GET", "/");
}

test "RFC 9110 §9.1: OPTIONS * gives 501 from a table with no OPTIONS route, and 404 from one" {
    try expect_not_implemented(greetings, "OPTIONS", "*");
    const options = routes(Route, .{
        .{ .get, "/greeting", .greeting },
        .{ .options, "/", .root },
    });
    // RFC 9112 §3.2.4: the asterisk-form names no path, so it matches no route.
    try expect_not_found(options, "OPTIONS", "*");
    try expect_found(options, Route.root, "OPTIONS", "/");
    try expect_allow(options, "GET, HEAD", "OPTIONS", "/greeting");
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
/// `large_segments` segments of `large_segment_len` octets. The last route names PUT, and each
/// other route names GET.
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
    for (&table, 0..) |*entry, index| entry.* = .{ if (index == large_routes - 1) .put else .get, large_pattern(index), index };
    break :build table;
};

test "decision 122: a table of 256 routes of four segments each compiles and matches" {
    const large = routes(u16, large_table);
    var parameters: PathParameters = .{};
    for (large_table) |entry| {
        const method: []const u8 = if (entry[0] == .put) "PUT" else "GET";
        try testing.expectEqual(entry[2], large.match(method, entry[1], &parameters).found);
    }
    // The first segment of a pattern alone names no route.
    const first = comptime large_segment(0, 0);
    try testing.expect(large.match("GET", &first, &parameters) == .not_found);
    try testing.expectEqualStrings("GET, HEAD", large.match("PUT", large_table[0][1], &parameters).method_not_allowed);
}

/// The route that a test of the back-up takes, by the kind of its last segments.
const Deeper = enum { literal, parameter, wildcard };

const literal_or_parameter = routes(Deeper, .{ .{ .get, "/a/b/c", .literal }, .{ .get, "/a/:x/d", .parameter } });
const literal_or_leaf = routes(Deeper, .{ .{ .get, "/a/b/c", .literal }, .{ .get, "/a/:x", .parameter } });
const literal_or_wildcard = routes(Deeper, .{ .{ .get, "/a/b/c", .literal }, .{ .get, "/a/*", .wildcard } });
const parameter_or_wildcard = routes(Deeper, .{ .{ .get, "/a/:x", .parameter }, .{ .get, "/a/*", .wildcard } });
const leaf_or_wildcard = routes(Deeper, .{ .{ .get, "/a/b", .literal }, .{ .get, "/a/*", .wildcard } });

test "decision 122: the walk backs up one level when a deeper segment has no child" {
    var parameters: PathParameters = .{};
    try testing.expectEqual(.parameter, literal_or_parameter.match("GET", "/a/b/d", &parameters).found);
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqualStrings("b", parameters.get("x").?);
    try expect_found(literal_or_parameter, Deeper.literal, "GET", "/a/b/c");
    try expect_not_found(literal_or_parameter, "GET", "/a/b/e");
    try testing.expectEqual(.wildcard, literal_or_wildcard.match("GET", "/a/b/x", &parameters).found);
    try testing.expectEqualStrings("b/x", parameters.get("*").?);
    try expect_found(literal_or_wildcard, Deeper.literal, "GET", "/a/b/c");
}

test "decision 122: the walk backs up one level when the segments end at a node with no leaf" {
    var parameters: PathParameters = .{};
    try testing.expectEqual(.parameter, literal_or_leaf.match("GET", "/a/b", &parameters).found);
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqualStrings("b", parameters.get("x").?);
    try expect_found(literal_or_leaf, Deeper.literal, "GET", "/a/b/c");
    try expect_not_found(literal_or_leaf, "GET", "/a/b/c/d");
    // A path deeper than every pattern backs up to the root and matches nothing.
    try expect_not_found(literal_or_leaf, "GET", "/a" ++ "/b" ** 63);
}

test "decision 122: the wildcard takes the rest of the path after a back-up from a deeper level" {
    var parameters: PathParameters = .{};
    // The parameter binds "b", its node has no child for "c", and the wildcard takes "b/c".
    try testing.expectEqual(.wildcard, parameter_or_wildcard.match("GET", "/a/b/c", &parameters).found);
    try testing.expectEqual(1, parameters.count);
    try testing.expectEqualStrings("b/c", parameters.get("*").?);
    try testing.expectEqual(null, parameters.get("x"));
    try testing.expectEqual(.parameter, parameter_or_wildcard.match("GET", "/a/b", &parameters).found);
    try testing.expectEqualStrings("b", parameters.get("x").?);
    // The literal "b" holds a leaf and no child, so the walk backs up for "/a/b/c".
    try testing.expectEqual(.wildcard, leaf_or_wildcard.match("GET", "/a/b/c", &parameters).found);
    try testing.expectEqualStrings("b/c", parameters.get("*").?);
    try expect_found(leaf_or_wildcard, Deeper.literal, "GET", "/a/b");
    // A path of 64 segments against a table of depth 2.
    try testing.expectEqual(.wildcard, parameter_or_wildcard.match("GET", "/a" ++ "/b" ** 63, &parameters).found);
    try testing.expectEqual(63 * "/b".len - 1, parameters.get("*").?.len);
}

/// Four routes where each pair competes for a path. Their table is built in each order.
const Overlap = enum { me, id, rest, posts };
const OverlapEntry = struct { http.method.Standard, []const u8, Overlap };
const overlap_entries = [_]OverlapEntry{
    .{ .get, "/u/me", .me },
    .{ .get, "/u/:id", .id },
    .{ .get, "/u/*", .rest },
    .{ .get, "/u/:id/p", .posts },
};

/// The count of orders of `overlap_entries`: the factorial of its length.
const overlap_orders = factorial(overlap_entries.len);

/// The tables of one test share its comptime branch count, so the test sets the quota of each
/// build and of its check of hidden routes, and of one more for the orders.
const overlap_quota = (overlap_orders + 1) * (routes_trie.quota_of(overlap_entries) + routes_hidden.quota_bound_of(overlap_entries));

fn factorial(comptime count: usize) usize {
    var product: usize = 1;
    for (1..count + 1) |factor| product *= factor;
    return product;
}

/// The entries of `overlap_entries` in the order `order` names. Each digit of `order` in the
/// factorial number system picks one of the entries left. Comptime-only.
fn overlap_order(comptime order: usize) [overlap_entries.len]OverlapEntry {
    var left = overlap_entries;
    var ordered: [overlap_entries.len]OverlapEntry = undefined;
    var rest = order;
    for (&ordered, 0..) |*entry, taken| {
        const left_count = left.len - taken;
        const pick = rest % left_count;
        rest /= left_count;
        entry.* = left[pick];
        for (pick..left_count - 1) |index| left[index] = left[index + 1];
    }
    return ordered;
}

fn expect_overlap(table: anytype) !void {
    var parameters: PathParameters = .{};
    try expect_found(table, Overlap.me, "GET", "/u/me");
    try testing.expectEqual(.id, table.match("GET", "/u/42", &parameters).found);
    try testing.expectEqualStrings("42", parameters.get("id").?);
    // The literal "me" has no child "p", so the walk backs up and the parameter binds "me".
    try testing.expectEqual(.posts, table.match("GET", "/u/me/p", &parameters).found);
    try testing.expectEqualStrings("me", parameters.get("id").?);
    try testing.expectEqual(.posts, table.match("GET", "/u/42/p", &parameters).found);
    try testing.expectEqualStrings("42", parameters.get("id").?);
    inline for (.{ "42/q", "me/q", "me/p/q", "42/p/q" }) |rest| {
        try testing.expectEqual(.rest, table.match("GET", "/u/" ++ rest, &parameters).found);
        try testing.expectEqual(1, parameters.count);
        try testing.expectEqualStrings(rest, parameters.get("*").?);
    }
    try expect_not_found(table, "GET", "/u");
    try expect_not_found(table, "GET", "/u/");
}

test "decision 122: routes that compete for a path give one result in each order of their table" {
    @setEvalBranchQuota(overlap_quota);
    inline for (0..overlap_orders) |order| {
        try expect_overlap(routes(Overlap, comptime overlap_order(order)));
    }
}

/// The levels of the deep table. Each level but the last holds a literal "l" and a parameter.
const deep_levels = 8;
const DeepEntry = struct { http.method.Standard, []const u8, u8 };

/// The pattern of route `route` of the deep table: the parameter at level `route` and "l" at
/// each other level, then "y" at the last level. Route `deep_levels - 1` has no parameter.
/// Comptime-only.
fn deep_pattern(comptime route: usize) []const u8 {
    var pattern: []const u8 = "";
    for (0..deep_levels - 1) |level| {
        pattern = pattern ++ if (level == route) std.fmt.comptimePrint("/:p{d}", .{level}) else "/l";
    }
    return pattern ++ "/y";
}

const deep_table: [deep_levels]DeepEntry = build: {
    var table: [deep_levels]DeepEntry = undefined;
    for (&table, 0..) |*entry, route| entry.* = .{ .get, deep_pattern(route), route };
    break :build table;
};

test "INV-32: a deep table and a path that fails at the last level finish within the bound" {
    const deep = routes(u8, deep_table);
    var parameters: PathParameters = .{};
    // Each branch reads "l" to the last level, where "x" is not "y", so the walk backs up past
    // every node once.
    try expect_not_found(deep, "GET", "/l" ** (deep_levels - 1) ++ "/x");
    try expect_found(deep, @as(u8, deep_levels - 1), "GET", "/l" ** (deep_levels - 1) ++ "/y");
    try testing.expectEqual(3, deep.match("GET", "/l/l/l/q/l/l/l/y", &parameters).found);
    try testing.expectEqualStrings("q", parameters.get("p3").?);
    try testing.expectEqual(0, deep.match("GET", "/q/l/l/l/l/l/l/y", &parameters).found);
    try testing.expectEqualStrings("q", parameters.get("p0").?);
}
