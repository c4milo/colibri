//! The tests of each check that refuses a table (decision 122, design §8 step 21e). Each test
//! calls a check at compile time on a refused case and on a valid case beside it, so a test
//! fails when a check goes and when a check refuses too much. `zig build routes-check` shows
//! that `server.routes` turns each refusal into a compile error.
const std = @import("std");
const http = @import("http");
const routes_pattern = @import("routes_pattern.zig");
const routes_method = @import("routes_method.zig");
const routes_trie = @import("routes_trie.zig");
const routes_trie_layout = @import("routes_trie_layout.zig");
const routes_hidden = @import("routes_hidden.zig");
const constants = @import("../constants.zig");
const core = @import("core");

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

test "refusal 10, wildcard_not_last: decision 122 ruling 6, the wildcard is the last segment" {
    try expect_pattern(.wildcard_not_last, "/files/*/meta");
    try expect_pattern(.wildcard_not_last, "/*/a");
    try expect_pattern(.wildcard_not_last, "/*/*");
    try expect_pattern(null, "/files/*");
    try expect_pattern(null, "/*");
    try expect_pattern(null, "/:id/*");
    // A segment that holds "*" and other octets, or ":" after its first octet, is a literal.
    try expect_pattern(null, "/a*b");
    try expect_pattern(null, "/**");
    try expect_pattern(null, "/*a/b");
    try expect_pattern(null, "/a:b");
}

test "refusal 6, parameter_unnamed: a parameter has a name after its \":\"" {
    try expect_pattern(.parameter_unnamed, "/users/:");
    try expect_pattern(.parameter_unnamed, "/:");
    try expect_pattern(.parameter_unnamed, "/:/a");
    try expect_pattern(null, "/users/:id");
    try expect_pattern(null, "/:a");
}

test "refusal 7, parameter_name_invalid: a name is 1*( ALPHA / DIGIT / \"_\" ), and a whole segment" {
    try expect_pattern(.parameter_name_invalid, "/:user-id");
    try expect_pattern(.parameter_name_invalid, "/:a:b");
    try expect_pattern(.parameter_name_invalid, "/:id.json");
    try expect_pattern(.parameter_name_invalid, "/::");
    try expect_pattern(.parameter_name_invalid, "/:%41");
    try expect_pattern(.parameter_name_invalid, "/:a~");
    try expect_pattern(.parameter_name_invalid, "/:a b");
    try expect_pattern(.parameter_name_invalid, "/:*");
    try expect_pattern(null, "/:user_id");
    try expect_pattern(null, "/:Id9");
    try expect_pattern(null, "/:_");
    try expect_pattern(null, "/:0");
    try expect_pattern(null, "/:azAZ09_");
}

test "refusal 8, parameter_repeated: each parameter of a pattern has a name of its own" {
    try expect_pattern(.parameter_repeated, "/:id/posts/:id");
    try expect_pattern(.parameter_repeated, "/:id/:id");
    try expect_pattern(.parameter_repeated, "/:a/:b/:a");
    try expect_pattern(null, "/:id/posts/:post");
    // A literal of the same text as a name is not a parameter.
    try expect_pattern(null, "/:id/id");
    // Names compare octet for octet.
    try expect_pattern(null, "/:id/:ID");
}

/// The comptime branches that `parameters_pattern` takes for each parameter. Test-only.
const branches_per_parameter = 1_000;

/// A pattern of `count` parameters, `/:p0/:p1/...`. Comptime-only.
fn parameters_pattern(comptime count: usize) []const u8 {
    var pattern: []const u8 = "";
    for (0..count) |index| pattern = pattern ++ std.fmt.comptimePrint("/:p{d}", .{index});
    return pattern;
}

test "refusal 9, parameters_too_many: a pattern holds path_parameters_max parameters at most" {
    @setEvalBranchQuota(constants.path_parameters_max * branches_per_parameter);
    const most = comptime parameters_pattern(constants.path_parameters_max);
    try expect_pattern(.parameters_too_many, most ++ "/:extra");
    try expect_pattern(.parameters_too_many, most ++ "/a/:extra");
    try expect_pattern(null, most);
    // A literal is not a parameter.
    try expect_pattern(null, most ++ "/extra");
    // Decision 122 ruling 10: the wildcard takes one entry of `PathParameters`.
    try expect_pattern(.parameters_too_many, most ++ "/*");
    const fewer = comptime parameters_pattern(constants.path_parameters_max - 1);
    try expect_pattern(null, fewer ++ "/*");
    try expect_pattern(.parameters_too_many, fewer ++ "/:extra/*");
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

test "refusal 19, parameter_names_differ: decision 122 ruling 5, one parameter node has one name" {
    try expect_table(.parameter_names_differ, .{ .{ .get, "/users/:id", .one }, .{ .put, "/users/:user", .two } });
    try expect_table(.parameter_names_differ, .{ .{ .get, "/:a/x", .one }, .{ .get, "/:b/y", .two } });
    try expect_table(.parameter_names_differ, .{ .{ .get, "/:a", .one }, .{ .get, "/:ab", .two } });
    try expect_table(.parameter_names_differ, .{ .{ .get, "/:ab", .one }, .{ .get, "/:a/c", .two } });
    try expect_table(.parameter_names_differ, .{ .{ .get, "/u/:id/p/:x", .one }, .{ .get, "/u/:id/p/:y", .two } });
    // The same name at one node, names at two nodes, and a literal beside a parameter.
    try expect_table(null, .{ .{ .get, "/users/:id", .one }, .{ .put, "/users/:id", .two } });
    try expect_table(null, .{ .{ .get, "/users/:id", .one }, .{ .get, "/posts/:id2", .two } });
    try expect_table(null, .{ .{ .get, "/users/:id", .one }, .{ .get, "/users/:id/:part", .two } });
    try expect_table(null, .{ .{ .get, "/users/me", .one }, .{ .get, "/users/:id", .two } });
    try expect_table(null, .{ .{ .get, "/:a/x", .one }, .{ .get, "/:a/:b", .two } });
    try expect_table(null, .{ .{ .get, "/", .one }, .{ .get, "/:a", .two } });
    try expect_table(null, .{ .{ .get, "/:a", .one }, .{ .get, "/:a/b", .two } });
    try expect_table(null, .{ .{ .get, "/a:b", .one }, .{ .get, "/a:c", .two } });
}

test "decision 122: two names at one node refuse the later route, before a repeated route" {
    const refusal = comptime routes_trie.refusal_of(.{
        .{ .get, "/a", .one },
        .{ .get, "/users/:id", .one },
        .{ .get, "/users/:name", .two },
        .{ .get, "/a", .two },
    }).?;
    try testing.expectEqual(2, refusal.route);
    try testing.expectEqualStrings("/users/:name", refusal.pattern);
    try testing.expectEqual(routes_trie.Reason.parameter_names_differ, refusal.reason);
    try expect_table(.route_repeated, .{ .{ .get, "/users/:id", .one }, .{ .get, "/users/:id", .two } });
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

/// The first refusal of `table` that reads its layout, in the order of `server.routes`:
/// `allow_too_long`, then `route_hidden` and `route_unreachable`. `table` passes every check
/// before the build. Comptime-only.
fn layout_refusal(comptime table: anytype) ?routes_trie.Refusal {
    @setEvalBranchQuota(routes_trie.quota_of(table) + routes_hidden.quota_bound_of(table));
    std.debug.assert(routes_trie.refusal_of(table) == null);
    const layout = routes_trie_layout.build(u8, table);
    if (routes_trie_layout.allow_refusal(layout, table)) |refusal| return refusal;
    return routes_hidden.refusal_of(u8, layout, table);
}

const Tag = std.meta.Tag(routes_trie.Reason);

/// Requires the refusal of `table` that reads its layout to name route `route` with `expected`,
/// or no refusal when `expected` is null.
fn expect_layout(comptime expected: ?Tag, comptime route: usize, comptime table: anytype) !void {
    const refusal = comptime layout_refusal(table);
    const tag = expected orelse return testing.expectEqual(null, refusal);
    const refused = refusal orelse return error.TestExpectedRefusal;
    try testing.expectEqual(tag, std.meta.activeTag(refused.reason));
    try testing.expectEqual(route, refused.route);
}

/// Requires `table` to refuse route `route` with `route_hidden`, for the request `method` and
/// `path`, which gets 405 from the routes of `pattern`.
fn expect_hidden(comptime route: usize, comptime method: []const u8, comptime path: []const u8, comptime pattern: []const u8, comptime table: anytype) !void {
    const refusal = comptime layout_refusal(table).?;
    try testing.expectEqual(route, refusal.route);
    try testing.expectEqualStrings(method, refusal.reason.route_hidden.method);
    try testing.expectEqualStrings(path, refusal.reason.route_hidden.path);
    try testing.expectEqualStrings(pattern, refusal.reason.route_hidden.pattern);
}

test "refusal 20, route_hidden: decision 122 ruling 12, a request that a route matches gets no 405" {
    // The owner's examples 2, 3, 5 and 7.
    try expect_hidden(0, "GET", "/users/me", "/users/me", .{ .{ .get, "/users/:id", 0 }, .{ .put, "/users/me", 1 } });
    try expect_hidden(2, "PUT", "/users/me", "/users/me", .{
        .{ .get, "/users/me", 0 }, .{ .get, "/users/:id", 1 }, .{ .put, "/users/:id", 2 }, .{ .delete, "/users/:id", 3 },
    });
    try expect_hidden(0, "GET", "/files/a", "/files/:name", .{ .{ .get, "/files/*", 0 }, .{ .post, "/files/:name", 1 } });
    try expect_hidden(0, "GET", "/a/b/c", "/a/b/:y", .{ .{ .get, "/a/:x/c", 0 }, .{ .put, "/a/b/:y", 1 } });
    // The plan's rule 13 table, and a leaf that names HEAD and no GET.
    try expect_hidden(1, "PUT", "/users/me", "/users/me", .{ .{ .get, "/users/me", 0 }, .{ .put, "/users/:id", 1 } });
    try expect_hidden(0, "GET", "/users/me", "/users/me", .{ .{ .get, "/users/:id", 0 }, .{ .head, "/users/me", 1 } });
    // The owner's examples 1, 4 and 6, and each refused table with the routes that it lacks.
    try expect_layout(null, 0, .{ .{ .get, "/users/me", 0 }, .{ .get, "/users/:id", 1 } });
    try expect_layout(null, 0, .{ .{ .get, "/files/*", 0 }, .{ .get, "/files/:name", 1 } });
    try expect_layout(null, 0, .{ .{ .get, "/a/:x/c", 0 }, .{ .get, "/a/b/:y", 1 } });
    try expect_layout(null, 0, .{ .{ .get, "/users/:id", 0 }, .{ .put, "/users/me", 1 }, .{ .get, "/users/me", 2 } });
    try expect_layout(null, 0, .{
        .{ .get, "/users/me", 0 },     .{ .get, "/users/:id", 1 }, .{ .put, "/users/:id", 2 },
        .{ .delete, "/users/:id", 3 }, .{ .put, "/users/me", 4 },  .{ .delete, "/users/me", 5 },
    });
    try expect_layout(null, 0, .{ .{ .get, "/a/:x/c", 0 }, .{ .put, "/a/b/:y", 1 }, .{ .get, "/a/b/c", 2 }, .{ .put, "/a/b/c", 3 } });
    // RFC 9110 §9.3.2: HEAD of `/users/me` finds the GET route of `/users/me`.
    try expect_layout(null, 0, .{ .{ .head, "/users/:id", 0 }, .{ .get, "/users/me", 1 } });
}

test "refusal 21, route_unreachable: decision 122 ruling 12, a request reaches each route" {
    // The owner's example 8: "/a/:x" takes each path of one segment, and "/a/:x/*" each longer path.
    const refusal = comptime layout_refusal(.{ .{ .get, "/a/*", 0 }, .{ .get, "/a/:x", 1 }, .{ .get, "/a/:x/*", 2 } }).?;
    try testing.expectEqual(0, refusal.route);
    try testing.expectEqualStrings("\"/a/:x\", \"/a/:x/*\"", refusal.reason.route_unreachable.patterns);
    try testing.expect(!refusal.reason.route_unreachable.too_long);
    try expect_layout(.route_unreachable, 1, .{ .{ .get, "/a/:x/*", 0 }, .{ .get, "/a/*", 1 }, .{ .get, "/a/:x", 2 } });
    // The wildcard takes a path of two segments or more, which "/a/:x" does not.
    try expect_layout(null, 0, .{ .{ .get, "/a/*", 0 }, .{ .get, "/a/:x", 1 } });
    try expect_layout(null, 0, .{ .{ .get, "/a/*", 0 }, .{ .get, "/a/:x/b", 1 }, .{ .get, "/a/:x", 2 } });
}

/// A segment of `path_len_max` octets, so a path of it is one octet too long.
const long_segment = "a" ** constants.path_len_max;

test "refusal 21, route_unreachable: a pattern whose paths are longer than path_len_max" {
    const refusal = comptime layout_refusal(.{ .{ .get, "/", 0 }, .{ .get, "/" ++ long_segment, 1 } }).?;
    try testing.expectEqual(1, refusal.route);
    try testing.expectEqualStrings("", refusal.reason.route_unreachable.patterns);
    try testing.expect(refusal.reason.route_unreachable.too_long);
    try expect_layout(null, 0, .{ .{ .get, "/", 0 }, .{ .get, "/" ++ long_segment[1..], 1 } });
    // INV-8: a request of a path longer than `path_len_max` gets 404, so the literal hides no GET
    // of the parameter. The literal is the route that no request reaches.
    try expect_layout(.route_unreachable, 1, .{ .{ .get, "/:x", 0 }, .{ .put, "/" ++ long_segment, 1 } });
}

test "refusal 22, allow_too_long: an Allow value fits core.constants.field_value_len_max" {
    const most = core.constants.field_value_len_max;
    try expect_layout(.allow_too_long, 1, .{ valid_entry, .{ "A" ** (most + 1), "/a", 1 } });
    try expect_layout(null, 0, .{ valid_entry, .{ "A" ** most, "/a", 1 } });
    // The Allow value "GET, HEAD, " and the token: HEAD counts.
    const head_allow = "GET, HEAD, ".len;
    try expect_layout(.allow_too_long, 0, .{ .{ .get, "/", 0 }, .{ "A" ** (most - head_allow + 1), "/", 1 } });
    try expect_layout(null, 0, .{ .{ .get, "/", 0 }, .{ "A" ** (most - head_allow), "/", 1 } });
}

/// A valid entry, which a refused table holds first.
const valid_entry = .{ .get, "/", 0 };

test "decision 122: the compile error of a hidden route names the request and the pattern" {
    try testing.expectEqualStrings(
        "server.routes: route 0, \"/users/:id\": route_hidden: a request that this route matches gets 405 " ++
            "from another pattern: GET \"/users/me\" matches \"/users/me\" first, and no route of that " ++
            "pattern names GET",
        comptime routes_trie.message(layout_refusal(.{ .{ .get, "/users/:id", 0 }, .{ .put, "/users/me", 1 } }).?),
    );
    try testing.expectEqualStrings(
        "server.routes: route 0, \"/a/*\": route_unreachable: no request reaches this route, because " ++
            "another pattern matches each of its paths first: \"/a/:x\", \"/a/:x/*\"",
        comptime routes_trie.message(layout_refusal(.{ .{ .get, "/a/*", 0 }, .{ .get, "/a/:x", 1 }, .{ .get, "/a/:x/*", 2 } }).?),
    );
    try testing.expectEqualStrings(
        "server.routes: route 1, \"/a\": allow_too_long: the Allow value of the routes of one pattern " ++
            "holds core.constants.field_value_len_max octets at most, because a 405 sends it as a field value",
        comptime routes_trie.message(.{ .route = 1, .pattern = "/a", .reason = .allow_too_long }),
    );
}
