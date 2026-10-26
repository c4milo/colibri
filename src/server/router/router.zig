//! `server.router`: a table of routes that the compiler builds, which calls the program's functions
//! (decision 127, design §8 step 25.3). colibri calls a function of the program's only inside a
//! call the program made, `handle`, and never from a loop of its own (decision 127 ruling 2).
//!
//! The matching is decision 122's, which `router_table.zig` holds: each route of the program's
//! table becomes an entry whose value is the route's `Route` tag.
const std = @import("std");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const router_table = @import("router_table.zig");
const router_method = @import("router_method.zig");
const router_pattern = @import("router_pattern.zig");
const router_trie = @import("router_trie.zig");
const router_pool = @import("router_pool.zig");
const router_call = @import("router_call.zig");
const router_handler = @import("router_handler.zig");

/// Builds a route table at compile time. `table` is a struct with two fields:
///
/// - `error_handler`: the function the router calls when a route's function returns an error,
///   with the context, the request, the error and the response writer. The program chooses the
///   status ("The user always decides what status to return", decision 127 ruling 4).
/// - `routes`: a tuple of entries. Each is a method, a pattern and a function, such as
///   `.{ .get, "/greetings/:name", greet }`, and options may follow, such as
///   `.{ .whole_body = true }`. The method and the pattern are decision 122's, which
///   `router_table.zig` lists.
///
/// A route's function takes five parameters: `*Context`, `*const server.Request`, the path
/// parameters, the query, and `*server.ResponseWriter`. It returns `!void`. The path parameters
/// are `void`, or a struct with a `[]const u8` field for each parameter of the pattern, and `rest`
/// for its wildcard. The query is `void`, `http.QueryParameters`, or a struct of fields that name
/// query pairs.
///
/// A route can be a struct instead, with `on_request`, which takes a `*State` after the context and
/// else the parameters of a function, and any of `on_body`, `on_writable` and `on_finished`.
/// `on_body` reads the request body through a `*std.Io.Reader`. With `.whole_body`, it runs once,
/// after the last byte.
///
/// Middleware run before a route: the route table's `middleware`, then the route entry's, each a
/// struct with `on_request`, `on_finished` or both (`server.middleware`).
///
/// A program places one `Of(options)` and passes each event of its endpoint to its `handle`.
/// `match` stays for a program that dispatches a request itself: its `found` gives the route's
/// `Route` tag, named by its method and its pattern, such as `.@"GET /users/:id"`.
pub fn router(comptime Context: type, comptime table: anytype) Router(Context, table) {
    return .{};
}

fn Router(comptime Context: type, comptime table: anytype) type {
    router_call.check_table(Context, table);
    const RouteTag = route_enum(table.routes);
    const Table = @TypeOf(router_table.table_of(RouteTag, values_of(RouteTag, table.routes)));
    router_handler.check(Context, table);
    return struct {
        /// One tag for each route, in the table's order, named by its method and its pattern.
        pub const Route = RouteTag;
        /// What `match` gives: `found` with the route's tag, `method_not_allowed` with the Allow
        /// field's value, `not_found`, or `not_implemented` (decision 122).
        pub const Match = Table.Match;
        /// The sizes of the pool `Of` makes.
        pub const Options = router_pool.Options;

        /// The route that `method` and `path` name, with its parameters in `parameters`.
        pub fn match(_: @This(), method: []const u8, path: []const u8, parameters: *PathParameters) Match {
            return (Table{}).match(method, path, parameters);
        }

        /// The type a program places once and does not move: a pool of `options.requests`
        /// entries, each with `options.response_bytes` of response memory.
        pub fn Of(comptime options: Options) type {
            return router_pool.Pool(Context, table, RouteTag, Table, options);
        }
    };
}

/// The enum of the routes, one tag for each in table order. Comptime-only.
fn route_enum(comptime routes: anytype) type {
    @setEvalBranchQuota(router_trie.quota_of(routes));
    var names: [routes.len][]const u8 = undefined;
    for (0..routes.len) |index| names[index] = name_of(routes[index], index, names[0..index]);
    const Tag = std.math.IntFittingRange(0, routes.len -| 1);
    return @Enum(Tag, .exhaustive, &names, &std.simd.iota(Tag, routes.len));
}

/// The tag name of the route at `index`: its method's token and its pattern. An entry that the
/// table refuses gets its index, and a name a route before it holds gets its index after it, so the
/// table's own refusal is the compile error. Comptime-only.
fn name_of(comptime entry: anytype, comptime index: usize, comptime earlier: []const []const u8) []const u8 {
    const name = if (is_named(@TypeOf(entry)) and router_method.refusal_of(entry[0]) == null)
        router_method.token_of(entry[0]) ++ " " ++ entry[1]
    else
        std.fmt.comptimePrint("{d}", .{index});
    for (earlier) |held| {
        if (std.mem.eql(u8, held, name)) return std.fmt.comptimePrint("{s} {d}", .{ name, index });
    }
    return name;
}

fn is_named(comptime Entry: type) bool {
    const info = @typeInfo(Entry);
    if (info != .@"struct" or !info.@"struct".is_tuple) return false;
    const parts = info.@"struct".fields.len;
    if (parts != route_parts and parts != route_parts + 1) return false;
    return router_pattern.is_text(info.@"struct".fields[1].type);
}

/// A route's parts: its method, its pattern and its function. Its options may follow.
const route_parts = 3;

/// The table `router_table` matches: each route with its tag in place of its function. An entry
/// of another shape stays as it is, so the table refuses it. Comptime-only.
fn values_of(comptime Route: type, comptime routes: anytype) ValuesOf(Route, routes) {
    var values: ValuesOf(Route, routes) = undefined;
    inline for (0..routes.len) |index| values[index] = value_of(routes[index], @as(Route, @enumFromInt(index)));
    return values;
}

fn ValuesOf(comptime Route: type, comptime routes: anytype) type {
    var types: [routes.len]type = undefined;
    for (0..routes.len) |index| types[index] = @TypeOf(value_of(routes[index], @as(Route, @enumFromInt(index))));
    return @Tuple(&types);
}

fn value_of(comptime entry: anytype, comptime tag: anytype) ValueOf(@TypeOf(entry), @TypeOf(tag)) {
    if (comptime !is_named(@TypeOf(entry))) return entry;
    return .{ entry[0], entry[1], tag };
}

fn ValueOf(comptime Entry: type, comptime Route: type) type {
    if (comptime !is_named(Entry)) return Entry;
    const fields = @typeInfo(Entry).@"struct".fields;
    return @Tuple(&.{ fields[0].type, fields[1].type, Route });
}

test "decision 127: a router's type exports Route, Match, Options, match and Of" {
    const sample = router(void, router_call.sample_table);
    try @import("core").public_names.expect(@TypeOf(sample), &.{ "Route", "Match", "Options", "match", "Of" });
}

test {
    _ = @import("router_handle_test.zig");
    _ = @import("router_struct_test.zig");
    _ = @import("router_middleware_test.zig");
}
