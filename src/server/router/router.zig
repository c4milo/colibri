//! `server.Router`: a table of routes that the compiler builds, which calls the program's functions
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

/// Builds a route table at compile time. `table` is a struct with these fields:
///
/// - `error_handler`: the function the router calls when a route's function returns an error,
///   with the context, the request context, the request, the error and the response. The
///   program chooses the status ("The user always decides what status to return", decision 127
///   ruling 4).
/// - `routes`: a tuple of entries. Each is a method, a pattern and a function, such as
///   `.{ .get, "/greetings/:name", greet }`, and options may follow, such as
///   `.{ .path = Name, .query = Mark }`. The method and the pattern are decision 122's, which
///   `router_table.zig` lists.
/// - `Values`, which a table may leave out: the type of each request's values, a struct whose
///   fields each have a default. Each request starts with `.{}` (decision 163 ruling 2).
/// - `middleware`, which a table may leave out: a tuple of the middleware of every route.
///
/// A route's function takes four parameters: `*Context`, `*server.RequestContext`,
/// `*const server.Request` and `*server.Response` (decision 163). It returns `!void`. It gets the
/// whole request in one call, and reads the body through `request.body`, which never waits
/// (decision 163 ruling 4):
///
/// - A request with no body gets its call at the head, with a body that ends at once.
/// - A request with a body gets its call when the body ended. The router copies the header into
///   the request's entry, and holds every byte of the body. `options.header_bytes` bounds the
///   copy, with 431 past it, and `options.body_bytes` bounds the body, with 413.
/// - With `options.header_bytes` 0, a request with a body gets its call at the head too. A read of
///   its body fails, and the router drops the body.
///
/// The route never sees a trailer section.
///
/// A route's options name the types of its path parameters and of its query (decision 163 ruling
/// 3). `.path` is a struct with a `[]const u8` field for each parameter of the pattern, and `rest`
/// for its wildcard. `.query` is `http.QueryParameters`, or a struct of fields that name query
/// pairs. The function reads them with `ctx.path(Name)` and `ctx.query(Mark)`. A route that names
/// no `.path` and no `.query` reads neither.
///
/// A route can be a struct instead, with `on_request`, which takes a `*State` after the request
/// context and else the parameters of a function, and any of `on_body`, `on_writable` and
/// `on_finished`. Each takes the context, the request context and the `*State` first. `on_body`
/// reads the request body through a `*std.Io.Reader`, as the bytes arrive. For a request with a
/// body, a read of `request.body` fails with `error.ReadFailed` in `on_request` and in a
/// middleware's `on_request`. The body comes after the head.
///
/// Middleware run before a route: the route table's `middleware`, then the route entry's, each a
/// struct with `on_request`, `on_finished` or both (`server.middleware`). Each hook takes the
/// request context after the context.
///
/// The type is the router: a program places one, which does not move, and passes each event of its
/// engine to its `handle`. `options` sizes it: `options.requests` entries, each with
/// `options.response_bytes` of response memory, `options.body_bytes` of body memory and
/// `options.header_bytes` for a copy of a header. `match` stays for a program that dispatches a
/// request itself. Its `found` gives the route's `Route` tag, named by its method and its pattern,
/// such as `.@"GET /users/:id"`.
pub fn Router(comptime Context: type, comptime table: anytype, comptime options: Options) type {
    router_call.check_table(Context, table);
    const RouteTag = route_enum(table.routes);
    const Table = @TypeOf(router_table.table_of(RouteTag, values_of(RouteTag, table.routes)));
    router_handler.check(Context, table);
    return router_pool.Pool(Context, table, RouteTag, Table, options);
}

/// The sizes of a router (decision 158 ruling 4).
pub const Options = router_pool.Options;

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

test "decision 158: a router's type exports Route, Match, match, memory_bytes and handle" {
    const Sample = Router(void, router_call.sample_table, .{ .requests = 1, .response_bytes = 0, .header_bytes = 0 });
    try @import("core").public_names.expect(Sample, &.{ "Route", "Match", "match", "memory_bytes", "handle" });
}

test "decision 158 ruling 16: a router's options default to 32 requests of 256 response octets" {
    const options: router_pool.Options = .{ .header_bytes = 0 };
    try std.testing.expectEqual(32, options.requests);
    try std.testing.expectEqual(256, options.response_bytes);
    try std.testing.expectEqual(0, options.body_bytes);
}

test "decision 163 ruling 5: header_bytes has no default, so a program names it" {
    const field = std.meta.fieldIndex(router_pool.Options, "header_bytes").?;
    try std.testing.expectEqual(null, @typeInfo(router_pool.Options).@"struct".fields[field].default_value_ptr);
}

test {
    _ = @import("router_handle_test.zig");
    _ = @import("router_struct_test.zig");
    _ = @import("router_middleware_test.zig");
    _ = @import("router_context_test.zig");
    _ = @import("router_wrap_test.zig");
    _ = @import("router_stream_test.zig");
    _ = @import("router_stream_h3_test.zig");
    _ = @import("router_duplex_test.zig");
    _ = @import("router_duplex_h3_test.zig");
    _ = @import("router_whole_test.zig");
    _ = @import("router_whole_head_test.zig");
    _ = @import("router_copy.zig");
    _ = @import("router_path.zig");
}
