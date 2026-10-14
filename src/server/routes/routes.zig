//! `server.routes`: a table of routes that the compiler builds, and the one call that matches a
//! method and a path against it (decision 122, design §8 step 21e). colibri calls no function of
//! the program's (decision 118): `match` gives the route's value, and the program acts on it.
const PathParameters = @import("../path_parameters.zig").PathParameters;
const routes_trie = @import("routes_trie.zig");
const routes_trie_layout = @import("routes_trie_layout.zig");
const routes_match = @import("routes_match.zig");

/// Builds a route table at compile time. `table` is a tuple, or an array, of entries, and each
/// entry is a tuple of a method, a pattern and a value: `.{ .get, "/greeting", .greeting }`.
///
/// - The method is an enum literal or a value of `http.method.Standard`, or the token of a
///   method outside RFC 9110 §9.1's eight, such as `"PATCH"`.
/// - The pattern is a path of segments, or "/" for the root. A segment is a literal, or a
///   parameter: ":" and a name of `1*( ALPHA / DIGIT / "_" )`, such as `/users/:id`. A
///   parameter matches one segment of a path, and a program reads its value with
///   `PathParameters.get`. The last segment can be the wildcard "*", such as `/files/*`. It
///   matches one segment or more, and `get("*")` gives the rest of the path.
/// - The value coerces to `Value`, which is a type that exists at run time: an enum, a pointer to
///   a function, or a struct. `match` reads the value at run time, so `Value` is not a `type` or
///   a bare `fn` type.
///
/// A HEAD request finds the GET route of a path that names no HEAD route (RFC 9110 §9.1,
/// §9.3.2). The endpoint writes no content in a response to HEAD, so a program writes one answer
/// for GET and HEAD.
///
/// A malformed or conflicting table does not compile. The compile error names the entry, the
/// refusal and its reason.
///
/// Each call returns a value of a type of its own, with no field. Its one call is `match`, which
/// returns a `Match`. A program names that type as `@TypeOf(table).Match`.
pub fn routes(comptime Value: type, comptime table: anytype) Table(Value, table) {
    return .{};
}

fn Table(comptime Value: type, comptime table: anytype) type {
    // Decision 122: a malformed or conflicting table does not compile, and the message names the
    // entry and the rule.
    if (routes_trie.refusal_of(table)) |refusal| @compileError(routes_trie.message(refusal));
    const layout = routes_trie_layout.build(Value, table);
    return struct {
        /// What `match` gives: `found` with the route's value, `method_not_allowed` with the
        /// value of the Allow field that a 405 carries, `not_found`, or `not_implemented` for a
        /// method that no route of the table names (RFC 9110 §9.1, §15.6.2). An `OPTIONS *`
        /// request gets `not_implemented` from a table with no OPTIONS route, and `not_found`
        /// from a table with one.
        pub const Match = routes_match.Match(Value);

        /// The route that `method` and `path` name. `path` is `Request.path`, which may end in a
        /// query: the match stops at the first "?". `match` writes the path's parameters into
        /// `parameters`, and sets `parameters.count` to 0 first. It reads the method before the
        /// path, so a method that no route names gives `not_implemented` on any path. A HEAD
        /// request finds the GET route of a path with no HEAD route. The endpoint writes no
        /// content in a response to HEAD, so a program writes one answer for GET and HEAD.
        pub fn match(_: @This(), method: []const u8, path: []const u8, parameters: *PathParameters) Match {
            return routes_match.match(Value, layout, method, path, parameters);
        }
    };
}

test "decision 122: a table's type exports Match and match alone" {
    const sample = routes(u8, .{.{ .get, "/", 0 }});
    try @import("core").public_names.expect(@TypeOf(sample), &.{ "Match", "match" });
}
