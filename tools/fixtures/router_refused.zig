//! The tables of `zig build router-check` (build/router_check.zig, decision 122). The build option
//! `case` names one declaration of `tables`, and the `comptime` block below builds that table
//! alone. Zig analyses only the declaration that the block names, so the other tables do not
//! change the result.
//!
//! The table `accepted` must compile. Each other table must fail to compile, with the refusal of
//! its name. In a refused table the first entry is valid, so the message must name route 1.
const server = @import("server");
const http = @import("http");
const case = @import("router_case").case;

/// A valid entry, which each refused table holds first.
const valid = .{ .get, "/", route };

const tables = struct {
    /// Each kind of method and pattern that a table accepts at design §8 step 21e.6: an enum
    /// literal, a value of `http.method.Standard`, a token, the root, literal segments,
    /// parameters and the wildcard.
    pub const accepted = .{
        .{ .get, "/", route },
        .{ http.method.Standard.put, "/users/me", route },
        .{ "PATCH", "/users/me", route },
        .{ .delete, "/a.b/~c/d@e:f", route },
        .{ .get, "/files/:name/parts/:part_2", route },
        .{ .put, "/files/:name", route },
        .{ .get, "/static/*", route },
    };
    pub const pattern_not_absolute = .{ valid, .{ .get, "users", route } };
    pub const segment_empty = .{ valid, .{ .get, "/a//b", route } };
    pub const segment_dot = .{ valid, .{ .get, "/a/./b", route } };
    pub const segment_encoded = .{ valid, .{ .get, "/caf%C3%A9", route } };
    pub const octet_outside_path = .{ valid, .{ .get, "/a b", route } };
    pub const parameter_unnamed = .{ valid, .{ .get, "/users/:", route } };
    pub const parameter_name_invalid = .{ valid, .{ .get, "/:user-id", route } };
    pub const parameter_repeated = .{ valid, .{ .get, "/:id/posts/:id", route } };
    pub const parameters_too_many = .{ valid, .{ .get, "/:a/:b/:c/:d/:e/:f/:g/:h/:i", route } };
    pub const wildcard_not_last = .{ valid, .{ .get, "/files/*/meta", route } };
    pub const method_unknown = .{ valid, .{ .gte, "/a", route } };
    pub const method_not_token = .{ valid, .{ "GET ", "/a", route } };
    pub const method_standard_as_token = .{ valid, .{ "GET", "/a", route } };
    pub const method_connect = .{ valid, .{ .connect, "/a", route } };
    pub const method_type = .{ valid, .{ 42, "/a", route } };
    pub const table_empty = .{};
    pub const entry_shape = .{ valid, .{ .get, "/a" } };
    pub const parameter_names_differ = .{ .{ .get, "/users/:id", route }, .{ .put, "/users/:user", route } };
    pub const route_repeated = .{ .{ .get, "/a", route }, .{ .get, "/a", route } };
    /// A token one octet longer than `core.constants.field_value_len_max`.
    pub const allow_too_long = .{ valid, .{ "A" ** (http.core.constants.field_value_len_max + 1), "/a", route } };
    /// The table of the cost of decision 122 ruling 12: a PUT of `/users/me` gets 405 from the
    /// GET route.
    pub const route_hidden = .{ .{ .get, "/users/me", route }, .{ .put, "/users/:id", route } };
    /// The owner's example 8 of decision 122 ruling 12.
    pub const route_unreachable = .{ .{ .get, "/a/:x", route }, .{ .get, "/a/*", route }, .{ .get, "/a/:x/*", route } };
};

comptime {
    _ = server.router(void, .{ .error_handler = on_error, .routes = @field(tables, case) });
}

/// The function of every route of the fixture.
fn route(_: *void, _: *const server.Request, _: void, _: void, _: *server.ResponseWriter) !void {}

fn on_error(_: *void, _: *const server.Request, _: anyerror, _: *server.ResponseWriter) void {}
