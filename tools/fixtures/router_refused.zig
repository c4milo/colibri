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
const valid = .{ .get, "/", 0 };

const tables = struct {
    /// Each kind of method and pattern that a table accepts at design §8 step 21e.6: an enum
    /// literal, a value of `http.method.Standard`, a token, the root, literal segments,
    /// parameters and the wildcard.
    pub const accepted = .{
        .{ .get, "/", 0 },
        .{ http.method.Standard.put, "/users/me", 1 },
        .{ "PATCH", "/users/me", 2 },
        .{ .delete, "/a.b/~c/d@e:f", 3 },
        .{ .get, "/files/:name/parts/:part_2", 4 },
        .{ .put, "/files/:name", 5 },
        .{ .get, "/static/*", 6 },
    };
    pub const pattern_not_absolute = .{ valid, .{ .get, "users", 1 } };
    pub const segment_empty = .{ valid, .{ .get, "/a//b", 1 } };
    pub const segment_dot = .{ valid, .{ .get, "/a/./b", 1 } };
    pub const segment_encoded = .{ valid, .{ .get, "/caf%C3%A9", 1 } };
    pub const octet_outside_path = .{ valid, .{ .get, "/a b", 1 } };
    pub const parameter_unnamed = .{ valid, .{ .get, "/users/:", 1 } };
    pub const parameter_name_invalid = .{ valid, .{ .get, "/:user-id", 1 } };
    pub const parameter_repeated = .{ valid, .{ .get, "/:id/posts/:id", 1 } };
    pub const parameters_too_many = .{ valid, .{ .get, "/:a/:b/:c/:d/:e/:f/:g/:h/:i", 1 } };
    pub const wildcard_not_last = .{ valid, .{ .get, "/files/*/meta", 1 } };
    pub const method_unknown = .{ valid, .{ .gte, "/a", 1 } };
    pub const method_not_token = .{ valid, .{ "GET ", "/a", 1 } };
    pub const method_standard_as_token = .{ valid, .{ "GET", "/a", 1 } };
    pub const method_connect = .{ valid, .{ .connect, "/a", 1 } };
    pub const method_type = .{ valid, .{ 42, "/a", 1 } };
    pub const table_empty = .{};
    pub const entry_shape = .{ valid, .{ .get, "/a" } };
    pub const parameter_names_differ = .{ .{ .get, "/users/:id", 0 }, .{ .put, "/users/:user", 1 } };
    pub const route_repeated = .{ .{ .get, "/a", 0 }, .{ .get, "/a", 1 } };
    /// A token one octet longer than `core.constants.field_value_len_max`.
    pub const allow_too_long = .{ valid, .{ "A" ** (http.core.constants.field_value_len_max + 1), "/a", 1 } };
    /// The table of the cost of decision 122 ruling 12: a PUT of `/users/me` gets 405 from the
    /// GET route.
    pub const route_hidden = .{ .{ .get, "/users/me", 0 }, .{ .put, "/users/:id", 1 } };
    /// The owner's example 8 of decision 122 ruling 12.
    pub const route_unreachable = .{ .{ .get, "/a/:x", 0 }, .{ .get, "/a/*", 1 }, .{ .get, "/a/:x/*", 2 } };
};

comptime {
    _ = server.router(u8, @field(tables, case));
}
