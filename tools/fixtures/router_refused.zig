//! The tables of `zig build router-check` (build/router_check.zig, decision 122). The build option
//! `case` names one declaration of `tables`, and the `comptime` block below builds that table
//! alone. Zig analyses only the declaration that the block names, so the other tables do not
//! change the result.
//!
//! The table `accepted` must compile. Each other table must fail to compile, with the refusal of
//! its name. In a refused table the first entry is valid, so the message must name route 1.
const std = @import("std");
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
    pub const route_repeated = .{ .{ .get, "/a", route }, .{ .get, "/a", route } };
    /// A token one octet longer than `core.constants.field_value_len_max`.
    pub const allow_too_long = .{ valid, .{ "A" ** (http.core.constants.field_value_len_max + 1), "/a", route } };
    /// Eleven methods: RFC 9110's seven that a route may name, and four tokens. The eleventh is one
    /// past `route_methods_max` (decision 128 ruling 3).
    pub const methods_too_many = .{
        .{ .get, "/a", route },    .{ .head, "/a", route },    .{ .post, "/a", route },  .{ .put, "/a", route },
        .{ .delete, "/a", route }, .{ .options, "/a", route }, .{ .trace, "/a", route }, .{ "PATCH", "/a", route },
        .{ "A", "/a", route },     .{ "B", "/a", route },      .{ "C", "/a", route },
    };
    /// The owner's example 8 of decision 122 ruling 12.
    pub const route_unreachable = .{ .{ .get, "/a/:x", route }, .{ .get, "/a/*", route }, .{ .get, "/a/:x/*", route } };
    // The refusals of a route's handler (decision 127 ruling 3, design §8 step 25.4).
    pub const handler_type = .{ valid, .{ .get, "/a", 42 } };
    pub const handler_type_not_struct = .{ valid, .{ .get, "/a", u8 } };
    pub const on_request_missing = .{ valid, .{ .get, "/a", struct {} } };
    pub const parameters_count = .{ valid, .{ .get, "/a", handlers.four } };
    pub const context_parameter = .{ valid, .{ .get, "/a", handlers.context } };
    pub const state_parameter = .{ valid, .{ .get, "/a", handlers.Stated } };
    pub const request_parameter = .{ valid, .{ .get, "/a", handlers.request } };
    pub const path_parameter = .{ valid, .{ .get, "/a", handlers.path } };
    pub const path_fields_differ = .{ valid, .{ .get, "/a/:id", handlers.fields } };
    pub const path_field_type = .{ valid, .{ .get, "/a/:id", handlers.field_type } };
    pub const path_field_extra = .{ valid, .{ .get, "/a/:id", handlers.field_extra } };
    pub const query_parameter = .{ valid, .{ .get, "/a", handlers.query } };
    pub const response_parameter = .{ valid, .{ .get, "/a", handlers.response } };
    pub const return_type = .{ valid, .{ .get, "/a", handlers.returns } };
    pub const on_body_parameters = .{ valid, .{ .post, "/a", handlers.Body } };
    pub const on_writable_parameters = .{ valid, .{ .get, "/a", handlers.Writable } };
    pub const on_finished_parameters = .{ valid, .{ .get, "/a", handlers.Finished } };
    pub const finished_returns = .{ valid, .{ .get, "/a", handlers.FinishedReturns } };
    pub const state_defaults = .{ valid, .{ .get, "/a", handlers.Defaults } };
    pub const state_not_struct = .{ valid, .{ .get, "/a", handlers.NotStruct } };
    pub const option_unknown = .{ valid, .{ .get, "/a", route, .{ .streaming = true } } };
    pub const option_not_struct = .{ valid, .{ .get, "/a", route, 7 } };
    pub const middleware_type = .{ valid, .{ .get, "/a", route, .{ .middleware = .{42} } } };
    pub const middleware_on_request = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.NoNext} } } };
    // The refusals of a route table as a whole: each case holds a whole route table.
    pub const table_middleware_hooks = .{ .whole_table = .{ .error_handler = on_error, .middleware = .{struct {}}, .routes = .{valid} } };
    pub const middleware_on_finished = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.FinishedLate} } } };
    pub const middleware_on_finished_parameters = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.FinishedParameters} } } };
    pub const middleware_on_request_parameters = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.RequestParameters} } } };
    pub const middleware_state_defaults = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.WrapDefaults} } } };
    pub const middleware_wrap_body = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.WrapBody} } } };
    pub const middleware_wrap_response = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.WrapResponse} } } };
    pub const middleware_finish_response = .{ valid, .{ .get, "/a", route, .{ .middleware = .{handlers.FinishAlone} } } };
    pub const route_table_shape = .{ .whole_table = 42 };
    pub const routes_missing = .{ .whole_table = .{ .error_handler = on_error } };
    pub const table_field_unknown = .{ .whole_table = .{ .error_handler = on_error, .routes = .{valid}, .extra = 1 } };
    pub const error_handler_missing = .{ .whole_table = .{ .routes = .{valid} } };
    pub const error_handler_type = .{ .whole_table = .{ .error_handler = route, .routes = .{valid} } };
    pub const whole_body_unread = .{ valid, .{ .post, "/a", route, .{ .whole_body = true } } };
};

/// One handler for each refusal of a route's handler, each wrong in one way alone.
const handlers = struct {
    const Request = server.Request;
    const Writer = server.ResponseWriter;
    fn four(_: *void, _: *const Request, _: void, _: void) !void {}
    fn context(_: *u8, _: *const Request, _: void, _: void, _: *Writer) !void {}
    const Stated = struct {
        pub fn on_request(_: *void, _: *u8, _: *const Request, _: void, _: void, _: *Writer) !void {}
    };
    fn request(_: *void, _: Request, _: void, _: void, _: *Writer) !void {}
    fn path(_: *void, _: *const Request, _: u8, _: void, _: *Writer) !void {}
    fn fields(_: *void, _: *const Request, _: struct { name: []const u8 }, _: void, _: *Writer) !void {}
    fn field_type(_: *void, _: *const Request, _: struct { id: u8 }, _: void, _: *Writer) !void {}
    fn field_extra(_: *void, _: *const Request, _: struct { id: []const u8, name: []const u8 }, _: void, _: *Writer) !void {}
    fn query(_: *void, _: *const Request, _: void, _: struct { count: u32 }, _: *Writer) !void {}
    fn response(_: *void, _: *const Request, _: void, _: void, _: *u8) !void {}
    fn returns(_: *void, _: *const Request, _: void, _: void, _: *Writer) u8 {
        return 0;
    }
    fn plain_on_request(_: *void, _: *void, _: *const Request, _: void, _: void, _: *Writer) !void {}
    const Body = struct {
        pub const on_request = handlers.plain_on_request;
        pub fn on_body(_: *void, _: *void, _: []const u8, _: *Writer) !void {}
    };
    const Writable = struct {
        pub const on_request = handlers.plain_on_request;
        pub fn on_writable(_: *void, _: *void) !void {}
    };
    const Finished = struct {
        pub const on_request = handlers.plain_on_request;
        pub fn on_finished(_: *void, _: *void, _: u8) void {}
    };
    const FinishedReturns = struct {
        pub const on_request = handlers.plain_on_request;
        pub fn on_finished(_: *void, _: *void, _: server.Result) !void {}
    };
    const NotStruct = struct {
        pub const State = u8;
        pub fn on_request(_: *void, _: *u8, _: *const Request, _: void, _: void, _: *Writer) !void {}
    };
    const FinishedParameters = struct {
        pub fn on_finished(_: *void, _: u8, _: server.Result) void {}
    };
    const RequestParameters = struct {
        pub fn on_request(_: *void, _: *const Request) server.middleware.Next {
            return .next;
        }
    };
    const FinishedLate = struct {
        pub fn on_finished(_: *void, _: server.RequestId, _: server.Result) !void {}
    };
    const NoNext = struct {
        pub fn on_request(_: *void, _: *const Request, _: *Writer) !void {}
    };
    const Defaults = struct {
        pub const State = struct { count: u8 };
        pub fn on_request(_: *void, _: *State, _: *const Request, _: void, _: void, _: *Writer) !void {}
    };
    const WrapDefaults = struct {
        pub const State = struct { count: u8 };
        pub fn wrap_body(_: *void, _: *State, _: *const Request, _: *std.Io.Reader) ?*std.Io.Reader {
            return null;
        }
    };
    const WrapBody = struct {
        pub fn wrap_body(_: *void, _: *void, _: *const Request, _: *std.Io.Reader) *std.Io.Reader {
            unreachable;
        }
    };
    const WrapResponse = struct {
        pub fn wrap_response(_: *void, _: *void, _: *const Request, _: *std.Io.Writer) ?*std.Io.Writer {
            return null;
        }
    };
    const FinishAlone = struct {
        pub fn on_finished(_: *void, _: server.RequestId, _: server.Result) void {}
        pub fn finish_response(_: *void, _: *void) !void {}
    };
};

comptime {
    _ = server.router(void, table_of(@field(tables, case)));
}

/// The route table of a case: the whole route table a case holds in `whole_table`, and else a
/// route table of the case's route entries.
fn table_of(comptime held: anytype) TableOf(@TypeOf(held)) {
    if (comptime is_whole(@TypeOf(held))) return held.whole_table;
    return .{ .error_handler = on_error, .routes = held };
}

fn TableOf(comptime Held: type) type {
    if (is_whole(Held)) return @FieldType(Held, "whole_table");
    return struct { error_handler: @TypeOf(on_error), routes: Held };
}

fn is_whole(comptime Held: type) bool {
    return @typeInfo(Held) == .@"struct" and @hasField(Held, "whole_table");
}

/// The function of every route of the fixture.
fn route(_: *void, _: *const server.Request, _: void, _: void, _: *server.ResponseWriter) !void {}

fn on_error(_: *void, _: *const server.Request, _: anyerror, _: *server.ResponseWriter) void {}
