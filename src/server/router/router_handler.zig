//! The compile-time checks of each route's function or struct (decision 127 ruling 3, design §8
//! step 25.4). A route whose function does not fit the five parameters of decision 127, whose path
//! struct does not name its pattern's parameters, or whose options the router does not read, does
//! not compile. The compile error names the route, as decision 122's refusals do.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const router_pattern = @import("router_pattern.zig");
const router_call = @import("router_call.zig");
const middleware = @import("../middleware.zig");
const router_wrap = @import("router_wrap.zig");

/// Why the router refuses a route's handler. Each name is the one the compile error writes.
pub const Reason = enum {
    handler_type,
    on_request_missing,
    parameters_count,
    context_parameter,
    state_parameter,
    request_parameter,
    path_parameter,
    path_fields_differ,
    query_parameter,
    response_parameter,
    return_type,
    on_body_parameters,
    on_writable_parameters,
    on_finished_parameters,
    state_defaults,
    option_unknown,
    whole_body_unread,
    middleware_type,
    middleware_hooks,
    middleware_on_request,
    middleware_on_finished,
    middleware_state_defaults,
    middleware_wrap_body,
    middleware_wrap_response,
    middleware_finish_response,

    /// The sentence that the compile error writes after the name. Comptime-only.
    pub fn sentence(reason: Reason) []const u8 {
        return switch (reason) {
            .handler_type => "a route holds a function, or a struct with on_request (decision 127)",
            .on_request_missing => "a struct route declares pub fn on_request (decision 127)",
            .parameters_count => "a route's function takes five parameters, and on_request six (decision 127)",
            .context_parameter => "the first parameter is a pointer to the router's Context",
            .state_parameter => "on_request, on_body, on_writable and on_finished take a *State after the context",
            .request_parameter => "the request parameter is *const server.Request",
            .path_parameter => "the path parameter is void, or a struct of []const u8 fields",
            .path_fields_differ => "the path struct has one field for each parameter of the pattern, and rest for its \"*\"",
            .query_parameter => "the query parameter is void, http.QueryParameters, or a struct of []const u8 and ?[]const u8 fields",
            .response_parameter => "the last parameter is *server.ResponseWriter",
            .return_type => "a route's function returns void or an error union of void",
            .on_body_parameters => "body takes the context, *State, *std.Io.Reader and *server.ResponseWriter",
            .on_writable_parameters => "writable takes the context, *State and *server.ResponseWriter",
            .on_finished_parameters => "finished takes the context, *State and server.Result, and returns void",
            .state_defaults => "each field of State has a default value, which each request starts from",
            .option_unknown => "a route's options are whole_body and middleware",
            .whole_body_unread => "whole_body needs a struct route with on_body",
            .middleware_type => "middleware is a tuple of structs (decision 127 ruling 5)",
            .middleware_hooks => "a middleware declares one or more of on_request, on_finished, wrap_body and wrap_response (decision 127 ruling 5)",
            .middleware_on_finished => "a middleware's on_finished takes the context, server.RequestId and server.Result, and returns void",
            .middleware_on_request => "a middleware's on_request takes the context, *const server.Request and *server.ResponseWriter, and returns server.middleware.Next",
            .middleware_state_defaults => "each field of a middleware's State has a default value, which each request starts from",
            .middleware_wrap_body => "wrap_body takes the context, *State, *const server.Request and *std.Io.Reader, and returns ?*std.Io.Reader",
            .middleware_wrap_response => "wrap_response takes the context, *State, *const server.Request, *server.ResponseWriter and *std.Io.Writer, and returns ?*std.Io.Writer",
            .middleware_finish_response => "finish_response goes with wrap_response, takes the context and *State, and returns an error union of void",
        };
    }
};

/// Stops the compile at the first middleware of the route table, then the first route, whose
/// handler the router refuses. Comptime-only.
pub fn check(comptime Context: type, comptime table: anytype) void {
    if (chain_refusal(Context, router_call.table_chain(table))) |reason| {
        @compileError(std.fmt.comptimePrint("server.router: middleware: {s}: {s}", .{ @tagName(reason), reason.sentence() }));
    }
    const routes = table.routes;
    for (0..routes.len) |index| {
        if (refusal_of(Context, routes[index])) |reason| {
            @compileError(std.fmt.comptimePrint("server.router: route {d}, \"{s}\": {s}: {s}", .{
                index, routes[index][1], @tagName(reason), reason.sentence(),
            }));
        }
    }
}

/// The first refusal of one route, or null. Comptime-only.
pub fn refusal_of(comptime Context: type, comptime entry: anytype) ?Reason {
    const handler = entry[router_call.handler_part];
    if (options_refusal(Context, entry)) |reason| return reason;
    if (comptime !router_call.is_struct(handler)) {
        const Function = function_type(@TypeOf(handler)) orelse return .handler_type;
        return function_refusal(Context, null, Function, entry[1]);
    }
    if (@typeInfo(handler) != .@"struct") return .handler_type;
    if (!@hasDecl(handler, "on_request")) return .on_request_missing;
    const State = router_call.StateOf(handler);
    if (state_refusal(State)) |reason| return reason;
    if (function_refusal(Context, State, @TypeOf(handler.on_request), entry[1])) |reason| return reason;
    return calls_refusal(Context, State, handler);
}

fn options_refusal(comptime Context: type, comptime entry: anytype) ?Reason {
    if (entry.len <= router_call.options_part) return null;
    const Options = @TypeOf(entry[router_call.options_part]);
    if (@typeInfo(Options) != .@"struct") return .option_unknown;
    for (@typeInfo(Options).@"struct".fields) |field| {
        const known = @hasField(router_call.RouteOptions, field.name) or std.mem.eql(u8, field.name, router_call.middleware_field);
        if (!known) return .option_unknown;
    }
    if (@hasField(Options, router_call.middleware_field)) {
        if (chain_refusal(Context, @field(entry[router_call.options_part], router_call.middleware_field))) |reason| return reason;
    }
    const handler = entry[router_call.handler_part];
    if (@hasField(Options, "whole_body") and !router_call.has(handler, "on_body")) return .whole_body_unread;
    return null;
}

/// The first refusal of a tuple of middleware, or null.
fn chain_refusal(comptime Context: type, comptime chain: anytype) ?Reason {
    const info = @typeInfo(@TypeOf(chain));
    if (info != .@"struct" or !info.@"struct".is_tuple) return .middleware_type;
    for (0..chain.len) |index| {
        if (@TypeOf(chain[index]) != type or @typeInfo(chain[index]) != .@"struct") return .middleware_type;
        if (hooks_refusal(Context, chain[index])) |reason| return reason;
    }
    return null;
}

/// The first refusal of one middleware's hooks, or null.
fn hooks_refusal(comptime Context: type, comptime Middleware: type) ?Reason {
    const requested = @hasDecl(Middleware, "on_request");
    const finished = @hasDecl(Middleware, "on_finished");
    if (!requested and !finished and !router_wrap.wraps(Middleware)) return .middleware_hooks;
    if (state_refusal(router_wrap.StateOf(Middleware)) != null) return .middleware_state_defaults;
    if (wrap_refusal(Context, Middleware)) |reason| return reason;
    if (requested) {
        if (!fits(@TypeOf(Middleware.on_request), &.{ *Context, *const event.Request, *ResponseWriter }, middleware.Next, true)) return .middleware_on_request;
    }
    if (finished) {
        if (!fits(@TypeOf(Middleware.on_finished), &.{ *Context, event.RequestId, event.Result }, void, false)) return .middleware_on_finished;
    }
    return null;
}

/// The first refusal of a middleware's `wrap_body`, `wrap_response` and `finish_response`, or
/// null (design §8 step 25.6).
fn wrap_refusal(comptime Context: type, comptime Middleware: type) ?Reason {
    const Stated = router_wrap.StatePointer(Middleware);
    if (@hasDecl(Middleware, "wrap_body")) {
        if (!fits(@TypeOf(Middleware.wrap_body), &.{ *Context, Stated, *const event.Request, *std.Io.Reader }, ?*std.Io.Reader, false)) return .middleware_wrap_body;
    }
    if (@hasDecl(Middleware, "wrap_response")) {
        if (!fits(@TypeOf(Middleware.wrap_response), &.{ *Context, Stated, *const event.Request, *ResponseWriter, *std.Io.Writer }, ?*std.Io.Writer, false)) return .middleware_wrap_response;
    }
    if (@hasDecl(Middleware, "finish_response")) {
        if (!@hasDecl(Middleware, "wrap_response")) return .middleware_finish_response;
        if (!takes(Middleware.finish_response, &.{ *Context, Stated })) return .middleware_finish_response;
    }
    return null;
}

/// Whether `Hook` is a function that takes exactly `types` and returns `Return`, or an error union
/// of it when `fallible` is true.
fn fits(comptime Hook: type, comptime types: []const type, comptime Return: type, comptime fallible: bool) bool {
    const info = @typeInfo(Hook);
    if (info != .@"fn" or !takes_types(info.@"fn", types)) return false;
    const returned = info.@"fn".return_type.?;
    return if (fallible) returns(returned, Return) else returned == Return;
}

/// Whether `info`'s parameters are exactly `types`.
fn takes_types(comptime info: std.builtin.Type.Fn, comptime types: []const type) bool {
    if (info.params.len != types.len) return false;
    for (info.params, types) |param, expected| {
        if (param.type != expected) return false;
    }
    return true;
}

/// Whether `Return` is `Payload`, or an error union of it.
fn returns(comptime Return: type, comptime Payload: type) bool {
    return switch (@typeInfo(Return)) {
        .error_union => |union_info| union_info.payload == Payload,
        else => Return == Payload,
    };
}

/// The function type of a function, or of a pointer to one, or null.
fn function_type(comptime Handler: type) ?type {
    return switch (@typeInfo(Handler)) {
        .@"fn" => Handler,
        .pointer => |pointer| if (@typeInfo(pointer.child) == .@"fn") pointer.child else null,
        else => null,
    };
}

/// The checks of a function, or of a struct's `on_request`, which takes `*State` after the
/// context.
/// `State` is null for a function, and `void` for a struct with no `State`.
fn function_refusal(comptime Context: type, comptime State: ?type, comptime Function: type, comptime pattern: []const u8) ?Reason {
    const info = @typeInfo(Function).@"fn";
    const params = info.params;
    const stated: usize = @intFromBool(State != null);
    if (params.len != function_parameters + stated) return .parameters_count;
    if (params[0].type != *Context) return .context_parameter;
    if (State) |Held| {
        if (params[1].type != *Held) return .state_parameter;
    }
    if (params[request_index + stated].type != *const event.Request) return .request_parameter;
    if (path_refusal(params[path_index + stated].type.?, pattern)) |reason| return reason;
    if (!is_query(params[query_index + stated].type.?)) return .query_parameter;
    if (params[response_index + stated].type != *ResponseWriter) return .response_parameter;
    if (!returns_void(info.return_type.?)) return .return_type;
    return null;
}

/// A function's parameters: the context, the request, the path, the query and the response, at
/// these places. A struct's `on_request` takes its state after the context, one place on.
const function_parameters = 5;
const request_index = 1;
const path_index = 2;
const query_index = 3;
const response_index = 4;

fn path_refusal(comptime Path: type, comptime pattern: []const u8) ?Reason {
    // A route that takes void reads none of its pattern's parameters.
    if (Path == void) return null;
    const names = parameter_names(pattern);
    if (@typeInfo(Path) != .@"struct") return .path_parameter;
    const fields = @typeInfo(Path).@"struct".fields;
    for (fields) |field| {
        if (field.type != []const u8) return .path_parameter;
    }
    if (fields.len != names.len) return .path_fields_differ;
    for (names) |name| {
        if (!@hasField(Path, name)) return .path_fields_differ;
    }
    return null;
}

/// The field names a path struct holds for `pattern`: each parameter's name, and `rest` for the
/// wildcard. Comptime-only.
fn parameter_names(comptime pattern: []const u8) []const []const u8 {
    var names: []const []const u8 = &.{};
    var segments = std.mem.splitScalar(u8, pattern[1..], router_pattern.separator);
    while (segments.next()) |segment| {
        if (router_pattern.is_parameter(segment)) names = names ++ .{router_pattern.parameter_name(segment)};
        if (router_pattern.is_wildcard(segment)) names = names ++ .{"rest"};
    }
    return names;
}

fn is_query(comptime Query: type) bool {
    if (Query == void or Query == http.QueryParameters) return true;
    if (@typeInfo(Query) != .@"struct") return false;
    for (@typeInfo(Query).@"struct".fields) |field| {
        if (field.type != []const u8 and field.type != ?[]const u8) return false;
    }
    return true;
}

fn returns_void(comptime Return: type) bool {
    return switch (@typeInfo(Return)) {
        .void => true,
        .error_union => |union_info| union_info.payload == void,
        else => false,
    };
}

fn state_refusal(comptime State: type) ?Reason {
    if (State == void) return null;
    if (@typeInfo(State) != .@"struct") return .state_defaults;
    for (@typeInfo(State).@"struct".fields) |field| {
        if (field.default_value_ptr == null) return .state_defaults;
    }
    return null;
}

/// The checks of a struct route's `on_body`, `on_writable` and `on_finished`.
fn calls_refusal(comptime Context: type, comptime State: type, comptime handler: type) ?Reason {
    const Stated = if (State == void) *void else *State;
    if (@hasDecl(handler, "on_body") and !takes(handler.on_body, &.{ *Context, Stated, *std.Io.Reader, *ResponseWriter })) return .on_body_parameters;
    if (@hasDecl(handler, "on_writable") and !takes(handler.on_writable, &.{ *Context, Stated, *ResponseWriter })) return .on_writable_parameters;
    if (@hasDecl(handler, "on_finished")) {
        if (!takes(handler.on_finished, &.{ *Context, Stated, event.Result })) return .on_finished_parameters;
        if (@typeInfo(@TypeOf(handler.on_finished)).@"fn".return_type.? != void) return .on_finished_parameters;
    }
    return null;
}

/// Whether `function` takes exactly `types` and returns void or an error union of void.
fn takes(comptime function: anytype, comptime types: []const type) bool {
    const info = @typeInfo(@TypeOf(function));
    if (info != .@"fn" or info.@"fn".params.len != types.len) return false;
    for (info.@"fn".params, types) |param, expected| {
        if (param.type != expected) return false;
    }
    return returns_void(info.@"fn".return_type.?);
}
