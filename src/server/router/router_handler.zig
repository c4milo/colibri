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

/// Why the router refuses a route's handler. Each name is the one the compile error writes.
pub const Reason = enum {
    handler_type,
    head_missing,
    parameters_count,
    context_parameter,
    state_parameter,
    request_parameter,
    path_parameter,
    path_fields_differ,
    query_parameter,
    response_parameter,
    return_type,
    body_parameters,
    writable_parameters,
    finished_parameters,
    state_defaults,
    option_unknown,
    whole_body_unread,

    /// The sentence that the compile error writes after the name. Comptime-only.
    pub fn sentence(reason: Reason) []const u8 {
        return switch (reason) {
            .handler_type => "a route holds a function, or a struct with head (decision 127)",
            .head_missing => "a struct route declares pub fn head (decision 127)",
            .parameters_count => "a route's function takes five parameters, and head six (decision 127)",
            .context_parameter => "the first parameter is a pointer to the router's Context",
            .state_parameter => "head, body, writable and finished take a *State after the context",
            .request_parameter => "the request parameter is *const server.Request",
            .path_parameter => "the path parameter is void, or a struct of []const u8 fields",
            .path_fields_differ => "the path struct has one field for each parameter of the pattern, and rest for its \"*\"",
            .query_parameter => "the query parameter is void, http.QueryParameters, or a struct of []const u8 and ?[]const u8 fields",
            .response_parameter => "the last parameter is *server.ResponseWriter",
            .return_type => "a route's function returns void or an error union of void",
            .body_parameters => "body takes the context, *State, *std.Io.Reader and *server.ResponseWriter",
            .writable_parameters => "writable takes the context, *State and *server.ResponseWriter",
            .finished_parameters => "finished takes the context, *State and server.Result, and returns void",
            .state_defaults => "each field of State has a default value, which each request starts from",
            .option_unknown => "a route's options are whole_body alone",
            .whole_body_unread => "whole_body needs a struct route with body",
        };
    }
};

/// Stops the compile at the first route whose handler the router refuses. Comptime-only.
pub fn check(comptime Context: type, comptime routes: anytype) void {
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
    if (options_refusal(entry)) |reason| return reason;
    if (comptime !router_call.is_struct(handler)) {
        const Function = function_type(@TypeOf(handler)) orelse return .handler_type;
        return function_refusal(Context, null, Function, entry[1]);
    }
    if (@typeInfo(handler) != .@"struct") return .handler_type;
    if (!@hasDecl(handler, "head")) return .head_missing;
    const State = router_call.StateOf(handler);
    if (state_refusal(State)) |reason| return reason;
    if (function_refusal(Context, State, @TypeOf(handler.head), entry[1])) |reason| return reason;
    return calls_refusal(Context, State, handler);
}

fn options_refusal(comptime entry: anytype) ?Reason {
    if (entry.len <= router_call.options_part) return null;
    const Options = @TypeOf(entry[router_call.options_part]);
    if (@typeInfo(Options) != .@"struct") return .option_unknown;
    for (@typeInfo(Options).@"struct".fields) |field| {
        if (!@hasField(router_call.RouteOptions, field.name)) return .option_unknown;
    }
    const handler = entry[router_call.handler_part];
    if (@hasField(Options, "whole_body") and !router_call.has(handler, "body")) return .whole_body_unread;
    return null;
}

/// The function type of a function, or of a pointer to one, or null.
fn function_type(comptime Handler: type) ?type {
    return switch (@typeInfo(Handler)) {
        .@"fn" => Handler,
        .pointer => |pointer| if (@typeInfo(pointer.child) == .@"fn") pointer.child else null,
        else => null,
    };
}

/// The checks of a function, or of a struct's `head`, which takes `*State` after the context.
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
/// these places. A struct's `head` takes its state after the context, one place on.
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

/// The checks of a struct route's `body`, `writable` and `finished`.
fn calls_refusal(comptime Context: type, comptime State: type, comptime handler: type) ?Reason {
    const Stated = if (State == void) *void else *State;
    if (@hasDecl(handler, "body") and !takes(handler.body, &.{ *Context, Stated, *std.Io.Reader, *ResponseWriter })) return .body_parameters;
    if (@hasDecl(handler, "writable") and !takes(handler.writable, &.{ *Context, Stated, *ResponseWriter })) return .writable_parameters;
    if (@hasDecl(handler, "finished")) {
        if (!takes(handler.finished, &.{ *Context, Stated, event.Result })) return .finished_parameters;
        if (@typeInfo(@TypeOf(handler.finished)).@"fn".return_type.? != void) return .finished_parameters;
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
