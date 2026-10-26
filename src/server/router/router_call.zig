//! How the router calls a route's function: the five arguments it builds, and the error function
//! it calls after an error (decision 127 rulings 2 and 4, design §8 step 25.3). The root exports
//! none of it.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;

/// A route's parts: the method, the pattern, the handler, then the options, which may be absent.
pub const handler_part = 2;
pub const options_part = 3;

/// The parameters a function takes after the path's and the query's: the response's writer. The
/// path's come three from the end, and the query's two.
const path_from_end = 3;
const query_from_end = 2;

/// The name of the parameter a trailing "*" binds, and the field of the path struct that holds it.
const wildcard_name = "*";
const rest_field = "rest";

/// Why the router refuses a route table as a whole. Each name is the one the compile error writes.
pub const TableReason = enum {
    route_table_shape,
    routes_missing,
    table_field_unknown,
    error_handler_missing,
    error_handler_type,

    /// The sentence that the compile error writes after the name. Comptime-only.
    pub fn sentence(reason: TableReason) []const u8 {
        return switch (reason) {
            .route_table_shape => "a route table is a struct with error_handler and routes (decision 127)",
            .routes_missing => "a route table names routes, a tuple of route entries",
            .table_field_unknown => "a route table holds error_handler, routes and middleware alone",
            .error_handler_missing => "a route table names error_handler, which chooses the status after an error (decision 127 ruling 4)",
            .error_handler_type => "error_handler takes the context, *const server.Request, anyerror and *server.ResponseWriter, and returns void",
        };
    }
};

/// Stops the compile when the route table as a whole is refused. Comptime-only.
pub fn check_table(comptime Context: type, comptime table: anytype) void {
    if (table_refusal(Context, table)) |reason| {
        @compileError(std.fmt.comptimePrint("server.router: route table: {s}: {s}", .{ @tagName(reason), reason.sentence() }));
    }
}

fn table_refusal(comptime Context: type, comptime table: anytype) ?TableReason {
    const Table = @TypeOf(table);
    if (@typeInfo(Table) != .@"struct" or @typeInfo(Table).@"struct".is_tuple) return .route_table_shape;
    if (!@hasField(Table, "routes")) return .routes_missing;
    for (@typeInfo(Table).@"struct".fields) |field| {
        const known = std.mem.eql(u8, field.name, "routes") or std.mem.eql(u8, field.name, "error_handler") or
            std.mem.eql(u8, field.name, middleware_field);
        if (!known) return .table_field_unknown;
    }
    if (!@hasField(Table, "error_handler")) return .error_handler_missing;
    const Handler = fn (*Context, *const event.Request, anyerror, *ResponseWriter) void;
    if (@TypeOf(table.error_handler) != Handler) return .error_handler_type;
    return null;
}

/// What a call of a route's function ended in.
pub const Outcome = union(enum) {
    /// The function returned.
    returned,
    /// The function returned this error.
    failed: anyerror,
    /// The router answered with this status before the call: the query has more pairs than it
    /// holds, or lacks one the function requires.
    refused: u16,
    /// An `on_body` read all the bytes that arrived and returned `error.ReadFailed`: it waits for more.
    waiting,
};

/// The memory the router reads a query into, which each call shares: the call reads it before it
/// returns.
pub const QueryMemory = struct {
    parameters: http.QueryParameters = .{},
    storage: [query_storage_len]u8 = undefined,
};

/// Octets of a query's decoded names and values. A query is part of a path that the endpoint
/// bounds, and decoding only shortens it.
const query_storage_len = @import("../constants.zig").path_len_max;

/// The options a route entry may carry after its function, other than its middleware.
pub const RouteOptions = struct {
    /// The router calls the route's `on_body` once, after the request's last byte, with every byte.
    whole_body: bool = false,
};

/// The name of the option, and of the route table's field, that holds a tuple of middleware.
pub const middleware_field = "middleware";

/// The middleware of the route table. The router calls them before a route entry's own.
pub fn table_chain(comptime table: anytype) TableChain(@TypeOf(table)) {
    if (comptime @hasField(@TypeOf(table), middleware_field)) return @field(table, middleware_field);
    return .{};
}

fn TableChain(comptime Table: type) type {
    if (@hasField(Table, middleware_field)) return @FieldType(Table, middleware_field);
    return @TypeOf(.{});
}

/// The middleware of a route entry, from its options.
pub fn entry_chain(comptime entry: anytype) EntryChain(@TypeOf(entry)) {
    if (comptime EntryChain(@TypeOf(entry)) == @TypeOf(.{})) return .{};
    return @field(entry[options_part], middleware_field);
}

fn EntryChain(comptime Entry: type) type {
    const fields = @typeInfo(Entry).@"struct".fields;
    if (fields.len <= options_part) return @TypeOf(.{});
    const Options = fields[options_part].type;
    if (@typeInfo(Options) != .@"struct" or !@hasField(Options, middleware_field)) return @TypeOf(.{});
    return @FieldType(Options, middleware_field);
}

/// What a chain of middleware ended in.
pub const Passed = union(enum) {
    /// Each middleware returned `.next`.
    next,
    /// A middleware answered the request.
    answered,
    /// A middleware returned this error.
    failed: anyerror,
};

/// Calls each middleware of `chain` that declares `on_request`, in order, until one answers or
/// fails. `ran` counts the middleware the chain reached, the one that answered or failed included,
/// whose `on_finished` the router calls when the request ends.
pub fn run_chain(comptime chain: anytype, context: anytype, request: *const event.Request, response: *ResponseWriter, ran: *u16) Passed {
    comptime std.debug.assert(chain.len <= std.math.maxInt(u16));
    inline for (0..chain.len) |index| {
        const Middleware = chain[index];
        ran.* = index + 1;
        if (comptime @hasDecl(Middleware, "on_request")) {
            const result = Middleware.on_request(context, request, response);
            const next = if (@typeInfo(@TypeOf(result)) == .error_union) (result catch |failure| return .{ .failed = failure }) else result;
            if (next == .answered) return .answered;
        }
    }
    return .next;
}

/// Calls the `on_finished` of each middleware the chain reached, in the reverse order, as code
/// after `next()` runs in a framework whose middleware wraps the next one.
pub fn finish_chain(comptime chain: anytype, ran: u16, context: anytype, id: event.RequestId, result: event.Result) void {
    std.debug.assert(ran <= chain.len);
    inline for (0..chain.len) |reverse| {
        const index = chain.len - 1 - reverse;
        if (comptime @hasDecl(chain[index], "on_finished")) {
            if (index < ran) chain[index].on_finished(context, id, result);
        }
    }
}

/// A route's handler: a function, or a struct of `on_request` and any of `on_body`,
/// `on_writable` and `on_finished`, with a `State`. Comptime-only.
pub fn is_struct(comptime handler: anytype) bool {
    return @TypeOf(handler) == type;
}

/// The state a struct route keeps in its request's entry, or `void` for a route with none.
/// Comptime-only.
pub fn StateOf(comptime handler: anytype) type {
    if (comptime is_struct(handler) and @hasDecl(handler, "State")) return handler.State;
    return void;
}

/// Whether a struct route declares `name`. Comptime-only.
pub fn has(comptime handler: anytype, comptime name: []const u8) bool {
    return comptime is_struct(handler) and @hasDecl(handler, name);
}

/// Calls a route's function, or its `on_request`, with the arguments of decision 127: the context, the
/// state of a struct route, the request, the path, the query and the response.
pub fn call_on_request(
    comptime handler: anytype,
    context: anytype,
    state: *StateOf(handler),
    request: *const event.Request,
    parameters: *const PathParameters,
    query: *QueryMemory,
    response: *ResponseWriter,
) Outcome {
    const function = if (comptime is_struct(handler)) handler.on_request else handler;
    const params = function_info(@TypeOf(function)).params;
    const path = path_of(params[params.len - path_from_end].type.?, parameters);
    const query_value = query_of(params[params.len - query_from_end].type.?, request.query orelse "", query) catch |failure| return .{ .refused = status_of(failure) };
    if (comptime is_struct(handler)) return outcome_of(function(context, state, request, path, query_value, response));
    return outcome_of(function(context, request, path, query_value, response));
}

/// Calls a struct route's `on_body` with the reader over the bytes that arrived.
pub fn call_body(comptime handler: anytype, context: anytype, state: *StateOf(handler), reader: *std.Io.Reader, response: *ResponseWriter) Outcome {
    return outcome_of(handler.on_body(context, state, reader, response));
}

/// Calls a struct route's `on_writable`.
pub fn call_writable(comptime handler: anytype, context: anytype, state: *StateOf(handler), response: *ResponseWriter) Outcome {
    return outcome_of(handler.on_writable(context, state, response));
}

fn outcome_of(result: anytype) Outcome {
    if (@typeInfo(@TypeOf(result)) != .error_union) return .returned;
    result catch |failure| {
        if (failure == error.ReadFailed) return .waiting;
        return .{ .failed = failure };
    };
    return .returned;
}

/// The function type of a route's function, which a table of one entry type holds by pointer.
fn function_info(comptime Function: type) std.builtin.Type.Fn {
    return switch (@typeInfo(Function)) {
        .@"fn" => |info| info,
        .pointer => |pointer| @typeInfo(pointer.child).@"fn",
        else => @compileError("server.router: a route holds a function (decision 127)"),
    };
}

fn path_of(comptime Path: type, parameters: *const PathParameters) Path {
    if (Path == void) return {};
    var path: Path = undefined;
    inline for (@typeInfo(Path).@"struct".fields) |field| {
        const name = if (comptime std.mem.eql(u8, field.name, rest_field)) wildcard_name else field.name;
        // Design §8 step 25.4: the compiler checks each field against the pattern's names.
        @field(path, field.name) = parameters.get(name).?;
    }
    return path;
}

/// A status the router answers with instead of a call.
const uri_too_long: u16 = @intFromEnum(http.status.Code.uri_too_long);
const bad_request: u16 = @intFromEnum(http.status.Code.bad_request);

fn query_of(comptime Query: type, raw: []const u8, query: *QueryMemory) error{ UriTooLong, BadRequest }!Query {
    if (Query == void) return {};
    // RFC 9110 §15.5.15: a target longer than the server reads gets 414.
    query.parameters.read(raw, &query.storage) catch return error.UriTooLong;
    if (Query == http.QueryParameters) return query.parameters;
    var value: Query = undefined;
    inline for (@typeInfo(Query).@"struct".fields) |field| {
        @field(value, field.name) = try field_of(field, query.parameters.get(field.name));
    }
    return value;
}

fn field_of(comptime field: std.builtin.Type.StructField, found: ?[]const u8) error{BadRequest}!field.type {
    if (field.type == ?[]const u8) return found;
    if (found) |bytes| return bytes;
    if (field.defaultValue()) |default| return default;
    // RFC 9110 §15.5.1: a request the server cannot process for a client's error gets 400.
    return error.BadRequest;
}

/// The status of a query the router refused.
fn status_of(failure: error{ UriTooLong, BadRequest }) u16 {
    return switch (failure) {
        error.UriTooLong => uri_too_long,
        error.BadRequest => bad_request,
    };
}

/// A table of one route, which the tests of the router's names build. Test-only.
pub const sample_table = .{ .error_handler = sample_error, .routes = .{.{ .get, "/", sample_route }} };

fn sample_route(_: *void, _: *const event.Request, _: void, _: void, response: *ResponseWriter) !void {
    try response.end();
}

fn sample_error(_: *void, _: *const event.Request, _: anyerror, _: *ResponseWriter) void {}
