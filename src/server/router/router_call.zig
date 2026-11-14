//! How the router calls a route's function: the four arguments of decision 163, the path and the
//! query it lends the request context, and the error function it calls after an error (decision
//! 127 rulings 2 and 4, design §8 step 25.3). The root exports none of it.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const Response = @import("../response/response.zig").Response;
const request_context = @import("../request_context.zig");
const RequestContext = request_context.RequestContext;
const router_wrap = @import("router_wrap.zig");

/// A route's parts: the method, the pattern, the handler, then the options, which may be absent.
pub const handler_part = 2;
pub const options_part = 3;

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
    values_type,

    /// The sentence that the compile error writes after the name. Comptime-only.
    pub fn sentence(reason: TableReason) []const u8 {
        return switch (reason) {
            .route_table_shape => "a route table is a struct with error_handler and routes (decision 127)",
            .routes_missing => "a route table names routes, a tuple of route entries",
            .table_field_unknown => "a route table holds error_handler, routes, middleware and Values alone",
            .error_handler_missing => "a route table names error_handler, which chooses the status after an error (decision 127 ruling 4)",
            .error_handler_type => "error_handler takes the context, *server.RequestContext, *const server.Request, anyerror and *server.Response, and returns void",
            .values_type => "Values is a struct whose fields each have a default, which each request starts from (decision 163)",
        };
    }
};

/// Stops the compile when the route table as a whole is refused. Comptime-only.
pub fn check_table(comptime Context: type, comptime table: anytype) void {
    if (table_refusal(Context, table)) |reason| {
        @compileError(std.fmt.comptimePrint("server.Router: route table: {s}: {s}", .{ @tagName(reason), reason.sentence() }));
    }
}

fn table_refusal(comptime Context: type, comptime table: anytype) ?TableReason {
    const Table = @TypeOf(table);
    if (@typeInfo(Table) != .@"struct" or @typeInfo(Table).@"struct".is_tuple) return .route_table_shape;
    if (!@hasField(Table, "routes")) return .routes_missing;
    for (@typeInfo(Table).@"struct".fields) |field| {
        const known = std.mem.eql(u8, field.name, "routes") or std.mem.eql(u8, field.name, "error_handler") or
            std.mem.eql(u8, field.name, middleware_field) or std.mem.eql(u8, field.name, values_field);
        if (!known) return .table_field_unknown;
    }
    if (!@hasField(Table, "error_handler")) return .error_handler_missing;
    const Handler = fn (*Context, *RequestContext, *const event.Request, anyerror, *Response) void;
    if (@TypeOf(table.error_handler) != Handler) return .error_handler_type;
    if (!values_defaulted(Values(table))) return .values_type;
    return null;
}

/// The name of the route table's field that names the type of each request's values.
pub const values_field = "Values";

/// The type of each request's values: the route table's `Values`, or an empty struct (decision
/// 163 ruling 2). Comptime-only.
pub fn Values(comptime table: anytype) type {
    if (@hasField(@TypeOf(table), values_field)) return @field(table, values_field);
    return struct {};
}

/// Whether `T` is a struct whose fields each have a default. Comptime-only.
fn values_defaulted(comptime T: type) bool {
    if (@TypeOf(T) != type or @typeInfo(T) != .@"struct") return false;
    for (@typeInfo(T).@"struct".fields) |field| {
        if (field.default_value_ptr == null) return false;
    }
    return true;
}

/// What a call of a route's function ended in.
pub const Outcome = union(enum) {
    /// The function returned.
    returned,
    /// The function returned this error.
    failed: anyerror,
    /// The router answered with this status before the call: the query has more pairs than it
    /// holds, or lacks one the function requires.
    refused: http.Status,
    /// A struct route read all the bytes that arrived and returned `error.ReadFailed`: it waits
    /// for more.
    waiting,
};

/// The memory the router reads a query into, which each call shares: the call reads it before it
/// returns.
pub const QueryMemory = struct {
    parameters: http.QueryParameters = .{},
    storage: [query_storage_len]u8 = undefined,
};

/// Octets of a query's decoded names and values. A query is part of a path that the engine
/// bounds, and decoding only shortens it.
const query_storage_len = @import("../constants.zig").limits.path_len_max;

/// The options a route entry may carry after its function, other than its middleware.
pub const RouteOptions = struct {
    /// The type of the path's parameters, which the request context lends `on_request` (decision
    /// 163 ruling 3).
    path: type = void,
    /// The type of the query's pairs, which the router reads before the call.
    query: type = void,
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
/// fails, and the wrappers of each that returned `.next`. `ran` counts the middleware the chain
/// reached, the one that answered or failed included, whose `on_finished` the router calls when the
/// request ends. `kept` holds the chain's `states` and what its wrappers gave, `held`
/// (`router_wrap.zig`).
pub fn run_chain(comptime chain: anytype, context: anytype, ctx: *RequestContext, request: *const event.Request, response: *Response, ran: *u16, kept: anytype) Passed {
    comptime std.debug.assert(chain.len <= std.math.maxInt(u16));
    router_wrap.reset(chain, kept.states);
    inline for (0..chain.len) |index| {
        const Middleware = chain[index];
        ran.* = index + 1;
        if (comptime @hasDecl(Middleware, "on_request")) {
            const result = Middleware.on_request(context, ctx, request, response);
            const next = if (@typeInfo(@TypeOf(result)) == .error_union) (result catch |failure| return .{ .failed = failure }) else result;
            if (next == .answered) return .answered;
        }
        router_wrap.wrap(chain, index, context, ctx, kept.states, kept.held, request, response);
    }
    return .next;
}

/// Calls the `on_finished` of each middleware the chain reached, in the reverse order, as code
/// after `next()` runs in a framework whose middleware wraps the next one.
pub fn finish_chain(comptime chain: anytype, ran: u16, context: anytype, ctx: *RequestContext, result: event.Result) void {
    std.debug.assert(ran <= chain.len);
    inline for (0..chain.len) |reverse| {
        const index = chain.len - 1 - reverse;
        if (comptime @hasDecl(chain[index], "on_finished")) {
            if (index < ran) chain[index].on_finished(context, ctx, result);
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
pub fn State(comptime handler: anytype) type {
    if (comptime is_struct(handler) and @hasDecl(handler, "State")) return handler.State;
    return void;
}

/// Whether a struct route declares `name`. Comptime-only.
pub fn has(comptime handler: anytype, comptime name: []const u8) bool {
    return comptime is_struct(handler) and @hasDecl(handler, name);
}

/// Calls a route's function, or its `on_request`, with the arguments of decision 163: the context,
/// the request context, the state of a struct route, the request and the response. The request
/// context holds the route's path `Path` and query `Query` during the call alone, because the
/// query's octets live in `query`, which every request shares.
pub fn call_on_request(
    comptime handler: anytype,
    comptime Path: type,
    comptime Query: type,
    context: anytype,
    ctx: *RequestContext,
    state: *State(handler),
    request: *const event.Request,
    parameters: *const PathParameters,
    query: *QueryMemory,
    response: *Response,
) Outcome {
    var path = path_of(Path, parameters);
    var query_value = query_of(Query, request.query orelse "", query) catch |failure| return .{ .refused = status_of(failure) };
    // A route with no path or no query lends none, so the two may stay unchanged.
    _ = .{ &path, &query_value };
    // Decision 163 ruling 3: the context holds the path and the query during this call alone. It
    // holds none before, so a route that names none writes nothing here (design §8 step 50c).
    if (comptime Path != void) {
        assert(ctx.path_held.pointer == null);
        ctx.path_held = .init(Path, &path);
    }
    if (comptime Query != void) {
        assert(ctx.query_held.pointer == null);
        ctx.query_held = .init(Query, &query_value);
    }
    defer {
        if (comptime Path != void) ctx.path_held = .{};
        if (comptime Query != void) ctx.query_held = .{};
    }
    if (comptime is_struct(handler)) return outcome_of(.waits, handler.on_request(context, ctx, state, request, response));
    return outcome_of(.fails, handler(context, ctx, request, response));
}

/// Calls a struct route's `on_body` with the reader over the bytes that arrived.
pub fn call_body(comptime handler: anytype, context: anytype, ctx: *RequestContext, state: *State(handler), reader: *std.Io.Reader, response: *Response) Outcome {
    return outcome_of(.waits, handler.on_body(context, ctx, state, reader, response));
}

/// Calls a struct route's `on_writable`.
pub fn call_writable(comptime handler: anytype, context: anytype, ctx: *RequestContext, state: *State(handler), response: *Response) Outcome {
    return outcome_of(.waits, handler.on_writable(context, ctx, state, response));
}

/// What a call's `error.ReadFailed` means. A struct route's call `waits` for more of the body. A
/// function route reads a whole body that never waits, so its read `fails` (decision 163 ruling 4).
const ReadFailed = enum { waits, fails };

fn outcome_of(comptime read_failed: ReadFailed, result: anytype) Outcome {
    if (@typeInfo(@TypeOf(result)) != .error_union) return .returned;
    result catch |failure| {
        if (read_failed == .waits and failure == error.ReadFailed) return .waiting;
        return .{ .failed = failure };
    };
    return .returned;
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
const uri_too_long: http.Status = .uri_too_long;
const bad_request: http.Status = .bad_request;

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
fn status_of(failure: error{ UriTooLong, BadRequest }) http.Status {
    return switch (failure) {
        error.UriTooLong => uri_too_long,
        error.BadRequest => bad_request,
    };
}

/// A table of one route, which the tests of the router's names build. Test-only.
pub const sample_table = .{ .error_handler = sample_error, .routes = .{.{ .get, "/", sample_route }} };

fn sample_route(_: *void, _: *RequestContext, _: *const event.Request, response: *Response) !void {
    try response.end();
}

fn sample_error(_: *void, _: *RequestContext, _: *const event.Request, _: anyerror, _: *Response) void {}
