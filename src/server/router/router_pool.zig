//! The pool of request entries a program places for a router, and `handle`, which takes the
//! engine's events and calls the routes' functions (decision 127 ruling 2, design §8 step 25.3).
//!
//! Each request a route answers holds one entry from its head to its `finished`. The entry holds
//! the request's `Response` and its response memory, which the engine may read until it
//! releases the bytes (decision 103 as amended), and a struct route's state and held body bytes.
//! The engine's word for the request is the entry's index plus one, so 0 names no entry.
//!
//! A function route gets the whole request in one call (decision 163 ruling 4). The call comes at
//! the head when the head ended the request, or when `header_bytes` is 0. Else it comes when the
//! body ended. The entry then holds a copy of the request's header and every byte of its body
//! (`router_copy.zig`, ruling 5).
//!
//! The router ends a response the program left open. It ends a function's at its return. It ends
//! a struct route's once the request body ended and `on_body` ran with its last byte, unless the
//! route has `on_writable`. A route with `on_writable` ends its response itself. Its
//! `on_writable` runs while the request body is open too (decision 127 as amended).
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");
const constants = @import("../constants.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const Response = @import("../response/response.zig").Response;
const RequestContext = @import("../request_context.zig").RequestContext;
const response_internal = @import("../response/response_internal.zig");
const router_call = @import("router_call.zig");
const router_body = @import("router_body.zig");
const router_copy = @import("router_copy.zig");
const router_pool_whole = @import("router_pool_whole.zig");
const router_wrap = @import("router_wrap.zig");

/// The sizes of a router's pool.
pub const Options = struct {
    /// The requests the router answers at once. One more gets 503.
    requests: u32 = constants.limits.router_requests_default,
    /// Octets of each entry's response memory: the copies of its headers and trailers, and the
    /// bytes its body's writer writes.
    response_bytes: usize = constants.limits.router_response_bytes_default,
    /// Octets of each entry's request body memory: the bytes an `on_body` left unread, and every byte
    /// of a function route's body. A body past it gets 413 (RFC 9110 §15.5.14).
    body_bytes: usize = 0,
    /// Octets of each entry's copy of a request's header, for a function route whose request has a
    /// body (decision 163 ruling 5). A program names it, 0 included, since the router cannot know
    /// the size of its requests.
    ///
    /// With 0, the router copies nothing, and calls each function route at the head, the owner's
    /// ruling of 2026-11-13. For a request whose body is still to come, a read of `request.body`
    /// fails, and the router drops the body.
    ///
    /// Above 0, the router copies the header of each request whose body is still to come. Over h2
    /// and h3 a GET may end in a later frame: an empty DATA frame with END_STREAM, or a FIN after
    /// HEADERS. Such a GET takes a copy too. The copy holds the section's live lines: 8 octets of
    /// record for each line, and its name and value. Over h2 and h3 the lines hold the
    /// pseudo-header fields, and the copy holds no more: the method, the target, the scheme, the
    /// authority, the path and the query are those fields' values. A `:path` that starts with `?`
    /// has the static "/" as its path, one octet more. Over h11 the copy holds the method and the
    /// target too, and each part that lies in neither the target nor a line, such as the scheme.
    /// A header past `header_bytes` gets 431 (RFC 6585 §5), with no call.
    header_bytes: usize,
};

/// What `handle` did with an event: it took it, or it hands it back, for the program to act on.
/// The router takes each event of a request, and hands back `send`, `close`, `ended` and `closed`.
pub const Handled = union(enum) {
    taken,
    event: event.Event,
};

/// The comptime branches of a switch over the routes: a base, and a share for each route's prong.
const branch_quota_base = 1000;
const branch_quota_per_route = 100;

/// The statuses the router answers with, with no call of a program's function.
const not_found: http.Status = .not_found;
const method_not_allowed: http.Status = .method_not_allowed;
pub const content_too_large: http.Status = .content_too_large;
const not_implemented: http.Status = .not_implemented;
const service_unavailable: http.Status = .service_unavailable;

/// The calls of `on_writable` one event makes while the engine takes all it is given, so a route
/// that writes little at a time cannot hold the program's call.
const writable_calls_max = constants.limits.response_pieces_max;

pub fn Pool(comptime ContextOf: type, comptime table_of: anytype, comptime RouteOf: type, comptime TableOf: type, comptime options_of: Options) type {
    comptime assert(options_of.requests > 0);
    const state_layout = state_layout_of(table_of.routes);
    const wrap_layout = router_wrap.layout_of(table_of);
    const ValuesOf = router_call.Values(table_of);
    const EntryOf = struct {
        used: bool = false,
        route: RouteOf = undefined,
        response: Response = undefined,
        /// The request's own object, and its values, which every callback of the request gets
        /// (decision 163). It lends nothing between two requests, so `start_context` writes the
        /// request's id alone.
        request_context: RequestContext = .{ .request_id = event.id_of(0) },
        values: ValuesOf = undefined,
        memory: [options_of.response_bytes]u8 = undefined,
        state: [state_layout.size]u8 align(state_layout.alignment) = undefined,
        body: router_body.Body(options_of.body_bytes) = .{},
        /// The middleware of the request's chain that ran, whose `on_finished` runs at its end.
        chain_ran: u16 = 0,
        /// The state of each middleware of the request's chain, and what their wrappers gave.
        middleware_states: [wrap_layout.size]u8 align(wrap_layout.alignment) = undefined,
        held: router_wrap.Held(wrap_layout.chain_max) = .{},
        /// The copy of the request's header, for a function route whose request has a body.
        header: router_copy.Header(options_of.header_bytes) = .{},
    };
    comptime {
        // An entry starts with a context that lends no path and no query, and `call_on_request`
        // takes back what it lent. So `start_context` writes the id alone (design §8 step 50c).
        const fresh: EntryOf = .{};
        assert(fresh.request_context.path_held.pointer == null);
        assert(fresh.request_context.query_held.pointer == null);
    }
    return struct {
        entries: [options_of.requests]EntryOf = @splat(.{}),
        parameters: PathParameters = .{},
        query: router_call.QueryMemory = .{},
        /// The reader at which `no_request_error` points the body of its request, whose every
        /// read fails (decision 163 ruling 4).
        failing_body: std.Io.Reader = event.failing_reader,

        const Self = @This();

        /// One tag for each route, in the table's order, named by its method and its pattern.
        pub const Route = RouteOf;
        /// What `match` gives: `found` with the route's tag, `method_not_allowed` with the Allow
        /// field's value, `not_found`, or `not_implemented` (decision 122).
        pub const Match = TableOf.Match;

        /// The route that `method` and `path` name, with its parameters in `parameters`. The table
        /// holds no state, so the call takes no router (decision 158 ruling 4).
        pub fn match(method: []const u8, path: []const u8, parameters: *PathParameters) Match {
            return (TableOf{}).match(method, path, parameters);
        }

        /// Octets of the router, which the program places.
        pub const memory_bytes = @sizeOf(Self);

        /// Takes one event of `engine`, an `*Engine(capacity)`. It answers a request's head
        /// with the route's function, or with 404, 405, 501 or 503, passes its body to a struct
        /// route, sends what waits on `writable`, and frees the request's entry on `finished`.
        ///
        /// A function route of a request with a body gets its call at the head when
        /// `header_bytes` is 0. With `header_bytes` above 0, the router copies the request's
        /// header and holds its body, and calls the function at the body's end. A header past
        /// `header_bytes` gets 431, and a body past `body_bytes` gets 413, with no call.
        pub fn handle(pool: *Self, context: *ContextOf, engine: anytype, received: event.Event) Handled {
            switch (received) {
                .request => |request| on_request(Self, pool, context, engine, &request),
                .body => |body| if (entry_of(Self, pool, body.user_data)) |entry| on_body(Self, pool, entry, context, engine, body.bytes, body.end),
                // A trailer section ends the body (RFC 9110 §6.5).
                .trailers => |trailers| if (entry_of(Self, pool, trailers.user_data)) |entry| on_body(Self, pool, entry, context, engine, "", true),
                .writable => |writable| if (entry_of(Self, pool, writable.user_data)) |entry| on_writable(Self, pool, entry, context, engine),
                .finished => |finished| if (entry_of(Self, pool, finished.user_data)) |entry| on_finished(Self, entry, context, finished),
                .send, .half_close, .close, .ended, .closed => return .{ .event = received },
            }
            return .taken;
        }

        /// The comptime branches a switch over every route takes in `start` and `on_finished`: an
        /// `inline else` makes one prong for each route, and the default budget of 1,000 does not
        /// hold the GitHub API's 203 routes there (`src/testing/server/server_routes.zig`).
        const branch_quota = branch_quota_base + branch_quota_per_route * table_of.routes.len;

        // What the free functions below read of the pool's type.
        const Entry = EntryOf;
        const Context = ContextOf;
        const Table = TableOf;
        const table = table_of;
        const options = options_of;
    };
}

/// What another file of the router reads of a pool's type. Only the pool's own file reads its
/// declarations, so a router's type exports no more names (decision 158).
pub fn Parts(comptime P: type) type {
    return struct {
        pub const Entry = P.Entry;
        pub const Context = P.Context;
        pub const Table = P.Table;
        pub const table = P.table;
        pub const header_bytes = P.options.header_bytes;
    };
}

fn on_request(comptime P: type, pool: *P, context: *P.Context, engine: anytype, request: *const event.Request) void {
    // RFC 9110 §9.3.6: a CONNECT request has no path, and no route names CONNECT.
    const path = request.path orelse return answer(engine, request.id, not_implemented, &.{});
    switch ((P.Table{}).match(request.method, path, &pool.parameters)) {
        .found => |route| start(P, pool, context, engine, request, route),
        // RFC 9110 §15.5.6: a 405 carries Allow.
        .method_not_allowed => |allow| answer(engine, request.id, method_not_allowed, &.{.{ .name = "allow", .value = allow }}),
        .not_found => answer(engine, request.id, not_found, &.{}),
        .not_implemented => answer(engine, request.id, not_implemented, &.{}),
    }
}

fn start(comptime P: type, pool: *P, context: *P.Context, engine: anytype, request: *const event.Request, route: P.Route) void {
    @setEvalBranchQuota(P.branch_quota);
    // RFC 9110 §15.6.4: a server that cannot take the request now answers 503.
    const index = free_index(P, pool) orelse return answer(engine, request.id, service_unavailable, &.{});
    const entry = &pool.entries[index];
    engine.set_user_data(request.id, index + 1) catch return engine.cancel(request.id);
    entry.used = true;
    entry.route = route;
    entry.body.held_len = 0;
    entry.body.delivered = false;
    entry.body.cursor = .{ .ended = request.end };
    response_internal.init(&entry.response, response_internal.Sink.init(@TypeOf(engine.*), engine), request.id, &entry.memory);
    entry.held = .{ .reader = &entry.body.cursor.reader };
    start_context(P, entry, request.id);
    switch (route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            const state = state_of(P, handler, entry);
            if (comptime router_call.State(handler) != void) state.* = .{};
            if (!run_chain(P, pool, @intFromEnum(tag), entry, context, engine, request)) return;
            if (comptime !router_call.is_struct(handler)) return router_pool_whole.start(P, pool, @intFromEnum(tag), entry, context, engine, request);
            const options = comptime route_options(P.table.routes[@intFromEnum(tag)]);
            const outcome = router_call.call_on_request(handler, options.path, options.query, context, &entry.request_context, state, request, &pool.parameters, &pool.query, &entry.response);
            if (!after(P, pool, entry, context, engine, request, outcome)) return;
            if (request.end) on_body(P, pool, entry, context, engine, "", true);
        },
    }
}

/// Gives the request its own context, with values that start from `.{}` (decision 163 ruling 2).
fn start_context(comptime P: type, entry: *P.Entry, id: event.RequestId) void {
    entry.request_context.request_id = id;
    if (comptime @hasField(@TypeOf(P.table), router_call.values_field)) {
        entry.values = .{};
        entry.request_context.values_held = .init(@TypeOf(entry.values), &entry.values);
    }
}

fn free_index(comptime P: type, pool: *const P) ?u32 {
    for (&pool.entries, 0..) |*entry, index| {
        if (!entry.used) return @intCast(index);
    }
    return null;
}

fn entry_of(comptime P: type, pool: *P, user_data: usize) ?*P.Entry {
    if (user_data == 0) return null;
    assert(user_data <= P.options.requests);
    const entry = &pool.entries[user_data - 1];
    assert(entry.used);
    return entry;
}

/// Passes body bytes to a function route, which holds them, or to a struct route's `on_body`. A
/// struct without `on_body` reads none.
fn on_body(comptime P: type, pool: *P, entry: *P.Entry, context: *P.Context, engine: anytype, bytes: []const u8, end: bool) void {
    if (entry.body.delivered) return;
    entry.body.cursor.ended = end;
    switch (entry.route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            if (comptime !router_call.is_struct(handler)) return router_pool_whole.on_body(P, pool, @intFromEnum(tag), entry, context, engine, bytes, end);
            if (comptime !router_call.has(handler, "on_body")) return body_ended(P, pool, entry, context, engine, handler, end);
            const outcome = read_body(P, @intFromEnum(tag), entry, context, bytes, end) catch return refuse(P, entry, context, engine, content_too_large);
            if (!after(P, pool, entry, context, engine, null, outcome)) return;
            body_ended(P, pool, entry, context, engine, handler, end);
        },
    }
}

fn read_body(comptime P: type, comptime index: usize, entry: *P.Entry, context: *P.Context, bytes: []const u8, end: bool) router_body.Error!router_call.Outcome {
    const handler = P.table.routes[index][router_call.handler_part];
    // Held bytes come first, so the new ones go after them.
    if (entry.body.held_len > 0) try entry.body.append(bytes);
    const over_bytes = entry.body.held_len == 0;
    // Design §8 step 25.6: the route reads through the last wrapper, which reads the held bytes.
    _ = entry.body.reader_over(bytes);
    const outcome = router_call.call_body(handler, context, &entry.request_context, state_of(P, handler, entry), entry.held.reader, &entry.response);
    if (end) {
        entry.body.delivered = true;
        return outcome;
    }
    try entry.body.keep_unread(over_bytes);
    return outcome;
}

fn body_ended(comptime P: type, pool: *P, entry: *P.Entry, context: *P.Context, engine: anytype, comptime handler: anytype, end: bool) void {
    if (!end) return;
    entry.body.delivered = true;
    if (comptime router_call.has(handler, "on_writable")) return run_writable(P, pool, entry, context, engine, handler);
    finish(P, entry, context, engine);
}

fn on_writable(comptime P: type, pool: *P, entry: *P.Entry, context: *P.Context, engine: anytype) void {
    const whole = response_internal.resume_writes(&entry.response) catch return engine.cancel(entry.response.id);
    if (whole or entry.response.ended) return;
    switch (entry.route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            if (comptime !router_call.has(handler, "on_writable")) return;
            run_writable(P, pool, entry, context, engine, handler);
        },
    }
}

/// Calls `on_writable` while the response is open, the engine took all it was given, and the
/// writer has room (design §8 step 46).
fn run_writable(comptime P: type, pool: *P, entry: *P.Entry, context: *P.Context, engine: anytype, comptime handler: anytype) void {
    for (0..writable_calls_max) |_| {
        if (entry.response.ended or response_internal.waiting(&entry.response)) return;
        // A response with no room waits for the engine to release bytes, which `waiting` says.
        const room = response_internal.has_room(&entry.response) catch return engine.cancel(entry.response.id);
        if (!room) break;
        const before = response_internal.mark(&entry.response);
        const outcome = router_call.call_writable(handler, context, &entry.request_context, state_of(P, handler, entry), &entry.response);
        if (!after(P, pool, entry, context, engine, null, outcome)) return;
        // Decision 127 as amended: while the request body is open, a call that wrote nothing waits
        // for the next body bytes or the next `writable`.
        if (!entry.body.delivered and response_internal.mark(&entry.response).eql(before)) return;
    }
    cancel_held(P, entry, engine);
}

/// Decision 127: a route that neither ends its response nor fills the engine holds the request,
/// so the router cancels it, once its request body ended.
fn cancel_held(comptime P: type, entry: *P.Entry, engine: anytype) void {
    if (!entry.body.delivered) return;
    if (!entry.response.ended and !response_internal.waiting(&entry.response)) engine.cancel(entry.response.id);
}

fn on_finished(comptime P: type, entry: *P.Entry, context: *P.Context, finished: event.Finished) void {
    @setEvalBranchQuota(P.branch_quota);
    switch (entry.route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            if (comptime router_call.has(handler, "on_finished")) handler.on_finished(context, &entry.request_context, state_of(P, handler, entry), finished.result);
            const chain = comptime router_call.table_chain(P.table) ++ router_call.entry_chain(P.table.routes[@intFromEnum(tag)]);
            router_call.finish_chain(chain, entry.chain_ran, context, &entry.request_context, finished.result);
        },
    }
    entry.used = false;
}

/// Acts on a call's outcome, and returns whether the router goes on with the request.
pub fn after(comptime P: type, pool: *P, entry: *P.Entry, context: *P.Context, engine: anytype, request: ?*const event.Request, outcome: router_call.Outcome) bool {
    switch (outcome) {
        .returned, .waiting => {
            // Design §8 step 25.6: the program ended a wrapped response, which ends once the
            // wrappers finish.
            if (entry.response.end_asked != .none) finish(P, entry, context, engine);
            return true;
        },
        .refused => |status| {
            entry.response.status = status;
            entry.body.delivered = true;
            finish(P, entry, context, engine);
            return false;
        },
        .failed => |failure| {
            entry.body.delivered = true;
            if (entry.response.head_sent()) {
                engine.cancel(entry.response.id);
                return false;
            }
            // Decision 127 ruling 4: the program chooses the status after an error.
            if (request) |known| {
                P.table.error_handler(context, &entry.request_context, known, failure, &entry.response);
            } else {
                no_request_error(P, pool, entry, context, failure);
            }
            finish(P, entry, context, engine);
            return false;
        },
    }
}

/// Answers a request with `status` and no call, and reads no more of its body: a body or a header
/// larger than the entry holds. A response whose head went out is cancelled instead.
pub fn refuse(comptime P: type, entry: *P.Entry, context: *P.Context, engine: anytype, status: http.Status) void {
    entry.body.delivered = true;
    if (entry.response.head_sent()) return engine.cancel(entry.response.id);
    entry.response.status = status;
    finish(P, entry, context, engine);
}

pub fn state_of(comptime P: type, comptime handler: anytype, entry: *P.Entry) *router_call.State(handler) {
    return @ptrCast(&entry.state);
}

/// The lines of the request that `no_request_error` gives, which hold none.
const no_lines: http.FieldSection.Slice = .{ .octets = &.{}, .lines = &.{} };

/// Calls the error function after an error of a struct route's `on_body` or `on_writable`. The
/// engine reused the head's slices by then, so the error function gets a request whose method and
/// path are empty. Its id names no request, its headers hold no line, and a read of its body fails.
fn no_request_error(comptime P: type, pool: *P, entry: *P.Entry, context: *P.Context, failure: anyerror) void {
    const request: event.Request = .{
        .id = @bitCast(@as(u128, 0)),
        .method = "",
        .version = .{ .major = 0, .minor = 0 },
        .target = "",
        .scheme = null,
        .authority = null,
        .path = null,
        .query = null,
        .headers = .{ .lines = &no_lines, .first = 0 },
        .body = &pool.failing_body,
        .end = true,
    };
    P.table.error_handler(context, &entry.request_context, &request, failure, &entry.response);
}

/// The options of a route's entry: its fourth part, or none.
pub fn route_options(comptime entry: anytype) router_call.RouteOptions {
    if (entry.len <= router_call.options_part) return .{};
    const given = entry[router_call.options_part];
    var held: router_call.RouteOptions = .{};
    inline for (@typeInfo(@TypeOf(given)).@"struct".fields) |field| {
        if (comptime !std.mem.eql(u8, field.name, router_call.middleware_field)) @field(held, field.name) = @field(given, field.name);
    }
    return held;
}

/// Runs the middleware of the route table and of the route entry at `index`, and returns whether
/// the router goes on to the route (decision 127 ruling 5).
fn run_chain(comptime P: type, pool: *P, comptime index: usize, entry: *P.Entry, context: *P.Context, engine: anytype, request: *const event.Request) bool {
    const chain = comptime router_call.table_chain(P.table) ++ router_call.entry_chain(P.table.routes[index]);
    if (chain.len == 0) return true;
    const kept = .{ .states = @as([*]u8, &entry.middleware_states), .held = &entry.held };
    switch (router_call.run_chain(chain, context, &entry.request_context, request, &entry.response, &entry.chain_ran, kept)) {
        .next => return true,
        .answered => {
            entry.body.delivered = true;
            finish(P, entry, context, engine);
            return false;
        },
        .failed => |failure| return after(P, pool, entry, context, engine, request, .{ .failed = failure }),
    }
}

/// The size and the alignment of the largest state of the table's struct routes.
fn state_layout_of(comptime routes: anytype) struct { size: usize, alignment: usize } {
    var size: usize = 0;
    var alignment: usize = 1;
    for (0..routes.len) |index| {
        const State = router_call.State(routes[index][router_call.handler_part]);
        size = @max(size, @sizeOf(State));
        alignment = @max(alignment, @alignOf(State));
    }
    return .{ .size = size, .alignment = alignment };
}

/// Ends a response the program left open, or a wrapped one the program ended, once each wrapper
/// wrote what it owes (design §8 step 25.6). An error of a wrapper or of the engine cancels the
/// request.
pub fn finish(comptime P: type, entry: *P.Entry, context: *P.Context, engine: anytype) void {
    @setEvalBranchQuota(P.branch_quota);
    const response = &entry.response;
    if (response.ended) return;
    if (response.wrapped == null) return response.end() catch engine.cancel(response.id);
    // The headers close before a wrapper writes what it owes.
    if (!response.body_started) response_internal.start_body(response);
    switch (entry.route) {
        inline else => |tag| {
            const chain = comptime router_call.table_chain(P.table) ++ router_call.entry_chain(P.table.routes[@intFromEnum(tag)]);
            router_wrap.finish(chain, context, &entry.request_context, &entry.middleware_states, &entry.held) catch return cancel_wrapped(engine, response);
        },
    }
    response_internal.end_wrapped(response) catch cancel_wrapped(engine, response);
}

/// Cancels a wrapped response that could not end, and marks it ended, so no later call finishes
/// it again.
fn cancel_wrapped(engine: anytype, response: *Response) void {
    response.ended = true;
    engine.cancel(response.id);
}

/// Answers a request with no entry: a head with `status`, `headers` and no content. A head the
/// engine has no room for cancels the request, since no entry holds it.
fn answer(engine: anytype, id: event.RequestId, status: http.Status, headers: []const http.Field) void {
    engine.respond(id, .{ .status = status, .headers = headers, .end = true }) catch engine.cancel(id);
}
