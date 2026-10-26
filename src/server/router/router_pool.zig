//! The pool of request entries a program places for a router, and `handle`, which takes the
//! endpoint's events and calls the routes' functions (decision 127 ruling 2, design §8 step 25.3).
//!
//! Each request a route answers holds one entry from its head to its `finished`. The entry holds
//! the request's `ResponseWriter` and its response memory, which the endpoint may read until the
//! `finished` (decision 103), and a struct route's state and held body bytes. The endpoint's word
//! for the request is the entry's index plus one, so 0 names no entry.
//!
//! The router ends a response the program left open: a function's at its return, and a struct
//! route's once the request body ended and `on_body` ran with its last byte, unless the route has
//! `on_writable`. A route with `on_writable` ends its response itself.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");
const constants = @import("../constants.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const writer_internal = @import("../response_writer/response_writer_internal.zig");
const router_call = @import("router_call.zig");
const router_body = @import("router_body.zig");

/// The sizes of a router's pool.
pub const Options = struct {
    /// The requests the router answers at once. One more gets 503.
    requests: u32,
    /// Octets of each entry's response memory: the copies of its headers and trailers, and the
    /// bytes its body's writer writes.
    response_bytes: usize,
    /// Octets of each entry's request body memory: the bytes an `on_body` left unread, and every byte
    /// of a `.whole_body` route.
    body_bytes: usize = 0,
};

/// What `handle` did with an event: it took it, or it hands it back, for the program to act on.
/// The router takes each event of a request, and hands back `send`, `close`, `ended` and `closed`.
pub const Handled = union(enum) {
    taken,
    event: event.Event,
};

/// The statuses the router answers with, with no call of a program's function.
const not_found: u16 = @intFromEnum(http.status.Code.not_found);
const method_not_allowed: u16 = @intFromEnum(http.status.Code.method_not_allowed);
const content_too_large: u16 = @intFromEnum(http.status.Code.content_too_large);
const not_implemented: u16 = @intFromEnum(http.status.Code.not_implemented);
const service_unavailable: u16 = @intFromEnum(http.status.Code.service_unavailable);

/// The calls of `on_writable` one event makes while the endpoint takes all it is given, so a route
/// that writes little at a time cannot hold the program's call.
const writable_calls_max = constants.response_pieces_max;

pub fn Pool(comptime ContextOf: type, comptime table_of: anytype, comptime RouteOf: type, comptime TableOf: type, comptime options_of: Options) type {
    comptime assert(options_of.requests > 0);
    const state_layout = state_layout_of(table_of.routes);
    const EntryOf = struct {
        used: bool = false,
        route: RouteOf = undefined,
        response: ResponseWriter = undefined,
        memory: [options_of.response_bytes]u8 = undefined,
        state: [state_layout.size]u8 align(state_layout.alignment) = undefined,
        body: router_body.Body(options_of.body_bytes) = .{},
        /// The middleware of the request's chain that ran, whose `on_finished` runs at its end.
        chain_ran: u16 = 0,
    };
    return struct {
        entries: [options_of.requests]EntryOf = @splat(.{}),
        parameters: PathParameters = .{},
        query: router_call.QueryMemory = .{},

        const Self = @This();

        /// Octets of the pool, which the program places.
        pub const memory_bytes = @sizeOf(Self);

        /// Takes one event of `endpoint`, an `*EndpointOf(capacity)`. It answers a request's head
        /// with the route's function, or with 404, 405, 501 or 503, passes its body to a struct
        /// route, sends what waits on `writable`, and frees the request's entry on `finished`.
        pub fn handle(pool: *Self, context: *ContextOf, endpoint: anytype, received: event.Event) Handled {
            switch (received) {
                .request => |request| on_request(Self, pool, context, endpoint, &request),
                .body => |body| if (entry_of(Self, pool, body.user_data)) |entry| on_body(Self, entry, context, endpoint, body.bytes, body.end),
                // A trailer section ends the body (RFC 9110 §6.5).
                .trailers => |trailers| if (entry_of(Self, pool, trailers.user_data)) |entry| on_body(Self, entry, context, endpoint, "", true),
                .writable => |writable| if (entry_of(Self, pool, writable.user_data)) |entry| on_writable(Self, entry, context, endpoint),
                .finished => |finished| if (entry_of(Self, pool, finished.user_data)) |entry| on_finished(Self, entry, context, finished),
                .send, .close, .ended, .closed => return .{ .event = received },
            }
            return .taken;
        }

        // What the free functions below read of the pool's type.
        const Entry = EntryOf;
        const Context = ContextOf;
        const Route = RouteOf;
        const Table = TableOf;
        const table = table_of;
        const options = options_of;
    };
}

fn on_request(comptime P: type, pool: *P, context: *P.Context, endpoint: anytype, request: *const event.Request) void {
    // RFC 9110 §9.3.6: a CONNECT request has no path, and no route names CONNECT.
    const path = request.path orelse return answer(endpoint, request.id, not_implemented, &.{});
    switch ((P.Table{}).match(request.method, path, &pool.parameters)) {
        .found => |route| start(P, pool, context, endpoint, request, route),
        // RFC 9110 §15.5.6: a 405 carries Allow.
        .method_not_allowed => |allow| answer(endpoint, request.id, method_not_allowed, &.{.{ .name = "allow", .value = allow }}),
        .not_found => answer(endpoint, request.id, not_found, &.{}),
        .not_implemented => answer(endpoint, request.id, not_implemented, &.{}),
    }
}

fn start(comptime P: type, pool: *P, context: *P.Context, endpoint: anytype, request: *const event.Request, route: P.Route) void {
    // RFC 9110 §15.6.4: a server that cannot take the request now answers 503.
    const index = free_index(P, pool) orelse return answer(endpoint, request.id, service_unavailable, &.{});
    const entry = &pool.entries[index];
    endpoint.set_user_data(request.id, index + 1) catch return endpoint.cancel(request.id);
    entry.used = true;
    entry.route = route;
    entry.body.held_len = 0;
    entry.body.delivered = false;
    entry.body.cursor = .{ .ended = request.end };
    writer_internal.init(&entry.response, writer_internal.Sink.of(@TypeOf(endpoint.*), endpoint), request.id, &entry.memory);
    switch (route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            const state = state_of(P, handler, entry);
            if (comptime router_call.StateOf(handler) != void) state.* = .{};
            if (!run_chain(P, @intFromEnum(tag), entry, context, endpoint, request)) return;
            const outcome = router_call.call_on_request(handler, context, state, request, &pool.parameters, &pool.query, &entry.response);
            if (!after(P, entry, context, endpoint, request, outcome)) return;
            if (comptime !router_call.is_struct(handler)) return finish(endpoint, &entry.response);
            if (request.end) on_body(P, entry, context, endpoint, "", true);
        },
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

/// Passes body bytes to a struct route's `on_body`. A function, or a struct without `on_body`,
/// reads none.
fn on_body(comptime P: type, entry: *P.Entry, context: *P.Context, endpoint: anytype, bytes: []const u8, end: bool) void {
    if (entry.body.delivered) return;
    entry.body.cursor.ended = end;
    switch (entry.route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            if (comptime !router_call.has(handler, "on_body")) return body_ended(P, entry, context, endpoint, handler, end);
            const outcome = read_body(P, @intFromEnum(tag), entry, context, bytes, end) catch return refuse_body(P, entry, endpoint);
            if (!after(P, entry, context, endpoint, null, outcome)) return;
            body_ended(P, entry, context, endpoint, handler, end);
        },
    }
}

fn read_body(comptime P: type, comptime index: usize, entry: *P.Entry, context: *P.Context, bytes: []const u8, end: bool) router_body.Error!router_call.Outcome {
    const handler = P.table.routes[index][router_call.handler_part];
    const whole = comptime route_options(P.table.routes[index]).whole_body;
    // Held bytes come first, so the new ones go after them.
    if (whole or entry.body.held_len > 0) try entry.body.append(bytes);
    if (whole and !end) return .returned;
    const over_bytes = entry.body.held_len == 0;
    const reader = entry.body.reader_over(bytes);
    const outcome = router_call.call_body(handler, context, state_of(P, handler, entry), reader, &entry.response);
    if (end) {
        entry.body.delivered = true;
        return outcome;
    }
    try entry.body.keep_unread(over_bytes);
    return outcome;
}

fn body_ended(comptime P: type, entry: *P.Entry, context: *P.Context, endpoint: anytype, comptime handler: anytype, end: bool) void {
    if (!end) return;
    entry.body.delivered = true;
    if (comptime router_call.has(handler, "on_writable")) return run_writable(P, entry, context, endpoint, handler);
    finish(endpoint, &entry.response);
}

fn on_writable(comptime P: type, entry: *P.Entry, context: *P.Context, endpoint: anytype) void {
    const whole = writer_internal.resume_writes(&entry.response) catch return endpoint.cancel(entry.response.id);
    if (whole or entry.response.ended or !entry.body.delivered) return;
    switch (entry.route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            if (comptime router_call.has(handler, "on_writable")) run_writable(P, entry, context, endpoint, handler);
        },
    }
}

/// Calls `on_writable` while the response is open and the endpoint took all it was given.
fn run_writable(comptime P: type, entry: *P.Entry, context: *P.Context, endpoint: anytype, comptime handler: anytype) void {
    for (0..writable_calls_max) |_| {
        if (entry.response.ended or writer_internal.waiting(&entry.response)) return;
        const outcome = router_call.call_writable(handler, context, state_of(P, handler, entry), &entry.response);
        if (!after(P, entry, context, endpoint, null, outcome)) return;
    }
    // Decision 127: a route that neither ends its response nor fills the endpoint holds
    // the request, so the router cancels it.
    if (!entry.response.ended and !writer_internal.waiting(&entry.response)) endpoint.cancel(entry.response.id);
}

fn on_finished(comptime P: type, entry: *P.Entry, context: *P.Context, finished: event.Finished) void {
    switch (entry.route) {
        inline else => |tag| {
            const handler = P.table.routes[@intFromEnum(tag)][router_call.handler_part];
            if (comptime router_call.has(handler, "on_finished")) handler.on_finished(context, state_of(P, handler, entry), finished.result);
            const chain = comptime router_call.table_chain(P.table) ++ router_call.entry_chain(P.table.routes[@intFromEnum(tag)]);
            router_call.finish_chain(chain, entry.chain_ran, context, finished.id, finished.result);
        },
    }
    entry.used = false;
}

/// Acts on a call's outcome, and returns whether the router goes on with the request.
fn after(comptime P: type, entry: *P.Entry, context: *P.Context, endpoint: anytype, request: ?*const event.Request, outcome: router_call.Outcome) bool {
    switch (outcome) {
        .returned, .waiting => return true,
        .refused => |status| {
            entry.response.status = status;
            entry.body.delivered = true;
            finish(endpoint, &entry.response);
            return false;
        },
        .failed => |failure| {
            entry.body.delivered = true;
            if (entry.response.head_sent()) {
                endpoint.cancel(entry.response.id);
                return false;
            }
            // Decision 127 ruling 4: the program chooses the status after an error.
            P.table.error_handler(context, request orelse &no_request, failure, &entry.response);
            finish(endpoint, &entry.response);
            return false;
        },
    }
}

fn refuse_body(comptime P: type, entry: *P.Entry, endpoint: anytype) void {
    entry.body.delivered = true;
    if (entry.response.head_sent()) return endpoint.cancel(entry.response.id);
    entry.response.status = content_too_large;
    finish(endpoint, &entry.response);
}

fn state_of(comptime P: type, comptime handler: anytype, entry: *P.Entry) *router_call.StateOf(handler) {
    return @ptrCast(&entry.state);
}

/// The request an error function gets when the error came after the head, whose slices the
/// endpoint reused. Its method and path are empty, and its id names no request.
const no_request: event.Request = .{
    .id = @bitCast(@as(u128, 0)),
    .method = "",
    .version = .{ .major = 0, .minor = 0 },
    .target = "",
    .scheme = null,
    .authority = null,
    .path = null,
    .query = null,
    .headers = undefined,
    .end = true,
};

/// The options of a route's entry: its fourth part, or none.
fn route_options(comptime entry: anytype) router_call.RouteOptions {
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
fn run_chain(comptime P: type, comptime index: usize, entry: *P.Entry, context: *P.Context, endpoint: anytype, request: *const event.Request) bool {
    const chain = comptime router_call.table_chain(P.table) ++ router_call.entry_chain(P.table.routes[index]);
    if (chain.len == 0) return true;
    switch (router_call.run_chain(chain, context, request, &entry.response, &entry.chain_ran)) {
        .next => return true,
        .answered => {
            entry.body.delivered = true;
            finish(endpoint, &entry.response);
            return false;
        },
        .failed => |failure| return after(P, entry, context, endpoint, request, .{ .failed = failure }),
    }
}

/// The size and the alignment of the largest state of the table's struct routes.
fn state_layout_of(comptime routes: anytype) struct { size: usize, alignment: usize } {
    var size: usize = 0;
    var alignment: usize = 1;
    for (0..routes.len) |index| {
        const State = router_call.StateOf(routes[index][router_call.handler_part]);
        size = @max(size, @sizeOf(State));
        alignment = @max(alignment, @alignOf(State));
    }
    return .{ .size = size, .alignment = alignment };
}

/// Ends a response the program left open. An error of the endpoint cancels the request.
fn finish(endpoint: anytype, response: *ResponseWriter) void {
    if (response.ended) return;
    response.end() catch endpoint.cancel(response.id);
}

/// Answers a request with no entry: a head with `status`, `headers` and no content. A head the
/// endpoint has no room for cancels the request, since no entry holds it.
fn answer(endpoint: anytype, id: event.RequestId, status: u16, headers: []const http.Field) void {
    endpoint.respond(id, .{ .status = status, .headers = headers, .end = true }) catch endpoint.cancel(id);
}
