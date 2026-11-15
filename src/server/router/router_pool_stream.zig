//! How the router's pool calls a stream route, a struct route (decision 163 ruling 6, design §8
//! step 50f). Its `on_request` runs at the head, `on_data` at each body event with the request's
//! `server.RequestBodyStream`, `next` while the response has room, and `on_finished` at the
//! request's end. Each callback writes the request's `server.Response`, which the chain wrote
//! first. The root exports none of it.
//!
//! The router drops the body of a route with no `on_data`, and of a route that ended its
//! response: `on_data` never runs after the end. The router ends a response the route left open
//! once the body ended and `on_data` ran with the last piece, unless the route declares `next`. A
//! route with `next` ends its response itself, and its `next` runs while the request body is open
//! too (decision 127 as amended).
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");
const constants = @import("../constants.zig");
const Response = @import("../response/response.zig").Response;
const response_internal = @import("../response/response_internal.zig");
const router_body = @import("router_body.zig");
const router_call = @import("router_call.zig");
const router_pool = @import("router_pool.zig");
const router_wrap = @import("router_wrap.zig");

const Parts = router_pool.Parts;

/// The calls of `next` that one event makes while the engine takes all it is given, so a route
/// that writes little at a time cannot hold the program's call.
const next_calls_max = constants.limits.response_pieces_max;

/// Starts a stream route's request once its chain ran and no middleware answered: the stream of
/// its body reads through the last wrapper of a middleware's `wrap_body`, and `on_request` runs.
/// When the head ended the request, `on_data` runs once, and finds the body's end.
pub inline fn start(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype, request: *const event.Request) void {
    const handler = Parts(P).table.routes[index][router_call.handler_part];
    // A middleware's `wrap_body` that returns null keeps the router's reader, whose buffer holds
    // the event's octets and no kept octets of its own.
    const wraps = comptime wraps_body(P, index);
    const wrapped = wraps and entry.held.reader != &entry.body.cursor.reader;
    // `next` peeks through a wrapper, which needs a buffer to peek into (std.Io.Reader).
    assert(!wrapped or entry.held.reader.buffer.len > 0);
    // The router's reader holds kept octets in the entry's `body_bytes` itself. `read` points the
    // storage of a wrapper's stream at the octets past the held ones.
    entry.body_stream = .{ .reader = entry.held.reader, .storage = &entry.body.held, .wrapped = wrapped };
    const options = comptime router_pool.route_options(Parts(P).table.routes[index]);
    const state = router_pool.state_of(P, handler, entry);
    const outcome = router_call.call_on_request(handler, options.path, options.query, context, &entry.request_context, state, request, &pool.parameters, &pool.query, &entry.response);
    if (!router_pool.after(P, pool, entry, context, engine, request, outcome)) return;
    if (request.end) on_body(P, pool, index, entry, context, engine, "", true);
}

/// Whether the route ended its response: `end` or `trailers` returned, or the router ended it.
fn route_ended(response: *const Response) bool {
    return response.ended or response.end_asked != .none;
}

/// Passes a body event to `on_data`. The router drops the body of a route with no `on_data`, and
/// of a route that ended its response.
pub fn on_body(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype, bytes: []const u8, end: bool) void {
    const handler = Parts(P).table.routes[index][router_call.handler_part];
    if (comptime !router_call.has(handler, "on_data")) return body_ended(P, pool, index, entry, context, engine, end);
    // Decision 163 ruling 6: no `on_data` after the response ended, as a refusal at the head.
    if (route_ended(&entry.response)) {
        entry.body.delivered = true;
        return;
    }
    const outcome = read(P, index, entry, context, bytes, end) catch
        return router_pool.refuse(P, entry, context, engine, router_pool.content_too_large);
    if (!router_pool.after(P, pool, entry, context, engine, null, outcome)) return;
    body_ended(P, pool, index, entry, context, engine, end);
}

/// Whether a middleware of the route's chain wraps the request body's reader. Comptime-only.
fn wraps_body(comptime P: type, comptime index: usize) bool {
    const chain = router_call.table_chain(Parts(P).table) ++ router_call.entry_chain(Parts(P).table.routes[index]);
    return router_wrap.wraps_body(chain);
}

/// Calls `on_data` over the octets that the entry held and `bytes`. Then it keeps the octets that
/// the call left unread, which the engine's next event writes over, in the entry's `body_bytes`.
fn read(comptime P: type, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, bytes: []const u8, end: bool) router_body.Error!router_call.Outcome {
    const handler = Parts(P).table.routes[index][router_call.handler_part];
    const wraps = comptime wraps_body(P, index);
    const stream = &entry.body_stream;
    // Held bytes come first, so the new ones go after them.
    if (entry.body.held_len > 0) {
        if (comptime wraps) try hold_clear(entry, entry.body.held_len + bytes.len);
        try entry.body.append(bytes);
    }
    const over_bytes = entry.body.held_len == 0;
    // Design §8 step 25.6: the stream reads through the last wrapper, which reads the held bytes.
    _ = entry.body.reader_over(bytes);
    assert(stream.reader == entry.held.reader);
    if (comptime wraps) give_storage(entry);
    const outcome = router_call.call_data(handler, context, &entry.request_context, router_pool.state_of(P, handler, entry), stream, &entry.response);
    router_body.let_go(stream, wraps);
    // The router drops the rest of the body once the response ended.
    if (end or route_ended(&entry.response)) return read_last(entry, outcome);
    if (comptime wraps) try hold_clear(entry, entry.body.cursor.reader.bufferedLen());
    try entry.body.keep_unread(over_bytes);
    return outcome;
}

/// Points the storage of a wrapper's stream at the entry's `body_bytes` past the octets that the
/// router holds. The kept octets that the stream stored stay at its end.
fn give_storage(entry: anytype) void {
    const stream = &entry.body_stream;
    if (stream.wrapped) stream.storage = entry.body.held[entry.body.held_len..];
}

/// Refuses `held_len` octets that the router would hold beside the octets that a wrapper's stream
/// kept, or a stream whose kept octets did not fit its storage.
fn hold_clear(entry: anytype, held_len: usize) router_body.Error!void {
    const stream = &entry.body_stream;
    // RFC 9110 §15.5.14: content larger than the server takes gets 413, kept octets too.
    if (stream.too_large) return error.ContentTooLarge;
    // RFC 9110 §15.5.14: the kept octets and the octets the router holds share `body_bytes`.
    if (held_len + router_body.stored_len(stream) > entry.body.held.len) return error.ContentTooLarge;
}

/// Ends the read of the body, at its end or once the route ended its response. Kept octets that
/// the last piece could not take get 413 when the response is still open.
fn read_last(entry: anytype, outcome: router_call.Outcome) router_body.Error!router_call.Outcome {
    entry.body.delivered = true;
    // RFC 9110 §15.5.14: kept octets past the entry's `body_bytes` get 413, at the body's end too.
    if (entry.body_stream.too_large and !route_ended(&entry.response)) return error.ContentTooLarge;
    return outcome;
}

fn body_ended(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype, end: bool) void {
    if (!end) return;
    entry.body.delivered = true;
    const handler = Parts(P).table.routes[index][router_call.handler_part];
    if (comptime router_call.has(handler, "next")) return run_next(P, pool, index, entry, context, engine);
    router_pool.finish(P, entry, context, engine);
}

/// Calls `next` while the response is open, the engine took all it was given, and the writer has
/// room (design §8 step 46).
pub fn run_next(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype) void {
    const handler = Parts(P).table.routes[index][router_call.handler_part];
    const response = &entry.response;
    for (0..next_calls_max) |_| {
        if (response.ended or response_internal.waiting(response)) return;
        // A response with no room waits for the engine to release bytes, which `waiting` says.
        const room = response_internal.has_room(response) catch return engine.cancel(response.id);
        if (!room) break;
        const before = response_internal.mark(response);
        const outcome = router_call.call_next(handler, context, &entry.request_context, router_pool.state_of(P, handler, entry), response);
        if (!router_pool.after(P, pool, entry, context, engine, null, outcome)) return;
        // Decision 127 as amended: while the request body is open, a call that wrote nothing waits
        // for the next body bytes or the next `writable`.
        if (!entry.body.delivered and response_internal.mark(response).eql(before)) return;
    }
    cancel_held(entry, engine);
}

/// Decision 127: a route that neither ends its response nor fills the engine holds the request,
/// so the router cancels it, once its request body ended.
fn cancel_held(entry: anytype, engine: anytype) void {
    if (!entry.body.delivered) return;
    if (!entry.response.ended and !response_internal.waiting(&entry.response)) engine.cancel(entry.response.id);
}
