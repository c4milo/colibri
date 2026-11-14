//! How the router's pool calls a function route with the whole request, in one call (decision 163
//! ruling 4, design §8 step 50e). The root exports none of it.
//!
//! A request whose head ended it gets its call at the head. It gets the engine's request as it
//! is, whose body reads as ended. A middleware with `wrap_body` makes the router give the
//! last wrapper's reader instead, in a copy of the request.
//!
//! A request with a body gets its call at the head too when `header_bytes` is 0, the owner's
//! ruling of 2026-11-13. Its body is the engine's, whose every read fails, and the router drops
//! its body events. Else the entry keeps a copy of the header (`router_copy.zig`, ruling 5), and
//! every byte of the body in `body_bytes`. The call comes at the body's end: a body event that
//! ends it, or a trailer section, which the route never sees. A header past `header_bytes` gets
//! 431, and a body past `body_bytes` gets 413, each with no call.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");
const constants = @import("../constants.zig");
const router_call = @import("router_call.zig");
const router_copy = @import("router_copy.zig");
const router_pool = @import("router_pool.zig");
const router_wrap = @import("router_wrap.zig");

const Parts = router_pool.Parts;
const request_header_fields_too_large = constants.protocol.request_header_fields_too_large;

/// Calls a function route at the head when the head ended the request, or when the entry holds no
/// copy of a header. Else the entry keeps a copy of the header, because the engine writes the
/// header's storage again before the body ends.
///
/// It is `inline`, with `start_ended` and `call`. The call at the head is the path of each
/// request with no body. It stays in the pool's `start`, as a struct route's first call does.
/// Design §8 step 50e records what three calls cost a GET.
pub inline fn start(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype, request: *const event.Request) void {
    const chain = comptime router_call.table_chain(Parts(P).table) ++ router_call.entry_chain(Parts(P).table.routes[index]);
    // With no copy and no wrapper, a request gets the same call whether its head ended it or not.
    if (comptime Parts(P).header_bytes == 0 and !router_wrap.wraps_body(chain)) return call(P, pool, index, entry, context, engine, request);
    if (request.end) return start_ended(P, pool, index, entry, context, engine, request);
    if (comptime Parts(P).header_bytes == 0) return call(P, pool, index, entry, context, engine, request);
    const header = &entry.header;
    // RFC 6585 §5: header fields larger than the server takes get 431.
    router_copy.copy(request, &header.octets, &header.lines, &header.request) catch
        return router_pool.refuse(P, entry, context, engine, request_header_fields_too_large);
    assert(header.request.headers.first == request.headers.first);
}

/// Calls a function route whose head ended the request. With no `wrap_body` in its chain, the
/// route reads the engine's body, which ends at once, so the router copies nothing.
inline fn start_ended(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype, request: *const event.Request) void {
    const chain = comptime router_call.table_chain(Parts(P).table) ++ router_call.entry_chain(Parts(P).table.routes[index]);
    if (comptime !router_wrap.wraps_body(chain)) return call(P, pool, index, entry, context, engine, request);
    var wrapped = request.*;
    // Design §8 step 25.6: the route reads through the last wrapper, over a body that ended.
    assert(entry.body.cursor.ended);
    wrapped.body = entry.held.reader;
    call(P, pool, index, entry, context, engine, &wrapped);
}

/// Holds each byte of a function route's body, and calls the route with the whole request at the
/// body's end.
pub fn on_body(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype, bytes: []const u8, end: bool) void {
    if (comptime Parts(P).header_bytes == 0) {
        // The route had its call at the head, which marked the body delivered, so the router
        // drops each body event before this call.
        unreachable;
    }
    entry.body.append(bytes) catch return router_pool.refuse(P, entry, context, engine, router_pool.content_too_large);
    if (!end) return;
    // The reader reads the held bytes, and then ends.
    _ = entry.body.reader_over(&.{});
    if (comptime router_pool.route_options(Parts(P).table.routes[index]).path != void) match_again(P, pool, entry);
    const request = &entry.header.request;
    // The route reads the whole body through the middleware's wrappers.
    request.body = entry.held.reader;
    call(P, pool, index, entry, context, engine, request);
}

/// Matches the copy's path again. Every request of the router shares the parameters, and the
/// event of a later request may have written them since this request's head.
fn match_again(comptime P: type, pool: *P, entry: *const Parts(P).Entry) void {
    const request = &entry.header.request;
    const found = (Parts(P).Table{}).match(request.method, request.path.?, &pool.parameters);
    // A match reads the method and the path alone, so the copy finds the route again.
    assert(found == .found and found.found == entry.route);
}

/// Calls a function route once with `request`, and ends the response the route left open.
inline fn call(comptime P: type, pool: *P, comptime index: usize, entry: *Parts(P).Entry, context: *Parts(P).Context, engine: anytype, request: *const event.Request) void {
    const handler = Parts(P).table.routes[index][router_call.handler_part];
    const options = comptime router_pool.route_options(Parts(P).table.routes[index]);
    // No later body event calls the route again.
    assert(!entry.body.delivered);
    entry.body.delivered = true;
    const state = router_pool.state_of(P, handler, entry);
    const outcome = router_call.call_on_request(handler, options.path, options.query, context, &entry.request_context, state, request, &pool.parameters, &pool.query, &entry.response);
    if (!router_pool.after(P, pool, entry, context, engine, request, outcome)) return;
    router_pool.finish(P, entry, context, engine);
}
