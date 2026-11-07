//! What the pool does with an exchange's request and response as a connection reports its pieces
//! and its end (decisions 124 and 153), split from `pool_events.zig` in design §8 step 39. The
//! pool sends the request again on another connection while it holds the whole request, or gives
//! both back to the program. A streamed request's pieces give back their memory one at a time, and
//! after the first the pool holds no whole request. After a streamed response's head, the program
//! has some of the response, and the exchange never moves. Each function takes a pool of any
//! `ConnectionPool` type.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const event_internal = @import("../event_internal.zig");
const pool_module = @import("pool.zig");
const pool_events = @import("pool_events.zig");

const Event = pool_module.Event;
const Entry = pool_module.Entry;

/// A connection reads the exchange's piece no more: the program may reuse its memory, and the pool
/// holds no whole request from here on (decision 153 ruling 3).
pub fn on_taken(pool: anytype, slot: u32, carried_id: event.RequestId) ?Event {
    // A cancelled exchange reports nothing, so every reported one is carried.
    const entry = pool_events.carried(pool, slot, carried_id).?;
    assert(entry.piece_held);
    entry.piece = "";
    entry.piece_held = false;
    entry.taken_any = true;
    return .{ .body_taken = entry.id };
}

/// A streamed response's head arrived (decision 153 ruling 7). The program has it, so the exchange
/// never moves to another connection.
pub fn on_headers(pool: anytype, slot: u32, carried_id: event.RequestId) ?Event {
    // A cancelled exchange reports nothing, so every reported one is carried.
    const entry = pool_events.carried(pool, slot, carried_id).?;
    assert(entry.request.streamed.response and !entry.headers_reported);
    entry.headers_reported = true;
    return .{ .headers = entry.id };
}

/// A piece of a streamed response is in the exchange's `Response.body` (decision 153 ruling 7).
pub fn on_body(pool: anytype, slot: u32, piece: event.Piece) ?Event {
    const entry = pool_events.carried(pool, slot, piece.id).?;
    assert(entry.headers_reported);
    return .{ .body = .{ .id = entry.id, .len = piece.len } };
}

/// A connection reported an exchange's end. One that moves goes to another connection (the model's
/// MoveOn), and any other goes to the caller (its Deliver), which frees its room for a waiting one.
pub fn on_finished(pool: anytype, slot: u32, ended: event.Ended) ?Event {
    // A cancelled exchange reports nothing, so every reported one is carried.
    const entry = pool_events.carried(pool, slot, ended.id).?;
    assert(entry.request == ended.request and entry.response == ended.response);
    if (movable(pool, entry, slot, ended.response_began)) {
        // RFC 9114 §4.1.1: a refused request is treated "as though [it] had never been sent". A
        // request sent again starts its response anew, and counts its content again.
        const closed = entry.response.result == .closed;
        // RFC 9112 §9.3.2: a failed connection is one "not explicitly closed by the server in its
        // last complete response", which leaves the connection draining instead.
        const after_failure = closed and pool.phase(slot) == .failed;
        event_internal.clear(entry.response);
        // No piece was taken, so the one the program handed, if any, is the body's first.
        assert(!entry.taken_any);
        entry.* = .{
            .stage = .waiting,
            .id = entry.id,
            .request = entry.request,
            .response = entry.response,
            .moves = entry.moves + 1,
            .resent = entry.resent or closed,
            .after_failure = after_failure,
            .piece = entry.piece,
            .piece_end = entry.piece_end,
            .piece_held = entry.piece_held,
            .body_ended = entry.body_ended,
            .handed_len = entry.handed_len,
        };
        pool_events.assign_waiting(pool);
        return null;
    }
    const reported: Event = .{ .finished = pool_events.deliver(entry) };
    pool_events.assign_waiting(pool);
    return reported;
}

/// Whether a reported exchange moves: the connection that reported it takes no new exchange, the
/// exchange moved fewer than `moves_max` times, refusals and resends together, no piece of it was
/// taken, and the connection refused it unprocessed, or closed before any of its response arrived
/// and its method is idempotent (decisions 124 and 153).
fn movable(pool: anytype, entry: *const Entry, slot: u32, response_began: bool) bool {
    // RFC 9110 §9.2.2: "A client SHOULD NOT automatically retry a failed automatic retry."
    if (entry.moves >= constants.limits.moves_max) return false;
    // Decision 153 ruling 3: after its first `body_taken` the pool holds no copy of the request,
    // and after a streamed response's `headers` the program has some of the response.
    if (entry.taken_any or entry.headers_reported) return false;
    if (pool.phase(slot) == .open) return false;
    return switch (entry.response.result) {
        // RFC 9113 §8.7: a client "MAY automatically retry" a request no server processed.
        .refused => true,
        // RFC 9110 §9.2.2, RFC 9112 §9.3.1: an idempotent request is repeated after a failure
        // "before the client is able to read the server's response".
        .closed => !response_began and idempotent(entry.request),
        .pending, .response, .reset, .malformed, .invalid, .too_large => false,
    };
}

/// RFC 9110 §9.2.2: "PUT, DELETE, and safe request methods are idempotent", and §9.2.1 names GET,
/// HEAD, OPTIONS and TRACE safe. A method that RFC 9110 §9.1 does not define is not known to be.
fn idempotent(request: *const event.Request) bool {
    const method = http.method.standard(request.method) orelse return false;
    return switch (method) {
        .get, .head, .options, .trace, .put, .delete => true,
        .post, .connect => false,
    };
}
