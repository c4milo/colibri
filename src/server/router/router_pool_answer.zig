//! The router's answers to a request with no entry: 404, 405, 501 and 503 (RFC 9110 §15.5.5,
//! §15.5.6, §15.6.2, §15.6.4), each a head with no content. Split out of `router_pool.zig` for
//! length.
//!
//! A head that the engine has no room for waits in a slot of the pool, and goes on the request's
//! `writable` (design §8 step 53). A slot names its request by its id, so the request's
//! `user_data` stays 0, as that of each request with no entry. The pool has one slot for each of
//! its `requests`. With an answer in each slot, the router cancels the request, as it did for
//! each head with no room before.
//!
//! No call here is inline: a request that a route serves runs none of this code, and the pool's
//! `handle` stays as small as it was (design §8 step 53).
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");

/// A head that waits for room in the engine: its request, its status, and the Allow value of a
/// 405, which is a constant of the route table.
pub const Waiting = struct {
    used: bool = false,
    id: event.RequestId = event.id_of(0),
    status: http.Status = .not_found,
    allow: []const u8 = "",
};

/// The slots of a pool of `count` requests, and how many of them hold an answer, so a request
/// with no answer that waits scans none.
pub fn Answers(comptime count: usize) type {
    return struct {
        slots: [count]Waiting = @splat(.{}),
        used: usize = 0,
    };
}

/// Answers request `id` with `status` and no content. `allow` is the Allow value of a 405 (RFC
/// 9110 §15.5.6), and empty for each other status.
pub noinline fn answer(answers: anytype, engine: anytype, id: event.RequestId, status: http.Status, allow: []const u8) void {
    write(engine, id, status, allow) catch |failure| switch (failure) {
        // The engine sends the request's `writable` once it has room for the head.
        error.NoSpaceLeft => hold(answers, engine, id, status, allow),
        else => engine.cancel(id),
    };
}

fn write(engine: anytype, id: event.RequestId, status: http.Status, allow: []const u8) !void {
    const lines = [1]http.Field{.{ .name = "allow", .value = allow }};
    const headers: []const http.Field = if (allow.len == 0) &.{} else &lines;
    return engine.respond(id, .{ .status = status, .headers = headers, .end = true });
}

/// Keeps the answer in a free slot.
fn hold(answers: anytype, engine: anytype, id: event.RequestId, status: http.Status, allow: []const u8) void {
    for (&answers.slots) |*slot| {
        if (slot.used) continue;
        slot.* = .{ .used = true, .id = id, .status = status, .allow = allow };
        answers.used += 1;
        return;
    }
    // Each slot holds an answer that waits, so this one has none.
    engine.cancel(id);
}

/// The slot that holds the answer of request `id`, or null.
fn slot_of(answers: anytype, id: event.RequestId) ?*Waiting {
    if (answers.used == 0) return null;
    for (&answers.slots) |*slot| {
        if (slot.used and same(slot.id, id)) return slot;
    }
    return null;
}

fn same(left: event.RequestId, right: event.RequestId) bool {
    return @as(u128, @bitCast(left)) == @as(u128, @bitCast(right));
}

/// Writes the answer that waits for request `id`, which now has room. A head that finds no room
/// again waits for the next `writable`.
pub noinline fn on_writable(answers: anytype, engine: anytype, id: event.RequestId) void {
    const slot = slot_of(answers, id) orelse return;
    write(engine, id, slot.status, slot.allow) catch |failure| switch (failure) {
        error.NoSpaceLeft => {},
        else => engine.cancel(id),
    };
}

/// Frees the slot of request `id`, which is over: its answer went, or the request ended first.
pub noinline fn on_finished(answers: anytype, id: event.RequestId) void {
    const slot = slot_of(answers, id) orelse return;
    slot.used = false;
    assert(answers.used > 0);
    answers.used -= 1;
}
