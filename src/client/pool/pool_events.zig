//! The steps the pool takes on its own and on its connections' events (decision 100, design §8
//! step 17d), each named after the step of spec/tla/client_exchanges it is (decision 105): hand
//! the waiting exchanges to an open connection with room, drain once shut down, close a slot whose
//! connection is over, open a connection or give up, and read what each connection reports. A
//! pool holds a QUIC slot and several TCP slots (decision 125), and takes the QUIC slot first, as
//! the model takes QUIC before TCP. `pool_links.zig` holds each link's life.
//!
//! Each step takes a pool of any `PoolOf` type. A pool with no QUIC (decision 124) never
//! opens QUIC, so its code holds no step on a QUIC connection: each one is out at build time.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const event_internal = @import("../event_internal.zig");
const pool_module = @import("pool.zig");
const choice = @import("pool_choice.zig");
const pool_handle = @import("pool_handle.zig");
const pool_connection = @import("pool_connection.zig");
const pool_links = @import("pool_links.zig");

const Event = pool_module.Event;
const Entry = pool_module.Entry;
const Stage = pool_module.Stage;

/// The slot visited `index`th, the QUIC slot first.
fn slot_at(pool: anytype, index: usize) u32 {
    return pool_handle.ordered(pool, @intCast(index));
}

/// Moves the pool on at `now_ns`, as the model's Assign, Drain, Close, Open and GiveUp do.
pub fn plan(pool: anytype, now_ns: u64) void {
    // A connection that drops a cancelled exchange's response frees its room and reports no
    // event, so the pool hands over the waiting exchanges here too.
    assign_waiting(pool);
    drain_if_shut(pool);
    for (0..pool_handle.slots_count(pool)) |index| pool_links.close_over(pool, slot_at(pool, index));
    const view = view_of(pool, now_ns);
    if (choice.next_open(&view)) |next| {
        const slot = switch (next) {
            .quic => pool_handle.quic_slot(pool),
            .tcp => |tcp_slot| tcp_slot,
        };
        pool_links.open_link(pool, slot, now_ns);
    } else if (choice.give_up(&view)) {
        give_up(pool);
    }
}

/// The first event the pool owes of its own, or null: a connection to open or close, an exchange
/// it ended, and its close.
pub fn owed(pool: anytype) ?Event {
    for (0..pool_handle.slots_count(pool)) |index| {
        const slot = slot_at(pool, index);
        const link = pool_handle.link(pool, slot);
        // The caller closes a slot's socket before it opens the next one.
        if (link.close_owed) {
            const closing = pool_handle.closing_handle(pool, slot);
            link.close_owed = false;
            return .{ .close = closing };
        }
        if (link.open_owed) {
            link.open_owed = false;
            return .{ .open = .{ .connection = pool_handle.handle_of(pool, slot), .transport = pool_handle.transport_of(pool, slot), .to = link.to } };
        }
    }
    if (oldest(pool, .ended)) |entry| return .{ .finished = deliver(entry) };
    if (!pool.shut or pool.closed_reported) return null;
    if (!all_idle(pool)) return null;
    // An exchange waiting with no connection opens one or ends, and a finished one was reported
    // above.
    assert(!any_entry(pool));
    pool.closed_reported = true;
    return .closed;
}

/// A TCP connection's `send`, once for each debt (decision 125): the connection may owe octets,
/// no `send` for them is outstanding, and no `send_stream` found it blocked since it last read
/// octets or the program last made a call.
pub fn owed_send(pool: anytype) ?Event {
    for (pool.tcp_links, 0..) |*link, index| {
        if (link.state != .running or link.send_outstanding or link.send_blocked) continue;
        if (!pool.tcp[index].owes_octets()) continue;
        link.send_outstanding = true;
        return .{ .send = pool_handle.handle_of(pool, @intCast(index)) };
    }
    return null;
}

/// A request or a cancel may give a blocked connection a debt it can write, so its next `send` may
/// go out (decision 125). A shutdown gives none: h2's GOAWAY waits until the exchanges end, which
/// octets the connection reads end.
pub fn unblock_sends(pool: anytype) void {
    for (pool.tcp_links) |*link| link.send_blocked = false;
}

/// One event a connection reported: the caller's, or null when the pool took it itself.
pub const Polled = struct {
    event: ?Event,
};

/// Reads one event a connection owes and handles it, or null when none owes one.
pub fn poll(pool: anytype, now_ns: u64) ?Polled {
    for (0..pool_handle.slots_count(pool)) |index| {
        const slot = slot_at(pool, index);
        if (pool_handle.link(pool, slot).state != .running) continue;
        const received = pool_connection.poll(pool, slot, now_ns);
        assert(received.consumed == 0);
        const reported = received.event orelse continue;
        return .{ .event = handle(pool, slot, reported) };
    }
    return null;
}

/// What `feed` took of the caller's input, and the caller's event it gave.
pub const Fed = struct {
    len: usize,
    event: ?Event,
};

/// Passes `input` to the connection that read it, and handles what it reports. Octets for a slot
/// with no running connection are dropped: its connection is over.
pub fn feed(pool: anytype, input: pool_module.Input, now_ns: u64) Fed {
    switch (input) {
        .none => return .{ .len = 0, .event = null },
        .datagram => |datagram| {
            if (!pool.capacity.quic or pool.quic_link.state != .running) return .{ .len = datagram.bytes.len, .event = null };
            const received = pool.quic.receive(datagram.bytes, datagram.ecn, datagram.from, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(pool, pool_handle.quic_slot(pool), reported) };
        },
        .stream => |stream| {
            const octets = stream.bytes;
            // Octets for a handle that names no running TCP connection are an earlier connection's.
            const slot = pool_handle.resolve(pool, stream.connection) orelse return .{ .len = octets.len, .event = null };
            // The program reads datagrams for the QUIC connection, so its handle names no stream.
            if (pool_handle.transport_of(pool, slot) != .tcp) return .{ .len = octets.len, .event = null };
            const link = &pool.tcp_links[slot];
            if (link.state != .running) return .{ .len = octets.len, .event = null };
            const connection = &pool.tcp[slot];
            const received = connection.receive(octets, now_ns);
            // What the connection read may let what it holds go out.
            if (received.consumed > 0) link.send_blocked = false;
            if (connection.take_alt_svc()) |advert| pool_links.learn(pool, advert, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(pool, slot, reported) };
        },
    }
}

/// What a connection's event means for the pool, and the caller's event it gives, if any.
fn handle(pool: anytype, slot: u32, reported: event.Event) ?Event {
    switch (reported) {
        .connected => |protocol| return on_connected(pool, slot, protocol),
        .ticket => return .{ .ticket = pool_handle.handle_of(pool, slot) },
        .finished => |finished| return on_finished(pool, slot, finished),
        // The phase reads the connection's own flag.
        .draining => return null,
        .closed => {
            pool_handle.link(pool, slot).reported_closed = true;
            return null;
        },
    }
}

/// A connection's handshake completed (the model's Handshake): it takes the waiting exchanges it
/// has room for, and ends the attempt. One the client abandoned owes its close but has not sent
/// it, so datagrams in flight may still complete its handshake, and it carries nothing.
fn on_connected(pool: anytype, slot: u32, protocol: event.Protocol) ?Event {
    const link = pool_handle.link(pool, slot);
    if (link.abandoned) return null;
    // The connection failed, or takes no new exchange, in the call that completed its handshake,
    // so it carries nothing. The attempt that opened it goes on (the model's FailHandshake): its
    // slot stays tried, and the exchanges go to another connection or end refused.
    const phase = pool.phase(slot);
    if (phase != .handshake) {
        if (phase == .draining) pool_links.abandon(pool, slot);
        return null;
    }
    const transport = pool_handle.transport_of(pool, slot);
    // The client abandons a handshake the moment a connection of the other transport is open,
    // so none is.
    assert(!other_open(pool, transport));
    link.won = true;
    pool_links.end_attempt(pool);
    abandon_other(pool, transport);
    assign_waiting(pool);
    // The connection that reports `connected` took every waiting exchange it could (the model's
    // TakeAtHandshake).
    assert(!any_waiting(pool) or slot_taking(pool) == null);
    return .{ .connected = .{ .connection = pool_handle.handle_of(pool, slot), .protocol = protocol } };
}

/// Whether a connection of the transport other than `transport` is open.
fn other_open(pool: anytype, transport: choice.Transport) bool {
    for (0..pool_handle.slots_count(pool)) |index| {
        const slot = slot_at(pool, index);
        if (pool_handle.transport_of(pool, slot) != transport and pool.phase(slot) == .open) return true;
    }
    return false;
}

/// Abandons each handshake of the transport other than `transport`, which lost.
fn abandon_other(pool: anytype, transport: choice.Transport) void {
    for (0..pool_handle.slots_count(pool)) |index| {
        const slot = slot_at(pool, index);
        if (pool_handle.transport_of(pool, slot) != transport and pool.phase(slot) == .handshake) pool_links.abandon(pool, slot);
    }
}

/// A connection reported an exchange's end. One that moves goes to another connection (the model's
/// MoveOn), and any other goes to the caller (its Deliver), which frees its room for a waiting one.
fn on_finished(pool: anytype, slot: u32, ended: event.Ended) ?Event {
    // A cancelled exchange reports nothing, so every reported one is carried.
    const entry = carried(pool, slot, ended.id).?;
    assert(entry.request == ended.request and entry.response == ended.response);
    if (movable(pool, entry, slot, ended.response_began)) {
        // RFC 9114 §4.1.1: a refused request is treated "as though [it] had never been sent". A
        // request sent again starts its response anew, and counts its content again.
        const closed = entry.response.outcome == .closed;
        // RFC 9112 §9.3.2: a failed connection is one "not explicitly closed by the server in its
        // last complete response", which leaves the connection draining instead.
        const after_failure = closed and pool.phase(slot) == .failed;
        event_internal.clear(entry.response);
        entry.* = .{
            .stage = .waiting,
            .id = entry.id,
            .request = entry.request,
            .response = entry.response,
            .moves = entry.moves + 1,
            .resent = entry.resent or closed,
            .after_failure = after_failure,
        };
        assign_waiting(pool);
        return null;
    }
    const reported: Event = .{ .finished = deliver(entry) };
    assign_waiting(pool);
    return reported;
}

/// Whether a reported exchange moves: the connection that reported it takes no new exchange, the
/// exchange moved fewer than `moves_max` times, refusals and resends together, and the connection
/// refused it unprocessed, or closed before any of its response arrived and its method is
/// idempotent (decision 124).
fn movable(pool: anytype, entry: *const Entry, slot: u32, response_began: bool) bool {
    // RFC 9110 §9.2.2: "A client SHOULD NOT automatically retry a failed automatic retry."
    if (entry.moves >= constants.moves_max) return false;
    if (pool.phase(slot) == .open) return false;
    return switch (entry.response.outcome) {
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

/// Gives `entry` back to the caller, and returns its event. A request sent again that a later
/// connection refused, or that no connection took, ends `closed`: the first server may have
/// processed it, and `refused` says that no server did (decision 105).
fn deliver(entry: *Entry) event.Finished {
    assert(entry.stage == .carried or entry.stage == .ended);
    if (entry.resent and entry.response.outcome == .refused) entry.response.outcome = .closed;
    const reported: event.Finished = .{ .id = entry.id, .request = entry.request, .response = entry.response };
    entry.* = .{};
    return reported;
}

/// Hands each waiting exchange, oldest first, to an open connection that takes it (the model's
/// Assign), which ends the attempt's tries. The connection then owes the request, so a `send` the
/// connection blocked may go out (decision 125).
pub fn assign_waiting(pool: anytype) void {
    // Bounded: each pass hands over the oldest waiting exchange, or stops.
    for (0..pool.entries.len) |_| {
        const entry = oldest(pool, .waiting) orelse return;
        const slot = slot_taking(pool) orelse return;
        // A connection whose slots are full takes no more until one ends.
        const carried_id = pool_connection.request(pool, slot, entry.request, entry.response) catch return;
        entry.stage = .carried;
        entry.carrier = slot;
        entry.carried_id = carried_id;
        pool_links.clear_tried(pool);
        if (pool_handle.transport_of(pool, slot) == .tcp) pool.tcp_links[slot].send_blocked = false;
    }
}

/// The open connection with room for another exchange, the QUIC one first, or null. A connection
/// with room may still hold every exchange its slots take: then no other connection opens beside
/// it, and the exchanges wait (`slot_taking`).
fn slot_with_room(pool: anytype) ?u32 {
    for (0..pool_handle.slots_count(pool)) |index| {
        const slot = slot_at(pool, index);
        if (pool.phase(slot) == .open and pool_connection.room(pool, slot)) return slot;
    }
    return null;
}

/// The open connection that takes an exchange now, the QUIC one first, or null.
fn slot_taking(pool: anytype) ?u32 {
    for (0..pool_handle.slots_count(pool)) |index| {
        const slot = slot_at(pool, index);
        if (pool.phase(slot) == .open and pool_connection.takes(pool, slot)) return slot;
    }
    return null;
}

/// A shut-down pool drains its open connections once no exchange waits for one (the model's
/// Drain), and ends a handshake once it holds no exchange, which could come back refused (its
/// Abandon).
fn drain_if_shut(pool: anytype) void {
    if (!pool.shut) return;
    if (!any_waiting(pool)) {
        for (0..pool_handle.slots_count(pool)) |index| {
            const slot = slot_at(pool, index);
            if (pool.phase(slot) == .open) pool_connection.shutdown(pool, slot);
        }
    }
    if (any_entry(pool)) return;
    for (0..pool_handle.slots_count(pool)) |index| {
        const slot = slot_at(pool, index);
        if (pool.phase(slot) == .handshake) pool_links.abandon(pool, slot);
    }
}

/// Ends each waiting exchange refused, since no connection is left to take it (the model's
/// GiveUp). RFC 9113 §8.7: no server processed it, so the caller may make it again. One the pool
/// sent again ends `closed` once it is reported (`deliver`).
fn give_up(pool: anytype) void {
    for (pool.entries) |*entry| {
        if (entry.stage != .waiting) continue;
        entry.response.outcome = .refused;
        entry.stage = .ended;
    }
    pool_links.end_attempt(pool);
}

fn view_of(pool: anytype, now_ns: u64) choice.View {
    var view: choice.View = .{
        .quic = if (pool.capacity.quic) pool.phase(pool_handle.quic_slot(pool)) else .none,
        .quic_tried = pool.quic_link.tried,
        .quic_allowed = pool_links.quic_allowed(pool, now_ns),
        .tcp_allowed = pool.offered.tcp,
        .tcp_free = null,
        .tcp_opening = 0,
        .tcp_open = false,
        .waiting = count(pool, .waiting),
        .room = slot_with_room(pool) != null,
        .fallback = pool.fallback,
        .all_idle = all_idle(pool),
    };
    for (pool.tcp_links, 0..) |*link, index| {
        const slot: u32 = @intCast(index);
        const phase = pool.phase(slot);
        if (phase.idle() and !link.tried and view.tcp_free == null) view.tcp_free = slot;
        if (phase == .handshake) view.tcp_opening += 1;
        if (phase == .open) view.tcp_open = true;
    }
    return view;
}

/// Whether no slot has a connection.
fn all_idle(pool: anytype) bool {
    for (0..pool_handle.slots_count(pool)) |index| {
        if (!pool.phase(slot_at(pool, index)).idle()) return false;
    }
    return true;
}

/// The entry at `stage` with the lowest id, or null.
fn oldest(pool: anytype, stage: Stage) ?*Entry {
    var found: ?*Entry = null;
    for (pool.entries) |*entry| {
        if (entry.stage != stage) continue;
        if (found == null or entry.id < found.?.id) found = entry;
    }
    return found;
}

fn carried(pool: anytype, slot: u32, carried_id: event.RequestId) ?*Entry {
    for (pool.entries) |*entry| {
        if (entry.stage == .carried and entry.carrier == slot and entry.carried_id == carried_id) return entry;
    }
    return null;
}

fn count(pool: anytype, stage: Stage) u32 {
    var counted: u32 = 0;
    for (pool.entries) |*entry| counted += @intFromBool(entry.stage == stage);
    return counted;
}

fn any_waiting(pool: anytype) bool {
    return count(pool, .waiting) > 0;
}

fn any_entry(pool: anytype) bool {
    for (pool.entries) |*entry| {
        if (entry.stage != .free) return true;
    }
    return false;
}
