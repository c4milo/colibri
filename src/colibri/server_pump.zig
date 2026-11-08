//! The program around a `colibri.Server`'s engine, with no socket in it: the octets a socket read
//! go in, the octets it sends come out, and the router answers every request. Moved from the
//! test-only server's `server_session.zig` for design §8 step 37b, with the router in place of its
//! fixed answers. `server_loop.zig` is the socket side.
//!
//! The server keeps one entry for each socket, and the entry outlives the engine's slot: the
//! engine frees a slot when it reports the connection's `ended`, straight after its `close`,
//! while the socket may still hold octets to send. So `entry_of` maps each slot to the entry of
//! the connection the slot holds now, and an entry keeps its connection's whole handle.
//!
//! `step` serves one socket. It repeats three things until none of the first two moves:
//!   1. passes the socket's input to the engine and routes every event it reports;
//!   2. calls `send_stream` once, into the socket's room;
//!   3. reads the engine's events until it reports none.
//! The router writes each response as it takes the request's events, so the responses to the
//! requests one read carried leave in one `send_stream` (decision 119 as amended).
//!
//! Each function takes `run`, the server, which holds the program's router and context behind
//! `erased.zig`'s `Router`.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("constants.zig");

/// What one step did.
pub const Step = struct {
    /// Octets of the socket's input the connection consumed.
    consumed: usize,
    /// Octets written into the socket's output, to be sent in order.
    written: usize,
};

/// What the server holds for one socket's connection.
pub const Entry = struct {
    /// The connection the entry was given last. The entry keeps it after the connection ended,
    /// when it names nothing, so a late call for the socket reaches no later connection.
    handle: server.ConnectionHandle,
    /// Whether the engine holds that connection: it has not reported its `ended`.
    attached: bool,
    /// The engine reported the connection's `close`: the socket closes once its octets are out.
    closing: bool,
    /// The engine reported the connection's `half_close`: the socket's write side closes once its
    /// octets are out, and its receives go on (decision 160).
    half_closing: bool = false,
    /// The connection owes octets no `send_stream` has taken.
    send_owed: bool,
};

/// The handle of an entry no socket has taken yet. Generation 0 names no connection (decision
/// 119).
pub const no_connection: server.ConnectionHandle = .{ .slot = 0, .generation = 0 };

/// Starts the connection of a socket the listener accepted at `now_ns`, in the free entry
/// `index`. False when the engine starts none: the caller closes the socket.
pub fn accept(run: anytype, index: usize, tls: bool, now_ns: u64) bool {
    const state = run;
    const entry = &state.entries[index];
    assert(!entry.attached);
    state.now_ns = now_ns;
    const handle = state.engine.accept(.{ .tls = tls }, now_ns) orelse return false;
    // A slot the engine hands out is one whose last connection it reported `ended`.
    assert(state.entry_of[handle.slot] == null);
    state.entry_of[handle.slot] = @intCast(index);
    entry.* = .{ .handle = handle, .attached = true, .closing = false, .send_owed = false };
    return true;
}

/// Serves the socket of entry `index` at `now_ns`: consumes what it can of `input`, and writes what
/// it can into `output`. See the header.
pub fn step(run: anytype, index: usize, input: []u8, output: []u8, now_ns: u64) Step {
    const state = run;
    const entry = &state.entries[index];
    state.now_ns = now_ns;
    var consumed: usize = 0;
    var written: usize = 0;
    // Bounded: a pass in which nothing moves ends the loop.
    for (0..constants.limits.events_per_step_max) |_| {
        const taken = read(run, entry, input[consumed..]);
        consumed += taken.consumed;
        const sent = send(state, entry, output[written..]);
        written += sent;
        drain(run);
        if (taken.moved or sent > 0) continue;
        state.pending.unset(index);
        break;
    } else state.pending.set(index);
    return .{ .consumed = consumed, .written = written };
}

/// The socket of entry `index` closed before the engine asked: its peer closed it, or a read or
/// a send failed. The engine ends the connection, and its slot frees.
pub fn peer_closed(run: anytype, index: usize, now_ns: u64) void {
    const state = run;
    state.now_ns = now_ns;
    state.engine.transport_closed(state.entries[index].handle);
    drain(run);
}

const Read = struct { consumed: usize, moved: bool };

/// Passes `input` to the entry's connection until the engine consumes nothing and reports
/// nothing, routing each event. A connection the engine closed or ended reads nothing.
fn read(run: anytype, entry: *Entry, input: []u8) Read {
    const state = run;
    var taken: Read = .{ .consumed = 0, .moved = false };
    for (0..constants.limits.events_per_step_max) |_| {
        if (entry.closing or !entry.attached) break;
        const bytes: server.StreamBytes = .{ .connection = entry.handle, .bytes = input[taken.consumed..] };
        const received = state.engine.receive(.{ .stream = bytes }, state.now_ns);
        taken.consumed += received.consumed;
        if (received.event) |reported| route(run, reported);
        if (received.consumed == 0 and received.event == null) break;
        taken.moved = true;
    }
    return taken;
}

/// Writes what the entry's connection owes into `room`. A call that fills the room leaves more
/// owed (decision 119), so the entry stays owing for the step that has room again.
fn send(state: anytype, entry: *Entry, room: []u8) usize {
    if (!entry.send_owed or room.len == 0) return 0;
    const written = state.engine.send_stream(entry.handle, room, state.now_ns);
    entry.send_owed = written == room.len;
    return written;
}

/// Reads the engine's events until it reports none, routing each.
pub fn drain(run: anytype) void {
    const state = run;
    for (0..constants.limits.events_per_step_max) |_| {
        const reported = state.engine.receive(.none, state.now_ns).event orelse {
            state.undrained = false;
            return;
        };
        route(run, reported);
    }
    state.undrained = true;
}

/// Hands an event of a TCP or a QUIC connection to the router. The router writes each response
/// itself, so the TCP connection of a request's event is stepped. The router hands back the events
/// of the connections, which are the server's I/O. A QUIC connection's datagrams leave in the
/// loop's flush.
pub fn route(run: anytype, reported: server.Event) void {
    if (request_connection(reported)) |handle| {
        if (is_tcp(run, handle)) _ = named(run, handle);
    }
    switch (run.router.handle(&run.engine, reported)) {
        .taken => {},
        .event => |other| on_connection_event(run, other),
    }
}

/// The connection of a request's event, or null for a connection's own event.
fn request_connection(reported: server.Event) ?server.ConnectionHandle {
    return switch (reported) {
        .request => |request| request.id.connection,
        .body => |body| body.id.connection,
        .trailers => |trailers| trailers.id.connection,
        .writable => |writable| writable.id.connection,
        .finished => |finished| finished.id.connection,
        .send, .half_close, .close, .ended, .closed => null,
    };
}

fn on_connection_event(state: anytype, reported: server.Event) void {
    switch (reported) {
        .send => |handle| named(state, handle).send_owed = true,
        .half_close => |handle| named(state, handle).half_closing = true,
        .close => |handle| named(state, handle).closing = true,
        // A QUIC connection has no socket of its own, and its slot frees in the engine.
        .ended => |over| if (is_tcp(state, over.connection)) {
            // The slot takes another connection from here on, and the entry stays its socket's.
            named(state, over.connection).attached = false;
            state.entry_of[over.connection.slot] = null;
        },
        // The shut-down engine holds no connection, and `run` returns.
        .closed => state.over = true,
        // The router takes every event of a request.
        .request, .body, .trailers, .writable, .finished => {},
    }
}

/// Whether `handle` names a TCP connection: the engine's TCP slots come first.
fn is_tcp(state: anytype, handle: server.ConnectionHandle) bool {
    return handle.slot < state.entries.len;
}

/// The entry of the connection `handle` names, which the loop steps.
fn named(state: anytype, handle: server.ConnectionHandle) *Entry {
    const index = state.entry_of[handle.slot].?;
    const entry = &state.entries[index];
    // The engine reports nothing of a connection after its `ended`, which empties the slot's
    // place in the map, so the entry found is this connection's.
    assert(entry.attached and std.meta.eql(entry.handle, handle));
    state.pending.set(index);
    return entry;
}
