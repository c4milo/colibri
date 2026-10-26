//! One worker's connections in design §9's server, with no socket in them (design §8 step 21b.6):
//! one `server.Endpoint` serves every connection the worker holds, and this file is the program
//! around it. The octets a socket read go in, the octets it sends come out, and every request is
//! answered once it is read whole (`server_session_answer.zig`). `../server.zig` is the socket
//! side.
//!
//! The program keeps one entry for each socket, and the entry outlives the endpoint's slot: the
//! endpoint frees a slot when it reports the connection's `ended`, straight after its `close`,
//! while the socket may still hold octets to send. So `entry_of` maps each slot to the entry of
//! the connection the slot holds now, every event is routed through it, and an entry keeps its
//! connection's whole handle, whose generation a later connection in the slot does not share.
//!
//! `step` serves one socket. It repeats four things until none of the first three moves:
//!   1. passes the socket's input to the endpoint and routes every event it reports;
//!   2. writes as much of the owed responses as the connection takes, oldest first;
//!   3. calls `send_stream` once, into the socket's room;
//!   4. reads the endpoint's events until it reports none.
//! An event the last pass's fourth thing reads for this socket's connection needs no pass of its
//! own. It is a `close` or an `ended`, which the caller reads from the entry, or a `send` whose
//! record did not fit the room left: the socket then has a send in flight, and the step that
//! follows it has the room.
//! So the responses to the requests one read carried leave in one `send_stream`, and nothing is
//! read between a response's write and its send, which would pause an h2 stream's send meter
//! (decision 119 as amended). h11 reads a pipelined request only once the response before it is
//! done (decision 92), which the fourth thing reports, so the next pass reads it.
//!
//! An event may name another connection than the one `step` serves: a deadline fired there, or
//! its turn came in the endpoint's ring. The event changes that connection's entry, and `pending`
//! names the entry so the worker steps it too.
//!
//! The caller hands each call the instant it runs at, and wakes at `deadline_ns` to call
//! `on_instant`, so decision 110's deadlines run on the caller's clock. The endpoint runs TLS
//! itself when its configuration names an identity, so this file holds no record and no protocol
//! rule.
const std = @import("std");
const assert = std.debug.assert;
pub const server = @import("server");
const constants = @import("../constants.zig");
const h11_echo = @import("../h11/h11_echo.zig");
const server_session_answer = @import("server_session_answer.zig");
const server_routes = @import("server_routes.zig");

/// What one step did.
pub const Step = struct {
    /// Octets of the caller's input the connection consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// Whether the endpoint has reported the connection's `close`: the socket closes once the
    /// octets written so far are out.
    done: bool,
};

/// What the program holds for one socket: its connection in the endpoint, and what it owes.
pub const Entry = struct {
    /// The connection the entry was given last. The entry keeps it after the connection ended,
    /// when it names nothing, so a late call for the socket reaches no later connection.
    handle: server.ConnectionHandle,
    /// Whether the endpoint holds that connection: it has not reported its `ended`.
    attached: bool,
    /// The endpoint reported the connection's `close`: the program closes the socket once the
    /// octets it holds are out. A connection whose peer closed first gets none.
    closing: bool,
    /// The connection owes octets no `send_stream` has taken: the endpoint reported a `send`, a
    /// response was written, or the last `send_stream` filled its room.
    send_owed: bool,
    answers: server_session_answer.Answers,
};

/// The handle of an entry no socket has taken yet. Generation 0 names no connection (decision
/// 119).
const no_connection: server.ConnectionHandle = .{ .slot = 0, .generation = 0 };

/// Events one loop of a step reads at most, and passes one step makes. A loop that reaches the
/// bound leaves the entry in `pending` or the session `undrained`, so the worker comes back. A
/// session starts with this bound in `events_max`, which a test lowers to reach it.
const events_per_step_max: usize = 1024;

/// The session of a worker of the server.
pub const Session = SessionOf(constants.connections_per_worker_max);

/// A session that holds `connections_max` sockets' connections, in an endpoint of as many slots.
/// What its functions do is below the type, in functions that take a session of any size.
pub fn SessionOf(comptime connections_max: usize) type {
    return struct {
        const Self = @This();
        pub const Endpoint = server.EndpointOf(.{ .tcp_connections = connections_max, .quic_connections = 0 });
        const Pending = std.bit_set.IntegerBitSet(connections_max);

        /// It stays where `init` found it: the endpoint keeps pointers into itself.
        endpoint: Endpoint,
        entries: [connections_max]Entry,
        /// The entry of the connection each slot of the endpoint holds now, or null for a free
        /// slot.
        entry_of: [connections_max]?u32,
        /// The entries an event named since their last step.
        pending: Pending,
        /// Whether a read of the endpoint's events stopped at its bound.
        undrained: bool,
        /// The bound of each loop: `events_per_step_max`.
        events_max: usize,
        /// The instant of the last call (design §4.2).
        now_ns: u64,
        /// The router that answers every request in the `--routes github` mode, or null, when
        /// each connection's `answers` do (design §8 step 13f).
        routes: ?*server_routes.Pool,

        /// Prepares a session that holds no connection, under `config`, which the endpoint reads
        /// while it runs. The server issues no ticket, so it judges none at a clock: chapulin's 0
        /// for none.
        pub fn init(session: *Self, config: *const server.Config, random: std.Random, now_ns: u64) server.StartError!void {
            for (&session.entries) |*entry| {
                entry.handle = no_connection;
                entry.attached = false;
                entry.closing = false;
                entry.send_owed = false;
                entry.answers.reset(null);
            }
            session.events_max = events_per_step_max;
            session.routes = null;
            session.entry_of = @splat(null);
            session.pending = Pending.initEmpty();
            session.undrained = false;
            session.now_ns = now_ns;
            try session.endpoint.init(config, random, 0, now_ns);
        }

        /// Starts the connection of a socket the listener accepted at `now_ns`, in the free entry
        /// `index`. False when the endpoint starts none: the caller closes the socket. The caller
        /// marks the entry, so its first step runs.
        pub fn accept(session: *Self, index: usize, tls: bool, echo: ?*h11_echo.Echo, now_ns: u64) bool {
            return accept_into(session, index, tls, echo, now_ns);
        }

        /// Serves the socket of entry `index` at `now_ns`: consumes what it can of `input` and
        /// writes what it can into `output`. See the header.
        pub fn step(session: *Self, index: usize, input: []u8, output: []u8, now_ns: u64) Step {
            return step_entry(session, index, input, output, now_ns);
        }

        /// The socket of entry `index` closed before the endpoint asked: its peer closed it, or a
        /// read or a send failed. The endpoint ends the connection, and its slot frees.
        pub fn peer_closed(session: *Self, index: usize, now_ns: u64) void {
            return end_entry(session, index, now_ns);
        }

        /// The soonest instant a connection's deadline passes, or null (decision 110).
        pub fn deadline_ns(session: *Self) ?u64 {
            return session.endpoint.deadline_ns();
        }

        /// Hands the endpoint `now_ns`, which a deadline has passed at, and routes what its
        /// connections then report. `next_pending` names each entry to step.
        pub fn on_instant(session: *Self, now_ns: u64) void {
            session.now_ns = now_ns;
            session.endpoint.on_instant(now_ns);
            drain(session);
        }

        /// An entry an event named since its last step, which is no longer pending, or null.
        pub fn next_pending(session: *Self) ?usize {
            return session.pending.toggleFirstSet();
        }

        /// Names entry `index` for a step: its socket was accepted, read octets or has room again.
        pub fn mark(session: *Self, index: usize) void {
            session.pending.set(index);
        }

        /// Whether nothing waits for the worker: no entry is pending, and the endpoint reported
        /// its last event.
        pub fn settled(session: *const Self) bool {
            return !session.undrained and session.pending.count() == 0;
        }
    };
}

/// `accept` of a session of any size.
fn accept_into(session: anytype, index: usize, tls: bool, echo: ?*h11_echo.Echo, now_ns: u64) bool {
    const entry = &session.entries[index];
    assert(!entry.attached);
    session.now_ns = now_ns;
    const handle = session.endpoint.accept(.{ .tls = tls }, now_ns) orelse return false;
    // A slot the endpoint hands out is one whose last connection it reported `ended`.
    assert(session.entry_of[handle.slot] == null);
    session.entry_of[handle.slot] = @intCast(index);
    entry.handle = handle;
    entry.attached = true;
    entry.closing = false;
    entry.send_owed = false;
    entry.answers.reset(echo);
    return true;
}

/// `step` of a session of any size.
fn step_entry(session: anytype, index: usize, input: []u8, output: []u8, now_ns: u64) Step {
    const entry = &session.entries[index];
    session.now_ns = now_ns;
    var consumed: usize = 0;
    var written: usize = 0;
    // Bounded: a pass in which nothing moves ends the loop.
    for (0..session.events_max) |_| {
        const taken = read(session, entry, input[consumed..]);
        consumed += taken.consumed;
        const finished = answer(session, entry);
        const sent = send(session, entry, output[written..]);
        written += sent;
        drain(session);
        if (taken.moved or finished > 0 or sent > 0) continue;
        // See the header for what the drain above may have read for this entry.
        session.pending.unset(index);
        break;
    } else session.pending.set(index);
    return .{ .consumed = consumed, .written = written, .done = entry.closing };
}

/// `peer_closed` of a session of any size.
fn end_entry(session: anytype, index: usize, now_ns: u64) void {
    session.now_ns = now_ns;
    // The handle of a connection that ended names nothing, so a socket that fails after its
    // connection ended reaches no later connection in the slot.
    session.endpoint.transport_closed(session.entries[index].handle);
    drain(session);
}

const Read = struct { consumed: usize, moved: bool };

/// Passes `input` to the entry's connection until the endpoint consumes nothing and reports
/// nothing, routing each event. A connection the endpoint closed or ended reads nothing: the
/// endpoint would consume and drop the octets.
fn read(session: anytype, entry: *Entry, input: []u8) Read {
    var taken: Read = .{ .consumed = 0, .moved = false };
    for (0..session.events_max) |_| {
        if (entry.closing or !entry.attached) break;
        const octets: server.StreamBytes = .{ .connection = entry.handle, .bytes = input[taken.consumed..] };
        const received = session.endpoint.receive(.{ .stream = octets }, session.now_ns);
        taken.consumed += received.consumed;
        if (received.event) |reported| on_event(session, reported);
        if (received.consumed == 0 and received.event == null) break;
        taken.moved = true;
    }
    return taken;
}

/// Writes what the entry's connection takes of its owed responses, and returns how many it
/// finished. What the endpoint took, the connection owes its socket. A connection that ended
/// owes none: each of its requests ended first (INV-30).
fn answer(session: anytype, entry: *Entry) usize {
    const written = entry.answers.write(&session.endpoint, entry.handle);
    if (written.wrote) entry.send_owed = true;
    return written.finished;
}

/// Writes what the entry's connection owes into `room`, when it owes anything. A call that fills
/// the room leaves more owed (decision 119), so the entry stays owing for the step that has room
/// again. The handle of a connection that ended names nothing, and the endpoint writes nothing.
fn send(session: anytype, entry: *Entry, room: []u8) usize {
    if (!entry.send_owed or room.len == 0) return 0;
    const written = session.endpoint.send_stream(entry.handle, room, session.now_ns);
    entry.send_owed = written == room.len;
    return written;
}

/// Reads the endpoint's events until it reports none, routing each.
fn drain(session: anytype) void {
    for (0..session.events_max) |_| {
        const reported = session.endpoint.receive(.none, session.now_ns).event orelse {
            session.undrained = false;
            return;
        };
        on_event(session, reported);
    }
    session.undrained = true;
}

/// Notes what one event says in the entry of the connection it names. The event's octets are
/// valid until the endpoint's next call, so the echo copies them now.
fn on_event(session: anytype, reported: server.Event) void {
    if (session.routes) |pool| {
        if (routed(session, pool, reported)) return;
    }
    switch (reported) {
        .request => |request| named(session, request.id.connection).answers.on_request(request),
        .body => |body| named(session, body.id.connection).answers.on_body(body),
        .trailers => |trailers| named(session, trailers.id.connection).answers.finish_reading(trailers.id.number),
        // Every response body is a constant or the echo's own copy, so nothing waits to be freed.
        // The connection may read again, and the entry's next step passes its input. A cancelled
        // request takes no answer.
        .finished => |finished| switch (finished.result) {
            .sent => _ = named(session, finished.id.connection),
            .cancelled => named(session, finished.id.connection).answers.forget(finished.id.number),
        },
        .writable => |writable| _ = named(session, writable.id.connection),
        .send => |handle| named(session, handle).send_owed = true,
        .close => |handle| named(session, handle).closing = true,
        // The slot takes another connection from here on, and the entry stays its socket's.
        .ended => |over| {
            named(session, over.connection).attached = false;
            session.entry_of[over.connection.slot] = null;
        },
        // The server never shuts its endpoint down.
        .closed => unreachable,
    }
}

/// Passes a request's event to the router, and returns whether it took it. The router writes the
/// response itself, so the connection's entry is stepped, and its `answers` owe nothing.
fn routed(session: anytype, pool: *server_routes.Pool, reported: server.Event) bool {
    const connection = switch (reported) {
        .request => |request| request.id.connection,
        .body => |body| body.id.connection,
        .trailers => |trailers| trailers.id.connection,
        .writable => |writable| writable.id.connection,
        .finished => |finished| finished.id.connection,
        .send, .close, .ended, .closed => return false,
    };
    _ = named(session, connection);
    var context: void = {};
    const handled = pool.handle(&context, &session.endpoint, reported);
    assert(handled == .taken);
    return true;
}

/// The entry of the connection `handle` names, which an event named: its worker steps it.
fn named(session: anytype, handle: server.ConnectionHandle) *Entry {
    const index = session.entry_of[handle.slot].?;
    const entry = &session.entries[index];
    // The endpoint reports nothing of a connection after its `ended`, which empties the slot's
    // place in the map, so the entry found is this connection's.
    assert(entry.attached and std.meta.eql(entry.handle, handle));
    session.pending.set(index);
    return entry;
}

test {
    _ = @import("server_session_test.zig");
}
