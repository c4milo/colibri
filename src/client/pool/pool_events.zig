//! The steps the pool takes on its own and on its connections' events (decision 100, design §8
//! step 17d), each named after the step of spec/tla/client_exchanges it is (decision 105): hand
//! the waiting exchanges to the open connection, drain once shut down, close a transport whose
//! connection is over, open a transport or give up, and read what each connection reports.
//!
//! Each step takes a pool of any `PoolOf` type. A pool with no QUIC (decision 124) never
//! opens QUIC, so its code holds no step on a QUIC connection: each one is out at build time.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const event_internal = @import("../event_internal.zig");
const alt_svc = @import("../alt_svc.zig");
const quic_internal = @import("../quic/quic_connection_internal.zig");
const pool_module = @import("pool.zig");
const choice = @import("pool_choice.zig");
const pool_handle = @import("pool_handle.zig");

const Transport = pool_module.Transport;
const Event = pool_module.Event;
const Entry = pool_module.Entry;
const Link = pool_module.Link;
const Stage = pool_module.Stage;
const Alternative = pool_module.Alternative;

const transports = [_]Transport{ .quic, .tcp };

/// Moves the pool on at `now_ns`, as the model's Drain, Close, Open and GiveUp do. Its Assign
/// happens where an exchange starts waiting or a connection opens.
pub fn plan(pool: anytype, now_ns: u64) void {
    drain_if_shut(pool);
    for (transports) |transport| close_over(pool, transport);
    const view = view_of(pool, now_ns);
    if (choice.next_open(&view)) |transport| {
        open_link(pool, transport, now_ns);
    } else if (choice.give_up(&view)) {
        give_up(pool);
    }
}

/// The first event the pool owes of its own, or null: a transport to open or close, an exchange
/// it ended, and its close.
pub fn owed(pool: anytype) ?Event {
    for (transports) |transport| {
        const link = pool.links.getPtr(transport);
        // The caller closes a transport's socket before it opens the next one.
        if (link.close_owed) {
            const closing = pool_handle.closing_handle(pool, transport);
            link.close_owed = false;
            return .{ .close = closing };
        }
        if (link.open_owed) {
            link.open_owed = false;
            return .{ .open = .{ .connection = pool_handle.handle_of(pool, transport), .transport = transport, .to = link.to } };
        }
    }
    if (oldest(pool, .ended)) |entry| return .{ .finished = deliver(entry) };
    if (!pool.shut or pool.closed_reported) return null;
    if (!pool.phase(.quic).idle() or !pool.phase(.tcp).idle()) return null;
    // An exchange waiting with no connection opens one or ends, and a finished one was reported
    // above.
    assert(!any_entry(pool));
    pool.closed_reported = true;
    return .closed;
}

/// The TCP connection's `send`, once for each debt (decision 125): the connection may owe octets,
/// no `send` for them is outstanding, and no `send_stream` found it blocked since it last read
/// octets or the program last made a call.
pub fn owed_send(pool: anytype) ?Event {
    const link = pool.links.getPtr(.tcp);
    if (link.state != .running or link.send_outstanding or link.send_blocked) return null;
    if (!pool.tcp[0].owes_octets()) return null;
    link.send_outstanding = true;
    return .{ .send = pool_handle.handle_of(pool, .tcp) };
}

/// A request or a cancel may give a blocked connection a debt it can write, so its next `send` may
/// go out (decision 125). A shutdown gives none: h2's GOAWAY waits until the exchanges end, which
/// octets the connection reads end.
pub fn unblock_sends(pool: anytype) void {
    pool.links.getPtr(.tcp).send_blocked = false;
}

/// One event a connection reported: the caller's, or null when the pool took it itself.
pub const Polled = struct {
    event: ?Event,
};

/// Reads one event a connection owes and handles it, or null when neither owes one.
pub fn poll(pool: anytype, now_ns: u64) ?Polled {
    var none: [0]u8 = .{};
    for (transports) |transport| {
        if (pool.links.get(transport).state != .running) continue;
        const received = switch (transport) {
            .quic => if (pool.capacity.quic) pool.quic.receive(&none, .not_ect, .{}, now_ns) else unreachable,
            .tcp => pool.tcp[0].receive(&none, now_ns),
        };
        assert(received.consumed == 0);
        const reported = received.event orelse continue;
        return .{ .event = handle(pool, transport, reported) };
    }
    return null;
}

/// What `feed` took of the caller's input, and the caller's event it gave.
pub const Fed = struct {
    len: usize,
    event: ?Event,
};

/// Passes `input` to the connection of the transport that read it, and handles what it reports.
/// Octets for a transport with no running connection are dropped: its connection is over.
pub fn feed(pool: anytype, input: pool_module.Input, now_ns: u64) Fed {
    switch (input) {
        .none => return .{ .len = 0, .event = null },
        .datagram => |datagram| {
            if (!pool.capacity.quic or pool.links.get(.quic).state != .running) return .{ .len = datagram.octets.len, .event = null };
            const received = pool.quic.receive(datagram.octets, datagram.ecn, datagram.from, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(pool, .quic, reported) };
        },
        .stream => |stream| {
            const octets = stream.octets;
            // Octets for a handle that names no running TCP connection are an earlier connection's.
            if (pool_handle.resolve(pool, stream.connection) != .tcp) return .{ .len = octets.len, .event = null };
            if (pool.links.get(.tcp).state != .running) return .{ .len = octets.len, .event = null };
            const received = pool.tcp[0].receive(octets, now_ns);
            // What the connection read may let what it holds go out.
            if (received.consumed > 0) unblock_sends(pool);
            if (pool.tcp[0].take_alt_svc()) |advert| learn(pool, advert, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(pool, .tcp, reported) };
        },
    }
}

/// What a connection's event means for the pool, and the caller's event it gives, if any.
fn handle(pool: anytype, transport: Transport, reported: event.Event) ?Event {
    switch (reported) {
        .connected => |protocol| return on_connected(pool, transport, protocol),
        .ticket => return .{ .ticket = pool_handle.handle_of(pool, transport) },
        .finished => |finished| return on_finished(pool, transport, finished),
        // The phase reads the connection's own flag.
        .draining => return null,
        .closed => {
            pool.links.getPtr(transport).reported_closed = true;
            return null;
        },
    }
}

/// A connection's handshake completed (the model's Handshake): it takes every waiting exchange and
/// ends the attempt. One the client abandoned owes its close but has not sent it, so datagrams in
/// flight may still complete its handshake, and it carries nothing.
fn on_connected(pool: anytype, transport: Transport, protocol: event.Protocol) ?Event {
    const link = pool.links.getPtr(transport);
    if (link.abandoned) return null;
    // The connection failed, or takes no new exchange, in the call that completed its handshake,
    // so it carries nothing. The attempt that opened it goes on (the model's FailHandshake): its
    // transport stays in `tried`, and the exchanges go to the other transport or end refused.
    const phase = pool.phase(transport);
    if (phase != .handshake) {
        if (phase == .draining) abandon(pool, transport);
        return null;
    }
    const other = choice.other(transport);
    // The client abandons a handshake the moment another connection is open, so none is.
    assert(pool.phase(other) != .open);
    link.won = true;
    end_attempt(pool);
    if (pool.phase(other) == .handshake) abandon(pool, other);
    assign_waiting(pool);
    // The connection that reports `connected` took every waiting exchange (the model's
    // TakeAtHandshake).
    assert(!any_waiting(pool));
    return .{ .connected = .{ .connection = pool_handle.handle_of(pool, transport), .protocol = protocol } };
}

/// A connection reported an exchange's end. One that moves goes to another connection (the model's
/// MoveOn), and any other goes to the caller (its Deliver).
fn on_finished(pool: anytype, transport: Transport, ended: event.Ended) ?Event {
    // A cancelled exchange reports nothing, so every reported one is carried.
    const entry = carried(pool, transport, ended.id).?;
    assert(entry.request == ended.request and entry.response == ended.response);
    if (movable(pool, entry, transport, ended.response_began)) {
        // RFC 9114 §4.1.1: a refused request is treated "as though [it] had never been sent". A
        // request sent again starts its response anew, and counts its content again.
        const closed = entry.response.outcome == .closed;
        // RFC 9112 §9.3.2: a failed connection is one "not explicitly closed by the server in its
        // last complete response", which leaves the connection draining instead.
        const after_failure = closed and pool.phase(transport) == .failed;
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
    return .{ .finished = deliver(entry) };
}

/// Whether a reported exchange moves: the connection that reported it takes no new exchange, the
/// exchange moved fewer than `moves_max` times, refusals and resends together, and the connection
/// refused it unprocessed, or closed before any of its response arrived and its method is
/// idempotent (decision 124).
fn movable(pool: anytype, entry: *const Entry, transport: Transport, response_began: bool) bool {
    // RFC 9110 §9.2.2: "A client SHOULD NOT automatically retry a failed automatic retry."
    if (entry.moves >= constants.moves_max) return false;
    if (pool.phase(transport) == .open) return false;
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

/// Hands each waiting exchange, oldest first, to the open connection (the model's Assign).
pub fn assign_waiting(pool: anytype) void {
    const transport = open_transport(pool) orelse return;
    // Bounded: each pass hands over the oldest waiting exchange, or stops.
    for (0..pool.entries.len) |_| {
        const entry = oldest(pool, .waiting) orelse return;
        // The connection holds no more exchanges than the pool, and an open one takes them.
        const carried_id = switch (transport) {
            .quic => if (pool.capacity.quic) pool.quic.request(entry.request, entry.response) else unreachable,
            .tcp => pool.tcp[0].request(entry.request, entry.response),
        } catch unreachable;
        entry.stage = .carried;
        entry.carrier = transport;
        entry.carried_id = carried_id;
    }
}

/// A shut-down pool drains its open connection (the model's Drain), and ends a handshake once it
/// holds no exchange, which could come back refused (its Abandon). No exchange waits beside an
/// open connection, which takes each as it comes.
fn drain_if_shut(pool: anytype) void {
    if (!pool.shut) return;
    if (open_transport(pool)) |transport| {
        assert(!any_waiting(pool));
        shut_connection(pool, transport);
    }
    if (any_entry(pool)) return;
    for (transports) |transport| {
        if (pool.phase(transport) == .handshake) abandon(pool, transport);
    }
}

fn shut_connection(pool: anytype, transport: Transport) void {
    switch (transport) {
        .quic => if (pool.capacity.quic) pool.quic.shutdown() else unreachable,
        .tcp => pool.tcp[0].shutdown(),
    }
}

/// Ends the handshake of a connection another one beat, or one a shut-down pool has nothing
/// for (the model's Abandon).
fn abandon(pool: anytype, transport: Transport) void {
    const link = pool.links.getPtr(transport);
    // An `open` still owed reached no caller, which opened no socket for it, so the link closes
    // with no `close` of its own. Only a shut-down pool's `plan` meets one: a pass that closed
    // the link's last connection and opened it again reported that connection's `close` first.
    if (link.open_owed) {
        assert(link.state == .opening and pool.shut);
        link.* = .{ .state = .closed, .opens = link.opens, .generation = link.generation, .close_generation = link.close_generation, .address_index = link.address_index, .close_owed = link.close_owed };
        return;
    }
    link.abandoned = true;
    switch (link.state) {
        .opening => {},
        .running => switch (transport) {
            .quic => if (pool.capacity.quic) abandon_quic(pool) else unreachable,
            .tcp => pool.tcp[0].transport_closed(),
        },
        .none, .closed => unreachable,
    }
}

/// Owes the close of an abandoned QUIC connection, and ends it.
fn abandon_quic(pool: anytype) void {
    // RFC 9000 §10.2: the close carries NO_ERROR, since no error ended the connection.
    quic.connection_close.owe(&pool.quic.transport, quic.connection_close.transport(quic.error_code.no_error, null));
    quic_internal.fail(&pool.quic);
}

/// Closes `transport` once its connection is over (the model's Close): an abandoned attempt the
/// caller opened, or a connection that reported `closed` and whose transport may close.
fn close_over(pool: anytype, transport: Transport) void {
    const link = pool.links.getPtr(transport);
    if (link.state == .opening and link.abandoned) return finish_link(link);
    if (link.state != .running or !link.reported_closed) return;
    // The TCP connection says when `send_stream` has written what it owes: the alert of a
    // handshake it refused (RFC 9846 §6.2), the last flight of a handshake whose session the
    // protocol then refused, and h2's GOAWAY (RFC 9113 §6.8). The transport closes after them. One
    // the caller closed, and an abandoned one, have had `transport_closed`, which leaves nothing
    // to write.
    const ready = switch (transport) {
        .quic => if (pool.capacity.quic) pool.quic.closed or pool.quic.should_close() else unreachable,
        .tcp => pool.tcp[0].should_close(),
    };
    if (!ready) return;
    // The connection's `transport_closed` wipes its secrets, and a second call changes nothing.
    switch (transport) {
        .quic => if (pool.capacity.quic) pool.quic.transport_closed() else unreachable,
        .tcp => pool.tcp[0].transport_closed(),
    }
    finish_link(link);
}

/// The transport's connection is over: its transport closes, and the `close` event is owed
/// unless the caller closed it. A connection that took no exchange, and that the client did not
/// abandon, is a failed attempt, and the next one tries the next address.
fn finish_link(link: *Link) void {
    const failed = !link.won and !link.abandoned;
    link.* = .{
        .state = .closed,
        .opens = link.opens,
        .generation = link.generation,
        // Decision 125: the `close` names the connection that is over.
        .close_generation = link.generation,
        .address_index = if (failed) link.address_index + 1 else link.address_index,
        .close_owed = !link.gone,
    };
}

/// An attempt ended before it began: `start_quic` or `start_tcp` failed, or the caller's
/// transport closed first.
pub fn close_unstarted(pool: anytype, transport: Transport) void {
    const link = pool.links.getPtr(transport);
    assert(link.state == .opening);
    link.gone = true;
    finish_link(link);
}

/// Asks the caller to open `transport` (the model's Open).
fn open_link(pool: anytype, transport: Transport, now_ns: u64) void {
    // Decision 124: a pool with no QUIC refused h3 at `init`, so it never offers QUIC.
    assert(transport == .tcp or pool.capacity.quic);
    const link = pool.links.getPtr(transport);
    assert(link.state == .none or link.state == .closed);
    const addresses = pool.values.addresses;
    var to = addresses[link.address_index % addresses.len];
    to.port = port_of(pool, transport, now_ns);
    // Only a connection that is over owes its `close`.
    assert(!link.close_owed or link.state == .closed);
    // The connection this pass closed still owes its `close`, which goes out before the `open`.
    // Decision 125: the slot's next connection has the next generation, and the `close` still owed
    // names the one before it.
    link.* = .{
        .state = .opening,
        .opens = link.opens + 1,
        .generation = link.generation +% 1,
        .close_generation = link.close_generation,
        .address_index = link.address_index,
        .to = to,
        .open_owed = true,
        .close_owed = link.close_owed,
    };
    pool.tried.set(transport, true);
}

/// The port `transport` connects to: a fresh Alt-Svc alternative's for QUIC (RFC 7838 §3), else
/// the HTTPS record's "port", else the origin's (RFC 9460 §7.2).
fn port_of(pool: anytype, transport: Transport, now_ns: u64) u16 {
    if (transport == .quic) {
        if (fresh_alternative(pool, now_ns)) |held| return held.port;
    }
    const https = pool.values.https orelse return pool.values.port;
    return https.port orelse pool.values.port;
}

/// Whether QUIC may carry the exchanges at `now_ns`: the pool offers it, and a fresh Alt-Svc
/// alternative, an HTTPS record or the configuration says to try it.
pub fn quic_allowed(pool: anytype, now_ns: u64) bool {
    if (!pool.offered.quic) return false;
    if (fresh_alternative(pool, now_ns)) |_| return true;
    // RFC 9460 §7.1.2: a client uses the transports of the protocols the record names.
    if (pool.values.https) |https| return https.h3;
    return pool.config.quic_first;
}

/// The Alt-Svc alternative, while it is fresh (RFC 7838 §2.2).
fn fresh_alternative(pool: anytype, now_ns: u64) ?Alternative {
    const held = pool.values.alternative orelse return null;
    return if (now_ns < held.fresh_until_ns) held else null;
}

/// Keeps what a TCP response's Alt-Svc said at `now_ns`, which replaces what the pool knew
/// (RFC 7838 §3.1).
pub fn learn(pool: anytype, advert: alt_svc.Advert, now_ns: u64) void {
    pool.values.alternative = switch (advert) {
        .clear, .none => null,
        .h3 => |h3| .{ .port = h3.port, .fresh_until_ns = now_ns +| h3.max_age_s *| constants.nanoseconds_per_second },
    };
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
    end_attempt(pool);
}

/// The attempt ended: the next one tries QUIC first again.
fn end_attempt(pool: anytype) void {
    pool.tried = .initFill(false);
    pool.fallback = false;
    pool.fallback_at_ns = null;
}

fn view_of(pool: anytype, now_ns: u64) choice.View {
    return .{
        .phases = .init(.{ .quic = pool.phase(.quic), .tcp = pool.phase(.tcp) }),
        .waiting = any_waiting(pool),
        .quic_allowed = quic_allowed(pool, now_ns),
        .tcp_allowed = pool.offered.tcp,
        .tried = pool.tried,
        .fallback = pool.fallback,
    };
}

/// The transport whose connection is open, or null.
fn open_transport(pool: anytype) ?Transport {
    for (transports) |transport| {
        if (pool.phase(transport) == .open) return transport;
    }
    return null;
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

fn carried(pool: anytype, transport: Transport, carried_id: event.Id) ?*Entry {
    for (pool.entries) |*entry| {
        if (entry.stage == .carried and entry.carrier == transport and entry.carried_id == carried_id) return entry;
    }
    return null;
}

fn any_waiting(pool: anytype) bool {
    for (pool.entries) |*entry| {
        if (entry.stage == .waiting) return true;
    }
    return false;
}

fn any_entry(pool: anytype) bool {
    for (pool.entries) |*entry| {
        if (entry.stage != .free) return true;
    }
    return false;
}
