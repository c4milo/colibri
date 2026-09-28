//! The steps the origin takes on its own and on its connections' events (decision 100, design §8
//! step 17d), each named after the step of spec/tla/client_exchanges it is (decision 105): hand
//! the waiting exchanges to the open connection, drain once shut down, close a transport whose
//! connection is over, open a transport or give up, and read what each connection reports.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("constants.zig");
const event = @import("event.zig");
const origin_module = @import("origin.zig");
const choice = @import("origin_choice.zig");

const Origin = origin_module.Origin;
const Transport = origin_module.Transport;
const Event = origin_module.Event;
const Entry = origin_module.Entry;
const Link = origin_module.Link;
const Stage = origin_module.Stage;

const transports = [_]Transport{ .quic, .tcp };

/// Moves the origin on at `now_ns`, as the model's Drain, Close, Open and GiveUp do. Its Assign
/// happens where an exchange starts waiting or a connection opens.
pub fn plan(origin: *Origin, now_ns: u64) void {
    drain_if_shut(origin);
    for (transports) |transport| close_over(origin, transport);
    const view = view_of(origin, now_ns);
    if (choice.next_open(&view)) |transport| {
        open_link(origin, transport, now_ns);
    } else if (choice.give_up(&view)) {
        give_up(origin);
    }
}

/// The first event the origin owes of its own, or null: a transport to open or close, an exchange
/// it ended, and its close.
pub fn owed(origin: *Origin) ?Event {
    for (transports) |transport| {
        const link = origin.links.getPtr(transport);
        if (link.open_owed) {
            link.open_owed = false;
            return .{ .open = .{ .transport = transport, .to = link.to } };
        }
        if (link.close_owed) {
            link.close_owed = false;
            return .{ .close = transport };
        }
    }
    if (oldest(origin, .ended)) |entry| {
        const reported: event.Finished = .{ .id = entry.id, .exchange = entry.exchange };
        entry.* = .{};
        return .{ .finished = reported };
    }
    if (!origin.shut or origin.closed_reported) return null;
    if (!origin.phase(.quic).idle() or !origin.phase(.tcp).idle()) return null;
    // An exchange waiting with no connection opens one or ends, and a finished one was reported
    // above.
    assert(!any_entry(origin));
    origin.closed_reported = true;
    return .closed;
}

/// One event a connection reported: the caller's, or null when the origin took it itself.
pub const Polled = struct {
    event: ?Event,
};

/// Reads one event a connection owes and handles it, or null when neither owes one.
pub fn poll(origin: *Origin, now_ns: u64) ?Polled {
    var none: [0]u8 = .{};
    for (transports) |transport| {
        if (origin.links.get(transport).state != .running) continue;
        const received = switch (transport) {
            .quic => origin.quic.receive(&none, .not_ect, .{}, now_ns),
            .tcp => origin.tcp.receive(&none, now_ns),
        };
        assert(received.consumed == 0);
        const reported = received.event orelse continue;
        return .{ .event = handle(origin, transport, reported) };
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
pub fn feed(origin: *Origin, input: origin_module.Input, now_ns: u64) Fed {
    switch (input) {
        .none => return .{ .len = 0, .event = null },
        .datagram => |datagram| {
            if (origin.links.get(.quic).state != .running) return .{ .len = datagram.octets.len, .event = null };
            const received = origin.quic.receive(datagram.octets, datagram.ecn, datagram.from, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(origin, .quic, reported) };
        },
        .stream => |octets| {
            if (origin.links.get(.tcp).state != .running) return .{ .len = octets.len, .event = null };
            const received = origin.tcp.receive(octets, now_ns);
            if (origin.tcp.take_alt_svc()) |advert| origin.learn(advert, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(origin, .tcp, reported) };
        },
    }
}

/// What a connection's event means for the origin, and the caller's event it gives, if any.
fn handle(origin: *Origin, transport: Transport, reported: event.Event) ?Event {
    switch (reported) {
        .connected => |protocol| return on_connected(origin, transport, protocol),
        .ticket => return .{ .ticket = transport },
        .finished => |finished| return on_finished(origin, transport, finished),
        // The phase reads the connection's own flag.
        .draining => return null,
        .closed => {
            origin.links.getPtr(transport).reported_closed = true;
            return null;
        },
    }
}

/// A connection's handshake completed (the model's Handshake). The first one open takes the
/// waiting exchanges and ends the attempt, and one that completes after it drains at once.
fn on_connected(origin: *Origin, transport: Transport, protocol: event.Protocol) ?Event {
    const link = origin.links.getPtr(transport);
    link.connected = true;
    const other = choice.other(transport);
    if (origin.phase(other) == .open) {
        shut_connection(origin, transport);
        return null;
    }
    link.won = true;
    end_attempt(origin);
    if (origin.phase(other) == .handshake) abandon(origin, other);
    assign_waiting(origin);
    return .{ .connected = protocol };
}

/// A connection reported an exchange's end. One it refused unprocessed while taking no new
/// exchange moves to another connection (the model's MoveOn), and any other goes to the caller
/// (its Deliver).
fn on_finished(origin: *Origin, transport: Transport, finished: event.Finished) ?Event {
    // A cancelled exchange reports nothing, so every reported one is carried.
    const entry = carried(origin, transport, finished.id).?;
    assert(entry.exchange == finished.exchange);
    if (movable(origin, entry, transport)) {
        // RFC 9114 §4.1.1: a refused request is treated "as though [it] had never been sent".
        entry.exchange.clear();
        entry.* = .{ .stage = .waiting, .id = entry.id, .exchange = entry.exchange, .moves = entry.moves + 1 };
        assign_waiting(origin);
        return null;
    }
    const reported: event.Finished = .{ .id = entry.id, .exchange = entry.exchange };
    entry.* = .{};
    return .{ .finished = reported };
}

/// Whether a reported exchange moves: its connection refused it unprocessed and takes no new
/// exchange, and it has moved fewer than `moves_max` times. RFC 9113 §8.7: a client "MAY
/// automatically retry" a request no server processed.
fn movable(origin: *const Origin, entry: *const Entry, transport: Transport) bool {
    if (entry.exchange.outcome != .refused or entry.moves >= constants.moves_max) return false;
    return origin.phase(transport) != .open;
}

/// Hands each waiting exchange, oldest first, to the open connection (the model's Assign).
pub fn assign_waiting(origin: *Origin) void {
    const transport = open_transport(origin) orelse return;
    // Bounded: each pass hands over the oldest waiting exchange, or stops.
    for (0..constants.exchanges_max) |_| {
        const entry = oldest(origin, .waiting) orelse return;
        // The connection holds no more exchanges than the origin, and an open one takes them.
        const carried_id = switch (transport) {
            .quic => origin.quic.request(entry.exchange),
            .tcp => origin.tcp.request(entry.exchange),
        } catch unreachable;
        entry.stage = .carried;
        entry.carrier = transport;
        entry.carried_id = carried_id;
    }
}

/// A shut-down origin drains its open connection (the model's Drain), and ends a handshake once it
/// holds no exchange, which could come back refused (its Abandon). No exchange waits beside an
/// open connection, which takes each as it comes.
fn drain_if_shut(origin: *Origin) void {
    if (!origin.shut) return;
    if (open_transport(origin)) |transport| {
        assert(!any_waiting(origin));
        shut_connection(origin, transport);
    }
    if (any_entry(origin)) return;
    for (transports) |transport| {
        if (origin.phase(transport) == .handshake) abandon(origin, transport);
    }
}

fn shut_connection(origin: *Origin, transport: Transport) void {
    switch (transport) {
        .quic => origin.quic.shutdown(),
        .tcp => origin.tcp.shutdown(),
    }
}

/// Ends the handshake of a connection another one beat, or one a shut-down origin has nothing
/// for (the model's Abandon).
fn abandon(origin: *Origin, transport: Transport) void {
    const link = origin.links.getPtr(transport);
    link.abandoned = true;
    // The origin reports what it owes before it reads a connection's event, so the caller heard
    // of every transport the origin opened.
    assert(!link.open_owed);
    switch (link.state) {
        .opening => {},
        .running => switch (transport) {
            .quic => {
                // RFC 9000 §10.2: the close carries NO_ERROR, since no error ended the connection.
                quic.connection_close.owe(&origin.quic.transport, quic.connection_close.transport(quic.error_code.no_error, null));
                origin.quic.fail();
            },
            .tcp => origin.tcp.transport_closed(),
        },
        .none, .closed => unreachable,
    }
}

/// Closes `transport` once its connection is over (the model's Close): an abandoned attempt the
/// caller opened, or a connection that reported `closed` and whose transport may close.
fn close_over(origin: *Origin, transport: Transport) void {
    const link = origin.links.getPtr(transport);
    if (link.state == .opening and link.abandoned) return finish_link(link);
    if (link.state != .running or !link.reported_closed) return;
    // A transport the caller closed has its connection closed too.
    const ready = switch (transport) {
        .quic => origin.quic.closed or origin.quic.should_close(),
        .tcp => origin.tcp.phase == .closed or origin.tcp.should_close(),
    };
    if (!ready) return;
    // The connection's `transport_closed` wipes its secrets, and a second call changes nothing.
    switch (transport) {
        .quic => origin.quic.transport_closed(),
        .tcp => origin.tcp.transport_closed(),
    }
    finish_link(link);
}

/// The transport's connection is over: its transport closes, and the `close` event is owed
/// unless the caller closed it. An attempt whose handshake failed tries the next address.
fn finish_link(link: *Link) void {
    const failed = !link.connected and !link.abandoned;
    link.* = .{
        .state = .closed,
        .opens = link.opens,
        .address_index = if (failed) link.address_index + 1 else link.address_index,
        .close_owed = !link.gone,
    };
}

/// An attempt ended before it began: `start_quic` or `start_tcp` failed, or the caller's
/// transport closed first.
pub fn close_unstarted(origin: *Origin, transport: Transport) void {
    const link = origin.links.getPtr(transport);
    assert(link.state == .opening);
    link.gone = true;
    finish_link(link);
}

/// Asks the caller to open `transport` (the model's Open).
fn open_link(origin: *Origin, transport: Transport, now_ns: u64) void {
    const link = origin.links.getPtr(transport);
    assert(link.state == .none or link.state == .closed);
    const addresses = origin.values.addresses;
    var to = addresses[link.address_index % addresses.len];
    to.port = port_of(origin, transport, now_ns);
    link.* = .{ .state = .opening, .opens = link.opens + 1, .address_index = link.address_index, .to = to, .open_owed = true };
    origin.tried.set(transport, true);
}

/// The port `transport` connects to: a fresh Alt-Svc alternative's for QUIC (RFC 7838 §3), else
/// the HTTPS record's "port", else the origin's (RFC 9460 §7.2).
fn port_of(origin: *const Origin, transport: Transport, now_ns: u64) u16 {
    if (transport == .quic) {
        if (origin.fresh_alternative(now_ns)) |held| return held.port;
    }
    const https = origin.values.https orelse return origin.values.port;
    return https.port orelse origin.values.port;
}

/// Ends each waiting exchange refused, since no connection is left to take it (the model's
/// GiveUp). RFC 9113 §8.7: no server processed it, so the caller may make it again.
fn give_up(origin: *Origin) void {
    for (&origin.entries) |*entry| {
        if (entry.stage != .waiting) continue;
        entry.exchange.outcome = .refused;
        entry.stage = .ended;
    }
    end_attempt(origin);
}

/// The attempt ended: the next one tries QUIC first again.
fn end_attempt(origin: *Origin) void {
    origin.tried = .initFill(false);
    origin.fallback = false;
    origin.fallback_at_ns = null;
}

fn view_of(origin: *const Origin, now_ns: u64) choice.View {
    return .{
        .phases = .init(.{ .quic = origin.phase(.quic), .tcp = origin.phase(.tcp) }),
        .waiting = any_waiting(origin),
        .quic_allowed = origin.quic_allowed(now_ns),
        .tried = origin.tried,
        .fallback = origin.fallback,
    };
}

/// The transport whose connection is open, or null.
fn open_transport(origin: *const Origin) ?Transport {
    for (transports) |transport| {
        if (origin.phase(transport) == .open) return transport;
    }
    return null;
}

/// The entry at `stage` with the lowest id, or null.
fn oldest(origin: *Origin, stage: Stage) ?*Entry {
    var found: ?*Entry = null;
    for (&origin.entries) |*entry| {
        if (entry.stage != stage) continue;
        if (found == null or entry.id < found.?.id) found = entry;
    }
    return found;
}

fn carried(origin: *Origin, transport: Transport, carried_id: event.Id) ?*Entry {
    for (&origin.entries) |*entry| {
        if (entry.stage == .carried and entry.carrier == transport and entry.carried_id == carried_id) return entry;
    }
    return null;
}

fn any_waiting(origin: *const Origin) bool {
    for (&origin.entries) |*entry| {
        if (entry.stage == .waiting) return true;
    }
    return false;
}

fn any_entry(origin: *const Origin) bool {
    for (&origin.entries) |*entry| {
        if (entry.stage != .free) return true;
    }
    return false;
}
