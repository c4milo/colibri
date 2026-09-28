//! The steps the channel takes on its own and on its connections' events (decision 100, design §8
//! step 17d), each named after the step of spec/tla/client_exchanges it is (decision 105): hand
//! the waiting exchanges to the open connection, drain once shut down, close a transport whose
//! connection is over, open a transport or give up, and read what each connection reports.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const channel_module = @import("channel.zig");
const choice = @import("channel_choice.zig");

const Channel = channel_module.Channel;
const Transport = channel_module.Transport;
const Event = channel_module.Event;
const Entry = channel_module.Entry;
const Link = channel_module.Link;
const Stage = channel_module.Stage;

const transports = [_]Transport{ .quic, .tcp };

/// Moves the channel on at `now_ns`, as the model's Drain, Close, Open and GiveUp do. Its Assign
/// happens where an exchange starts waiting or a connection opens.
pub fn plan(channel: *Channel, now_ns: u64) void {
    drain_if_shut(channel);
    for (transports) |transport| close_over(channel, transport);
    const view = view_of(channel, now_ns);
    if (choice.next_open(&view)) |transport| {
        open_link(channel, transport, now_ns);
    } else if (choice.give_up(&view)) {
        give_up(channel);
    }
}

/// The first event the channel owes of its own, or null: a transport to open or close, an exchange
/// it ended, and its close.
pub fn owed(channel: *Channel) ?Event {
    for (transports) |transport| {
        const link = channel.links.getPtr(transport);
        if (link.open_owed) {
            link.open_owed = false;
            return .{ .open = .{ .transport = transport, .to = link.to } };
        }
        if (link.close_owed) {
            link.close_owed = false;
            return .{ .close = transport };
        }
    }
    if (oldest(channel, .ended)) |entry| {
        const reported: event.Finished = .{ .id = entry.id, .exchange = entry.exchange };
        entry.* = .{};
        return .{ .finished = reported };
    }
    if (!channel.shut or channel.closed_reported) return null;
    if (!channel.phase(.quic).idle() or !channel.phase(.tcp).idle()) return null;
    // An exchange waiting with no connection opens one or ends, and a finished one was reported
    // above.
    assert(!any_entry(channel));
    channel.closed_reported = true;
    return .closed;
}

/// One event a connection reported: the caller's, or null when the channel took it itself.
pub const Polled = struct {
    event: ?Event,
};

/// Reads one event a connection owes and handles it, or null when neither owes one.
pub fn poll(channel: *Channel, now_ns: u64) ?Polled {
    var none: [0]u8 = .{};
    for (transports) |transport| {
        if (channel.links.get(transport).state != .running) continue;
        const received = switch (transport) {
            .quic => channel.quic.receive(&none, .not_ect, .{}, now_ns),
            .tcp => channel.tcp.receive(&none, now_ns),
        };
        assert(received.consumed == 0);
        const reported = received.event orelse continue;
        return .{ .event = handle(channel, transport, reported) };
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
pub fn feed(channel: *Channel, input: channel_module.Input, now_ns: u64) Fed {
    switch (input) {
        .none => return .{ .len = 0, .event = null },
        .datagram => |datagram| {
            if (channel.links.get(.quic).state != .running) return .{ .len = datagram.octets.len, .event = null };
            const received = channel.quic.receive(datagram.octets, datagram.ecn, datagram.from, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(channel, .quic, reported) };
        },
        .stream => |octets| {
            if (channel.links.get(.tcp).state != .running) return .{ .len = octets.len, .event = null };
            const received = channel.tcp.receive(octets, now_ns);
            if (channel.tcp.take_alt_svc()) |advert| channel.learn(advert, now_ns);
            const reported = received.event orelse return .{ .len = received.consumed, .event = null };
            return .{ .len = received.consumed, .event = handle(channel, .tcp, reported) };
        },
    }
}

/// What a connection's event means for the channel, and the caller's event it gives, if any.
fn handle(channel: *Channel, transport: Transport, reported: event.Event) ?Event {
    switch (reported) {
        .connected => |protocol| return on_connected(channel, transport, protocol),
        .ticket => return .{ .ticket = transport },
        .finished => |finished| return on_finished(channel, transport, finished),
        // The phase reads the connection's own flag.
        .draining => return null,
        .closed => {
            channel.links.getPtr(transport).reported_closed = true;
            return null;
        },
    }
}

/// A connection's handshake completed (the model's Handshake): it takes the waiting exchanges and
/// ends the attempt. One the client abandoned owes its close but has not sent it, so datagrams in
/// flight may still complete its handshake, and it carries nothing.
fn on_connected(channel: *Channel, transport: Transport, protocol: event.Protocol) ?Event {
    const link = channel.links.getPtr(transport);
    link.connected = true;
    if (link.abandoned) return null;
    const other = choice.other(transport);
    // The client abandons a handshake the moment another connection is open, so none is.
    assert(channel.phase(other) != .open);
    link.won = true;
    end_attempt(channel);
    if (channel.phase(other) == .handshake) abandon(channel, other);
    assign_waiting(channel);
    return .{ .connected = protocol };
}

/// A connection reported an exchange's end. One it refused unprocessed while taking no new
/// exchange moves to another connection (the model's MoveOn), and any other goes to the caller
/// (its Deliver).
fn on_finished(channel: *Channel, transport: Transport, finished: event.Finished) ?Event {
    // A cancelled exchange reports nothing, so every reported one is carried.
    const entry = carried(channel, transport, finished.id).?;
    assert(entry.exchange == finished.exchange);
    if (movable(channel, entry, transport)) {
        // RFC 9114 §4.1.1: a refused request is treated "as though [it] had never been sent".
        entry.exchange.clear();
        entry.* = .{ .stage = .waiting, .id = entry.id, .exchange = entry.exchange, .moves = entry.moves + 1 };
        assign_waiting(channel);
        return null;
    }
    const reported: event.Finished = .{ .id = entry.id, .exchange = entry.exchange };
    entry.* = .{};
    return .{ .finished = reported };
}

/// Whether a reported exchange moves: its connection refused it unprocessed and takes no new
/// exchange, and it has moved fewer than `moves_max` times. RFC 9113 §8.7: a client "MAY
/// automatically retry" a request no server processed.
fn movable(channel: *const Channel, entry: *const Entry, transport: Transport) bool {
    if (entry.exchange.outcome != .refused or entry.moves >= constants.moves_max) return false;
    return channel.phase(transport) != .open;
}

/// Hands each waiting exchange, oldest first, to the open connection (the model's Assign).
pub fn assign_waiting(channel: *Channel) void {
    const transport = open_transport(channel) orelse return;
    // Bounded: each pass hands over the oldest waiting exchange, or stops.
    for (0..constants.exchanges_max) |_| {
        const entry = oldest(channel, .waiting) orelse return;
        // The connection holds no more exchanges than the channel, and an open one takes them.
        const carried_id = switch (transport) {
            .quic => channel.quic.request(entry.exchange),
            .tcp => channel.tcp.request(entry.exchange),
        } catch unreachable;
        entry.stage = .carried;
        entry.carrier = transport;
        entry.carried_id = carried_id;
    }
}

/// A shut-down channel drains its open connection (the model's Drain), and ends a handshake once it
/// holds no exchange, which could come back refused (its Abandon). No exchange waits beside an
/// open connection, which takes each as it comes.
fn drain_if_shut(channel: *Channel) void {
    if (!channel.shut) return;
    if (open_transport(channel)) |transport| {
        assert(!any_waiting(channel));
        shut_connection(channel, transport);
    }
    if (any_entry(channel)) return;
    for (transports) |transport| {
        if (channel.phase(transport) == .handshake) abandon(channel, transport);
    }
}

fn shut_connection(channel: *Channel, transport: Transport) void {
    switch (transport) {
        .quic => channel.quic.shutdown(),
        .tcp => channel.tcp.shutdown(),
    }
}

/// Ends the handshake of a connection another one beat, or one a shut-down channel has nothing
/// for (the model's Abandon).
fn abandon(channel: *Channel, transport: Transport) void {
    const link = channel.links.getPtr(transport);
    link.abandoned = true;
    // The channel reports what it owes before it reads a connection's event, so the caller heard
    // of every transport the channel opened.
    assert(!link.open_owed);
    switch (link.state) {
        .opening => {},
        .running => switch (transport) {
            .quic => {
                // RFC 9000 §10.2: the close carries NO_ERROR, since no error ended the connection.
                quic.connection_close.owe(&channel.quic.transport, quic.connection_close.transport(quic.error_code.no_error, null));
                channel.quic.fail();
            },
            .tcp => channel.tcp.transport_closed(),
        },
        .none, .closed => unreachable,
    }
}

/// Closes `transport` once its connection is over (the model's Close): an abandoned attempt the
/// caller opened, or a connection that reported `closed` and whose transport may close.
fn close_over(channel: *Channel, transport: Transport) void {
    const link = channel.links.getPtr(transport);
    if (link.state == .opening and link.abandoned) return finish_link(link);
    if (link.state != .running or !link.reported_closed) return;
    // A transport the caller closed has its connection closed too.
    const ready = switch (transport) {
        .quic => channel.quic.closed or channel.quic.should_close(),
        .tcp => channel.tcp.phase == .closed or channel.tcp.should_close(),
    };
    if (!ready) return;
    // The connection's `transport_closed` wipes its secrets, and a second call changes nothing.
    switch (transport) {
        .quic => channel.quic.transport_closed(),
        .tcp => channel.tcp.transport_closed(),
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
pub fn close_unstarted(channel: *Channel, transport: Transport) void {
    const link = channel.links.getPtr(transport);
    assert(link.state == .opening);
    link.gone = true;
    finish_link(link);
}

/// Asks the caller to open `transport` (the model's Open).
fn open_link(channel: *Channel, transport: Transport, now_ns: u64) void {
    const link = channel.links.getPtr(transport);
    assert(link.state == .none or link.state == .closed);
    const addresses = channel.values.addresses;
    var to = addresses[link.address_index % addresses.len];
    to.port = port_of(channel, transport, now_ns);
    link.* = .{ .state = .opening, .opens = link.opens + 1, .address_index = link.address_index, .to = to, .open_owed = true };
    channel.tried.set(transport, true);
}

/// The port `transport` connects to: a fresh Alt-Svc alternative's for QUIC (RFC 7838 §3), else
/// the HTTPS record's "port", else the origin's (RFC 9460 §7.2).
fn port_of(channel: *const Channel, transport: Transport, now_ns: u64) u16 {
    if (transport == .quic) {
        if (channel.fresh_alternative(now_ns)) |held| return held.port;
    }
    const https = channel.values.https orelse return channel.values.port;
    return https.port orelse channel.values.port;
}

/// Ends each waiting exchange refused, since no connection is left to take it (the model's
/// GiveUp). RFC 9113 §8.7: no server processed it, so the caller may make it again.
fn give_up(channel: *Channel) void {
    for (&channel.entries) |*entry| {
        if (entry.stage != .waiting) continue;
        entry.exchange.outcome = .refused;
        entry.stage = .ended;
    }
    end_attempt(channel);
}

/// The attempt ended: the next one tries QUIC first again.
fn end_attempt(channel: *Channel) void {
    channel.tried = .initFill(false);
    channel.fallback = false;
    channel.fallback_at_ns = null;
}

fn view_of(channel: *const Channel, now_ns: u64) choice.View {
    return .{
        .phases = .init(.{ .quic = channel.phase(.quic), .tcp = channel.phase(.tcp) }),
        .waiting = any_waiting(channel),
        .quic_allowed = channel.quic_allowed(now_ns),
        .tried = channel.tried,
        .fallback = channel.fallback,
    };
}

/// The transport whose connection is open, or null.
fn open_transport(channel: *const Channel) ?Transport {
    for (transports) |transport| {
        if (channel.phase(transport) == .open) return transport;
    }
    return null;
}

/// The entry at `stage` with the lowest id, or null.
fn oldest(channel: *Channel, stage: Stage) ?*Entry {
    var found: ?*Entry = null;
    for (&channel.entries) |*entry| {
        if (entry.stage != stage) continue;
        if (found == null or entry.id < found.?.id) found = entry;
    }
    return found;
}

fn carried(channel: *Channel, transport: Transport, carried_id: event.Id) ?*Entry {
    for (&channel.entries) |*entry| {
        if (entry.stage == .carried and entry.carrier == transport and entry.carried_id == carried_id) return entry;
    }
    return null;
}

fn any_waiting(channel: *const Channel) bool {
    for (&channel.entries) |*entry| {
        if (entry.stage == .waiting) return true;
    }
    return false;
}

fn any_entry(channel: *const Channel) bool {
    for (&channel.entries) |*entry| {
        if (entry.stage != .free) return true;
    }
    return false;
}
