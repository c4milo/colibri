//! The calls a program makes on a channel (decision 100, design §8 step 17d), for a channel of any
//! capacity (decision 124). Each function of `ChannelOf` in `channel.zig` passes its call here, so
//! the type holds no branch of its own, as `server.EndpointOf` does. A channel with no QUIC holds
//! no QUIC connection, and each step on one is out of its code at build time. The module's root
//! does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const constants = @import("../constants.zig");
const event_internal = @import("../event_internal.zig");
const connection_module = @import("../connection/connection.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const channel_module = @import("channel.zig");
const channel_config = @import("channel_config.zig");
const channel_events = @import("channel_events.zig");

const Config = channel_module.Config;
const Values = channel_module.Values;
const ReceiveStorage = channel_module.ReceiveStorage;
const StartError = channel_module.StartError;
const Request = channel_module.Request;
const Response = channel_module.Response;
const RequestError = channel_module.RequestError;
const Id = channel_module.Id;
const Input = channel_module.Input;
const Received = channel_module.Received;
const Sent = channel_module.Sent;
const Event = channel_module.Event;
const Entry = channel_module.Entry;
const Link = channel_module.Link;
const Phase = channel_module.Phase;
const Transport = channel_module.Transport;

pub fn init(channel: anytype, config: *const Config, values: Values, receive_pool: ?ReceiveStorage) StartError!void {
    assert(values.addresses.len > 0);
    // Decision 124: a channel with no QUIC takes no receive pool.
    assert(channel.capacity.quic or receive_pool == null);
    const offered = try channel_config.offer(config, channel.capacity.quic, receive_pool != null);
    if (channel.capacity.quic and offered.quic) try channel_config.build_quic(config, &channel.quic_tls, &channel.quic_config);
    if (offered.tcp) try channel_config.build_tcp(config, &channel.tcp_tls, &channel.tcp_config);
    // QUIC's connections need the pool, so the channel offers QUIC only with one.
    assert(!offered.quic or receive_pool != null);
    channel.offered = offered;
    if (channel.capacity.quic) channel.receive_pool = receive_pool;
    channel.config = config;
    channel.values = values;
    channel.links = .initFill(.{});
    channel.entries = @splat(.{});
    channel.next_id = 1;
    channel.tried = .initFill(false);
    channel.fallback = false;
    channel.fallback_at_ns = null;
    channel.shut = false;
    channel.closed_reported = false;
}

pub fn request(channel: anytype, message: *const Request, response: *Response) RequestError!Id {
    assert(!channel.shut);
    try connection_module.check_request(message);
    const entry = free_entry(channel) orelse return error.Full;
    event_internal.clear(response);
    entry.* = .{ .stage = .waiting, .id = channel.next_id, .request = message, .response = response };
    channel.next_id += 1;
    channel_events.assign_waiting(channel);
    return entry.id;
}

pub fn cancel(channel: anytype, id: Id) void {
    const entry = entry_of(channel, id) orelse return;
    if (entry.stage == .carried) switch (entry.carrier) {
        // Only a channel that holds QUIC opens a QUIC connection to carry an exchange.
        .quic => if (channel.capacity.quic) channel.quic.cancel(entry.carried_id) else unreachable,
        .tcp => channel.tcp.cancel(entry.carried_id),
    };
    entry.* = .{};
}

pub fn receive(channel: anytype, input: Input, now_ns: u64) Received {
    if (report(channel, now_ns)) |owed| return .{ .consumed = 0, .event = owed };
    const fed = channel_events.feed(channel, input, now_ns);
    return .{ .consumed = fed.len, .event = fed.event };
}

pub fn send_datagram(channel: anytype, output: []u8, now_ns: u64) ?Sent {
    if (!channel.capacity.quic or channel.links.get(.quic).state != .running) return null;
    return channel.quic.send(output, now_ns);
}

pub fn send_stream(channel: anytype, output: []u8, now_ns: u64) usize {
    if (channel.links.get(.tcp).state != .running) return 0;
    return channel.tcp.send(output, now_ns);
}

pub fn deadline_ns(channel: anytype) ?u64 {
    var deadline: ?u64 = null;
    if (channel.capacity.quic and channel.links.get(.quic).state == .running) deadline = channel.quic.deadline_ns();
    if (channel.offered.tcp and !channel.fallback and phase(channel, .quic) == .handshake) {
        const fallback_at = channel.fallback_at_ns orelse return deadline;
        deadline = @min(deadline orelse fallback_at, fallback_at);
    }
    return deadline;
}

pub fn on_instant(channel: anytype, now_ns: u64) void {
    if (channel.capacity.quic and channel.links.get(.quic).state == .running) channel.quic.on_instant(now_ns);
}

pub fn start_quic(channel: anytype, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) StartError!void {
    if (!channel.capacity.quic) @compileError("a channel with no QUIC never asks for QUIC, so it has no start_quic");
    const link = channel.links.getPtr(.quic);
    if (link.state != .opening) return;
    assert(!link.open_owed);
    channel.quic_config.server_address = link.to;
    // Decision 120: the grease value, then the source ID, then the original destination ID, then
    // the session's draws, in the order the server's endpoint draws its own.
    var start: quic_connection.Start = undefined;
    // RFC 9114 §7.2.4.1, §8.1: h3's reserved setting and error codes come from this value.
    start.grease = random.int(u64);
    // RFC 9000 §7.2: the client chooses its Source Connection ID, and its first Destination
    // Connection ID is "an unpredictable value".
    random.bytes(&start.source_id);
    random.bytes(&start.original_destination_id);
    channel.quic.init(&channel.quic_config, channel.receive_pool.?, start, random, now_seconds, now_ns, resumption) catch |failure| {
        // The attempt ended before it began: the model's FailHandshake, then Close.
        channel_events.close_unstarted(channel, .quic);
        return failure;
    };
    link.state = .running;
    channel.fallback_at_ns = now_ns + channel.config.fallback_delay_ns;
}

pub fn start_tcp(channel: anytype, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
    const link = channel.links.getPtr(.tcp);
    if (link.state != .opening) return;
    assert(!link.open_owed);
    channel.tcp.init(&channel.tcp_config, random, now_seconds, resumption, .{ .retrying = retrying(channel) }) catch |failure| {
        // The channel asks for TCP only while `versions` allows h11 or h2, so the TLS stack alone
        // refuses a start.
        assert(failure == error.TlsRefused);
        channel_events.close_unstarted(channel, .tcp);
        return failure;
    };
    link.state = .running;
}

pub fn transport_closed(channel: anytype, transport: Transport) void {
    const link = channel.links.getPtr(transport);
    switch (link.state) {
        .none, .closed => {},
        .opening => channel_events.close_unstarted(channel, transport),
        .running => {
            link.gone = true;
            switch (transport) {
                .quic => if (channel.capacity.quic) channel.quic.transport_closed() else unreachable,
                .tcp => channel.tcp.transport_closed(),
            }
        },
    }
}

pub fn take_ticket(channel: anytype, transport: Transport) ?tls.Ticket {
    if (channel.links.get(transport).state != .running) return null;
    return switch (transport) {
        .quic => if (channel.capacity.quic) channel.quic.take_ticket() else unreachable,
        .tcp => channel.tcp.take_ticket(),
    };
}

pub fn phase(channel: anytype, transport: Transport) Phase {
    const link = channel.links.get(transport);
    return switch (link.state) {
        .none => .none,
        .closed => .closed,
        .opening => if (link.abandoned) .failed else .handshake,
        .running => running_phase(channel, transport, link),
    };
}

fn running_phase(channel: anytype, transport: Transport, link: Link) Phase {
    const failed = switch (transport) {
        .quic => if (channel.capacity.quic) channel.quic.failed else unreachable,
        .tcp => channel.tcp.failed,
    };
    const draining = switch (transport) {
        .quic => if (channel.capacity.quic) channel.quic.draining else unreachable,
        .tcp => channel.tcp.draining,
    };
    if (failed) return .failed;
    if (draining) return .draining;
    return if (link.won) .open else .handshake;
}

/// Whether an exchange that waits for the connection starting now went out on a connection that
/// failed. The connection then writes the first request alone (RFC 9112 §9.3.2).
fn retrying(channel: anytype) bool {
    for (&channel.entries) |*entry| {
        if (entry.stage == .waiting and entry.after_failure) return true;
    }
    return false;
}

/// The first event the channel owes, after it has read what its connections owe and chosen what
/// to open, or null.
fn report(channel: anytype, now_ns: u64) ?Event {
    check_fallback(channel, now_ns);
    // Bounded: each pass reads a connection's event, or plans and stops.
    for (0..constants.channel_events_per_poll_max + 1) |_| {
        channel_events.plan(channel, now_ns);
        if (channel_events.owed(channel)) |owed| return owed;
        const read = channel_events.poll(channel, now_ns) orelse return null;
        if (read.event) |reported| return reported;
    }
    unreachable;
}

/// The fallback delay passed while QUIC's handshake runs, and TCP may open beside it.
fn check_fallback(channel: anytype, now_ns: u64) void {
    const fallback_at = channel.fallback_at_ns orelse return;
    if (channel.fallback or phase(channel, .quic) != .handshake) return;
    if (now_ns >= fallback_at) channel.fallback = true;
}

fn free_entry(channel: anytype) ?*Entry {
    for (&channel.entries) |*entry| {
        if (entry.stage == .free) return entry;
    }
    return null;
}

fn entry_of(channel: anytype, id: Id) ?*Entry {
    for (&channel.entries) |*entry| {
        if (entry.stage != .free and entry.id == id) return entry;
    }
    return null;
}
