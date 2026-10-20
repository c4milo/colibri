//! The calls a program makes on a pool (decision 100, design §8 step 17d), for a pool of any
//! capacity (decision 124). Each function of `PoolOf` in `pool.zig` passes its call here, so
//! the type holds no branch of its own, as `server.EndpointOf` does. A pool with no QUIC holds
//! no QUIC connection, and each step on one is out of its code at build time. The module's root
//! does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const constants = @import("../constants.zig");
const event_internal = @import("../event_internal.zig");
const connection_module = @import("../connection/connection.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const pool_module = @import("pool.zig");
const pool_config = @import("pool_config.zig");
const pool_events = @import("pool_events.zig");

const Config = pool_module.Config;
const Values = pool_module.Values;
const ReceiveStorage = pool_module.ReceiveStorage;
const StartError = pool_module.StartError;
const Request = pool_module.Request;
const Response = pool_module.Response;
const RequestError = pool_module.RequestError;
const Id = pool_module.Id;
const Input = pool_module.Input;
const Received = pool_module.Received;
const Sent = pool_module.Sent;
const Event = pool_module.Event;
const Entry = pool_module.Entry;
const Link = pool_module.Link;
const Phase = pool_module.Phase;
const Transport = pool_module.Transport;

pub fn init(pool: anytype, config: *const Config, values: Values, receive_pool: ?ReceiveStorage) StartError!void {
    assert(values.addresses.len > 0);
    // Decision 124: a pool with no QUIC takes no receive pool.
    assert(pool.capacity.quic or receive_pool == null);
    const offered = try pool_config.offer(config, pool.capacity.quic, receive_pool != null);
    if (pool.capacity.quic and offered.quic) try pool_config.build_quic(config, &pool.quic_tls, &pool.quic_config);
    if (offered.tcp) try pool_config.build_tcp(config, &pool.tcp_tls, &pool.tcp_config);
    // QUIC's connections need the pool, so the pool offers QUIC only with one.
    assert(!offered.quic or receive_pool != null);
    pool.offered = offered;
    if (pool.capacity.quic) pool.receive_pool = receive_pool;
    pool.config = config;
    pool.values = values;
    pool.links = .initFill(.{});
    pool.entries = @splat(.{});
    pool.next_id = 1;
    pool.tried = .initFill(false);
    pool.fallback = false;
    pool.fallback_at_ns = null;
    pool.shut = false;
    pool.closed_reported = false;
}

pub fn request(pool: anytype, message: *const Request, response: *Response) RequestError!Id {
    assert(!pool.shut);
    try connection_module.check_request(message);
    const entry = free_entry(pool) orelse return error.Full;
    event_internal.clear(response);
    entry.* = .{ .stage = .waiting, .id = pool.next_id, .request = message, .response = response };
    pool.next_id += 1;
    pool_events.assign_waiting(pool);
    return entry.id;
}

pub fn cancel(pool: anytype, id: Id) void {
    const entry = entry_of(pool, id) orelse return;
    if (entry.stage == .carried) switch (entry.carrier) {
        // Only a pool that holds QUIC opens a QUIC connection to carry an exchange.
        .quic => if (pool.capacity.quic) pool.quic.cancel(entry.carried_id) else unreachable,
        .tcp => pool.tcp.cancel(entry.carried_id),
    };
    entry.* = .{};
}

pub fn receive(pool: anytype, input: Input, now_ns: u64) Received {
    if (report(pool, now_ns)) |owed| return .{ .consumed = 0, .event = owed };
    const fed = pool_events.feed(pool, input, now_ns);
    return .{ .consumed = fed.len, .event = fed.event };
}

pub fn send_datagram(pool: anytype, output: []u8, now_ns: u64) ?Sent {
    if (!pool.capacity.quic or pool.links.get(.quic).state != .running) return null;
    return pool.quic.send(output, now_ns);
}

pub fn send_stream(pool: anytype, output: []u8, now_ns: u64) usize {
    if (pool.links.get(.tcp).state != .running) return 0;
    return pool.tcp.send(output, now_ns);
}

pub fn deadline_ns(pool: anytype) ?u64 {
    var deadline: ?u64 = null;
    if (pool.capacity.quic and pool.links.get(.quic).state == .running) deadline = pool.quic.deadline_ns();
    if (pool.offered.tcp and !pool.fallback and phase(pool, .quic) == .handshake) {
        const fallback_at = pool.fallback_at_ns orelse return deadline;
        deadline = @min(deadline orelse fallback_at, fallback_at);
    }
    return deadline;
}

pub fn on_instant(pool: anytype, now_ns: u64) void {
    if (pool.capacity.quic and pool.links.get(.quic).state == .running) pool.quic.on_instant(now_ns);
}

pub fn start_quic(pool: anytype, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) StartError!void {
    if (!pool.capacity.quic) @compileError("a pool with no QUIC never asks for QUIC, so it has no start_quic");
    const link = pool.links.getPtr(.quic);
    if (link.state != .opening) return;
    assert(!link.open_owed);
    pool.quic_config.server_address = link.to;
    // Decision 120: the grease value, then the source ID, then the original destination ID, then
    // the session's draws, in the order the server's endpoint draws its own.
    var start: quic_connection.Start = undefined;
    // RFC 9114 §7.2.4.1, §8.1: h3's reserved setting and error codes come from this value.
    start.grease = random.int(u64);
    // RFC 9000 §7.2: the client chooses its Source Connection ID, and its first Destination
    // Connection ID is "an unpredictable value".
    random.bytes(&start.source_id);
    random.bytes(&start.original_destination_id);
    pool.quic.init(&pool.quic_config, pool.receive_pool.?, start, random, now_seconds, now_ns, resumption) catch |failure| {
        // The attempt ended before it began: the model's FailHandshake, then Close.
        pool_events.close_unstarted(pool, .quic);
        return failure;
    };
    link.state = .running;
    pool.fallback_at_ns = now_ns + pool.config.fallback_delay_ns;
}

pub fn start_tcp(pool: anytype, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
    const link = pool.links.getPtr(.tcp);
    if (link.state != .opening) return;
    assert(!link.open_owed);
    pool.tcp.init(&pool.tcp_config, random, now_seconds, resumption, .{ .retrying = retrying(pool) }) catch |failure| {
        // The pool asks for TCP only while `versions` allows h11 or h2, so the TLS stack alone
        // refuses a start.
        assert(failure == error.TlsRefused);
        pool_events.close_unstarted(pool, .tcp);
        return failure;
    };
    link.state = .running;
}

pub fn transport_closed(pool: anytype, transport: Transport) void {
    const link = pool.links.getPtr(transport);
    switch (link.state) {
        .none, .closed => {},
        .opening => pool_events.close_unstarted(pool, transport),
        .running => {
            link.gone = true;
            switch (transport) {
                .quic => if (pool.capacity.quic) pool.quic.transport_closed() else unreachable,
                .tcp => pool.tcp.transport_closed(),
            }
        },
    }
}

pub fn take_ticket(pool: anytype, transport: Transport) ?tls.Ticket {
    if (pool.links.get(transport).state != .running) return null;
    return switch (transport) {
        .quic => if (pool.capacity.quic) pool.quic.take_ticket() else unreachable,
        .tcp => pool.tcp.take_ticket(),
    };
}

pub fn phase(pool: anytype, transport: Transport) Phase {
    const link = pool.links.get(transport);
    return switch (link.state) {
        .none => .none,
        .closed => .closed,
        .opening => if (link.abandoned) .failed else .handshake,
        .running => running_phase(pool, transport, link),
    };
}

fn running_phase(pool: anytype, transport: Transport, link: Link) Phase {
    const failed = switch (transport) {
        .quic => if (pool.capacity.quic) pool.quic.failed else unreachable,
        .tcp => pool.tcp.failed,
    };
    const draining = switch (transport) {
        .quic => if (pool.capacity.quic) pool.quic.draining else unreachable,
        .tcp => pool.tcp.draining,
    };
    if (failed) return .failed;
    if (draining) return .draining;
    return if (link.won) .open else .handshake;
}

/// Whether an exchange that waits for the connection starting now went out on a connection that
/// failed. The connection then writes the first request alone (RFC 9112 §9.3.2).
fn retrying(pool: anytype) bool {
    for (&pool.entries) |*entry| {
        if (entry.stage == .waiting and entry.after_failure) return true;
    }
    return false;
}

/// The first event the pool owes, after it has read what its connections owe and chosen what
/// to open, or null.
fn report(pool: anytype, now_ns: u64) ?Event {
    check_fallback(pool, now_ns);
    // Bounded: each pass reads a connection's event, or plans and stops.
    for (0..constants.pool_events_per_poll_max + 1) |_| {
        pool_events.plan(pool, now_ns);
        if (pool_events.owed(pool)) |owed| return owed;
        const read = pool_events.poll(pool, now_ns) orelse return null;
        if (read.event) |reported| return reported;
    }
    unreachable;
}

/// The fallback delay passed while QUIC's handshake runs, and TCP may open beside it.
fn check_fallback(pool: anytype, now_ns: u64) void {
    const fallback_at = pool.fallback_at_ns orelse return;
    if (pool.fallback or phase(pool, .quic) != .handshake) return;
    if (now_ns >= fallback_at) pool.fallback = true;
}

fn free_entry(pool: anytype) ?*Entry {
    for (&pool.entries) |*entry| {
        if (entry.stage == .free) return entry;
    }
    return null;
}

fn entry_of(pool: anytype, id: Id) ?*Entry {
    for (&pool.entries) |*entry| {
        if (entry.stage != .free and entry.id == id) return entry;
    }
    return null;
}
