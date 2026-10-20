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
const pool_handle = @import("pool_handle.zig");
const pool_connection = @import("pool_connection.zig");
const pool_links = @import("pool_links.zig");

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
const Options = pool_module.Options;
const ConnectionHandle = pool_module.ConnectionHandle;

pub fn init(pool: anytype, memory: []align(pool_module.pool_memory_alignment) u8, config: *const Config, values: Values, options: Options, receive_pool: ?ReceiveStorage) StartError!void {
    assert(values.addresses.len > 0);
    // Decision 35 as amended: the caller's memory holds what the options count, and the pool asks
    // for no more.
    const layout = pool_module.Layout.of(options);
    assert(memory.len >= layout.len);
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
    pool.options = options;
    pool.tcp = std.mem.bytesAsSlice(connection_module.Connection, memory[0..layout.tcp_len]);
    pool.tcp_links = @alignCast(std.mem.bytesAsSlice(Link, memory[layout.links_offset..layout.entries_offset]));
    pool.entries = @alignCast(std.mem.bytesAsSlice(Entry, memory[layout.entries_offset..layout.len]));
    assert(pool.tcp.len == options.tcp_connections and pool.tcp_links.len == options.tcp_connections);
    assert(pool.entries.len == options.exchanges);
    @memset(pool.tcp_links, .{});
    @memset(pool.entries, .{});
    pool.quic_link = .{};
    pool.quic_address_index = 0;
    pool.tcp_address_index = 0;
    pool.next_id = 1;
    pool.fallback = false;
    pool.fallback_at_ns = null;
    pool.shut = false;
    pool.closed_reported = false;
}

pub fn set_values(pool: anytype, values: Values) void {
    assert(values.addresses.len > 0);
    // RFC 9110 §4.3.1: the port is part of the origin, and a pool carries one origin's exchanges.
    assert(values.port == pool.values.port);
    const known = pool.values.alternative;
    pool.values = values;
    if (values.alternative == null) pool.values.alternative = known;
    pool.quic_address_index = 0;
    pool.tcp_address_index = 0;
    // Each connection open or opening now went to the old values. The next `open_link` of its
    // slot clears the flag.
    for (pool.tcp_links) |*link| link.replaced = true;
    pool.quic_link.replaced = true;
}

pub fn request(pool: anytype, message: *const Request, response: *Response) RequestError!Id {
    assert(!pool.shut);
    try connection_module.check_request(message);
    const entry = free_entry(pool) orelse return error.Full;
    event_internal.clear(response);
    entry.* = .{ .stage = .waiting, .id = pool.next_id, .request = message, .response = response };
    pool.next_id += 1;
    pool_events.assign_waiting(pool);
    pool_events.unblock_sends(pool);
    return entry.id;
}

pub fn cancel(pool: anytype, id: Id) void {
    const entry = entry_of(pool, id) orelse return;
    if (entry.stage == .carried) pool_connection.cancel(pool, entry.carrier, entry.carried_id);
    entry.* = .{};
    pool_events.unblock_sends(pool);
}

pub fn receive(pool: anytype, input: Input, now_ns: u64) Received {
    // Decision 125: a TCP connection's `send` comes in a call that hands it no octets, once it read
    // what the program held for it, as a program sends once it drained `receive`.
    const sends = input != .stream or input.stream.octets.len == 0;
    if (report(pool, now_ns, sends)) |owed| return .{ .consumed = 0, .event = owed };
    const fed = pool_events.feed(pool, input, now_ns);
    return .{ .consumed = fed.len, .event = fed.event };
}

pub fn send_datagram(pool: anytype, output: []u8, now_ns: u64) ?Sent {
    if (!pool.capacity.quic or pool.quic_link.state != .running) return null;
    return pool.quic.send(output, now_ns);
}

pub fn send_stream(pool: anytype, connection: ConnectionHandle, output: []u8, now_ns: u64) usize {
    const slot = pool_handle.resolve(pool, connection) orelse return 0;
    // The program sends datagrams through `send_datagram`.
    assert(pool_handle.transport_of(pool, slot) == .tcp);
    const link = &pool.tcp_links[slot];
    if (link.state != .running) return 0;
    const written = pool.tcp[slot].send(output, now_ns);
    // Decision 125: a call that leaves room in `output` wrote everything the connection could, and
    // one that writes nothing into the least output finds the connection blocked.
    if (written < output.len) link.send_outstanding = false;
    if (written == 0 and output.len >= constants.stream_output_len_min) link.send_blocked = true;
    return written;
}

pub fn deadline_ns(pool: anytype) ?u64 {
    var deadline: ?u64 = null;
    if (pool.capacity.quic and pool.quic_link.state == .running) deadline = pool.quic.deadline_ns();
    if (pool.offered.tcp and !pool.fallback and quic_phase(pool) == .handshake) {
        const fallback_at = pool.fallback_at_ns orelse return deadline;
        deadline = @min(deadline orelse fallback_at, fallback_at);
    }
    return deadline;
}

pub fn on_instant(pool: anytype, now_ns: u64) void {
    if (pool.capacity.quic and pool.quic_link.state == .running) pool.quic.on_instant(now_ns);
}

pub fn start_quic(pool: anytype, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) StartError!void {
    if (!pool.capacity.quic) @compileError("a pool with no QUIC never asks for QUIC, so it has no start_quic");
    const link = &pool.quic_link;
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
        pool_links.close_unstarted(pool, pool_handle.quic_slot(pool));
        return failure;
    };
    link.state = .running;
    pool.fallback_at_ns = now_ns + pool.config.fallback_delay_ns;
}

pub fn start_tcp(pool: anytype, connection: ConnectionHandle, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
    const slot = pool_handle.resolve(pool, connection) orelse return;
    if (pool_handle.transport_of(pool, slot) != .tcp) return;
    const link = &pool.tcp_links[slot];
    if (link.state != .opening) return;
    assert(!link.open_owed);
    pool.tcp[slot].init(&pool.tcp_config, random, now_seconds, resumption, .{ .retrying = retrying(pool) }) catch |failure| {
        // The pool asks for TCP only while `versions` allows h11 or h2, so the TLS stack alone
        // refuses a start.
        assert(failure == error.TlsRefused);
        pool_links.close_unstarted(pool, slot);
        return failure;
    };
    link.state = .running;
}

pub fn transport_closed(pool: anytype, connection: ConnectionHandle) void {
    const slot = pool_handle.resolve(pool, connection) orelse return;
    const link = pool_handle.link(pool, slot);
    switch (link.state) {
        .none, .closed => {},
        .opening => pool_links.close_unstarted(pool, slot),
        .running => {
            link.gone = true;
            pool_connection.transport_closed(pool, slot);
        },
    }
}

pub fn take_ticket(pool: anytype, connection: ConnectionHandle) ?tls.Ticket {
    const slot = pool_handle.resolve(pool, connection) orelse return null;
    if (pool_handle.link(pool, slot).state != .running) return null;
    return pool_connection.take_ticket(pool, slot);
}

pub fn phase(pool: anytype, slot: u32) Phase {
    const link = pool_handle.link(pool, slot);
    return switch (link.state) {
        .none => .none,
        .closed => .closed,
        .opening => if (link.abandoned) .failed else .handshake,
        .running => running_phase(pool, slot, link.*),
    };
}

fn running_phase(pool: anytype, slot: u32, link: Link) Phase {
    if (pool_connection.failed(pool, slot)) return .failed;
    if (pool_connection.draining(pool, slot)) return .draining;
    return if (link.won) .open else .handshake;
}

/// The QUIC slot's phase, or none in a pool with no QUIC.
fn quic_phase(pool: anytype) Phase {
    if (!pool.capacity.quic) return .none;
    return phase(pool, pool_handle.quic_slot(pool));
}

/// Whether an exchange that waits for the connection starting now went out on a connection that
/// failed. The connection then writes the first request alone (RFC 9112 §9.3.2).
fn retrying(pool: anytype) bool {
    for (pool.entries) |*entry| {
        if (entry.stage == .waiting and entry.after_failure) return true;
    }
    return false;
}

/// The first event the pool owes, after it has read what its connections owe and chosen what
/// to open, or null.
fn report(pool: anytype, now_ns: u64, sends: bool) ?Event {
    check_fallback(pool, now_ns);
    // Bounded: each pass reads a connection's event, or plans and stops. Each connection reports
    // at most `pool_events_per_poll_max / 2` events in one call.
    const passes = @as(usize, pool_handle.slots_count(pool)) * constants.pool_events_per_poll_max + 1;
    for (0..passes) |_| {
        pool_events.plan(pool, now_ns);
        if (pool_events.owed(pool)) |owed| return owed;
        if (pool_events.poll(pool, now_ns)) |read| {
            if (read.event) |reported| return reported;
            continue;
        }
        return if (sends) pool_events.owed_send(pool) else null;
    }
    unreachable;
}

/// The fallback delay passed while QUIC's handshake runs, and TCP may open beside it.
fn check_fallback(pool: anytype, now_ns: u64) void {
    const fallback_at = pool.fallback_at_ns orelse return;
    if (pool.fallback or quic_phase(pool) != .handshake) return;
    if (now_ns >= fallback_at) pool.fallback = true;
}

fn free_entry(pool: anytype) ?*Entry {
    for (pool.entries) |*entry| {
        if (entry.stage == .free) return entry;
    }
    return null;
}

fn entry_of(pool: anytype, id: Id) ?*Entry {
    for (pool.entries) |*entry| {
        if (entry.stage != .free and entry.id == id) return entry;
    }
    return null;
}
