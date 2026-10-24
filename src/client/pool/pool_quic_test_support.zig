//! What the tests of the pool to one origin with QUIC offered share (`pool_quic_test.zig` and
//! `pool_quic_flow_test.zig`): the pool they drive, its configurations and the events it
//! reported, and the calls that move datagrams between it and the h3 server of
//! `quic_test_support.zig`. No TCP connection is started unless a test starts it. Test-only.
const std = @import("std");
const quic = @import("quic");
const tls = @import("tls");
const support = @import("../connection/connection_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");
const pool_module = @import("pool.zig");
const tls_support = @import("../connection/connection_tls_test_support.zig");
const event = @import("../event.zig");

const ConnectionPool = pool_module.ConnectionPool;
const Exchange = support.Exchange;
const Event = pool_module.Event;

/// The pool the tests drive, its configurations and the events it reported, outside any stack
/// frame. Test-only.
pub var pool: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
pub var pool_memory: [ConnectionPool.memory_bytes(.{})]u8 align(ConnectionPool.memory_alignment) = undefined;
pub var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
pub var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
pub var events_len: usize = 0;
pub var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;
/// Where a datagram crosses from one side to the other. Test-only.
pub var datagram: [quic.constants.datagram_len_max]u8 = undefined;
pub var crossing: [quic.constants.datagram_len_max]u8 = undefined;
/// Whether the datagrams the pool sends are lost, as on a network that blocks UDP.
pub var blocked: bool = false;

pub const unstarted_octet: u8 = 0x01;
pub const https_port: u16 = 443;
pub const other_port: u16 = 8443;
pub const alternative_port: u16 = 50781;
/// The fallback delay, and how far each round of `pump` moves time: 250 ms, past which the ninth
/// round of 30 ms goes.
pub const fallback_delay_ns: u64 = 250_000_000;
const round_ns: u64 = 30_000_000;
pub const rounds_before_fallback: usize = 8;
/// Rounds past the first probe timeout of a handshake whose Initial was lost: RFC 9002 §6.2.2's
/// initial RTT of 333 ms makes it about a second.
pub const rounds_past_probe: usize = 48;
pub const datagrams_per_round_max: usize = 64;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
pub const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};

/// The receive pool of the pool's QUIC connections (decision 61). Test-only.
var receive_pool: quic.stream.stream_incoming.DefaultPool align(@alignOf(quic.stream.stream_incoming.DefaultPool)) = undefined;

/// A pool offering every version over TLS, with a receive pool, whose QUIC server selects from
/// `server_protocols`.
pub fn start(server_protocols: []const []const u8, values: pool_module.Destination, quic_first: bool) !void {
    try start_configured(server_protocols, values, configured(quic_first), receive_pool.storage());
}

/// The configuration `start` gives its pool, which a test changes before `start_configured`.
pub fn configured(quic_first: bool) pool_module.Config {
    return .{
        .tls = tls_support.client_values(support.authority),
        .authority = support.authority,
        .quic_first = quic_first,
        .fallback_delay_ns = fallback_delay_ns,
    };
}

/// The storage of the fixture's receive pool, which `start` gives its pool.
pub fn receive_storage() pool_module.ReceiveStorage {
    return receive_pool.storage();
}

/// As `start`, with the pool's configuration `given` and the receive pool `given_pool`, or
/// none.
pub fn start_configured(server_protocols: []const []const u8, values: pool_module.Destination, given: pool_module.Config, given_pool: ?pool_module.ReceiveStorage) !void {
    try quic_support.prepare(&quic_support.alpn_h3, server_protocols, false);
    config = given;
    // Every octet 1, so each flag of a connection the pool never started reads as set, and a
    // read of one shows. A configuration `init` leaves unwritten keeps the octet too.
    @memset(std.mem.asBytes(&pool), unstarted_octet);
    try pool.init(&pool_memory, &config, values, given_pool);
    events_len = 0;
    blocked = false;
}

pub fn values_at(port: u16) pool_module.Destination {
    return .{ .addresses = &addresses, .port = port };
}

pub fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/dns-query" }, .response = .{ .body = body } };
}

/// A POST, which RFC 9110 §9.2.2 does not make idempotent, so the pool never sends it again.
pub fn post(body: []u8) Exchange {
    return .{ .request = .{ .method = "POST", .path = "/dns-query", .body = "query" }, .response = .{ .body = body } };
}

/// Reports every event the pool owes, with no datagram, and keeps them.
pub fn collect() !void {
    for (0..support.events_max) |_| {
        const received = pool.receive(.none, quic_support.now_ns);
        try keep(received.event orelse return);
    }
    return error.TestUnexpectedResult;
}

/// Keeps `reported`, and starts QUIC when an `open` event asks for it. The tests start no TCP.
pub fn keep(reported: Event) !void {
    if (events_len == events.len) return error.TestUnexpectedResult;
    events[events_len] = reported;
    events_len += 1;
    if (reported == .open and reported.open.transport == .quic) {
        // Each QUIC connection meets a server of its own.
        quic_support.reset_server();
        try pool.start_quic(support.stream.random(), support.now_seconds, quic_support.now_ns, null);
    }
}

/// Moves datagrams both ways for `rounds` rounds, moving time on and firing each side's timers.
pub fn pump(rounds: usize) !void {
    for (0..rounds) |_| {
        quic_support.now_ns += round_ns;
        for (0..datagrams_per_round_max) |_| {
            const sent = pool.send_datagram(&datagram, quic_support.now_ns) orelse break;
            if (blocked) continue;
            @memcpy(crossing[0..sent.bytes.len], sent.bytes);
            try quic_support.server_receive(crossing[0..sent.bytes.len]);
        }
        try quic_support.answer_due();
        for (0..datagrams_per_round_max) |_| {
            const len = (try quic_support.server_send(&datagram)) orelse break;
            @memcpy(crossing[0..len], datagram[0..len]);
            try deliver(crossing[0..len]);
        }
        pool.on_instant(quic_support.now_ns);
        quic_support.server_on_instant();
        try collect();
    }
}

/// Passes a datagram the server sent to the pool. RFC 9000 §9: a client discards a datagram from
/// an address other than its server's, so it comes from the address the pool opened.
pub fn deliver(octets: []u8) !void {
    const from = pool.quic_link.to;
    // Bounded: each pass consumes the datagram or reports one of the pool's events.
    for (0..support.events_max) |_| {
        const received = pool.receive(.{ .datagram = .{ .bytes = octets, .from = from } }, quic_support.now_ns);
        if (received.event) |reported| try keep(reported);
        if (received.consumed > 0) return;
    }
    return error.TestUnexpectedResult;
}

/// The events of `tag`, in order. Test-only.
pub fn nth(tag: std.meta.Tag(Event), index: usize) ?Event {
    var seen: usize = 0;
    for (events[0..events_len]) |reported| {
        if (reported != tag) continue;
        if (seen == index) return reported;
        seen += 1;
    }
    return null;
}

pub fn opened(index: usize) ?pool_module.Open {
    const held = nth(.open, index) orelse return null;
    return held.open;
}
