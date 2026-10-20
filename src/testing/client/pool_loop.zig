//! The pool mode of the test-only client (design §8 step 17d): the plan's exchanges handed to
//! one `client.Pool`, which chooses between QUIC and TCP for them. `tools/pool_interop.sh`
//! runs it against other implementations' h3 servers, and against an h2 server with no UDP, which
//! the pool falls back to. `zig build http-client -- --pool --tls <anchor-prefix> --seconds
//! <unix-seconds> --get <path>` runs it.
//!
//! One Rotor loop holds both transports: the UDP socket of `../udp.zig`, which every QUIC
//! connection of the run shares, and one TCP socket at a time (`pool_tcp.zig`). Each turn waits
//! in Rotor's `tick` until an event arrives or the pool's next deadline passes, then reads the
//! instant that tick read (decision 63), passes what arrived to the pool, and sends what it
//! owes. A sent datagram's octets belong to Rotor until its send's event (Rotor's rule 3), so each
//! is built in a slot of its own, and a datagram Rotor has no room for is one lost on the way,
//! which RFC 9002 recovers.
//!
//! Every exchange is requested at once and the pool is shut down at once, so the run ends when
//! the pool reports `closed`. Nothing here allocates, and nothing reads a clock but the loop.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const client = @import("client");
const constants = @import("../constants.zig");
const udp = @import("../udp.zig");
const entropy = @import("../entropy.zig");
const client_options = @import("client_options.zig");
const client_session = @import("client_session.zig");
const client_exchange = @import("client_exchange.zig");
const pool_tcp = @import("pool_tcp.zig");

const Run = client_options.Run;
const Address = client.Address;
const Input = client.Input;

var memory: udp.Memory align(@alignOf(udp.Memory)) = undefined;
var socket: udp.Endpoint align(@alignOf(udp.Endpoint)) = undefined;
var events: [constants.udp_operations_max]udp.Event align(@alignOf(udp.Event)) = undefined;
var slots: [constants.pool_udp_send_slots][constants.quic_datagram_len_max]u8 = undefined;
var slot_busy: [constants.pool_udp_send_slots]bool = @splat(false);
/// Where each slot's datagram goes, which its send reads until its event (Rotor's rule 3).
var slot_outbound: [constants.pool_udp_send_slots]udp.Outbound align(@alignOf(udp.Outbound)) = undefined;
var tcp: pool_tcp.Socket align(@alignOf(pool_tcp.Socket)) = undefined;

var pool: client.Pool align(@alignOf(client.Pool)) = undefined;
var pool_memory: [client.Pool.memory_bytes(.{})]u8 align(client.Pool.memory_alignment) = undefined;
/// The TCP connection the pool's last `open` of TCP named (decision 125). Generation 0 names none.
var tcp_connection: client.ConnectionHandle align(@alignOf(client.ConnectionHandle)) = .{ .slot = 0, .generation = 0 };
var pool_config: client.Config align(@alignOf(client.Config)) = undefined;
/// The receive pool of the pool's QUIC connections (decision 61).
var receive_pool: client.DefaultReceivePool align(@alignOf(client.DefaultReceivePool)) = undefined;
var addresses: [1]Address align(@alignOf(Address)) = undefined;
var exchanges: [constants.exchanges_max]client_exchange.Exchange align(@alignOf(client_exchange.Exchange)) = undefined;
var exchanges_count: usize = 0;
var bodies: client_session.Bodies align(@alignOf(client_session.Bodies)) = undefined;
/// The protocol of the connection that last reported `connected`, and each exchange's when its
/// `finished` event arrived.
var connected: ?client.Protocol align(@alignOf(client.Protocol)) = null;
var protocols: [constants.exchanges_max]?client.Protocol align(@alignOf(client.Protocol)) = @splat(null);
/// Seconds since 1970-01-01T00:00:00Z, which the command line gave: chapulin judges each chain at
/// that instant.
var now_seconds: u64 = 0;
/// Whether the pool reported `closed`.
var closed: bool = false;

/// Runs the plan of `run` through one pool and reports each exchange. True when every exchange
/// ended the way a working peer ends one and the pool closed. `shared` is what every pool of
/// a run borrows: the TLS value the pool judges the server by, the versions, and the codings the
/// run offers and their pools, which both transports share (decision 101).
pub fn run_pool(run: *const Run, shared: *const client.Config) !bool {
    assert(run.pool and shared.tls != null);
    assert(run.plans_count > 0 and run.plans_count <= constants.exchanges_max);
    // `--h11` turns h2 off, so TCP offers `http/1.1` alone, and QUIC still offers h3.
    pool_config = shared.*;
    pool_config.fallback_delay_ns = run.fallback_delay_ns;
    addresses[0] = Address.of(&run.address, 0);
    now_seconds = run.now_seconds;
    try pool.init(&pool_memory, &pool_config, .{ .addresses = &addresses, .port = run.port }, .{}, receive_pool.storage());
    try request_plan(run.plans[0..run.plans_count]);
    pool.shutdown();
    // The TCP socket's user data starts just above the index of every UDP send slot, and lies far
    // below the UDP receive's.
    tcp.init(constants.pool_udp_send_slots);
    try socket.open(&memory, udp.Address.ipv4(@splat(0), 0));
    try turn_until_closed();
    tcp.close_now(&socket.loop);
    // Rotor makes a send's system call on a later tick, so the last datagrams leave only once the
    // loop has had every send's final event, which closing the socket waits for.
    try socket.close();
    return report();
}

/// Requests every exchange of the plan, which go out once a connection is open to take them.
fn request_plan(plans: []const client_exchange.Plan) !void {
    exchanges_count = plans.len;
    for (plans, exchanges[0..plans.len], bodies[0..plans.len]) |plan, *exchange, *body| {
        exchange.* = .init(plan, body);
        exchange.id = try pool.request(&exchange.request, &exchange.response);
    }
}

/// Turns until the pool reports `closed`, or the run lasts `pool_run_ns_max`. The first tick
/// waits for nothing: it reads the clock whose instant every turn then passes on (decision 63).
fn turn_until_closed() !void {
    var started_ns: u64 = 0;
    for (0..constants.client_ticks_max) |index| {
        const wait_ns = if (index == 0) 0 else next_wait_ns();
        const ready = try socket.tick(&events, wait_ns);
        const now_ns = socket.now_ns();
        if (index == 0) started_ns = now_ns;
        for (ready) |event| on_event(event, now_ns);
        pump(now_ns);
        if (closed or now_ns - started_ns >= constants.pool_run_ns_max) return;
    }
}

/// How long the next tick may wait: until the pool's next deadline, and never longer than
/// `quic_tick_wait_ns_max`.
fn next_wait_ns() u64 {
    const deadline_ns = pool.deadline_ns() orelse return constants.quic_tick_wait_ns_max;
    return @min(constants.quic_tick_wait_ns_max, deadline_ns -| socket.now_ns());
}

fn on_event(event: udp.Event, now_ns: u64) void {
    if (event.user_data == udp.receive_user_data) {
        if (event.flags.buffer) on_datagram(socket.delivery(event), now_ns);
        return socket.finish_receive(event);
    }
    if (tcp.owns(event.user_data)) return on_tcp_event(event);
    // A send's event gives its slot back.
    slot_busy[@intCast(event.user_data)] = false;
}

/// Passes a datagram to the pool, in Rotor's own buffer, which the connection opens in place.
fn on_datagram(delivery: udp.Delivery, now_ns: u64) void {
    _ = drain(.{ .datagram = .{ .octets = delivery.bytes, .from = peer_address(delivery.from.peer) } }, now_ns);
}

fn on_tcp_event(event: udp.Event) void {
    switch (tcp.on_event(&socket.loop, event)) {
        .none => {},
        // A start chapulin refuses ends the attempt, and the pool owes no `close` event for a
        // connection that never started, so the socket closes here.
        .connected => pool.start_tcp(tcp_connection, entropy.random(), now_seconds, null) catch tcp.close(&socket.loop),
        .failed, .open_failed => pool.transport_closed(tcp_connection),
    }
}

/// Fires the pool's deadlines, passes it what TCP read, and sends what it owes.
fn pump(now_ns: u64) void {
    pool.on_instant(now_ns);
    _ = drain(.none, now_ns);
    if (tcp.carrying() and tcp.input_len > 0) tcp.consume(drain(.{ .stream = .{ .connection = tcp_connection, .octets = tcp.unread() } }, now_ns));
    send_datagrams(now_ns);
    send_stream(now_ns);
    tcp.arm(&socket.loop);
}

/// Passes `first` to the pool and does what each event asks, until the pool consumes nothing
/// and reports nothing. Returns the octets it consumed. A datagram is consumed whole.
fn drain(first: Input, now_ns: u64) usize {
    var input = first;
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or reports one of the finitely many events.
    for (0..constants.wire_read_len + constants.exchanges_max * constants.steps_per_read_max) |_| {
        const received = pool.receive(input, now_ns);
        consumed += received.consumed;
        input = rest_of(input, received.consumed);
        const reported = received.event orelse {
            if (received.consumed == 0) return consumed;
            continue;
        };
        handle(reported, now_ns);
    }
    return consumed;
}

/// What is left of `input` once the pool consumed `consumed` octets of it.
fn rest_of(input: Input, consumed: usize) Input {
    return switch (input) {
        .none => .none,
        .datagram => if (consumed > 0) .none else input,
        .stream => |stream| if (consumed == stream.octets.len) .none else .{ .stream = .{ .connection = stream.connection, .octets = stream.octets[consumed..] } },
    };
}

fn handle(reported: client.Event, now_ns: u64) void {
    switch (reported) {
        .open => |open| switch (open.transport) {
            .quic => start_quic(now_ns),
            .tcp => {
                tcp_connection = open.connection;
                if (!tcp.open(&socket.loop, udp_address(open.to))) pool.transport_closed(open.connection);
            },
        },
        // Every QUIC connection of the run shares the one UDP socket, which stays open.
        .close => |connection| if (connection.slot == tcp_connection.slot) tcp.close(&socket.loop),
        // `pump` writes what the TCP connection owes at each turn.
        .send => {},
        .connected => |established| connected = established.protocol,
        // The client offers no ticket, so it keeps none it is given.
        .ticket => |connection| if (pool.take_ticket(connection)) |ticket| {
            var held = ticket;
            held.wipe();
        },
        .finished => |finished| on_finished(finished.id),
        .closed => closed = true,
    }
}

/// Starts the QUIC connection the pool asked for. The pool draws the connection's IDs (RFC
/// 9000 §7.2) and h3's grease value (RFC 9114 §7.2.4.1) from the source it is given (decision 120).
fn start_quic(now_ns: u64) void {
    // A start chapulin refuses is the pool's to report: it ends the attempt, and TCP opens.
    pool.start_quic(entropy.random(), now_seconds, now_ns, null) catch {};
}

/// Marks exchange `id` finished, over the protocol of the connection that last connected.
fn on_finished(id: client.Id) void {
    for (exchanges[0..exchanges_count], 0..) |*exchange, index| {
        if (exchange.id != id) continue;
        exchange.finished = true;
        protocols[index] = connected;
        return;
    }
    unreachable; // The pool reports only the exchanges `request_plan` requested.
}

/// Sends every datagram the pool owes now, each from a free slot.
fn send_datagrams(now_ns: u64) void {
    for (&slots, 0..) |*slot, index| {
        if (slot_busy[index]) continue;
        const sent = pool.send_datagram(slot, now_ns) orelse return;
        slot_outbound[index] = .{ .peer = udp_address(sent.to), .local = undefined, .segment_bytes = 0, .ecn = .not_ect, .flags = .{ .peer = true } };
        if (socket.send(index, sent.octets, &slot_outbound[index])) slot_busy[index] = true;
        _ = drain(.none, now_ns);
    }
}

/// Writes what the pool's TCP connection owes into the socket's output.
fn send_stream(now_ns: u64) void {
    // Bounded: each pass writes an octet, or stops.
    for (0..constants.steps_per_read_max) |_| {
        if (!tcp.carrying()) return;
        const room = tcp.room();
        if (room.len == 0) return;
        const written = pool.send_stream(tcp_connection, room, now_ns);
        if (written == 0) return;
        tcp.wrote(written);
        _ = drain(.none, now_ns);
    }
}

/// A socket address as colibri names a peer's (decision 72), as `../quic/udp/udp_peer.zig`
/// converts one: four octets for IPv4 and sixteen for IPv6, and the port.
fn peer_address(address: udp.Address) Address {
    const len: usize = if (address.family == .ipv4) udp.Address.ipv4_bytes else address.bytes.len;
    return Address.of(address.bytes[0..len], address.port);
}

/// The socket address colibri named, back in Rotor's form.
fn udp_address(address: Address) udp.Address {
    if (address.len == udp.Address.ipv4_bytes) return udp.Address.ipv4(address.octets[0..udp.Address.ipv4_bytes].*, address.port);
    assert(address.len == address.octets.len);
    return udp.Address.ipv6(address.octets, address.port, 0);
}

/// Prints one line per exchange, then the transports the pool opened. True when every exchange
/// succeeded and the pool closed.
fn report() bool {
    var succeeded: usize = 0;
    for (exchanges[0..exchanges_count], protocols[0..exchanges_count]) |*exchange, protocol| {
        std.debug.print("pool ", .{});
        exchange.print(if (protocol) |spoken| @tagName(spoken) else "none");
        if (exchange.succeeded()) succeeded += 1;
    }
    std.debug.print("http-client: pool closed={} quic_opens={d} tcp_opens={d} exchanges={d} succeeded={d}\n", .{
        closed,          pool.quic_link.opens, pool.tcp_links[0].opens,
        exchanges_count, succeeded,
    });
    return closed and succeeded == exchanges_count;
}
