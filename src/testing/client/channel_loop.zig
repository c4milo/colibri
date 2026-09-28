//! The channel mode of the test-only client (design §8 step 17d): the plan's exchanges handed to
//! one `client.Channel`, which chooses between QUIC and TCP for them. `tools/channel_interop.sh`
//! runs it against other implementations' h3 servers, and against an h2 server with no UDP, which
//! the channel falls back to. `zig build http-client -- --channel --tls <anchor-prefix> --seconds
//! <unix-seconds> --get <path>` runs it.
//!
//! One Rotor loop holds both transports: the UDP socket of `../udp.zig`, which every QUIC
//! connection of the run shares, and one TCP socket at a time (`channel_tcp.zig`). Each turn waits
//! in Rotor's `tick` until an event arrives or the channel's next deadline passes, then reads the
//! instant that tick read (decision 63), passes what arrived to the channel, and sends what it
//! owes. A sent datagram's octets belong to Rotor until its send's event (Rotor's rule 3), so each
//! is built in a slot of its own, and a datagram Rotor has no room for is one lost on the way,
//! which RFC 9002 recovers.
//!
//! Every exchange is requested at once and the channel is shut down at once, so the run ends when
//! the channel reports `closed`. Nothing here allocates, and nothing reads a clock but the loop.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const client = @import("client");
const tls = @import("tls");
const constants = @import("../constants.zig");
const udp = @import("../udp.zig");
const entropy = @import("../entropy.zig");
const client_options = @import("client_options.zig");
const client_session = @import("client_session.zig");
const client_exchange = @import("client_exchange.zig");
const client_tls = @import("../tls/client_tls.zig");
const channel_tcp = @import("channel_tcp.zig");

const Run = client_options.Run;
const Address = client.channel.Address;
const Input = client.channel.Input;

var memory: udp.Memory align(@alignOf(udp.Memory)) = undefined;
var socket: udp.Endpoint align(@alignOf(udp.Endpoint)) = undefined;
var events: [constants.udp_operations_max]udp.Event align(@alignOf(udp.Event)) = undefined;
var slots: [constants.channel_udp_send_slots][constants.quic_datagram_len_max]u8 = undefined;
var slot_busy: [constants.channel_udp_send_slots]bool = @splat(false);
/// Where each slot's datagram goes, which its send reads until its event (Rotor's rule 3).
var slot_outbound: [constants.channel_udp_send_slots]udp.Outbound align(@alignOf(udp.Outbound)) = undefined;
var tcp: channel_tcp.Socket align(@alignOf(channel_tcp.Socket)) = undefined;

var channel: client.Channel align(@alignOf(client.Channel)) = undefined;
var channel_config: client.ChannelConfig align(@alignOf(client.ChannelConfig)) = undefined;
var quic_config: client.QuicConfig align(@alignOf(client.QuicConfig)) = undefined;
var quic_tls: tls.quic.ClientConfig align(@alignOf(tls.quic.ClientConfig)) = undefined;
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
/// Whether the channel reported `closed`.
var closed: bool = false;

/// Runs the plan of `run` through one channel and reports each exchange. True when every exchange
/// ended the way a working peer ends one and the channel closed.
pub fn run_channel(run: *const Run, tcp_config: *const client.Config, anchors: *const client_tls.Anchors) !bool {
    assert(run.channel and run.anchor_prefix != null);
    assert(run.plans_count > 0 and run.plans_count <= constants.exchanges_max);
    quic_config = .{ .tls = try client_tls.load_quic(&quic_tls, anchors, run.authority), .authority = run.authority };
    channel_config = .{ .tcp = tcp_config, .quic = &quic_config, .fallback_delay_ns = run.fallback_delay_ns };
    addresses[0] = Address.of(&run.address, 0);
    now_seconds = run.now_seconds;
    channel.init(&channel_config, .{ .addresses = &addresses, .port = run.port });
    try request_plan(run.plans[0..run.plans_count]);
    channel.shutdown();
    tcp.init();
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
        exchange.id = try channel.request(&exchange.carried);
    }
}

/// Turns until the channel reports `closed`, or the run lasts `channel_run_ns_max`. The first tick
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
        if (closed or now_ns - started_ns >= constants.channel_run_ns_max) return;
    }
}

/// How long the next tick may wait: until the channel's next deadline, and never longer than
/// `quic_tick_wait_ns_max`.
fn next_wait_ns() u64 {
    const deadline_ns = channel.deadline_ns() orelse return constants.quic_tick_wait_ns_max;
    return @min(constants.quic_tick_wait_ns_max, deadline_ns -| socket.now_ns());
}

fn on_event(event: udp.Event, now_ns: u64) void {
    if (event.user_data == udp.receive_user_data) {
        if (event.flags.buffer) on_datagram(socket.delivery(event), now_ns);
        return socket.finish_receive(event);
    }
    if (channel_tcp.owns(event.user_data)) return on_tcp_event(event);
    // A send's event gives its slot back.
    slot_busy[@intCast(event.user_data)] = false;
}

/// Passes a datagram to the channel, in Rotor's own buffer, which the connection opens in place.
fn on_datagram(delivery: udp.Delivery, now_ns: u64) void {
    _ = drain(.{ .datagram = .{ .octets = delivery.bytes, .from = peer_address(delivery.from.peer) } }, now_ns);
}

fn on_tcp_event(event: udp.Event) void {
    switch (tcp.on_event(&socket.loop, event)) {
        .none => {},
        // A start chapulin refuses ends the attempt, and the channel owes no `close` event for a
        // connection that never started, so the socket closes here.
        .connected => channel.start_tcp(entropy.random(), now_seconds, null) catch tcp.close(&socket.loop),
        .failed, .open_failed => channel.transport_closed(.tcp),
    }
}

/// Fires the channel's deadlines, passes it what TCP read, and sends what it owes.
fn pump(now_ns: u64) void {
    channel.on_instant(now_ns);
    _ = drain(.none, now_ns);
    if (tcp.carrying() and tcp.input_len > 0) tcp.consume(drain(.{ .stream = tcp.unread() }, now_ns));
    send_datagrams(now_ns);
    send_stream(now_ns);
    tcp.arm(&socket.loop);
}

/// Passes `first` to the channel and does what each event asks, until the channel consumes nothing
/// and reports nothing. Returns the octets it consumed. A datagram is consumed whole.
fn drain(first: Input, now_ns: u64) usize {
    var input = first;
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or reports one of the finitely many events.
    for (0..constants.wire_read_len + constants.exchanges_max * constants.steps_per_read_max) |_| {
        const received = channel.receive(input, now_ns);
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

/// What is left of `input` once the channel consumed `consumed` octets of it.
fn rest_of(input: Input, consumed: usize) Input {
    return switch (input) {
        .none => .none,
        .datagram => if (consumed > 0) .none else input,
        .stream => |octets| if (consumed == octets.len) .none else .{ .stream = octets[consumed..] },
    };
}

fn handle(reported: client.channel.Event, now_ns: u64) void {
    switch (reported) {
        .open => |open| switch (open.transport) {
            .quic => start_quic(now_ns),
            .tcp => if (!tcp.open(&socket.loop, udp_address(open.to))) channel.transport_closed(.tcp),
        },
        // Every QUIC connection of the run shares the one UDP socket, which stays open.
        .close => |transport| if (transport == .tcp) tcp.close(&socket.loop),
        .connected => |protocol| connected = protocol,
        // The client offers no ticket, so it keeps none it is given.
        .ticket => |transport| if (channel.take_ticket(transport)) |ticket| {
            var held = ticket;
            held.wipe();
        },
        .finished => |finished| on_finished(finished.id),
        .closed => closed = true,
    }
}

/// Starts the QUIC connection the channel asked for, from values drawn at random (invariant 5): its
/// connection IDs (RFC 9000 §7.2) and h3's grease (RFC 9114 §7.2.4.1).
fn start_quic(now_ns: u64) void {
    var start: client.QuicStart = undefined;
    entropy.fill(&start.source_id);
    entropy.fill(&start.original_destination_id);
    entropy.fill(std.mem.asBytes(&start.grease));
    // A start chapulin refuses is the channel's to report: it ends the attempt, and TCP opens.
    channel.start_quic(start, entropy.random(), now_seconds, now_ns, null) catch {};
}

/// Marks exchange `id` finished, over the protocol of the connection that last connected.
fn on_finished(id: client.Id) void {
    for (exchanges[0..exchanges_count], 0..) |*exchange, index| {
        if (exchange.id != id) continue;
        exchange.finished = true;
        protocols[index] = connected;
        return;
    }
    unreachable; // The channel reports only the exchanges `request_plan` requested.
}

/// Sends every datagram the channel owes now, each from a free slot.
fn send_datagrams(now_ns: u64) void {
    for (&slots, 0..) |*slot, index| {
        if (slot_busy[index]) continue;
        const sent = channel.send_datagram(slot, now_ns) orelse return;
        slot_outbound[index] = .{ .peer = udp_address(sent.to), .local = undefined, .segment_bytes = 0, .ecn = .not_ect, .flags = .{ .peer = true } };
        if (socket.send(index, sent.octets, &slot_outbound[index])) slot_busy[index] = true;
        _ = drain(.none, now_ns);
    }
}

/// Writes what the channel's TCP connection owes into the socket's output.
fn send_stream(now_ns: u64) void {
    // Bounded: each pass writes an octet, or stops.
    for (0..constants.steps_per_read_max) |_| {
        if (!tcp.carrying()) return;
        const room = tcp.room();
        if (room.len == 0) return;
        const written = channel.send_stream(room, now_ns);
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

/// Prints one line per exchange, then the transports the channel opened. True when every exchange
/// succeeded and the channel closed.
fn report() bool {
    var succeeded: usize = 0;
    for (exchanges[0..exchanges_count], protocols[0..exchanges_count]) |*exchange, protocol| {
        std.debug.print("channel ", .{});
        exchange.print(if (protocol) |spoken| @tagName(spoken) else "none");
        if (exchange.succeeded()) succeeded += 1;
    }
    std.debug.print("http-client: channel closed={} quic_opens={d} tcp_opens={d} exchanges={d} succeeded={d}\n", .{
        closed,          channel.links.get(.quic).opens, channel.links.get(.tcp).opens,
        exchanges_count, succeeded,
    });
    return closed and succeeded == exchanges_count;
}
