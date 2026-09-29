//! The world of the client trace run (decision 105): the caller of a `client.Channel`, the QUIC
//! server over the simulator's datagram network, and the TCP server over an ordered link, acting
//! out one seed's plan. Time moves from one instant something is due to the next: a datagram or
//! TCP octets arriving, a deadline, a server's answer, or the plan's next action. At each instant
//! the world runs every receive and send until nothing moves, which is where the run logs the
//! model's state.
//!
//! Every draw the handshakes make comes from the seed: the caller hands chapulin a `tls.Random`
//! over the simulator's generator (decision 94 as amended), and the QUIC connection IDs are the
//! caller's too (invariant 5). The run judges every certificate at the identity's instant.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const quic = @import("quic");
const tls = @import("tls");
const sim = @import("sim");
const plan_module = @import("client_trace_plan.zig");
const ledger_module = @import("client_trace_ledger.zig");
const link_module = @import("client_trace_link.zig");
const identity = @import("client_trace_identity.zig");
const QuicServer = @import("client_trace_quic_server.zig").QuicServer;
const TcpServer = @import("client_trace_tcp_server.zig").TcpServer;

const limits = sim.constants.client_trace;
const Random = sim.Random;
const Plan = plan_module.Plan;
const Ledger = ledger_module.Ledger;
const Direction = link_module.Direction;
const Channel = client.Channel;
const Transport = client.channel.Transport;

pub const Error = error{
    /// An exchange was reported twice, or after the caller cancelled it.
    ReportedTwice,
    ReportedAfterCancel,
    /// Nothing is due and the channel has not closed.
    Stuck,
    /// An instant's receives and sends did not settle within `settle_rounds_max` rounds.
    Unsettled,
} || link_module.Error || client.RequestError;

/// Octets of each exchange's response body, and of the content POSTs send.
const body_len: usize = 64;
const datagram_len: usize = sim.constants.network_datagram_len_max;
const segment_len: usize = 65_536;
/// The addresses the channel is told of: one, as a caller that resolved one would pass.
const server_octet: u8 = 0x7f;
const ipv4_len: usize = 4;
const server_host: [ipv4_len]u8 = @splat(server_octet);
const https_port: u16 = 443;
/// The octets every POST's content is cut from.
var content_source: [limits.content_len_max]u8 = @splat(content_octet);
const content_octet: u8 = 'c';

pub const World = struct {
    plan: Plan,
    /// The caller's draws: each QUIC connection's IDs and grease, and every TLS session's.
    random: Random,
    tls_random: Random,
    now_ns: u64,
    channel: Channel,
    channel_config: client.ChannelConfig,
    /// The receive pool of the channel's QUIC connections (decision 61).
    receive_pool: client.DefaultReceivePool,
    tcp_tls: tls.record.ClientConfig,
    tcp_config: client.Config,
    quic_tls: tls.quic.ClientConfig,
    quic_config: client.QuicConfig,
    addresses: [1]client.channel.Address,
    exchanges: [limits.exchanges_max]client.HttpExchange,
    bodies: [limits.exchanges_max][body_len]u8,
    paths: [limits.exchanges_max][body_len]u8,
    ids: [limits.exchanges_max]?client.Id,
    /// What the caller did with each exchange and heard of it.
    cancelled: [limits.exchanges_max]bool,
    reported: [limits.exchanges_max]bool,
    /// The instant the last exchange was reported or cancelled.
    settled_ns: u64,
    shut: bool,
    closed: bool,
    goaway_sent: bool,
    broken: bool,
    /// The PINGs the channel's QUIC connections owed to keep an idle timeout off while an exchange
    /// was outstanding (RFC 9000 §10.1.2, design §8 step 17g).
    keep_alives: u64,
    network: sim.Network,
    to_server: Direction,
    to_client: Direction,
    quic_server: QuicServer,
    tcp_server: TcpServer,
    ledger: Ledger,
    datagram: [datagram_len]u8,
    crossing: [datagram_len]u8,
    segment: [segment_len]u8,

    /// Prepares the world for `seed`'s plan, with nothing opened.
    pub fn init(world: *World, seed: u64) !void {
        world.random = Random.init(seed);
        world.plan.draw(&world.random);
        world.tls_random = Random.init(seed ^ tls_seed_mark);
        world.now_ns = 0;
        world.ids = @splat(null);
        world.cancelled = @splat(false);
        world.reported = @splat(false);
        world.settled_ns = 0;
        world.shut = false;
        world.closed = false;
        world.goaway_sent = false;
        world.broken = false;
        world.keep_alives = 0;
        world.ledger.init();
        world.to_server.clear();
        world.to_client.clear();
        world.network.init(seed, world.schedule());
        try world.configure();
        const receive = if (world.channel_config.quic == null) null else world.receive_pool.storage();
        world.channel.init(&world.channel_config, world.values(), receive);
        world.quic_server.started = false;
        world.tcp_server.running = false;
    }

    fn configure(world: *World) !void {
        try world.tcp_tls.init(.{
            .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = identity.authority } },
            .alpn = &alpn_tcp,
        });
        world.tcp_config = .{ .authority = identity.authority, .tls = &world.tcp_tls };
        try world.quic_tls.init(.{
            .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = identity.authority } },
            .alpn = &alpn_quic,
        });
        world.quic_config = .{ .tls = &world.quic_tls, .authority = identity.authority };
        world.channel_config = .{
            .tcp = &world.tcp_config,
            .quic = if (world.plan.policy == .never) null else &world.quic_config,
            .quic_first = world.plan.policy == .first,
            .fallback_delay_ns = limits.fallback_delay_ns,
        };
        try world.quic_server.configure(&world.plan);
        try world.tcp_server.configure();
    }

    fn values(world: *World) client.channel.Values {
        world.addresses = .{client.channel.Address.of(&server_host, 0)};
        var held: client.channel.Values = .{ .addresses = &world.addresses, .port = https_port };
        // RFC 9460 §7.1.2: an HTTPS record naming h3 has the channel try QUIC first, and one naming
        // no h3 has it wait for Alt-Svc.
        if (world.plan.https) held.https = .{ .h3 = world.plan.policy == .first };
        return held;
    }

    /// How the network treats QUIC's datagrams, as the plan's QUIC fate says.
    fn schedule(world: *const World) sim.network.Schedule {
        return switch (world.plan.quic) {
            .works, .refused => .{},
            .blocked => .{ .drop = sim.constants.schedule_denominator },
            .slow => .{ .delay_min_ns = limits.slow_delay_min_ns, .delay_max_ns = limits.slow_delay_max_ns },
            .lossy => .{ .drop = limits.lossy_drop, .drop_run_max = limits.lossy_drop_run_max },
        };
    }

    /// The next instant something is due after the last one, or null when nothing is.
    pub fn next_instant(world: *World) ?u64 {
        var at: ?u64 = world.plan_due_ns();
        at = earliest(at, world.network.next_arrival_ns());
        at = earliest(at, world.to_server.next_arrival_ns(world.now_ns));
        at = earliest(at, world.to_client.next_arrival_ns(world.now_ns));
        at = earliest(at, world.channel.deadline_ns());
        if (world.quic_server.started) {
            at = earliest(at, world.quic_server.deadline_ns());
            at = earliest(at, world.quic_server.due_ns(&world.plan));
        }
        at = earliest(at, world.tcp_server.due_ns(&world.plan));
        return at;
    }

    /// Moves to `at` and runs everything due there until nothing moves.
    pub fn step(world: *World, at: u64) Error!void {
        world.now_ns = @max(world.now_ns, at);
        try world.act_on_plan();
        try world.deliver();
        const deadline = world.channel.deadline_ns();
        if (deadline != null and deadline.? <= world.now_ns) world.fire_channel();
        if (world.quic_server.started) world.quic_server.on_instant(world.now_ns);
        try world.settle();
        if (world.cancel_on_end()) try world.settle();
    }

    /// Fires the channel's deadlines at the instant, and counts a keep-alive its QUIC connection
    /// owes from then.
    fn fire_channel(world: *World) void {
        const quic_link = &world.channel.links.get(.quic);
        const running = quic_link.state == .running;
        const owed_before = running and quic.connection_idle.keep_alive_owed(&world.channel.quic.transport);
        world.channel.on_instant(world.now_ns);
        if (!running or owed_before) return;
        if (quic.connection_idle.keep_alive_owed(&world.channel.quic.transport)) world.keep_alives += 1;
    }

    /// Cancels each exchange the plan cancels once its connection ended it, before the channel
    /// reported it. Returns whether it cancelled one.
    fn cancel_on_end(world: *World) bool {
        var cancelled = false;
        for (0..world.plan.exchanges) |index| {
            if (!world.plan.cancel_on_end[index] or world.cancelled[index] or world.reported[index]) continue;
            const id = world.ids[index] orelse continue;
            if (world.exchanges[index].outcome == .pending) continue;
            world.channel.cancel(id);
            world.cancelled[index] = true;
            world.settled_ns = world.now_ns;
            cancelled = true;
        }
        return cancelled;
    }

    /// The plan's next action after the last instant, or null.
    fn plan_due_ns(world: *const World) ?u64 {
        var at: ?u64 = null;
        for (0..world.plan.exchanges) |index| at = earliest(at, world.exchange_due_ns(index));
        if (!world.shut) at = earliest(at, world.plan.shutdown_at_ns);
        if (!world.goaway_sent) at = earliest(at, world.not_passed(world.plan.goaway_at_ns));
        if (!world.broken) at = earliest(at, world.not_passed(world.plan.break_at_ns));
        return at;
    }

    /// The instant exchange `index` is made or cancelled next, or null.
    fn exchange_due_ns(world: *const World, index: usize) ?u64 {
        if (world.ids[index] == null) return if (world.shut) null else world.plan.make_at_ns[index];
        if (world.cancelled[index] or world.reported[index]) return null;
        return world.plan.cancel_at_ns[index];
    }

    /// `at`, unless it has passed.
    fn not_passed(world: *const World, at: ?u64) ?u64 {
        const held = at orelse return null;
        return if (held >= world.now_ns) held else null;
    }

    fn act_on_plan(world: *World) Error!void {
        for (0..world.plan.exchanges) |index| {
            if (world.ids[index] == null and !world.shut and world.plan.make_at_ns[index] <= world.now_ns) try world.make(index);
            world.cancel_if_due(index);
        }
        if (!world.shut and world.plan.shutdown_at_ns <= world.now_ns) {
            world.channel.shutdown();
            world.shut = true;
        }
        world.goaway_if_due();
        world.break_if_due();
    }

    /// Breaks the connection the plan names once its instant comes, if one runs then.
    fn break_if_due(world: *World) void {
        const break_at = world.plan.break_at_ns orelse return;
        if (world.broken or break_at > world.now_ns) return;
        world.broken = true;
        switch (world.plan.break_kind) {
            .quic_close => if (world.quic_server.started) world.quic_server.close_with_error(),
            .quic_flow => {
                world.channel.transport_closed(.quic);
                world.network.init(world.random.next(), world.schedule());
                world.quic_server.started = false;
            },
            .tcp_flow => {
                world.channel.transport_closed(.tcp);
                world.to_server.clear();
                world.to_client.clear();
                world.tcp_server.stop();
            },
        }
    }

    fn cancel_if_due(world: *World, index: usize) void {
        const cancel_at = world.plan.cancel_at_ns[index] orelse return;
        const id = world.ids[index] orelse return;
        if (cancel_at > world.now_ns or world.cancelled[index] or world.reported[index]) return;
        world.channel.cancel(id);
        world.cancelled[index] = true;
        world.settled_ns = world.now_ns;
    }

    /// Sends the seed's GOAWAY once its instant comes, from whichever server the plan names. A
    /// GOAWAY no running server could send is not sent later.
    fn goaway_if_due(world: *World) void {
        const goaway_at = world.plan.goaway_at_ns orelse return;
        if (world.goaway_sent or goaway_at > world.now_ns) return;
        world.goaway_sent = true;
        _ = switch (world.plan.goaway_transport) {
            .quic => world.quic_server.started and (world.quic_server.send_goaway(&world.ledger, world.now_ns) catch false),
            .tcp => world.tcp_server.send_goaway(&world.ledger),
        };
    }

    fn make(world: *World, index: usize) Error!void {
        const path = ledger_module.path_of(index, &world.paths[index]);
        const content_len = world.plan.content_len[index];
        world.exchanges[index] = .{
            .method = if (content_len > 0) "POST" else "GET",
            .path = path,
            .content = content_source[0..content_len],
            .body = &world.bodies[index],
        };
        world.ids[index] = try world.channel.request(&world.exchanges[index]);
    }

    /// Hands each side what arrived by now.
    fn deliver(world: *World) Error!void {
        // Bounded: the network holds at most `network_in_flight_max` datagrams.
        for (0..sim.constants.network_in_flight_max) |_| {
            const delivery = world.network.receive(world.now_ns, .server) orelse break;
            @memcpy(world.crossing[0..delivery.octets.len], delivery.octets);
            if (world.quic_server.started or world.quic_open()) {
                world.quic_server.receive(world.crossing[0..delivery.octets.len], tls_source(&world.tls_random), world.now_ns) catch {};
            }
        }
        for (0..sim.constants.network_in_flight_max) |_| {
            const delivery = world.network.receive(world.now_ns, .client) orelse break;
            @memcpy(world.crossing[0..delivery.octets.len], delivery.octets);
            try world.to_channel(.{ .datagram = .{ .octets = world.crossing[0..delivery.octets.len], .from = world.channel.links.get(.quic).to } });
        }
        const arrived = world.to_server.arrived(world.now_ns);
        world.tcp_server.take(arrived) catch {};
        world.to_server.consume(arrived.len);
        try world.stream_to_channel();
    }

    fn quic_open(world: *const World) bool {
        return world.channel.links.get(.quic).state == .running;
    }

    /// Passes a datagram to the channel, reporting each event it owes first.
    fn to_channel(world: *World, input: client.channel.Input) Error!void {
        // Bounded: each pass consumes the datagram or reports one of the channel's events.
        for (0..limits.settle_rounds_max) |_| {
            const received = world.channel.receive(input, world.now_ns);
            if (received.event) |reported| try world.handle(reported);
            if (received.consumed > 0 or received.event == null) return;
        }
        return error.Unsettled;
    }

    /// Passes what the TCP link carried to the channel until it consumes nothing more.
    fn stream_to_channel(world: *World) Error!void {
        // Bounded: each pass consumes octets or reports an event.
        for (0..limits.tcp_chunks_max) |_| {
            const arrived = world.to_client.arrived(world.now_ns);
            const received = world.channel.receive(.{ .stream = arrived }, world.now_ns);
            world.to_client.consume(received.consumed);
            if (received.event) |reported| try world.handle(reported);
            if (received.consumed == 0 and received.event == null) return;
        }
        return error.Unsettled;
    }

    /// Runs the channel's receives and sends and the servers' until nothing moves.
    fn settle(world: *World) Error!void {
        for (0..limits.settle_rounds_max) |_| {
            var moved = try world.collect();
            moved = try world.channel_sends() or moved;
            moved = try world.servers_serve() or moved;
            try world.stream_to_channel();
            if (!moved) return;
        }
        return error.Unsettled;
    }

    /// Reports every event the channel owes, and handles each. Returns whether there was one.
    fn collect(world: *World) Error!bool {
        var any = false;
        for (0..limits.settle_rounds_max) |_| {
            const received = world.channel.receive(.none, world.now_ns);
            const reported = received.event orelse return any;
            try world.handle(reported);
            any = true;
        }
        return error.Unsettled;
    }

    fn channel_sends(world: *World) Error!bool {
        var moved = false;
        for (0..limits.datagrams_per_round_max) |_| {
            const sent = world.channel.send_datagram(&world.datagram, world.now_ns) orelse break;
            _ = world.network.send(world.now_ns, .client, sent.octets, .not_ect);
            moved = true;
        }
        const written = world.channel.send_stream(&world.segment, world.now_ns);
        if (written > 0) {
            try world.to_server.push(world.segment[0..written], world.now_ns + limits.tcp_delay_ns);
            moved = true;
        }
        return moved;
    }

    fn servers_serve(world: *World) Error!bool {
        var moved = false;
        if (world.quic_server.started) {
            world.quic_server.serve(&world.plan, &world.ledger, world.now_ns) catch {};
            for (0..limits.datagrams_per_round_max) |_| {
                const len = world.quic_server.send(&world.datagram, world.now_ns) orelse break;
                _ = world.network.send(world.now_ns, .server, world.datagram[0..len], .not_ect);
                moved = true;
            }
        }
        const served = world.tcp_server.serve(&world.plan, &world.ledger, &world.to_client, world.now_ns) catch false;
        return served or moved;
    }

    /// What the caller does with each of the channel's events.
    fn handle(world: *World, reported: client.channel.Event) Error!void {
        switch (reported) {
            .open => |open| switch (open.transport) {
                .quic => world.open_quic(),
                .tcp => world.open_tcp(),
            },
            .close => |transport| switch (transport) {
                // The caller closes the flow, so what was in flight reaches no one.
                .quic => {
                    world.network.init(world.random.next(), world.schedule());
                    world.quic_server.started = false;
                },
                .tcp => {
                    world.to_server.clear();
                    world.to_client.clear();
                    world.tcp_server.stop();
                },
            },
            .ticket => |transport| if (world.channel.take_ticket(transport)) |ticket| {
                var held = ticket;
                held.wipe();
            },
            .finished => |finished| try world.report(finished),
            .connected => {},
            .closed => world.closed = true,
        }
    }

    /// Starts the QUIC connection the channel asked for, over a fresh flow to a fresh server.
    fn open_quic(world: *World) void {
        world.network.init(world.random.next(), world.schedule());
        world.quic_server.reset(world.channel.links.get(.quic).opens);
        var start: client.QuicStart = undefined;
        fill(&world.random, &start.source_id);
        fill(&world.random, &start.original_destination_id);
        start.grease = world.random.next();
        // A start chapulin refuses is the channel's to report.
        world.channel.start_quic(start, tls_source(&world.tls_random), identity.now_seconds, world.now_ns, null) catch {};
    }

    fn open_tcp(world: *World) void {
        world.to_server.clear();
        world.to_client.clear();
        world.tcp_server.reset(world.channel.links.get(.tcp).opens, tls_source(&world.tls_random)) catch {};
        world.channel.start_tcp(tls_source(&world.tls_random), identity.now_seconds, null) catch {};
    }

    fn report(world: *World, finished: client.Finished) Error!void {
        const index = world.index_of(finished.exchange);
        if (world.reported[index]) return error.ReportedTwice;
        if (world.cancelled[index]) return error.ReportedAfterCancel;
        world.reported[index] = true;
        world.settled_ns = world.now_ns;
    }

    /// The index of the exchange at `exchange`, which the world placed.
    pub fn index_of(world: *const World, exchange: *const client.HttpExchange) usize {
        const index = (@intFromPtr(exchange) - @intFromPtr(&world.exchanges[0])) / @sizeOf(client.HttpExchange);
        assert(index < limits.exchanges_max and &world.exchanges[index] == exchange);
        return index;
    }
};

/// Marks the TLS draws' seed apart from the caller's, so the two sequences differ.
const tls_seed_mark: u64 = 0x746c_735f_7365_6564;

const alpn_tcp = [_][]const u8{"h2"};
const alpn_quic = [_][]const u8{"h3"};

fn earliest(at: ?u64, candidate: ?u64) ?u64 {
    const held = candidate orelse return at;
    return @min(at orelse held, held);
}

/// The source a TLS session draws from: the simulator's generator, octet by octet.
fn tls_source(random: *Random) tls.Random {
    return tls.Random.init(random, fill);
}

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}
