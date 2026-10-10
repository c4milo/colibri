//! One run of the endpoint check (design §8 step 21b.5, decision 119): one endpoint with two TCP
//! and two QUIC slots, the seed's three TCP and three QUIC peers (`endpoint_plan.zig`), and the
//! program that drives the endpoint as docs/usage.md says a program does, in simulated time.
//!
//! At each instant the run makes passes until one moves nothing. A pass hands the endpoint the
//! instant, accepts the TCP peers that wait while a slot is free, passes the endpoint every octet
//! a socket holds and every datagram a peer sent, reads every event, answers every request that
//! can be answered, reads every event again, writes every datagram the endpoint owes, and lets
//! each peer read. The octets a TCP connection did not consume are passed again on the next pass,
//! so after each event that names it. Every `send` is answered at once (P7). Once a pass moves
//! nothing, the program checks P6 and P8 (`endpoint_program.zig`), and the run goes to the next
//! instant something is due.
//!
//! A run ends at `closed`, once every peer's connection ended, or at the horizon.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const tls = @import("tls");
const server = @import("server");
const identity = @import("../client_trace_identity.zig");
const plan_module = @import("endpoint_plan.zig");
const ledger_module = @import("endpoint_ledger.zig");
const program_module = @import("endpoint_program.zig");
const tcp_module = @import("endpoint_tcp.zig");
const quic_module = @import("endpoint_quic.zig");
const route_module = @import("endpoint_run_route.zig");
const answer_module = @import("endpoint_answer.zig");
const stale = @import("endpoint_program_stale.zig");

const Random = sim.Random;
const limits = sim.constants.endpoint;
const Plan = plan_module.Plan;
const Program = program_module.Program;
const Endpoint = program_module.Endpoint;
const Peer = tcp_module.Peer;

pub const Error = program_module.Violation || tcp_module.Error || quic_module.Error || error{
    /// chapulin refused the endpoint's identity.
    ServerRefused,
    /// The run visited `instants_max` instants, or an instant did not settle.
    RunStalled,
    /// The endpoint wrote more to a TCP peer than its socket holds.
    SocketFull,
    /// The endpoint wrote a datagram to an address no peer sends from.
    DatagramUnaddressed,
};

/// How a run ended.
pub const End = enum {
    /// The endpoint reported `closed` after the program shut it down.
    closed,
    /// Every peer's connection ended.
    finished,
    /// The horizon came first.
    horizon,
};

/// What a run did beside the events, which the check writes into the seed's trace.
pub const Record = struct {
    end: End = .horizon,
    end_ms: u64 = 0,
    closed: bool = false,
    shut_down: bool = false,
    /// Connections that took a slot an earlier connection held.
    reused: u32 = 0,
    /// TCP peers that waited for a free slot, and peers no slot served.
    accept_waits: u32 = 0,
    unserved: u32 = 0,
    /// The endpoint's datagrams to a peer that was driven no more.
    dropped: u32 = 0,
    /// The CRC-32 of every octet a peer wrote, every octet `send_stream` wrote and every datagram,
    /// each before the endpoint or a peer opened it in place.
    wire: std.hash.Crc32 = .init(),
};

pub const Storage = struct {
    endpoint_config: server.EndpointConfig,
    endpoint: Endpoint,
    ledger: ledger_module.Ledger,
    program: Program,
    tcp: tcp_module.Peers,
    quic: quic_module.Peers,
    /// The handle the run last saw in each QUIC slot, which tells a new connection from one it
    /// holds.
    quic_known: [limits.quic_slots]?server.ConnectionHandle,
    /// The TCP peers in the order they arrive, which the endpoint accepts them in.
    arrival: [limits.tcp_peers]u8,
    datagram: [quic.constants.datagram_len_max]u8,
    record: Record,
    server_random: Random,
    program_random: Random,
};

/// Runs `plan` from its first instant until it ends.
pub fn run(storage: *Storage, plan: *const Plan, seed: u64) Error!void {
    try start(storage, plan, seed);
    var now_ms: u64 = 0;
    // Bounded: each pass goes to a later instant, or ends the run.
    for (0..limits.instants_max) |_| {
        try settle(storage, plan, now_ms);
        if (storage.record.closed) return finish(storage, plan, .closed, now_ms);
        if (all_over(storage)) return finish(storage, plan, .finished, now_ms);
        const next_ms = try next_instant(storage, plan, now_ms) orelse return finish(storage, plan, .horizon, limits.horizon_ms);
        if (next_ms >= limits.horizon_ms) return finish(storage, plan, .horizon, limits.horizon_ms);
        assert(next_ms > now_ms);
        now_ms = next_ms;
    }
    return error.RunStalled;
}

fn start(storage: *Storage, plan: *const Plan, seed: u64) Error!void {
    storage.endpoint_config = .{
        .tls = .{
            .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
            .cookie_key = &identity.cookie_key,
            .ticket_key = null,
            .cpu = identity.cpu,
        },
        .idle_timeout_ms = limits.quic_idle_timeout_ms,
    };
    storage.server_random = Random.init(seed ^ limits.server_salt);
    storage.program_random = Random.init(seed ^ limits.program_salt);
    const source = tls.Random.init(&storage.server_random, tcp_module.fill);
    storage.endpoint.init(&storage.endpoint_config, source, identity.now_seconds, route_module.ns_of(plan, 0)) catch return error.ServerRefused;
    storage.ledger.init();
    storage.program.init(&storage.endpoint, &storage.ledger);
    try storage.tcp.init(seed);
    storage.quic.init(seed);
    storage.quic_known = @splat(null);
    storage.record = .{};
    order_arrivals(storage, plan);
}

/// The TCP peers sorted by the instant each arrives, the lower index first at one instant.
fn order_arrivals(storage: *Storage, plan: *const Plan) void {
    for (&storage.arrival, 0..) |*index, at| index.* = @intCast(at);
    // Bounded: an insertion sort of `tcp_peers` entries.
    for (1..limits.tcp_peers) |at| {
        var index = at;
        while (index > 0 and plan.tcp[storage.arrival[index]].arrive_ms < plan.tcp[storage.arrival[index - 1]].arrive_ms) : (index -= 1) {
            std.mem.swap(u8, &storage.arrival[index], &storage.arrival[index - 1]);
        }
    }
}

/// Makes passes at `now_ms` until one moves nothing, then checks P6 and P8.
fn settle(storage: *Storage, plan: *const Plan, now_ms: u64) Error!void {
    const now_ns = route_module.ns_of(plan, now_ms);
    storage.program.now_ms = now_ms;
    for (0..limits.passes_per_instant_max) |_| {
        try storage.program.on_instant(now_ns);
        const moved_in = try pass_in(storage, plan, now_ns, now_ms);
        const moved_out = try pass_out(storage, plan, now_ns, now_ms);
        if (!moved_in and !moved_out) return storage.program.quiescence(now_ns);
    }
    return error.RunStalled;
}

/// The first half of a pass: the shutdown, the TCP peers the endpoint accepts, and what every
/// peer writes, which the endpoint takes, and the events it reports.
fn pass_in(storage: *Storage, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    var moved = try shutdown_due(storage, plan, now_ns);
    if (try tcp_accept(storage, plan, now_ns, now_ms)) moved = true;
    if (try tcp_write(storage, plan, now_ns, now_ms)) moved = true;
    if (try tcp_give(storage, now_ns, now_ms)) moved = true;
    if (try quic_send(storage, plan, now_ns, now_ms)) moved = true;
    if (try route_module.drain(storage, now_ns, now_ms)) moved = true;
    return moved;
}

/// The second half: the program answers, makes a stale call now and then, reads the events that
/// follow, and writes the endpoint's octets and datagrams to the peers, which read them.
fn pass_out(storage: *Storage, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    var moved = try route_module.answer_all(storage);
    if (try stale_maybe(storage, now_ns, now_ms)) moved = true;
    if (try route_module.drain(storage, now_ns, now_ms)) moved = true;
    if (try datagrams_out(storage, now_ns, now_ms)) moved = true;
    if (try tcp_read(storage, plan, now_ns, now_ms)) moved = true;
    if (try quic_read(storage, plan, now_ns, now_ms)) moved = true;
    return moved;
}

fn shutdown_due(storage: *Storage, plan: *const Plan, now_ns: u64) Error!bool {
    const at_ms = plan.shutdown_ms orelse return false;
    if (storage.record.shut_down or storage.program.now_ms < at_ms) return false;
    storage.record.shut_down = true;
    try storage.program.shutdown(now_ns);
    return true;
}

/// The TCP peers that arrived join the queue, and the endpoint accepts the oldest while a slot is
/// free. After `shutdown` the endpoint accepts none, and a peer that waits is refused.
fn tcp_accept(storage: *Storage, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    for (storage.arrival) |index| {
        const peer = &storage.tcp.peers[index];
        const peer_plan = &plan.tcp[index];
        if (peer.state == .away and now_ms >= peer_plan.arrive_ms) peer.state = .waiting;
        if (peer.state != .waiting) continue;
        if (storage.ledger.shut_down) {
            // P1: after `shutdown` the endpoint accepts no socket.
            _ = try storage.program.accept(peer_plan.security, now_ns);
            peer.state = .refused;
            continue;
        }
        const handle = try storage.program.accept(peer_plan.security, now_ns) orelse {
            if (!peer.waited) storage.record.accept_waits += 1;
            peer.waited = true;
            return moved;
        };
        const connection = try storage.ledger.register(handle, .tcp, index, peer_plan.honest(), now_ms);
        connection.reads_slowly = peer_plan.behaviour.peer == .slow_reader;
        if (handle.generation > 1) storage.record.reused += 1;
        try storage.program.set_deadlines(handle, peer_plan.behaviour.deadlines);
        try storage.tcp.start(index, peer_plan, handle, now_ms);
        moved = true;
    }
    return moved;
}

/// Each served TCP peer writes what is due, cancels or closes as its overlay says, and closes its
/// socket once its client says so.
fn tcp_write(storage: *Storage, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    for (&storage.tcp.peers, 0..) |*peer, index| {
        if (peer.state != .served or peer.closed) continue;
        const peer_plan = &plan.tcp[index];
        if (Peer.played_by_client(peer_plan) and tcp_module.reset_due(peer, peer_plan, now_ms)) moved = true;
        if (try tcp_module.write(peer, peer_plan, now_ns, now_ms, &storage.record.wire)) moved = true;
        if (!tcp_module.closes(peer, peer_plan, now_ms)) continue;
        peer.closed = true;
        moved = true;
        const connection = storage.ledger.connection_of(peer.handle).?;
        if (connection.socket == .open) try storage.program.transport_closed(connection);
    }
    return moved;
}

/// The endpoint takes what each open socket delivered, which it may take in part: the rest stays
/// for the next pass.
fn tcp_give(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    for (&storage.tcp.peers) |*peer| {
        if (peer.state != .served) continue;
        if (try give(storage, peer, now_ns, now_ms)) moved = true;
    }
    return moved;
}

/// Passes the endpoint what one peer's socket holds, again until the endpoint takes nothing and
/// reports nothing, or the socket closes.
fn give(storage: *Storage, peer: *Peer, now_ns: u64, now_ms: u64) Error!bool {
    const connection = storage.ledger.connection_of(peer.handle).?;
    const stream = &peer.to_server;
    var moved = false;
    // Bounded: each call consumes an octet or reports an event, or ends the loop.
    for (0..limits.receives_per_stream_max) |_| {
        if (connection.socket != .open or stream.held().len == 0) return moved;
        const input: server.Input = .{ .stream = .{ .connection = peer.handle, .octets = stream.held() } };
        const received = try storage.program.receive(input, now_ns);
        stream.consumed += received.consumed;
        if (received.event) |reported| try route_module.route(storage, reported, now_ns, now_ms);
        if (received.consumed == 0 and received.event == null) return moved;
        moved = true;
    }
    return error.RunStalled;
}

/// Each QUIC peer that arrived acts, and the endpoint takes every datagram it writes that the run
/// does not drop. A datagram that starts a connection gives the peer its handle.
fn quic_send(storage: *Storage, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    for (&storage.quic.peers, 0..) |*peer, index| {
        const peer_plan = &plan.quic[index];
        if (try quic_module.arrive(peer, index, peer_plan, now_ns, now_ms)) moved = true;
        if (peer.state != .running) continue;
        if (try quic_module.act(peer, peer_plan, now_ns, now_ms)) moved = true;
        if (try send_datagrams(storage, index, peer_plan, now_ns, now_ms)) moved = true;
        if (peer.peer.mute_pending) peer.peer.muted = true;
        // A peer that owed its close sent it: it is driven no more.
        if (peer.closing) peer.state = .detached;
    }
    return moved;
}

fn send_datagrams(storage: *Storage, index: usize, peer_plan: *const plan_module.QuicPeer, now_ns: u64, now_ms: u64) Error!bool {
    const peer = &storage.quic.peers[index];
    var moved = false;
    // Bounded: a peer sends `datagrams_per_pass_max` datagrams in one pass at most.
    for (0..limits.datagrams_per_pass_max) |_| {
        const len = try peer.peer.send(&storage.datagram, now_ns) orelse break;
        moved = true;
        // A deaf peer's datagrams are dropped: the endpoint reads no acknowledgment from it.
        if (peer.peer.muted) continue;
        const octets = storage.datagram[0..len];
        storage.record.wire.update(octets);
        const received = try storage.program.receive(.{ .datagram = .{ .octets = octets, .from = peer.address } }, now_ns);
        try note_new_connection(storage, index, peer_plan, now_ms);
        if (received.event) |reported| try route_module.route(storage, reported, now_ns, now_ms);
    }
    return moved;
}

/// A QUIC slot that turned live, or that holds a later generation, holds the connection the
/// datagram of peer `index` just started. The program sets the peer's deadlines on it.
fn note_new_connection(storage: *Storage, index: usize, peer_plan: *const plan_module.QuicPeer, now_ms: u64) Error!void {
    for (&storage.quic_known, 0..) |*known, quic_index| {
        const slot = limits.tcp_slots + quic_index;
        if (!storage.endpoint.live[slot]) continue;
        const handle: server.ConnectionHandle = .{ .slot = @intCast(slot), .generation = storage.endpoint.generations[slot] };
        if (known.* != null and known.*.? == handle) continue;
        known.* = handle;
        storage.quic.peers[index].handle = handle;
        _ = try storage.ledger.register(handle, .quic, @intCast(index), peer_plan.honest(), now_ms);
        if (handle.generation > 1) storage.record.reused += 1;
        try storage.program.set_deadlines(handle, peer_plan.behaviour.deadlines);
    }
}

/// In one pass of `stale_call_one_in`, the program makes a call by an id or a handle that names
/// nothing any more. The event a stale `receive` reports is routed.
fn stale_maybe(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    if (storage.program_random.below(limits.stale_call_one_in) != 0) return false;
    const reported = try stale.call(&storage.program, &storage.program_random, now_ns) orelse return false;
    try route_module.route(storage, reported, now_ns, now_ms);
    return true;
}

/// The endpoint writes every datagram it owes into the link of the peer it names, and the peer
/// takes each one the link has carried by `now_ms`.
fn datagrams_out(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    // Bounded: the endpoint sends `datagrams_per_pass_max` datagrams in one pass at most.
    for (0..limits.datagrams_per_pass_max) |_| {
        const sent = try storage.program.send_datagram(&storage.datagram, now_ns) orelse break;
        moved = true;
        storage.record.wire.update(sent.octets);
        const index = storage.quic.index_of(&sent.to) orelse return error.DatagramUnaddressed;
        const peer = &storage.quic.peers[index];
        if (peer.state != .running) {
            storage.record.dropped += 1;
            continue;
        }
        peer.link.take(sent.octets, now_ms);
        _ = try quic_module.deliver(peer, now_ns, now_ms);
    }
    return moved;
}

/// Each served TCP peer reads what its socket delivered.
fn tcp_read(storage: *Storage, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    for (&storage.tcp.peers, 0..) |*peer, index| {
        if (peer.state != .served or peer.closed) continue;
        if (try tcp_module.read(peer, &plan.tcp[index], now_ns, now_ms)) moved = true;
    }
    return moved;
}

/// Each running QUIC peer reads what its link carried.
fn quic_read(storage: *Storage, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    for (&storage.quic.peers, 0..) |*peer, index| {
        if (peer.state != .running) continue;
        if (try quic_module.read(peer, &plan.quic[index], now_ns, now_ms)) moved = true;
    }
    return moved;
}

/// The next instant after `now_ms` something is due: the endpoint's deadline, the shutdown, or
/// what a peer does on its own.
fn next_instant(storage: *Storage, plan: *const Plan, now_ms: u64) Error!?u64 {
    var soonest: ?u64 = null;
    if (try storage.program.deadline_ns()) |at_ns| soonest = later_than(now_ms, quic_module.ms_of(plan.base_ms, at_ns));
    if (plan.shutdown_ms) |at_ms| {
        if (!storage.record.shut_down) soonest = earlier(soonest, later_than(now_ms, at_ms));
    }
    for (&storage.tcp.peers, &plan.tcp) |*peer, *peer_plan| {
        if (tcp_module.next_ms(peer, peer_plan, now_ms)) |at_ms| soonest = earlier(soonest, at_ms);
    }
    for (&storage.quic.peers, &plan.quic) |*peer, *peer_plan| {
        if (quic_module.next_ms(peer, peer_plan, plan.base_ms, now_ms)) |at_ms| soonest = earlier(soonest, at_ms);
    }
    const ledger = &storage.ledger;
    for (ledger.requests[0..ledger.requests_len]) |*request| {
        if (answer_module.due_ms(request, now_ms)) |at_ms| soonest = earlier(soonest, at_ms);
    }
    return soonest;
}

/// `at_ms`, or the instant after `now_ms` when `at_ms` has come.
fn later_than(now_ms: u64, at_ms: u64) u64 {
    return @max(at_ms, now_ms + 1);
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}

/// Whether every peer is over: each TCP peer's connection ended or the endpoint refused it, and
/// each QUIC peer's connection ended.
fn all_over(storage: *Storage) bool {
    for (&storage.tcp.peers) |*peer| {
        if (peer.state != .over and peer.state != .refused) return false;
    }
    for (&storage.quic.peers) |*peer| {
        if (!peer.ended) return false;
    }
    return true;
}

/// Notes how the run ended, and checks P4 once more: every connection the program holds that has
/// not ended is one the endpoint holds, and at the horizon only the one decision 110 leaves open.
fn finish(storage: *Storage, plan: *const Plan, end: End, end_ms: u64) Error!void {
    storage.record.end = end;
    storage.record.end_ms = end_ms;
    storage.record.unserved = unserved(storage);
    const ledger = &storage.ledger;
    for (ledger.connections[0..ledger.connections_len]) |*connection| {
        if (connection.ended) continue;
        const slot = connection.handle.slot;
        const held = storage.endpoint.live[slot] and storage.endpoint.generations[slot] == connection.handle.generation;
        if (!held) return storage.program.fail(error.EndedMissing, "finish", connection.handle, 0);
        if (end == .horizon and !outlasts_horizon(plan, connection)) return storage.program.fail(error.EndedMissing, "horizon", connection.handle, 0);
    }
}

/// The peers no slot served: one the endpoint refused after `shutdown`, one that waited or had not
/// arrived when the run ended, and a QUIC peer whose Initials found every slot taken.
fn unserved(storage: *const Storage) u32 {
    var count: u32 = 0;
    for (&storage.tcp.peers) |*peer| {
        if (peer.state != .served and peer.state != .over) count += 1;
    }
    for (&storage.quic.peers) |*peer| {
        if (peer.handle == null) count += 1;
    }
    return count;
}

/// Whether a connection may still run at the horizon. Decision 110's stream send meter waits while
/// the output holds octets, and an h2 PING's acknowledgment is octets, so an h2 peer that pings
/// every few seconds and never opens its stream's window is never cut. Design §8 step 21b.5 leaves
/// that to the owner; every other connection ends before the horizon.
fn outlasts_horizon(plan: *const Plan, connection: *const ledger_module.Connection) bool {
    if (connection.kind != .tcp) return false;
    const behaviour = &plan.tcp[connection.peer].behaviour;
    return behaviour.peer == .idle_pinger and behaviour.protocol == .h2;
}
