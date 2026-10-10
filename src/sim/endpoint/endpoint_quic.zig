//! The QUIC peers of the endpoint check (design §8 step 21b.5, decision 119): each a peer of the
//! h3 deadline check (`h3_deadline_peer.zig`) with connection IDs and an address of its own, so the
//! endpoint tells the peers apart (RFC 9000 §5.2), and the link that carries the endpoint's
//! datagrams to it (`h3_deadline_link.zig`). A resetting peer cancels its first request, and an
//! early-closing peer closes its connection (RFC 9000 §10.2). A peer that read the endpoint's close,
//! or closed its own, is driven no more.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const tls = @import("tls");
const h3 = @import("h3");
const quic = @import("quic");
const server = @import("server");
const peer_module = @import("../h3_deadline_peer.zig");
const script = @import("../h3_deadline_script.zig");
const link_module = @import("../h3_deadline_link.zig");
const plan_module = @import("endpoint_plan.zig");
const tcp_module = @import("endpoint_tcp.zig");

const Random = sim.Random;
const limits = sim.constants.endpoint;
const QuicPeer = plan_module.QuicPeer;

pub const Error = peer_module.Error;

/// Where a QUIC peer is: not yet arrived, running, or driven no more.
pub const State = enum { away, running, detached };

/// The octets every peer's client and original connection IDs are made of, the last octet of each
/// naming the peer, and the address every peer sends from, from a port of its own.
const client_octet: u8 = 0xc1;
const original_octet: u8 = 0x0d;
const address_octet: u8 = 0xc1;
const ipv4_len: usize = 4;

pub const Peer = struct {
    peer: peer_module.Peer,
    link: link_module.Link,
    address: server.Address,
    state: State,
    /// The connection the endpoint gave the peer, once it gave one, and whether it ended.
    handle: ?server.ConnectionHandle,
    ended: bool,
    started_ms: u64,
    /// When the endpoint read the peer's first request, and whether the peer cancelled it.
    first_read_ms: ?u64,
    reset_done: bool,
    /// When h3 started, and whether the peer owes its close.
    h3_started_ms: ?u64,
    closing: bool,
    random: Random,

    /// The peer's connection IDs, the last octet of each naming it.
    fn ids_of(index: usize) peer_module.Ids {
        var ids: peer_module.Ids = .{ .client = @splat(client_octet), .original = @splat(original_octet) };
        ids.client[peer_module.id_len - 1] = @intCast(index + 1);
        ids.original[peer_module.id_len - 1] = @intCast(index + 1);
        return ids;
    }
};

pub const Peers = struct {
    peers: [limits.quic_peers]Peer,

    pub fn init(peers: *Peers, seed: u64) void {
        for (&peers.peers, 0..) |*peer, index| {
            peer.state = .away;
            peer.handle = null;
            peer.ended = false;
            const octets: [ipv4_len]u8 = @splat(address_octet);
            peer.address = server.Address.of(&octets, limits.port_first + @as(u16, @intCast(index)));
            // QUIC peers draw after the TCP peers' salts.
            peer.random = Random.init(seed ^ limits.peer_salt ^ (limits.tcp_peers + index));
        }
    }

    /// The peer that sends from `address`, or null.
    pub fn index_of(peers: *Peers, address: *const server.Address) ?usize {
        for (&peers.peers, 0..) |*peer, index| {
            if (peer.address.eql(address)) return index;
        }
        return null;
    }
};

/// Starts the peer at `index` when it arrives, and returns whether it did.
pub fn arrive(peer: *Peer, index: usize, plan: *const QuicPeer, now_ns: u64, now_ms: u64) Error!bool {
    if (peer.state != .away or now_ms < plan.arrive_ms) return false;
    peer.state = .running;
    peer.started_ms = now_ms;
    peer.first_read_ms = null;
    peer.reset_done = false;
    peer.h3_started_ms = null;
    peer.closing = false;
    peer.link.init(plan.behaviour.link_rate);
    try peer.peer.start_with(&plan.behaviour, tls.Random.init(&peer.random, tcp_module.fill), now_ns, Peer.ids_of(index));
    return true;
}

/// The peer does what is due at `now_ms`: its QUIC timers, its script, and its overlay. Returns
/// whether it did anything.
pub fn act(peer: *Peer, plan: *const QuicPeer, now_ns: u64, now_ms: u64) Error!bool {
    assert(peer.state == .running);
    const client = &peer.peer;
    client.on_instant(now_ns);
    // RFC 9114 §5.2: a client that read a GOAWAY opens no more requests.
    var moved = if (client.goaway_ms == null)
        try script.act(client, &plan.behaviour, now_ns, now_ms)
    else
        script.finish_begun(client, &plan.behaviour, now_ms);
    if (client.h3_started and peer.h3_started_ms == null) peer.h3_started_ms = now_ms;
    moved = reset_due(peer, plan, now_ms) or moved;
    return close_due(peer, plan, now_ms) or moved;
}

/// The endpoint read request `number` of the peer's connection at `now_ms`. A reset counts from
/// its read of the peer's first request: one sent with the head, or before it arrived whole, leaves
/// the connection with no request, which the first-request deadline of decision 110 ends.
pub fn note_read(peer: *Peer, number: u64, now_ms: u64) void {
    const client = &peer.peer;
    if (peer.first_read_ms != null or client.fetches_len == 0 or client.fetches[0].id != number) return;
    peer.first_read_ms = now_ms;
}

/// A resetting peer cancels its first request once due (RFC 9114 §4.1.1).
fn reset_due(peer: *Peer, plan: *const QuicPeer, now_ms: u64) bool {
    const at_ms = reset_ms(peer, plan) orelse return false;
    if (now_ms < at_ms) return false;
    peer.reset_done = true;
    const fetch = &peer.peer.fetches[0];
    if (fetch.ended_ms != null or fetch.reset != null or !peer.peer.active()) return false;
    peer.peer.cancel(fetch);
    return true;
}

fn reset_ms(peer: *const Peer, plan: *const QuicPeer) ?u64 {
    if (plan.overlay != .resetting or peer.reset_done) return null;
    return (peer.first_read_ms orelse return null) + plan.reset_after_ms;
}

/// An early-closing peer closes its connection once due, with H3_NO_ERROR (RFC 9114 §8.1): its
/// next datagram carries the CONNECTION_CLOSE (RFC 9000 §10.2), and the run drives it no more.
fn close_due(peer: *Peer, plan: *const QuicPeer, now_ms: u64) bool {
    const at_ms = close_ms(peer, plan) orelse return false;
    if (now_ms < at_ms) return false;
    peer.closing = true;
    quic.connection_close.owe(&peer.peer.connection, .{
        .layer = .application,
        .error_code = h3.constants.error_no_error,
        .frame_type = null,
        .reason = "",
    });
    return true;
}

fn close_ms(peer: *const Peer, plan: *const QuicPeer) ?u64 {
    if (plan.overlay != .early_closing or peer.closing) return null;
    return (peer.h3_started_ms orelse return null) + plan.close_after_ms;
}

/// The peer takes each datagram the link has carried by `now_ms`, and returns whether one came.
pub fn deliver(peer: *Peer, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    // Bounded: the link holds `link_queue_len` datagrams.
    for (0..sim.constants.h3_deadline.link_queue_len) |_| {
        const octets = peer.link.next(now_ms) orelse break;
        moved = true;
        try peer.peer.receive(octets, now_ns, now_ms);
    }
    return moved;
}

/// The peer reads what arrived, as its plan's pace allows. One that read the endpoint's close is
/// driven no more. Returns whether it read anything.
pub fn read(peer: *Peer, plan: *const QuicPeer, now_ns: u64, now_ms: u64) Error!bool {
    assert(peer.state == .running);
    var moved = try deliver(peer, now_ns, now_ms);
    moved = try peer.peer.read(&plan.behaviour, now_ns, now_ms) or moved;
    if (peer.peer.close != null) peer.state = .detached;
    return moved;
}

/// The next instant after `now_ms` the peer does something on its own, or null.
pub fn next_ms(peer: *Peer, plan: *const QuicPeer, base_ms: u64, now_ms: u64) ?u64 {
    if (peer.state == .away) return @max(plan.arrive_ms, now_ms + 1);
    if (peer.state != .running) return null;
    const client = &peer.peer;
    var soonest: ?u64 = null;
    if (client.timer_ns()) |at_ns| soonest = earlier(soonest, ms_of(base_ms, at_ns));
    if (client.next_act_ms) |at_ms| soonest = earlier(soonest, at_ms);
    if (peer.link.arrival_ms()) |at_ms| soonest = earlier(soonest, at_ms);
    const reads = plan.behaviour.reads_paced() and client.awaits_response() and client.active();
    if (reads) soonest = earlier(soonest, client.next_read_ms);
    if (reset_ms(peer, plan)) |at_ms| soonest = earlier(soonest, at_ms);
    if (close_ms(peer, plan)) |at_ms| soonest = earlier(soonest, at_ms);
    const at_ms = soonest orelse return null;
    return @max(at_ms, now_ms + 1);
}

/// The first whole millisecond of the run at or after `at_ns`.
pub fn ms_of(base_ms: u64, at_ns: u64) u64 {
    const at_ms = std.math.divCeil(u64, at_ns, limits.ns_per_ms) catch unreachable;
    assert(at_ms >= base_ms);
    return at_ms - base_ms;
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}
