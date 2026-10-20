//! The TCP peers of the endpoint check (design §8 step 21b.5, decision 119). Each honest peer is
//! colibri's client: a `client.Pool` with TCP alone, in cleartext or over TLS (decision 120,
//! design §8 step 21c). Every other is a hostile peer of the deadline check (`deadline_peer.zig`),
//! which writes its script in cleartext. Each peer has a socket of two directions. The peer writes
//! into one at its plan's pace and reads the other at its plan's pace. The run passes the endpoint
//! what the peer wrote, and writes what the endpoint owes the peer into the other at once, so the
//! socket is never full (P7).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const tls = @import("tls");
const client = @import("client");
const server = @import("server");
const identity = @import("../client_trace_identity.zig");
const deadline_plan = @import("../deadline_plan.zig");
const deadline_peer = @import("../deadline_peer.zig");
const plan_module = @import("endpoint_plan.zig");

const Random = sim.Random;
const limits = sim.constants.endpoint;
const exchanges_max = sim.constants.deadline.exchanges_max;
const TcpPeer = plan_module.TcpPeer;

pub const Error = client.RequestError || deadline_peer.Error || error{
    /// colibri's client refused to start, or its TLS configuration.
    PeerFailed,
};

/// One direction of a socket: written at the back, delivered to the reader, consumed from the
/// front. Nothing is taken out, so every offset into it holds for the whole run.
pub fn Stream(comptime len: usize) type {
    return struct {
        const Self = @This();

        octets: [len]u8,
        written: usize,
        delivered: usize,
        consumed: usize,

        pub fn reset(stream: *Self) void {
            stream.written = 0;
            stream.delivered = 0;
            stream.consumed = 0;
        }

        pub fn free(stream: *Self) []u8 {
            return stream.octets[stream.written..];
        }

        /// What the reader was delivered and has not consumed.
        pub fn held(stream: *Self) []u8 {
            return stream.octets[stream.consumed..stream.delivered];
        }

        /// Delivers up to `count` octets written and not yet delivered, and returns whether any
        /// moved.
        pub fn deliver(stream: *Self, count: usize) bool {
            const moved = @min(count, stream.written - stream.delivered);
            stream.delivered += moved;
            return moved > 0;
        }
    };
}

/// Where a TCP peer is: not yet arrived, waiting for the endpoint to accept it, served, refused
/// after the endpoint shut down, or over, its connection ended.
pub const State = enum { away, waiting, served, refused, over };

/// The pool configurations a peer starts from: one for each protocol in cleartext and over TLS.
/// Each allows its plan's protocol alone, so over TLS the pool offers the ALPN ID of RFC 9113
/// §3.2 ("h2") or of RFC 9112 §12.4 ("http/1.1") alone, and ALPN selects it (RFC 7301 §3.2).
const Way = enum { cleartext_h11, cleartext_h2, tls_h11, tls_h2 };

/// The endpoint's address and port, which each pool names when it asks for its socket. The run
/// has no network, so nothing else reads them.
const ipv4_len: usize = 4;
const endpoint_octet: u8 = 0x0a;
const endpoint_port: u16 = 443;

pub const Peer = struct {
    state: State,
    handle: server.ConnectionHandle,
    /// Whether the peer waited for a free slot, and when the endpoint accepted it.
    waited: bool,
    accepted_ms: ?u64,
    /// Whether the peer closes its socket no more: it closed it, or the endpoint did.
    closed: bool,
    /// colibri's client, a pool that opens TCP alone, and whether it reported `close`: its
    /// connection is over and wrote what it owed, so the peer closes its socket.
    client: client.Pool,
    client_memory: [client.Pool.memory_bytes(.{})]u8 align(client.Pool.memory_alignment),
    /// The connection the pool's `open` named (decision 125).
    connection: client.ConnectionHandle,
    close_reported: bool,
    hostile: deadline_peer.Hostile,
    /// Each exchange's request and response, by index (decision 124).
    requests: [exchanges_max]client.Request,
    responses: [exchanges_max]client.Response,
    ids: [exchanges_max]?client.Id,
    /// When the endpoint read each of the peer's first requests, and how many it read.
    read_ms: [exchanges_max]u64,
    reads: u8,
    bodies: [exchanges_max][limits.answer_long_len_max]u8,
    exchanges_requested: u8,
    exchanges_done: u8,
    reset_done: bool,
    to_server: Stream(limits.to_server_len),
    to_client: Stream(limits.to_client_len),
    next_piece_ms: u64,
    next_read_ms: u64,
    random: Random,

    /// Whether colibri's client plays the peer.
    pub fn played_by_client(plan: *const TcpPeer) bool {
        return plan.behaviour.honest();
    }

    /// The instant into the peer's connection, from the instant the endpoint accepted it, in
    /// milliseconds: what a hostile peer's script counts from.
    fn connection_ms(peer: *const Peer, now_ms: u64) u64 {
        return now_ms - peer.accepted_ms.?;
    }
};

pub const Peers = struct {
    /// The one address each pool opens its socket to.
    addresses: [1]client.Address,
    configs: [std.enums.values(Way).len]client.Config,
    /// The content an uploading peer's requests carry.
    upload: [sim.constants.deadline.upload_len_max]u8,
    peers: [limits.tcp_peers]Peer,

    /// The pool configurations, and every peer away.
    pub fn init(peers: *Peers, seed: u64) void {
        const octets: [ipv4_len]u8 = @splat(endpoint_octet);
        peers.addresses = .{client.Address.of(&octets, 0)};
        // One TLS value serves both protocols: the pool names the ALPN ID `versions` allows.
        const trust: tls.Client = .{
            .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = identity.authority } },
            .cpu = identity.cpu,
        };
        peers.configs[@intFromEnum(Way.cleartext_h11)] = .{ .authority = identity.authority, .versions = .{ .h2 = false } };
        peers.configs[@intFromEnum(Way.cleartext_h2)] = .{ .authority = identity.authority, .versions = .{ .h11 = false } };
        peers.configs[@intFromEnum(Way.tls_h11)] = .{ .authority = identity.authority, .versions = .{ .h2 = false }, .tls = trust };
        peers.configs[@intFromEnum(Way.tls_h2)] = .{ .authority = identity.authority, .versions = .{ .h11 = false }, .tls = trust };
        for (&peers.upload, 0..) |*octet, index| octet.* = letters[index % letters.len];
        for (&peers.peers, 0..) |*peer, index| {
            peer.state = .away;
            peer.waited = false;
            peer.accepted_ms = null;
            peer.closed = false;
            peer.exchanges_done = 0;
            peer.random = Random.init(seed ^ limits.peer_salt ^ index);
        }
    }

    /// Starts the peer at `index`, which the endpoint accepted as `handle` at `now_ms`, the instant
    /// `now_ns` on the endpoint's clock.
    pub fn start(peers: *Peers, index: usize, plan: *const TcpPeer, handle: server.ConnectionHandle, now_ns: u64, now_ms: u64) Error!void {
        const peer = &peers.peers[index];
        assert(peer.state == .waiting);
        peer.state = .served;
        peer.handle = handle;
        peer.accepted_ms = now_ms;
        peer.to_server.reset();
        peer.to_client.reset();
        peer.next_piece_ms = now_ms;
        peer.next_read_ms = now_ms;
        peer.exchanges_requested = 0;
        peer.exchanges_done = 0;
        peer.reads = 0;
        peer.reset_done = false;
        peer.ids = @splat(null);
        peer.close_reported = false;
        if (!Peer.played_by_client(plan)) return peer.hostile.start(&plan.behaviour);
        const config = &peers.configs[@intFromEnum(way_of(plan))];
        // TCP alone: the pool is given no receive pool, so it offers no QUIC.
        peer.client.init(&peer.client_memory, config, .{ .addresses = &peers.addresses, .port = endpoint_port }, .{}, null) catch return error.PeerFailed;
        // Generation 0 names no connection until the pool's `open`.
        peer.connection = .{ .slot = 0, .generation = 0 };
        const behaviour = &plan.behaviour;
        const count = behaviour.exchanges_len;
        for (peer.requests[0..count], peer.responses[0..count], 0..) |*message, *response, exchange_index| {
            message.* = .{ .method = "GET", .path = "/" };
            response.* = .{ .body = &peer.bodies[exchange_index] };
            if (behaviour.peer != .upload) continue;
            message.method = "POST";
            message.content = peers.upload[0..behaviour.upload_len[exchange_index]];
        }
        const at_once = if (one_at_a_time(plan)) 1 else behaviour.exchanges_len;
        for (0..at_once) |_| try request_next(peer);
        try connect(peer, now_ns);
    }
};

/// The pool asks for its socket, which the endpoint accepted already, and the peer starts the
/// connection on it. In cleartext the connection owes `connected` from its start, and the pool
/// hands it the exchanges as it reports it, so the peer's first write carries them. Over TLS the
/// read that completes the handshake reports it, in `read`. Either way the pool then asks for a
/// `send` of what the connection owes (decision 125), which the peer's writes take.
fn connect(peer: *Peer, now_ns: u64) Error!void {
    const asked = peer.client.receive(.none, now_ns);
    assert(asked.event.?.open.transport == .tcp);
    peer.connection = asked.event.?.open.connection;
    peer.client.start_tcp(peer.connection, tls.Random.init(&peer.random, fill), identity.now_seconds, null) catch return error.PeerFailed;
    // Bounded: `connected` in cleartext, and one `send`.
    for (0..connect_events_max + 1) |_| {
        const reported = peer.client.receive(.none, now_ns).event orelse return;
        assert(reported == .connected or reported == .send);
    }
    unreachable;
}

/// The events of a connection's start with no octet read: `connected` in cleartext, and `send`.
const connect_events_max = 2;

/// Whether the peer's exchanges go one at a time: an upload's, so each request's body has the whole
/// link.
fn one_at_a_time(plan: *const TcpPeer) bool {
    return plan.behaviour.peer == .upload;
}

/// How a peer's client speaks: in cleartext the plan's protocol alone, which the endpoint chooses
/// from the client's first octets (RFC 9113 §3.3), and over TLS the plan's protocol alone, which
/// ALPN selects.
fn way_of(plan: *const TcpPeer) Way {
    const h2 = plan.behaviour.protocol == .h2;
    return switch (plan.security) {
        .cleartext => if (h2) .cleartext_h2 else .cleartext_h11,
        .tls => if (h2) .tls_h2 else .tls_h11,
    };
}

/// The name of the way a peer speaks, for the trace.
pub fn kind_name(plan: *const TcpPeer) []const u8 {
    return switch (way_of(plan)) {
        .cleartext_h11 => "tcp-cleartext-h11",
        .cleartext_h2 => "tcp-cleartext-h2",
        .tls_h11 => "tcp-tls-h11",
        .tls_h2 => "tcp-tls-h2",
    };
}

/// Gives colibri's client its next exchange.
fn request_next(peer: *Peer) Error!void {
    const index = peer.exchanges_requested;
    peer.ids[index] = try peer.client.request(&peer.requests[index], &peer.responses[index]);
    peer.exchanges_requested += 1;
}

/// The endpoint read a request of the peer's connection at `now_ms`.
pub fn note_read(peer: *Peer, now_ms: u64) void {
    if (peer.reads == exchanges_max) return;
    peer.read_ms[peer.reads] = now_ms;
    peer.reads += 1;
}

/// The octets of each upload: letters alone.
const letters = "abcdefghijklmnopqrstuvwxyz";

pub fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}

/// The peer writes what is due at `now_ms`, each octet into `wire` as it writes it, and what it
/// wrote is delivered as its pace allows. Returns whether anything moved.
pub fn write(peer: *Peer, plan: *const TcpPeer, now_ns: u64, now_ms: u64, wire: *std.hash.Crc32) Error!bool {
    assert(peer.state == .served and !peer.closed);
    const stream = &peer.to_server;
    const before = stream.written;
    if (Peer.played_by_client(plan)) {
        stream.written += peer.client.send_stream(peer.connection, stream.free(), now_ns);
    } else {
        try write_script(peer, plan, now_ms);
    }
    wire.update(stream.octets[before..stream.written]);
    const behaviour = &plan.behaviour;
    if (!behaviour.paced()) return stream.deliver(stream.written) or stream.written > before;
    if (now_ms < peer.next_piece_ms or stream.written == stream.delivered) return stream.written > before;
    peer.next_piece_ms = now_ms + behaviour.gap_ms;
    return stream.deliver(behaviour.piece_len);
}

/// A hostile peer writes the pieces of its script that are due, and the acknowledgments of the
/// SETTINGS it read. A silent peer acknowledges nothing.
fn write_script(peer: *Peer, plan: *const TcpPeer, now_ms: u64) Error!void {
    const stream = &peer.to_server;
    // Bounded: each pass takes one piece of the script.
    for (0..sim.constants.deadline.pieces_max) |_| {
        const piece = peer.hostile.due(peer.connection_ms(now_ms)) orelse break;
        @memcpy(stream.free()[0..piece.len], piece);
        stream.written += piece.len;
    }
    if (plan.behaviour.peer != .silent) stream.written += try peer.hostile.write_acks(stream.free());
}

/// The peer reads what the endpoint wrote, as its pace allows: colibri's client reads its
/// responses, and a hostile h2 peer the frames it acknowledges. The next exchange of a peer whose
/// exchanges go one at a time starts when one finishes. Returns whether anything moved.
pub fn read(peer: *Peer, plan: *const TcpPeer, now_ns: u64, now_ms: u64) Error!bool {
    assert(peer.state == .served and !peer.closed);
    const stream = &peer.to_client;
    var moved = read_socket(peer, plan, now_ms);
    if (!Peer.played_by_client(plan)) {
        const reads_frames = plan.behaviour.protocol == .h2 and plan.security == .cleartext;
        if (reads_frames) peer.hostile.read_h2(stream.octets[0..stream.delivered], peer.connection_ms(now_ms));
        return moved;
    }
    // Bounded: each pass consumes an octet or reports an event.
    for (0..limits.to_client_len + limits.events_per_pass_max) |_| {
        const received = peer.client.receive(.{ .stream = .{ .connection = peer.connection, .octets = stream.held() } }, now_ns);
        stream.consumed += received.consumed;
        const reported = received.event orelse return moved or received.consumed > 0;
        if (try on_event(peer, plan, reported)) moved = true;
    }
    return moved;
}

/// What the peer does with an event of its pool. Returns whether the event counts as something
/// that moved: what the connection reports does, and what the pool says of the socket does not.
fn on_event(peer: *Peer, plan: *const TcpPeer, reported: client.Event) Error!bool {
    switch (reported) {
        // A peer has one socket, and `connect` started the one connection it carries. The peer
        // opens no other, so each exchange that waits for one ends refused.
        .open => |asked| {
            assert(asked.transport == .tcp);
            peer.client.transport_closed(asked.connection);
            return false;
        },
        .close => |connection| {
            assert(connection.slot == peer.connection.slot);
            peer.close_reported = true;
            return false;
        },
        // The peer writes what the pool owes as its pace allows, so the `send` moves nothing.
        .send => return false,
        .connected, .ticket => return true,
        .finished => |finished| {
            if (finished.response.outcome == .response) peer.exchanges_done += 1;
            const exchanges_left = one_at_a_time(plan) and peer.exchanges_requested < plan.behaviour.exchanges_len;
            if (exchanges_left) try request_next(peer);
            return true;
        },
        // The peer never shuts its pool down.
        .closed => unreachable,
    }
}

/// What the socket delivers to the peer: all at once, a piece every gap when it reads slowly, or
/// nothing.
fn read_socket(peer: *Peer, plan: *const TcpPeer, now_ms: u64) bool {
    const stream = &peer.to_client;
    const behaviour = &plan.behaviour;
    if (behaviour.reads_none()) return false;
    if (!behaviour.reads_paced()) return stream.deliver(stream.written);
    if (now_ms < peer.next_read_ms or stream.written == stream.delivered) return false;
    peer.next_read_ms = now_ms + behaviour.read_gap_ms;
    return stream.deliver(behaviour.read_len);
}

/// A resetting peer cancels its exchange once due: h2 resets its stream (RFC 9113 §6.4), and h11
/// drops its response or ends the connection. Returns whether it did.
pub fn reset_due(peer: *Peer, plan: *const TcpPeer, now_ms: u64) bool {
    const at_ms = reset_ms(peer, plan) orelse return false;
    if (now_ms < at_ms) return false;
    peer.reset_done = true;
    if (peer.responses[plan.reset_exchange].outcome != .pending) return false;
    peer.client.cancel(peer.ids[plan.reset_exchange].?);
    return true;
}

/// The instant a resetting peer cancels its exchange, once the endpoint read its request: one
/// cancelled before its head went out leaves the connection with no request, which the
/// first-request deadline of decision 110 ends.
fn reset_ms(peer: *const Peer, plan: *const TcpPeer) ?u64 {
    if (plan.overlay != .resetting or peer.reset_done) return null;
    if (plan.reset_exchange >= peer.reads) return null;
    return peer.read_ms[plan.reset_exchange] + plan.reset_after_ms;
}

/// Whether the peer closes its socket at `now_ms`: an early-closing peer once its delay passed,
/// and colibri's client once its pool reported `close` and the endpoint consumed every octet
/// it wrote.
pub fn closes(peer: *Peer, plan: *const TcpPeer, now_ms: u64) bool {
    if (plan.overlay == .early_closing and now_ms >= close_ms(peer, plan)) return true;
    if (!Peer.played_by_client(plan) or !peer.close_reported) return false;
    return peer.to_server.consumed == peer.to_server.written;
}

fn close_ms(peer: *const Peer, plan: *const TcpPeer) u64 {
    return peer.accepted_ms.? + plan.close_after_ms;
}

/// The next instant after `now_ms` the peer does something on its own, or null.
pub fn next_ms(peer: *const Peer, plan: *const TcpPeer, now_ms: u64) ?u64 {
    var soonest: ?u64 = null;
    if (peer.state == .away) return @max(plan.arrive_ms, now_ms + 1);
    if (peer.state != .served or peer.closed) return null;
    if (!Peer.played_by_client(plan)) {
        if (peer.hostile.next_ms()) |at_ms| soonest = earlier(soonest, peer.accepted_ms.? + at_ms);
    }
    const behaviour = &plan.behaviour;
    const to_server = &peer.to_server;
    if (behaviour.paced() and to_server.written > to_server.delivered) soonest = earlier(soonest, peer.next_piece_ms);
    const to_client = &peer.to_client;
    if (behaviour.reads_paced() and to_client.written > to_client.delivered) soonest = earlier(soonest, peer.next_read_ms);
    if (reset_ms(peer, plan)) |at_ms| soonest = earlier(soonest, at_ms);
    if (plan.overlay == .early_closing) soonest = earlier(soonest, close_ms(peer, plan));
    const at_ms = soonest orelse return null;
    return @max(at_ms, now_ms + 1);
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}

comptime {
    // Every answer to every exchange of a peer, with the TLS handshake and h2's own frames, fits
    // the socket toward it, with room for one more call of `send_stream` (P7).
    assert(limits.to_client_len >= exchanges_max * (limits.answer_long_len_max + limits.answer_slack_len) +
        limits.server_output_slack_len + server.constants.output_len);
    assert(limits.to_client_len / server.constants.output_len + 1 <= limits.sends_per_event_max);
}
