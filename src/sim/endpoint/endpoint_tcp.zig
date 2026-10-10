//! The TCP peers of the endpoint check (design §8 step 21b.5, decision 119): colibri's client in
//! cleartext or over TLS for an honest peer, and for every other a hostile peer of the deadline
//! check (`deadline_peer.zig`), which writes its script in cleartext. Each peer has a socket of two
//! directions. The peer writes into one at its plan's pace and reads the other at its plan's pace.
//! The run passes the endpoint what the peer wrote, and writes what the endpoint owes the peer into
//! the other at once, so the socket is never full (P7).
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

/// The ALPN IDs of RFC 9113 §3.2 ("h2") and RFC 9112 §12.4 ("http/1.1"). Each peer offers its
/// plan's protocol alone, so ALPN selects it (RFC 7301 §3.2).
const alpn_h2 = [_][]const u8{"h2"};
const alpn_h11 = [_][]const u8{"http/1.1"};

/// The client configurations a peer starts from: one for each protocol in cleartext and over TLS.
const Way = enum { cleartext_h11, cleartext_h2, tls_h11, tls_h2 };

pub const Peer = struct {
    state: State,
    handle: server.ConnectionHandle,
    /// Whether the peer waited for a free slot, and when the endpoint accepted it.
    waited: bool,
    accepted_ms: ?u64,
    /// Whether the peer closes its socket no more: it closed it, or the endpoint did.
    closed: bool,
    client: client.Connection,
    hostile: deadline_peer.Hostile,
    exchanges: [exchanges_max]client.HttpExchange,
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
    tls_h2: tls.record.ClientConfig,
    tls_h11: tls.record.ClientConfig,
    configs: [std.enums.values(Way).len]client.Config,
    /// The content an uploading peer's requests carry.
    upload: [sim.constants.deadline.upload_len_max]u8,
    peers: [limits.tcp_peers]Peer,

    /// The client configurations, and every peer away.
    pub fn init(peers: *Peers, seed: u64) Error!void {
        peers.tls_h2.init(trust(&alpn_h2)) catch return error.PeerFailed;
        peers.tls_h11.init(trust(&alpn_h11)) catch return error.PeerFailed;
        peers.configs[@intFromEnum(Way.cleartext_h11)] = .{ .authority = identity.authority, .versions = .{ .h2 = false } };
        peers.configs[@intFromEnum(Way.cleartext_h2)] = .{ .authority = identity.authority, .versions = .{ .h11 = false } };
        peers.configs[@intFromEnum(Way.tls_h11)] = .{ .authority = identity.authority, .tls = &peers.tls_h11 };
        peers.configs[@intFromEnum(Way.tls_h2)] = .{ .authority = identity.authority, .tls = &peers.tls_h2 };
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

    /// Starts the peer at `index`, which the endpoint accepted as `handle` at `now_ms`.
    pub fn start(peers: *Peers, index: usize, plan: *const TcpPeer, handle: server.ConnectionHandle, now_ms: u64) Error!void {
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
        if (!Peer.played_by_client(plan)) return peer.hostile.start(&plan.behaviour);
        const config = &peers.configs[@intFromEnum(way_of(plan))];
        peer.client.init(config, tls.Random.init(&peer.random, fill), identity.now_seconds, null) catch return error.PeerFailed;
        const behaviour = &plan.behaviour;
        for (peer.exchanges[0..behaviour.exchanges_len], 0..) |*exchange, exchange_index| {
            exchange.* = .{ .method = "GET", .path = "/", .body = &peer.bodies[exchange_index] };
            if (behaviour.peer != .upload) continue;
            exchange.method = "POST";
            exchange.content = peers.upload[0..behaviour.upload_len[exchange_index]];
        }
        const at_once = if (one_at_a_time(plan)) 1 else behaviour.exchanges_len;
        for (0..at_once) |_| try request_next(peer);
    }
};

/// Whether the peer's exchanges go one at a time: an upload's, so each request's body has the whole
/// link.
fn one_at_a_time(plan: *const TcpPeer) bool {
    return plan.behaviour.peer == .upload;
}

fn trust(alpn: []const []const u8) tls.Client {
    return .{
        .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = identity.authority } },
        .alpn = alpn,
        .cpu = identity.cpu,
    };
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
    peer.ids[index] = try peer.client.request(&peer.exchanges[index]);
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
        stream.written += peer.client.send(stream.free(), now_ns);
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
        const received = peer.client.receive(stream.held(), now_ns);
        stream.consumed += received.consumed;
        const reported = received.event orelse return moved or received.consumed > 0;
        moved = true;
        if (reported != .finished) continue;
        if (reported.finished.exchange.outcome == .response) peer.exchanges_done += 1;
        const exchanges_left = one_at_a_time(plan) and peer.exchanges_requested < plan.behaviour.exchanges_len;
        if (exchanges_left) try request_next(peer);
    }
    return moved;
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
    const exchange = &peer.exchanges[plan.reset_exchange];
    if (exchange.outcome != .pending) return false;
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
/// and colibri's client once it says so and the endpoint consumed every octet it wrote.
pub fn closes(peer: *Peer, plan: *const TcpPeer, now_ms: u64) bool {
    if (plan.overlay == .early_closing and now_ms >= close_ms(peer, plan)) return true;
    if (!Peer.played_by_client(plan) or !peer.client.should_close()) return false;
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
