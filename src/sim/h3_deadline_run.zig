//! One run of the h3 deadline check (`h3_deadline_check.zig`, decision 110 as amended): a server
//! `Endpoint` that holds one QUIC connection, the application that answers its requests
//! (`h3_deadline_app.zig`), and the peer of the seed's plan (`h3_deadline_peer.zig`), in simulated
//! time. At each instant the run moves datagrams both ways until nothing moves, then goes to the
//! next instant something is due: an action or a read of the peer's, a timer of either side's
//! QUIC, an answer of the application's, or a deadline of the server's. A run ends when the peer
//! reads the server's CONNECTION_CLOSE, or at the horizon with the connection still open.
//!
//! The peer's datagrams arrive at the instant it wrote them, and the run drops those of a muted
//! peer. The server's go through the plan's link (`h3_deadline_link.zig`), which most plans give
//! no rate.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const tls = @import("tls");
const server = @import("server");
const identity = @import("client_trace_identity.zig");
const plan_module = @import("h3_deadline_plan.zig");
const peer_module = @import("h3_deadline_peer.zig");
const script = @import("h3_deadline_script.zig");
const app_module = @import("h3_deadline_app.zig");
const link_module = @import("h3_deadline_link.zig");

const Random = sim.Random;
const limits = sim.constants.h3_deadline;
const Plan = plan_module.Plan;
const Peer = peer_module.Peer;
pub const Close = peer_module.Close;

pub const Error = peer_module.Error || app_module.Error || error{
    /// chapulin refused the server's identity, or the endpoint the plan's limits.
    ServerRefused,
    /// The server failed the connection on what an honest peer sent.
    ExchangeRefused,
    /// The run visited `instants_max` instants, or an instant did not settle.
    RunStalled,
};

/// How a run ended.
pub const End = enum {
    /// The peer read the server's CONNECTION_CLOSE.
    closed,
    /// The horizon came with the connection still open.
    held,
};

/// The requests of a peer the record keeps the answers to: the two a hostile peer makes at most
/// before the server ends it.
pub const kept_fetches: usize = 2;

/// What the server did to one request, as the peer saw it.
pub const Seen = struct {
    status: ?u16 = null,
    status_ms: ?u64 = null,
    reset: ?u64 = null,
    reset_ms: ?u64 = null,
    ended_ms: ?u64 = null,
};

/// What a run did, which the check verifies and writes into the seed's trace.
pub const Record = struct {
    end: End,
    end_ms: u64,
    /// The requests the application read, answered, and was told were done or cancelled.
    app: app_module.Application,
    /// Exchanges an honest peer ended with a whole response.
    exchanges_done: u8,
    /// The requests the peer opened, and what it saw of the first ones.
    requests_opened: u32,
    seen: [kept_fetches]Seen,
    /// The server's CONNECTION_CLOSE as the peer read it.
    close: ?peer_module.Close,
    /// The instant the peer read the server's GOAWAY, when it read one (RFC 9114 §5.2).
    goaway_ms: ?u64,
    /// Why the server closed the connection on its own, if it did (decision 110).
    close_reason: ?server.CloseReason,
    /// The datagrams the link dropped.
    dropped: u32,
    /// The CRC-32 of every datagram the endpoint took and wrote, in the order it did: what the
    /// wire carried, apart from what the application reads of it.
    wire: std.hash.Crc32,
};

const Endpoint = app_module.Endpoint;
const alpn_h3 = [_][]const u8{"h3"};
/// Where the peer sends from, which the endpoint reads off each datagram (decision 72).
const ipv4_len: usize = 4;
const peer_octet: u8 = 0xc1;
const peer_octets: [ipv4_len]u8 = @splat(peer_octet);
const peer_port: u16 = 50_000;

pub const Storage = struct {
    server_tls: tls.quic.ServerConfig,
    quic_config: server.QuicConfig,
    endpoint_config: server.EndpointConfig,
    endpoint: Endpoint,
    /// The connection's `ended`, once the endpoint reported it.
    ended: ?server.Ended,
    peer: Peer,
    link: link_module.Link,
    datagram: [quic.constants.datagram_len_max]u8,
    /// The content the application's answers carry.
    content: [limits.read_content_len_max]u8,
    record: Record,
    server_random: Random,
    peer_random: Random,
};

/// Runs `plan` from its first instant until the peer reads the server's close or the horizon
/// comes.
pub fn run(storage: *Storage, plan: *const Plan, seed: u64) Error!void {
    try start(storage, plan, seed);
    var now_ms: u64 = 0;
    // Bounded: each pass goes to a later instant, or ends the run.
    for (0..limits.instants_max) |_| {
        try settle(storage, plan, now_ms);
        if (storage.peer.close != null) return finish(storage, plan, .closed, now_ms);
        const next_ms = next_instant(storage, plan, now_ms) orelse return finish(storage, plan, .held, limits.horizon_ms);
        if (next_ms >= limits.horizon_ms) return finish(storage, plan, .held, limits.horizon_ms);
        assert(next_ms > now_ms);
        now_ms = next_ms;
    }
    return error.RunStalled;
}

fn start(storage: *Storage, plan: *const Plan, seed: u64) Error!void {
    storage.server_tls.init(.{
        .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
        .cookie_key = &identity.cookie_key,
        .ticket_key = null,
        .alpn = &alpn_h3,
        .cpu = identity.cpu,
    }) catch return error.ServerRefused;
    storage.quic_config = .{
        .tls = &storage.server_tls,
        .idle_timeout_ms = limits.quic_idle_timeout_ms,
        .deadlines = plan.deadlines,
    };
    storage.endpoint_config = .{ .quic = &storage.quic_config };
    storage.server_random = Random.init(seed);
    storage.peer_random = Random.init(~seed);
    const now_ns = ns_of(plan, 0);
    // Decision 110 as amended: an endpoint refuses limits a connection would refuse.
    storage.endpoint.init(&storage.endpoint_config, tls.Random.init(&storage.server_random, fill), identity.now_seconds, now_ns) catch return error.ServerRefused;
    storage.ended = null;
    storage.link.init(plan.link_rate);
    try storage.peer.start(plan, tls.Random.init(&storage.peer_random, fill), now_ns);
    for (&storage.content, 0..) |*octet, index| octet.* = content_letters[index % content_letters.len];
    storage.record = .{
        .wire = .init(),
        .end = .held,
        .end_ms = 0,
        .app = undefined,
        .exchanges_done = 0,
        .requests_opened = 0,
        .seen = @splat(.{}),
        .close = null,
        .goaway_ms = null,
        .close_reason = null,
        .dropped = 0,
    };
    storage.record.app.init();
}

/// The octets of each answer's content: letters alone.
const content_letters = "abcdefghijklmnopqrstuvwxyz";

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}

/// The instant `ms` milliseconds into the run, from its base, in nanoseconds.
fn ns_of(plan: *const Plan, ms: u64) u64 {
    return (plan.base_ms + ms) * limits.ns_per_ms;
}

/// The first whole millisecond of the run at or after `at_ns`.
fn ms_of(plan: *const Plan, at_ns: u64) u64 {
    const at_ms = std.math.divCeil(u64, at_ns, limits.ns_per_ms) catch unreachable;
    assert(at_ms >= plan.base_ms);
    return at_ms - plan.base_ms;
}

/// Moves datagrams both ways at `now_ms` until nothing moves, after each side's caller hands it
/// the instant, as it does whenever it wakes (decision 110).
fn settle(storage: *Storage, plan: *const Plan, now_ms: u64) Error!void {
    const now_ns = ns_of(plan, now_ms);
    for (0..limits.passes_per_instant_max) |_| {
        storage.endpoint.on_instant(now_ns);
        storage.peer.on_instant(now_ns);
        var moved = try script.act(&storage.peer, plan, now_ns, now_ms);
        moved = try peer_send(storage, now_ns, now_ms) or moved;
        moved = try server_read(storage, now_ns, now_ms) or moved;
        // The endpoint notes that colibri failed the connection, and reports it with `ended`. A
        // deadline or a limit may end a hostile peer's connection; an honest peer's, never.
        if (plan.honest() and storage.endpoint.failed[0]) return error.ExchangeRefused;
        moved = try storage.record.app.answer(&storage.endpoint, plan, &storage.content, now_ms) or moved;
        moved = try server_send(storage, now_ns, now_ms) or moved;
        moved = try storage.peer.read(plan, now_ns, now_ms) or moved;
        if (!moved) return;
    }
    return error.RunStalled;
}

/// The peer writes every datagram it owes, and the endpoint takes each one a muted peer did not
/// write, and reports the next event it owes.
fn peer_send(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    const peer = &storage.peer;
    var moved = false;
    for (0..limits.datagrams_per_pass_max) |_| {
        const len = try peer.send(&storage.datagram, now_ns) orelse break;
        moved = true;
        if (peer.muted) continue;
        const from = server.Address.of(&peer_octets, peer_port);
        storage.record.wire.update(storage.datagram[0..len]);
        const received = storage.endpoint.receive(.{ .datagram = .{ .octets = storage.datagram[0..len], .from = from } }, now_ns);
        if (received.event) |reported| note(storage, reported, now_ms);
    }
    // A deaf peer's request has left, and nothing of its leaves after.
    if (peer.mute_pending) peer.muted = true;
    return moved;
}

/// The application reads every event the endpoint reports.
fn server_read(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    // Bounded: every event reads an octet the pool holds, or ends a request.
    for (0..limits.events_per_pass_max) |_| {
        const reported = storage.endpoint.receive(.none, now_ns).event orelse return moved;
        moved = true;
        note(storage, reported, now_ms);
    }
    return error.RunStalled;
}

/// Keeps the connection's `ended`, and hands every other event to the application.
fn note(storage: *Storage, reported: server.Event, now_ms: u64) void {
    switch (reported) {
        .ended => |over| storage.ended = over,
        else => storage.record.app.note_event(reported, now_ms),
    }
}

/// The endpoint writes every datagram it owes into the link, and the peer takes each one the
/// link has carried by `now_ms`.
fn server_send(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    var moved = try deliver(storage, now_ns, now_ms);
    for (0..limits.datagrams_per_pass_max) |_| {
        const sent = storage.endpoint.send_datagram(&storage.datagram, now_ns) orelse break;
        moved = true;
        storage.record.wire.update(sent.octets);
        storage.link.take(sent.octets, now_ms);
        // A link with no rate has carried the datagram already.
        _ = try deliver(storage, now_ns, now_ms);
    }
    return moved;
}

fn deliver(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    // Bounded: the link holds `link_queue_len` datagrams.
    for (0..limits.link_queue_len) |_| {
        const octets = storage.link.next(now_ms) orelse break;
        moved = true;
        try storage.peer.receive(octets, now_ns, now_ms);
    }
    return moved;
}

/// The next instant something is due after `now_ms`: a deadline or a timer of the server's, a
/// timer, an action or a read of the peer's, or an answer, or null for none.
fn next_instant(storage: *Storage, plan: *const Plan, now_ms: u64) ?u64 {
    const peer = &storage.peer;
    var soonest: ?u64 = null;
    if (storage.endpoint.deadline_ns()) |at_ns| soonest = later_than(now_ms, ms_of(plan, at_ns));
    if (peer.timer_ns()) |at_ns| soonest = earlier(soonest, later_than(now_ms, ms_of(plan, at_ns)));
    if (peer.next_act_ms) |at_ms| soonest = earlier(soonest, later_than(now_ms, at_ms));
    if (storage.link.arrival_ms()) |at_ms| soonest = earlier(soonest, later_than(now_ms, at_ms));
    if (plan.reads_paced() and peer.awaits_response() and peer.active()) {
        soonest = earlier(soonest, later_than(now_ms, peer.next_read_ms));
    }
    return storage.record.app.next_ms(plan, soonest);
}

/// `at_ms`, or the instant after `now_ms` when `at_ms` has come: a timer that fell due inside an
/// instant fires at the next one.
fn later_than(now_ms: u64, at_ms: u64) u64 {
    return @max(at_ms, now_ms + 1);
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}

fn finish(storage: *Storage, plan: *const Plan, end: End, end_ms: u64) void {
    const record = &storage.record;
    const peer = &storage.peer;
    record.end = end;
    record.end_ms = end_ms;
    record.close = peer.close;
    record.goaway_ms = peer.goaway_ms;
    record.dropped = storage.link.dropped;
    record.requests_opened = @intCast(peer.fetches_len);
    // `ended` names why colibri closed the connection. A run ends when the peer reads the
    // CONNECTION_CLOSE, while the connection is still closing and before its `ended`, so the check
    // then reads the reason off the endpoint's slot, as a program does not (RFC 9000 §10.2).
    if (storage.ended) |over| {
        record.close_reason = over.reason;
    } else if (storage.endpoint.live[0]) {
        record.close_reason = storage.endpoint.quic[0].close_reason();
    }
    for (peer.fetches[0..peer.fetches_len], 0..) |*fetch, index| {
        if (index < kept_fetches) record.seen[index] = .{
            .status = fetch.status,
            .status_ms = fetch.status_ms,
            .reset = fetch.reset,
            .reset_ms = fetch.reset_ms,
            .ended_ms = fetch.ended_ms,
        };
        if (index >= plan.exchanges_len or !plan.honest()) continue;
        // An honest peer's exchange is whole: 200, every octet of its content, and its end.
        const whole = fetch.status == ok_status and fetch.ended_ms != null and fetch.received_len == plan.content_len[index];
        if (whole) record.exchanges_done += 1;
    }
}

/// The status the application answers with: 200 (OK), RFC 9110 §15.3.1.
const ok_status: u16 = 200;
