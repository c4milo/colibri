//! One run of the deadline check (`deadline_check.zig`, decision 110): a server over one
//! connection, the application that answers its requests, and the peer of the seed's plan, in
//! simulated time. At each instant the run moves octets both ways until nothing moves, then goes
//! to the next instant something is due: a piece of the peer's, or an answer of the application's.
//! A run ends when the server says to close the connection, or at the horizon with it still open.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const tls = @import("tls");
const client = @import("client");
const server = @import("server");
const plan_module = @import("deadline_plan.zig");
const peer_module = @import("deadline_peer.zig");

const Random = sim.Random;
const limits = sim.constants.deadline;
const Plan = plan_module.Plan;
const Hostile = peer_module.Hostile;

pub const Error = client.RequestError || client.StartError || server.StartError || peer_module.Error || error{
    /// The server failed the connection on octets an honest peer sent, or the application could
    /// not answer.
    ExchangeRefused,
    /// The run visited `instants_max` instants, or an instant did not settle.
    RunStalled,
};

/// How a run ended.
pub const End = enum {
    /// The server said to close the connection.
    closed,
    /// The horizon came with the connection still open.
    held,
};

/// A request the application read, and when it answered it.
pub const Answer = struct {
    id: server.Id,
    read_ms: u64,
    answered_ms: ?u64,
};

/// What a run did, which the check verifies and writes into the seed's trace.
pub const Record = struct {
    end: End,
    end_ms: u64,
    answers: [limits.exchanges_max]Answer,
    answers_len: u8,
    /// Exchanges an honest peer ended with a whole response.
    exchanges_done: u8,
    /// Whether a hostile h11 peer read a 408, and the code of the GOAWAY a hostile h2 peer read.
    saw_timeout_response: bool,
    goaway_code: ?u32,
};

/// One direction's octets: written at the back, delivered to the reader, consumed from the front.
const Stream = struct {
    octets: [limits.stream_len_max]u8,
    written: usize,
    delivered: usize,
    consumed: usize,

    fn reset(stream: *Stream) void {
        stream.written = 0;
        stream.delivered = 0;
        stream.consumed = 0;
    }

    fn free(stream: *Stream) []u8 {
        return stream.octets[stream.written..];
    }

    fn held(stream: *Stream) []u8 {
        return stream.octets[stream.consumed..stream.delivered];
    }

    /// Delivers up to `len` octets written and not yet delivered, and returns whether any moved.
    fn deliver(stream: *Stream, len: usize) bool {
        const moved = @min(len, stream.written - stream.delivered);
        stream.delivered += moved;
        return moved > 0;
    }
};

pub const Storage = struct {
    server_config: server.Config,
    server_connection: server.Connection,
    client_config: client.Config,
    client_connection: client.Connection,
    hostile: Hostile,
    to_server: Stream,
    to_client: Stream,
    exchanges: [limits.exchanges_max]client.HttpExchange,
    bodies: [limits.exchanges_max][limits.content_len_max]u8,
    content: [limits.content_len_max]u8,
    record: Record,
    /// When a slow honest peer delivers its next piece.
    next_piece_ms: u64,
    tls_random: Random,
};

/// Runs `plan` from its first instant until the server closes the connection or the horizon comes.
pub fn run(storage: *Storage, plan: *const Plan, seed: u64) Error!void {
    try start(storage, plan, seed);
    var now_ms: u64 = 0;
    // Bounded: each pass goes to a later instant, or ends the run.
    for (0..limits.instants_max) |_| {
        try settle(storage, plan, now_ms);
        if (storage.server_connection.should_close()) return finish(storage, plan, .closed, now_ms);
        const next_ms = next_instant(storage, plan) orelse return finish(storage, plan, .held, limits.horizon_ms);
        if (next_ms >= limits.horizon_ms) return finish(storage, plan, .held, limits.horizon_ms);
        assert(next_ms > now_ms);
        now_ms = next_ms;
    }
    return error.RunStalled;
}

fn start(storage: *Storage, plan: *const Plan, seed: u64) Error!void {
    const protocol: server.Protocol = switch (plan.protocol) {
        .h11 => .h11,
        .h2 => .h2,
    };
    storage.server_config = .{ .cleartext = protocol };
    storage.tls_random = Random.init(seed);
    const source = tls.Random.init(&storage.tls_random, fill);
    try storage.server_connection.init(&storage.server_config, source, 0);
    storage.to_server.reset();
    storage.to_client.reset();
    storage.record = .{
        .end = .held,
        .end_ms = 0,
        .answers = undefined,
        .answers_len = 0,
        .exchanges_done = 0,
        .saw_timeout_response = false,
        .goaway_code = null,
    };
    storage.next_piece_ms = 0;
    for (&storage.content, 0..) |*octet, index| octet.* = content_letters[index % content_letters.len];
    if (!plan.honest()) return storage.hostile.start(plan);
    const client_protocol: client.Protocol = switch (plan.protocol) {
        .h11 => .h11,
        .h2 => .h2,
    };
    storage.client_config = .{ .authority = "a.example", .cleartext = client_protocol };
    try storage.client_connection.init(&storage.client_config, source, 0, null);
    for (storage.exchanges[0..plan.exchanges_len], 0..) |*exchange, index| {
        exchange.* = .{ .method = "GET", .path = "/", .body = &storage.bodies[index] };
        _ = try storage.client_connection.request(exchange);
    }
}

/// The octets of each response's content: letters alone, so no content reads as a status line.
const content_letters = "abcdefghijklmnopqrstuvwxyz";

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}

fn ns_of(ms: u64) u64 {
    return ms * limits.ns_per_ms;
}

/// Moves octets both ways at `now_ms` until nothing moves.
fn settle(storage: *Storage, plan: *const Plan, now_ms: u64) Error!void {
    for (0..limits.passes_per_instant_max) |_| {
        var moved = try peer_write(storage, plan, now_ms);
        moved = try server_read(storage, plan, now_ms) or moved;
        moved = try answer(storage, plan, now_ms) or moved;
        moved = server_send(storage, now_ms) or moved;
        moved = peer_read(storage, plan, now_ms) or moved;
        if (!moved) return;
    }
    return error.RunStalled;
}

/// The peer writes what is due, and the octets it wrote are delivered as its pace allows.
fn peer_write(storage: *Storage, plan: *const Plan, now_ms: u64) Error!bool {
    const stream = &storage.to_server;
    if (!plan.honest()) {
        var moved = false;
        // Bounded: each pass takes one piece of the script.
        for (0..limits.pieces_max) |_| {
            const piece = storage.hostile.due(now_ms) orelse break;
            @memcpy(stream.free()[0..piece.len], piece);
            stream.written += piece.len;
            moved = true;
        }
        // A silent peer sends nothing, not even an acknowledgment of the server's SETTINGS.
        if (plan.peer != .silent) stream.written += try storage.hostile.write_acks(stream.free());
        return stream.deliver(stream.written) or moved;
    }
    stream.written += storage.client_connection.send(stream.free(), ns_of(now_ms));
    if (plan.peer == .honest) return stream.deliver(stream.written);
    if (now_ms < storage.next_piece_ms or stream.written == stream.delivered) return false;
    storage.next_piece_ms = now_ms + plan.gap_ms;
    return stream.deliver(plan.piece_len);
}

/// The server reads what arrived, and the application notes each request it must answer.
fn server_read(storage: *Storage, plan: *const Plan, now_ms: u64) Error!bool {
    const stream = &storage.to_server;
    var moved = false;
    // Bounded: each pass consumes an octet or reports an event.
    for (0..limits.stream_len_max + events_max) |_| {
        const received = storage.server_connection.receive(stream.held(), ns_of(now_ms)) catch {
            // A hostile peer's octets may end the connection; an honest peer's may not.
            if (plan.honest()) return error.ExchangeRefused;
            return moved;
        };
        stream.consumed += received.consumed;
        const reported = received.event orelse return moved or received.consumed > 0;
        moved = true;
        if (reported == .request) note_request(storage, reported.request.id, now_ms);
    }
    return error.RunStalled;
}

/// The events one run gives the server at most: each exchange's request, end and `done`.
const events_per_exchange: usize = 3;
const events_max: usize = limits.exchanges_max * events_per_exchange + 1;

/// The status each answer carries: 200 (OK), RFC 9110 §15.3.1.
const answer_status: u16 = 200;

fn note_request(storage: *Storage, id: server.Id, now_ms: u64) void {
    const record = &storage.record;
    // The application answers as many requests as a peer makes whole.
    if (record.answers_len == limits.exchanges_max) return;
    record.answers[record.answers_len] = .{ .id = id, .read_ms = now_ms, .answered_ms = null };
    record.answers_len += 1;
}

/// The application answers each request whose delay has passed, with the content the plan names.
fn answer(storage: *Storage, plan: *const Plan, now_ms: u64) Error!bool {
    var moved = false;
    const record = &storage.record;
    for (record.answers[0..record.answers_len], 0..) |*pending, index| {
        if (pending.answered_ms != null) continue;
        if (now_ms < pending.read_ms + plan.answer_delay_ms[index]) continue;
        const content = storage.content[0..plan.content_len[index]];
        storage.server_connection.respond(pending.id, .{ .status = answer_status, .end = content.len == 0 }) catch return error.ExchangeRefused;
        if (content.len > 0) {
            const taken = storage.server_connection.write_body(pending.id, .{ .octets = content, .end = true }) catch return error.ExchangeRefused;
            // The server's output holds a whole response of the longest content.
            if (taken != content.len) return error.ExchangeRefused;
        }
        pending.answered_ms = now_ms;
        moved = true;
    }
    return moved;
}

fn server_send(storage: *Storage, now_ms: u64) bool {
    const stream = &storage.to_client;
    const written = storage.server_connection.send(stream.free(), ns_of(now_ms));
    stream.written += written;
    _ = stream.deliver(written);
    return written > 0;
}

/// The peer reads what the server sent: colibri's client reads its responses, and a hostile peer
/// reads the frames it must acknowledge.
fn peer_read(storage: *Storage, plan: *const Plan, now_ms: u64) bool {
    const stream = &storage.to_client;
    if (!plan.honest()) {
        if (plan.protocol == .h2) storage.hostile.read_h2(stream.octets[0..stream.delivered]);
        return false;
    }
    var moved = false;
    // Bounded: each pass consumes an octet or reports an event.
    for (0..limits.stream_len_max + events_max) |_| {
        const received = storage.client_connection.receive(stream.held(), ns_of(now_ms));
        stream.consumed += received.consumed;
        const reported = received.event orelse return moved or received.consumed > 0;
        moved = true;
        if (reported == .finished and reported.finished.exchange.outcome == .response) storage.record.exchanges_done += 1;
    }
    return moved;
}

/// The next instant something is due: a piece of the peer's, or an answer, or null for none.
fn next_instant(storage: *Storage, plan: *const Plan) ?u64 {
    var soonest: ?u64 = null;
    if (!plan.honest()) soonest = storage.hostile.next_ms();
    const to_server = &storage.to_server;
    if (plan.peer == .slow_honest and to_server.written > to_server.delivered) soonest = earlier(soonest, storage.next_piece_ms);
    const record = &storage.record;
    for (record.answers[0..record.answers_len], 0..) |pending, index| {
        if (pending.answered_ms == null) soonest = earlier(soonest, pending.read_ms + plan.answer_delay_ms[index]);
    }
    return soonest;
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}

fn finish(storage: *Storage, plan: *const Plan, end: End, end_ms: u64) void {
    const record = &storage.record;
    record.end = end;
    record.end_ms = end_ms;
    if (plan.honest()) return;
    const received = storage.to_client.octets[0..storage.to_client.delivered];
    switch (plan.protocol) {
        .h11 => record.saw_timeout_response = std.mem.indexOf(u8, received, peer_module.h11_timeout_line) != null,
        .h2 => record.goaway_code = storage.hostile.goaway_code,
    }
}
