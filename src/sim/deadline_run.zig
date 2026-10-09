//! One run of the deadline check (`deadline_check.zig`, decision 110): a server over one
//! connection, the application that answers its requests (`deadline_app.zig`), and the peer of
//! the seed's plan, in simulated time. At each instant the run moves octets both ways until nothing
//! moves, then goes to the next instant something is due: a piece the peer writes or reads, an
//! answer of the application's, or a deadline of the server's. A run ends when the server says to
//! close the connection, or at the horizon with it still open.
//!
//! The socket between them holds `socket_len` octets the peer has not read, so the server's
//! `send` takes only what the peer's reading has made room for.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const tls = @import("tls");
const client = @import("client");
const server = @import("server");
const plan_module = @import("deadline_plan.zig");
const peer_module = @import("deadline_peer.zig");
const app_module = @import("deadline_app.zig");

const Random = sim.Random;
const limits = sim.constants.deadline;
const Plan = plan_module.Plan;
const Hostile = peer_module.Hostile;

pub const Error = client.RequestError || client.StartError || server.StartError || peer_module.Error || app_module.Error || error{
    /// The server failed the connection on octets an honest peer sent.
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

/// What a run did, which the check verifies and writes into the seed's trace.
pub const Record = struct {
    end: End,
    end_ms: u64,
    /// The requests the application answered, and the deadline that cancelled one.
    app: app_module.Application,
    /// Exchanges an honest peer ended with a whole response.
    exchanges_done: u8,
    /// Whether a hostile h11 peer read a 408, and in h2 the status of the last response, the code
    /// of the first RST_STREAM and its instant, and the code of the GOAWAY a hostile peer read.
    saw_timeout_response: bool,
    response_status: ?u16,
    reset_code: ?u32,
    reset_at_ms: ?u64,
    goaway_code: ?u32,
    /// The RST_STREAM frames with NO_ERROR, and with REFUSED_STREAM, a hostile h2 peer read.
    resets_no_error: u32,
    resets_refused: u32,
    /// Why the server closed the connection on its own, if it did (decision 110).
    close_reason: ?server.CloseReason,

    /// The deadline that closed the connection, or null when none did.
    pub fn deadline_passed(record: *const Record) ?server.Deadline {
        const reason = record.close_reason orelse return null;
        return switch (reason) {
            .deadline => |passed| passed,
            // The check's peers pass no limit, so `verify` refuses a run a limit closed.
            .limit => null,
        };
    }
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

    /// The room the socket has for more: `socket_len` less what the reader has not read.
    fn socket_room(stream: *Stream) []u8 {
        const unread = stream.written - stream.delivered;
        assert(unread <= limits.socket_len);
        return stream.free()[0..@min(stream.free().len, limits.socket_len - unread)];
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
    bodies: [limits.exchanges_max][limits.read_content_len_max]u8,
    content: [limits.read_content_len_max]u8,
    /// The content an uploading peer's requests carry.
    upload: [limits.upload_len_max]u8,
    /// The exchanges colibri's client was given: all at once, or for an upload one at a time.
    exchanges_requested: u8,
    record: Record,
    /// When a paced honest peer delivers its next piece, and when a slow reader reads its next.
    next_piece_ms: u64,
    next_read_ms: u64,
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
    // Decision 117: each side allows the plan's version alone, so each speaks it from the start.
    const versions: server.Versions = switch (plan.protocol) {
        .h11 => .{ .h2 = false },
        .h2 => .{ .h11 = false },
    };
    storage.server_config = .{ .versions = versions, .deadlines = plan.deadlines };
    storage.tls_random = Random.init(seed);
    const source = tls.Random.init(&storage.tls_random, fill);
    try storage.server_connection.init(&storage.server_config, source, 0, ns_of(plan, 0));
    storage.to_server.reset();
    storage.to_client.reset();
    storage.record = .{
        .end = .held,
        .end_ms = 0,
        .app = undefined,
        .exchanges_done = 0,
        .saw_timeout_response = false,
        .response_status = null,
        .reset_code = null,
        .reset_at_ms = null,
        .goaway_code = null,
        .resets_no_error = 0,
        .resets_refused = 0,
        .close_reason = null,
    };
    storage.record.app.init();
    storage.next_piece_ms = 0;
    storage.next_read_ms = 0;
    storage.exchanges_requested = 0;
    for (&storage.content, 0..) |*octet, index| octet.* = content_letters[index % content_letters.len];
    for (&storage.upload, 0..) |*octet, index| octet.* = content_letters[index % content_letters.len];
    if (!plan.honest()) return storage.hostile.start(plan);
    const client_versions: client.Versions = switch (plan.protocol) {
        .h11 => .{ .h2 = false },
        .h2 => .{ .h11 = false },
    };
    storage.client_config = .{ .authority = "a.example", .versions = client_versions };
    try storage.client_connection.init(&storage.client_config, source, 0, null);
    for (storage.exchanges[0..plan.exchanges_len], 0..) |*exchange, index| {
        exchange.* = .{ .method = "GET", .path = "/", .body = &storage.bodies[index] };
        if (plan.peer == .upload) {
            exchange.method = "POST";
            exchange.content = storage.upload[0..plan.upload_len[index]];
        }
    }
    // An upload's exchanges go one at a time, so each request's body has the whole link.
    const at_once = if (plan.peer == .upload) 1 else plan.exchanges_len;
    for (0..at_once) |_| try request_next(storage);
}

/// Gives colibri's client its next exchange.
fn request_next(storage: *Storage) Error!void {
    _ = try storage.client_connection.request(&storage.exchanges[storage.exchanges_requested]);
    storage.exchanges_requested += 1;
}

/// The octets of each response's content: letters alone, so no content reads as a status line.
const content_letters = "abcdefghijklmnopqrstuvwxyz";

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}

/// The instant `ms` milliseconds into the run, from its base, in nanoseconds.
fn ns_of(plan: *const Plan, ms: u64) u64 {
    return (plan.base_ms + ms) * limits.ns_per_ms;
}

/// Moves octets both ways at `now_ms` until nothing moves, after the server's caller hands it the
/// instant, as it does whenever it wakes (decision 110).
fn settle(storage: *Storage, plan: *const Plan, now_ms: u64) Error!void {
    storage.server_connection.on_instant(ns_of(plan, now_ms));
    for (0..limits.passes_per_instant_max) |_| {
        var moved = try peer_write(storage, plan, now_ms);
        moved = try server_read(storage, plan, now_ms) or moved;
        moved = try storage.record.app.answer(&storage.server_connection, plan, &storage.content, now_ms) or moved;
        moved = server_send(storage, plan, now_ms) or moved;
        storage.record.app.note_drained(&storage.server_connection, plan, now_ms);
        moved = try peer_read(storage, plan, now_ms) or moved;
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
    stream.written += storage.client_connection.send(stream.free(), ns_of(plan, now_ms));
    if (!plan.paced()) return stream.deliver(stream.written);
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
        const received = storage.server_connection.receive(stream.held(), ns_of(plan, now_ms)) catch {
            // A hostile peer's octets may end the connection; an honest peer's may not.
            if (plan.honest()) return error.ExchangeRefused;
            return moved;
        };
        stream.consumed += received.consumed;
        const reported = received.event orelse return moved or received.consumed > 0;
        moved = true;
        storage.record.app.note_event(reported, now_ms);
    }
    return error.RunStalled;
}

/// The events one run gives the server at most: each exchange's request, end and `done`.
const events_per_exchange: usize = 3;
const events_max: usize = limits.exchanges_max * events_per_exchange + 1;

/// The server writes into the socket as much as its room takes.
fn server_send(storage: *Storage, plan: *const Plan, now_ms: u64) bool {
    const stream = &storage.to_client;
    const written = storage.server_connection.send(stream.socket_room(), ns_of(plan, now_ms));
    stream.written += written;
    return written > 0;
}

/// The peer reads from the socket: at once, a piece every gap when it reads slowly, or nothing.
fn read_socket(storage: *Storage, plan: *const Plan, now_ms: u64) bool {
    const stream = &storage.to_client;
    if (plan.reads_none()) return false;
    if (!plan.reads_paced()) return stream.deliver(stream.written);
    if (now_ms < storage.next_read_ms or stream.written == stream.delivered) return false;
    storage.next_read_ms = now_ms + plan.read_gap_ms;
    return stream.deliver(plan.read_len);
}

/// The peer reads what the server sent: colibri's client reads its responses, and a hostile peer
/// reads the frames it must acknowledge. An upload's next exchange starts when one finishes.
fn peer_read(storage: *Storage, plan: *const Plan, now_ms: u64) Error!bool {
    const stream = &storage.to_client;
    var moved = read_socket(storage, plan, now_ms);
    if (!plan.honest()) {
        if (plan.protocol == .h2) storage.hostile.read_h2(stream.octets[0..stream.delivered], now_ms);
        return moved;
    }
    // Bounded: each pass consumes an octet or reports an event.
    for (0..limits.stream_len_max + events_max) |_| {
        const received = storage.client_connection.receive(stream.held(), ns_of(plan, now_ms));
        stream.consumed += received.consumed;
        const reported = received.event orelse return moved or received.consumed > 0;
        moved = true;
        if (reported != .finished) continue;
        if (reported.finished.exchange.outcome == .response) storage.record.exchanges_done += 1;
        if (plan.peer == .upload and storage.exchanges_requested < plan.exchanges_len) try request_next(storage);
    }
    return moved;
}

/// The next instant something is due: a piece the peer writes or reads, an answer, or a deadline
/// of the server's, or null for none.
fn next_instant(storage: *Storage, plan: *const Plan) ?u64 {
    var soonest: ?u64 = null;
    // The run's instants are whole milliseconds, and so is every deadline that starts at one.
    if (storage.server_connection.deadline_ns()) |at_ns| {
        const at_ms = std.math.divCeil(u64, at_ns, limits.ns_per_ms) catch unreachable;
        assert(at_ms >= plan.base_ms);
        soonest = at_ms - plan.base_ms;
    }
    if (!plan.honest()) {
        if (storage.hostile.next_ms()) |at_ms| soonest = earlier(soonest, at_ms);
    }
    const to_server = &storage.to_server;
    if (plan.paced() and to_server.written > to_server.delivered) soonest = earlier(soonest, storage.next_piece_ms);
    const to_client = &storage.to_client;
    if (plan.reads_paced() and to_client.written > to_client.delivered) soonest = earlier(soonest, storage.next_read_ms);
    return storage.record.app.next_ms(plan, soonest);
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}

fn finish(storage: *Storage, plan: *const Plan, end: End, end_ms: u64) void {
    const record = &storage.record;
    record.end = end;
    record.end_ms = end_ms;
    record.close_reason = storage.server_connection.close_reason();
    if (plan.honest()) return;
    const received = storage.to_client.octets[0..storage.to_client.delivered];
    switch (plan.protocol) {
        .h11 => record.saw_timeout_response = std.mem.indexOf(u8, received, peer_module.h11_timeout_line) != null,
        .h2 => {
            record.response_status = storage.hostile.response_status;
            record.reset_code = storage.hostile.reset_code;
            record.reset_at_ms = storage.hostile.reset_at_ms;
            record.goaway_code = storage.hostile.goaway_code;
            record.resets_no_error = storage.hostile.resets_no_error;
            record.resets_refused = storage.hostile.resets_refused;
        },
    }
}

test "a run a limit closed names no deadline, so the check refuses it" {
    var record: Record = undefined;
    record.close_reason = .{ .limit = .peer_resets };
    try std.testing.expectEqual(null, record.deadline_passed());
    record.close_reason = .{ .deadline = .idle };
    try std.testing.expectEqual(.idle, record.deadline_passed().?);
    record.close_reason = null;
    try std.testing.expectEqual(null, record.deadline_passed());
}
