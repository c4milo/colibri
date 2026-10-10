//! What the program of the endpoint check knows (design §8 step 21b.5, decision 119): every
//! connection handle the endpoint gave it, every request it read, and the word it set on each. It
//! checks each event the endpoint reports against that, as a program that frees a request's state
//! on its ending relies on:
//!   - P1: every request's id is new, and names a connection the program holds;
//!   - P2: every later event of a request carries the word the program set last;
//!   - P3: each request ends once, with `done` or `cancelled`, and nothing of it comes after;
//!   - P4: each connection ends once, after its requests, and nothing names it after.
//!
//! The ledger keeps the CRC-32 of every event in the order the endpoint reported it, and on a
//! violation the call, the slot and the number that broke it, which the trace prints.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const answer_module = @import("endpoint_answer.zig");
const record_module = @import("endpoint_ledger_record.zig");

const limits = sim.constants.endpoint;
const Answer = answer_module.Answer;
const Handle = server.ConnectionHandle;

pub const Violation = error{
    /// P1: a request's id equals an earlier id of the seed.
    IdReused,
    /// P1: an event names a connection the endpoint never gave the program.
    IdOnUnknownConnection,
    /// P1: `accept` gave a handle it gave before, gave none while a TCP slot was free, or gave one
    /// after `shutdown`.
    AcceptWrong,
    /// P2: an event carries another word than the one the program set last.
    WordWrong,
    /// P3: an event of a request that ended, or that the endpoint never reported.
    EventAfterEnding,
    /// P3: a request the program cancelled ended otherwise, or one it did not cancel ended with
    /// the reason `program`.
    CancelWrong,
    /// P3: `done` came before the program's write that ended the response returned.
    DoneEarly,
    /// P3: `writable` came for a request whose last write found room.
    WritableUnasked,
    /// P3: a call by the id of an open request was refused.
    RequestLost,
    /// P4: `ended` came with a request of the connection still open.
    EndedEarly,
    /// P4: a TCP connection's `ended` came while its socket was open.
    EndedOpen,
    /// P4: an event named a connection whose `ended` came before.
    NamedAfterEnded,
    /// P4: a call by a handle or an id that names nothing was not refused.
    StaleCallTaken,
    /// P4: a connection whose socket closed had not ended when nothing more moved.
    EndedMissing,
    /// A `send` or a `close` came for a connection that is not TCP or whose socket closed.
    SocketWrong,
    /// `closed` came before `shutdown`, twice, or with a connection that had not ended.
    ClosedWrong,
    /// An honest peer's connection ended with `failed`: colibri failed it on what the peer sent.
    HonestFailed,
    /// A deadline or a limit cut an honest peer: a request of its own ended for one, or its
    /// connection did for one other than idle. Only the drain after `shutdown` may cut it.
    HonestCut,
    /// The run holds as many requests or connections as its ledger has room for.
    LedgerFull,
};

pub const Kind = enum { tcp, quic };

/// Whether a TCP connection's socket is open, or which side closed it.
pub const Socket = enum { open, closed_by_endpoint, closed_by_program };

/// A connection the endpoint gave the program, and what happened to it.
pub const Connection = struct {
    handle: Handle,
    kind: Kind,
    peer: u8,
    honest: bool,
    /// A TCP peer that reads its responses slowly. The run's socket takes every octet the endpoint
    /// writes at once, so what the peer has not read waits in the socket, never in the endpoint's
    /// output, and its h2 streams' send meters never wait (decision 110 as amended): the send rate
    /// may cut it, which a socket that fills would not. Design §8 step 21b.5 leaves a full socket
    /// out.
    reads_slowly: bool = false,
    socket: Socket = .open,
    ended: bool = false,
    ended_ms: ?u64 = null,
    reason: ?server.CloseReason = null,
    failed: bool = false,
    requests: u32 = 0,
    done: u32 = 0,
    cancelled: u32 = 0,

    /// Notes that the connection's socket closed, which `by` closed.
    pub fn close_socket(connection: *Connection, by: Socket) void {
        assert(connection.kind == .tcp and by != .open);
        if (connection.socket == .open) connection.socket = by;
    }
};

/// A request the program read, its word, and the answer it writes.
pub const Request = struct {
    id: server.Id,
    connection: u8,
    word: usize = 0,
    open: bool = true,
    cancel_called: bool = false,
    answer: Answer,
};

/// Where a check found a violation: the instant, the event or call, and what it named.
pub const Fault = struct {
    at_ms: u64 = 0,
    call: []const u8 = "",
    slot: u32 = 0,
    generation: u32 = 0,
    number: u64 = 0,
};

/// The events the endpoint reported, by kind and by the reason of each `cancelled`.
pub const Counts = struct {
    requests: u32 = 0,
    bodies: u32 = 0,
    trailers: u32 = 0,
    done: u32 = 0,
    cancelled: [std.meta.fields(server.CancelReason).len]u32 = @splat(0),
    writable: u32 = 0,
    sends: u32 = 0,
    closes: u32 = 0,
    ended: u32 = 0,
    failed: u32 = 0,
    closed: u32 = 0,
};

pub const Ledger = struct {
    connections: [limits.handles_max]Connection,
    connections_len: u32,
    requests: [limits.requests_max]Request,
    requests_len: u32,
    requests_ended: u32,
    connections_ended: u32,
    shut_down: bool,
    counts: Counts,
    fault: Fault,
    events: std.hash.Crc32,

    pub fn init(ledger: *Ledger) void {
        ledger.connections_len = 0;
        ledger.requests_len = 0;
        ledger.requests_ended = 0;
        ledger.connections_ended = 0;
        ledger.shut_down = false;
        ledger.counts = .{};
        ledger.fault = .{};
        ledger.events = .init();
    }

    /// Notes where a check failed, and returns its error.
    pub fn fail(ledger: *Ledger, failure: Violation, call: []const u8, handle: Handle, number: u64, now_ms: u64) Violation {
        ledger.fault = .{ .at_ms = now_ms, .call = call, .slot = handle.slot, .generation = handle.generation, .number = number };
        return failure;
    }

    /// Holds a connection the endpoint gave the program. P1: its handle is new.
    pub fn register(ledger: *Ledger, handle: Handle, kind: Kind, peer: u8, honest: bool, now_ms: u64) Violation!*Connection {
        for (ledger.connections[0..ledger.connections_len]) |*held| {
            if (held.handle == handle) return ledger.fail(error.AcceptWrong, "register", handle, 0, now_ms);
        }
        if (ledger.connections_len == limits.handles_max) return ledger.fail(error.LedgerFull, "register", handle, 0, now_ms);
        const connection = &ledger.connections[ledger.connections_len];
        connection.* = .{ .handle = handle, .kind = kind, .peer = peer, .honest = honest };
        ledger.connections_len += 1;
        return connection;
    }

    /// The connection `handle` names, ended or not, or null for one the endpoint never gave.
    pub fn connection_of(ledger: *Ledger, handle: Handle) ?*Connection {
        for (ledger.connections[0..ledger.connections_len]) |*held| {
            if (held.handle == handle) return held;
        }
        return null;
    }

    /// The request `id` names, ended or not, or null for one the endpoint never reported.
    pub fn request_of(ledger: *Ledger, id: server.Id) ?*Request {
        var index = ledger.requests_len;
        // Bounded by the requests held; the newest are asked first, as most events name them.
        for (0..ledger.requests_len) |_| {
            index -= 1;
            if (ledger.requests[index].id == id) return &ledger.requests[index];
        }
        return null;
    }

    /// Where `connection` is among the connections the ledger holds.
    fn index_of(ledger: *Ledger, connection: *const Connection) u8 {
        for (ledger.connections[0..ledger.connections_len], 0..) |*held, index| {
            if (held == connection) return @intCast(index);
        }
        unreachable;
    }

    /// The connection of the request at `request`.
    pub fn connection_at(ledger: *Ledger, request: *const Request) *Connection {
        assert(request.connection < ledger.connections_len);
        return &ledger.connections[request.connection];
    }

    /// Checks `reported` against what the program holds, adds it to the CRC of the events, and
    /// notes what it opens or ends.
    pub fn note(ledger: *Ledger, reported: server.Event, now_ms: u64) Violation!void {
        ledger.events.update(&record_module.encode(reported, now_ms));
        switch (reported) {
            .request => |request| try ledger.note_request(&request, now_ms),
            .body => |body| {
                ledger.counts.bodies += 1;
                _ = try ledger.open_request(body.id, body.user_data, "body", now_ms);
            },
            .trailers => |trailers| {
                ledger.counts.trailers += 1;
                _ = try ledger.open_request(trailers.id, trailers.user_data, "trailers", now_ms);
            },
            .writable => |writable| try ledger.note_writable(writable, now_ms),
            .done => |done| try ledger.note_done(done, now_ms),
            .cancelled => |cancelled| try ledger.note_cancelled(cancelled, now_ms),
            .send => |handle| {
                ledger.counts.sends += 1;
                _ = try ledger.open_socket(handle, "send", now_ms);
            },
            .close => |handle| {
                ledger.counts.closes += 1;
                (try ledger.open_socket(handle, "close", now_ms)).close_socket(.closed_by_endpoint);
            },
            .ended => |over| try ledger.note_ended(over, now_ms),
            .closed => try ledger.note_closed(now_ms),
        }
    }

    /// P1: a request's id is new and names a connection the program holds, which has not ended.
    fn note_request(ledger: *Ledger, request: *const server.Request, now_ms: u64) Violation!void {
        const handle = request.id.connection;
        const connection = try ledger.live_connection(handle, "request", now_ms);
        // Ids compare whole: the same number on another connection, or on a later connection in
        // the same slot, is another request.
        if (ledger.request_of(request.id) != null) return ledger.fail(error.IdReused, "request", handle, request.id.number, now_ms);
        if (ledger.requests_len == limits.requests_max) return ledger.fail(error.LedgerFull, "request", handle, request.id.number, now_ms);
        ledger.requests[ledger.requests_len] = .{ .id = request.id, .connection = ledger.index_of(connection), .answer = .{} };
        ledger.requests_len += 1;
        connection.requests += 1;
        ledger.counts.requests += 1;
    }

    /// The connection `handle` names, which the endpoint gave and which has not ended. P4: an event
    /// that names a connection after its `ended` is refused.
    fn live_connection(ledger: *Ledger, handle: Handle, call: []const u8, now_ms: u64) Violation!*Connection {
        const connection = ledger.connection_of(handle) orelse return ledger.fail(error.IdOnUnknownConnection, call, handle, 0, now_ms);
        if (connection.ended) return ledger.fail(error.NamedAfterEnded, call, handle, 0, now_ms);
        return connection;
    }

    /// The TCP connection `handle` names, whose socket is open.
    fn open_socket(ledger: *Ledger, handle: Handle, call: []const u8, now_ms: u64) Violation!*Connection {
        const connection = try ledger.live_connection(handle, call, now_ms);
        if (connection.kind != .tcp or connection.socket != .open) return ledger.fail(error.SocketWrong, call, handle, 0, now_ms);
        return connection;
    }

    /// The open request `id` names. P3: nothing of a request comes after its ending, and P2: an
    /// event carries the word the program set last.
    fn open_request(ledger: *Ledger, id: server.Id, word: usize, call: []const u8, now_ms: u64) Violation!*Request {
        _ = try ledger.live_connection(id.connection, call, now_ms);
        const request = ledger.request_of(id) orelse return ledger.fail(error.EventAfterEnding, call, id.connection, id.number, now_ms);
        if (!request.open) return ledger.fail(error.EventAfterEnding, call, id.connection, id.number, now_ms);
        if (request.word != word) return ledger.fail(error.WordWrong, call, id.connection, id.number, now_ms);
        return request;
    }

    /// P3: `writable` comes only for a request whose last write found no room.
    fn note_writable(ledger: *Ledger, writable: server.Writable, now_ms: u64) Violation!void {
        const request = try ledger.open_request(writable.id, writable.user_data, "writable", now_ms);
        if (!request.answer.waiting) return ledger.fail(error.WritableUnasked, "writable", writable.id.connection, writable.id.number, now_ms);
        request.answer.waiting = false;
        ledger.counts.writable += 1;
    }

    /// P3: `done` comes once the program's write that ended the response returned, and ends the
    /// request.
    fn note_done(ledger: *Ledger, done: server.Done, now_ms: u64) Violation!void {
        const request = try ledger.open_request(done.id, done.user_data, "done", now_ms);
        if (request.answer.phase != .ended) return ledger.fail(error.DoneEarly, "done", done.id.connection, done.id.number, now_ms);
        ledger.end_request(request);
        ledger.connection_at(request).done += 1;
        ledger.counts.done += 1;
    }

    /// P3: a request the program cancelled ends with the reason `program`, and only such a request
    /// does.
    fn note_cancelled(ledger: *Ledger, cancelled: server.Cancelled, now_ms: u64) Violation!void {
        const request = try ledger.open_request(cancelled.id, cancelled.user_data, "cancelled", now_ms);
        if (request.cancel_called != (cancelled.reason == .program)) {
            return ledger.fail(error.CancelWrong, "cancelled", cancelled.id.connection, cancelled.id.number, now_ms);
        }
        const connection = ledger.connection_at(request);
        if (connection.honest and !honest_cancel(cancelled.reason, connection.reads_slowly)) {
            return ledger.fail(error.HonestCut, "cancelled", cancelled.id.connection, cancelled.id.number, now_ms);
        }
        ledger.end_request(request);
        ledger.connection_at(request).cancelled += 1;
        ledger.counts.cancelled[@intFromEnum(cancelled.reason)] += 1;
    }

    fn end_request(ledger: *Ledger, request: *Request) void {
        assert(request.open);
        request.open = false;
        ledger.requests_ended += 1;
    }

    /// P4: a connection ends once, after each of its requests ended, and a TCP connection after its
    /// socket closed. An honest peer's connection never ends `failed`.
    fn note_ended(ledger: *Ledger, over: server.Ended, now_ms: u64) Violation!void {
        const handle = over.connection;
        const connection = try ledger.live_connection(handle, "ended", now_ms);
        for (ledger.requests[0..ledger.requests_len]) |*request| {
            if (request.open and request.id.connection == handle) return ledger.fail(error.EndedEarly, "ended", handle, request.id.number, now_ms);
        }
        if (connection.kind == .tcp and connection.socket == .open) return ledger.fail(error.EndedOpen, "ended", handle, 0, now_ms);
        if (over.failed and connection.honest) return ledger.fail(error.HonestFailed, "ended", handle, 0, now_ms);
        if (connection.honest and !honest_end(over.reason, connection.reads_slowly)) return ledger.fail(error.HonestCut, "ended", handle, 0, now_ms);
        connection.ended = true;
        connection.ended_ms = now_ms;
        connection.reason = over.reason;
        connection.failed = over.failed;
        ledger.connections_ended += 1;
        ledger.counts.ended += 1;
        if (over.failed) ledger.counts.failed += 1;
    }

    /// Decision 110: no deadline cuts a request of an honest peer but the drain after `shutdown`,
    /// and the send rate of one that reads slowly (`Connection.reads_slowly`).
    fn honest_cancel(reason: server.CancelReason, reads_slowly: bool) bool {
        return switch (reason) {
            .deadline => |passed| passed == .drain or (reads_slowly and passed == .send_rate),
            else => true,
        };
    }

    /// Decision 110: an honest peer's connection ends for no reason of colibri's, once it was idle,
    /// once the drain after `shutdown` passed, or at the send rate of one that reads slowly.
    fn honest_end(reason: ?server.CloseReason, reads_slowly: bool) bool {
        const held = reason orelse return true;
        return switch (held) {
            .deadline => |passed| passed == .idle or passed == .drain or (reads_slowly and passed == .send_rate),
            .limit => false,
        };
    }

    /// `closed` comes once, after `shutdown`, once every connection has ended.
    fn note_closed(ledger: *Ledger, now_ms: u64) Violation!void {
        const nothing: Handle = .{ .slot = 0, .generation = 0 };
        if (!ledger.shut_down or ledger.counts.closed > 0) return ledger.fail(error.ClosedWrong, "closed", nothing, 0, now_ms);
        if (ledger.connections_ended != ledger.connections_len) return ledger.fail(error.ClosedWrong, "closed", nothing, 0, now_ms);
        ledger.counts.closed += 1;
    }

    /// P4: each TCP connection whose socket closed has ended by the time nothing more moves.
    pub fn expect_closed_ended(ledger: *Ledger, now_ms: u64) Violation!void {
        for (ledger.connections[0..ledger.connections_len]) |*connection| {
            if (connection.ended or connection.socket == .open) continue;
            return ledger.fail(error.EndedMissing, "quiescence", connection.handle, 0, now_ms);
        }
    }

    /// The `index`th request that ended, in the order the endpoint reported them, for a call by an
    /// id that names nothing.
    pub fn ended_request(ledger: *Ledger, index: u64) *Request {
        assert(index < ledger.requests_ended);
        var seen: u64 = 0;
        for (ledger.requests[0..ledger.requests_len]) |*request| {
            if (request.open) continue;
            if (seen == index) return request;
            seen += 1;
        }
        unreachable;
    }

    /// The `index`th connection that ended, for a call by a handle that names nothing.
    pub fn ended_connection(ledger: *Ledger, index: u64) *Connection {
        assert(index < ledger.connections_ended);
        var seen: u64 = 0;
        for (ledger.connections[0..ledger.connections_len]) |*connection| {
            if (!connection.ended) continue;
            if (seen == index) return connection;
            seen += 1;
        }
        unreachable;
    }
};

const testing = std.testing;

/// The ledger the unit tests write into: too large for a test's stack.
var test_ledger: Ledger align(@alignOf(Ledger)) = undefined;

/// A handle of a slot's third connection, and the major version of h2 (RFC 9110 §2.5).
const test_slot: u32 = 1;
const test_generation: u32 = 3;
const test_handle: Handle = .{ .slot = test_slot, .generation = test_generation };
const test_major: u8 = 2;

fn test_request(number: u64) server.Event {
    return .{ .request = .{
        .id = .{ .connection = test_handle, .number = number },
        .method = "GET",
        .version = .{ .major = test_major, .minor = 0 },
        .target = "/",
        .scheme = "https",
        .authority = null,
        .path = "/",
        .fields = undefined,
        .end = true,
    } };
}

test "P2: a body carrying another word than the one set last is refused" {
    const ledger = &test_ledger;
    ledger.init();
    _ = try ledger.register(test_handle, .quic, 0, true, 0);
    try ledger.note(test_request(0), 0);
    const id: server.Id = .{ .connection = test_handle, .number = 0 };
    ledger.request_of(id).?.word = 0xa1;
    try ledger.note(.{ .body = .{ .id = id, .user_data = 0xa1, .octets = "", .end = false } }, 1);
    try testing.expectError(error.WordWrong, ledger.note(.{ .body = .{ .id = id, .user_data = 0xa2, .octets = "", .end = true } }, 2));
    try testing.expectEqualStrings("body", ledger.fault.call);
}

test "P1 and P3: an id seen before is refused, and nothing of a request comes after its ending" {
    const ledger = &test_ledger;
    ledger.init();
    _ = try ledger.register(test_handle, .quic, 0, true, 0);
    try ledger.note(test_request(4), 0);
    try testing.expectError(error.IdReused, ledger.note(test_request(4), 1));
    const id: server.Id = .{ .connection = test_handle, .number = 4 };
    // `done` before the program's ending write returned.
    try testing.expectError(error.DoneEarly, ledger.note(.{ .done = .{ .id = id } }, 2));
    ledger.request_of(id).?.answer.phase = .ended;
    try ledger.note(.{ .done = .{ .id = id } }, 3);
    try testing.expectError(error.EventAfterEnding, ledger.note(.{ .cancelled = .{ .id = id, .reason = .closed } }, 4));
    // A `writable` nobody asked for, and a `cancelled` for the program's reason with no cancel.
    try ledger.note(test_request(8), 5);
    const next: server.Id = .{ .connection = test_handle, .number = 8 };
    try testing.expectError(error.WritableUnasked, ledger.note(.{ .writable = .{ .id = next, .user_data = 0 } }, 6));
    try testing.expectError(error.CancelWrong, ledger.note(.{ .cancelled = .{ .id = next, .reason = .program } }, 7));
}

test "P4: a connection ends after its requests and its socket, and nothing names it after" {
    const ledger = &test_ledger;
    ledger.init();
    const connection = try ledger.register(test_handle, .tcp, 0, true, 0);
    try testing.expectError(error.AcceptWrong, ledger.register(test_handle, .tcp, 1, true, 0));
    try ledger.note(test_request(1), 0);
    const ended: server.Event = .{ .ended = .{ .connection = test_handle, .reason = null, .failed = false } };
    try testing.expectError(error.EndedEarly, ledger.note(ended, 1));
    ledger.request_of(.{ .connection = test_handle, .number = 1 }).?.cancel_called = true;
    try ledger.note(.{ .cancelled = .{ .id = .{ .connection = test_handle, .number = 1 }, .reason = .program } }, 2);
    try testing.expectError(error.EndedOpen, ledger.note(ended, 3));
    try ledger.expect_closed_ended(3);
    connection.close_socket(.closed_by_program);
    try testing.expectError(error.EndedMissing, ledger.expect_closed_ended(4));
    try testing.expectError(error.SocketWrong, ledger.note(.{ .send = test_handle }, 4));
    try ledger.note(ended, 5);
    try testing.expectError(error.NamedAfterEnded, ledger.note(.{ .send = test_handle }, 6));
    try testing.expectError(error.ClosedWrong, ledger.note(.closed, 7));
}

test "an honest peer's connection that ends failed is refused" {
    const ledger = &test_ledger;
    ledger.init();
    _ = try ledger.register(test_handle, .quic, 0, true, 0);
    const ended: server.Event = .{ .ended = .{ .connection = test_handle, .reason = null, .failed = true } };
    try testing.expectError(error.HonestFailed, ledger.note(ended, 1));
}
