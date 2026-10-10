//! The program of the endpoint check (design §8 step 21b.5, decision 119): every call the run
//! makes to the endpoint goes through here, and after each one P5 holds: `deadline_ns()` is the
//! soonest deadline of every live slot, each read from that slot's connection alone (INV-31).
//!
//! When a pass of the run moves nothing, `quiescence` checks P6, that the endpoint owes the
//! program nothing it has not reported, and then P8, that no deadline it reports has come.
//!
//! The oracle of P5 is `Held.deadline_of`, which the check calls through the endpoint's field
//! `held`: a program reads no slot's deadline, and this check reads it as the server's own
//! fixtures do.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const sim = @import("sim");
const server = @import("server");
const ledger_module = @import("endpoint_ledger.zig");
const answer_module = @import("endpoint_answer.zig");

const limits = sim.constants.endpoint;
const Ledger = ledger_module.Ledger;
const Request = ledger_module.Request;
const Handle = server.ConnectionHandle;

/// The run's endpoint: fewer slots of each kind than the seed draws peers.
pub const Endpoint = server.EndpointOf(.{
    .tcp_connections = limits.tcp_slots,
    .quic_connections = limits.quic_slots,
    .receive_pool_len = limits.receive_pool_len,
});

pub const Violation = ledger_module.Violation || error{
    /// P5: `deadline_ns()` differs from the soonest deadline of the live slots.
    DeadlineWrong,
    /// P6: a TCP connection with no `send` outstanding wrote octets.
    SendMissed,
    /// P6: `receive(.none)` reported an event once a pass moved nothing.
    EventMissed,
    /// P6: a response waiting for room took a write, with no `writable` first.
    WritableMissed,
    /// P6: `send_datagram` wrote a datagram once a pass moved nothing.
    DatagramOwed,
    /// P7: the first `send_stream` after a `send` wrote nothing.
    SendEmpty,
    /// A write by the id of an open request was refused for another reason than room or a
    /// connection that closes.
    WriteRefused,
    /// P8: once nothing moved, `deadline_ns()` named an instant that has come.
    DeadlineNotAdvanced,
};

/// What `write_body` took, or why it took nothing.
pub const Written = struct { taken: usize, failure: ?server.SendError };

const nothing: Handle = .{ .slot = 0, .generation = 0 };

/// Whether a write was refused because its id names no open request.
pub fn unknown(failure: ?server.SendError) bool {
    const refused = failure orelse return false;
    return refused == error.RequestUnknown;
}

/// What the program counted beside the events.
pub const Counts = struct {
    calls: u64 = 0,
    stale_calls: u32 = 0,
    waiting_probes: u32 = 0,
    deadlines_refused: u32 = 0,
    shutdowns: u32 = 0,
};

pub const Program = struct {
    endpoint: *Endpoint,
    ledger: *Ledger,
    now_ms: u64,
    counts: Counts,
    /// What a probe of P6 or a stale call hands `send_stream` and `send_datagram`.
    probe: [server.constants.output_len]u8,
    datagram: [quic.constants.datagram_len_max]u8,
    /// The content every answer is written from, which stays the program's (decision 103).
    content: [limits.answer_long_len_max]u8,

    pub fn init(program: *Program, endpoint: *Endpoint, ledger: *Ledger) void {
        program.endpoint = endpoint;
        program.ledger = ledger;
        program.now_ms = 0;
        program.counts = .{};
        const letters = answer_module.content_letters;
        for (&program.content, 0..) |*octet, index| octet.* = letters[index % letters.len];
    }

    /// Notes where a check failed, and returns its error.
    pub fn fail(program: *Program, failure: Violation, call: []const u8, handle: Handle, number: u64) Violation {
        program.ledger.fault = .{ .at_ms = program.now_ms, .call = call, .slot = handle.slot, .generation = handle.generation, .number = number };
        return failure;
    }

    /// P5: the endpoint's deadline is the soonest of its live slots' deadlines, each read from
    /// that slot's connection alone (INV-31). Run after every call the program makes.
    pub fn check_deadline(program: *Program, call: []const u8) Violation!void {
        var soonest: ?u64 = null;
        for (0..program.endpoint.live.len) |slot| {
            const at_ns = program.endpoint.held.deadline_of(@intCast(slot)) orelse continue;
            soonest = @min(soonest orelse at_ns, at_ns);
        }
        if (!std.meta.eql(soonest, program.endpoint.deadline_ns())) return program.fail(error.DeadlineWrong, call, nothing, 0);
    }

    fn called(program: *Program, call: []const u8) Violation!void {
        program.counts.calls += 1;
        try program.check_deadline(call);
    }

    pub fn receive(program: *Program, input: server.Input, now_ns: u64) Violation!server.Received {
        const received = program.endpoint.receive(input, now_ns);
        try program.called("receive");
        return received;
    }

    /// Accepts a TCP socket. P1: a handle is one the endpoint never gave, none comes after
    /// `shutdown`, and null comes only with every TCP slot taken.
    pub fn accept(program: *Program, security: server.Security, now_ns: u64) Violation!?Handle {
        const accepted = program.endpoint.accept(security, now_ns);
        try program.called("accept");
        const handle = accepted orelse {
            if (program.ledger.shut_down) return null;
            for (program.endpoint.live[0..limits.tcp_slots]) |live| {
                if (!live) return program.fail(error.AcceptWrong, "accept", nothing, 0);
            }
            return null;
        };
        if (program.ledger.shut_down or handle.slot >= limits.tcp_slots) return program.fail(error.AcceptWrong, "accept", handle, 0);
        return handle;
    }

    /// Sets the word of an open request, which the endpoint may not refuse.
    pub fn set_user_data(program: *Program, request: *Request, word: usize) Violation!void {
        const set = program.endpoint.set_user_data(request.id, word);
        try program.called("set_user_data");
        set catch return program.fail(error.RequestLost, "set_user_data", request.id.connection, request.id.number);
        request.word = word;
    }

    pub fn respond(program: *Program, id: server.Id, response: server.Response) Violation!?server.SendError {
        const responded = program.endpoint.respond(id, response);
        try program.called("respond");
        if (responded) |_| return null else |failure| return @as(?server.SendError, failure);
    }

    pub fn write_body(program: *Program, id: server.Id, content: server.Content) Violation!Written {
        const written = program.endpoint.write_body(id, content);
        try program.called("write_body");
        const taken = written catch |failure| return .{ .taken = 0, .failure = failure };
        return .{ .taken = taken, .failure = null };
    }

    pub fn write_trailers(program: *Program, id: server.Id, fields: []const server.Field) Violation!?server.SendError {
        const written = program.endpoint.write_trailers(id, fields);
        try program.called("write_trailers");
        if (written) |_| return null else |failure| return @as(?server.SendError, failure);
    }

    /// Cancels an open request. P3: from here the request's id names nothing a call may answer,
    /// and its one ending is `cancelled` with the reason `program`.
    pub fn cancel(program: *Program, request: *Request) Violation!void {
        assert(request.open and !request.cancel_called);
        program.endpoint.cancel(request.id);
        try program.called("cancel");
        request.cancel_called = true;
        const id = request.id;
        const head = try program.respond(id, .{ .status = answer_module.status, .end = true });
        const body = try program.write_body(id, .{ .octets = "", .end = true });
        const word = program.endpoint.set_user_data(id, request.word);
        try program.called("set_user_data");
        const word_refused = if (word) |_| false else |failure| failure == error.RequestUnknown;
        if (!unknown(head) or !unknown(body.failure) or !word_refused) return program.fail(error.CancelWrong, "cancel", id.connection, id.number);
    }

    pub fn shutdown(program: *Program, now_ns: u64) Violation!void {
        program.endpoint.shutdown(now_ns);
        program.ledger.shut_down = true;
        program.counts.shutdowns += 1;
        try program.called("shutdown");
    }

    pub fn send_stream(program: *Program, handle: Handle, output: []u8, now_ns: u64) Violation!usize {
        const written = program.endpoint.send_stream(handle, output, now_ns);
        try program.called("send_stream");
        return written;
    }

    /// The program closed the socket of a connection it holds, or its peer did.
    pub fn transport_closed(program: *Program, connection: *ledger_module.Connection) Violation!void {
        program.endpoint.transport_closed(connection.handle);
        try program.called("transport_closed");
        connection.close_socket(.closed_by_program);
    }

    pub fn send_datagram(program: *Program, output: []u8, now_ns: u64) Violation!?server.Sent {
        const sent = program.endpoint.send_datagram(output, now_ns);
        try program.called("send_datagram");
        return sent;
    }

    pub fn deadline_ns(program: *Program) Violation!?u64 {
        const at_ns = program.endpoint.deadline_ns();
        try program.called("deadline_ns");
        return at_ns;
    }

    pub fn on_instant(program: *Program, now_ns: u64) Violation!void {
        program.endpoint.on_instant(now_ns);
        try program.called("on_instant");
    }

    /// Sets a live connection's deadlines. A set the connection refuses keeps the ones it has, and
    /// is counted.
    pub fn set_deadlines(program: *Program, handle: Handle, deadlines: server.Deadlines) Violation!void {
        const set = program.endpoint.set_deadlines(handle, deadlines);
        try program.called("set_deadlines");
        set catch |failure| switch (failure) {
            error.DeadlineInvalid => program.counts.deadlines_refused += 1,
            error.ConnectionUnknown => return program.fail(error.RequestLost, "set_deadlines", handle, 0),
        };
    }

    /// P6, once a pass moved nothing, then P8. P6: a TCP connection with no `send` outstanding owes
    /// its socket nothing, the endpoint owes no event, a response that waits for room takes no
    /// write, and the endpoint owes no datagram.
    pub fn quiescence(program: *Program, now_ns: u64) Violation!void {
        // P8: after `on_instant(now)`, the drains and the datagrams it brought, the endpoint wants
        // no instant that has come. It goes first: the probes below fire each TCP connection's
        // deadlines themselves, which would hide an `on_instant` that missed one.
        if (try program.deadline_ns()) |at_ns| {
            if (at_ns <= now_ns) return program.fail(error.DeadlineNotAdvanced, "deadline_ns", nothing, at_ns);
        }
        try program.ledger.expect_closed_ended(program.now_ms);
        // P1: after `shutdown` the endpoint accepts no socket, a slot free or not.
        if (program.ledger.shut_down) _ = try program.accept(.cleartext, now_ns);
        try program.probe_sends(now_ns);
        try program.expect_no_event(now_ns);
        for (program.ledger.requests[0..program.ledger.requests_len]) |*request| {
            if (!request.open or !request.answer.waiting) continue;
            program.counts.waiting_probes += 1;
            if (try answer_module.probe(program, request)) return program.fail(error.WritableMissed, "probe", request.id.connection, request.id.number);
        }
        try program.expect_no_event(now_ns);
        if (try program.send_datagram(&program.datagram, now_ns)) |sent| {
            _ = sent;
            return program.fail(error.DatagramOwed, "send_datagram", nothing, 0);
        }
    }

    /// P6: `send_stream` writes nothing for a TCP connection with no `send` outstanding.
    fn probe_sends(program: *Program, now_ns: u64) Violation!void {
        const ledger = program.ledger;
        for (ledger.connections[0..ledger.connections_len]) |*connection| {
            if (connection.kind != .tcp or connection.ended or connection.socket != .open) continue;
            // The run answers every `send` at once, until a call leaves room, which ends it.
            if (program.endpoint.send_outstanding[connection.handle.slot]) return program.fail(error.SendMissed, "send_outstanding", connection.handle, 0);
            const written = try program.send_stream(connection.handle, &program.probe, now_ns);
            if (written > 0) return program.fail(error.SendMissed, "send_stream", connection.handle, written);
        }
    }

    fn expect_no_event(program: *Program, now_ns: u64) Violation!void {
        const received = try program.receive(.none, now_ns);
        const reported = received.event orelse return;
        _ = reported;
        return program.fail(error.EventMissed, "receive", nothing, 0);
    }
};

const testing = std.testing;
const tls = @import("tls");
const identity = @import("../client_trace_identity.zig");

/// The endpoint, the ledger and the program of the unit test: too large for a test's stack.
var test_endpoint: Endpoint align(@alignOf(Endpoint)) = undefined;
var test_config: server.EndpointConfig align(@alignOf(server.EndpointConfig)) = undefined;
var test_ledger: Ledger align(@alignOf(Ledger)) = undefined;
var test_program: Program align(@alignOf(Program)) = undefined;
var test_random: sim.Random align(@alignOf(sim.Random)) = undefined;

/// The instant the unit test's endpoint starts at, and the seed its draws come from.
const test_start_ns: u64 = 7_000_000;
const test_seed: u64 = 0x21b5;

fn test_fill(random: *sim.Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}

test "P5: a deadline heap whose top differs from the soonest slot's deadline is refused" {
    test_config = .{ .tls = .{
        .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
        .cookie_key = &identity.cookie_key,
        .cpu = identity.cpu,
    } };
    test_random = sim.Random.init(test_seed);
    try test_endpoint.init(&test_config, tls.Random.init(&test_random, test_fill), identity.now_seconds, test_start_ns);
    test_ledger.init();
    test_program.init(&test_endpoint, &test_ledger);
    const handle = (try test_program.accept(.cleartext, test_start_ns)).?;
    // The connection's first-request deadline (decision 110), which the heap holds for its slot.
    const at_ns = (try test_program.deadline_ns()).?;
    try testing.expectEqual(at_ns, test_endpoint.held.deadline_of(handle.slot).?);
    // The heap's copy moves without the connection's deadline moving: the oracle reads the slot.
    test_endpoint.cached[handle.slot] = at_ns + 1;
    try testing.expectError(error.DeadlineWrong, test_program.check_deadline("test"));
    try testing.expectEqualStrings("test", test_ledger.fault.call);
}
