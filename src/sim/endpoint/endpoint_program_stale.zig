//! The stale calls of the endpoint check's program (design §8 step 21b.5, decision 119): a call
//! by the id of a request that ended, or by the handle of a connection that ended, which the
//! endpoint must refuse (P4). Split off `endpoint_program.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const ledger_module = @import("endpoint_ledger.zig");
const program_module = @import("endpoint_program.zig");
const answer_module = @import("endpoint_answer.zig");

const Random = sim.Random;
const limits = sim.constants.endpoint;
const Program = program_module.Program;
const Violation = program_module.Violation;
const Request = ledger_module.Request;
const Connection = ledger_module.Connection;

/// The calls by an id, and the calls by a handle: two that any connection takes, and three more a
/// TCP connection takes.
const RequestCall = enum { set_user_data, respond, write_body, write_trailers, cancel };
const HandleCall = enum { set_deadlines, server_name, send_stream, transport_closed, receive };
const calls_any_connection: u64 = 2;

/// Makes one call by an id or a handle that names nothing any more, drawn from `random`, and
/// checks the endpoint refused it. Returns the event a stale `receive` reported, which the run
/// routes: one of another connection, since the stale one names nothing.
pub fn call(program: *Program, random: *Random, now_ns: u64) Violation!?server.Event {
    const ledger = program.ledger;
    const targets = ledger.requests_ended + ledger.connections_ended;
    if (targets == 0) return null;
    const target = random.below(targets);
    const drawn = random.next();
    program.counts.stale_calls += 1;
    if (target < ledger.requests_ended) {
        const request_call: RequestCall = @enumFromInt(drawn % std.enums.values(RequestCall).len);
        try by_id(program, ledger.ended_request(target), request_call);
        return null;
    }
    const connection = ledger.ended_connection(target - ledger.requests_ended);
    const count: u64 = if (connection.kind == .tcp) std.enums.values(HandleCall).len else calls_any_connection;
    return by_handle(program, connection, @enumFromInt(drawn % count), now_ns);
}

/// RFC 9110 §3.4: a response answers a request, so an id that names no open request takes no
/// write, and decision 119: no word.
fn by_id(program: *Program, request: *const Request, which: RequestCall) Violation!void {
    assert(!request.open);
    const id = request.id;
    const refused = switch (which) {
        .set_user_data => refused: {
            const set = program.endpoint.set_user_data(id, request.word);
            try program.check_deadline("set_user_data");
            break :refused if (set) |_| false else |failure| failure == error.RequestUnknown;
        },
        .respond => program_module.unknown(try program.respond(id, .{ .status = answer_module.status, .end = true })),
        .write_body => program_module.unknown((try program.write_body(id, .{ .octets = program.content[0..1], .end = true })).failure),
        .write_trailers => program_module.unknown(try program.write_trailers(id, &.{})),
        // Nothing follows: an event of the request after it is `EventAfterEnding`.
        .cancel => cancelled: {
            program.endpoint.cancel(id);
            try program.check_deadline("cancel");
            break :cancelled true;
        },
    };
    if (!refused) return program.fail(error.StaleCallTaken, @tagName(which), id.connection, id.number);
}

/// Decision 119: a slot's generation advances at its connection's `ended`, so a handle of an ended
/// connection names none.
fn by_handle(program: *Program, connection: *const Connection, which: HandleCall, now_ns: u64) Violation!?server.Event {
    assert(connection.ended);
    const handle = connection.handle;
    var reported: ?server.Event = null;
    const refused = switch (which) {
        .set_deadlines => refused: {
            const set = program.endpoint.set_deadlines(handle, .{});
            try program.check_deadline("set_deadlines");
            break :refused if (set) |_| false else |failure| failure == error.ConnectionUnknown;
        },
        .server_name => program.endpoint.server_name(handle) == null,
        .send_stream => try program.send_stream(handle, &program.probe, now_ns) == 0,
        .transport_closed => try closed_nothing(program, connection),
        .receive => dropped: {
            // The connection that holds the slot now, if one does, reads none of the octets: a
            // connection that failed on them would also consume them whole.
            const before = Holder.of(program, handle.slot);
            const octets = program.probe[0..limits.stale_octets_len];
            const received = try program.receive(.{ .stream = .{ .connection = handle, .octets = octets } }, now_ns);
            reported = received.event;
            break :dropped received.consumed == octets.len and std.meta.eql(before, Holder.of(program, handle.slot));
        },
    };
    if (!refused) return program.fail(error.StaleCallTaken, @tagName(which), handle, 0);
    return reported;
}

/// What the endpoint holds in a TCP slot: whether a connection, which one, and whether it failed
/// or its socket closed.
const Holder = struct {
    live: bool,
    generation: u32,
    failed: bool,
    transport: @TypeOf(@as(program_module.Endpoint, undefined).transports[0]),

    fn of(program: *const Program, slot: u32) Holder {
        const endpoint = program.endpoint;
        return .{ .live = endpoint.live[slot], .generation = endpoint.generations[slot], .failed = endpoint.failed[slot], .transport = endpoint.transports[slot] };
    }
};

/// A stale handle's `transport_closed` leaves the connection that took its slot since, whose socket
/// is open, with its socket open.
fn closed_nothing(program: *Program, connection: *const Connection) Violation!bool {
    const endpoint = program.endpoint;
    const slot = connection.handle.slot;
    assert(connection.kind == .tcp and slot < limits.tcp_slots);
    endpoint.transport_closed(connection.handle);
    try program.check_deadline("transport_closed");
    if (!endpoint.live[slot]) return true;
    const current: server.ConnectionHandle = .{ .slot = slot, .generation = endpoint.generations[slot] };
    const holder = program.ledger.connection_of(current) orelse return true;
    if (holder.socket != .open) return true;
    return endpoint.transports[slot] == .open;
}
