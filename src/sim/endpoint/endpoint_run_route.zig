//! What the program of an endpoint run does with each event (design §8 step 21b.5, decision 119):
//! the ledger checks it first, then a request's head sets its word and draws its answer, its end
//! lets the answer start, a `send` is answered with `send_stream` at once, a `close` closes the
//! peer's socket, and an `ended` frees the peer. Split off `endpoint_run.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const plan_module = @import("endpoint_plan.zig");
const answer_module = @import("endpoint_answer.zig");
const run_module = @import("endpoint_run.zig");
const tcp_module = @import("endpoint_tcp.zig");
const quic_module = @import("endpoint_quic.zig");

const limits = sim.constants.endpoint;
const Storage = run_module.Storage;
const Error = run_module.Error;

/// The instant `ms` milliseconds into the run, from its base, in nanoseconds.
pub fn ns_of(plan: *const plan_module.Plan, ms: u64) u64 {
    return (plan.base_ms + ms) * limits.ns_per_ms;
}

/// Reads every event the endpoint owes, and returns whether it reported any.
pub fn drain(storage: *Storage, now_ns: u64, now_ms: u64) Error!bool {
    var moved = false;
    // Bounded: a pass reads `events_per_pass_max` events at most.
    for (0..limits.events_per_pass_max) |_| {
        const received = try storage.program.receive(.none, now_ns);
        const reported = received.event orelse return moved;
        moved = true;
        try route(storage, reported, now_ns, now_ms);
    }
    return error.RunStalled;
}

/// The ledger checks `reported` (P1 to P4), and the program acts on it.
pub fn route(storage: *Storage, reported: server.Event, now_ns: u64, now_ms: u64) Error!void {
    try storage.ledger.note(reported, now_ms);
    const program = &storage.program;
    const random = &storage.program_random;
    switch (reported) {
        .request => |head| {
            const connection = storage.ledger.connection_of(head.id.connection).?;
            switch (connection.kind) {
                .tcp => tcp_module.note_read(&storage.tcp.peers[connection.peer], now_ms),
                .quic => quic_module.note_read(&storage.quic.peers[connection.peer], head.id.number, now_ms),
            }
            try answer_module.on_request(program, storage.ledger.request_of(head.id).?, &head, random);
        },
        .body => |body| {
            const request = storage.ledger.request_of(body.id).?;
            if (body.end) answer_module.on_request_end(request);
            try answer_module.reword(program, request, random);
        },
        .trailers => |trailers| answer_module.on_request_end(storage.ledger.request_of(trailers.id).?),
        .writable, .done, .cancelled => {},
        .send => |handle| try answer_send(storage, handle, now_ns),
        // The program closes the socket: its peer reads and writes nothing more on it.
        .close => |handle| storage.tcp.peers[storage.ledger.connection_of(handle).?.peer].closed = true,
        .ended => |over| note_ended(storage, over.connection),
        .closed => storage.record.closed = true,
    }
}

/// A connection ended, so its peer is over and driven no more.
fn note_ended(storage: *Storage, handle: server.ConnectionHandle) void {
    const connection = storage.ledger.connection_of(handle).?;
    switch (connection.kind) {
        .tcp => {
            const peer = &storage.tcp.peers[connection.peer];
            peer.state = .over;
            peer.closed = true;
        },
        .quic => {
            const peer = &storage.quic.peers[connection.peer];
            peer.ended = true;
            peer.state = .detached;
        },
    }
}

/// P7: a `send` brings octets. The run answers it at once with a buffer of the endpoint's output,
/// again until a call leaves room, and the peer's socket takes every octet: it is never full.
fn answer_send(storage: *Storage, handle: server.ConnectionHandle, now_ns: u64) Error!void {
    const connection = storage.ledger.connection_of(handle).?;
    const stream = &storage.tcp.peers[connection.peer].to_client;
    const output_len = server.constants.output_len;
    // Bounded: the socket holds `sends_per_event_max` buffers of the endpoint's output.
    for (0..limits.sends_per_event_max) |index| {
        const room = stream.free();
        if (room.len < output_len) return error.SocketFull;
        const written = try storage.program.send_stream(handle, room[0..output_len], now_ns);
        // P7 (design §8 step 21b.5): a `send` is followed by a `send_stream` that writes an octet.
        if (index == 0 and written == 0) return storage.program.fail(error.SendEmpty, "send_stream", handle, 0);
        storage.record.wire.update(room[0..written]);
        stream.written += written;
        if (written < output_len) return;
    }
    return error.RunStalled;
}

/// The program writes what each answer owes that can be written: its request ended, it waits for
/// no room, and it is not over. Returns whether the endpoint took anything.
pub fn answer_all(storage: *Storage) Error!bool {
    var moved = false;
    const ledger = &storage.ledger;
    // Bounded by the requests the ledger holds; an answer opens none.
    for (ledger.requests[0..ledger.requests_len]) |*request| {
        if (!request.open) continue;
        if (try answer_module.write(&storage.program, request, &storage.program_random)) moved = true;
    }
    return moved;
}
