//! The state of `spec/tla/h2_connection`'s model, computed from the TCP trace run's endpoints
//! (https://github.com/c4milo/colibri/issues/79), in the h2 trace's `State`.
//!
//! Each stream's state comes from each connection's h2 stream table, as in the h2 trace. What each
//! side wrote is parsed out of the protocol's octets it handed out and those its output still
//! holds, after its preface; the server's HEADERS frames are of the kinds its caller's calls wrote.
//! What each side read comes from the events the server reported and the exchanges the client
//! filled. The frames in flight are the ones the writer wrote and the reader has not read: what the
//! reader left of what was handed out, then the writer's output.
//!
//! Over TLS the protocol's octets are the plaintext of the records (`tcp_trace_direction.zig`), and
//! the reader has read what the records it opened held, less what it holds unread. Until a side's
//! handshake completes it has no h2 connection, and the model's state for it is the initial one.
//!
//! The client sends a GOAWAY of its own when it closes after the server's (RFC 9113 §6.8). It names
//! the last stream the server opened, and colibri's server opens none (decision 17), so it changes
//! no stream the model holds, which leaves it out as it leaves out SETTINGS and PING.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const client = @import("client");
const sim = @import("sim");
const h2_trace_state = @import("h2_trace_state.zig");
const h2_trace_pair = @import("h2_trace_pair.zig");
const world_module = @import("tcp_trace_world.zig");
const plan_module = @import("tcp_trace_plan.zig");
const direction_module = @import("tcp_trace_direction.zig");

const limits = sim.constants.h2_trace;
pub const State = h2_trace_state.State;
const Frame = h2_trace_state.Frame;
const Kind = h2_trace_state.Kind;
const HeadKind = h2_trace_state.HeadKind;
const ResponsePhase = h2_trace_state.ResponsePhase;
const World = world_module.World;
const Direction = direction_module.Direction;
const Plan = plan_module.Plan;

pub const Error = h2_trace_state.Error || error{
    /// A send wrote the protocol's octets after it sealed some, or a reader stopped inside one
    /// send's records, so the run cannot place the reader in the plaintext.
    PlaintextUnplaced,
};

/// The frames of one side's writes, at most: the model's kinds over a whole run.
const Frames = [limits.frames_max]Frame;

/// One side's writes: every octet it handed out, then what its output holds, which the reader takes
/// in that order.
const Written = struct {
    handed: []const u8,
    output: []const u8,
    /// The octets at the start that are its preface (RFC 9113 §3.4), or 0 while it wrote none.
    preface_len: usize,

    fn of(direction: *const Direction, output: []const u8, magic_len: usize) Written {
        // A send takes the whole output, so what a side wrote first is in one of the two.
        const handed = direction.handed_plaintext();
        const start = if (handed.len > 0) handed else output;
        const preface_len = preface_len_of(start, magic_len);
        assert(handed.len == 0 or handed.len >= preface_len);
        return .{ .handed = handed, .output = output, .preface_len = preface_len };
    }

    /// The two parts with the first `skip` octets left out.
    fn after(written: Written, skip: usize) Parts {
        if (skip <= written.handed.len) return .{ .handed = written.handed[skip..], .output = written.output };
        return .{ .handed = "", .output = written.output[skip - written.handed.len ..] };
    }
};

/// What a reader takes from one side's writes, in order.
const Parts = struct {
    handed: []const u8,
    output: []const u8,
};

/// The model's state after an action, for a seed whose plan names `plan.streams` streams.
pub fn compute(world: *World, plan: *const Plan) Error!State {
    var state: State = .{};
    const n: usize = plan.streams;
    const client_h2 = world_module.h2_of(&world.client.session);
    const server_h2 = world_module.h2_of(&world.server.session);
    note_streams(client_h2, server_h2, n, &state);
    const from_client = Written.of(&world.to_server, pending(&world.client), h2.constants.client_preface_len);
    const from_server = Written.of(&world.to_client, pending(&world.server), 0);
    try note_client_writes(from_client, &state);
    try note_server_writes(from_server, world.to_client.heads[0..world.to_client.heads_written], &state);
    @memcpy(state.request_read[0..n], world.request_read[0..n]);
    for (world.exchanges[0..world.requested], 0..) |*exchange, index| {
        state.response_read[index] = response_read_of(exchange.outcome, exchange.status, exchange.interims);
    }
    // The client drops the plaintext it read at once, so all it holds is unread. The server holds
    // what its last event pointed into, `plain_in_read` octets, until its next call.
    const server_read = try read_of(&world.to_server, world.tls, world.server.plain_in_len - world.server.plain_in_read);
    const client_read = try read_of(&world.to_client, world.tls, world.client.plain_in_len);
    state.to_server_len = drop_goaways(&state.to_server, try in_flight(from_client, server_read, .preface, null, &state.to_server));
    const heads = world.to_client.heads[0..world.to_client.heads_written];
    state.to_client_len = try in_flight(from_server, client_read, .settings, heads, &state.to_client);
    const no_goaway: u32 = plan.streams + 1;
    state.goaway_sent = if (server_h2) |connection| last_of(connection.streams.goaway_sent_last_id, no_goaway) else no_goaway;
    state.goaway_read = if (client_h2) |connection| last_of(connection.streams.goaway_received_last_id, no_goaway) else no_goaway;
    state.malformed = world.malformed;
    state.broken = world.broken or has_failed(client_h2) or has_failed(server_h2);
    state.late_open = if (world.open_at_goaway) |open| world.client_streams_open() > open else false;
    note_prefaces(client_h2, server_h2, &state);
    return state;
}

/// Each stream's state at each endpoint, idle at one with no h2 connection yet.
fn note_streams(client_h2: ?*h2.Connection, server_h2: ?*h2.Connection, n: usize, state: *State) void {
    for (0..n) |index| {
        const id = h2_trace_pair.id_of(@intCast(index + 1));
        if (client_h2) |connection| state.client_state[index], state.client_closed[index] = h2_trace_state.stream_of(connection, id);
        if (server_h2) |connection| state.server_state[index], state.server_closed[index] = h2_trace_state.stream_of(connection, id);
    }
}

/// Whether each endpoint wrote its preface and read its peer's.
fn note_prefaces(client_h2: ?*h2.Connection, server_h2: ?*h2.Connection, state: *State) void {
    if (client_h2) |connection| {
        state.client_preface = connection.preface_done();
        // RFC 9113 §3.4: the first frame each endpoint reads is its peer's SETTINGS, which ends
        // the peer's preface.
        state.client_read_preface = connection.first_frame_read;
    }
    if (server_h2) |connection| {
        state.server_preface = connection.preface_done();
        state.server_read_preface = connection.first_frame_read;
    }
}

fn has_failed(connection: ?*h2.Connection) bool {
    return if (connection) |h2_connection| h2_connection.has_failed() else false;
}

fn last_of(last_id: ?u32, no_goaway: u32) u32 {
    return if (last_id) |last| h2_trace_state.last_index(last) else no_goaway;
}

/// The protocol's octets a connection wrote that its caller has not handed out: what `output`
/// holds after the records of the handshake.
fn pending(connection: anytype) []const u8 {
    return connection.output[connection.records_len..connection.output_len];
}

/// The protocol's octets the reader of `direction` has read: what it opened, less the `unread`
/// octets it holds.
fn read_of(direction: *const Direction, tls: bool, unread: usize) Error!usize {
    const opened = direction.opened_plaintext(tls) orelse return error.PlaintextUnplaced;
    assert(unread <= opened);
    return opened - unread;
}

/// The octets of the preface `start` begins with: `magic_len` octets and a whole SETTINGS frame
/// (RFC 9113 §3.4), or 0 when it begins with anything else. A side that wrote another frame first
/// has no preface at the start, and the state shows that frame for TLC to judge.
fn preface_len_of(start: []const u8, magic_len: usize) usize {
    if (start.len <= magic_len) return 0;
    var reader = h2.core.Reader.init(start[magic_len..]);
    const header = h2.frame.read_header(&reader) catch return 0;
    const len = magic_len + h2.constants.frame_header_len + header.length;
    if (header.type != h2.constants.frame_type_settings or len > start.len) return 0;
    return len;
}

/// Leaves the client's GOAWAY frames out of `frames[0..len]`, and returns how many are left.
fn drop_goaways(frames: *[limits.frames_max]Frame, len: u32) u32 {
    var kept: u32 = 0;
    for (frames[0..len]) |frame| {
        if (frame.kind == .goaway) continue;
        frames[kept] = frame;
        kept += 1;
    }
    return kept;
}

/// How far the client read a response, from what it filled in the exchange (RFC 9110 §15.2).
fn response_read_of(outcome: client.Outcome, status: u16, interims: u32) ResponsePhase {
    if (outcome == .response) return .ended;
    if (status != 0) return .final;
    return if (interims > 0) .interim else .none;
}

/// The model's frames among a side's writes after its preface: every one of the run, in order.
fn frames_written(written: Written, heads: ?[]const HeadKind, frames: *Frames) Error![]const Frame {
    const parts = written.after(written.preface_len);
    const first_heads = if (heads) |kinds| kinds[0..h2_trace_state.headers_in(parts.handed)] else null;
    const second_heads = if (heads) |kinds| kinds[h2_trace_state.headers_in(parts.handed)..] else null;
    const first = try h2_trace_state.frames_in(parts.handed, first_heads, frames);
    const second = try h2_trace_state.frames_in(parts.output, second_heads, frames[first..]);
    return frames[0 .. first + second];
}

/// How far the client wrote each request, and its DATA frames.
fn note_client_writes(written: Written, state: *State) Error!void {
    var frames: Frames = undefined;
    for (try frames_written(written, null, &frames)) |frame| {
        if (frame.stream == 0) continue;
        const index = frame.stream - 1;
        switch (frame.kind) {
            .head => state.request[index] = if (frame.end) .ended else .head,
            .data => {
                state.request_data[index] += 1;
                if (frame.end) state.request[index] = .ended;
            },
            .trailers => state.request[index] = .ended,
            .interim, .rst, .goaway, .preface, .settings => {},
        }
    }
}

/// How far the server wrote each response, its interim heads and DATA frames, and its GOAWAY
/// frames.
fn note_server_writes(written: Written, heads: []const HeadKind, state: *State) Error!void {
    var frames: Frames = undefined;
    for (try frames_written(written, heads, &frames)) |frame| {
        if (frame.kind == .goaway) state.goaway_count += 1;
        if (frame.stream != 0) note_response_frame(frame, state);
    }
}

fn note_response_frame(frame: Frame, state: *State) void {
    assert(frame.stream >= 1);
    const index = frame.stream - 1;
    switch (frame.kind) {
        .interim => {
            state.response_interims[index] += 1;
            if (state.response[index] == .none) state.response[index] = .interim;
        },
        .head => state.response[index] = if (frame.end) .ended else .final,
        .data => {
            state.response_data[index] += 1;
            if (frame.end) state.response[index] = .ended;
        },
        .trailers => state.response[index] = .ended,
        .rst, .goaway, .preface, .settings => {},
    }
}

/// The model's frames in flight from a side whose reader consumed `consumed` octets: its preface,
/// as `preface` names it, while any of it is left, then the frames after. `heads` names the kinds
/// of every HEADERS frame the side wrote, in order, or null when each is a head.
fn in_flight(written: Written, consumed: usize, preface: Kind, heads: ?[]const HeadKind, frames: *[limits.frames_max]Frame) Error!u32 {
    var len: u32 = 0;
    if (written.preface_len > consumed) {
        frames[0] = .{ .stream = 0, .kind = preface, .end = false, .last = 0 };
        len = 1;
    }
    const parts = written.after(@max(written.preface_len, consumed));
    const first_count = h2_trace_state.headers_in(parts.handed);
    const second_count = h2_trace_state.headers_in(parts.output);
    // The HEADERS frames in flight are the last ones written.
    const first_heads = if (heads) |kinds| kinds[kinds.len - first_count - second_count .. kinds.len - second_count] else null;
    const second_heads = if (heads) |kinds| kinds[kinds.len - second_count ..] else null;
    len += try h2_trace_state.frames_in(parts.handed, first_heads, frames[len..]);
    len += try h2_trace_state.frames_in(parts.output, second_heads, frames[len..]);
    return len;
}
