//! The state of `spec/tla/h3_connection`'s model, computed from both endpoints of the h3 trace
//! run after each of its steps (https://github.com/c4milo/colibri/issues/58). The model's
//! variables keep their names here, spelled the Zig way.
//!
//! Most variables read colibri directly. Five are choices, because colibri and the model cut the
//! same events at different places:
//! - A frame is sent once the client's QUIC framed it: the model's frames arrive as they are
//!   sent, and a frame QUIC framed may still be in flight, which the model reads as not yet read.
//! - Flow control never binds in a trace run, so the two limits are the scope's windows.
//! - `decoderKnown` counts the acknowledgments the decoder queued: the model raises it when it
//!   queues one, colibri when it writes one (`qpack/decoder_stream.zig`).
//! - `decoderStream` is what the server wrote on its decoder stream and the client has not read,
//!   then what its decoder queued and has not written.
//! - Before the server starts h3, `control` holds SETTINGS, which the model's Init writes.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h3_trace_plan = @import("h3_trace_plan.zig");
const h3_trace_endpoint = @import("h3_trace_endpoint.zig");
const h3_trace_tracker = @import("h3_trace_tracker.zig");

const Endpoint = h3_trace_endpoint.Endpoint;
const Tracker = h3_trace_tracker.Tracker;
const constants = sim.constants;
const request_count = constants.h3_trace_requests_max;
const request_stream_step = h3_trace_endpoint.request_stream_step;

pub const Outcome = h3_trace_endpoint.Outcome;
pub const Reset = enum { none, sent, arrived, read };
pub const Phase = enum { unseen, head, blocked, content, done, answered, abandoned };
pub const ToClient = enum { none, response, rejected };
pub const InstructionKind = enum { acknowledgment, cancellation, increment };

pub const Instruction = struct {
    kind: InstructionKind = .increment,
    stream: u64 = 0,
    count: u64 = 0,
};

pub const ControlFrame = struct {
    goaway: bool = false,
    id: u64 = 0,
};

/// The most instructions in flight at once, and the most control frames.
const in_flight_max: usize = constants.h3_trace_units_max;

/// The model's constants for one plan (spec/tla/h3_connection/H3Connection.tla).
pub const Scope = struct {
    requests: u64,
    content: u64,
    inserts_max: u64,
    blocked_streams: u64,
    goaways: u64,
    /// Whether the server's decoder allows a dynamic table (RFC 9204 §3.2.3).
    decoder_table: bool,

    pub fn of(plan: *const h3_trace_plan.Plan) Scope {
        const table = plan.server_decoder.max_table_capacity > 0;
        return .{
            .requests = plan.requests,
            .content = plan.content,
            .inserts_max = if (table) plan.inserts_max() else 0,
            .blocked_streams = plan.server_decoder.blocked_streams,
            .goaways = plan.goaways,
            .decoder_table = table,
        };
    }

    pub fn units(scope: Scope) u64 {
        return 1 + scope.content;
    }

    /// Wider than everything the plan sends, so no limit ever binds.
    pub fn connection_window(scope: Scope) u64 {
        return scope.requests * scope.units() + scope.inserts_max + 1;
    }

    pub fn encoder_window(scope: Scope) u64 {
        return scope.inserts_max + 1;
    }

    /// The model's `NoGoaway`, which is above every stream.
    pub fn no_goaway(scope: Scope) u64 {
        return scope.requests + 1;
    }
};

pub const State = struct {
    opened: u64 = 0,
    inserted: u64 = 0,
    known: u64 = 0,
    ric: [request_count]u64 = @splat(0),
    outstanding: [request_count]u64 = @splat(0),
    encoder_queued: u64 = 0,
    request_queued: [request_count]u64 = @splat(0),
    encoder_sent: u64 = 0,
    request_sent: [request_count]u64 = @splat(0),
    connection_limit: u64 = 0,
    encoder_limit: u64 = 0,
    settings_received: bool = false,
    goaway_received: u64 = 0,
    outcome: [request_count]Outcome = @splat(.none),
    reset: [request_count]Reset = @splat(.none),
    taken: u64 = 0,
    phase: [request_count]Phase = @splat(.unseen),
    processed: [request_count]bool = @splat(false),
    consumed: [request_count]u64 = @splat(0),
    encoder_consumed: u64 = 0,
    decoder_known: u64 = 0,
    decoder_stream: [in_flight_max]Instruction = @splat(.{}),
    decoder_stream_len: usize = 0,
    to_client: [request_count]ToClient = @splat(.none),
    goaway_sent: u64 = 0,
    goaway_count: u64 = 0,
    control: [in_flight_max]ControlFrame = @splat(.{}),
    control_len: usize = 0,
};

/// The model's state after the step that just ended. `tracker` has observed it.
pub fn compute(tracker: *Tracker, scope: Scope, client: *const Endpoint, server: *const Endpoint) State {
    var state: State = .{};
    client_state(&state, tracker, scope, client);
    server_state(&state, tracker, scope, client, server);
    return state;
}

fn client_state(state: *State, tracker: *const Tracker, scope: Scope, client: *const Endpoint) void {
    const h3 = &client.h3;
    state.opened = client.opened;
    state.inserted = h3.encoder.table.insert_count();
    state.known = h3.encoder.state.known_received;
    state.encoder_sent = inserts_framed(tracker, client);
    assert(state.encoder_sent <= state.inserted);
    state.encoder_queued = state.inserted - state.encoder_sent;
    state.connection_limit = scope.connection_window();
    state.encoder_limit = scope.encoder_window();
    state.settings_received = h3.peer_settings != null;
    state.goaway_received = if (h3.goaway_received) |id| id / request_stream_step else scope.no_goaway();
    for (0..client.opened) |r| {
        state.ric[r] = client.required[r];
        state.outstanding[r] = client.outstanding_required(r * request_stream_step);
        state.request_sent[r] = tracker.request_sent[r];
        state.request_queued[r] = if (tracker.reset_sent[r]) 0 else scope.units() - tracker.request_sent[r];
        state.outcome[r] = client.outcome[r];
    }
}

/// Inserts whose octets the client's QUIC framed at least once.
fn inserts_framed(tracker: *const Tracker, client: *const Endpoint) u64 {
    const id = client.h3.local.encoder_id orelse return 0;
    const stream = h3_trace_tracker.live(&client.transport.connection, .{ .value = id }) orelse return 0;
    var count: u64 = 0;
    for (tracker.inserts.items()) |end| {
        if (end <= stream.outgoing.framed_end) count += 1;
    }
    return count;
}

fn server_state(state: *State, tracker: *Tracker, scope: Scope, client: *const Endpoint, server: *const Endpoint) void {
    const h3 = &server.h3;
    state.taken = @min(h3.requests.next_index, scope.requests);
    state.encoder_consumed = h3.decoder.table.insert_count();
    state.decoder_known = decoder_known(server);
    state.goaway_sent = if (h3.goaway_sent) |id| id / request_stream_step else scope.no_goaway();
    state.goaway_count = server.goaways_sent;
    write_control(state, tracker, client, server);
    write_decoder_stream(state, tracker, client, server);
    for (0..scope.requests) |r| {
        state.phase[r] = phase_of(state, scope, server, r);
        state.reset[r] = reset_of(state, tracker, server, r);
        state.processed[r] = server.read[r].head;
        state.consumed[r] = consumed_of(state, tracker, scope, server, r);
        tracker.consumed[r] = state.consumed[r];
        state.to_client[r] = to_client_of(state, client, server, r);
    }
}

/// The insert count the decoder has reported, or queued an acknowledgment to report.
fn decoder_known(server: *const Endpoint) u64 {
    const decoder = &server.h3.decoder;
    var known = decoder.known_received;
    for (decoder.owed[0..decoder.owed_len]) |owed| {
        switch (owed) {
            .section_acknowledgment => |section| known = @max(known, section.required_insert_count),
            .stream_cancellation => {},
        }
    }
    return known;
}

/// How far the client's h3 has read one of the server's streams.
fn read_end(client: *const Endpoint, id: ?u64) u64 {
    const held = id orelse return 0;
    const stream = h3_trace_tracker.live(&client.transport.connection, .{ .value = held }) orelse return 0;
    return stream.receive_flow.consumed;
}

fn write_control(state: *State, tracker: *const Tracker, client: *const Endpoint, server: *const Endpoint) void {
    // The model's Init writes SETTINGS, which colibri writes when the server's h3 starts.
    if (server.h3.local.control_id == null) {
        state.control[0] = .{};
        state.control_len = 1;
        return;
    }
    const read = read_end(client, server.h3.local.control_id);
    for (tracker.control.items()) |frame| {
        if (frame.end <= read) continue;
        state.control[state.control_len] = .{ .goaway = frame.kind == .goaway, .id = frame.id };
        state.control_len += 1;
    }
}

fn write_decoder_stream(state: *State, tracker: *const Tracker, client: *const Endpoint, server: *const Endpoint) void {
    const read = read_end(client, server.h3.local.decoder_id);
    for (tracker.decoder.items()) |held| {
        if (held.end <= read) continue;
        append_instruction(state, .{ .kind = @enumFromInt(@intFromEnum(held.kind)), .stream = held.stream, .count = held.count });
    }
    const decoder = &server.h3.decoder;
    for (decoder.owed[0..decoder.owed_len]) |owed| {
        append_instruction(state, switch (owed) {
            .section_acknowledgment => |section| .{ .kind = .acknowledgment, .stream = section.stream_id / request_stream_step },
            .stream_cancellation => |id| .{ .kind = .cancellation, .stream = id / request_stream_step },
        });
    }
}

fn append_instruction(state: *State, instruction: Instruction) void {
    assert(state.decoder_stream_len < state.decoder_stream.len);
    state.decoder_stream[state.decoder_stream_len] = instruction;
    state.decoder_stream_len += 1;
}

fn reset_of(state: *const State, tracker: *const Tracker, server: *const Endpoint, r: usize) Reset {
    if (!tracker.reset_sent[r]) return .none;
    if (server.read[r].reset) return .read;
    if (!tracker.reset_arrived[r]) return .sent;
    // A refused stream's reset is read and forgotten with no event (`h3` `on_reset`). A reset
    // that arrives after the request was read whole is read by no one (ReadReset).
    const reading = state.phase[r] != .done and state.phase[r] != .answered;
    return if (reading and slot_of(server, r) == null) .read else .arrived;
}

/// The server h3's slot for request `r`, while it holds one.
fn slot_of(server: *const Endpoint, r: usize) ?*const @TypeOf(server.h3.requests.slots[0].?) {
    for (&server.h3.requests.slots) |*slot| {
        if (slot.*) |*held| {
            if (held.id == r * request_stream_step) return held;
        }
    }
    return null;
}

/// Whether the server refused request `r` after its GOAWAY (RFC 9114 §5.2): a GOAWAY names the
/// first request not taken, so a request taken since is at or above it.
fn rejected(state: *const State, r: usize) bool {
    return r < state.taken and r >= state.goaway_sent;
}

fn phase_of(state: *const State, scope: Scope, server: *const Endpoint, r: usize) Phase {
    if (r >= state.taken) return .unseen;
    const read = &server.read[r];
    if (rejected(state, r) or read.reset) return .abandoned;
    if (slot_of(server, r)) |slot| {
        if (slot.phase == .abandoned) return .abandoned;
        if (slot.blocked_at != null) return .blocked;
    }
    if (read.answered) return .answered;
    if (!read.head) return .head;
    const data_frames = read.content_len / constants.h3_trace_data_len;
    return if (data_frames == scope.content) .done else .content;
}

fn consumed_of(state: *const State, tracker: *const Tracker, scope: Scope, server: *const Endpoint, r: usize) u64 {
    if (state.phase[r] == .abandoned) {
        // The model discards what arrives on an abandoned stream, but not past a reset it has
        // not read (Discard, ReadReset).
        return if (state.reset[r] == .arrived) tracker.consumed[r] else state.request_sent[r];
    }
    const read = &server.read[r];
    if (!read.head) return 0;
    return 1 + @min(read.content_len / constants.h3_trace_data_len, scope.content);
}

fn to_client_of(state: *const State, client: *const Endpoint, server: *const Endpoint, r: usize) ToClient {
    if (client.answer_read[r]) return .none;
    if (rejected(state, r)) return .rejected;
    if (server.read[r].answered) return .response;
    return .none;
}
