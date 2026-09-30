//! The state of `spec/tla/server_deadlines`'s model, computed from the deadline trace run's
//! endpoints after an action (https://github.com/c4milo/colibri/issues/86). Each variable is one the
//! model names, in octets as the model counts them, and three more are colibri's own clocks, which
//! TLC requires to run exactly when the model says they do.
//!
//! The windows, the credit gathered and the replies owed come from each endpoint's h2 connection.
//! A stream's window keeps its last value once the stream's record is gone, as the model's does,
//! and credit gathered on a stream whose DATA ended is dropped, as the model drops it. The frames
//! in flight, and those colibri's output holds, are parsed out of the octets. What each message
//! wrote and read comes from the calls each endpoint took and the events it reported
//! (`deadline_trace_world.zig`).
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const server = @import("server");
const sim = @import("sim");
const world_module = @import("deadline_trace_world.zig");

const limits = sim.constants.deadline_trace;
const World = world_module.World;
pub const Part = world_module.Part;

/// The frames the model carries, the client's preface and SETTINGS counting as one.
pub const Kind = enum { preface, settings, settings_ack, headers, data, window_update };

pub const Frame = struct {
    kind: Kind = .data,
    /// The stream identifier, 0 for the connection.
    stream: u32 = 0,
    /// Payload octets.
    len: u32 = 0,
    end: bool = false,
    /// A WINDOW_UPDATE's increment.
    value: u32 = 0,
};

pub const Frames = struct {
    items: [limits.frames_max]Frame = @splat(.{}),
    len: u32 = 0,

    pub fn slice(frames: *const Frames) []const Frame {
        return frames.items[0..frames.len];
    }
};

/// A WINDOW_UPDATE owed on a stream.
pub const Owed = struct {
    stream: u32 = 0,
    increment: u32 = 0,
};

pub const OwedList = struct {
    items: [limits.stream_owed_max]Owed = @splat(.{}),
    len: u32 = 0,

    pub fn slice(owed: *const OwedList) []const Owed {
        return owed.items[0..owed.len];
    }
};

/// What one endpoint's h2 connection says about one side: its windows, its credit and its replies.
pub const Side = struct {
    window: [limits.streams_max]i64 = @splat(0),
    connection: i64 = 0,
    released: [limits.streams_max]u32 = @splat(0),
    released_connection: u32 = 0,
    acks_owed: u32 = 0,
    connection_owed: u32 = 0,
    stream_owed: OwedList = .{},
};

pub const State = struct {
    req_read: [limits.streams_max]Part = @splat(.none),
    resp: [limits.streams_max]Part = @splat(.none),
    resp_written: [limits.streams_max]u32 = @splat(0),
    produced: [limits.streams_max]u32 = @splat(0),
    /// colibri's side: its send windows, the credit it gathered and what it owes.
    colibri: Side = .{},
    out: Frames = .{},
    first_request_read: bool = false,
    idle_started: bool = false,
    settings_acked: bool = false,
    small_increment: bool = false,
    to_client: Frames = .{},
    to_server: Frames = .{},
    cli_req: [limits.streams_max]Part = @splat(.none),
    cli_sent: [limits.streams_max]u32 = @splat(0),
    cli_resp: [limits.streams_max]Part = @splat(.none),
    /// The client's side.
    client: Side = .{},
    /// The frames that arrived at colibri, and those it handed out.
    arrived: u32 = 0,
    handed_out: u32 = 0,
    /// colibri's clocks: the SETTINGS acknowledgment's, each body's rate and each stream's send.
    settings_runs: bool = false,
    body_runs: [limits.streams_max]bool = @splat(false),
    send_runs: [limits.streams_max]bool = @splat(false),
};

pub const Error = error{
    /// A queue, or colibri's output, held more frames than `frames_max`, or an endpoint owed more
    /// WINDOW_UPDATE frames about streams than `stream_owed_max`: a harness defect.
    FramesFull,
};

/// Frame types (RFC 9113 §6), and the flags the model reads (§6.1, §6.2, §6.5).
const type_data: u8 = 0x0;
const type_headers: u8 = 0x1;
const type_settings: u8 = 0x4;
const type_window_update: u8 = 0x8;
const flag_end_stream: u8 = 0x1;
const flag_ack: u8 = 0x1;
/// The reserved bit of a WINDOW_UPDATE's increment (RFC 9113 §6.9).
const increment_mask: u32 = 0x7fff_ffff;

/// The model's state after an action. `previous` is the state before it, whose windows a stream
/// whose record is gone keeps.
pub fn compute(world: *World, plan_streams: u32, previous: ?*const State) Error!State {
    var state: State = .{};
    const n: usize = plan_streams;
    @memcpy(state.req_read[0..n], world.req_read[0..n]);
    @memcpy(state.resp[0..n], world.resp[0..n]);
    @memcpy(state.resp_written[0..n], world.resp_written[0..n]);
    @memcpy(state.produced[0..n], world.produced[0..n]);
    @memcpy(state.cli_req[0..n], world.cli_req[0..n]);
    @memcpy(state.cli_sent[0..n], world.cli_sent[0..n]);
    @memcpy(state.cli_resp[0..n], world.cli_resp[0..n]);
    const session = &world.server.session.h2;
    state.colibri = try side_of(session, n, &world.req_read, if (previous) |before| &before.colibri else null);
    state.client = try side_of(&world.client, n, &world.cli_resp, if (previous) |before| &before.client else null);
    state.out = try frames_of(world.server.output[0..world.server.output_len], 0);
    state.to_client = try frames_of(world.to_client.held(), world.to_client.preface_len);
    state.to_server = try frames_of(world.to_server.held(), world.to_server.preface_len);
    state.arrived = world.arrived;
    state.handed_out = world.handed_out;
    state.first_request_read = world.server.clock.first_request_read;
    state.idle_started = world.server.clock.idle_since_ns != null;
    state.settings_acked = session.settings_deadline_ns() == null;
    state.small_increment = session.tiny_update_read;
    state.settings_runs = !state.settings_acked and world.server.clock.settings_pause_since_ns == null;
    for (0..n) |index| {
        const id: u64 = world_module.id_of(@intCast(index));
        state.body_runs[index] = body_runs(&world.server, id);
        state.send_runs[index] = send_runs(&world.server, id);
    }
    return state;
}

/// One endpoint's windows, credit and replies. `ended` names the streams whose DATA toward it
/// ended, whose credit it no longer gathers.
fn side_of(connection: *h2.Connection, n: usize, ended: *const [limits.streams_max]Part, before: ?*const Side) Error!Side {
    var side: Side = .{};
    for (0..n) |index| {
        const last: ?i64 = if (before) |previous| previous.window[index] else null;
        stream_of(connection, @intCast(index), ended[index] == .ended, last, &side);
    }
    side.connection = connection.send_window.available;
    side.released_connection = connection.receive_window.released;
    side.acks_owed = connection.replies.settings_acks;
    side.connection_owed = connection.replies.connection_increment;
    for (connection.replies.stream_replies[0..connection.replies.stream_reply_count]) |reply| {
        if (reply.kind != .window_update) continue;
        if (side.stream_owed.len == side.stream_owed.items.len) return error.FramesFull;
        side.stream_owed.items[side.stream_owed.len] = .{ .stream = reply.stream_id, .increment = reply.value };
        side.stream_owed.len += 1;
    }
    return side;
}

/// One stream's window and credit on `side`. A stream whose record is gone keeps `last`, its window
/// before the action.
fn stream_of(connection: *h2.Connection, index: u32, ended: bool, last: ?i64, side: *Side) void {
    switch (connection.streams.lookup(world_module.id_of(index))) {
        .live => |record| {
            side.window[index] = record.send_window.available;
            side.released[index] = if (ended) 0 else record.receive.released;
        },
        // RFC 9113 §6.9.2: a stream opens with the peer's initial window.
        .idle => side.window[index] = connection.peer.initial_window_size,
        .reset_and_dropped, .forgotten => side.window[index] = last orelse 0,
    }
}

/// Whether colibri's meter of the body on stream `id` runs.
fn body_runs(connection: *const server.Connection, id: u64) bool {
    for (&connection.bodies.entries) |*body| {
        if (body.id == id) return body.started and body.meter.running();
    }
    return false;
}

/// Whether colibri's meter of the send on stream `id` runs, a window holding it.
fn send_runs(connection: *const server.Connection, id: u64) bool {
    for (&connection.sends.entries) |*blocked| {
        if (blocked.id == id) return blocked.meter.running();
    }
    return false;
}

/// The frames `octets` holds, in order, the first `preface_len` octets counting as the preface.
fn frames_of(octets: []const u8, preface_len: usize) Error!Frames {
    var frames: Frames = .{};
    if (preface_len > 0) try push(&frames, .{ .kind = .preface });
    var reader = h2.core.Reader.init(octets[preface_len..]);
    // Bounded: each pass reads a frame's header of nine octets at least.
    for (0..octets.len / h2.constants.frame_header_len + 1) |_| {
        const header = h2.frame.read_header(&reader) catch break;
        const payload = reader.take(header.length) catch unreachable;
        try push(&frames, frame_of(header, payload));
    }
    assert(reader.remaining_len() == 0);
    return frames;
}

fn push(frames: *Frames, frame: Frame) Error!void {
    if (frames.len == frames.items.len) return error.FramesFull;
    frames.items[frames.len] = frame;
    frames.len += 1;
}

fn frame_of(header: h2.frame.Header, payload: []const u8) Frame {
    const end = header.flags & flag_end_stream != 0;
    return switch (header.type) {
        type_data => .{ .kind = .data, .stream = header.stream_id, .len = header.length, .end = end },
        type_headers => .{ .kind = .headers, .stream = header.stream_id, .len = header.length, .end = end },
        type_settings => if (header.flags & flag_ack != 0)
            .{ .kind = .settings_ack }
        else
            .{ .kind = .settings, .len = header.length },
        type_window_update => .{
            .kind = .window_update,
            .stream = header.stream_id,
            .len = header.length,
            .value = increment_of(payload),
        },
        // Two honest colibri endpoints send no other frame to each other.
        else => unreachable,
    };
}

fn increment_of(payload: []const u8) u32 {
    var reader = h2.core.Reader.init(payload);
    return (reader.read_int(u32) catch unreachable) & increment_mask;
}
