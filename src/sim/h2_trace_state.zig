//! The state of `spec/tla/h2_connection`'s model, computed from a colibri client and server after
//! a step of the h2 trace run (https://github.com/c4milo/colibri/issues/75). Each variable is one
//! the model names, in the model's units.
//!
//! A stream's state and how it closed come from each connection's stream table (RFC 9113 §5.1).
//! What each message has written and read comes from the calls each connection took and the
//! events it reported (`h2_trace_pair.zig`). The frames in flight are parsed out of each queue:
//! DATA, HEADERS, RST_STREAM and GOAWAY, which the model carries, and none of the others, which it
//! leaves to other models (§4.1). A HEADERS frame's kind is the one the run wrote it as.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const sim = @import("sim");
const h2_trace_pair = @import("h2_trace_pair.zig");
const h2_trace_plan = @import("h2_trace_plan.zig");

const limits = sim.constants.h2_trace;
const Pair = h2_trace_pair.Pair;
const Queue = h2_trace_pair.Queue;
pub const RequestPhase = h2_trace_pair.RequestPhase;
pub const ResponsePhase = h2_trace_pair.ResponsePhase;

/// The model's stream states (RFC 9113 §5.1, Figure 2, less the reserved ones push would use).
pub const StreamState = enum { idle, open, half_closed_local, half_closed_remote, closed };
/// How a closed stream closed, as the model names it.
pub const Closing = enum { none, end_stream, rst_sent, rst_received };
/// The frames the model carries: the client's preface, its 24 octets and its SETTINGS, is one, and
/// the server's, its SETTINGS, another (RFC 9113 §3.4).
pub const Kind = enum { head, interim, data, trailers, rst, goaway, preface, settings };

pub const Frame = struct {
    /// The model's stream index, 1 up, or 0 for GOAWAY.
    stream: u32 = 0,
    kind: Kind = .data,
    end: bool = false,
    /// A GOAWAY's last stream, as the model's index.
    last: u32 = 0,
};

pub const State = struct {
    client_state: [limits.streams_max]StreamState = @splat(.idle),
    client_closed: [limits.streams_max]Closing = @splat(.none),
    server_state: [limits.streams_max]StreamState = @splat(.idle),
    server_closed: [limits.streams_max]Closing = @splat(.none),
    request: [limits.streams_max]RequestPhase = @splat(.none),
    request_data: [limits.streams_max]u32 = @splat(0),
    response: [limits.streams_max]ResponsePhase = @splat(.none),
    response_interims: [limits.streams_max]u32 = @splat(0),
    response_data: [limits.streams_max]u32 = @splat(0),
    request_read: [limits.streams_max]RequestPhase = @splat(.none),
    response_read: [limits.streams_max]ResponsePhase = @splat(.none),
    to_server: [limits.frames_max]Frame = @splat(.{}),
    to_server_len: u32 = 0,
    to_client: [limits.frames_max]Frame = @splat(.{}),
    to_client_len: u32 = 0,
    goaway_sent: u32 = 0,
    goaway_count: u32 = 0,
    goaway_read: u32 = 0,
    malformed: bool = false,
    broken: bool = false,
    late_open: bool = false,
    /// Whether each endpoint wrote its preface, and read its peer's (RFC 9113 §3.4).
    client_preface: bool = false,
    server_preface: bool = false,
    client_read_preface: bool = false,
    server_read_preface: bool = false,
};

pub const Error = error{
    /// A queue held more of the model's frames than `frames_max`, which is a harness defect.
    FramesFull,
};

/// Frame types (RFC 9113 §6) and the END_STREAM flag (§6.1, §6.2).
const type_data: u8 = 0x0;
const type_headers: u8 = 0x1;
const type_rst_stream: u8 = 0x3;
const type_goaway: u8 = 0x7;
const flag_end_stream: u8 = 0x1;
/// The reserved bit of a stream identifier (RFC 9113 §4.1).
const stream_id_mask: u32 = 0x7fff_ffff;
/// Offsets into a frame header (RFC 9113 §4.1): a 24-bit length, a type, flags and the stream.
const length_len: usize = 3;
const type_offset: usize = 3;
const flags_offset: usize = 4;
const stream_offset: usize = 5;
const header_len: usize = h2.constants.frame_header_len;
/// Octets of a GOAWAY's Last-Stream-ID (RFC 9113 §6.8).
const last_stream_id_len: usize = 4;

/// The model's state after a step, for a seed whose plan names `plan.streams` streams.
pub fn compute(pair: *Pair, plan: *const h2_trace_plan.Plan) Error!State {
    var state: State = .{};
    const n: usize = plan.streams;
    for (0..n) |index| {
        const id = h2_trace_pair.id_of(@intCast(index + 1));
        state.client_state[index], state.client_closed[index] = stream_of(&pair.client, id);
        state.server_state[index], state.server_closed[index] = stream_of(&pair.server, id);
    }
    const seen = &pair.seen;
    @memcpy(state.request[0..n], seen.request[0..n]);
    @memcpy(state.request_data[0..n], seen.request_data[0..n]);
    @memcpy(state.response[0..n], seen.response[0..n]);
    @memcpy(state.response_interims[0..n], seen.response_interims[0..n]);
    @memcpy(state.response_data[0..n], seen.response_data[0..n]);
    @memcpy(state.request_read[0..n], seen.request_read[0..n]);
    @memcpy(state.response_read[0..n], seen.response_read[0..n]);
    state.to_server_len = try frames_of(&pair.to_server, .preface, &state.to_server);
    state.to_client_len = try frames_of(&pair.to_client, .settings, &state.to_client);
    const no_goaway: u32 = plan.streams + 1;
    state.goaway_sent = if (pair.server.streams.goaway_sent_last_id) |last| last_index(last) else no_goaway;
    state.goaway_read = if (pair.client.streams.goaway_received_last_id) |last| last_index(last) else no_goaway;
    state.goaway_count = seen.goaways_sent;
    state.malformed = seen.malformed;
    state.broken = pair.client.has_failed() or pair.server.has_failed();
    state.late_open = seen.late_open;
    state.client_preface = pair.client.preface_done();
    state.server_preface = pair.server.preface_done();
    // RFC 9113 §3.4: the first frame each endpoint reads is its peer's SETTINGS, which ends the
    // peer's preface.
    state.client_read_preface = pair.client.first_frame_read;
    state.server_read_preface = pair.server.first_frame_read;
    return state;
}

/// A stream's state and how it closed, from the connection's table.
fn stream_of(connection: *h2.Connection, id: u32) struct { StreamState, Closing } {
    return switch (connection.streams.lookup(id)) {
        .live => |record| .{ state_of(record.state), closing_of(record.closed) },
        .idle => .{ .idle, .none },
        // RFC 9113 §5.1: a stream colibri reset and whose record it dropped is closed.
        .reset_and_dropped => .{ .closed, .rst_sent },
        // Each run opens fewer streams than a table drops records for.
        .forgotten => unreachable,
    };
}

fn state_of(state: h2.stream.State) StreamState {
    return switch (state) {
        .idle => .idle,
        .open => .open,
        .half_closed_local => .half_closed_local,
        .half_closed_remote => .half_closed_remote,
        .closed => .closed,
        // decision 17: colibri pushes nothing, so no stream is reserved.
        .reserved_local, .reserved_remote => unreachable,
    };
}

fn closing_of(closed: ?h2.stream.Closed) Closing {
    const how = closed orelse return .none;
    return switch (how) {
        .end_stream => .end_stream,
        .rst_stream_sent => .rst_sent,
        .rst_stream_received => .rst_received,
    };
}

/// The model's index of the stream a GOAWAY names: 0 for none opened, else the stream's index.
fn last_index(last_stream_id: u32) u32 {
    if (last_stream_id == 0) return 0;
    return @intCast(h2_trace_pair.index_of(last_stream_id) + 1);
}

/// The model's frames a queue holds, in order, written into `frames`; returns how many. While any
/// of its writer's preface is still in it, the first is that preface, as `preface` names it.
fn frames_of(queue: *const Queue, preface: Kind, frames: *[limits.frames_max]Frame) Error!u32 {
    const octets = queue.held()[queue.preface_left..];
    // Bounded: a frame is a header of `header_len` octets at least.
    const frames_bound = octets.len / header_len + 1;
    // The HEADERS frames in flight are the last ones written, so count them first.
    var heads_in_flight: usize = 0;
    var counting: FrameIterator = .{ .octets = octets };
    for (0..frames_bound) |_| {
        const frame = counting.next() orelse break;
        if (frame[type_offset] == type_headers) heads_in_flight += 1;
    }
    assert(counting.offset == octets.len);
    var head_index = queue.heads_written - heads_in_flight;
    var len: u32 = 0;
    if (queue.preface_left > 0) {
        frames[0] = .{ .stream = 0, .kind = preface, .end = false, .last = 0 };
        len = 1;
    }
    var reading: FrameIterator = .{ .octets = octets };
    for (0..frames_bound) |_| {
        const frame = reading.next() orelse break;
        const kind: Kind = switch (frame[type_offset]) {
            type_data => .data,
            type_headers => head_kind(queue, &head_index),
            type_rst_stream => .rst,
            type_goaway => .goaway,
            // SETTINGS, PING, WINDOW_UPDATE and PRIORITY change no stream the model holds.
            else => continue,
        };
        if (len == frames.len) return error.FramesFull;
        frames[len] = model_frame(frame, kind);
        len += 1;
    }
    return len;
}

/// The kind the run wrote the next HEADERS frame in flight as.
fn head_kind(queue: *const Queue, head_index: *usize) Kind {
    defer head_index.* += 1;
    return switch (queue.heads[head_index.*]) {
        .head => .head,
        .interim => .interim,
        .trailers => .trailers,
    };
}

/// The whole frames of `octets` in order, each its header and its payload (RFC 9113 §4.1).
const FrameIterator = struct {
    octets: []const u8,
    offset: usize = 0,

    fn next(iterator: *FrameIterator) ?[]const u8 {
        if (iterator.offset + header_len > iterator.octets.len) return null;
        const frame_len = header_len + length_of(iterator.octets[iterator.offset..]);
        const frame = iterator.octets[iterator.offset..][0..frame_len];
        iterator.offset += frame_len;
        return frame;
    }
};

fn model_frame(frame: []const u8, kind: Kind) Frame {
    const id = std.mem.readInt(u32, frame[stream_offset..][0..@sizeOf(u32)], .big) & stream_id_mask;
    if (kind == .goaway) {
        const last = std.mem.readInt(u32, frame[header_len..][0..last_stream_id_len], .big) & stream_id_mask;
        return .{ .stream = 0, .kind = .goaway, .end = false, .last = last_index(last) };
    }
    const end = (kind == .data or kind == .head or kind == .interim or kind == .trailers) and
        frame[flags_offset] & flag_end_stream != 0;
    return .{ .stream = @intCast(h2_trace_pair.index_of(id) + 1), .kind = kind, .end = end, .last = 0 };
}

/// The length of the frame whose header starts `octets` (RFC 9113 §4.1).
fn length_of(octets: []const u8) usize {
    return std.mem.readInt(u24, octets[0..length_len], .big);
}
