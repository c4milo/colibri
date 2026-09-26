//! The frames of the h2 input check (`h2_input_check.zig`). It draws a stream of frames of all
//! ten types RFC 9113 §6 defines, and one of a type it does not, written with `h2.frame`'s
//! writers. It reads a stream back frame by frame, as the connection does: the header, the
//! Length against SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2), then `h2.frame.parse`. A frame read
//! must keep three rules:
//! - a refused frame gets a verdict of PROTOCOL_ERROR or FRAME_SIZE_ERROR, and a stream error
//!   only on a stream other than 0 (§5.4.2);
//! - an accepted frame keeps every rule its writer asserts, so writing it again cannot halt;
//! - an accepted frame is written again with its type, its stream and its defined flags but
//!   PADDED, and a second write of what that reads back is the same octets.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const core = @import("core");
const h2 = @import("h2");

const constants = sim.constants;
const Random = sim.Random;
const Reader = core.Reader;
const Writer = core.Writer;
const frame = h2.frame;
const limits = h2.constants;

pub const Violation = error{
    /// A refusal was given a verdict RFC 9113 does not attach to it.
    VerdictWrong,
    /// An accepted frame breaks a rule its writer asserts.
    FrameNotWritable,
    /// An accepted frame was written again with another type, stream or flag, did not fit where
    /// it was read from, or read back as another frame.
    FrameChanged,
};

/// What reading a stream came to: every octet read as frames, a last frame cut short, or a
/// frame refused.
pub const Outcome = enum(u8) { taken, incomplete, refused };

pub const Storage = struct {
    stream: [constants.h2_input_check_input_len_max]u8,
    rewritten: [constants.h2_input_check_input_len_max]u8,
    rewritten_again: [constants.h2_input_check_input_len_max]u8,
    /// The settings of a SETTINGS frame being written again.
    settings: [settings_max]frame.Setting,
};

/// The most settings a stream as long as an input holds in one frame.
const settings_max = constants.h2_input_check_input_len_max / limits.setting_len;

const draw: sim.input_draw.Draw = .{
    .one_in = constants.h2_input_check_one_in,
    .near_bound = constants.h2_input_check_near_bound,
    .bits_max = @bitSizeOf(u32),
};

/// The settings drawn into one SETTINGS frame, at most.
const drawn_settings_max = 4;

/// The frames a stream is drawn from: the ten types of RFC 9113 §6, a SETTINGS acknowledgment,
/// and a type §6 does not define.
const Kind = enum {
    data,
    headers,
    priority,
    rst_stream,
    settings,
    settings_ack,
    push_promise,
    ping,
    goaway,
    window_update,
    continuation,
    unknown,
};

/// The first Type octet RFC 9113 §6 does not define.
const type_unknown_first: u8 = limits.frame_type_continuation + 1;

/// Writes a stream of drawn frames and returns it.
pub fn draw_stream(storage: *Storage, random: *Random, material: []const u8) []const u8 {
    var writer = Writer.init(&storage.stream);
    for (0..random.between(1, constants.h2_input_check_frames_max)) |_| {
        const kind: Kind = @enumFromInt(random.below(std.meta.fields(Kind).len));
        draw_frame(&writer, random, material, kind) catch break;
    }
    return writer.written();
}

fn draw_frame(writer: *Writer, random: *Random, material: []const u8, kind: Kind) !void {
    const stream_id: u32 = @intCast(draw.bounded(random, 1, limits.stream_id_max));
    const fragment = sim.input_draw.octets(random, material, 0, constants.h2_input_check_octets_len_max);
    const padding: u8 = @intCast(draw.bounded(random, 0, constants.h2_input_check_octets_len_max));
    switch (kind) {
        .data => try frame.write_data(writer, stream_id, fragment, draw.chosen(random), padding),
        .headers => try frame.write_headers(writer, stream_id, fragment, draw.chosen(random), draw.chosen(random), padding, draw_optional_priority(random)),
        .priority => try frame.write_priority(writer, stream_id, draw_priority(random)),
        .rst_stream => try frame.write_rst_stream(writer, stream_id, @intCast(draw.by_bits(random))),
        .settings => try draw_settings(writer, random),
        .settings_ack => try frame.write_settings_ack(writer),
        .push_promise => {
            // RFC 9113 §5.1.1: a server, which alone promises, initiates even-numbered streams.
            const promised: u32 = @intCast(draw.bounded(random, 1, limits.stream_id_max / limits.stream_id_step) * limits.stream_id_step);
            try frame.write_push_promise(writer, stream_id, promised, fragment, draw.chosen(random), padding);
        },
        .ping => try frame.write_ping(writer, sim.input_draw.octets(random, material, limits.ping_len, limits.ping_len)[0..limits.ping_len].*, draw.chosen(random)),
        .goaway => try frame.write_goaway(writer, @intCast(draw.bounded(random, 0, limits.stream_id_max)), @intCast(draw.by_bits(random)), fragment),
        .window_update => try frame.write_window_update(writer, @intCast(draw.bounded(random, 0, limits.stream_id_max)), @intCast(draw.bounded(random, 1, limits.window_max))),
        .continuation => try frame.write_continuation(writer, stream_id, fragment, draw.chosen(random)),
        .unknown => try write_unknown(writer, random, fragment),
    }
}

fn draw_priority(random: *Random) frame.Priority {
    return .{
        .exclusive = draw.chosen(random),
        .dependency = @intCast(draw.bounded(random, 0, limits.stream_id_max)),
        .weight = @truncate(random.next()),
    };
}

fn draw_optional_priority(random: *Random) ?frame.Priority {
    return if (draw.chosen(random)) null else draw_priority(random);
}

fn draw_settings(writer: *Writer, random: *Random) !void {
    var settings: [drawn_settings_max]frame.Setting = undefined;
    const count = random.between(0, drawn_settings_max);
    for (settings[0..count]) |*setting| {
        setting.* = .{ .id = @truncate(draw.by_bits(random)), .value = @intCast(draw.by_bits(random)) };
    }
    try frame.write_settings(writer, settings[0..count]);
}

/// A frame of a type RFC 9113 does not define, which a receiver ignores and discards (§4.1, §5.5).
fn write_unknown(writer: *Writer, random: *Random, payload: []const u8) !void {
    var copy = writer.*;
    try frame.write_header(&copy, .{
        .length = @intCast(payload.len),
        .type = @intCast(random.between(type_unknown_first, std.math.maxInt(u8))),
        .flags = @truncate(random.next()),
        .stream_id = @intCast(draw.bounded(random, 0, limits.stream_id_max)),
    });
    try copy.write_bytes(payload);
    writer.* = copy;
}

/// Reads `stream` frame by frame and checks each frame. `frames_read` counts the frames accepted.
pub fn read_stream(storage: *Storage, stream: []const u8, frames_read: *u64) Violation!Outcome {
    var reader = Reader.init(stream);
    // Bounded: every frame read consumes its nine-octet header.
    for (0..stream.len + 1) |_| {
        if (reader.remaining_len() == 0) return .taken;
        const header = frame.read_header(&reader) catch return .incomplete;
        // RFC 9113 §4.2: a frame longer than SETTINGS_MAX_FRAME_SIZE is a FRAME_SIZE_ERROR.
        if (header.length > limits.frame_size_max) return .refused;
        const payload = reader.take(header.length) catch return .incomplete;
        const parsed = frame.parse(header, payload) catch |failure| {
            try check_verdict(failure, header);
            return .refused;
        };
        frames_read.* += 1;
        try check_writable(header, parsed);
        try check_round_trip(storage, header, parsed);
    }
    unreachable;
}

/// RFC 9113 §5.4.1 and §5.4.2: a refusal ends the connection or a stream, and a stream error
/// names a stream other than 0. Every refusal of the frame layer carries PROTOCOL_ERROR or
/// FRAME_SIZE_ERROR.
fn check_verdict(failure: frame.ParseError, header: frame.Header) Violation!void {
    const verdict = frame.verdict(failure, @enumFromInt(header.type), header.stream_id);
    const code_known = verdict.code == limits.error_protocol_error or verdict.code == limits.error_frame_size_error;
    if (!code_known) return error.VerdictWrong;
    if (verdict.kind == .stream and header.stream_id == limits.connection_stream_id) return error.VerdictWrong;
}

/// The rules the writers assert, which the parser must have checked on the peer's behalf.
fn check_writable(header: frame.Header, parsed: frame.Payload) Violation!void {
    const on_stream = header.stream_id != limits.connection_stream_id;
    const writable = switch (parsed) {
        .data => |data| on_stream and padded_fits(header, data.data.len, data.padding_len),
        .headers => |headers| on_stream and padded_fits(header, headers.fragment.len + priority_len(headers.priority), headers.padding_len),
        .priority, .rst_stream, .continuation => on_stream,
        // RFC 9113 §6.5: a SETTINGS frame is on stream 0, its payload is whole settings, and an
        // acknowledgment carries none.
        .settings => |settings| !on_stream and header.length % limits.setting_len == 0 and
            (!settings.ack or header.length == 0),
        // RFC 9113 §5.1.1, §6.6: a promised stream is even and not 0.
        .push_promise => |promise| on_stream and promise.promised_stream_id != limits.connection_stream_id and
            promise.promised_stream_id % limits.stream_id_step == 0,
        .ping, .goaway => !on_stream,
        // RFC 9113 §6.9: an increment is 1 to 2^31-1.
        .window_update => |update| update.increment >= 1 and update.increment <= limits.window_max,
        .unknown => |unknown| unknown.payload.len == header.length,
    };
    if (!writable) return error.FrameNotWritable;
}

/// Whether the fields, the Pad Length octet and the padding of a frame make up its payload
/// (RFC 9113 §6.1, §6.2).
fn padded_fits(header: frame.Header, fields_len: usize, padding_len: u8) bool {
    if (!frame.has_flag(header, limits.flag_padded)) return padding_len == 0 and fields_len == header.length;
    return fields_len + limits.pad_length_len + padding_len == header.length;
}

fn priority_len(priority: ?frame.Priority) usize {
    return if (priority == null) 0 else limits.priority_fields_len;
}

/// The flags RFC 9113 §6 defines for a type, less PADDED: a frame whose padding is empty is
/// written again without it.
fn kept_flags(frame_type: u8) u8 {
    return switch (frame_type) {
        limits.frame_type_data => limits.flag_end_stream,
        limits.frame_type_headers => limits.flag_end_stream | limits.flag_end_headers | limits.flag_priority,
        limits.frame_type_settings, limits.frame_type_ping => limits.flag_ack,
        limits.frame_type_push_promise, limits.frame_type_continuation => limits.flag_end_headers,
        else => 0,
    };
}

/// Writes an accepted frame again, checks its header against the one read, reads it back, and
/// writes that a second time. colibri writes no frame of an unknown type, so those are skipped.
fn check_round_trip(storage: *Storage, header: frame.Header, parsed: frame.Payload) Violation!void {
    if (parsed == .unknown) return;
    const first = try write_into(storage, &storage.rewritten, header.stream_id, parsed);
    var reader = Reader.init(first);
    const first_header = frame.read_header(&reader) catch return error.FrameChanged;
    const kept = kept_flags(header.type);
    const same_header = first_header.type == header.type and first_header.stream_id == header.stream_id and
        first_header.flags & kept == header.flags & kept;
    if (!same_header) return error.FrameChanged;
    const payload = reader.take(first_header.length) catch return error.FrameChanged;
    if (reader.remaining_len() != 0) return error.FrameChanged;
    const again = frame.parse(first_header, payload) catch return error.FrameChanged;
    const second = try write_into(storage, &storage.rewritten_again, first_header.stream_id, again);
    if (!std.mem.eql(u8, first, second)) return error.FrameChanged;
}

/// Writes `parsed` with its type's writer. A frame is never longer written than read, so a
/// buffer as long as the input holds it.
fn write_into(storage: *Storage, buffer: []u8, stream_id: u32, parsed: frame.Payload) Violation![]const u8 {
    var writer = Writer.init(buffer);
    write_payload(storage, &writer, stream_id, parsed) catch return error.FrameChanged;
    return writer.written();
}

fn write_payload(storage: *Storage, writer: *Writer, stream_id: u32, parsed: frame.Payload) !void {
    switch (parsed) {
        .data => |data| try frame.write_data(writer, stream_id, data.data, data.end_stream, data.padding_len),
        .headers => |headers| try frame.write_headers(writer, stream_id, headers.fragment, headers.end_stream, headers.end_headers, headers.padding_len, headers.priority),
        .priority => |priority| try frame.write_priority(writer, stream_id, priority),
        .rst_stream => |reset| try frame.write_rst_stream(writer, stream_id, reset.error_code),
        .settings => |settings| try write_settings(storage, writer, settings),
        .push_promise => |promise| try frame.write_push_promise(writer, stream_id, promise.promised_stream_id, promise.fragment, promise.end_headers, promise.padding_len),
        .ping => |ping| try frame.write_ping(writer, ping.opaque_data, ping.ack),
        .goaway => |goaway| try frame.write_goaway(writer, goaway.last_stream_id, goaway.error_code, goaway.debug_data),
        .window_update => |update| try frame.write_window_update(writer, stream_id, update.increment),
        .continuation => |continuation| try frame.write_continuation(writer, stream_id, continuation.fragment, continuation.end_headers),
        .unknown => unreachable,
    }
}

fn write_settings(storage: *Storage, writer: *Writer, settings: frame.Settings) !void {
    if (settings.ack) return frame.write_settings_ack(writer);
    var walk = settings.iterator();
    var count: usize = 0;
    // Bounded by the payload, which the input's length bounds.
    for (&storage.settings) |*setting| {
        setting.* = walk.next() orelse break;
        count += 1;
    }
    assert(walk.next() == null);
    try frame.write_settings(writer, storage.settings[0..count]);
}
