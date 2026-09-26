//! The frame target of the QUIC input check (`quic_input_check.zig`). It draws a payload of frames
//! of every type RFC 9000 §19 defines, writes it with `quic.frame.write`, and reads a payload back
//! frame by frame, as a connection does. A frame that is read must keep three rules:
//! - a refused frame consumes nothing;
//! - an accepted frame keeps every rule the writer asserts, so writing it again cannot halt;
//! - an accepted frame is written again with the type it was read from, and reads back as itself.
//!
//! The last rule compares octets and not frames: the frame written again is read back and written
//! a second time, and the two writes must be the same octets.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");

const constants = sim.constants;
const Random = sim.Random;
const Reader = quic.core.Reader;
const Writer = quic.core.Writer;
const frame = quic.frame;
const Frame = frame.Frame;
const varint = quic.wire.varint;
const limits = quic.constants;

pub const Violation = error{
    /// A refused frame consumed octets.
    RefusalConsumed,
    /// An accepted frame breaks a rule the writer asserts.
    FrameNotWritable,
    /// An accepted frame was written again with another type, did not fit where it was read from,
    /// or read back as another frame.
    FrameChanged,
};

/// The fields of one ACK range after the first: a Gap and an ACK Range Length (RFC 9000 §19.3.1).
const ack_range_fields = 2;

/// Octets one ACK frame's ranges after the first take at most.
const ack_ranges_len_max = constants.quic_input_check_ack_ranges_max * ack_range_fields *
    quic.wire.constants.varint_len_max;

pub const Storage = struct {
    payload: [constants.quic_input_check_input_len_max]u8,
    /// The gap and length pairs of the ACK frame being drawn.
    ack_ranges: [ack_ranges_len_max]u8,
    rewritten: [constants.quic_input_check_input_len_max]u8,
    rewritten_again: [constants.quic_input_check_input_len_max]u8,
};

/// The bit length of the largest variable-length integer (RFC 9000 §16).
const varint_value_bits = std.math.log2_int(u64, quic.wire.constants.varint_value_max + 1);

/// How this check draws a value: variable-length integers, and a bound once in
/// `quic_input_check_one_in`.
const draw: sim.input_draw.Draw = .{
    .one_in = constants.quic_input_check_one_in,
    .near_bound = constants.quic_input_check_near_bound,
    .bits_max = varint_value_bits,
};

/// A variable-length integer's value, drawn by bit length first.
pub fn draw_varint(random: *Random) u64 {
    return draw.by_bits(random);
}

pub fn draw_bounded(random: *Random, min: u64, max: u64) u64 {
    return draw.bounded(random, min, max);
}

pub fn chosen(random: *Random) bool {
    return draw.chosen(random);
}

pub const draw_octets = sim.input_draw.octets;

/// Writes a payload of drawn frames and returns it. A STREAM frame with no Length runs to the end
/// of the payload (RFC 9000 §19.8), so only the last frame may be one.
pub fn draw_payload(storage: *Storage, random: *Random, material: []const u8) []const u8 {
    var writer = Writer.init(&storage.payload);
    const count = random.between(1, constants.quic_input_check_frames_max);
    for (0..count) |index| {
        const drawn = draw_frame(storage, random, material, index + 1 == count);
        frame.write(&writer, drawn) catch break;
    }
    return writer.written();
}

fn draw_frame(storage: *Storage, random: *Random, material: []const u8, last: bool) Frame {
    const tag: std.meta.Tag(Frame) = @enumFromInt(random.below(std.meta.fields(Frame).len));
    return switch (tag) {
        .padding => .{ .padding = .{ .len = random.between(1, constants.quic_input_check_octets_len_max) } },
        .ping => .ping,
        .ack => .{ .ack = draw_ack(storage, random) },
        .reset_stream => .{ .reset_stream = .{
            .stream_id = draw_varint(random),
            .error_code = draw_varint(random),
            .final_size = draw_varint(random),
        } },
        .stop_sending => .{ .stop_sending = .{ .stream_id = draw_varint(random), .error_code = draw_varint(random) } },
        .crypto => .{ .crypto = draw_crypto(random, material) },
        .new_token => .{ .new_token = .{ .token = draw_octets(random, material, 1, constants.quic_input_check_octets_len_max) } },
        .stream => .{ .stream = draw_stream(random, material, last) },
        .max_data => .{ .max_data = .{ .maximum = draw_varint(random) } },
        .max_stream_data => .{ .max_stream_data = .{ .stream_id = draw_varint(random), .maximum = draw_varint(random) } },
        .max_streams => .{ .max_streams = .{
            .directionality = draw_directionality(random),
            .maximum = draw_bounded(random, 0, limits.max_streams_max),
        } },
        .data_blocked => .{ .data_blocked = .{ .limit = draw_varint(random) } },
        .stream_data_blocked => .{ .stream_data_blocked = .{ .stream_id = draw_varint(random), .limit = draw_varint(random) } },
        .streams_blocked => .{ .streams_blocked = .{
            .directionality = draw_directionality(random),
            .limit = draw_bounded(random, 0, limits.max_streams_max),
        } },
        .new_connection_id => .{ .new_connection_id = draw_new_connection_id(random, material) },
        .retire_connection_id => .{ .retire_connection_id = .{ .sequence_number = draw_varint(random) } },
        .path_challenge => .{ .path_challenge = .{ .data = draw_path_data(random, material) } },
        .path_response => .{ .path_response = .{ .data = draw_path_data(random, material) } },
        .connection_close => .{ .connection_close = draw_close(random, material) },
        .handshake_done => .handshake_done,
    };
}

fn draw_directionality(random: *Random) frame.Directionality {
    return if (chosen(random)) .unidirectional else .bidirectional;
}

/// RFC 9000 §19.3.1: the largest of the next range is two below the smallest of the last, less
/// the gap.
const ack_gap_step: u64 = 2;

/// An ACK frame whose ranges stay at or above packet number 0 (RFC 9000 §19.3.1).
fn draw_ack(storage: *Storage, random: *Random) frame.Ack {
    const largest = draw_varint(random);
    const first_range = draw_bounded(random, 0, largest);
    var writer = Writer.init(&storage.ack_ranges);
    var previous_smallest = largest - first_range;
    var count: u64 = 0;
    for (0..random.between(0, constants.quic_input_check_ack_ranges_max)) |_| {
        if (previous_smallest < ack_gap_step) break;
        const gap = draw_bounded(random, 0, previous_smallest - ack_gap_step);
        const range_largest = previous_smallest - gap - ack_gap_step;
        const length = draw_bounded(random, 0, range_largest);
        varint.encode(&writer, gap) catch unreachable;
        varint.encode(&writer, length) catch unreachable;
        previous_smallest = range_largest - length;
        count += 1;
    }
    const ranges: frame.AckRanges = .{
        .largest_acknowledged = largest,
        .first_range = first_range,
        .octets = writer.written(),
        .count = count,
    };
    const ecn: ?frame.EcnCounts = if (chosen(random)) null else .{
        .ect_0 = draw_varint(random),
        .ect_1 = draw_varint(random),
        .ecn_ce = draw_varint(random),
    };
    return .{ .ranges = ranges, .delay = draw_varint(random), .ecn = ecn };
}

/// An offset whose data ends at or below 2^62-1 (RFC 9000 §19.8, §19.6), and 0 once in
/// `quic_input_check_one_in`.
fn draw_offset(random: *Random, data_len: usize) u64 {
    if (chosen(random)) return 0;
    return draw_bounded(random, 0, limits.stream_offset_max - data_len);
}

fn draw_crypto(random: *Random, material: []const u8) frame.Crypto {
    const data = draw_octets(random, material, 0, constants.quic_input_check_octets_len_max);
    return .{ .offset = draw_offset(random, data.len), .data = data };
}

fn draw_stream(random: *Random, material: []const u8, last: bool) frame.Stream {
    const data = draw_octets(random, material, 0, constants.quic_input_check_octets_len_max);
    return .{
        .stream_id = draw_varint(random),
        .offset = draw_offset(random, data.len),
        .data = data,
        .fin = chosen(random),
        .has_length = !last or chosen(random),
    };
}

/// A NEW_CONNECTION_ID frame that keeps RFC 9000 §19.15's two rules.
fn draw_new_connection_id(random: *Random, material: []const u8) frame.frame_control.NewConnectionId {
    const sequence_number = draw_varint(random);
    const token_start = random.below(material.len - limits.stateless_reset_token_len + 1);
    return .{
        .sequence_number = sequence_number,
        .retire_prior_to = draw_bounded(random, 0, sequence_number),
        .connection_id = draw_octets(random, material, limits.connection_id_len_min, limits.connection_id_len_max),
        .stateless_reset_token = material[token_start..][0..limits.stateless_reset_token_len],
    };
}

fn draw_path_data(random: *Random, material: []const u8) *const [limits.path_challenge_len]u8 {
    const start = random.below(material.len - limits.path_challenge_len + 1);
    return material[start..][0..limits.path_challenge_len];
}

/// A CONNECTION_CLOSE, which names a frame type when it speaks for the transport (§19.19).
fn draw_close(random: *Random, material: []const u8) frame.frame_control.ConnectionClose {
    const transport = chosen(random);
    return .{
        .layer = if (transport) .transport else .application,
        .error_code = draw_varint(random),
        .frame_type = if (transport) draw_varint(random) else null,
        .reason = draw_octets(random, material, 0, constants.quic_input_check_octets_len_max),
    };
}

/// Reads `payload` frame by frame and checks each frame. True when every octet was read as
/// frames, false when a frame was refused. `frames_read` counts the frames accepted.
pub fn read_payload(storage: *Storage, payload: []const u8, frames_read: *u64) Violation!bool {
    var reader = Reader.init(payload);
    // Bounded: every frame that is read consumes at least its type's octet.
    for (0..payload.len + 1) |_| {
        if (reader.remaining_len() == 0) return true;
        const at_frame = reader;
        const read = frame.read(&reader) catch {
            if (reader.offset != at_frame.offset) return error.RefusalConsumed;
            return false;
        };
        assert(reader.offset > at_frame.offset);
        frames_read.* += 1;
        try check_writable(read);
        try check_round_trip(storage, read, type_at(at_frame));
    }
    unreachable;
}

/// The rules the writer asserts, which the reader must have checked on the peer's behalf.
fn check_writable(read: Frame) Violation!void {
    const writable = switch (read) {
        .padding => |padding| padding.len > 0,
        .ack => |ack| ranges_descend(ack.ranges),
        .stream => |stream| stream.offset <= limits.stream_offset_max - stream.data.len,
        .crypto => |crypto| crypto.offset <= limits.stream_offset_max - crypto.data.len,
        .new_token => |new_token| new_token.token.len > 0,
        .max_streams => |max| max.maximum <= limits.max_streams_max,
        .streams_blocked => |blocked| blocked.limit <= limits.max_streams_max,
        .new_connection_id => |new| new.retire_prior_to <= new.sequence_number and
            new.connection_id.len >= limits.connection_id_len_min and
            new.connection_id.len <= limits.connection_id_len_max,
        .connection_close => |close| (close.layer == .transport) == (close.frame_type != null),
        else => true,
    };
    if (!writable) return error.FrameNotWritable;
}

/// Whether an ACK frame's ranges each run upward and lie at least one packet number below the
/// last (RFC 9000 §19.3.1), and number one more than the count the frame carries.
fn ranges_descend(ranges: frame.AckRanges) bool {
    var walk = ranges.iterator();
    var previous: ?frame.frame_ack.Range = null;
    var walked: u64 = 0;
    // Bounded by the count, which the octets the frame was read from bound.
    for (0..constants.quic_input_check_input_len_max + 1) |_| {
        const range = walk.next() orelse break;
        if (range.smallest > range.largest) return false;
        if (previous) |last| {
            if (range.largest + 1 >= last.smallest) return false;
        }
        previous = range;
        walked += 1;
    }
    return walked == ranges.count + 1;
}

/// Writes `read` again, with the type it was read from but for a STREAM frame at offset 0, whose
/// Offset RFC 9000 §19.8 lets go unwritten; reads it back; and writes that a second time.
fn check_round_trip(storage: *Storage, read: Frame, read_type: u64) Violation!void {
    const first = try write_into(&storage.rewritten, read);
    const offset_dropped = read == .stream and read.stream.offset == 0;
    const expected_type = if (offset_dropped) read_type & ~limits.stream_flag_off else read_type;
    if (type_at(Reader.init(first)) != expected_type) return error.FrameChanged;
    var reader = Reader.init(first);
    const again = frame.read(&reader) catch return error.FrameChanged;
    if (reader.remaining_len() != 0) return error.FrameChanged;
    const second = try write_into(&storage.rewritten_again, again);
    if (!std.mem.eql(u8, first, second)) return error.FrameChanged;
}

/// A frame is never longer written than it was read, so a buffer as long as the input holds it.
fn write_into(buffer: []u8, value: Frame) Violation![]const u8 {
    var writer = Writer.init(buffer);
    frame.write(&writer, value) catch return error.FrameChanged;
    return writer.written();
}

/// The type of the frame at the reader's cursor, which a frame read from there decoded already.
fn type_at(at_frame: Reader) u64 {
    var type_reader = at_frame;
    return (varint.decode(&type_reader) catch unreachable).value;
}
