//! Writing the frames of RFC 9114 §7. Part of design §8 step 12.
//!
//! The reader and the types are `frame.zig`; this is the other direction, split out because a
//! hand-written source file stays at or under 500 lines (CLAUDE.md).
//!
//! Two shapes. A frame whose payload colibri holds — SETTINGS, GOAWAY and the rest — is written
//! whole, with its Length computed from the fields before a single octet goes out. A frame whose
//! payload the caller streams — DATA, HEADERS, PUSH_PROMISE's field section — gets its header
//! written here and its payload written by the caller, because §7.1's Length is the only thing
//! this layer can add to octets it never holds.
//!
//! Every function writes all of its octets or none.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const frame = @import("frame.zig");

const Writer = core.Writer;
const Error = core.writer.Error;
const Settings = frame.Settings;
const varint = wire.varint;

/// Writes a frame header: the type and the payload's length (RFC 9114 §7.1). The caller writes
/// the payload, which is what DATA, HEADERS and PUSH_PROMISE need.
pub fn write_header(writer: *Writer, frame_type: u64, length: u64) Error!void {
    var cursor = writer.*;
    try varint.encode(&cursor, frame_type);
    try varint.encode(&cursor, length);
    writer.* = cursor;
}

/// RFC 9114 §7.2.5: the push ID comes before the field section, and both are inside the Length.
pub fn write_push_promise_header(writer: *Writer, push_id: u64, field_section_len: u64) Error!void {
    var cursor = writer.*;
    const length = @as(u64, varint.encoded_len_minimal(push_id)) +| field_section_len;
    try write_header(&cursor, constants.frame_push_promise, length);
    try varint.encode(&cursor, push_id);
    writer.* = cursor;
}

/// A frame whose payload is one variable-length integer (RFC 9114 §7.2.3, §7.2.6, §7.2.7).
pub fn write_single(writer: *Writer, frame_type: u64, value: u64) Error!void {
    assert(frame_type == constants.frame_cancel_push or
        frame_type == constants.frame_goaway or
        frame_type == constants.frame_max_push_id);
    var cursor = writer.*;
    try write_header(&cursor, frame_type, varint.encoded_len_minimal(value));
    try varint.encode(&cursor, value);
    writer.* = cursor;
}

/// Writes a SETTINGS frame (RFC 9114 §7.2.4). A setting that is null is left out, which is how a
/// peer is told to apply the default rather than a value.
pub fn write_settings(writer: *Writer, settings: Settings) Error!void {
    var cursor = writer.*;
    try write_header(&cursor, constants.frame_settings, settings_len(settings));
    try write_setting(&cursor, constants.setting_qpack_max_table_capacity, settings.qpack_max_table_capacity);
    try write_setting(&cursor, constants.setting_max_field_section_size, settings.max_field_section_size);
    try write_setting(&cursor, constants.setting_qpack_blocked_streams, settings.qpack_blocked_streams);
    if (settings.reserved) |reserved| try write_setting(&cursor, reserved.identifier(), reserved.value);
    writer.* = cursor;
}

/// The octets a SETTINGS payload will take, which §7.1's Length needs before any of it is written.
fn settings_len(settings: Settings) u64 {
    var total: u64 = 0;
    total +|= pair_len(constants.setting_qpack_max_table_capacity, settings.qpack_max_table_capacity);
    total +|= pair_len(constants.setting_max_field_section_size, settings.max_field_section_size);
    total +|= pair_len(constants.setting_qpack_blocked_streams, settings.qpack_blocked_streams);
    if (settings.reserved) |reserved| total +|= pair_len(reserved.identifier(), reserved.value);
    return total;
}

fn pair_len(identifier: u64, value: ?u64) u64 {
    const held = value orelse return 0;
    return varint.encoded_len_minimal(identifier) + @as(u64, varint.encoded_len_minimal(held));
}

fn write_setting(cursor: *Writer, identifier: u64, value: ?u64) Error!void {
    const held = value orelse return;
    try varint.encode(cursor, identifier);
    try varint.encode(cursor, held);
}

/// Writes a reserved frame of RFC 9114 §7.2.8, whose `N` the caller picks. It has no semantics:
/// an endpoint MUST NOT consider it to mean anything, which is exactly what makes it useful for
/// proving a peer ignores what it does not know, and for application-layer padding.
pub fn write_reserved(writer: *Writer, n: u64, payload: []const u8) Error!void {
    var cursor = writer.*;
    const frame_type = constants.reserved_base +| (constants.reserved_step *| n);
    assert(constants.is_reserved(frame_type));
    try write_header(&cursor, frame_type, payload.len);
    try cursor.write_bytes(payload);
    writer.* = cursor;
}

const testing = std.testing;
const Reader = core.Reader;

/// Room for what a test writes, larger than any of them. Test-only.
const test_room: usize = 256;
var test_octets: [test_room]u8 = undefined;

/// Writes with `write` and reads the header back, returning it with the payload. Test-only.
fn round_trip(written: []const u8) !struct { header: frame.Header, payload: []const u8 } {
    var reader = Reader.init(written);
    const header = try frame.read_header(&reader);
    const payload = try reader.take(@intCast(header.length));
    try testing.expectEqual(0, reader.remaining_len());
    return .{ .header = header, .payload = payload };
}

test "§7.2.6: a one-integer frame is its type, its length and its value" {
    var writer = Writer.init(&test_octets);
    try write_single(&writer, constants.frame_goaway, 4);
    try testing.expectEqualSlices(u8, &.{ 0x07, 0x01, 0x04 }, writer.written());
    // The Length counts the octets the value takes, not the value.
    var wide = Writer.init(&test_octets);
    try write_single(&wide, constants.frame_max_push_id, 0x100);
    try testing.expectEqualSlices(u8, &.{ 0x0d, 0x02, 0x41, 0x00 }, wide.written());
    const back = try round_trip(wide.written());
    try testing.expectEqual(0x100, (try frame.read_payload(back.header.frame_type, back.payload)).max_push_id);
}

test "§7.2.4: SETTINGS carries the settings that are present and no others" {
    var writer = Writer.init(&test_octets);
    try write_settings(&writer, .{ .max_field_section_size = 0x100, .qpack_blocked_streams = 0x10 });
    const back = try round_trip(writer.written());
    try testing.expectEqual(constants.frame_settings, back.header.frame_type);
    const found = (try frame.read_payload(back.header.frame_type, back.payload)).settings;
    try testing.expectEqual(0x100, found.max_field_section_size);
    try testing.expectEqual(0x10, found.qpack_blocked_streams);
    // A setting left null is not written at all, which is how a peer is told to use the default
    // rather than a value that happens to equal it.
    try testing.expectEqual(null, found.qpack_max_table_capacity);
    // An empty SETTINGS frame is a Length of zero and no payload, which §7.2.4 permits and
    // every connection sends before it has anything to say.
    var empty = Writer.init(&test_octets);
    try write_settings(&empty, .{});
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x00 }, empty.written());
    const none = (try frame.read_payload(constants.frame_settings, &.{})).settings;
    try testing.expectEqual(null, none.max_field_section_size);
}

test "§7.2.4.1: a reserved setting goes out, and a reader ignores it" {
    var writer = Writer.init(&test_octets);
    const reserved: frame.Reserved = .{ .n = 3, .value = 0x4000 };
    try write_settings(&writer, .{ .max_field_section_size = 0x100, .reserved = reserved });
    const back = try round_trip(writer.written());
    // Its identifier, 0x1f * 3 + 0x21, and its value are in the payload after the size.
    var payload = Reader.init(back.payload);
    _ = try payload.take(3);
    try testing.expectEqual(reserved.identifier(), (try wire.varint.decode(&payload)).value);
    try testing.expectEqual(0x4000, (try wire.varint.decode(&payload)).value);
    const found = (try frame.read_payload(back.header.frame_type, back.payload)).settings;
    try testing.expectEqual(0x100, found.max_field_section_size);
    try testing.expectEqual(null, found.reserved);
}

test "§7.1: the Length a writer computes is the payload a reader finds" {
    // Every combination of present and absent settings, so the computed Length and the octets
    // written can never disagree about which pairs went out.
    const values = [_]?u64{ null, 0, 0x3f, 0x40, 0x4000 };
    for (values) |capacity| {
        for (values) |size| {
            for (values) |blocked| {
                var writer = Writer.init(&test_octets);
                const settings: Settings = .{
                    .qpack_max_table_capacity = capacity,
                    .max_field_section_size = size,
                    .qpack_blocked_streams = blocked,
                };
                try write_settings(&writer, settings);
                const back = try round_trip(writer.written());
                const found = (try frame.read_payload(back.header.frame_type, back.payload)).settings;
                try testing.expectEqual(settings, found);
            }
        }
    }
}

test "§7.2.5: a PUSH_PROMISE header covers the push ID and the field section after it" {
    var writer = Writer.init(&test_octets);
    const field_section = [_]u8{ 0x00, 0x00, 0xd1 };
    try write_push_promise_header(&writer, 4, field_section.len);
    try writer.write_bytes(&field_section);
    const back = try round_trip(writer.written());
    const found = (try frame.read_payload(back.header.frame_type, back.payload)).push_promise;
    try testing.expectEqual(4, found.push_id);
    try testing.expectEqualSlices(u8, &field_section, found.field_section);
}

test "§7.2.8: a reserved frame is 0x1f * N + 0x21 and means nothing" {
    var writer = Writer.init(&test_octets);
    try write_reserved(&writer, 0, "pad");
    const expected = [_]u8{ 0x21, 0x03 } ++ "pad".*;
    try testing.expectEqualSlices(u8, &expected, writer.written());
    const back = try round_trip(writer.written());
    try testing.expect(constants.is_reserved(back.header.frame_type));
    // §9: an endpoint MUST ignore it, so the payload is not read however it is filled.
    try testing.expectEqual(0x21, (try frame.read_payload(back.header.frame_type, back.payload)).unknown);
    // A larger N is a larger type, and still reserved.
    var third = Writer.init(&test_octets);
    try write_reserved(&third, 3, "");
    const wide = try round_trip(third.written());
    try testing.expectEqual(0x21 + 0x1f * 3, wide.header.frame_type);
    try testing.expect(constants.is_reserved(wide.header.frame_type));
    // §7: a reserved frame may be sent on any stream where frames are allowed.
    for ([_]frame.StreamKind{ .control, .request, .push }) |kind| {
        try testing.expect(frame.permitted(wide.header.frame_type, kind));
    }
}

test "a frame that does not fit writes nothing" {
    // GOAWAY with a one-octet value takes three octets. Two are not enough, and a writer that
    // ran out must leave nothing half-written behind it.
    var room: [3]u8 = undefined;
    var tight = Writer.init(room[0..2]);
    try testing.expectError(error.NoSpaceLeft, write_single(&tight, constants.frame_goaway, 4));
    try testing.expectEqual(0, tight.written().len);
    // The same for a SETTINGS frame whose header fits and whose payload does not.
    var partial = Writer.init(room[0..3]);
    try testing.expectError(error.NoSpaceLeft, write_settings(&partial, .{ .max_field_section_size = 0x4000 }));
    try testing.expectEqual(0, partial.written().len);
}
