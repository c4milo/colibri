//! The SETTINGS frame of RFC 9113 §6.5 as octets: the frame's shape, and the settings it carries
//! in the order they appear (§6.5.3). What each identifier means, and which values are legal, is
//! settings.zig's job; this file never reads a value.
//!
//! `parse_settings` checks, in order (invariant 7):
//!   1. the stream identifier is 0, or `error.StreamIdNotZero`, a connection error of
//!      PROTOCOL_ERROR (§6.5);
//!   2. an ACK carries no payload, or `error.AckNotEmpty`, a connection error of
//!      FRAME_SIZE_ERROR (§6.5);
//!   3. the length is a multiple of the setting length, or `error.LengthInvalid`, a connection
//!      error of FRAME_SIZE_ERROR (§6.5).
//! `Iterator` then yields one `Setting` per six octets (§6.5.1), bounded by
//! `settings_per_frame_max`. The writers write the whole frame or nothing and set only the ACK
//! flag (§4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame_header = @import("frame_header.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Header = frame_header.Header;

/// Every error `parse_settings` returns, one RFC 9113 §6.5 rule each.
pub const Error = error{
    /// SETTINGS on a stream other than 0 (RFC 9113 §6.5).
    StreamIdNotZero,
    /// A SETTINGS ACK with a payload (RFC 9113 §6.5).
    AckNotEmpty,
    /// A payload that is not whole settings (RFC 9113 §6.5).
    LengthInvalid,
};

/// One setting: a 16-bit identifier and a 32-bit value (RFC 9113 §6.5.1).
pub const Setting = struct {
    id: u16,
    value: u32,
};

/// A SETTINGS frame as octets (RFC 9113 §6.5): its ACK flag and the payload `iterator` walks.
pub const Settings = struct {
    /// The whole payload, checked to be a multiple of `setting_len` octets and at most
    /// `frame_size_max`.
    payload: []const u8,
    ack: bool,

    /// The settings in the order they appear (RFC 9113 §6.5.3).
    pub fn iterator(settings: Settings) Iterator {
        assert(settings.payload.len % constants.setting_len == 0);
        assert(settings.payload.len <= constants.frame_size_max);
        return .{ .reader = Reader.init(settings.payload) };
    }
};

/// Walks the settings of one payload in the order they appear (RFC 9113 §6.5.3).
pub const Iterator = struct {
    reader: Reader,
    yielded: u32 = 0,

    /// The next setting, or null after the last. Never more than `settings_per_frame_max`.
    pub fn next(self: *Iterator) ?Setting {
        if (self.reader.remaining_len() == 0) return null;
        assert(self.yielded < constants.settings_per_frame_max);
        // `iterator` asserted the payload is whole settings, so neither read can fall short.
        const id = self.reader.read_int(u16) catch unreachable;
        const value = self.reader.read_int(u32) catch unreachable;
        self.yielded += 1;
        return .{ .id = id, .value = value };
    }
};

/// Parses the payload of a SETTINGS frame whose header the connection has read and sized.
pub fn parse_settings(header: Header, payload: []const u8) Error!Settings {
    assert(header.type == constants.frame_type_settings);
    assert(payload.len == header.length and payload.len <= constants.frame_size_max);
    // RFC 9113 §6.5: a SETTINGS frame whose Stream Identifier field is anything other than 0x00
    // is a connection error of PROTOCOL_ERROR.
    if (header.stream_id != constants.connection_stream_id) return error.StreamIdNotZero;
    const ack = frame_header.has_flag(header, constants.flag_ack);
    // RFC 9113 §6.5: a SETTINGS frame with the ACK flag set and a length other than 0 is a
    // connection error of FRAME_SIZE_ERROR.
    if (ack and payload.len != 0) return error.AckNotEmpty;
    // RFC 9113 §6.5: a length other than a multiple of 6 octets is a connection error of
    // FRAME_SIZE_ERROR.
    if (payload.len % constants.setting_len != 0) return error.LengthInvalid;
    return .{ .payload = payload, .ack = ack };
}

/// Writes one SETTINGS frame carrying `settings` in order, all of it or nothing.
pub fn write_settings(writer: *Writer, settings: []const Setting) core.writer.Error!void {
    assert(settings.len <= constants.settings_per_frame_max);
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = @intCast(settings.len * constants.setting_len),
        .type = constants.frame_type_settings,
        .flags = 0,
        .stream_id = constants.connection_stream_id,
    });
    for (settings) |setting| {
        try cursor.write_int(u16, setting.id);
        try cursor.write_int(u32, setting.value);
    }
    writer.* = cursor;
}

/// Writes the empty SETTINGS frame with the ACK flag that acknowledges the peer's settings
/// (RFC 9113 §6.5.3).
pub fn write_settings_ack(writer: *Writer) core.writer.Error!void {
    try frame_header.write(writer, .{
        .length = 0,
        .type = constants.frame_type_settings,
        .flags = constants.flag_ack,
        .stream_id = constants.connection_stream_id,
    });
}

const testing = std.testing;

fn settings_header(length: u32, flags: u8, stream_id: u32) Header {
    return .{ .length = length, .type = constants.frame_type_settings, .flags = flags, .stream_id = stream_id };
}

test "SETTINGS yields each setting in order and then null (RFC 9113 §6.5.1, §6.5.3)" {
    const payload = "\x00\x01\x00\x00\x20\x00\x00\x03\x00\x00\x13\x88";
    const settings = try parse_settings(settings_header(12, 0, 0), payload);
    try testing.expect(!settings.ack);
    var iterator = settings.iterator();
    try testing.expectEqual(Setting{ .id = constants.setting_header_table_size, .value = 8192 }, iterator.next().?);
    try testing.expectEqual(Setting{ .id = constants.setting_max_concurrent_streams, .value = 5000 }, iterator.next().?);
    try testing.expectEqual(null, iterator.next());
    try testing.expectEqual(2, iterator.yielded);
}

test "an empty SETTINGS frame and an ACK are legal and yield nothing" {
    var empty = (try parse_settings(settings_header(0, 0, 0), "")).iterator();
    try testing.expectEqual(null, empty.next());
    const ack = try parse_settings(settings_header(0, constants.flag_ack, 0), "");
    try testing.expect(ack.ack);
}

test "SETTINGS on a stream other than 0 is StreamIdNotZero (RFC 9113 §6.5)" {
    try testing.expectError(error.StreamIdNotZero, parse_settings(settings_header(6, 0, 1), "\xaa\xaa\xbb\xbb\xbb\xbb"));
}

test "a SETTINGS ACK with a payload is AckNotEmpty (RFC 9113 §6.5)" {
    try testing.expectError(error.AckNotEmpty, parse_settings(settings_header(6, constants.flag_ack, 0), "\xaa\xaa\xbb\xbb\xbb\xbb"));
}

test "a SETTINGS length that is not a multiple of 6 is LengthInvalid (RFC 9113 §6.5)" {
    try testing.expectError(error.LengthInvalid, parse_settings(settings_header(8, 0, 0), "\xaa\xaa\xbb\xbb\xbb\xbb\xcc\xcc"));
    try testing.expectError(error.LengthInvalid, parse_settings(settings_header(1, 0, 0), "\x00"));
}

test "the stream is checked before the ACK, and the ACK before the length" {
    try testing.expectError(error.StreamIdNotZero, parse_settings(settings_header(1, constants.flag_ack, 1), "\x00"));
    try testing.expectError(error.AckNotEmpty, parse_settings(settings_header(1, constants.flag_ack, 0), "\x00"));
}

test "an unknown setting identifier is yielded, not refused (RFC 9113 §6.5.2 leaves ignoring it to the reader)" {
    var iterator = (try parse_settings(settings_header(6, 0, 0), "\xff\xff\x00\x00\x00\x01")).iterator();
    try testing.expectEqual(Setting{ .id = 0xffff, .value = 1 }, iterator.next().?);
}

/// Octets of the largest SETTINGS payload colibri accepts: every setting zero. Test-only.
const full_payload_len = constants.settings_per_frame_max * constants.setting_len;
var full_payload: [full_payload_len]u8 = @splat(0);

test "the iterator walks a payload of the largest frame colibri accepts, bounded by settings_per_frame_max" {
    var iterator = (try parse_settings(settings_header(full_payload_len, 0, 0), &full_payload)).iterator();
    var count: u32 = 0;
    while (iterator.next()) |_| count += 1;
    try testing.expectEqual(constants.settings_per_frame_max, count);
}

test "write_settings and write_settings_ack write what parse_settings reads back" {
    var buffer: [32]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write_settings(&writer, &.{
        .{ .id = constants.setting_header_table_size, .value = 8192 },
        .{ .id = constants.setting_max_concurrent_streams, .value = 5000 },
    });
    try testing.expectEqualSlices(u8, "\x00\x00\x0c\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x20\x00\x00\x03\x00\x00\x13\x88", writer.written());
    var reader = Reader.init(writer.written());
    var iterator = (try parse_settings(try frame_header.read(&reader), reader.take_rest())).iterator();
    try testing.expectEqual(8192, iterator.next().?.value);
    try testing.expectEqual(5000, iterator.next().?.value);
    try testing.expectEqual(null, iterator.next());
    writer = Writer.init(&buffer);
    try write_settings_ack(&writer);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x04\x01\x00\x00\x00\x00", writer.written());
}

test "a writer with too little room commits nothing" {
    var buffer: [12]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try testing.expectError(error.NoSpaceLeft, write_settings(&writer, &.{.{ .id = 1, .value = 1 }}));
    try testing.expectEqual(0, writer.offset);
    var short = Writer.init(buffer[0..8]);
    try testing.expectError(error.NoSpaceLeft, write_settings_ack(&short));
    try testing.expectEqual(0, short.offset);
    try testing.expectEqual(0, short.written().len);
}
