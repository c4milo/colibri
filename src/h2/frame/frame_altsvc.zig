//! The ALTSVC frame of RFC 7838 §4, an extension of h2 (RFC 9113 §5.5) by which a server
//! advertises an alternative service: a 16-bit Origin-Len, the Origin it names, and an Alt-Svc
//! field value (RFC 7838 §3) in the rest of the payload. It defines no flags.
//!
//! `frame.parse` returns the frame as `Payload.unknown`, because RFC 9113 §6 does not define it,
//! and the connection reads it with `parse` here when it is a client's to read. `parse` answers
//! null for a payload whose Origin-Len runs past it: RFC 7838 §4 makes the frame "a non-critical
//! extension", so a payload that cannot be read carries nothing a client may use, and is dropped
//! as a frame of an unknown type is (RFC 9113 §5.5). `write_altsvc` writes the whole frame or
//! nothing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame_header = @import("frame_header.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Header = frame_header.Header;

/// The two fields of an ALTSVC payload (RFC 7838 §4), each a slice of it.
pub const AltSvc = struct {
    /// The ASCII serialization of the origin the alternative applies to (RFC 6454 §6.2), or
    /// empty for the origin of the frame's stream.
    origin: []const u8,
    /// An Alt-Svc field value (RFC 7838 §3).
    value: []const u8,
};

/// Reads the payload of an ALTSVC frame whose header the connection has read and sized, or null
/// when its Origin-Len runs past it.
pub fn parse(header: Header, payload: []const u8) ?AltSvc {
    assert(header.type == constants.frame_type_altsvc);
    assert(payload.len == header.length);
    var reader = Reader.init(payload);
    // RFC 7838 §4: the payload starts with the 16-bit Origin-Len.
    const origin_len = reader.read_int(u16) catch return null;
    // RFC 7838 §4: the Origin holds Origin-Len octets, and the field value is every octet after.
    const origin = reader.take(origin_len) catch return null;
    return .{ .origin = origin, .value = reader.take_rest() };
}

/// Writes one ALTSVC frame on `stream_id`, naming `origin` and carrying the Alt-Svc field value
/// `value` (RFC 7838 §4).
pub fn write_altsvc(writer: *Writer, stream_id: u32, origin: []const u8, value: []const u8) core.writer.Error!void {
    assert(stream_id <= constants.stream_id_max);
    assert(origin.len <= std.math.maxInt(u16));
    const length = constants.altsvc_origin_len_len + origin.len + value.len;
    assert(length <= constants.frame_length_max);
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = @intCast(length),
        .type = constants.frame_type_altsvc,
        // RFC 7838 §4: "The ALTSVC frame does not define any flags."
        .flags = 0,
        .stream_id = stream_id,
    });
    try cursor.write_int(u16, @intCast(origin.len));
    try cursor.write_bytes(origin);
    try cursor.write_bytes(value);
    writer.* = cursor;
}

const testing = std.testing;

/// Room for the test frames: a header and a short payload. Test-only.
const test_frame_len: usize = 64;

test "RFC 7838 §4: an ALTSVC frame carries its Origin-Len, its Origin and the field value" {
    var buffer: [test_frame_len]u8 = undefined;
    var writer = Writer.init(&buffer);
    try write_altsvc(&writer, 3, "", "h3=\":443\"");
    const written = writer.written();
    var reader = Reader.init(written);
    const header = try frame_header.read(&reader);
    try testing.expectEqual(constants.frame_type_altsvc, header.type);
    try testing.expectEqual(0, header.flags);
    try testing.expectEqual(3, header.stream_id);
    // Two octets of Origin-Len, none of Origin, then the value.
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, written[constants.frame_header_len..][0..2]);
    const read = parse(header, reader.take_rest()).?;
    try testing.expectEqualStrings("", read.origin);
    try testing.expectEqualStrings("h3=\":443\"", read.value);
}

test "RFC 7838 §4: an Origin is Origin-Len octets, and the value is the rest" {
    var buffer: [test_frame_len]u8 = undefined;
    var writer = Writer.init(&buffer);
    try write_altsvc(&writer, 0, "https://example.org", "clear");
    var reader = Reader.init(writer.written());
    const header = try frame_header.read(&reader);
    const read = parse(header, reader.take_rest()).?;
    try testing.expectEqualStrings("https://example.org", read.origin);
    try testing.expectEqualStrings("clear", read.value);
}

test "RFC 7838 §4: a payload whose Origin-Len runs past it, or too short for one, reads as nothing" {
    const past = [_]u8{ 0, 4, 'a', 'b' };
    const header: Header = .{ .length = past.len, .type = constants.frame_type_altsvc, .flags = 0, .stream_id = 1 };
    try testing.expectEqual(null, parse(header, &past));
    const short = [_]u8{0};
    const short_header: Header = .{ .length = short.len, .type = constants.frame_type_altsvc, .flags = 0, .stream_id = 1 };
    try testing.expectEqual(null, parse(short_header, &short));
    // Exactly Origin-Len octets, and no value.
    const exact = [_]u8{ 0, 2, 'a', 'b' };
    const read = parse(header, &exact).?;
    try testing.expectEqualStrings("ab", read.origin);
    try testing.expectEqualStrings("", read.value);
}
