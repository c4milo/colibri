//! The five fixed-shape control frames of RFC 9113: PRIORITY (§6.3), RST_STREAM (§6.4), PING
//! (§6.7), GOAWAY (§6.8) and WINDOW_UPDATE (§6.9). None carries padding or a field block.
//!
//! Every parser checks, in order (invariant 7):
//!   1. the stream identifier the section requires: not 0 for PRIORITY and RST_STREAM
//!      (`error.StreamIdZero`), exactly 0 for PING and GOAWAY (`error.StreamIdNotZero`), either
//!      for WINDOW_UPDATE; each a connection error of PROTOCOL_ERROR;
//!   2. the payload length the section fixes, or `error.LengthInvalid`: a FRAME_SIZE_ERROR that
//!      §6.3 makes a stream error for PRIORITY and every other section a connection error;
//!   3. the fields, read through the bounded reader (invariant 3), with the reserved bit of a
//!      31-bit field masked off (§4.1); a WINDOW_UPDATE increment of 0 is
//!      `error.WindowIncrementZero` (§6.9).
//!
//! colibri never sends PRIORITY (decision 18) and never sends a PING or WINDOW_UPDATE it has not
//! decided to; `write_priority` exists so the corpus of design §8 step 4 round-trips. Every writer
//! writes the whole frame or nothing and sets only the flags its section defines (§4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame_header = @import("frame_header.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Header = frame_header.Header;

/// Every error the five parsers return, one RFC 9113 rule each.
pub const Error = error{
    /// PRIORITY or RST_STREAM on stream 0 (RFC 9113 §6.3, §6.4).
    StreamIdZero,
    /// PING or GOAWAY on a stream other than 0 (RFC 9113 §6.7, §6.8).
    StreamIdNotZero,
    /// A payload not of the length the frame type fixes (RFC 9113 §6.3, §6.4, §6.7, §6.9), or
    /// shorter than GOAWAY's mandatory fields (§4.2).
    LengthInvalid,
    /// A WINDOW_UPDATE increment of 0 (RFC 9113 §6.9).
    WindowIncrementZero,
};

/// The Exclusive bit, Stream Dependency and Weight of a PRIORITY frame (RFC 9113 §6.3), and of a
/// HEADERS frame under the PRIORITY flag (§6.2). `weight` is the octet as sent.
pub const Priority = struct {
    exclusive: bool,
    dependency: u32,
    weight: u8,
};

/// The Error Code of a RST_STREAM frame (RFC 9113 §6.4), one of the codes of §7 or any other.
pub const RstStream = struct { error_code: u32 };

/// The Opaque Data and the ACK flag of a PING frame (RFC 9113 §6.7).
pub const Ping = struct {
    /// The Opaque Data field (RFC 9113 §6.7), returned unchanged in the PING that answers.
    opaque_data: [constants.ping_len]u8,
    ack: bool,
};

/// The three fields of a GOAWAY frame (RFC 9113 §6.8), the Last-Stream-ID with its reserved bit
/// masked off.
pub const Goaway = struct {
    last_stream_id: u32,
    error_code: u32,
    /// The Additional Debug Data field (RFC 9113 §6.8), which carries no semantic value.
    debug_data: []const u8,
};

/// The Window Size Increment of a WINDOW_UPDATE frame (RFC 9113 §6.9): 1 to `window_max`.
pub const WindowUpdate = struct { increment: u32 };

/// Reads the five priority octets: one Exclusive bit, a 31-bit dependency and a weight (§6.2, §6.3).
pub fn read_priority(reader: *Reader) core.reader.Error!Priority {
    var cursor = reader.*;
    const dependency_field = try cursor.read_int(u32);
    const weight = try cursor.read_byte();
    reader.* = cursor;
    return .{
        .exclusive = dependency_field & constants.exclusive_bit_mask != 0,
        .dependency = dependency_field & ~constants.exclusive_bit_mask,
        .weight = weight,
    };
}

/// Writes the five priority octets, all or none.
pub fn write_priority_fields(writer: *Writer, priority: Priority) core.writer.Error!void {
    assert(priority.dependency <= constants.stream_id_max);
    var cursor = writer.*;
    const exclusive_bit: u32 = if (priority.exclusive) constants.exclusive_bit_mask else 0;
    try cursor.write_int(u32, exclusive_bit | priority.dependency);
    try cursor.write_byte(priority.weight);
    writer.* = cursor;
}

/// Parses the payload of a PRIORITY frame whose header the connection has read and sized.
pub fn parse_priority(header: Header, payload: []const u8) Error!Priority {
    assert(header.type == constants.frame_type_priority);
    assert(payload.len == header.length);
    // RFC 9113 §6.3: a PRIORITY frame with a stream identifier of 0x00 is a connection error of
    // PROTOCOL_ERROR.
    if (header.stream_id == constants.connection_stream_id) return error.StreamIdZero;
    // RFC 9113 §6.3: a length other than 5 octets is a stream error of FRAME_SIZE_ERROR.
    if (payload.len != constants.priority_fields_len) return error.LengthInvalid;
    var reader = Reader.init(payload);
    const priority = read_priority(&reader) catch unreachable;
    assert(reader.remaining_len() == 0);
    return priority;
}

/// Parses the payload of a RST_STREAM frame whose header the connection has read and sized.
pub fn parse_rst_stream(header: Header, payload: []const u8) Error!RstStream {
    assert(header.type == constants.frame_type_rst_stream);
    assert(payload.len == header.length);
    // RFC 9113 §6.4: a RST_STREAM frame with a stream identifier of 0x00 is a connection error of
    // PROTOCOL_ERROR.
    if (header.stream_id == constants.connection_stream_id) return error.StreamIdZero;
    // RFC 9113 §6.4: a length other than 4 octets is a connection error of FRAME_SIZE_ERROR.
    if (payload.len != constants.rst_stream_len) return error.LengthInvalid;
    var reader = Reader.init(payload);
    const error_code = reader.read_int(u32) catch unreachable;
    assert(reader.remaining_len() == 0);
    return .{ .error_code = error_code };
}

/// Parses the payload of a PING frame whose header the connection has read and sized.
pub fn parse_ping(header: Header, payload: []const u8) Error!Ping {
    assert(header.type == constants.frame_type_ping);
    assert(payload.len == header.length);
    // RFC 9113 §6.7: a PING frame with a Stream Identifier other than 0x00 is a connection error
    // of PROTOCOL_ERROR.
    if (header.stream_id != constants.connection_stream_id) return error.StreamIdNotZero;
    // RFC 9113 §6.7: a length other than 8 is a connection error of FRAME_SIZE_ERROR.
    if (payload.len != constants.ping_len) return error.LengthInvalid;
    var reader = Reader.init(payload);
    var opaque_data: [constants.ping_len]u8 = @splat(0);
    for (&opaque_data) |*octet| octet.* = reader.read_byte() catch unreachable;
    assert(reader.remaining_len() == 0);
    return .{ .opaque_data = opaque_data, .ack = frame_header.has_flag(header, constants.flag_ack) };
}

/// Parses the payload of a GOAWAY frame whose header the connection has read and sized. The
/// Additional Debug Data is every octet after the Error Code, and may be empty.
pub fn parse_goaway(header: Header, payload: []const u8) Error!Goaway {
    assert(header.type == constants.frame_type_goaway);
    assert(payload.len == header.length);
    // RFC 9113 §6.8: a GOAWAY frame with a stream identifier other than 0x00 is a connection
    // error of PROTOCOL_ERROR.
    if (header.stream_id != constants.connection_stream_id) return error.StreamIdNotZero;
    // RFC 9113 §4.2: a frame too small to contain its mandatory data, here the Last-Stream-ID and
    // the Error Code of §6.8, is a FRAME_SIZE_ERROR; on stream 0 a connection error.
    if (payload.len < constants.goaway_len_min) return error.LengthInvalid;
    var reader = Reader.init(payload);
    // RFC 9113 §6.8: a reserved bit precedes the 31-bit Last-Stream-ID; §4.1: ignored on receipt.
    const last_stream_id = (reader.read_int(u32) catch unreachable) & ~constants.reserved_bit_mask;
    const error_code = reader.read_int(u32) catch unreachable;
    return .{ .last_stream_id = last_stream_id, .error_code = error_code, .debug_data = reader.take_rest() };
}

/// Parses the payload of a WINDOW_UPDATE frame whose header the connection has read and sized.
/// The frame is legal on any stream, 0 included (RFC 9113 §6.9).
pub fn parse_window_update(header: Header, payload: []const u8) Error!WindowUpdate {
    assert(header.type == constants.frame_type_window_update);
    assert(payload.len == header.length);
    // RFC 9113 §6.9: a length other than 4 octets is a connection error of FRAME_SIZE_ERROR.
    if (payload.len != constants.window_update_len) return error.LengthInvalid;
    var reader = Reader.init(payload);
    // RFC 9113 §6.9: a reserved bit precedes the 31-bit increment; §4.1: ignored on receipt.
    const increment = (reader.read_int(u32) catch unreachable) & ~constants.reserved_bit_mask;
    assert(reader.remaining_len() == 0);
    // RFC 9113 §6.9: an increment of 0 is a stream error of PROTOCOL_ERROR, and on the connection
    // flow-control window a connection error.
    if (increment == 0) return error.WindowIncrementZero;
    assert(increment <= constants.window_max);
    return .{ .increment = increment };
}

/// Writes one PRIORITY frame. colibri sends none (decision 18); the corpus round trip needs it.
pub fn write_priority(writer: *Writer, stream_id: u32, priority: Priority) core.writer.Error!void {
    assert(stream_id != constants.connection_stream_id and stream_id <= constants.stream_id_max);
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = constants.priority_fields_len,
        .type = constants.frame_type_priority,
        .flags = 0,
        .stream_id = stream_id,
    });
    try write_priority_fields(&cursor, priority);
    writer.* = cursor;
}

/// Writes one RST_STREAM frame for `stream_id` carrying `error_code` (RFC 9113 §6.4).
pub fn write_rst_stream(writer: *Writer, stream_id: u32, error_code: u32) core.writer.Error!void {
    assert(stream_id != constants.connection_stream_id and stream_id <= constants.stream_id_max);
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = constants.rst_stream_len,
        .type = constants.frame_type_rst_stream,
        .flags = 0,
        .stream_id = stream_id,
    });
    try cursor.write_int(u32, error_code);
    writer.* = cursor;
}

/// Writes one PING frame on stream 0, with the ACK flag when `ack` (RFC 9113 §6.7).
pub fn write_ping(writer: *Writer, opaque_data: [constants.ping_len]u8, ack: bool) core.writer.Error!void {
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = constants.ping_len,
        .type = constants.frame_type_ping,
        .flags = if (ack) constants.flag_ack else 0,
        .stream_id = constants.connection_stream_id,
    });
    try cursor.write_bytes(&opaque_data);
    assert(cursor.offset - writer.offset == constants.frame_header_len + constants.ping_len);
    writer.* = cursor;
}

/// Writes one GOAWAY frame on stream 0 with `debug_data` as its Additional Debug Data
/// (RFC 9113 §6.8).
pub fn write_goaway(writer: *Writer, last_stream_id: u32, error_code: u32, debug_data: []const u8) core.writer.Error!void {
    assert(last_stream_id <= constants.stream_id_max);
    assert(debug_data.len <= constants.frame_length_max - constants.goaway_len_min);
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = @intCast(constants.goaway_len_min + debug_data.len),
        .type = constants.frame_type_goaway,
        .flags = 0,
        .stream_id = constants.connection_stream_id,
    });
    // RFC 9113 §4.1: the reserved bit above the Last-Stream-ID stays unset when sending.
    try cursor.write_int(u32, last_stream_id & ~constants.reserved_bit_mask);
    try cursor.write_int(u32, error_code);
    try cursor.write_bytes(debug_data);
    writer.* = cursor;
}

/// Writes one WINDOW_UPDATE frame for `stream_id`, 0 for the connection (RFC 9113 §6.9).
pub fn write_window_update(writer: *Writer, stream_id: u32, increment: u32) core.writer.Error!void {
    assert(stream_id <= constants.stream_id_max);
    assert(increment >= 1 and increment <= constants.window_max);
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = constants.window_update_len,
        .type = constants.frame_type_window_update,
        .flags = 0,
        .stream_id = stream_id,
    });
    try cursor.write_int(u32, increment & ~constants.reserved_bit_mask);
    writer.* = cursor;
}

const testing = std.testing;

fn header_of(frame_type: u8, length: u32, flags: u8, stream_id: u32) Header {
    return .{ .length = length, .type = frame_type, .flags = flags, .stream_id = stream_id };
}

test "PRIORITY yields its three fields, with the Exclusive bit split from the dependency" {
    const exclusive = try parse_priority(header_of(2, 5, 0, 3), "\x80\x00\x00\x14\x09");
    try testing.expect(exclusive.exclusive);
    try testing.expectEqual(20, exclusive.dependency);
    try testing.expectEqual(9, exclusive.weight);
    const shared = try parse_priority(header_of(2, 5, 0, 9), "\x00\x00\x00\x0b\x07");
    try testing.expect(!shared.exclusive);
    try testing.expectEqual(11, shared.dependency);
}

test "PRIORITY on stream 0 is StreamIdZero and a length other than 5 is LengthInvalid (RFC 9113 §6.3)" {
    try testing.expectError(error.StreamIdZero, parse_priority(header_of(2, 5, 0, 0), "\x00\x00\x00\x01\x00"));
    try testing.expectError(error.LengthInvalid, parse_priority(header_of(2, 4, 0, 1), "\x00\x00\x00\x01"));
    try testing.expectError(error.LengthInvalid, parse_priority(header_of(2, 6, 0, 1), "\x00\x00\x00\x01\x00\x00"));
    try testing.expectError(error.StreamIdZero, parse_priority(header_of(2, 4, 0, 0), "\x00\x00\x00\x01"));
}

test "RST_STREAM yields its error code; stream 0 and a length other than 4 are refused (RFC 9113 §6.4)" {
    const reset = try parse_rst_stream(header_of(3, 4, 0, 5), "\x00\x00\x00\x08");
    try testing.expectEqual(constants.error_cancel, reset.error_code);
    try testing.expectError(error.StreamIdZero, parse_rst_stream(header_of(3, 4, 0, 0), "\x00\x00\x00\x08"));
    try testing.expectError(error.LengthInvalid, parse_rst_stream(header_of(3, 3, 0, 5), "\x00\x00\x08"));
    try testing.expectError(error.LengthInvalid, parse_rst_stream(header_of(3, 8, 0, 5), "\x00\x00\x00\x08\x00\x00\x00\x00"));
}

test "PING yields its opaque data and ACK; a stream and a length other than 8 are refused (RFC 9113 §6.7)" {
    const ping = try parse_ping(header_of(6, 8, constants.flag_ack, 0), "deadbeef");
    try testing.expectEqualStrings("deadbeef", &ping.opaque_data);
    try testing.expect(ping.ack);
    try testing.expect(!(try parse_ping(header_of(6, 8, 0, 0), "deadbeef")).ack);
    try testing.expectError(error.StreamIdNotZero, parse_ping(header_of(6, 8, 0, 1), "deadbeef"));
    try testing.expectError(error.LengthInvalid, parse_ping(header_of(6, 4, 0, 0), "dead"));
    try testing.expectError(error.LengthInvalid, parse_ping(header_of(6, 9, 0, 0), "deadbeef!"));
}

test "GOAWAY yields its identifiers and debug data; a stream and a short payload are refused (RFC 9113 §6.8)" {
    const goaway = try parse_goaway(header_of(7, 11, 0, 0), "\x80\x00\x00\x1e\x00\x00\x00\x09bye");
    try testing.expectEqual(30, goaway.last_stream_id);
    try testing.expectEqual(constants.error_compression_error, goaway.error_code);
    try testing.expectEqualStrings("bye", goaway.debug_data);
    const bare = try parse_goaway(header_of(7, 8, 0, 0), "\x00\x00\x00\x00\x00\x00\x00\x00");
    try testing.expectEqual(0, bare.debug_data.len);
    try testing.expectError(error.StreamIdNotZero, parse_goaway(header_of(7, 8, 0, 1), "\x00\x00\x00\x00\x00\x00\x00\x00"));
    try testing.expectError(error.LengthInvalid, parse_goaway(header_of(7, 7, 0, 0), "\x00\x00\x00\x00\x00\x00\x00"));
}

test "WINDOW_UPDATE yields its increment on any stream; a length other than 4 and an increment of 0 are refused (RFC 9113 §6.9)" {
    try testing.expectEqual(1000, (try parse_window_update(header_of(8, 4, 0, 50), "\x00\x00\x03\xe8")).increment);
    try testing.expectEqual(constants.window_max, (try parse_window_update(header_of(8, 4, 0, 0), "\xff\xff\xff\xff")).increment);
    try testing.expectError(error.LengthInvalid, parse_window_update(header_of(8, 2, 0, 1), "\x55\x66"));
    try testing.expectError(error.LengthInvalid, parse_window_update(header_of(8, 8, 0, 1), "\x00\x00\x00\x01\x00\x00\x00\x00"));
    try testing.expectError(error.WindowIncrementZero, parse_window_update(header_of(8, 4, 0, 1), "\x00\x00\x00\x00"));
    try testing.expectError(error.WindowIncrementZero, parse_window_update(header_of(8, 4, 0, 1), "\x80\x00\x00\x00"));
}

test "the stream identifier is checked before the length in RST_STREAM, PING and GOAWAY (invariant 7)" {
    // Each payload breaks both rules; the error names the rule checked first.
    try testing.expectError(error.StreamIdZero, parse_rst_stream(header_of(3, 3, 0, 0), "\x00\x00\x08"));
    try testing.expectError(error.StreamIdNotZero, parse_ping(header_of(6, 4, 0, 1), "dead"));
    try testing.expectError(error.StreamIdNotZero, parse_goaway(header_of(7, 7, 0, 1), "\x00\x00\x00\x00\x00\x00\x00"));
}

fn expect_round_trip(written: []const u8, expected: []const u8) !void {
    try testing.expectEqualSlices(u8, expected, written);
}

test "each writer produces the octets its section draws, and the parser reads them back" {
    var buffer: [64]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write_priority(&writer, 9, .{ .exclusive = true, .dependency = 11, .weight = 7 });
    try expect_round_trip(writer.written(), "\x00\x00\x05\x02\x00\x00\x00\x00\x09\x80\x00\x00\x0b\x07");
    writer = Writer.init(&buffer);
    try write_rst_stream(&writer, 5, constants.error_cancel);
    try expect_round_trip(writer.written(), "\x00\x00\x04\x03\x00\x00\x00\x00\x05\x00\x00\x00\x08");
    writer = Writer.init(&buffer);
    try write_ping(&writer, "deadbeef".*, true);
    try expect_round_trip(writer.written(), "\x00\x00\x08\x06\x01\x00\x00\x00\x00deadbeef");
    writer = Writer.init(&buffer);
    try write_goaway(&writer, 30, constants.error_compression_error, "bye");
    try expect_round_trip(writer.written(), "\x00\x00\x0b\x07\x00\x00\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00\x09bye");
    writer = Writer.init(&buffer);
    try write_window_update(&writer, 50, 1000);
    try expect_round_trip(writer.written(), "\x00\x00\x04\x08\x00\x00\x00\x00\x32\x00\x00\x03\xe8");
    var reader = Reader.init(writer.written());
    const header = try frame_header.read(&reader);
    try testing.expectEqual(1000, (try parse_window_update(header, reader.take_rest())).increment);
}

test "a writer with too little room commits nothing" {
    var buffer: [12]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try testing.expectError(error.NoSpaceLeft, write_rst_stream(&writer, 1, 0));
    try testing.expectError(error.NoSpaceLeft, write_ping(&writer, "01234567".*, false));
    try testing.expectError(error.NoSpaceLeft, write_goaway(&writer, 0, 0, ""));
    try testing.expectError(error.NoSpaceLeft, write_window_update(&writer, 0, 1));
    try testing.expectError(error.NoSpaceLeft, write_priority(&writer, 1, .{ .exclusive = false, .dependency = 0, .weight = 0 }));
    try testing.expectEqual(0, writer.offset);
    try testing.expectEqual(0, writer.written().len);
}
