//! The three frames that carry a field block fragment (RFC 9113 §4.3): HEADERS (§6.2),
//! PUSH_PROMISE (§6.6) and CONTINUATION (§6.10). Each parser returns the fragment as the octets
//! it is: decoding it is hpack's job, and joining fragments across CONTINUATION frames is the
//! connection's.
//!
//! Every parser checks, in order (invariant 7):
//!   1. the stream identifier is not 0, or `error.StreamIdZero`, a connection error of
//!      PROTOCOL_ERROR (§6.2, §6.6, §6.10);
//!   2. for HEADERS and PUSH_PROMISE, the padding rule of frame_padding.zig (§6.2, §6.6);
//!   3. the fields before the fragment are present, or `error.LengthInvalid`: the five priority
//!      octets the PRIORITY flag announces (§6.2) and the Promised Stream ID (§6.6). §4.2 makes
//!      a frame too small for its mandatory data a FRAME_SIZE_ERROR, and a connection error for
//!      any frame that carries a field block;
//!   4. for PUSH_PROMISE, the promised identifier is even and not 0, or
//!      `error.PromisedStreamIdInvalid`, a connection error of PROTOCOL_ERROR (§6.6 with §5.1.1);
//!   5. the rest of the payload is the fragment, which may be empty.
//!
//! colibri never sends PUSH_PROMISE (decision 17) and never sends priority fields (decision 18):
//! `write_push_promise` and the `priority` argument of `write_headers` exist so the corpus of
//! design §8 step 4 round-trips. Every writer writes the whole frame or nothing and sets only the
//! flags its section defines (§4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame_header = @import("frame_header.zig");
const frame_padding = @import("frame_padding.zig");
const frame_control = @import("frame_control.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Header = frame_header.Header;
const Priority = frame_control.Priority;

/// Every error the three parsers return: the padding rule's two, and one RFC 9113 rule each below.
pub const Error = frame_padding.Error || error{
    /// HEADERS, PUSH_PROMISE or CONTINUATION on stream 0 (RFC 9113 §6.2, §6.6, §6.10).
    StreamIdZero,
    /// A promised stream identifier of 0 or an odd one (RFC 9113 §6.6, §5.1.1).
    PromisedStreamIdInvalid,
};

/// The fields and flags of a HEADERS frame (RFC 9113 §6.2), with the Pad Length octet and the
/// padding removed.
pub const Headers = struct {
    /// The Field Block Fragment, as sent: hpack decodes it.
    fragment: []const u8,
    /// The priority fields, present under the PRIORITY flag (RFC 9113 §6.2).
    priority: ?Priority,
    padding_len: u8,
    end_stream: bool,
    end_headers: bool,
};

/// The fields and the END_HEADERS flag of a PUSH_PROMISE frame (RFC 9113 §6.6), with the Pad
/// Length octet and the padding removed and the reserved bit masked off the promised identifier.
pub const PushPromise = struct {
    promised_stream_id: u32,
    fragment: []const u8,
    padding_len: u8,
    end_headers: bool,
};

/// The Field Block Fragment and the END_HEADERS flag of a CONTINUATION frame (RFC 9113 §6.10).
pub const Continuation = struct {
    fragment: []const u8,
    end_headers: bool,
};

/// Parses the payload of a HEADERS frame whose header the connection has read and sized.
pub fn parse_headers(header: Header, payload: []const u8) Error!Headers {
    assert(header.type == constants.frame_type_headers);
    assert(payload.len == header.length);
    // RFC 9113 §6.2: a HEADERS frame whose Stream Identifier field is 0x00 is a connection error
    // of PROTOCOL_ERROR.
    if (header.stream_id == constants.connection_stream_id) return error.StreamIdZero;
    const unpadded = try frame_padding.strip(header, payload);
    var reader = Reader.init(unpadded.payload);
    var priority: ?Priority = null;
    if (frame_header.has_flag(header, constants.flag_priority)) {
        // RFC 9113 §4.2: a HEADERS frame too small for the Exclusive, Stream Dependency and
        // Weight fields its PRIORITY flag announces (§6.2) is a connection error of
        // FRAME_SIZE_ERROR.
        priority = frame_control.read_priority(&reader) catch return error.LengthInvalid;
    }
    return .{
        .fragment = reader.take_rest(),
        .priority = priority,
        .padding_len = unpadded.padding_len,
        .end_stream = frame_header.has_flag(header, constants.flag_end_stream),
        .end_headers = frame_header.has_flag(header, constants.flag_end_headers),
    };
}

/// Parses the payload of a PUSH_PROMISE frame whose header the connection has read and sized.
pub fn parse_push_promise(header: Header, payload: []const u8) Error!PushPromise {
    assert(header.type == constants.frame_type_push_promise);
    assert(payload.len == header.length);
    // RFC 9113 §6.6: a PUSH_PROMISE frame whose Stream Identifier field is 0x00 is a connection
    // error of PROTOCOL_ERROR.
    if (header.stream_id == constants.connection_stream_id) return error.StreamIdZero;
    const unpadded = try frame_padding.strip(header, payload);
    var reader = Reader.init(unpadded.payload);
    // RFC 9113 §4.2: a PUSH_PROMISE frame too small for its Promised Stream ID (§6.6) is a
    // connection error of FRAME_SIZE_ERROR.
    const promised_field = reader.read_int(u32) catch return error.LengthInvalid;
    // RFC 9113 §6.6: a reserved bit precedes the 31-bit Promised Stream ID; §4.1: ignored.
    const promised_stream_id = promised_field & ~constants.reserved_bit_mask;
    // RFC 9113 §6.6: a promise of an illegal stream identifier is a connection error of
    // PROTOCOL_ERROR; RFC 9113 §5.1.1: the identifier 0 cannot establish a new stream.
    if (promised_stream_id == constants.connection_stream_id) return error.PromisedStreamIdInvalid;
    // RFC 9113 §5.1.1: a server, the only endpoint that promises (§8.4), initiates even-numbered
    // streams, so an odd promise is the illegal identifier §6.6 refuses.
    if (promised_stream_id & 1 != 0) return error.PromisedStreamIdInvalid;
    return .{
        .promised_stream_id = promised_stream_id,
        .fragment = reader.take_rest(),
        .padding_len = unpadded.padding_len,
        .end_headers = frame_header.has_flag(header, constants.flag_end_headers),
    };
}

/// Parses the payload of a CONTINUATION frame whose header the connection has read and sized:
/// the whole payload is the fragment.
pub fn parse_continuation(header: Header, payload: []const u8) Error!Continuation {
    assert(header.type == constants.frame_type_continuation);
    assert(payload.len == header.length);
    // RFC 9113 §6.10: a CONTINUATION frame with a Stream Identifier field of 0x00 is a connection
    // error of PROTOCOL_ERROR.
    if (header.stream_id == constants.connection_stream_id) return error.StreamIdZero;
    return .{
        .fragment = payload,
        .end_headers = frame_header.has_flag(header, constants.flag_end_headers),
    };
}

/// Writes one HEADERS frame, all of it or nothing. `priority` is null from colibri (decision 18)
/// and set only by the corpus round trip; `padding_len` zero octets of padding follow the
/// fragment when it is not 0.
pub fn write_headers(
    writer: *Writer,
    stream_id: u32,
    fragment: []const u8,
    end_stream: bool,
    end_headers: bool,
    padding_len: u8,
    priority: ?Priority,
) core.writer.Error!void {
    assert(stream_id != constants.connection_stream_id and stream_id <= constants.stream_id_max);
    const priority_len: usize = if (priority == null) 0 else constants.priority_fields_len;
    const length = frame_padding.padded_len(fragment.len + priority_len, padding_len);
    var flags: u8 = frame_padding.flag(padding_len);
    if (end_stream) flags |= constants.flag_end_stream;
    if (end_headers) flags |= constants.flag_end_headers;
    if (priority != null) flags |= constants.flag_priority;
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = length,
        .type = constants.frame_type_headers,
        .flags = flags,
        .stream_id = stream_id,
    });
    try frame_padding.write_pad_length(&cursor, padding_len);
    if (priority) |fields| try frame_control.write_priority_fields(&cursor, fields);
    try cursor.write_bytes(fragment);
    try frame_padding.write_padding(&cursor, padding_len);
    assert(cursor.offset - writer.offset == constants.frame_header_len + length);
    writer.* = cursor;
}

/// Writes one PUSH_PROMISE frame. colibri never sends push (decision 17); the corpus round trip
/// needs the writer.
pub fn write_push_promise(
    writer: *Writer,
    stream_id: u32,
    promised_stream_id: u32,
    fragment: []const u8,
    end_headers: bool,
    padding_len: u8,
) core.writer.Error!void {
    assert(stream_id != constants.connection_stream_id and stream_id <= constants.stream_id_max);
    assert(promised_stream_id != constants.connection_stream_id and promised_stream_id & 1 == 0);
    assert(promised_stream_id <= constants.stream_id_max);
    const length = frame_padding.padded_len(fragment.len + constants.promised_stream_id_len, padding_len);
    const end_headers_flag: u8 = if (end_headers) constants.flag_end_headers else 0;
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = length,
        .type = constants.frame_type_push_promise,
        .flags = end_headers_flag | frame_padding.flag(padding_len),
        .stream_id = stream_id,
    });
    try frame_padding.write_pad_length(&cursor, padding_len);
    // RFC 9113 §4.1: the reserved bit above the Promised Stream ID stays unset when sending.
    try cursor.write_int(u32, promised_stream_id & ~constants.reserved_bit_mask);
    try cursor.write_bytes(fragment);
    try frame_padding.write_padding(&cursor, padding_len);
    assert(cursor.offset - writer.offset == constants.frame_header_len + length);
    writer.* = cursor;
}

/// Writes one CONTINUATION frame carrying `fragment`, all of it or nothing (RFC 9113 §6.10).
pub fn write_continuation(
    writer: *Writer,
    stream_id: u32,
    fragment: []const u8,
    end_headers: bool,
) core.writer.Error!void {
    assert(stream_id != constants.connection_stream_id and stream_id <= constants.stream_id_max);
    assert(fragment.len <= constants.frame_length_max);
    var cursor = writer.*;
    try frame_header.write(&cursor, .{
        .length = @intCast(fragment.len),
        .type = constants.frame_type_continuation,
        .flags = if (end_headers) constants.flag_end_headers else 0,
        .stream_id = stream_id,
    });
    try cursor.write_bytes(fragment);
    writer.* = cursor;
}

const testing = std.testing;

fn header_of(frame_type: u8, length: u32, flags: u8, stream_id: u32) Header {
    return .{ .length = length, .type = frame_type, .flags = flags, .stream_id = stream_id };
}

test "HEADERS yields its fragment and flags, with no priority when the flag is unset" {
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const headers = try parse_headers(header_of(1, 3, flags, 1), "abc");
    try testing.expectEqualStrings("abc", headers.fragment);
    try testing.expectEqual(null, headers.priority);
    try testing.expectEqual(0, headers.padding_len);
    try testing.expect(headers.end_stream and headers.end_headers);
}

test "HEADERS reads END_HEADERS and END_STREAM from their own bits (RFC 9113 §6.2)" {
    const only_end_headers = try parse_headers(header_of(1, 3, constants.flag_end_headers, 1), "abc");
    try testing.expect(only_end_headers.end_headers and !only_end_headers.end_stream);
    const only_end_stream = try parse_headers(header_of(1, 3, constants.flag_end_stream, 1), "abc");
    try testing.expect(only_end_stream.end_stream and !only_end_stream.end_headers);
}

test "HEADERS under PRIORITY and PADDED yields the priority fields, then the fragment (RFC 9113 §6.2)" {
    const flags = constants.flag_priority | constants.flag_padded;
    const headers = try parse_headers(header_of(1, 10, flags, 3), "\x02\x80\x00\x00\x14\x09ab\xaa\xaa");
    try testing.expectEqualStrings("ab", headers.fragment);
    try testing.expect(headers.priority.?.exclusive);
    try testing.expectEqual(20, headers.priority.?.dependency);
    try testing.expectEqual(9, headers.priority.?.weight);
    try testing.expectEqual(2, headers.padding_len);
    try testing.expect(!headers.end_stream and !headers.end_headers);
}

test "HEADERS on stream 0 is StreamIdZero (RFC 9113 §6.2)" {
    try testing.expectError(error.StreamIdZero, parse_headers(header_of(1, 1, 0, 0), "\xaa"));
}

test "HEADERS on stream 0 is refused before its padding is read (invariant 7)" {
    try testing.expectError(error.StreamIdZero, parse_headers(header_of(1, 4, constants.flag_padded, 0), "\x04\xaa\xaa\xaa"));
}

test "HEADERS with padding of the payload length is PaddingTooLong (RFC 9113 §6.2)" {
    try testing.expectError(error.PaddingTooLong, parse_headers(header_of(1, 4, constants.flag_padded, 1), "\x04\xaa\xaa\xaa"));
}

test "HEADERS under PRIORITY with fewer than five octets after the padding is LengthInvalid (RFC 9113 §4.2)" {
    try testing.expectError(error.LengthInvalid, parse_headers(header_of(1, 4, constants.flag_priority, 1), "\x00\x00\x00\x01"));
    const flags = constants.flag_priority | constants.flag_padded;
    try testing.expectError(error.LengthInvalid, parse_headers(header_of(1, 7, flags, 1), "\x02\x00\x00\x00\x01\x00\x00"));
    const exact = try parse_headers(header_of(1, 5, constants.flag_priority, 1), "\x00\x00\x00\x01\x00");
    try testing.expectEqual(0, exact.fragment.len);
}

test "PUSH_PROMISE yields the promised identifier, the fragment and END_HEADERS (RFC 9113 §6.6)" {
    const flags = constants.flag_end_headers | constants.flag_padded;
    const promise = try parse_push_promise(header_of(5, 9, flags, 10), "\x02\x80\x00\x00\x0cab\x00\x00");
    try testing.expectEqual(12, promise.promised_stream_id);
    try testing.expectEqualStrings("ab", promise.fragment);
    try testing.expectEqual(2, promise.padding_len);
    try testing.expect(promise.end_headers);
    const bare = try parse_push_promise(header_of(5, 4, 0, 1), "\x00\x00\x00\x02");
    try testing.expectEqual(2, bare.promised_stream_id);
    try testing.expectEqual(0, bare.fragment.len);
}

test "PUSH_PROMISE on stream 0 is StreamIdZero (RFC 9113 §6.6)" {
    try testing.expectError(error.StreamIdZero, parse_push_promise(header_of(5, 4, 0, 0), "\x77\x77\x77\x77"));
}

test "PUSH_PROMISE on stream 0 is refused before its padding is read (invariant 7)" {
    try testing.expectError(error.StreamIdZero, parse_push_promise(header_of(5, 4, constants.flag_padded, 0), "\x04\xaa\xaa\xaa"));
}

test "PUSH_PROMISE with padding of the payload length is PaddingTooLong (RFC 9113 §6.6)" {
    try testing.expectError(error.PaddingTooLong, parse_push_promise(header_of(5, 4, constants.flag_padded, 1), "\x04\xaa\xaa\xaa"));
}

test "PUSH_PROMISE shorter than its Promised Stream ID is LengthInvalid (RFC 9113 §4.2)" {
    try testing.expectError(error.LengthInvalid, parse_push_promise(header_of(5, 3, 0, 1), "\x00\x00\x02"));
    try testing.expectError(error.LengthInvalid, parse_push_promise(header_of(5, 0, 0, 1), ""));
    // Five octets, but two of them are padding: the fields left are too short for the identifier.
    try testing.expectError(error.LengthInvalid, parse_push_promise(header_of(5, 5, constants.flag_padded, 1), "\x02\x00\x00\x00\x02"));
}

test "PUSH_PROMISE promising stream 0 or an odd stream is PromisedStreamIdInvalid (RFC 9113 §6.6, §5.1.1)" {
    try testing.expectError(error.PromisedStreamIdInvalid, parse_push_promise(header_of(5, 4, 0, 1), "\x00\x00\x00\x00"));
    try testing.expectError(error.PromisedStreamIdInvalid, parse_push_promise(header_of(5, 4, 0, 1), "\x00\x00\x00\x01"));
    try testing.expectError(error.PromisedStreamIdInvalid, parse_push_promise(header_of(5, 4, 0, 1), "\x80\x00\x00\x00"));
}

test "CONTINUATION yields its fragment and END_HEADERS; stream 0 is StreamIdZero (RFC 9113 §6.10)" {
    const continuation = try parse_continuation(header_of(9, 2, constants.flag_end_headers, 50), "ab");
    try testing.expectEqualStrings("ab", continuation.fragment);
    try testing.expect(continuation.end_headers);
    const empty = try parse_continuation(header_of(9, 0, 0, 50), "");
    try testing.expectEqual(0, empty.fragment.len);
    try testing.expect(!empty.end_headers);
    try testing.expectError(error.StreamIdZero, parse_continuation(header_of(9, 2, 0, 0), "ab"));
}

test "write_headers writes the flags, the priority fields, the fragment and zero padding" {
    var buffer: [64]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write_headers(&writer, 1, "abc", true, true, 0, null);
    try testing.expectEqualSlices(u8, "\x00\x00\x03\x01\x05\x00\x00\x00\x01abc", writer.written());
    writer = Writer.init(&buffer);
    const priority: Priority = .{ .exclusive = true, .dependency = 20, .weight = 9 };
    try write_headers(&writer, 3, "ab", false, false, 2, priority);
    try testing.expectEqualSlices(u8, "\x00\x00\x0a\x01\x28\x00\x00\x00\x03\x02\x80\x00\x00\x14\x09ab\x00\x00", writer.written());
    var reader = Reader.init(writer.written());
    const parsed = try parse_headers(try frame_header.read(&reader), reader.take_rest());
    try testing.expectEqualStrings("ab", parsed.fragment);
    try testing.expectEqual(priority, parsed.priority.?);
    try testing.expectEqual(2, parsed.padding_len);
}

test "write_push_promise and write_continuation write what their parsers read back" {
    var buffer: [64]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write_push_promise(&writer, 10, 12, "ab", true, 1);
    try testing.expectEqualSlices(u8, "\x00\x00\x08\x05\x0c\x00\x00\x00\x0a\x01\x00\x00\x00\x0cab\x00", writer.written());
    var reader = Reader.init(writer.written());
    const promise = try parse_push_promise(try frame_header.read(&reader), reader.take_rest());
    try testing.expectEqual(12, promise.promised_stream_id);
    try testing.expectEqualStrings("ab", promise.fragment);
    writer = Writer.init(&buffer);
    try write_continuation(&writer, 50, "xyz", true);
    try testing.expectEqualSlices(u8, "\x00\x00\x03\x09\x04\x00\x00\x00\x32xyz", writer.written());
    reader = Reader.init(writer.written());
    const continuation = try parse_continuation(try frame_header.read(&reader), reader.take_rest());
    try testing.expectEqualStrings("xyz", continuation.fragment);
    try testing.expect(continuation.end_headers);
}

test "a writer with too little room commits nothing" {
    var buffer: [10]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try testing.expectError(error.NoSpaceLeft, write_headers(&writer, 1, "ab", false, true, 0, null));
    try testing.expectError(error.NoSpaceLeft, write_push_promise(&writer, 1, 2, "", true, 0));
    try testing.expectError(error.NoSpaceLeft, write_continuation(&writer, 1, "ab", true));
    try testing.expectEqual(0, writer.offset);
    try testing.expectEqual(0, writer.written().len);
}
