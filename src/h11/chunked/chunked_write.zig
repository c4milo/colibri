//! Writes the chunked coding (RFC 9112 §7.1) into the caller's buffer: one chunk around data the
//! caller hands over, or the last chunk with its trailer section. colibri writes no chunk
//! extension, and a chunk-size in lowercase hex with no leading zero.
//!
//! A trailer field is refused when it is one of the fields RFC 9110 §6.5.1 says cannot be
//! processed outside the header section and whose definition colibri knows: Content-Length and
//! Transfer-Encoding frame the message, and Host routes it. Whether any other field may be a
//! trailer is the caller's to know, as §6.5.1 puts it on the sender.
//!
//! A write is all or nothing: on an error, the caller's buffer holds no chunk.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");

const Field = http.field.Field;
const Writer = core.writer.Writer;

pub const Error = error{
    /// The caller's buffer cannot hold the chunk.
    OutputTooSmall,
    /// A trailer field name that is not a token (RFC 9110 §5.1).
    FieldNameInvalid,
    /// A trailer field value holding a control, or leading or trailing whitespace (RFC 9110 §5.5).
    FieldValueInvalid,
    /// A trailer field that frames or routes the message (RFC 9110 §6.5.1).
    TrailerFieldForbidden,
};

/// The fields a trailer section never carries (RFC 9110 §6.5.1).
const forbidden_trailers = [_][]const u8{ "Content-Length", "Transfer-Encoding", "Host" };

/// `chunk = chunk-size CRLF chunk-data CRLF` around `data`, which is not empty: a zero-size chunk
/// is the last chunk (RFC 9112 §7.1). Returns the octets written.
pub fn write_chunk(output: []u8, data: []const u8) Error!usize {
    assert(data.len > 0);
    var writer = Writer.init(output);
    // RFC 9112 §7.1: a chunk is its size line, its data and a CRLF, so a buffer that holds less
    // holds no chunk at all.
    write_chunk_octets(&writer, data) catch return error.OutputTooSmall;
    return writer.written().len;
}

fn write_chunk_octets(writer: *Writer, data: []const u8) core.writer.Error!void {
    // RFC 9112 §7.1: chunk-size = 1*HEXDIG.
    try writer.print("{x}\r\n", .{data.len});
    try writer.write_bytes(data);
    try writer.write_bytes("\r\n");
}

/// `last-chunk trailer-section CRLF`, where `last-chunk = 1*("0") CRLF` (RFC 9112 §7.1, §7.1.2).
/// Returns the octets written.
pub fn write_last_chunk(output: []u8, trailers: []const Field) Error!usize {
    for (trailers) |line| {
        // RFC 9110 §5.1: field-name = token.
        http.field.validate_name(line.name) catch return error.FieldNameInvalid;
        // RFC 9110 §5.5: no NUL, CR, LF or other control.
        http.field.validate_value(line.value) catch return error.FieldValueInvalid;
        for (forbidden_trailers) |name| {
            // RFC 9110 §6.5.1: a sender MUST NOT generate a trailer field whose definition does
            // not permit it; these frame or route the message.
            if (http.field.names_equal(line.name, name)) return error.TrailerFieldForbidden;
        }
    }
    var writer = Writer.init(output);
    // RFC 9112 §7.1: the last chunk, the trailer section and the empty line end the coding
    // together, so a buffer that holds less holds none of them.
    write_last_octets(&writer, trailers) catch return error.OutputTooSmall;
    return writer.written().len;
}

fn write_last_octets(writer: *Writer, trailers: []const Field) core.writer.Error!void {
    try writer.write_bytes("0\r\n");
    for (trailers) |line| {
        try writer.write_bytes(line.name);
        try writer.write_bytes(": ");
        try writer.write_bytes(line.value);
        try writer.write_bytes("\r\n");
    }
    try writer.write_bytes("\r\n");
}

const testing = std.testing;
const chunked = @import("chunked.zig");

/// The buffer and section the tests use, placed outside any stack frame.
var test_output: [test_output_len]u8 = undefined;
const test_output_len = 128;
var test_trailers: http.FieldSection = undefined;

test "chunks written decode back to their data and trailers" {
    var length = try write_chunk(&test_output, "Wiki");
    length += try write_chunk(test_output[length..], "0123456789abcdefg");
    length += try write_last_chunk(test_output[length..], &.{.{ .name = "Checksum", .value = "1" }});
    try testing.expectEqualStrings("4\r\nWiki\r\n11\r\n0123456789abcdefg\r\n0\r\nChecksum: 1\r\n\r\n", test_output[0..length]);
    var decoder: chunked.Decoder = .{};
    var data: [32]u8 = undefined;
    var written: usize = 0;
    var offset: usize = 0;
    for (0..8) |_| {
        const decoded = try decoder.decode(.request, test_output[offset..length], &test_trailers);
        @memcpy(data[written..][0..decoded.data.len], decoded.data);
        written += decoded.data.len;
        offset += decoded.consumed;
        if (decoded.done) break;
    }
    try testing.expectEqualStrings("Wiki0123456789abcdefg", data[0..written]);
    try testing.expectEqualStrings("1", test_trailers.find("checksum").?.value);
}

test "RFC 9110 §6.5.1: a trailer that frames or routes the message is refused" {
    for (forbidden_trailers) |name| {
        try testing.expectError(error.TrailerFieldForbidden, write_last_chunk(&test_output, &.{.{ .name = name, .value = "1" }}));
    }
    try testing.expectError(error.TrailerFieldForbidden, write_last_chunk(&test_output, &.{.{ .name = "content-length", .value = "1" }}));
    try testing.expectError(error.FieldNameInvalid, write_last_chunk(&test_output, &.{.{ .name = "a b", .value = "1" }}));
    try testing.expectError(error.FieldValueInvalid, write_last_chunk(&test_output, &.{.{ .name = "a", .value = "1\n" }}));
    try testing.expectEqualStrings("0\r\n\r\n", test_output[0..try write_last_chunk(&test_output, &.{})]);
}

test "a chunk that does not fit is not written, and one that fits exactly is" {
    try testing.expectError(error.OutputTooSmall, write_chunk(test_output[0..6], "ab"));
    try testing.expectEqual(7, try write_chunk(test_output[0..7], "ab"));
    try testing.expectError(error.OutputTooSmall, write_last_chunk(test_output[0..4], &.{}));
    try testing.expectEqual(5, try write_last_chunk(test_output[0..5], &.{}));
}
