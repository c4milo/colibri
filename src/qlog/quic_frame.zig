//! The QUIC frames of quic-events §8.13, one writer per frame type. `quic` calls them for each
//! frame of a packet it logs, passing plain values, so this module knows no type of `quic`'s.
//!
//! Each writer writes one member of a `frames` array: an object whose `frame_type` is the
//! draft's name for the frame. A peer's octets are written as hexstrings (decision 102), and a
//! token's contents are not written at all: main schema §14.1 lists tokens among the data at
//! risk, and quic-events §8.9 leaves every field of a token optional.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const member = @import("member.zig");
const TextWriter = @import("json").TextWriter;
const Features = @import("codec").Features;

pub const Error = member.Error;

/// Quic-events §8.13.12's `StreamType`.
pub const Directionality = enum { bidirectional, unidirectional };

/// Quic-events §8.13.20's `ErrorSpace`.
pub const ErrorSpace = enum { transport, application };

/// The ECN counts an ACK frame of type 0x03 carries (RFC 9000 §19.3.2).
pub const EcnCounts = struct { ect0: u64, ect1: u64, ce: u64 };

/// Quic-events §8.13.24's `$TransportError` names, indexed by the codes RFC 9000 §20.1 gives
/// them, 0x00 through 0x10.
const transport_error_names = [_][]const u8{
    "no_error",                  "internal_error",         "connection_refused",
    "flow_control_error",        "stream_limit_error",     "stream_state_error",
    "final_size_error",          "frame_encoding_error",   "transport_parameter_error",
    "connection_id_limit_error", "protocol_violation",     "invalid_token",
    "application_error",         "crypto_buffer_exceeded", "key_update_error",
    "aead_limit_reached",        "no_viable_path",
};

/// Quic-events §8.13.26's name of a CRYPTO_ERROR: the code in hex, all three digits.
const crypto_error_prefix = "crypto_error_0x";

/// §8.13.1: one PADDING frame for a run of them, with the run's length as `raw.payload_length`.
pub fn padding(text: *TextWriter, len: u64) Error!void {
    assert(len > 0);
    try begin(text, "padding");
    try text.name("raw");
    try text.begin_object();
    try member.unsigned(text, "payload_length", len);
    try text.end_object();
    try text.end_object();
}

pub fn ping(text: *TextWriter) Error!void {
    try begin(text, "ping");
    try text.end_object();
}

/// Opens an ACK frame (§8.13.3) whose delay, already scaled by the ACK Delay Exponent, is
/// `delay_ns`. `ack_range` writes each range and `ack_end` closes the frame.
pub fn ack_begin(text: *TextWriter, delay_ns: u64) Error!void {
    try begin(text, "ack");
    try member.milliseconds(text, "ack_delay", delay_ns);
    try text.name("acked_ranges");
    try text.begin_array();
}

/// One acknowledged range. §8.13.3: a range of one packet SHOULD be logged as one number.
pub fn ack_range(text: *TextWriter, smallest: u64, largest: u64) Error!void {
    assert(smallest <= largest);
    try text.begin_array();
    try text.unsigned(smallest);
    if (largest != smallest) try text.unsigned(largest);
    try text.end_array();
}

pub fn ack_end(text: *TextWriter, ecn: ?EcnCounts) Error!void {
    try text.end_array();
    if (ecn) |counts| {
        try member.unsigned(text, "ect1", counts.ect1);
        try member.unsigned(text, "ect0", counts.ect0);
        try member.unsigned(text, "ce", counts.ce);
    }
    try text.end_object();
}

/// §8.13.4. The error is the application's, whose names `quic` does not know, so it is
/// "unknown" and the code follows.
pub fn reset_stream(text: *TextWriter, stream_id: u64, error_code: u64, final_size: u64) Error!void {
    try begin(text, "reset_stream");
    try member.unsigned(text, "stream_id", stream_id);
    try application_error(text, "error", error_code);
    try member.unsigned(text, "final_size", final_size);
    try text.end_object();
}

/// §8.13.6, with the error written as `reset_stream` writes it.
pub fn stop_sending(text: *TextWriter, stream_id: u64, error_code: u64) Error!void {
    try begin(text, "stop_sending");
    try member.unsigned(text, "stream_id", stream_id);
    try application_error(text, "error", error_code);
    try text.end_object();
}

/// §8.13.7: "The length field of the Crypto frame MUST be logged in the qlog raw.length field."
pub fn crypto(text: *TextWriter, offset: u64, len: u64) Error!void {
    try begin(text, "crypto");
    try member.unsigned(text, "offset", offset);
    try raw_length(text, len);
    try text.end_object();
}

/// §8.13.8, with the token's length alone.
pub fn new_token(text: *TextWriter, token_len: u64) Error!void {
    try begin(text, "new_token");
    try text.name("token");
    try text.begin_object();
    try raw_length(text, token_len);
    try text.end_object();
    try text.end_object();
}

/// §8.13.9: a STREAM frame's length "MUST be logged in the qlog raw.length field".
pub fn stream(text: *TextWriter, stream_id: u64, offset: u64, len: u64, fin: bool) Error!void {
    try begin(text, "stream");
    try member.unsigned(text, "stream_id", stream_id);
    try member.unsigned(text, "offset", offset);
    if (fin) try member.boolean(text, "fin", true);
    try raw_length(text, len);
    try text.end_object();
}

pub fn max_data(text: *TextWriter, maximum: u64) Error!void {
    try begin(text, "max_data");
    try member.unsigned(text, "maximum", maximum);
    try text.end_object();
}

pub fn max_stream_data(text: *TextWriter, stream_id: u64, maximum: u64) Error!void {
    try begin(text, "max_stream_data");
    try member.unsigned(text, "stream_id", stream_id);
    try member.unsigned(text, "maximum", maximum);
    try text.end_object();
}

pub fn max_streams(text: *TextWriter, directionality: Directionality, maximum: u64) Error!void {
    try begin(text, "max_streams");
    try member.string(text, "stream_type", @tagName(directionality));
    try member.unsigned(text, "maximum", maximum);
    try text.end_object();
}

pub fn data_blocked(text: *TextWriter, limit: u64) Error!void {
    try begin(text, "data_blocked");
    try member.unsigned(text, "limit", limit);
    try text.end_object();
}

pub fn stream_data_blocked(text: *TextWriter, stream_id: u64, limit: u64) Error!void {
    try begin(text, "stream_data_blocked");
    try member.unsigned(text, "stream_id", stream_id);
    try member.unsigned(text, "limit", limit);
    try text.end_object();
}

pub fn streams_blocked(text: *TextWriter, directionality: Directionality, limit: u64) Error!void {
    try begin(text, "streams_blocked");
    try member.string(text, "stream_type", @tagName(directionality));
    try member.unsigned(text, "limit", limit);
    try text.end_object();
}

/// §8.13.16, without the optional stateless reset token, which is state a peer keeps.
pub fn new_connection_id(text: *TextWriter, sequence_number: u64, retire_prior_to: u64, connection_id: []const u8) Error!void {
    try begin(text, "new_connection_id");
    try member.unsigned(text, "sequence_number", sequence_number);
    try member.unsigned(text, "retire_prior_to", retire_prior_to);
    try member.hex(text, "connection_id", connection_id);
    try text.end_object();
}

pub fn retire_connection_id(text: *TextWriter, sequence_number: u64) Error!void {
    try begin(text, "retire_connection_id");
    try member.unsigned(text, "sequence_number", sequence_number);
    try text.end_object();
}

pub fn path_challenge(text: *TextWriter, data: []const u8) Error!void {
    try begin(text, "path_challenge");
    try member.hex(text, "data", data);
    try text.end_object();
}

pub fn path_response(text: *TextWriter, data: []const u8) Error!void {
    try begin(text, "path_response");
    try member.hex(text, "data", data);
    try text.end_object();
}

/// §8.13.20. A transport error is named by its code, and an application error, whose names
/// `quic` does not know, is "unknown" with the code. The reason is a peer's octets, so it is
/// `reason_bytes` and never `reason` (decision 102).
pub fn connection_close(text: *TextWriter, space: ErrorSpace, error_code: u64, frame_type: ?u64, reason: []const u8) Error!void {
    try begin(text, "connection_close");
    try member.string(text, "error_space", @tagName(space));
    switch (space) {
        .transport => try transport_error(text, "error", error_code),
        .application => try application_error(text, "error", error_code),
    }
    if (reason.len > 0) try member.hex(text, "reason_bytes", reason);
    if (frame_type) |trigger| try member.unsigned(text, "trigger_frame_type", trigger);
    try text.end_object();
}

pub fn handshake_done(text: *TextWriter) Error!void {
    try begin(text, "handshake_done");
    try text.end_object();
}

fn begin(text: *TextWriter, frame_type: []const u8) Error!void {
    assert(frame_type.len > 0);
    try text.begin_object();
    try member.string(text, "frame_type", frame_type);
}

fn raw_length(text: *TextWriter, len: u64) Error!void {
    try text.name("raw");
    try text.begin_object();
    try member.unsigned(text, "length", len);
    try text.end_object();
}

/// An application's error, whose names `quic` does not know: "unknown" under `name`, and the
/// code in `error_code` (quic-events §8.13.25).
pub fn application_error(text: *TextWriter, name: []const u8, error_code: u64) Error!void {
    try member.string(text, name, "unknown");
    try member.unsigned(text, "error_code", error_code);
}

/// A transport error under `name` (§8.13.24, §8.13.26): the name RFC 9000 §20.1 gives the code,
/// a CRYPTO_ERROR by its code in hex, or "unknown" with the code in `error_code`.
pub fn transport_error(text: *TextWriter, name: []const u8, error_code: u64) Error!void {
    if (error_code < transport_error_names.len) {
        try member.string(text, name, transport_error_names[@intCast(error_code)]);
        return;
    }
    if (error_code >= constants.crypto_error_first and error_code <= constants.crypto_error_last) {
        var error_name: [crypto_error_prefix.len + constants.crypto_error_digits]u8 = undefined;
        @memcpy(error_name[0..crypto_error_prefix.len], crypto_error_prefix);
        const digits = std.fmt.bufPrint(error_name[crypto_error_prefix.len..], "{x:0>3}", .{error_code}) catch unreachable;
        assert(digits.len == error_name.len - crypto_error_prefix.len);
        try member.string(text, name, &error_name);
        return;
    }
    try member.string(text, name, "unknown");
    try member.unsigned(text, "error_code", error_code);
}

const testing = std.testing;

/// Room for the longest frame a test writes.
const test_buffer_len = 256;

fn expect_frame(expected: []const u8, comptime write: anytype, arguments: anytype) !void {
    var buffer: [test_buffer_len]u8 = undefined;
    var text = TextWriter.init(&buffer, .text, Features.none());
    try @call(.auto, write, .{&text} ++ arguments);
    try testing.expectEqualStrings(expected, text.written());
}

test "padding, ping and handshake_done" {
    try expect_frame("{\"frame_type\":\"padding\",\"raw\":{\"payload_length\":1100}}", padding, .{1100});
    try expect_frame("{\"frame_type\":\"ping\"}", ping, .{});
    try expect_frame("{\"frame_type\":\"handshake_done\"}", handshake_done, .{});
}

test "an ack frame writes a single-packet range as one number, and its ECN counts" {
    var buffer: [256]u8 = undefined;
    var text = TextWriter.init(&buffer, .text, Features.none());
    try ack_begin(&text, 1_500_000);
    try ack_range(&text, 7, 9);
    try ack_range(&text, 3, 3);
    try ack_end(&text, .{ .ect0 = 4, .ect1 = 0, .ce = 1 });
    try testing.expectEqualStrings("{\"frame_type\":\"ack\",\"ack_delay\":1.500,\"acked_ranges\":[[7,9],[3]]," ++
        "\"ect1\":0,\"ect0\":4,\"ce\":1}", text.written());
}

test "stream and crypto frames log their length as raw.length" {
    try expect_frame("{\"frame_type\":\"stream\",\"stream_id\":4,\"offset\":10,\"fin\":true,\"raw\":{\"length\":5}}", stream, .{ 4, 10, 5, true });
    try expect_frame("{\"frame_type\":\"stream\",\"stream_id\":0,\"offset\":0,\"raw\":{\"length\":1}}", stream, .{ 0, 0, 1, false });
    try expect_frame("{\"frame_type\":\"crypto\",\"offset\":2,\"raw\":{\"length\":3}}", crypto, .{ 2, 3 });
    try expect_frame("{\"frame_type\":\"new_token\",\"token\":{\"raw\":{\"length\":40}}}", new_token, .{40});
}

test "stream errors are the application's and written as unknown with the code" {
    try expect_frame("{\"frame_type\":\"reset_stream\",\"stream_id\":8,\"error\":\"unknown\",\"error_code\":268,\"final_size\":20}", reset_stream, .{ 8, 268, 20 });
    try expect_frame("{\"frame_type\":\"stop_sending\",\"stream_id\":8,\"error\":\"unknown\",\"error_code\":0}", stop_sending, .{ 8, 0 });
}

test "flow control and connection ID frames" {
    try expect_frame("{\"frame_type\":\"max_streams\",\"stream_type\":\"unidirectional\",\"maximum\":3}", max_streams, .{ Directionality.unidirectional, 3 });
    try expect_frame("{\"frame_type\":\"streams_blocked\",\"stream_type\":\"bidirectional\",\"limit\":9}", streams_blocked, .{ Directionality.bidirectional, 9 });
    try expect_frame("{\"frame_type\":\"max_stream_data\",\"stream_id\":1,\"maximum\":2}", max_stream_data, .{ 1, 2 });
    try expect_frame("{\"frame_type\":\"stream_data_blocked\",\"stream_id\":1,\"limit\":2}", stream_data_blocked, .{ 1, 2 });
    try expect_frame("{\"frame_type\":\"max_data\",\"maximum\":5}", max_data, .{5});
    try expect_frame("{\"frame_type\":\"data_blocked\",\"limit\":5}", data_blocked, .{5});
    try expect_frame("{\"frame_type\":\"new_connection_id\",\"sequence_number\":2,\"retire_prior_to\":1,\"connection_id\":\"0a0b\"}", new_connection_id, .{ 2, 1, &[_]u8{ 0x0a, 0x0b } });
    try expect_frame("{\"frame_type\":\"retire_connection_id\",\"sequence_number\":2}", retire_connection_id, .{2});
    try expect_frame("{\"frame_type\":\"path_challenge\",\"data\":\"0102\"}", path_challenge, .{&[_]u8{ 1, 2 }});
    try expect_frame("{\"frame_type\":\"path_response\",\"data\":\"0102\"}", path_response, .{&[_]u8{ 1, 2 }});
}

test "a transport close names its error, a CRYPTO_ERROR by its code, and the rest as unknown" {
    try expect_frame("{\"frame_type\":\"connection_close\",\"error_space\":\"transport\",\"error\":\"protocol_violation\",\"trigger_frame_type\":6}", connection_close, .{ ErrorSpace.transport, 0x0a, 6, "" });
    try expect_frame("{\"frame_type\":\"connection_close\",\"error_space\":\"transport\",\"error\":\"no_viable_path\"}", connection_close, .{ ErrorSpace.transport, 0x10, null, "" });
    try expect_frame("{\"frame_type\":\"connection_close\",\"error_space\":\"transport\",\"error\":\"crypto_error_0x128\"}", connection_close, .{ ErrorSpace.transport, 0x128, null, "" });
    try expect_frame("{\"frame_type\":\"connection_close\",\"error_space\":\"transport\",\"error\":\"unknown\",\"error_code\":17}", connection_close, .{ ErrorSpace.transport, 0x11, null, "" });
    try expect_frame("{\"frame_type\":\"connection_close\",\"error_space\":\"application\",\"error\":\"unknown\",\"error_code\":256,\"reason_bytes\":\"6279\"}", connection_close, .{ ErrorSpace.application, 0x100, null, "by" });
}
