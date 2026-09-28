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
const json_module = @import("json.zig");
const Json = json_module.Json;

pub const Error = json_module.Error;

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
pub fn padding(json: *Json, len: u64) Error!void {
    assert(len > 0);
    try begin(json, "padding");
    try json.key("raw");
    try json.begin_object();
    try json.field_unsigned("payload_length", len);
    try json.end_object();
    try json.end_object();
}

pub fn ping(json: *Json) Error!void {
    try begin(json, "ping");
    try json.end_object();
}

/// Opens an ACK frame (§8.13.3) whose delay, already scaled by the ACK Delay Exponent, is
/// `delay_ns`. `ack_range` writes each range and `ack_end` closes the frame.
pub fn ack_begin(json: *Json, delay_ns: u64) Error!void {
    try begin(json, "ack");
    try json.field_milliseconds("ack_delay", delay_ns);
    try json.key("acked_ranges");
    try json.begin_array();
}

/// One acknowledged range. §8.13.3: a range of one packet SHOULD be logged as one number.
pub fn ack_range(json: *Json, smallest: u64, largest: u64) Error!void {
    assert(smallest <= largest);
    try json.begin_array();
    try json.unsigned(smallest);
    if (largest != smallest) try json.unsigned(largest);
    try json.end_array();
}

pub fn ack_end(json: *Json, ecn: ?EcnCounts) Error!void {
    try json.end_array();
    if (ecn) |counts| {
        try json.field_unsigned("ect1", counts.ect1);
        try json.field_unsigned("ect0", counts.ect0);
        try json.field_unsigned("ce", counts.ce);
    }
    try json.end_object();
}

/// §8.13.4. The error is the application's, whose names `quic` does not know, so it is
/// "unknown" and the code follows.
pub fn reset_stream(json: *Json, stream_id: u64, error_code: u64, final_size: u64) Error!void {
    try begin(json, "reset_stream");
    try json.field_unsigned("stream_id", stream_id);
    try application_error(json, "error", error_code);
    try json.field_unsigned("final_size", final_size);
    try json.end_object();
}

/// §8.13.6, with the error written as `reset_stream` writes it.
pub fn stop_sending(json: *Json, stream_id: u64, error_code: u64) Error!void {
    try begin(json, "stop_sending");
    try json.field_unsigned("stream_id", stream_id);
    try application_error(json, "error", error_code);
    try json.end_object();
}

/// §8.13.7: "The length field of the Crypto frame MUST be logged in the qlog raw.length field."
pub fn crypto(json: *Json, offset: u64, len: u64) Error!void {
    try begin(json, "crypto");
    try json.field_unsigned("offset", offset);
    try raw_length(json, len);
    try json.end_object();
}

/// §8.13.8, with the token's length alone.
pub fn new_token(json: *Json, token_len: u64) Error!void {
    try begin(json, "new_token");
    try json.key("token");
    try json.begin_object();
    try raw_length(json, token_len);
    try json.end_object();
    try json.end_object();
}

/// §8.13.9: a STREAM frame's length "MUST be logged in the qlog raw.length field".
pub fn stream(json: *Json, stream_id: u64, offset: u64, len: u64, fin: bool) Error!void {
    try begin(json, "stream");
    try json.field_unsigned("stream_id", stream_id);
    try json.field_unsigned("offset", offset);
    if (fin) try json.field_boolean("fin", true);
    try raw_length(json, len);
    try json.end_object();
}

pub fn max_data(json: *Json, maximum: u64) Error!void {
    try begin(json, "max_data");
    try json.field_unsigned("maximum", maximum);
    try json.end_object();
}

pub fn max_stream_data(json: *Json, stream_id: u64, maximum: u64) Error!void {
    try begin(json, "max_stream_data");
    try json.field_unsigned("stream_id", stream_id);
    try json.field_unsigned("maximum", maximum);
    try json.end_object();
}

pub fn max_streams(json: *Json, directionality: Directionality, maximum: u64) Error!void {
    try begin(json, "max_streams");
    try json.field_string("stream_type", @tagName(directionality));
    try json.field_unsigned("maximum", maximum);
    try json.end_object();
}

pub fn data_blocked(json: *Json, limit: u64) Error!void {
    try begin(json, "data_blocked");
    try json.field_unsigned("limit", limit);
    try json.end_object();
}

pub fn stream_data_blocked(json: *Json, stream_id: u64, limit: u64) Error!void {
    try begin(json, "stream_data_blocked");
    try json.field_unsigned("stream_id", stream_id);
    try json.field_unsigned("limit", limit);
    try json.end_object();
}

pub fn streams_blocked(json: *Json, directionality: Directionality, limit: u64) Error!void {
    try begin(json, "streams_blocked");
    try json.field_string("stream_type", @tagName(directionality));
    try json.field_unsigned("limit", limit);
    try json.end_object();
}

/// §8.13.16, without the optional stateless reset token, which is state a peer keeps.
pub fn new_connection_id(json: *Json, sequence_number: u64, retire_prior_to: u64, connection_id: []const u8) Error!void {
    try begin(json, "new_connection_id");
    try json.field_unsigned("sequence_number", sequence_number);
    try json.field_unsigned("retire_prior_to", retire_prior_to);
    try json.field_hexstring("connection_id", connection_id);
    try json.end_object();
}

pub fn retire_connection_id(json: *Json, sequence_number: u64) Error!void {
    try begin(json, "retire_connection_id");
    try json.field_unsigned("sequence_number", sequence_number);
    try json.end_object();
}

pub fn path_challenge(json: *Json, data: []const u8) Error!void {
    try begin(json, "path_challenge");
    try json.field_hexstring("data", data);
    try json.end_object();
}

pub fn path_response(json: *Json, data: []const u8) Error!void {
    try begin(json, "path_response");
    try json.field_hexstring("data", data);
    try json.end_object();
}

/// §8.13.20. A transport error is named by its code, and an application error, whose names
/// `quic` does not know, is "unknown" with the code. The reason is a peer's octets, so it is
/// `reason_bytes` and never `reason` (decision 102).
pub fn connection_close(json: *Json, space: ErrorSpace, error_code: u64, frame_type: ?u64, reason: []const u8) Error!void {
    try begin(json, "connection_close");
    try json.field_string("error_space", @tagName(space));
    switch (space) {
        .transport => try transport_error(json, "error", error_code),
        .application => try application_error(json, "error", error_code),
    }
    if (reason.len > 0) try json.field_hexstring("reason_bytes", reason);
    if (frame_type) |trigger| try json.field_unsigned("trigger_frame_type", trigger);
    try json.end_object();
}

pub fn handshake_done(json: *Json) Error!void {
    try begin(json, "handshake_done");
    try json.end_object();
}

fn begin(json: *Json, frame_type: []const u8) Error!void {
    assert(frame_type.len > 0);
    try json.begin_object();
    try json.field_string("frame_type", frame_type);
}

fn raw_length(json: *Json, len: u64) Error!void {
    try json.key("raw");
    try json.begin_object();
    try json.field_unsigned("length", len);
    try json.end_object();
}

/// An application's error, whose names `quic` does not know: "unknown" under `name`, and the
/// code in `error_code` (quic-events §8.13.25).
pub fn application_error(json: *Json, name: []const u8, error_code: u64) Error!void {
    try json.field_string(name, "unknown");
    try json.field_unsigned("error_code", error_code);
}

/// A transport error under `name` (§8.13.24, §8.13.26): the name RFC 9000 §20.1 gives the code,
/// a CRYPTO_ERROR by its code in hex, or "unknown" with the code in `error_code`.
pub fn transport_error(json: *Json, name: []const u8, error_code: u64) Error!void {
    if (error_code < transport_error_names.len) {
        try json.field_string(name, transport_error_names[@intCast(error_code)]);
        return;
    }
    if (error_code >= constants.crypto_error_first and error_code <= constants.crypto_error_last) {
        var text: [crypto_error_prefix.len + constants.crypto_error_digits]u8 = undefined;
        @memcpy(text[0..crypto_error_prefix.len], crypto_error_prefix);
        const digits = std.fmt.bufPrint(text[crypto_error_prefix.len..], "{x:0>3}", .{error_code}) catch unreachable;
        assert(digits.len == text.len - crypto_error_prefix.len);
        try json.field_string(name, &text);
        return;
    }
    try json.field_string(name, "unknown");
    try json.field_unsigned("error_code", error_code);
}

const testing = std.testing;

/// Room for the longest frame a test writes.
const test_buffer_len = 256;

fn expect_frame(expected: []const u8, comptime write: anytype, arguments: anytype) !void {
    var buffer: [test_buffer_len]u8 = undefined;
    var json = Json.init(&buffer);
    try @call(.auto, write, .{&json} ++ arguments);
    try testing.expectEqualStrings(expected, json.written());
}

test "padding, ping and handshake_done" {
    try expect_frame("{\"frame_type\":\"padding\",\"raw\":{\"payload_length\":1100}}", padding, .{1100});
    try expect_frame("{\"frame_type\":\"ping\"}", ping, .{});
    try expect_frame("{\"frame_type\":\"handshake_done\"}", handshake_done, .{});
}

test "an ack frame writes a single-packet range as one number, and its ECN counts" {
    var buffer: [256]u8 = undefined;
    var json = Json.init(&buffer);
    try ack_begin(&json, 1_500_000);
    try ack_range(&json, 7, 9);
    try ack_range(&json, 3, 3);
    try ack_end(&json, .{ .ect0 = 4, .ect1 = 0, .ce = 1 });
    try testing.expectEqualStrings("{\"frame_type\":\"ack\",\"ack_delay\":1.500,\"acked_ranges\":[[7,9],[3]]," ++
        "\"ect1\":0,\"ect0\":4,\"ce\":1}", json.written());
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
