//! The h2 frame codec of RFC 9113 §4 and §6: the entry point of `src/h2/frame/`, which re-exports
//! the header codec (frame_header.zig), the padding rule (frame_padding.zig) and the parsers and
//! writers of the ten frame types (frame_data.zig, frame_headers.zig, frame_control.zig,
//! frame_settings.zig).
//!
//! The connection reads a header with `read_header`, checks the Length against
//! SETTINGS_MAX_FRAME_SIZE (§4.2), collects that many octets and hands both to `parse`, which
//! dispatches on the Type octet and applies every format rule of that type. A type this document
//! does not define is returned as `Payload.unknown` with its octets, for the connection to ignore
//! and discard (§4.1, §5.5). `verdict` is the one table that maps each parse error, for the type
//! and stream it occurred on, to the connection or stream error and the code the RFC attaches.
//!
//! The codec is a pure function of the header and the payload (invariant 6): it holds no state,
//! reads no clock and allocates nothing. Every parser is a check on the shape of one frame; every
//! rule that needs the connection's state, such as which stream is open, is the connection's.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");

pub const frame_header = @import("frame_header.zig");
pub const frame_padding = @import("frame_padding.zig");
pub const frame_data = @import("frame_data.zig");
pub const frame_headers = @import("frame_headers.zig");
pub const frame_control = @import("frame_control.zig");
pub const frame_settings = @import("frame_settings.zig");

pub const Header = frame_header.Header;
pub const read_header = frame_header.read;
pub const write_header = frame_header.write;
pub const has_flag = frame_header.has_flag;

pub const Data = frame_data.Data;
pub const Headers = frame_headers.Headers;
pub const PushPromise = frame_headers.PushPromise;
pub const Continuation = frame_headers.Continuation;
pub const Priority = frame_control.Priority;
pub const RstStream = frame_control.RstStream;
pub const Ping = frame_control.Ping;
pub const Goaway = frame_control.Goaway;
pub const WindowUpdate = frame_control.WindowUpdate;
pub const Settings = frame_settings.Settings;
pub const Setting = frame_settings.Setting;

pub const write_data = frame_data.write_data;
pub const write_headers = frame_headers.write_headers;
pub const write_push_promise = frame_headers.write_push_promise;
pub const write_continuation = frame_headers.write_continuation;
pub const write_priority = frame_control.write_priority;
pub const write_rst_stream = frame_control.write_rst_stream;
pub const write_ping = frame_control.write_ping;
pub const write_goaway = frame_control.write_goaway;
pub const write_window_update = frame_control.write_window_update;
pub const write_settings = frame_settings.write_settings;
pub const write_settings_ack = frame_settings.write_settings_ack;

/// The ten frame types RFC 9113 §6 defines. Non-exhaustive: any other Type octet is an unknown
/// type, which a receiver ignores and discards (§4.1, §5.5) after consuming its octets.
pub const Type = enum(u8) {
    data = constants.frame_type_data,
    headers = constants.frame_type_headers,
    priority = constants.frame_type_priority,
    rst_stream = constants.frame_type_rst_stream,
    settings = constants.frame_type_settings,
    push_promise = constants.frame_type_push_promise,
    ping = constants.frame_type_ping,
    goaway = constants.frame_type_goaway,
    window_update = constants.frame_type_window_update,
    continuation = constants.frame_type_continuation,
    _,
};

/// A frame of a type RFC 9113 does not define: its Type octet and its whole payload.
pub const Unknown = struct {
    type: u8,
    payload: []const u8,
};

/// The parsed payload of one frame, tagged by its type; `unknown` for a type §6 does not define.
pub const Payload = union(enum) {
    data: Data,
    headers: Headers,
    priority: Priority,
    rst_stream: RstStream,
    settings: Settings,
    push_promise: PushPromise,
    ping: Ping,
    goaway: Goaway,
    window_update: WindowUpdate,
    continuation: Continuation,
    unknown: Unknown,
};

/// Every error a parser returns. Each is one RFC 9113 rule; `verdict` names the section.
pub const ParseError = frame_data.Error || frame_headers.Error || frame_control.Error || frame_settings.Error;

/// Parses the payload of one frame whose header the connection has read and sized: `payload` is
/// exactly `header.length` octets, at most `frame_size_max` of them (§4.2).
pub fn parse(header: Header, payload: []const u8) ParseError!Payload {
    assert(payload.len == header.length);
    assert(header.length <= constants.frame_size_max);
    assert(header.stream_id <= constants.stream_id_max);
    const frame_type: Type = @enumFromInt(header.type);
    return switch (frame_type) {
        .data => .{ .data = try frame_data.parse(header, payload) },
        .headers => .{ .headers = try frame_headers.parse_headers(header, payload) },
        .priority => .{ .priority = try frame_control.parse_priority(header, payload) },
        .rst_stream => .{ .rst_stream = try frame_control.parse_rst_stream(header, payload) },
        .settings => .{ .settings = try frame_settings.parse_settings(header, payload) },
        .push_promise => .{ .push_promise = try frame_headers.parse_push_promise(header, payload) },
        .ping => .{ .ping = try frame_control.parse_ping(header, payload) },
        .goaway => .{ .goaway = try frame_control.parse_goaway(header, payload) },
        .window_update => .{ .window_update = try frame_control.parse_window_update(header, payload) },
        .continuation => .{ .continuation = try frame_headers.parse_continuation(header, payload) },
        // RFC 9113 §4.1 and §5.5: a frame of an unknown type is ignored and discarded, whatever
        // its flags, stream identifier or payload.
        _ => .{ .unknown = .{ .type = header.type, .payload = payload } },
    };
}

/// What the connection does about a parse error: end the connection with a GOAWAY (§5.4.1) or
/// the stream with a RST_STREAM (§5.4.2), carrying `code`.
pub const Verdict = struct {
    kind: enum { connection, stream },
    code: u32,
};

fn connection_error(code: u32) Verdict {
    return .{ .kind = .connection, .code = code };
}

fn stream_error(code: u32) Verdict {
    return .{ .kind = .stream, .code = code };
}

/// The error kind and code RFC 9113 attaches to `failure` in a frame of `frame_type` on
/// `stream_id`. The only stream errors are a PRIORITY frame of the wrong length (§6.3) and a
/// zero WINDOW_UPDATE increment on a stream (§6.9); every other parse error ends the connection.
pub fn verdict(failure: ParseError, frame_type: Type, stream_id: u32) Verdict {
    assert(stream_id <= constants.stream_id_max);
    return switch (failure) {
        // RFC 9113 §6.1, §6.2, §6.3, §6.4, §6.6, §6.10: a frame that must name a stream and
        // names 0 is a connection error of PROTOCOL_ERROR.
        error.StreamIdZero => connection_error(constants.error_protocol_error),
        // RFC 9113 §6.5, §6.7, §6.8: a frame that must be on stream 0 and is not is a connection
        // error of PROTOCOL_ERROR.
        error.StreamIdNotZero => connection_error(constants.error_protocol_error),
        // RFC 9113 §6.1, §6.2, §6.6: padding of the payload length or greater is a connection
        // error of PROTOCOL_ERROR.
        error.PaddingTooLong => connection_error(constants.error_protocol_error),
        // RFC 9113 §6.6: a promise of an illegal stream identifier (§5.1.1) is a connection error
        // of PROTOCOL_ERROR.
        error.PromisedStreamIdInvalid => connection_error(constants.error_protocol_error),
        // RFC 9113 §6.5: a SETTINGS ACK with a payload is a connection error of FRAME_SIZE_ERROR.
        error.AckNotEmpty => connection_error(constants.error_frame_size_error),
        // RFC 9113 §6.3: a PRIORITY frame of a length other than 5 is a stream error of
        // FRAME_SIZE_ERROR, the one size error that is not a connection error. §4.2: a size
        // error in HEADERS, PUSH_PROMISE, CONTINUATION, SETTINGS or any frame on stream 0, and
        // §6.4, §6.7, §6.9: in RST_STREAM, PING or WINDOW_UPDATE, is a connection error of
        // FRAME_SIZE_ERROR. The one size error DATA has, a PADDED frame with no Pad Length
        // octet, §4.2 leaves at the stream level; colibri ends the connection instead, which
        // §5.4.1 permits (an endpoint MAY treat a stream error as a connection error).
        error.LengthInvalid => length_verdict(frame_type, stream_id),
        // RFC 9113 §6.9: an increment of 0 is a stream error of PROTOCOL_ERROR; on the connection
        // flow-control window, stream 0, a connection error.
        error.WindowIncrementZero => increment_verdict(frame_type, stream_id),
    };
}

fn length_verdict(frame_type: Type, stream_id: u32) Verdict {
    if (frame_type != .priority) return connection_error(constants.error_frame_size_error);
    // parse_priority refuses stream 0 before it reads the length, so a stream error has a stream.
    assert(stream_id != constants.connection_stream_id);
    return stream_error(constants.error_frame_size_error);
}

fn increment_verdict(frame_type: Type, stream_id: u32) Verdict {
    assert(frame_type == .window_update);
    if (stream_id == constants.connection_stream_id) return connection_error(constants.error_protocol_error);
    return stream_error(constants.error_protocol_error);
}

const testing = std.testing;

/// Most octets a fuzzed frame holds, header included. Test-only.
const fuzz_frame_len_max = 64;

/// A whole frame either fails to read, parses, or is refused with an error `verdict` maps; none of
/// the three traps, and an unknown type keeps every octet of its payload.
fn fuzz_frame(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_frame_len_max]u8 = @splat(0);
    const octets = input[0..smith.slice(&input)];
    var reader = core.Reader.init(octets);
    const header = read_header(&reader) catch return;
    const rest = reader.take_rest();
    if (rest.len != header.length or header.length > constants.frame_size_max) return;
    const payload = parse(header, rest) catch |failure| {
        const outcome = verdict(failure, @enumFromInt(header.type), header.stream_id);
        try testing.expect(outcome.code == constants.error_protocol_error or outcome.code == constants.error_frame_size_error);
        return;
    };
    switch (payload) {
        .unknown => |unknown| try testing.expectEqual(rest.len, unknown.payload.len),
        .data => |data| try testing.expect(data.data.len + data.padding_len <= rest.len),
        else => {},
    }
}

test "fuzz: a frame reads, parses or is refused with a verdict, and never traps" {
    try testing.fuzz({}, fuzz_frame, .{ .corpus = &.{
        core.fuzz.input("\x00\x00\x14\x00\x08\x00\x00\x00\x02\x06Hello, world!Howdy!"),
        core.fuzz.input("\x00\x00\x23\x01\x2c\x00\x00\x00\x03\x10\x80\x00\x00\x14\x09this is dummyThis is padding."),
        core.fuzz.input("\x00\x00\x05\x02\x00\x00\x00\x00\x09\x00\x00\x00\x0b\x07"),
        core.fuzz.input("\x00\x00\x0c\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x20\x00\x00\x03\x00\x00\x13\x88"),
        core.fuzz.input("\x00\x00\x04\x08\x00\x00\x00\x00\x01\x00\x00\x00\x00"),
        core.fuzz.input("\x00\x00\x03\xff\xff\xff\xff\xff\xff\xaa\xbb\xcc"),
    } });
    try core.fuzz.sweep(fuzz_frame, null);
}

fn header_of(frame_type: u8, length: u32, flags: u8, stream_id: u32) Header {
    return .{ .length = length, .type = frame_type, .flags = flags, .stream_id = stream_id };
}

test "parse dispatches each defined type to its parser" {
    try testing.expectEqualStrings("ab", (try parse(header_of(0, 2, 0, 1), "ab")).data.data);
    try testing.expectEqualStrings("ab", (try parse(header_of(1, 2, 0, 1), "ab")).headers.fragment);
    try testing.expectEqual(11, (try parse(header_of(2, 5, 0, 9), "\x00\x00\x00\x0b\x07")).priority.dependency);
    try testing.expectEqual(8, (try parse(header_of(3, 4, 0, 5), "\x00\x00\x00\x08")).rst_stream.error_code);
    try testing.expect((try parse(header_of(4, 0, 1, 0), "")).settings.ack);
    try testing.expectEqual(12, (try parse(header_of(5, 4, 0, 10), "\x00\x00\x00\x0c")).push_promise.promised_stream_id);
    try testing.expectEqualStrings("deadbeef", &(try parse(header_of(6, 8, 0, 0), "deadbeef")).ping.opaque_data);
    try testing.expectEqual(30, (try parse(header_of(7, 8, 0, 0), "\x00\x00\x00\x1e\x00\x00\x00\x09")).goaway.last_stream_id);
    try testing.expectEqual(1000, (try parse(header_of(8, 4, 0, 50), "\x00\x00\x03\xe8")).window_update.increment);
    try testing.expectEqualStrings("ab", (try parse(header_of(9, 2, 0, 50), "ab")).continuation.fragment);
}

test "an unknown type is returned with its type octet and every payload octet (RFC 9113 §4.1, §5.5)" {
    const payload = try parse(header_of(0x0a, 3, 0xff, 0), "\xaa\xbb\xcc");
    try testing.expectEqual(0x0a, payload.unknown.type);
    try testing.expectEqualStrings("\xaa\xbb\xcc", payload.unknown.payload);
    const extension = try parse(header_of(0xff, 0, 0, 7), "");
    try testing.expectEqual(0xff, extension.unknown.type);
}

test "parse returns each parser's error unchanged" {
    try testing.expectError(error.StreamIdZero, parse(header_of(0, 1, 0, 0), "a"));
    try testing.expectError(error.LengthInvalid, parse(header_of(0, 0, constants.flag_padded, 1), ""));
    try testing.expectError(error.PaddingTooLong, parse(header_of(1, 4, constants.flag_padded, 1), "\x04\xaa\xaa\xaa"));
    try testing.expectError(error.LengthInvalid, parse(header_of(2, 4, 0, 1), "\x00\x00\x00\x01"));
    try testing.expectError(error.StreamIdNotZero, parse(header_of(4, 0, 0, 1), ""));
    try testing.expectError(error.AckNotEmpty, parse(header_of(4, 6, 1, 0), "\x00\x01\x00\x00\x00\x01"));
    try testing.expectError(error.PromisedStreamIdInvalid, parse(header_of(5, 4, 0, 1), "\x00\x00\x00\x01"));
    try testing.expectError(error.WindowIncrementZero, parse(header_of(8, 4, 0, 1), "\x00\x00\x00\x00"));
}

test "verdict maps every PROTOCOL_ERROR rule to a connection error of PROTOCOL_ERROR" {
    const protocol_error: Verdict = .{ .kind = .connection, .code = constants.error_protocol_error };
    try testing.expectEqual(protocol_error, verdict(error.StreamIdZero, .data, 0));
    try testing.expectEqual(protocol_error, verdict(error.StreamIdNotZero, .ping, 1));
    try testing.expectEqual(protocol_error, verdict(error.PaddingTooLong, .headers, 1));
    try testing.expectEqual(protocol_error, verdict(error.PromisedStreamIdInvalid, .push_promise, 1));
    try testing.expectEqual(protocol_error, verdict(error.WindowIncrementZero, .window_update, 0));
}

test "verdict makes a PRIORITY length error the one stream-level FRAME_SIZE_ERROR (RFC 9113 §6.3)" {
    const connection_size: Verdict = .{ .kind = .connection, .code = constants.error_frame_size_error };
    try testing.expectEqual(Verdict{ .kind = .stream, .code = constants.error_frame_size_error }, verdict(error.LengthInvalid, .priority, 1));
    try testing.expectEqual(connection_size, verdict(error.LengthInvalid, .data, 1));
    try testing.expectEqual(connection_size, verdict(error.LengthInvalid, .rst_stream, 1));
    try testing.expectEqual(connection_size, verdict(error.LengthInvalid, .headers, 1));
    try testing.expectEqual(connection_size, verdict(error.LengthInvalid, .ping, 0));
    try testing.expectEqual(connection_size, verdict(error.LengthInvalid, .goaway, 0));
    try testing.expectEqual(connection_size, verdict(error.LengthInvalid, .window_update, 1));
    try testing.expectEqual(connection_size, verdict(error.AckNotEmpty, .settings, 0));
}

test "verdict makes a zero increment a stream error on a stream and a connection error on stream 0 (RFC 9113 §6.9)" {
    try testing.expectEqual(Verdict{ .kind = .stream, .code = constants.error_protocol_error }, verdict(error.WindowIncrementZero, .window_update, 1));
    try testing.expectEqual(Verdict{ .kind = .connection, .code = constants.error_protocol_error }, verdict(error.WindowIncrementZero, .window_update, 0));
}

test {
    testing.refAllDecls(@This());
    _ = frame_header;
    _ = frame_padding;
    _ = frame_data;
    _ = frame_headers;
    _ = frame_control;
    _ = frame_settings;
}
