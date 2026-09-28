//! The HTTP/3 events of h3-events §3 that `h3` logs, and the frames of §4.2 they carry. `h3`
//! passes plain values, so this module knows no type of `h3`'s: a frame event is its stream ID and
//! one frame, written between `begin_frame` and `end_frame`.
//!
//! A field line's name and value are text when every octet is printable ASCII, and hexstrings
//! otherwise, which is h3-events §4.2.2's rule (decision 102 as amended).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const json_module = @import("json.zig");
const Json = json_module.Json;
const quic_event = @import("quic_event.zig");

pub const Error = json_module.Error;

/// The names of the events (h3-events §3).
pub const name = struct {
    pub const parameters_set = "http3:parameters_set";
    pub const stream_type_set = "http3:stream_type_set";
    pub const frame_created = "http3:frame_created";
    pub const frame_parsed = "http3:frame_parsed";
};

/// H3-events §3.1, the settings of RFC 9114 §7.2.4.1 and RFC 9204 §5 that colibri sends and reads.
pub const ParametersSet = struct {
    initiator: quic_event.Initiator,
    max_field_section_size: ?u64 = null,
    max_table_capacity: ?u64 = null,
    blocked_streams_count: ?u64 = null,

    pub fn write(event: ParametersSet, json: *Json) Error!void {
        try quic_event.fields(json, event);
    }
};

/// H3-events §3.3's stream types.
pub const StreamType = enum { request, control, push, reserved, unknown, qpack_encode, qpack_decode };

/// H3-events §3.3.
pub const StreamTypeSet = struct {
    initiator: quic_event.Initiator,
    stream_id: u64,
    stream_type: StreamType,
    /// The type's number, only when `stream_type` is unknown.
    stream_type_bytes: ?u64 = null,
    /// The push ID, only when `stream_type` is push.
    associated_push_id: ?u64 = null,

    pub fn write(event: StreamTypeSet, json: *Json) Error!void {
        try quic_event.fields(json, event);
    }
};

/// H3-events §4.2.4's names of the settings RFC 9114 §7.2.4.1, RFC 9204 §5, RFC 9220 §3 and
/// RFC 9297 §2.1.1 define, and of the ones reserved or unknown.
pub const SettingName = enum {
    settings_qpack_max_table_capacity,
    settings_max_field_section_size,
    settings_qpack_blocked_streams,
    settings_enable_connect_protocol,
    settings_h3_datagram,
    reserved,
    unknown,
};

/// Opens the `frame` of a frame_created or frame_parsed event on `stream_id` (h3-events §3.5,
/// §3.6), whose type is `frame_type`. The frame's own members follow, and `end_frame` closes it.
pub fn begin_frame(json: *Json, stream_id: u64, frame_type: []const u8) Error!void {
    try json.field_unsigned("stream_id", stream_id);
    try json.key("frame");
    try json.begin_object();
    try json.field_string("frame_type", frame_type);
}

/// Closes the frame, whose payload is `payload_len` octets long, which main schema §10's RawInfo
/// holds.
pub fn end_frame(json: *Json, payload_len: u64) Error!void {
    try json.key("raw");
    try json.begin_object();
    try json.field_unsigned("payload_length", payload_len);
    try json.end_object();
    try json.end_object();
}

/// A reserved frame type (RFC 9114 §7.2.8) or an unknown one (§9), as its number (h3-events
/// §4.2.8, §4.2.9).
pub fn frame_type_bytes(json: *Json, frame_type: u64) Error!void {
    try json.field_unsigned("frame_type_bytes", frame_type);
}

/// A GOAWAY's identifier (h3-events §4.2.6), and the push ID of MAX_PUSH_ID or CANCEL_PUSH
/// (§4.2.7, §4.2.3).
pub fn goaway_id(json: *Json, id: u64) Error!void {
    try json.field_unsigned("id", id);
}

pub fn push_id(json: *Json, id: u64) Error!void {
    try json.field_unsigned("push_id", id);
}

/// Opens a SETTINGS frame's list (h3-events §4.2.4). `setting` writes each entry.
pub fn begin_settings(json: *Json) Error!void {
    try json.key("settings");
    try json.begin_array();
}

/// One setting. An unknown one carries its identifier, as §4.2.4 asks.
pub fn setting(json: *Json, setting_name: SettingName, identifier: u64, value: u64) Error!void {
    try json.begin_object();
    try json.field_string("name", @tagName(setting_name));
    if (setting_name == .unknown) try json.field_unsigned("name_bytes", identifier);
    try json.field_unsigned("value", value);
    try json.end_object();
}

pub fn end_settings(json: *Json) Error!void {
    try json.end_array();
}

/// Opens a HEADERS frame's field lines (h3-events §4.2.2). `field_line` writes each one.
pub fn begin_headers(json: *Json) Error!void {
    try json.key("headers");
    try json.begin_array();
}

/// One field line: its name, and its value, each as text when every octet is printable ASCII and
/// as a hexstring otherwise (h3-events §4.2.2).
pub fn field_line(json: *Json, field_name: []const u8, value: []const u8) Error!void {
    try json.begin_object();
    try text_or_octets(json, "name", "name_bytes", field_name);
    try text_or_octets(json, "value", "value_bytes", value);
    try json.end_object();
}

pub fn end_headers(json: *Json) Error!void {
    try json.end_array();
}

fn text_or_octets(json: *Json, comptime text_key: []const u8, comptime octets_key: []const u8, octets: []const u8) Error!void {
    if (is_printable(octets)) return json.field_string(text_key, octets);
    try json.field_hexstring(octets_key, octets);
}

/// Whether every octet is printable ASCII, which JSON text holds as it is, `"` and `\` escaped.
fn is_printable(octets: []const u8) bool {
    // Bounded by the octets.
    for (octets) |octet| {
        if (octet < constants.printable_first or octet > constants.printable_last) return false;
    }
    return true;
}

const testing = std.testing;

/// Room for the longest event a test writes. Test-only.
const test_buffer_len = 512;

test "a HEADERS frame's lines are text when printable, and octets otherwise" {
    var buffer: [test_buffer_len]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try begin_frame(&json, 0, "headers");
    try begin_headers(&json);
    try field_line(&json, ":status", "200");
    // A value a peer sent with an octet past ASCII, and one with a control octet.
    try field_line(&json, "x-tag", &.{ 'a', 0xe9 });
    try field_line(&json, "x-tab", "a\tb");
    try end_headers(&json);
    try end_frame(&json, 12);
    try json.end_object();
    try testing.expectEqualStrings("{\"stream_id\":0,\"frame\":{\"frame_type\":\"headers\",\"headers\":[" ++
        "{\"name\":\":status\",\"value\":\"200\"}," ++
        "{\"name\":\"x-tag\",\"value_bytes\":\"61e9\"}," ++
        "{\"name\":\"x-tab\",\"value_bytes\":\"610962\"}]," ++
        "\"raw\":{\"payload_length\":12}}}", json.written());
}

test "a SETTINGS frame names each setting, and an unknown one carries its identifier" {
    var buffer: [test_buffer_len]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try begin_frame(&json, 3, "settings");
    try begin_settings(&json);
    try setting(&json, .settings_max_field_section_size, 0x06, 65_536);
    try setting(&json, .reserved, 0x21, 0);
    try setting(&json, .unknown, 0x4242, 1);
    try end_settings(&json);
    try end_frame(&json, 11);
    try json.end_object();
    try testing.expectEqualStrings("{\"stream_id\":3,\"frame\":{\"frame_type\":\"settings\",\"settings\":[" ++
        "{\"name\":\"settings_max_field_section_size\",\"value\":65536}," ++
        "{\"name\":\"reserved\",\"value\":0}," ++
        "{\"name\":\"unknown\",\"name_bytes\":16962,\"value\":1}]," ++
        "\"raw\":{\"payload_length\":11}}}", json.written());
}

test "a GOAWAY names its identifier, and an unknown frame its type" {
    var buffer: [test_buffer_len]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try begin_frame(&json, 3, "goaway");
    try goaway_id(&json, 8);
    try end_frame(&json, 1);
    try json.end_object();
    try testing.expectEqualStrings("{\"stream_id\":3,\"frame\":{\"frame_type\":\"goaway\",\"id\":8,\"raw\":{\"payload_length\":1}}}", json.written());
    json = Json.init(&buffer);
    try json.begin_object();
    try begin_frame(&json, 4, "unknown");
    try frame_type_bytes(&json, 0x2f);
    try end_frame(&json, 0);
    try json.end_object();
    try testing.expectEqualStrings("{\"stream_id\":4,\"frame\":{\"frame_type\":\"unknown\",\"frame_type_bytes\":47,\"raw\":{\"payload_length\":0}}}", json.written());
}

test "settings and stream types, under the draft's names" {
    var buffer: [test_buffer_len]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try (ParametersSet{ .initiator = .remote, .max_field_section_size = 16_384, .blocked_streams_count = 0 }).write(&json);
    try json.end_object();
    try testing.expectEqualStrings("{\"initiator\":\"remote\",\"max_field_section_size\":16384,\"blocked_streams_count\":0}", json.written());
    json = Json.init(&buffer);
    try json.begin_object();
    try (StreamTypeSet{ .initiator = .local, .stream_id = 2, .stream_type = .qpack_encode }).write(&json);
    try json.end_object();
    try testing.expectEqualStrings("{\"initiator\":\"local\",\"stream_id\":2,\"stream_type\":\"qpack_encode\"}", json.written());
    json = Json.init(&buffer);
    try json.begin_object();
    try (StreamTypeSet{ .initiator = .remote, .stream_id = 7, .stream_type = .unknown, .stream_type_bytes = 0x54 }).write(&json);
    try json.end_object();
    try testing.expectEqualStrings("{\"initiator\":\"remote\",\"stream_id\":7,\"stream_type\":\"unknown\",\"stream_type_bytes\":84}", json.written());
}
