//! The qlog an h3 connection writes when its caller gave it a log (decision 102, design §8 step
//! 18d): the HTTP/3 events of h3-events §3. Every function here returns at once when the
//! connection holds no log.
//!
//! Each call of the connection that writes or reads a frame takes the instant (decision 102 as
//! amended) and keeps it in `Connection.now_ns` while it runs, and these events carry it. A log
//! reads the connection and never changes it: a SETTINGS frame is logged from its octets, read a
//! second time, and a HEADERS frame from the field section colibri encoded or decoded.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const qlog = @import("qlog");
const wire = @import("wire");
const constants = @import("../constants.zig");
const frame = @import("../frame.zig");
const stream = @import("../stream.zig");
const connection_module = @import("connection.zig");

const Json = qlog.Json;
const Reader = core.Reader;
const Connection = connection_module.Connection;
const FieldSection = http.FieldSection;
const Initiator = qlog.quic_event.Initiator;
const h3_event = qlog.h3_event;

pub const Log = qlog.Log;

/// Whether colibri wrote a frame or read it (h3-events §3.5, §3.6).
pub const Direction = enum { created, parsed };

/// One frame of a frame_created or frame_parsed event (h3-events §4.2), with its payload's length.
pub const Frame = union(enum) {
    data: u64,
    headers: Headers,
    /// The payload, whose settings are read from it again.
    settings: []const u8,
    goaway: Identified,
    max_push_id: Identified,
    cancel_push: Identified,
    /// A reserved type (RFC 9114 §7.2.8) or an unknown one (§9).
    other: Other,

    pub const Headers = struct { section: *const FieldSection, payload_len: u64 };
    pub const Identified = struct { id: u64, payload_len: u64 };
    pub const Other = struct { frame_type: u64, payload_len: u64 };
};

/// H3-events §3.5 or §3.6 for `value` on `stream_id`.
pub fn frame_event(connection: *const Connection, direction: Direction, stream_id: u64, value: Frame) void {
    const log = connection.options.qlog orelse return;
    const event_name = switch (direction) {
        .created => h3_event.name.frame_created,
        .parsed => h3_event.name.frame_parsed,
    };
    log.event(event_name, connection.now_ns, FrameEvent{ .stream_id = stream_id, .frame = value });
}

/// H3-events §3.6 for a control frame `frame.read_payload` read out of `payload`.
pub fn control_frame_parsed(connection: *const Connection, stream_id: u64, found: frame.Payload, payload: []const u8) void {
    const payload_len: u64 = payload.len;
    frame_event(connection, .parsed, stream_id, switch (found) {
        .settings => .{ .settings = payload },
        .goaway => |id| .{ .goaway = .{ .id = id, .payload_len = payload_len } },
        .max_push_id => |id| .{ .max_push_id = .{ .id = id, .payload_len = payload_len } },
        .cancel_push => |id| .{ .cancel_push = .{ .id = id, .payload_len = payload_len } },
        // `connection_peer` reads neither on the control stream (RFC 9114 §7.2.5, §9).
        .push_promise, .unknown => unreachable,
    });
}

/// H3-events §3.3 for the stream `stream_id`, of `kind`, opened by `initiator`.
pub fn stream_type_set(connection: *const Connection, initiator: Initiator, stream_id: u64, kind: stream.Kind) void {
    const log = connection.options.qlog orelse return;
    var event: h3_event.StreamTypeSet = .{ .initiator = initiator, .stream_id = stream_id, .stream_type = .unknown };
    switch (kind) {
        .control => event.stream_type = .control,
        .qpack_encoder => event.stream_type = .qpack_encode,
        .qpack_decoder => event.stream_type = .qpack_decode,
        .push => |push_id| {
            event.stream_type = .push;
            event.associated_push_id = push_id;
        },
        // RFC 9114 §6.2.3: a reserved type is one the grease formula gives.
        .unknown => |value| if (constants.is_reserved(value)) {
            event.stream_type = .reserved;
        } else {
            event.stream_type_bytes = value;
        },
    }
    log.event(h3_event.name.stream_type_set, connection.now_ns, event);
}

/// H3-events §3.3 for a request stream (RFC 9114 §6.1), which a client opens.
pub fn request_stream_set(connection: *const Connection, initiator: Initiator, stream_id: u64) void {
    const log = connection.options.qlog orelse return;
    log.event(h3_event.name.stream_type_set, connection.now_ns, h3_event.StreamTypeSet{
        .initiator = initiator,
        .stream_id = stream_id,
        .stream_type = .request,
    });
}

/// H3-events §3.1 for the settings colibri sent or the peer's.
pub fn parameters_set(connection: *const Connection, initiator: Initiator, settings: frame.Settings) void {
    const log = connection.options.qlog orelse return;
    log.event(h3_event.name.parameters_set, connection.now_ns, h3_event.ParametersSet{
        .initiator = initiator,
        .max_field_section_size = settings.max_field_section_size,
        .max_table_capacity = settings.qpack_max_table_capacity,
        .blocked_streams_count = settings.qpack_blocked_streams,
    });
}

const FrameEvent = struct {
    stream_id: u64,
    frame: Frame,

    pub fn write(event: FrameEvent, json: *Json) qlog.json.Error!void {
        switch (event.frame) {
            .data => |payload_len| try write_empty(json, event.stream_id, "data", payload_len),
            .headers => |headers| try write_headers(json, event.stream_id, headers),
            .settings => |payload| try write_settings(json, event.stream_id, payload),
            .goaway => |held| try write_identified(json, event.stream_id, "goaway", "id", held),
            .max_push_id => |held| try write_identified(json, event.stream_id, "max_push_id", "push_id", held),
            .cancel_push => |held| try write_identified(json, event.stream_id, "cancel_push", "push_id", held),
            .other => |other| try write_other(json, event.stream_id, other),
        }
    }
};

fn write_empty(json: *Json, stream_id: u64, frame_type: []const u8, payload_len: u64) qlog.json.Error!void {
    try h3_event.begin_frame(json, stream_id, frame_type);
    try h3_event.end_frame(json, payload_len);
}

fn write_identified(
    json: *Json,
    stream_id: u64,
    frame_type: []const u8,
    comptime id_key: []const u8,
    held: Frame.Identified,
) qlog.json.Error!void {
    try h3_event.begin_frame(json, stream_id, frame_type);
    try json.field_unsigned(id_key, held.id);
    try h3_event.end_frame(json, held.payload_len);
}

fn write_other(json: *Json, stream_id: u64, other: Frame.Other) qlog.json.Error!void {
    // RFC 9114 §7.2.8: a reserved type is one the grease formula gives, and h3-events §4.2.8
    // names it apart from an unknown one.
    try h3_event.begin_frame(json, stream_id, if (constants.is_reserved(other.frame_type)) "reserved" else "unknown");
    try h3_event.frame_type_bytes(json, other.frame_type);
    try h3_event.end_frame(json, other.payload_len);
}

fn write_headers(json: *Json, stream_id: u64, headers: Frame.Headers) qlog.json.Error!void {
    try h3_event.begin_frame(json, stream_id, "headers");
    try h3_event.begin_headers(json);
    var lines = headers.section.iterator();
    // Bounded by the section's lines, at most `field_count_max`.
    while (lines.next()) |line| try h3_event.field_line(json, line.name, line.value);
    try h3_event.end_headers(json);
    try h3_event.end_frame(json, headers.payload_len);
}

/// Each setting of a SETTINGS frame's payload (RFC 9114 §7.2.4), read again. A payload that
/// stops parsing ends the list: `frame.read_payload` refused it, or colibri wrote it.
fn write_settings(json: *Json, stream_id: u64, payload: []const u8) qlog.json.Error!void {
    try h3_event.begin_frame(json, stream_id, "settings");
    try h3_event.begin_settings(json);
    var reader = Reader.init(payload);
    // Bounded by the payload: each setting takes two octets at least.
    for (0..payload.len) |_| {
        if (reader.remaining_len() == 0) break;
        const identifier = (wire.varint.decode(&reader) catch break).value;
        const value = (wire.varint.decode(&reader) catch break).value;
        try h3_event.setting(json, setting_name(identifier), identifier, value);
    }
    try h3_event.end_settings(json);
    try h3_event.end_frame(json, payload.len);
}

/// H3-events §4.2.4's name for the setting `identifier`: the three colibri reads, a reserved one
/// (RFC 9114 §7.2.4.1), or unknown.
fn setting_name(identifier: u64) h3_event.SettingName {
    return switch (identifier) {
        constants.setting_qpack_max_table_capacity => .settings_qpack_max_table_capacity,
        constants.setting_max_field_section_size => .settings_max_field_section_size,
        constants.setting_qpack_blocked_streams => .settings_qpack_blocked_streams,
        else => if (constants.is_reserved(identifier)) .reserved else .unknown,
    };
}

test {
    _ = @import("connection_qlog_test.zig");
}
