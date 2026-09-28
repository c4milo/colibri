//! The QUIC events of quic-events §3 that `quic` logs, as plain structs whose field names and
//! enum tag names are the draft's own spellings. `fields` writes any of them: a null field is
//! left out, a `Duration` is milliseconds, `Hex` is a hexstring, and a nested struct is an
//! object. `packet_sent` and `packet_received` have frames, which `quic` writes itself with
//! `quic_frame` between `begin_frames` and `end_frames`.
const std = @import("std");
const assert = std.debug.assert;
const json_module = @import("json.zig");
const Json = json_module.Json;
const quic_frame = @import("quic_frame.zig");
const VantagePoint = @import("log.zig").VantagePoint;

pub const Error = json_module.Error;

/// The names of the events (quic-events §3).
pub const name = struct {
    pub const version_information = "quic:version_information";
    pub const alpn_information = "quic:alpn_information";
    pub const parameters_set = "quic:parameters_set";
    pub const packet_sent = "quic:packet_sent";
    pub const packet_received = "quic:packet_received";
    pub const packet_dropped = "quic:packet_dropped";
    pub const packet_lost = "quic:packet_lost";
    pub const recovery_metrics_updated = "quic:recovery_metrics_updated";
    pub const connection_state_updated = "quic:connection_state_updated";
    pub const connection_closed = "quic:connection_closed";
};

/// A time span in nanoseconds, which `fields` writes as milliseconds (main schema §1.2).
pub const Duration = struct { ns: u64 };

/// Octets that `fields` writes as a hexstring (main schema §1.2).
pub const Hex = struct { octets: []const u8 };

/// Quic-events §8.6.
pub const PacketType = enum { initial, handshake, @"0RTT", @"1RTT", retry, version_negotiation, stateless_reset, unknown };

/// Quic-events §8.8. A 1-RTT packet's destination connection ID is left out, as §8.8 allows,
/// because the connection logs its connection IDs elsewhere.
pub const PacketHeader = struct {
    packet_type: PacketType,
    packet_number: ?u64 = null,
    version: ?Hex = null,
    scid: ?Hex = null,
    dcid: ?Hex = null,
};

/// Main schema §10's `RawInfo`, the lengths alone.
pub const Raw = struct {
    length: ?u64 = null,
    payload_length: ?u64 = null,
};

/// Quic-events §8.3.
pub const Initiator = enum { local, remote };

/// Quic-events §5.5's triggers of a sent packet.
pub const SendTrigger = enum { retransmit_reordered, retransmit_timeout, pto_probe, retransmit_crypto, cc_bandwidth_probe };

/// Quic-events §5.7.
pub const PacketDropped = struct {
    header: ?PacketHeader = null,
    raw: ?Raw = null,
    trigger: enum { internal_error, rejected, unsupported, invalid, duplicate, connection_unknown, decryption_failure, key_unavailable, general },

    pub fn write(event: PacketDropped, json: *Json) Error!void {
        try fields(json, event);
    }
};

/// Quic-events §7.4's causes of a loss.
pub const LossTrigger = enum { reordering_threshold, time_threshold, pto_expired };

/// Quic-events §7.4. The trigger is left out when the loss has more than one possible cause.
pub const PacketLost = struct {
    header: PacketHeader,
    trigger: ?LossTrigger = null,

    pub fn write(event: PacketLost, json: *Json) Error!void {
        try fields(json, event);
    }
};

/// Quic-events §7.2. `quic` logs one when a value changed since the last one it logged.
pub const RecoveryMetricsUpdated = struct {
    min_rtt: ?Duration = null,
    smoothed_rtt: ?Duration = null,
    latest_rtt: ?Duration = null,
    rtt_variance: ?Duration = null,
    pto_count: ?u16 = null,
    congestion_window: ?u64 = null,
    bytes_in_flight: ?u64 = null,
    ssthresh: ?u64 = null,

    pub fn write(event: RecoveryMetricsUpdated, json: *Json) Error!void {
        try fields(json, event);
    }
};

/// Quic-events §4.6's base and granular states.
pub const ConnectionState = enum { attempted, handshake_started, handshake_complete, handshake_confirmed, closing, draining, closed };

pub const ConnectionStateUpdated = struct {
    old: ?ConnectionState = null,
    new: ConnectionState,

    pub fn write(event: ConnectionStateUpdated, json: *Json) Error!void {
        try fields(json, event);
    }
};

/// Quic-events §4.3. A transport error is named as a CONNECTION_CLOSE frame names it, and an
/// application's is "unknown" with its code.
pub const ConnectionClosed = struct {
    initiator: Initiator,
    error_space: ?quic_frame.ErrorSpace = null,
    error_code: u64 = 0,
    trigger: enum { idle_timeout, application, @"error", version_mismatch, stateless_reset, aborted, unspecified },

    pub fn write(event: ConnectionClosed, json: *Json) Error!void {
        try json.field_string("initiator", @tagName(event.initiator));
        if (event.error_space) |space| switch (space) {
            .transport => try quic_frame.transport_error(json, "connection_error", event.error_code),
            .application => try quic_frame.application_error(json, "application_error", event.error_code),
        };
        try json.field_string("trigger", @tagName(event.trigger));
    }
};

/// Quic-events §5.1 from an endpoint that supports one version and chose it: a client logs it
/// when it starts, and a server once it took the client's first Initial.
pub const VersionInformation = struct {
    vantage_point: VantagePoint,
    version: Hex,

    pub fn write(event: VersionInformation, json: *Json) Error!void {
        try json.key(switch (event.vantage_point) {
            .client => "client_versions",
            .server => "server_versions",
        });
        try json.begin_array();
        try json.hexstring(event.version.octets);
        try json.end_array();
        try json.field_hexstring("chosen_version", event.version.octets);
    }
};

/// Quic-events §5.2's ALPNIdentifier, as octets (decision 102).
pub const AlpnIdentifier = struct { byte_value: Hex };

/// Quic-events §5.2, once the handshake chose a protocol.
pub const AlpnInformation = struct {
    chosen_alpn: AlpnIdentifier,

    pub fn write(event: AlpnInformation, json: *Json) Error!void {
        try fields(json, event);
    }
};

/// Quic-events §5.3, the transport parameters of RFC 9000 §18.2 that colibri sends and reads.
/// Each duration is the parameter's own value in milliseconds.
pub const ParametersSet = struct {
    initiator: Initiator,
    original_destination_connection_id: ?Hex = null,
    initial_source_connection_id: ?Hex = null,
    retry_source_connection_id: ?Hex = null,
    disable_active_migration: ?bool = null,
    max_idle_timeout: ?u64 = null,
    max_udp_payload_size: ?u64 = null,
    ack_delay_exponent: ?u64 = null,
    max_ack_delay: ?u64 = null,
    active_connection_id_limit: ?u64 = null,
    initial_max_data: ?u64 = null,
    initial_max_stream_data_bidi_local: ?u64 = null,
    initial_max_stream_data_bidi_remote: ?u64 = null,
    initial_max_stream_data_uni: ?u64 = null,
    initial_max_streams_bidi: ?u64 = null,
    initial_max_streams_uni: ?u64 = null,

    pub fn write(event: ParametersSet, json: *Json) Error!void {
        try fields(json, event);
    }
};

/// Opens the `frames` array of a `packet_sent` or `packet_received` event (quic-events §5.5).
pub fn begin_frames(json: *Json) Error!void {
    try json.key("frames");
    try json.begin_array();
}

pub fn end_frames(json: *Json) Error!void {
    try json.end_array();
}

/// Each field of the struct `value` that is not null, under its own name.
pub fn fields(json: *Json, value: anytype) Error!void {
    const Value = @TypeOf(value);
    comptime assert(@typeInfo(Value) == .@"struct");
    inline for (@typeInfo(Value).@"struct".fields) |member| {
        try field(json, member.name, @field(value, member.name));
    }
}

/// One member named `member_name` whose value is `value`, or nothing when `value` is null.
pub fn field(json: *Json, comptime member_name: []const u8, value: anytype) Error!void {
    const Value = @TypeOf(value);
    switch (@typeInfo(Value)) {
        .optional => if (value) |present| try field(json, member_name, present),
        .bool => try json.field_boolean(member_name, value),
        .int => try json.field_unsigned(member_name, value),
        .@"enum" => try json.field_string(member_name, @tagName(value)),
        .@"struct" => try struct_field(json, member_name, value),
        else => @compileError("qlog writes no " ++ @typeName(Value)),
    }
}

fn struct_field(json: *Json, comptime member_name: []const u8, value: anytype) Error!void {
    const Value = @TypeOf(value);
    if (Value == Duration) return json.field_milliseconds(member_name, value.ns);
    if (Value == Hex) return json.field_hexstring(member_name, value.octets);
    try json.key(member_name);
    try json.begin_object();
    try fields(json, value);
    try json.end_object();
}

const testing = std.testing;

/// Room for the longest event a test writes.
const test_buffer_len = 512;

fn expect_event(expected: []const u8, event: anytype) !void {
    var buffer: [test_buffer_len]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try event.write(&json);
    try json.end_object();
    try testing.expectEqualStrings(expected, json.written());
}

test "a lost packet's header and trigger, with the draft's packet type names" {
    try expect_event("{\"header\":{\"packet_type\":\"1RTT\",\"packet_number\":7},\"trigger\":\"time_threshold\"}", PacketLost{
        .header = .{ .packet_type = .@"1RTT", .packet_number = 7 },
        .trigger = .time_threshold,
    });
    try expect_event("{\"header\":{\"packet_type\":\"0RTT\"},\"trigger\":\"pto_expired\"}", PacketLost{
        .header = .{ .packet_type = .@"0RTT" },
        .trigger = .pto_expired,
    });
    try expect_event("{\"header\":{\"packet_type\":\"handshake\",\"packet_number\":3}}", PacketLost{
        .header = .{ .packet_type = .handshake, .packet_number = 3 },
    });
}

test "recovery metrics write only what is present, and durations in milliseconds" {
    try expect_event("{\"smoothed_rtt\":33.333,\"pto_count\":2,\"bytes_in_flight\":1200}", RecoveryMetricsUpdated{
        .smoothed_rtt = .{ .ns = 33_333_333 },
        .pto_count = 2,
        .bytes_in_flight = 1200,
    });
}

test "a long header carries its version and connection IDs as hexstrings" {
    var buffer: [256]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try field(&json, "header", PacketHeader{
        .packet_type = .initial,
        .packet_number = 0,
        .version = .{ .octets = &.{ 0, 0, 0, 1 } },
        .scid = .{ .octets = &.{0xab} },
        .dcid = .{ .octets = &.{ 0xcd, 0xef } },
    });
    try json.end_object();
    try testing.expectEqualStrings("{\"header\":{\"packet_type\":\"initial\",\"packet_number\":0,\"version\":\"00000001\"," ++
        "\"scid\":\"ab\",\"dcid\":\"cdef\"}}", json.written());
}

test "a closed connection names a transport error, and an application's as unknown" {
    try expect_event("{\"initiator\":\"local\",\"connection_error\":\"flow_control_error\",\"trigger\":\"error\"}", ConnectionClosed{
        .initiator = .local,
        .error_space = .transport,
        .error_code = 0x03,
        .trigger = .@"error",
    });
    try expect_event("{\"initiator\":\"remote\",\"application_error\":\"unknown\",\"error_code\":256,\"trigger\":\"application\"}", ConnectionClosed{
        .initiator = .remote,
        .error_space = .application,
        .error_code = 0x100,
        .trigger = .application,
    });
    try expect_event("{\"initiator\":\"local\",\"trigger\":\"idle_timeout\"}", ConnectionClosed{
        .initiator = .local,
        .trigger = .idle_timeout,
    });
}

test "a version and a protocol, each as a hexstring" {
    try expect_event("{\"client_versions\":[\"00000001\"],\"chosen_version\":\"00000001\"}", VersionInformation{
        .vantage_point = .client,
        .version = .{ .octets = &.{ 0, 0, 0, 1 } },
    });
    try expect_event("{\"server_versions\":[\"00000001\"],\"chosen_version\":\"00000001\"}", VersionInformation{
        .vantage_point = .server,
        .version = .{ .octets = &.{ 0, 0, 0, 1 } },
    });
    try expect_event("{\"chosen_alpn\":{\"byte_value\":\"6833\"}}", AlpnInformation{
        .chosen_alpn = .{ .byte_value = .{ .octets = "h3" } },
    });
}

test "state updates, dropped packets and parameters" {
    try expect_event("{\"old\":\"attempted\",\"new\":\"handshake_complete\"}", ConnectionStateUpdated{ .old = .attempted, .new = .handshake_complete });
    try expect_event("{\"header\":{\"packet_type\":\"handshake\"},\"raw\":{\"length\":1200},\"trigger\":\"key_unavailable\"}", PacketDropped{
        .header = .{ .packet_type = .handshake },
        .raw = .{ .length = 1200 },
        .trigger = .key_unavailable,
    });
    try expect_event("{\"initiator\":\"remote\",\"initial_source_connection_id\":\"0102\",\"disable_active_migration\":true," ++
        "\"max_idle_timeout\":30000,\"initial_max_data\":65536}", ParametersSet{
        .initiator = .remote,
        .initial_source_connection_id = .{ .octets = &.{ 1, 2 } },
        .disable_active_migration = true,
        .max_idle_timeout = 30_000,
        .initial_max_data = 65_536,
    });
}
