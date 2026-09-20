//! The transport parameters of RFC 9000 §7.4 and §18, which an endpoint sends inside the TLS
//! handshake and which say what it will accept for the life of the connection.
//!
//! This file holds the values, their defaults and the writer; `transport_parameters_read.zig`
//! holds the reader. Every value is stored inline, so a `Parameters` is one struct the caller
//! owns and nothing here allocates ([decision 35](../../docs/decisions.md)).
//!
//! **A default is not an absence.** RFC 9000 §18.2 gives most parameters a value that applies
//! when the peer sends none, and three of those defaults are not zero: `max_udp_payload_size` is
//! 65527, `ack_delay_exponent` is 3 and `max_ack_delay` is 25 milliseconds, with
//! `active_connection_id_limit` at 2. So `Parameters.initial()` is what a peer that sent an empty
//! extension means, and the reader starts from it rather than from zeros.
//!
//! **What colibri does not use.** `preferred_address` (0x0d) is read past rather than kept:
//! [decision 21](../../docs/decisions.md) refuses connection migration in both directions, and
//! §9.6 makes using a preferred address a MAY. Its octets are skipped by the length every
//! parameter carries, so a server that sends one is not refused for it.
//!
//! **What is not checked.** A repeated parameter whose identifier colibri does not know goes
//! undetected, although §7.4 forbids a repeat of any parameter. Detecting it would mean keeping
//! every identifier a peer sent, which is storage proportional to what the peer chose to send;
//! the ACK range walk of §19.3.1 refuses the same trade. An unknown parameter has no semantics to
//! conflict with (§18.1), so the repeat changes nothing colibri would have done.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const crypto = @import("crypto");
const constants = @import("constants.zig");

const Writer = core.Writer;

/// Which endpoint sent a set of parameters. Three parameters are the server's alone (§18.2).
pub const Role = crypto.suite.Role;

/// Why a peer's parameters are refused. Every one is a connection error of
/// TRANSPORT_PARAMETER_ERROR (RFC 9000 §7.4), which `error_code.transport_parameter_error` names.
pub const Error = error{
    /// RFC 9000 §7.4: "An endpoint MUST treat receipt of a transport parameter with an invalid
    /// value as a connection error of type TRANSPORT_PARAMETER_ERROR."
    ParameterInvalid,
    /// RFC 9000 §7.4: an endpoint must not send a parameter more than once in one extension.
    ParameterRepeated,
    /// RFC 9000 §18.2: "A client MUST NOT include any server-only transport parameter."
    ParameterServerOnly,
    /// The octets ended inside a parameter, which is a value that cannot be read (§7.4).
    ParameterTruncated,
};

/// The identifiers RFC 9000 §18.2 assigns. The enum is not exhaustive: §18.1 reserves a family
/// of identifiers to exercise the rule that an unknown parameter is ignored, and a later
/// extension may define more.
pub const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,
};

/// A connection ID a parameter carries, stored inline. RFC 9000 §18.2 gives three parameters this
/// shape, and §17.2 bounds one at `connection_id_len_max`.
pub const ConnectionId = struct {
    octets: [constants.connection_id_len_max]u8,
    len: u8,

    pub fn of(source: []const u8) ConnectionId {
        assert(source.len <= constants.connection_id_len_max);
        var id: ConnectionId = .{ .octets = @splat(0), .len = @intCast(source.len) };
        @memcpy(id.octets[0..source.len], source);
        return id;
    }

    pub fn slice(id: *const ConnectionId) []const u8 {
        return id.octets[0..id.len];
    }
};

/// RFC 9000 §18.2: a stateless reset token is "a sequence of 16 bytes".
pub const stateless_reset_token_len: usize = 16;

/// RFC 9000 §18.2's defaults for the parameters whose absent value is not zero.
pub const default_max_udp_payload_size: u64 = 65527;
pub const default_ack_delay_exponent: u64 = 3;
pub const default_max_ack_delay_ms: u64 = 25;
pub const default_active_connection_id_limit: u64 = 2;

/// RFC 9000 §18.2's bounds, each stated as a value that is invalid.
pub const max_udp_payload_size_min: u64 = constants.datagram_len_min;

comptime {
    // `constants.max_ack_delay_default_ns` spells RFC 9000 §18.2's same 25 milliseconds in the
    // unit RFC 9002 counts in. Two spellings of one number, so they are held together here.
    assert(default_max_ack_delay_ms * constants.nanoseconds_per_millisecond ==
        constants.max_ack_delay_default_ns);
}
pub const ack_delay_exponent_max: u64 = 20;
/// RFC 9000 §18.2 states this bound as a power of two, so the exponent is named rather than the
/// product: "Values of 2^14 or greater are invalid."
pub const max_ack_delay_ms_exponent: u6 = 14;
pub const max_ack_delay_ms_max: u64 = @as(u64, 1) << max_ack_delay_ms_exponent;
pub const active_connection_id_limit_min: u64 = 2;

/// What one endpoint told the other it will accept (RFC 9000 §18.2).
pub const Parameters = struct {
    /// The Destination Connection ID of the client's first Initial, echoed by the server (0x00).
    original_destination_connection_id: ?ConnectionId,
    /// The Source Connection ID of the sender's own first packet (0x0f).
    initial_source_connection_id: ?ConnectionId,
    /// The Source Connection ID of a Retry the server sent, absent when it sent none (0x10).
    retry_source_connection_id: ?ConnectionId,
    /// The token §10.3 uses to reset the connection statelessly (0x02).
    stateless_reset_token: ?[stateless_reset_token_len]u8,
    /// Milliseconds of idleness after which the sender will close (0x01); 0 disables it.
    max_idle_timeout_ms: u64,
    /// The largest UDP payload the sender will process (0x03).
    max_udp_payload_size: u64,
    /// The connection-level flow control limit the sender starts with (0x04).
    initial_max_data: u64,
    /// The stream-level limit for streams the receiver of this opened, bidirectional (0x05).
    initial_max_stream_data_bidi_local: u64,
    /// The stream-level limit for streams the sender of this opened, bidirectional (0x06).
    initial_max_stream_data_bidi_remote: u64,
    /// The stream-level limit for unidirectional streams (0x07).
    initial_max_stream_data_uni: u64,
    /// Bidirectional streams the peer may open before a MAX_STREAMS frame (0x08).
    initial_max_streams_bidi: u64,
    /// Unidirectional streams the peer may open before a MAX_STREAMS frame (0x09).
    initial_max_streams_uni: u64,
    /// The exponent an ACK frame's Delay field is decoded with (0x0a).
    ack_delay_exponent: u64,
    /// Milliseconds the sender may hold an acknowledgment for (0x0b).
    max_ack_delay_ms: u64,
    /// Whether the sender refuses the peer moving to a new local address (0x0c, decision 21).
    disable_active_migration: bool,
    /// Connection IDs the sender will hold at once (0x0e).
    active_connection_id_limit: u64,

    /// What a peer that sent an empty extension means: every default of §18.2, which is zero for
    /// most and is not for four of them.
    pub fn initial() Parameters {
        return .{
            .original_destination_connection_id = null,
            .initial_source_connection_id = null,
            .retry_source_connection_id = null,
            .stateless_reset_token = null,
            .max_idle_timeout_ms = 0,
            .max_udp_payload_size = default_max_udp_payload_size,
            .initial_max_data = 0,
            .initial_max_stream_data_bidi_local = 0,
            .initial_max_stream_data_bidi_remote = 0,
            .initial_max_stream_data_uni = 0,
            .initial_max_streams_bidi = 0,
            .initial_max_streams_uni = 0,
            .ack_delay_exponent = default_ack_delay_exponent,
            .max_ack_delay_ms = default_max_ack_delay_ms,
            .disable_active_migration = false,
            .active_connection_id_limit = default_active_connection_id_limit,
        };
    }

    /// The bounds RFC 9000 §18.2 states as values that are invalid. It is the same check on both
    /// sides, so the reader runs it on what arrived and the writer asserts it on what it sends.
    pub fn valid(parameters: *const Parameters) bool {
        // RFC 9000 §18.2: for max_udp_payload_size, "Values below 1200 are invalid."
        if (parameters.max_udp_payload_size < max_udp_payload_size_min) return false;
        // RFC 9000 §18.2: for ack_delay_exponent, "Values above 20 are invalid."
        if (parameters.ack_delay_exponent > ack_delay_exponent_max) return false;
        // RFC 9000 §18.2: for max_ack_delay, "Values of 2^14 or greater are invalid."
        if (parameters.max_ack_delay_ms >= max_ack_delay_ms_max) return false;
        // RFC 9000 §18.2: an endpoint receiving an active_connection_id_limit below 2 must close
        // the connection with TRANSPORT_PARAMETER_ERROR.
        if (parameters.active_connection_id_limit < active_connection_id_limit_min) return false;
        // RFC 9000 §4.6: a limit above 2^60 is invalid, which §19.11 states for MAX_STREAMS and
        // §18.2 makes these two parameters equivalent to.
        if (parameters.initial_max_streams_bidi > constants.max_streams_max) return false;
        if (parameters.initial_max_streams_uni > constants.max_streams_max) return false;
        return true;
    }
};

/// True for a parameter RFC 9000 §18.2 permits a server alone to send.
pub fn server_only(id: Id) bool {
    return switch (id) {
        // RFC 9000 §18.2: "A client MUST NOT include any server-only transport parameter:
        // original_destination_connection_id, preferred_address, retry_source_connection_id, or
        // stateless_reset_token."
        .original_destination_connection_id,
        .preferred_address,
        .retry_source_connection_id,
        .stateless_reset_token,
        => true,
        else => false,
    };
}

/// Writes `parameters` as the sequence RFC 9000 §18 defines: each one an identifier, a length and
/// a value, all three variable-length where §18 makes them so.
pub fn write(writer: *Writer, parameters: *const Parameters, sender: Role) core.writer.Error!void {
    assert(parameters.valid());
    assert(sender == .server or parameters.original_destination_connection_id == null);
    assert(sender == .server or parameters.retry_source_connection_id == null);
    assert(sender == .server or parameters.stateless_reset_token == null);
    try write_connection_ids(writer, parameters);
    try write_integers(writer, parameters);
    if (parameters.stateless_reset_token) |token| {
        try write_octets(writer, .stateless_reset_token, &token);
    }
    // RFC 9000 §18.2: disable_active_migration has a zero-length value, so its presence is the
    // whole of it (decision 21).
    if (parameters.disable_active_migration) {
        try write_octets(writer, .disable_active_migration, &.{});
    }
}

fn write_connection_ids(writer: *Writer, parameters: *const Parameters) core.writer.Error!void {
    if (parameters.original_destination_connection_id) |id| {
        try write_octets(writer, .original_destination_connection_id, id.slice());
    }
    if (parameters.initial_source_connection_id) |id| {
        try write_octets(writer, .initial_source_connection_id, id.slice());
    }
    if (parameters.retry_source_connection_id) |id| {
        try write_octets(writer, .retry_source_connection_id, id.slice());
    }
}

/// The integer parameters. Each is written only when it differs from the default §18.2 gives it,
/// because a parameter the peer does not send means that default and the octets cost nothing.
fn write_integers(writer: *Writer, parameters: *const Parameters) core.writer.Error!void {
    const defaults = Parameters.initial();
    const each = [_]struct { id: Id, value: u64, default: u64 }{
        .{ .id = .max_idle_timeout, .value = parameters.max_idle_timeout_ms, .default = defaults.max_idle_timeout_ms },
        .{ .id = .max_udp_payload_size, .value = parameters.max_udp_payload_size, .default = defaults.max_udp_payload_size },
        .{ .id = .initial_max_data, .value = parameters.initial_max_data, .default = defaults.initial_max_data },
        .{ .id = .initial_max_stream_data_bidi_local, .value = parameters.initial_max_stream_data_bidi_local, .default = defaults.initial_max_stream_data_bidi_local },
        .{ .id = .initial_max_stream_data_bidi_remote, .value = parameters.initial_max_stream_data_bidi_remote, .default = defaults.initial_max_stream_data_bidi_remote },
        .{ .id = .initial_max_stream_data_uni, .value = parameters.initial_max_stream_data_uni, .default = defaults.initial_max_stream_data_uni },
        .{ .id = .initial_max_streams_bidi, .value = parameters.initial_max_streams_bidi, .default = defaults.initial_max_streams_bidi },
        .{ .id = .initial_max_streams_uni, .value = parameters.initial_max_streams_uni, .default = defaults.initial_max_streams_uni },
        .{ .id = .ack_delay_exponent, .value = parameters.ack_delay_exponent, .default = defaults.ack_delay_exponent },
        .{ .id = .max_ack_delay, .value = parameters.max_ack_delay_ms, .default = defaults.max_ack_delay_ms },
        .{ .id = .active_connection_id_limit, .value = parameters.active_connection_id_limit, .default = defaults.active_connection_id_limit },
    };
    for (each) |one| {
        if (one.value == one.default) continue;
        try write_integer(writer, one.id, one.value);
    }
}

/// One parameter whose value is a variable-length integer (RFC 9000 §18).
fn write_integer(writer: *Writer, id: Id, value: u64) core.writer.Error!void {
    try wire.varint.encode(writer, @intFromEnum(id));
    try wire.varint.encode(writer, wire.varint.encoded_len_minimal(value));
    try wire.varint.encode(writer, value);
}

/// One parameter whose value is a run of octets (RFC 9000 §18).
fn write_octets(writer: *Writer, id: Id, octets: []const u8) core.writer.Error!void {
    try wire.varint.encode(writer, @intFromEnum(id));
    try wire.varint.encode(writer, octets.len);
    try writer.write_bytes(octets);
}

test {
    _ = @import("transport_parameters_read.zig");
    _ = @import("transport_parameters_test.zig");
}
