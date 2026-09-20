//! The reader for RFC 9000 §18's transport parameters. `transport_parameters.zig` holds the
//! values, their defaults and the writer.
//!
//! The sequence is read start to end, each parameter an identifier, a length and that many
//! octets. A parameter colibri does not know is read past, which is what §7.4.2 requires and what
//! §18.1's reserved identifiers exist to exercise.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const transport_parameters = @import("transport_parameters.zig");

const Reader = core.Reader;
const Error = transport_parameters.Error;
const Id = transport_parameters.Id;
const Parameters = transport_parameters.Parameters;
const ConnectionId = transport_parameters.ConnectionId;
const Role = transport_parameters.Role;

/// The identifiers §18.2 defines, which is what `Seen` can track: 0x00 through 0x10.
const known_id_max: u64 = @intFromEnum(Id.retry_source_connection_id);

/// Which of §18.2's parameters have been read, so a repeat is refused (RFC 9000 §7.4). One bit
/// per identifier, which fits because §18.2 defines seventeen of them.
const Seen = struct {
    bits: u32 = 0,

    fn mark(seen: *Seen, id: Id) Error!void {
        // RFC 9000 §18.1: an identifier colibri does not know has no semantics, so a repeat of
        // one changes nothing. `transport_parameters.zig` records why it is not tracked.
        const index = index_of(id) orelse return;
        const bit = @as(u32, 1) << index;
        // RFC 9000 §7.4: receipt of a duplicate transport parameter is a connection error.
        if (seen.bits & bit != 0) return Error.ParameterRepeated;
        seen.bits |= bit;
    }

    fn index_of(id: Id) ?u5 {
        const value = @intFromEnum(id);
        if (value > known_id_max) return null;
        return @intCast(value);
    }
};

comptime {
    // One bit per identifier, and `Seen.bits` must hold them all.
    assert(known_id_max < @bitSizeOf(@FieldType(Seen, "bits")));
}

/// Reads the whole extension, as a message from an endpoint in `sender`. What it returns is every
/// value the peer stated, with §18.2's default wherever it stated none.
pub fn read(reader: *Reader, sender: Role) Error!Parameters {
    var parameters = Parameters.initial();
    var seen: Seen = .{};
    // Bounded by the octets: every turn consumes an identifier and a length, each at least one
    // octet, so the reader runs out.
    while (reader.remaining_len() > 0) {
        const id: Id = @enumFromInt(try read_varint(reader));
        const body = try read_sized(reader);
        try seen.mark(id);
        // RFC 9000 §18.2: a server must treat receipt of a server-only parameter from a client as
        // a connection error of type TRANSPORT_PARAMETER_ERROR.
        if (sender == .client and transport_parameters.server_only(id)) {
            return Error.ParameterServerOnly;
        }
        try apply(&parameters, id, body);
    }
    // RFC 9000 §7.4: a parameter with an invalid value is a connection error, and §18.2 states
    // each bound as a value that is invalid.
    if (!parameters.valid()) return Error.ParameterInvalid;
    return parameters;
}

/// Puts one parameter's value where it belongs. An identifier this version does not define is
/// ignored, which RFC 9000 §7.4.2 requires of every endpoint.
fn apply(parameters: *Parameters, id: Id, body: []const u8) Error!void {
    if (try apply_integer(parameters, id, body)) return;
    if (try apply_connection_id(parameters, id, body)) return;
    switch (id) {
        .stateless_reset_token => {
            // RFC 9000 §18.2: a stateless reset token is a sequence of 16 bytes.
            if (body.len != transport_parameters.stateless_reset_token_len) return Error.ParameterInvalid;
            var token: [transport_parameters.stateless_reset_token_len]u8 = undefined;
            @memcpy(&token, body);
            parameters.stateless_reset_token = token;
        },
        .disable_active_migration => {
            // RFC 9000 §18.2: this parameter is included with a zero-length value, so any octet
            // in it is a value the parameter does not have.
            if (body.len != 0) return Error.ParameterInvalid;
            parameters.disable_active_migration = true;
        },
        // RFC 9000 §9.6 makes using a preferred address a MAY, and decision 21 refuses migration
        // in both directions, so its octets are read past like any parameter colibri does not use.
        .preferred_address => {},
        // RFC 9000 §7.4.2: an endpoint must ignore a transport parameter it does not understand.
        else => {},
    }
}

/// The eleven parameters whose value is a variable-length integer (RFC 9000 §18.2). Returns true
/// when `id` is one of them.
fn apply_integer(parameters: *Parameters, id: Id, body: []const u8) Error!bool {
    const slot: *u64 = switch (id) {
        .max_idle_timeout => &parameters.max_idle_timeout_ms,
        .max_udp_payload_size => &parameters.max_udp_payload_size,
        .initial_max_data => &parameters.initial_max_data,
        .initial_max_stream_data_bidi_local => &parameters.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote => &parameters.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni => &parameters.initial_max_stream_data_uni,
        .initial_max_streams_bidi => &parameters.initial_max_streams_bidi,
        .initial_max_streams_uni => &parameters.initial_max_streams_uni,
        .ack_delay_exponent => &parameters.ack_delay_exponent,
        .max_ack_delay => &parameters.max_ack_delay_ms,
        .active_connection_id_limit => &parameters.active_connection_id_limit,
        else => return false,
    };
    slot.* = try integer_of(body);
    return true;
}

/// The three parameters whose value is a connection ID (RFC 9000 §18.2). Returns true when `id`
/// is one of them.
fn apply_connection_id(parameters: *Parameters, id: Id, body: []const u8) Error!bool {
    const slot: *?ConnectionId = switch (id) {
        .original_destination_connection_id => &parameters.original_destination_connection_id,
        .initial_source_connection_id => &parameters.initial_source_connection_id,
        .retry_source_connection_id => &parameters.retry_source_connection_id,
        else => return false,
    };
    // RFC 9000 §17.2: a connection ID in version 1 is at most 20 octets, so a longer one is a
    // value this parameter cannot carry.
    if (body.len > constants.connection_id_len_max) return Error.ParameterInvalid;
    slot.* = ConnectionId.of(body);
    return true;
}

/// One parameter's value as a variable-length integer, which must be the whole of it.
fn integer_of(body: []const u8) Error!u64 {
    var reader = Reader.init(body);
    const value = try read_varint(&reader);
    // RFC 9000 §18: the Length field is the length of the Value field, so an integer parameter
    // whose length exceeds its integer carries octets the parameter does not define.
    if (reader.remaining_len() != 0) return Error.ParameterInvalid;
    return value;
}

/// A variable-length integer, with a short read reported as the truncation it is.
fn read_varint(reader: *Reader) Error!u64 {
    const decoded = wire.varint.decode(reader) catch return Error.ParameterTruncated;
    return decoded.value;
}

/// One length-prefixed value (RFC 9000 §18).
fn read_sized(reader: *Reader) Error![]const u8 {
    const len = try read_varint(reader);
    if (len > reader.remaining_len()) return Error.ParameterTruncated;
    return reader.take(@intCast(len)) catch unreachable;
}
