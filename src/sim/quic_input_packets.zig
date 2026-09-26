//! The packet and transport parameter targets of the QUIC input check (`quic_input_check.zig`).
//!
//! A datagram holds up to `quic_input_check_packets_max` packets written with
//! `quic.packet.header_write` and `invariant.write_version_negotiation`: long headers first, then
//! at most one packet that runs to the end of the datagram. It is read packet by packet, as a
//! receiver does (RFC 9000 §12.2), and every packet read must lie inside what is left of it.
//!
//! A set of transport parameters is drawn inside RFC 9000 §18.2's bounds and written with
//! `quic.transport_parameters.write`. What is read back must keep those bounds, must hold no
//! server-only parameter from a client, and must be written again as the same octets.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const frames = @import("quic_input_frames.zig");

const constants = sim.constants;
const Random = sim.Random;
const Reader = quic.core.Reader;
const Writer = quic.core.Writer;
const limits = quic.constants;
const header = quic.packet.header;
const header_write = quic.packet.header_write;
const invariant = quic.packet.invariant;
const transport_parameters = quic.transport_parameters;
const Parameters = transport_parameters.Parameters;
const Role = transport_parameters.Role;

const chosen = frames.chosen;
const draw_bounded = frames.draw_bounded;
const draw_octets = frames.draw_octets;
const draw_varint = frames.draw_varint;

pub const Violation = error{
    /// A packet that was read does not lie inside the datagram, or breaks a rule its type keeps.
    PacketOutsideDatagram,
    /// Accepted transport parameters break RFC 9000 §18.2.
    ParametersInvalid,
    /// Accepted transport parameters, written again, were not the same octets.
    ParametersChanged,
};

pub const Storage = struct {
    datagram: [constants.quic_input_check_input_len_max]u8,
    /// The length of the connection IDs a short header carries, which the reader is told.
    short_dcid_len: usize,
    parameters: [constants.quic_input_check_input_len_max]u8,
    rewritten: [constants.quic_input_check_input_len_max]u8,
    rewritten_again: [constants.quic_input_check_input_len_max]u8,
};

/// The packets a datagram is drawn from. A Retry, a short header and a Version Negotiation packet
/// carry no Length, so each ends the datagram.
const Kind = enum { initial, zero_rtt, handshake, retry, short, version_negotiation };

/// The versions a drawn Version Negotiation packet offers: version 1, and two of the form
/// 0x?a?a?a?a that RFC 9000 §15 reserves so that negotiation is exercised.
const supported_versions = [_]u32{ limits.version_1, reserved_version_first, reserved_version_second };
const reserved_version_first: u32 = 0x1a2a3a4a;
const reserved_version_second: u32 = 0x5a6a7a8a;

/// Writes a datagram of drawn packets and returns it.
pub fn draw_datagram(storage: *Storage, random: *Random, material: []const u8) []const u8 {
    storage.short_dcid_len = random.between(0, limits.connection_id_len_max);
    var writer = Writer.init(&storage.datagram);
    for (0..random.between(1, constants.quic_input_check_packets_max)) |_| {
        const kind: Kind = @enumFromInt(random.below(std.meta.fields(Kind).len));
        draw_packet(storage, random, material, kind, &writer) catch break;
        if (kind == .retry or kind == .short or kind == .version_negotiation) break;
    }
    return writer.written();
}

fn draw_packet(storage: *Storage, random: *Random, material: []const u8, kind: Kind, writer: *Writer) !void {
    const dcid = draw_octets(random, material, 0, limits.connection_id_len_max);
    const scid = draw_octets(random, material, 0, limits.connection_id_len_max);
    const payload = draw_octets(random, material, 0, constants.quic_input_check_octets_len_max);
    var copy = writer.*;
    switch (kind) {
        .initial, .zero_rtt, .handshake => try write_long(&copy, random, material, kind, dcid, scid, payload.len),
        .retry => {
            const token = draw_octets(random, material, 1, constants.quic_input_check_octets_len_max);
            try header_write.write_retry(&copy, .{ .dcid = dcid, .scid = scid, .token = token });
            try copy.write_bytes(draw_octets(random, material, limits.retry_integrity_tag_len, limits.retry_integrity_tag_len));
            writer.* = copy;
            return;
        },
        .short => try header_write.write_short(&copy, .{
            .dcid = material[0..storage.short_dcid_len],
            .packet_number = draw_packet_number(random),
            .key_phase = chosen(random),
            .spin = chosen(random),
        }),
        .version_negotiation => {
            const received: invariant.Long = .{ .first_octet = 0, .version = limits.version_1, .dcid = dcid, .scid = scid, .rest = &.{} };
            const count = random.between(1, supported_versions.len);
            try invariant.write_version_negotiation(&copy, @truncate(random.next()), received, supported_versions[0..count]);
            writer.* = copy;
            return;
        },
    }
    try copy.write_bytes(payload);
    writer.* = copy;
}

fn write_long(
    writer: *Writer,
    random: *Random,
    material: []const u8,
    kind: Kind,
    dcid: []const u8,
    scid: []const u8,
    payload_len: usize,
) !void {
    const long_type: header.LongType = switch (kind) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        else => unreachable,
    };
    const token = if (kind == .initial) draw_octets(random, material, 0, constants.quic_input_check_octets_len_max) else &.{};
    try header_write.write_long(writer, .{
        .type = long_type,
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .packet_number = draw_packet_number(random),
        .protected_payload_len = payload_len,
        .length_len = if (chosen(random)) 0 else quic.wire.constants.varint_len_max,
    });
}

fn draw_packet_number(random: *Random) quic.packet.packet_number.Truncated {
    const len: u8 = @intCast(random.between(1, limits.packet_number_len_max));
    return .{ .value = @truncate(random.below(@as(u64, 1) << @intCast(len * @bitSizeOf(u8)))), .len = len };
}

/// Reads `datagram` packet by packet. True when every octet was read as packets, false when a
/// packet was refused.
pub fn read_datagram(storage: *const Storage, datagram: []const u8) Violation!bool {
    var reader = Reader.init(datagram);
    // Bounded: every packet read consumes at least its first octet.
    for (0..datagram.len + 1) |_| {
        if (reader.remaining_len() == 0) return true;
        const rest = reader.peek_rest();
        const packet = header.read(rest, storage.short_dcid_len) catch return false;
        _ = reader.take(try packet_len_of(packet, rest.len, storage.short_dcid_len)) catch unreachable;
    }
    unreachable;
}

/// Octets of a packet that was read, once it is checked to lie inside the `rest_len` octets left.
fn packet_len_of(packet: header.Packet, rest_len: usize, short_dcid_len: usize) Violation!usize {
    const inside = switch (packet) {
        // RFC 9000 §12.2: the Length ends a long packet, which may be followed by another.
        .long => |long| long.packet_number_offset <= long.packet_len and long.packet_len <= rest_len and
            @max(long.dcid.len, long.scid.len) <= limits.connection_id_len_max and fixed(long.first_octet),
        .short => |short| short.packet_number_offset == 1 + short_dcid_len and short.packet_len == rest_len and
            fixed(short.first_octet),
        .retry => |retry| retry.token.len > 0 and fixed(retry.first_octet) and
            retry.without_tag.len + limits.retry_integrity_tag_len == rest_len,
        .version_negotiation => |negotiation| negotiation.supported.count() > 0,
        .other_version => |other| other.version != limits.version_1,
    };
    if (!inside) return error.PacketOutsideDatagram;
    return if (packet == .long) packet.long.packet_len else rest_len;
}

/// RFC 9000 §17.2, §17.3.1: a version 1 packet whose Fixed Bit is 0 is discarded.
fn fixed(first_octet: u8) bool {
    return first_octet & limits.fixed_bit != 0;
}

/// Writes a drawn set of transport parameters as `sender` sends it, and returns the octets.
pub fn draw_parameters(storage: *Storage, random: *Random, material: []const u8, sender: Role) []const u8 {
    var parameters = Parameters.initial();
    draw_integers(&parameters, random);
    draw_connection_ids(&parameters, random, material, sender);
    parameters.disable_active_migration = chosen(random);
    var writer = Writer.init(&storage.parameters);
    transport_parameters.write(&writer, &parameters, sender) catch unreachable;
    return writer.written();
}

/// Sets each integer parameter, or leaves its default, inside the bounds of RFC 9000 §18.2.
fn draw_integers(parameters: *Parameters, random: *Random) void {
    const varint_max = quic.wire.constants.varint_value_max;
    const integers = [_]struct { slot: *u64, min: u64, max: u64 }{
        .{ .slot = &parameters.max_idle_timeout_ms, .min = 0, .max = varint_max },
        .{ .slot = &parameters.max_udp_payload_size, .min = transport_parameters.max_udp_payload_size_min, .max = varint_max },
        .{ .slot = &parameters.initial_max_data, .min = 0, .max = varint_max },
        .{ .slot = &parameters.initial_max_stream_data_bidi_local, .min = 0, .max = varint_max },
        .{ .slot = &parameters.initial_max_stream_data_bidi_remote, .min = 0, .max = varint_max },
        .{ .slot = &parameters.initial_max_stream_data_uni, .min = 0, .max = varint_max },
        .{ .slot = &parameters.initial_max_streams_bidi, .min = 0, .max = limits.max_streams_max },
        .{ .slot = &parameters.initial_max_streams_uni, .min = 0, .max = limits.max_streams_max },
        .{ .slot = &parameters.ack_delay_exponent, .min = 0, .max = transport_parameters.ack_delay_exponent_max },
        .{ .slot = &parameters.max_ack_delay_ms, .min = 0, .max = transport_parameters.max_ack_delay_ms_max - 1 },
        .{ .slot = &parameters.active_connection_id_limit, .min = transport_parameters.active_connection_id_limit_min, .max = varint_max },
    };
    for (integers) |integer| {
        if (chosen(random)) integer.slot.* = draw_bounded(random, integer.min, integer.max);
    }
}

/// Sets the connection IDs and the stateless reset token, the server-only ones only for a server
/// (RFC 9000 §18.2).
fn draw_connection_ids(parameters: *Parameters, random: *Random, material: []const u8, sender: Role) void {
    const ConnectionId = transport_parameters.ConnectionId;
    const cid_max = limits.connection_id_len_max;
    if (chosen(random)) parameters.initial_source_connection_id = ConnectionId.of(draw_octets(random, material, 0, cid_max));
    if (sender == .client) return;
    if (chosen(random)) parameters.original_destination_connection_id = ConnectionId.of(draw_octets(random, material, 0, cid_max));
    if (chosen(random)) parameters.retry_source_connection_id = ConnectionId.of(draw_octets(random, material, 0, cid_max));
    if (chosen(random)) {
        const token_len = transport_parameters.stateless_reset_token_len;
        parameters.stateless_reset_token = draw_octets(random, material, token_len, token_len)[0..token_len].*;
    }
}

/// Reads `input` as the transport parameters `sender` sent and checks what is accepted. True when
/// they were accepted.
pub fn read_parameters(storage: *Storage, input: []const u8, sender: Role) Violation!bool {
    var reader = Reader.init(input);
    const parameters = quic.transport_parameters_read.read(&reader, sender) catch return false;
    if (!within_bounds(parameters)) return error.ParametersInvalid;
    // RFC 9000 §18.2: a client MUST NOT include a server-only parameter.
    if (sender == .client and has_server_only(parameters)) return error.ParametersInvalid;
    const first = try write_parameters(&storage.rewritten, parameters, sender);
    var again_reader = Reader.init(first);
    const again = quic.transport_parameters_read.read(&again_reader, sender) catch return error.ParametersChanged;
    const second = try write_parameters(&storage.rewritten_again, again, sender);
    if (!std.mem.eql(u8, first, second)) return error.ParametersChanged;
    return true;
}

/// The bounds RFC 9000 §18.2 states as values that are invalid, read again here rather than
/// through `Parameters.valid`, the function a mutation of the reader would change.
fn within_bounds(parameters: Parameters) bool {
    const connection_ids = [_]?transport_parameters.ConnectionId{
        parameters.original_destination_connection_id,
        parameters.initial_source_connection_id,
        parameters.retry_source_connection_id,
    };
    for (connection_ids) |connection_id| {
        // RFC 9000 §17.2: a version 1 connection ID is at most 20 octets.
        if (connection_id) |id| if (id.len > limits.connection_id_len_max) return false;
    }
    return parameters.max_udp_payload_size >= transport_parameters.max_udp_payload_size_min and
        parameters.ack_delay_exponent <= transport_parameters.ack_delay_exponent_max and
        parameters.max_ack_delay_ms < transport_parameters.max_ack_delay_ms_max and
        parameters.active_connection_id_limit >= transport_parameters.active_connection_id_limit_min and
        parameters.initial_max_streams_bidi <= limits.max_streams_max and
        parameters.initial_max_streams_uni <= limits.max_streams_max;
}

fn has_server_only(parameters: Parameters) bool {
    return parameters.original_destination_connection_id != null or
        parameters.retry_source_connection_id != null or
        parameters.stateless_reset_token != null;
}

fn write_parameters(buffer: []u8, parameters: Parameters, sender: Role) Violation![]const u8 {
    var writer = Writer.init(buffer);
    transport_parameters.write(&writer, &parameters, sender) catch return error.ParametersChanged;
    return writer.written();
}
