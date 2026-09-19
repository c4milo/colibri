//! The version 1 header writers (RFC 9000 §17), split off `packet_header.zig` for length. Each
//! writes a header up to and including its Packet Number field, which is the associated data of
//! the packet's AEAD (RFC 9001 §5.3), and leaves the low bits of byte 0 and the packet number
//! unprotected: whoever holds the keys applies header protection after it seals the payload.
//!
//! A write happens whole or not at all, so a buffer too small leaves the writer where it was.
//! Every other refusal is an assertion, because every other input is the caller's own.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");
const invariant = @import("invariant.zig");
const packet_header = @import("packet_header.zig");
const packet_number = @import("packet_number.zig");

const Writer = core.Writer;
const LongType = packet_header.LongType;

/// The header of an Initial, 0-RTT or Handshake packet (RFC 9000 §17.2.2 to §17.2.4).
pub const Long = struct {
    type: LongType,
    dcid: []const u8,
    scid: []const u8,
    /// The Token of an Initial packet, and empty in every other type (§17.2.2).
    token: []const u8 = &.{},
    packet_number: packet_number.Truncated,
    /// Octets of the payload as the wire carries it, the AEAD tag included.
    protected_payload_len: usize,
    /// Octets the Length field is written in (RFC 9000 §16 permits a longer encoding than the
    /// shortest). 0 picks the shortest.
    length_len: u8 = 0,
};

pub fn write_long(writer: *Writer, header: Long) core.writer.Error!void {
    assert(header.type != .retry);
    assert(header.type == .initial or header.token.len == 0);
    assert(@max(header.dcid.len, header.scid.len) <= constants.connection_id_len_max);
    var copy = writer.*;
    // RFC 9000 §17.2: Header Form 1, Fixed Bit 1, the type, Reserved Bits 0, and the Packet
    // Number Length as one less than the field's octets.
    try copy.write_byte(long_first_octet(header.type) | (header.packet_number.len - 1));
    try copy.write_int(u32, constants.version_1);
    try invariant.write_connection_id(&copy, header.dcid);
    try invariant.write_connection_id(&copy, header.scid);
    // RFC 9000 §17.2.2: only an Initial packet carries a Token Length and a Token.
    if (header.type == .initial) {
        try wire.varint.encode(&copy, header.token.len);
        try copy.write_bytes(header.token);
    }
    // RFC 9000 §17.2: the Length counts the Packet Number and the Payload.
    const length = header.packet_number.len + header.protected_payload_len;
    const length_len = if (header.length_len == 0) wire.varint.encoded_len_minimal(length) else header.length_len;
    try wire.varint.encode_with_len(&copy, length, length_len);
    try packet_number.write(&copy, header.packet_number);
    writer.* = copy;
}

/// Byte 0 of a long header of `long_type`, less its Packet Number Length (RFC 9000 §17.2).
fn long_first_octet(long_type: LongType) u8 {
    const form_and_fixed = invariant_long_form | constants.fixed_bit;
    return form_and_fixed | (@as(u8, @intFromEnum(long_type)) << constants.long_packet_type_shift);
}

/// RFC 8999 §5.1: the Header Form bit of a long header.
const invariant_long_form: u8 = 0x80;

/// The header of a 1-RTT packet (RFC 9000 §17.3.1).
pub const Short = struct {
    dcid: []const u8,
    packet_number: packet_number.Truncated,
    key_phase: bool,
    spin: bool = false,
};

pub fn write_short(writer: *Writer, header: Short) core.writer.Error!void {
    assert(header.dcid.len <= constants.connection_id_len_max);
    var copy = writer.*;
    // RFC 9000 §17.3.1: Header Form 0, Fixed Bit 1, Reserved Bits 0.
    var first_octet: u8 = constants.fixed_bit | (header.packet_number.len - 1);
    if (header.spin) first_octet |= constants.spin_bit;
    if (header.key_phase) first_octet |= constants.key_phase_bit;
    try copy.write_byte(first_octet);
    // RFC 8999 §5.2: the connection ID follows byte 0 with no length before it.
    try copy.write_bytes(header.dcid);
    try packet_number.write(&copy, header.packet_number);
    writer.* = copy;
}

/// A Retry packet less its Retry Integrity Tag (RFC 9000 §17.2.5).
pub const Retry = struct {
    /// The four bits the RFC leaves to the server, which a client MUST ignore.
    unused_bits: u4 = 0,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
};

pub fn write_retry(writer: *Writer, retry: Retry) core.writer.Error!void {
    assert(@max(retry.dcid.len, retry.scid.len) <= constants.connection_id_len_max);
    // RFC 9000 §17.2.5.2: a client discards a Retry with a zero-length token, so none is sent.
    assert(retry.token.len > 0);
    var copy = writer.*;
    try copy.write_byte(long_first_octet(.retry) | retry.unused_bits);
    try copy.write_int(u32, constants.version_1);
    try invariant.write_connection_id(&copy, retry.dcid);
    try invariant.write_connection_id(&copy, retry.scid);
    try copy.write_bytes(retry.token);
    writer.* = copy;
}

/// Writes the Retry Pseudo-Packet, which is the associated data the Retry Integrity Tag is
/// computed over (RFC 9001 §5.8): the Original Destination Connection ID after its length, then
/// the Retry packet less its tag. `original_dcid` is the Destination Connection ID of the Initial
/// packet the Retry answers.
pub fn write_retry_pseudo_packet(
    writer: *Writer,
    original_dcid: []const u8,
    retry_without_tag: []const u8,
) core.writer.Error!void {
    assert(original_dcid.len <= constants.connection_id_len_max);
    var copy = writer.*;
    try invariant.write_connection_id(&copy, original_dcid);
    try copy.write_bytes(retry_without_tag);
    writer.* = copy;
}

const testing = std.testing;

/// A connection ID and the octets RFC 9001 Appendix A publishes. Test-only.
const client_dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08".*;
const server_scid = "\xf0\x67\xa5\x50\x2a\x42\x62\xb5".*;

test "RFC 9001 Appendix A.2: the client Initial's unprotected header, octet for octet" {
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    // 1162 octets of frames and the 16-octet tag, under a 4-octet packet number of 2.
    try write_long(&writer, .{
        .type = .initial,
        .dcid = &client_dcid,
        .scid = &.{},
        .packet_number = .{ .value = 2, .len = 4 },
        .protected_payload_len = 1162 + constants.aead_tag_len,
        .length_len = 2,
    });
    const expected = [_]u8{ 0xc3, 0x00, 0x00, 0x00, 0x01, 0x08 } ++ client_dcid ++
        [_]u8{ 0x00, 0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02 };
    try testing.expectEqualSlices(u8, &expected, writer.written());
}

test "RFC 9001 Appendix A.3: the server Initial's unprotected header, octet for octet" {
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    // The Length of 117 is written in two octets, which RFC 9000 §16 permits.
    try write_long(&writer, .{
        .type = .initial,
        .dcid = &.{},
        .scid = &server_scid,
        .packet_number = .{ .value = 1, .len = 2 },
        .protected_payload_len = 99 + constants.aead_tag_len,
        .length_len = 2,
    });
    const expected = [_]u8{ 0xc1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08 } ++ server_scid ++
        [_]u8{ 0x00, 0x40, 0x75, 0x00, 0x01 };
    try testing.expectEqualSlices(u8, &expected, writer.written());
}

test "RFC 9001 Appendix A.5: the short header, octet for octet" {
    var buffer: [8]u8 = undefined;
    var writer = Writer.init(&buffer);
    // Packet number 654360564 in three octets, with no connection ID and Key Phase 0.
    try write_short(&writer, .{
        .dcid = &.{},
        .packet_number = .{ .value = 0x00bff4, .len = 3 },
        .key_phase = false,
    });
    try testing.expectEqualSlices(u8, &.{ 0x42, 0x00, 0xbf, 0xf4 }, writer.written());
}

test "RFC 9001 Appendix A.4: the Retry packet less its tag, and the pseudo-packet over it" {
    var buffer: [64]u8 = undefined;
    var writer = Writer.init(&buffer);
    try write_retry(&writer, .{ .unused_bits = 0xf, .dcid = &.{}, .scid = &server_scid, .token = "token" });
    const expected = [_]u8{ 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08 } ++ server_scid ++ "token".*;
    try testing.expectEqualSlices(u8, &expected, writer.written());
    // RFC 9001 §5.8: the ODCID Length and the ODCID, then the packet as sent, less its tag.
    var pseudo_buffer: [64]u8 = undefined;
    var pseudo = Writer.init(&pseudo_buffer);
    try write_retry_pseudo_packet(&pseudo, &client_dcid, writer.written());
    try testing.expectEqualSlices(u8, &([_]u8{0x08} ++ client_dcid ++ expected), pseudo.written());
}

test "§17.2: every long type is read back as it was written, with what follows it left alone" {
    const token = "a token the server issued";
    for ([_]LongType{ .initial, .zero_rtt, .handshake }) |long_type| {
        var buffer: [128]u8 = @splat(0xee);
        var writer = Writer.init(&buffer);
        const header: Long = .{
            .type = long_type,
            .dcid = &client_dcid,
            .scid = &server_scid,
            .token = if (long_type == .initial) token else &.{},
            .packet_number = .{ .value = 0x1234, .len = 2 },
            .protected_payload_len = 20,
        };
        try write_long(&writer, header);
        const header_len = writer.written().len;
        // The payload, then the first octets of a second packet in the same datagram (§12.2).
        const datagram = buffer[0 .. header_len + 20 + 5];
        const packet = (try packet_header.read(datagram, 0)).long;
        try testing.expectEqual(long_type, packet.type);
        try testing.expectEqualSlices(u8, &client_dcid, packet.dcid);
        try testing.expectEqualSlices(u8, &server_scid, packet.scid);
        try testing.expectEqualSlices(u8, header.token, packet.token);
        try testing.expectEqual(header_len - 2, packet.packet_number_offset);
        try testing.expectEqual(header_len + 20, packet.packet_len);
        try testing.expectEqual(2, try packet_header.unprotected_long(packet.first_octet));
    }
}

test "§17.3.1: a short header is read back, and its bits after protection is removed" {
    var buffer: [32]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write_short(&writer, .{
        .dcid = &client_dcid,
        .packet_number = .{ .value = 7, .len = 1 },
        .key_phase = true,
        .spin = true,
    });
    const packet = (try packet_header.read(&buffer, client_dcid.len)).short;
    try testing.expectEqualSlices(u8, &client_dcid, packet.dcid);
    try testing.expectEqual(1 + client_dcid.len, packet.packet_number_offset);
    try testing.expectEqual(buffer.len, packet.packet_len);
    const bits = try packet_header.unprotected_short(packet.first_octet);
    try testing.expectEqual(1, bits.packet_number_len);
    try testing.expect(bits.key_phase and bits.spin);
}

test "a header that does not fit writes nothing" {
    var buffer: [64]u8 = undefined;
    var whole = Writer.init(&buffer);
    const header: Long = .{
        .type = .handshake,
        .dcid = &client_dcid,
        .scid = &server_scid,
        .packet_number = .{ .value = 1, .len = 1 },
        .protected_payload_len = 17,
    };
    try write_long(&whole, header);
    for (0..whole.written().len) |room| {
        var writer = Writer.init(buffer[0..room]);
        try testing.expectError(error.NoSpaceLeft, write_long(&writer, header));
        try testing.expectEqual(0, writer.written().len);
    }
}
