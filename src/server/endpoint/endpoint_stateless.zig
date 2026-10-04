//! What the server's QUIC endpoint (`endpoint.zig`) reads off a datagram before any connection
//! holds it, and the packets it answers with no connection at all: Version Negotiation (RFC 9000
//! §6.1) and the address a Retry token binds (RFC 9000 §8.1.4).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../constants.zig");

const PeerAddress = quic.PeerAddress;

/// The Destination Connection ID of a datagram's first packet, which RFC 9000 §5.2 matches to a
/// connection, or null for a packet that names none. §12.2: "Receivers SHOULD ignore any
/// subsequent packets with a different Destination Connection ID than the first packet in the
/// datagram", so the first one routes the whole datagram. A short header carries no length, so
/// its ID is as long as the ones this endpoint issues.
pub fn destination_of(datagram: []const u8) ?[]const u8 {
    const parsed = quic.packet.header.read(datagram, constants.quic_id_len) catch return null;
    return switch (parsed) {
        // RFC 9000 §5.2.2: a packet in a version the server does not speak gets a Version
        // Negotiation packet or is dropped, and reaches no connection.
        .long => |long| if (quic.connection_version.speaks(@intFromEnum(long.version))) long.dcid else null,
        .short => |short| short.dcid,
        else => null,
    };
}

/// The long header of a client's first Initial packet, which a server starts a connection from
/// (RFC 9000 §7.2), or null for any other datagram.
pub fn first_initial(datagram: []const u8) ?quic.packet.header.Long {
    const parsed = quic.packet.header.read(datagram, constants.quic_id_len) catch return null;
    const long = switch (parsed) {
        .long => |held| held,
        else => return null,
    };
    // RFC 9000 §17.2.2: a client's first packet is an Initial.
    if (long.type != .initial) return null;
    return long;
}

/// The Version Negotiation packet a server owes a datagram that asks for a version it does not
/// speak, written into `output`, or null when it owes none. RFC 9000 §6.1: a server "SHOULD send
/// a Version Negotiation packet" when the packet "is large enough to initiate a new connection
/// for any supported version", which §14.1 makes 1,200 octets.
pub fn version_negotiation(datagram: []const u8, output: []u8) ?[]const u8 {
    const invariant = quic.packet.invariant;
    const long = invariant.read_long(datagram) catch return null;
    // RFC 8999 §6: a Version Negotiation packet is never answered with one, and RFC 9000 §6.1: a
    // version the server accepts starts a connection instead.
    if (long.is_version_negotiation() or quic.connection_version.speaks(long.version)) return null;
    // RFC 9000 §5.2.2: a server drops a datagram too small to start a connection.
    if (datagram.len < quic.constants.datagram_len_min) return null;
    var writer = quic.core.Writer.init(output);
    // RFC 9000 §17.2.1: the server "SHOULD set the most significant bit of this field (0x40) to
    // 1", so the packet reads as QUIC to a version that uses the Fixed Bit.
    invariant.write_version_negotiation(&writer, version_negotiation_unused_bits, long, &quic.connection_version.supported_versions) catch return null;
    return writer.written();
}

/// The seven bits RFC 8999 §6 leaves free, with RFC 9000 §17.2.1's 0x40 set.
const version_negotiation_unused_bits: u7 = 0x40;

/// Octets of the longest address a Retry token binds: an IPv6 address and a port.
pub const token_address_len_max: usize = ipv6_octets + @sizeOf(u16);
const ipv6_octets: usize = 16;

/// The client's address as the opaque octets a Retry token binds. RFC 9000 §8.1.4: a token lets
/// "the server verify that the source IP address and port in client packets remain constant", so
/// it covers both: the address, then the port in network byte order.
pub fn token_address(address: PeerAddress, into: *[token_address_len_max]u8) []const u8 {
    assert(address.len <= ipv6_octets);
    @memcpy(into[0..address.len], address.octets[0..address.len]);
    std.mem.writeInt(u16, into[address.len..][0..@sizeOf(u16)], address.port, .big);
    return into[0 .. address.len + @sizeOf(u16)];
}

const testing = std.testing;

/// A connection ID and a payload length for the test packets. Test-only.
const test_id: [constants.quic_id_len]u8 = @splat(test_id_octet);
const test_id_octet: u8 = 0x0d;
const test_payload_len: usize = 20;
threadlocal var test_packet: [quic.constants.datagram_len_min]u8 = undefined;

/// A long header of `long_type` followed by its payload's room, as colibri writes one. Test-only.
fn long_packet(long_type: quic.packet.header.LongType) ![]const u8 {
    var writer = quic.core.Writer.init(&test_packet);
    try quic.packet.header_write.write_long(&writer, .{
        .version = .v1,
        .type = long_type,
        .dcid = &test_id,
        .scid = &test_id,
        .packet_number = try quic.packet.packet_number.encode(0, null),
        .protected_payload_len = test_payload_len,
    });
    const header_len = writer.written().len;
    @memset(test_packet[header_len..][0..test_payload_len], 0);
    return test_packet[0 .. header_len + test_payload_len];
}

test "RFC 9000 §6.1: an unknown version large enough to start a connection gets Version Negotiation" {
    var answer: [quic.constants.datagram_len_min]u8 = undefined;
    const initial = try long_packet(.initial);
    @memset(test_packet[initial.len..], 0);
    const expanded = test_packet[0..quic.constants.datagram_len_min];
    try testing.expectEqual(null, version_negotiation(expanded, &answer));
    // The same datagram under a reserved version (RFC 9000 §15).
    const reserved_version = [_]u8{ 0x1a, 0x2a, 0x3a, 0x4a };
    @memcpy(test_packet[1..][0..reserved_version.len], &reserved_version);
    const written = version_negotiation(expanded, &answer).?;
    const parsed = try quic.packet.invariant.read_long(written);
    try testing.expect(parsed.is_version_negotiation());
    // RFC 8999 §6: the connection IDs come back swapped, and here they are the same octets.
    try testing.expectEqualSlices(u8, &test_id, parsed.dcid);
    // RFC 9000 §6.1: it lists the versions the server accepts, both of them (decision 108).
    const listed = (try quic.packet.header.read(written, 0)).version_negotiation.supported;
    try testing.expect(listed.count() == 2 and listed.at(0) == quic.constants.version_1 and listed.at(1) == quic.constants.version_2);
    // RFC 9000 §5.2.2: a datagram too small to start a connection gets nothing.
    try testing.expectEqual(null, version_negotiation(expanded[0 .. expanded.len - 1], &answer));
    // Version 2 is one the server speaks, so a datagram in it starts a connection instead.
    std.mem.writeInt(u32, test_packet[1..][0..@sizeOf(u32)], quic.constants.version_2, .big);
    try testing.expectEqual(null, version_negotiation(expanded, &answer));
}

test "RFC 9000 §7.2: a connection starts from a client's Initial alone, and §5.2 routes by the first ID" {
    const initial = try long_packet(.initial);
    try testing.expectEqualSlices(u8, &test_id, first_initial(initial).?.dcid);
    try testing.expectEqualSlices(u8, &test_id, destination_of(initial).?);
    const handshake = try long_packet(.handshake);
    try testing.expectEqual(null, first_initial(handshake));
    try testing.expectEqualSlices(u8, &test_id, destination_of(handshake).?);
}

test "RFC 9000 §8.1.4: a Retry token binds the client's address and its port" {
    var octets: [token_address_len_max]u8 = undefined;
    const port: u16 = 0x1f90;
    const bound = token_address(PeerAddress.of(&.{ 192, 0, 2, 7 }, port), &octets);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7, 0x1f, 0x90 }, bound);
    var other: [token_address_len_max]u8 = undefined;
    try testing.expect(!std.mem.eql(u8, bound, token_address(PeerAddress.of(&.{ 192, 0, 2, 7 }, port + 1), &other)));
}
