//! The version 1 packet reader (RFC 9000 §17), above the version-independent one. It reads one
//! packet of a datagram as far as header protection allows: the type, the connection IDs, the
//! token, and where the Packet Number field starts and the packet ends. The low bits of byte 0 and
//! the packet number are under header protection (RFC 9001 §5.4), so they are read by
//! `unprotected_long` and `unprotected_short` once whoever holds the keys has removed it.
//!
//! A datagram may hold several packets (§12.2). `read` takes what is left of the datagram and
//! reports `packet_len`, so the caller reads the next one from there. A short header, a Retry and
//! a Version Negotiation packet carry no Length and always end the datagram.
//!
//! Every rule of version 1 that RFC 8999 does not state is applied here and never below: this is
//! the only file that names the 20-octet connection ID maximum, and the comptime block at the end
//! holds `invariant.zig` to that (invariant 22).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");
const invariant = @import("invariant.zig");

const Reader = core.Reader;

/// The long packet types of version 1 (RFC 9000 §17.2, Table 5).
pub const LongType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

/// Why a packet was not read. Each one means "discard the packet": none of them is a connection
/// error, because nothing here has been authenticated yet.
pub const Error = invariant.Error || error{
    /// RFC 9000 §17.2, §17.3.1: a packet with a zero Fixed Bit is not valid in this version and
    /// MUST be discarded.
    FixedBitClear,
    /// RFC 9000 §17.2: a version 1 long header whose connection ID is longer than 20 octets MUST
    /// be dropped.
    ConnectionIdTooLong,
    /// The Length field counts more octets than the datagram holds, so the packet is not whole.
    LengthPastDatagram,
    /// RFC 9000 §17.2.5: a Retry packet ends with a 16-octet Retry Integrity Tag, and this one is
    /// too short to hold it.
    RetryTagMissing,
    /// RFC 9000 §17.2.5.2: a client MUST discard a Retry packet with a zero-length Retry Token.
    RetryTokenEmpty,
};

/// An Initial, 0-RTT or Handshake packet, read as far as header protection allows.
pub const Long = struct {
    type: LongType,
    /// Byte 0 as it arrived. Its low four bits are still protected.
    first_octet: u8,
    dcid: []const u8,
    scid: []const u8,
    /// The Token of an Initial packet (RFC 9000 §17.2.2), and empty in every other type.
    token: []const u8,
    /// Octets from the start of the packet to its Packet Number field.
    packet_number_offset: usize,
    /// Octets of the whole packet, which is where the next one of the datagram starts (§12.2).
    packet_len: usize,
};

/// A 1-RTT packet, read as far as header protection allows (RFC 9000 §17.3.1).
pub const Short = struct {
    /// Byte 0 as it arrived. Its low five bits are still protected.
    first_octet: u8,
    dcid: []const u8,
    packet_number_offset: usize,
    /// A short header carries no Length, so the packet is the rest of the datagram (§12.2).
    packet_len: usize,
};

/// A Retry packet (RFC 9000 §17.2.5). Nothing in it is protected.
pub const Retry = struct {
    first_octet: u8,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    integrity_tag: *const [constants.retry_integrity_tag_len]u8,
    /// The packet less its tag, which the Retry Pseudo-Packet of RFC 9001 §5.8 is built from.
    without_tag: []const u8,
};

pub const VersionNegotiation = struct {
    dcid: []const u8,
    scid: []const u8,
    supported: invariant.SupportedVersions,
};

pub const Packet = union(enum) {
    long: Long,
    short: Short,
    retry: Retry,
    version_negotiation: VersionNegotiation,
    /// A long header of a version other than 1, with the fields RFC 8999 fixes and no more. A
    /// server answers it with a Version Negotiation packet (RFC 9000 §5.2.2).
    other_version: invariant.Long,
};

/// Reads the packet at the start of `datagram`, which is a whole datagram or what is left of one
/// after the packets before. `short_dcid_len` is the length of the connection IDs this endpoint
/// issued, which a short header does not carry (RFC 8999 §5.2).
pub fn read(datagram: []const u8, short_dcid_len: usize) Error!Packet {
    assert(short_dcid_len <= constants.connection_id_len_max);
    if (datagram.len == 0) return error.Truncated;
    if (invariant.form_of(datagram[0]) == .short) {
        return .{ .short = try read_short(datagram, short_dcid_len) };
    }
    const header = try invariant.read_long(datagram);
    // RFC 8999 §6, RFC 9000 §17.2.1: a Version field of 0 is a Version Negotiation packet, in
    // every version, and its other seven bits of byte 0 MUST be ignored.
    if (header.is_version_negotiation()) {
        const supported = try invariant.read_supported_versions(header);
        return .{ .version_negotiation = .{ .dcid = header.dcid, .scid = header.scid, .supported = supported } };
    }
    // RFC 9000 §17.2.1: version-specific rules MUST NOT influence whether a Version Negotiation
    // packet is sent, so a packet of another version is handed over before any rule below runs.
    if (header.version != constants.version_1) return .{ .other_version = header };
    // RFC 9000 §17.2: packets containing a zero value for the Fixed Bit MUST be discarded.
    if (header.first_octet & constants.fixed_bit == 0) return error.FixedBitClear;
    const longest = @max(header.dcid.len, header.scid.len);
    // RFC 9000 §17.2: in version 1 neither connection ID length may exceed 20 octets, and an
    // endpoint that receives a larger value MUST drop the packet.
    if (longest > constants.connection_id_len_max) return error.ConnectionIdTooLong;
    const long_type: LongType = @enumFromInt((header.first_octet & constants.long_packet_type_mask) >>
        constants.long_packet_type_shift);
    if (long_type == .retry) return .{ .retry = try read_retry(datagram, header) };
    return .{ .long = try read_long(long_type, header) };
}

fn read_short(datagram: []const u8, dcid_len: usize) Error!Short {
    const header = try invariant.read_short(datagram, dcid_len);
    // RFC 9000 §17.3.1: packets containing a zero value for the Fixed Bit MUST be discarded.
    if (header.first_octet & constants.fixed_bit == 0) return error.FixedBitClear;
    return .{
        .first_octet = header.first_octet,
        .dcid = header.dcid,
        .packet_number_offset = datagram.len - header.rest.len,
        .packet_len = datagram.len,
    };
}

/// The fields after the Source Connection ID of an Initial, 0-RTT or Handshake packet.
fn read_long(long_type: LongType, header: invariant.Long) Error!Long {
    assert(long_type != .retry);
    var reader = Reader.init(header.rest);
    var token: []const u8 = &.{};
    if (long_type == .initial) {
        // RFC 9000 §17.2.2: a Token Length as a variable-length integer, then the Token.
        const token_len = (wire.varint.decode(&reader) catch return error.Truncated).value;
        if (token_len > reader.remaining_len()) return error.Truncated;
        token = reader.take(@intCast(token_len)) catch unreachable;
    }
    // RFC 9000 §17.2: the Length is the length of the rest of the packet, the Packet Number and
    // the Payload, as a variable-length integer.
    const length = (wire.varint.decode(&reader) catch return error.Truncated).value;
    // RFC 9000 §12.2: the Length determines the end of the packet, so one that runs past the
    // datagram names a packet that is not there.
    if (length > reader.remaining_len()) return error.LengthPastDatagram;
    const packet_number_offset = header.header_len() + reader.offset;
    return .{
        .type = long_type,
        .first_octet = header.first_octet,
        .dcid = header.dcid,
        .scid = header.scid,
        .token = token,
        .packet_number_offset = packet_number_offset,
        .packet_len = packet_number_offset + @as(usize, @intCast(length)),
    };
}

/// The fields after the Source Connection ID of a Retry packet (RFC 9000 §17.2.5).
fn read_retry(datagram: []const u8, header: invariant.Long) Error!Retry {
    const tag_len = constants.retry_integrity_tag_len;
    // RFC 9000 §17.2.5: the Retry Token, then the 128-bit Retry Integrity Tag, and no Length: the
    // tag is the last 16 octets of the datagram.
    if (header.rest.len < tag_len) return error.RetryTagMissing;
    const token = header.rest[0 .. header.rest.len - tag_len];
    // RFC 9000 §17.2.5.2: a client MUST discard a Retry packet with a zero-length Retry Token.
    if (token.len == 0) return error.RetryTokenEmpty;
    return .{
        .first_octet = header.first_octet,
        .dcid = header.dcid,
        .scid = header.scid,
        .token = token,
        .integrity_tag = header.rest[header.rest.len - tag_len ..][0..tag_len],
        .without_tag = datagram[0 .. datagram.len - tag_len],
    };
}

/// Why a packet whose protection was removed is refused. RFC 9000 §17.2 and §17.3.1 make each a
/// connection error of type PROTOCOL_VIOLATION, and only once packet protection is removed too:
/// acting on the bits after header protection alone exposes the endpoint (RFC 9001 §9.5).
pub const UnprotectedError = error{ReservedBitsSet};

/// What byte 0 of a long header says once header protection is removed.
pub fn unprotected_long(first_octet: u8) UnprotectedError!u8 {
    // RFC 9000 §17.2: the value of the Reserved Bits MUST be 0 prior to protection.
    if (first_octet & constants.long_reserved_bits != 0) return error.ReservedBitsSet;
    return packet_number_len_of(first_octet);
}

/// What byte 0 of a short header says once header protection is removed (RFC 9000 §17.3.1).
pub const UnprotectedShort = struct {
    packet_number_len: u8,
    key_phase: bool,
    spin: bool,
};

pub fn unprotected_short(first_octet: u8) UnprotectedError!UnprotectedShort {
    // RFC 9000 §17.3.1: the value of the Reserved Bits MUST be 0 prior to protection.
    if (first_octet & constants.short_reserved_bits != 0) return error.ReservedBitsSet;
    return .{
        .packet_number_len = packet_number_len_of(first_octet),
        .key_phase = first_octet & constants.key_phase_bit != 0,
        .spin = first_octet & constants.spin_bit != 0,
    };
}

/// RFC 9000 §17.2: the Packet Number Length is one less than the field's length in octets.
fn packet_number_len_of(first_octet: u8) u8 {
    return (first_octet & constants.packet_number_len_mask) + 1;
}

/// Occurrences of `needle` in `source`. Comptime-only.
fn occurrences(comptime source: []const u8, comptime needle: []const u8) usize {
    @setEvalBranchQuota(source.len * needle.len * constants.comptime_scan_branches_per_octet);
    return std.mem.count(u8, source, needle);
}

comptime {
    // Invariant 22: the version-independent reader imports `std` and `core` and nothing else, so
    // no version 1 value is within its reach, and it never names the version 1 maximum.
    const source = @embedFile("invariant.zig");
    assert(occurrences(source, "@import(") == 2);
    assert(occurrences(source, "@import(\"std\")") == 1 and occurrences(source, "@import(\"core\")") == 1);
    assert(occurrences(source, "connection_id_len_max") == 0);
    assert(occurrences(source, "@embedFile(") == 0);
}

const testing = std.testing;

/// RFC 9001 Appendix A.4's Retry packet, as published. Test-only.
const sample_retry = "\xff\x00\x00\x00\x01\x00\x08\xf0\x67\xa5\x50\x2a\x42\x62\xb5token" ++
    "\x04\xa2\x65\xba\x2e\xff\x4d\x82\x90\x58\xfb\x3f\x0f\x24\x96\xba";

/// A version 1 Handshake packet: connection IDs of 2 and 1 octets, a Length of 5. Test-only.
const sample_handshake = "\xe0\x00\x00\x00\x01\x02\xaa\xbb\x01\xcc\x05\x01\x02\x03\x04\x05";

test "RFC 9001 Appendix A.4: the published Retry packet reads into its fields" {
    const retry = (try read(sample_retry, 0)).retry;
    try testing.expectEqual(0, retry.dcid.len);
    try testing.expectEqualSlices(u8, sample_retry[7..15], retry.scid);
    try testing.expectEqualStrings("token", retry.token);
    try testing.expectEqualSlices(u8, sample_retry[20..], retry.integrity_tag);
    try testing.expectEqualSlices(u8, sample_retry[0..20], retry.without_tag);
}

test "§17.2.5: a Retry too short for its tag, or with no token before it, is discarded" {
    const header_len = 15;
    for (header_len..header_len + constants.retry_integrity_tag_len) |len| {
        try testing.expectError(error.RetryTagMissing, read(sample_retry[0..len], 0));
    }
    // Sixteen octets after the connection IDs are all tag, which leaves a zero-length token.
    const no_token = sample_retry[0..header_len] ++ sample_retry[20..];
    try testing.expectError(error.RetryTokenEmpty, read(no_token, 0));
}

test "§17.2.1: a long header of another version is handed over whatever its connection IDs" {
    const other = [_]u8{ 0x80, 0xfa, 0xce, 0xb0, 0x0c, 21 } ++ [_]u8{0xd1} ** 21 ++ [_]u8{0};
    const packet = try read(&other, 0);
    try testing.expectEqual(0xfaceb00c, packet.other_version.version);
    try testing.expectEqual(21, packet.other_version.dcid.len);
    // The same octets under version 1 are dropped, by either connection ID.
    var version_1 = other;
    version_1[0] |= constants.fixed_bit;
    @memcpy(version_1[1..5], &[_]u8{ 0, 0, 0, 1 });
    try testing.expectError(error.ConnectionIdTooLong, read(&version_1, 0));
    const long_scid = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 21 } ++ [_]u8{0x5c} ** 21 ++ [_]u8{ 0, 1, 0 };
    try testing.expectError(error.ConnectionIdTooLong, read(&long_scid, 0));
    // Twenty octets is the most version 1 permits, and is read.
    const at_limit = [_]u8{ 0xc0, 0, 0, 0, 1, 20 } ++ [_]u8{0xd1} ** 20 ++ [_]u8{ 0, 0, 1, 9 };
    try testing.expectEqual(20, (try read(&at_limit, 0)).long.dcid.len);
}

test "§17.2, §17.3.1: a zero Fixed Bit is discarded in both header forms, and only in version 1" {
    var long = sample_handshake.*;
    long[0] &= ~constants.fixed_bit;
    try testing.expectError(error.FixedBitClear, read(&long, 0));
    try testing.expectError(error.FixedBitClear, read(&.{ 0x00, 0xaa, 0x01 }, 1));
    // RFC 8999 §6: the bit is one of the seven a Version Negotiation packet leaves unused.
    const negotiation = [_]u8{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectEqual(1, (try read(&negotiation, 0)).version_negotiation.supported.count());
}

test "§12.2: the Length ends the packet, and one past the datagram is refused" {
    const two = sample_handshake ++ sample_handshake;
    const first = (try read(two, 0)).long;
    try testing.expectEqual(LongType.handshake, first.type);
    try testing.expectEqual(11, first.packet_number_offset);
    try testing.expectEqual(sample_handshake.len, first.packet_len);
    const second = (try read(two[first.packet_len..], 0)).long;
    try testing.expectEqual(sample_handshake.len, second.packet_len);
    // One octet short of what the Length counts.
    try testing.expectError(error.LengthPastDatagram, read(two[0 .. sample_handshake.len - 1], 0));
    try testing.expectError(error.Truncated, read(sample_handshake[0..10], 0));
}

test "§17.2.2: an Initial packet's token is read, and one past the datagram is truncated" {
    const initial = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 0, 3, 'a', 'b', 'c', 2, 7, 7 };
    const packet = (try read(&initial, 0)).long;
    try testing.expectEqual(LongType.initial, packet.type);
    try testing.expectEqualStrings("abc", packet.token);
    try testing.expectEqual(12, packet.packet_number_offset);
    try testing.expectEqual(initial.len, packet.packet_len);
    try testing.expectError(error.Truncated, read(initial[0..10], 0));
    // A Token Length of eight octets that names more than any datagram holds.
    const huge = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 0 } ++ [_]u8{0xff} ** 8 ++ [_]u8{ 1, 2, 3 };
    try testing.expectError(error.Truncated, read(&huge, 0));
    // A 0-RTT packet carries no token: the octet after the connection IDs is its Length.
    const zero_rtt = [_]u8{ 0xd0, 0, 0, 0, 1, 0, 0, 2, 7, 7 };
    try testing.expectEqual(0, (try read(&zero_rtt, 0)).long.token.len);
}

test "§17.2, §17.3.1: Reserved Bits that are set are refused once protection is removed" {
    try testing.expectEqual(4, try unprotected_long(0xc3));
    try testing.expectError(error.ReservedBitsSet, unprotected_long(0xc4));
    try testing.expectError(error.ReservedBitsSet, unprotected_long(0xc8));
    try testing.expectEqual(UnprotectedShort{ .packet_number_len = 3, .key_phase = false, .spin = false }, try unprotected_short(0x42));
    try testing.expectEqual(true, (try unprotected_short(0x44)).key_phase);
    try testing.expectError(error.ReservedBitsSet, unprotected_short(0x48));
    try testing.expectError(error.ReservedBitsSet, unprotected_short(0x50));
}

/// Most octets a fuzz input carries: a long header with both connection IDs at their longest.
const fuzz_input_len_max = 600;

fn fuzz_read(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const dcid_len = smith.valueRangeAtMost(u8, 0, constants.connection_id_len_max);
    const datagram = input[0..smith.slice(&input)];
    const packet = read(datagram, dcid_len) catch return;
    // Whatever was read lies inside the datagram, and a protected packet has room for the
    // Packet Number field's offset inside its own length.
    switch (packet) {
        .long => |long| {
            try testing.expect(long.packet_number_offset <= long.packet_len);
            try testing.expect(long.packet_len <= datagram.len);
            try testing.expect(@max(long.dcid.len, long.scid.len) <= constants.connection_id_len_max);
        },
        .short => |short| {
            try testing.expectEqual(1 + @as(usize, dcid_len), short.packet_number_offset);
            try testing.expectEqual(datagram.len, short.packet_len);
        },
        .retry => |retry| {
            try testing.expect(retry.token.len > 0);
            try testing.expectEqual(datagram.len, retry.without_tag.len + constants.retry_integrity_tag_len);
        },
        .version_negotiation => |negotiation| try testing.expect(negotiation.supported.count() > 0),
        .other_version => |other| try testing.expect(other.version != constants.version_1),
    }
}

test "fuzz: a packet that is read lies inside its datagram" {
    try testing.fuzz({}, fuzz_read, .{ .corpus = &.{
        core.fuzz.input_with_value(0, sample_retry),
        core.fuzz.input_with_value(0, sample_handshake),
        core.fuzz.input_with_value(2, &.{ 0x41, 0xaa, 0xbb, 0x01 }),
        core.fuzz.input_with_value(0, &.{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }),
    } });
    try core.fuzz.sweep(fuzz_read, .{ .min = 0, .max = 1 });
}
