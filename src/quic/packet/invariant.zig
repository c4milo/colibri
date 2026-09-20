//! The version-independent packet reader: RFC 8999 and nothing else (invariant 22). It reads what
//! every version of QUIC promises to keep, which is what an endpoint may rely on before it knows
//! the version: the Header Form bit, and in a long header the Version and both connection IDs
//! (RFC 8999 §5.1). It also reads and writes the Version Negotiation packet, which §6 defines for
//! all versions.
//!
//! This file imports `std` and `core` and nothing else, and `packet_header.zig` holds a comptime
//! assert that says so. It has no access to a version-1 constant, so it cannot apply a version-1
//! rule by accident. The rule that matters is RFC 9000's 20-octet connection ID maximum: RFC 9000
//! §17.2.1 forbids a version-specific rule from deciding whether a Version Negotiation packet is
//! sent, so a long header of an unknown version with a 255-octet connection ID parses here.
//!
//! It reads one packet and stops. RFC 8999 §5 scopes the invariants to the first packet of a
//! datagram, and the Length field that finds a second one is version 1's (RFC 9000 §12.2).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

const Reader = core.Reader;
const Writer = core.Writer;

/// RFC 8999 §5: the most significant bit of the first octet is set in a long header and clear in
/// a short one.
const header_form_bit: u8 = 0x80;

/// RFC 8999 §6: the seven bits of a Version Negotiation packet's first octet that carry no
/// meaning.
const unused_bits_mask: u8 = 0x7f;

/// RFC 8999 §5.4: a Version field of 0x00000000 is reserved for version negotiation.
pub const version_negotiation: u32 = 0;

/// Octets of one Version or Supported Version field (RFC 8999 §5.1, §6).
pub const version_len: usize = @sizeOf(u32);

/// Octets of the first octet of any packet, which carries the Header Form bit (RFC 8999 §5).
pub const first_octet_len: usize = 1;

/// Octets of the length that precedes a connection ID in a long header (RFC 8999 §5.1).
pub const connection_id_length_len: usize = 1;

pub const Form = enum { long, short };

/// Why a read stopped. A datagram is hostile input, so every one is a value and none asserts.
pub const Error = error{
    /// The header runs past the end of the datagram.
    Truncated,
    /// The first octet's Header Form bit names the other form (RFC 8999 §5).
    WrongForm,
    /// RFC 8999 §6: a Version Negotiation packet with no Supported Version field MUST be ignored.
    NoSupportedVersion,
    /// RFC 8999 §6: one with a truncated Supported Version value MUST be ignored.
    TruncatedSupportedVersion,
};

/// The form the first octet of a packet names (RFC 8999 §5).
pub fn form_of(first_octet: u8) Form {
    return if (first_octet & header_form_bit != 0) .long else .short;
}

/// A long header as RFC 8999 §5.1 fixes it. Every slice points into the datagram.
pub const Long = struct {
    /// The whole first octet. Its low seven bits are version specific.
    first_octet: u8,
    version: u32,
    /// The Destination Connection ID, 0 to 255 octets.
    dcid: []const u8,
    /// The Source Connection ID, 0 to 255 octets.
    scid: []const u8,
    /// Everything after the Source Connection ID, which the version defines.
    rest: []const u8,

    /// RFC 8999 §6: a Version Negotiation packet is identifiable by its Version field of 0.
    pub fn is_version_negotiation(long: Long) bool {
        return long.version == version_negotiation;
    }

    /// Octets from the start of the packet to the start of `rest`.
    pub fn header_len(long: Long) usize {
        return @sizeOf(u8) + version_len + @sizeOf(u8) + long.dcid.len + @sizeOf(u8) + long.scid.len;
    }
};

/// Reads the long header at the start of `datagram`.
pub fn read_long(datagram: []const u8) Error!Long {
    var reader = Reader.init(datagram);
    const first_octet = reader.read_byte() catch return error.Truncated;
    // RFC 8999 §5.1: a long header has the high bit of the first byte set to 1.
    if (form_of(first_octet) != .long) return error.WrongForm;
    const version = reader.read_int(u32) catch return error.Truncated;
    // RFC 8999 §5.1: each connection ID follows a one-octet length, so it is 0 to 255 octets and
    // no length the octet can carry is refused here.
    const dcid = read_connection_id(&reader) catch return error.Truncated;
    const scid = read_connection_id(&reader) catch return error.Truncated;
    const long: Long = .{
        .first_octet = first_octet,
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .rest = reader.take_rest(),
    };
    assert(long.header_len() + long.rest.len == datagram.len);
    return long;
}

/// One connection ID after its length octet (RFC 8999 §5.1).
fn read_connection_id(reader: *Reader) core.reader.Error![]const u8 {
    const len = try reader.read_byte();
    return reader.take(len);
}

/// A short header as RFC 8999 §5.2 fixes it.
pub const Short = struct {
    /// The whole first octet. Its low seven bits are version specific.
    first_octet: u8,
    dcid: []const u8,
    /// Everything after the Destination Connection ID, which the version defines.
    rest: []const u8,
};

/// Reads the short header at the start of `datagram`. RFC 8999 §5.2 does not encode the length
/// of the Destination Connection ID, so the caller passes the length it issued.
pub fn read_short(datagram: []const u8, dcid_len: usize) Error!Short {
    var reader = Reader.init(datagram);
    const first_octet = reader.read_byte() catch return error.Truncated;
    // RFC 8999 §5.2: a short header has the high bit of the first byte set to 0.
    if (form_of(first_octet) != .short) return error.WrongForm;
    const dcid = reader.take(dcid_len) catch return error.Truncated;
    return .{ .first_octet = first_octet, .dcid = dcid, .rest = reader.take_rest() };
}

/// The Supported Version fields of a Version Negotiation packet (RFC 8999 §6).
pub const SupportedVersions = struct {
    /// A whole number of Version fields, and at least one.
    octets: []const u8,

    pub fn count(versions: SupportedVersions) usize {
        return versions.octets.len / version_len;
    }

    /// The Supported Version at `index`, in the order the sender wrote them.
    pub fn at(versions: SupportedVersions, index: usize) u32 {
        assert(index < versions.count());
        var reader = Reader.init(versions.octets[index * version_len ..]);
        return reader.read_int(u32) catch unreachable;
    }

    pub fn contains(versions: SupportedVersions, version: u32) bool {
        for (0..versions.count()) |index| {
            if (versions.at(index) == version) return true;
        }
        return false;
    }
};

/// Reads the Supported Version list of a Version Negotiation packet, which is all of `long.rest`.
pub fn read_supported_versions(long: Long) Error!SupportedVersions {
    assert(long.is_version_negotiation());
    // RFC 8999 §6: an endpoint MUST ignore a packet that contains no Supported Version fields.
    if (long.rest.len == 0) return error.NoSupportedVersion;
    // RFC 8999 §6: or one that contains a truncated Supported Version value.
    if (long.rest.len % version_len != 0) return error.TruncatedSupportedVersion;
    return .{ .octets = long.rest };
}

/// Writes a Version Negotiation packet (RFC 8999 §6). `unused_bits` are the seven bits of the
/// first octet the RFC leaves to the sender. `received` is the long header being answered.
pub fn write_version_negotiation(
    writer: *Writer,
    unused_bits: u7,
    received: Long,
    supported: []const u32,
) core.writer.Error!void {
    assert(supported.len > 0);
    assert(!received.is_version_negotiation());
    var copy = writer.*;
    try copy.write_byte(header_form_bit | (@as(u8, unused_bits) & unused_bits_mask));
    try copy.write_int(u32, version_negotiation);
    // RFC 8999 §6: the Destination Connection ID carries the Source Connection ID of the packet
    // received, and the Source Connection ID carries its Destination Connection ID.
    try write_connection_id(&copy, received.scid);
    try write_connection_id(&copy, received.dcid);
    for (supported) |version| try copy.write_int(u32, version);
    assert(copy.written().len - writer.written().len ==
        version_negotiation_len(received, supported.len));
    writer.* = copy;
}

/// Octets `write_version_negotiation` writes when it answers `received` with `supported_count`
/// versions (RFC 8999 §6). Both connection IDs are `received`'s, swapped, so their lengths are
/// the ones that arrived and not any this endpoint's version would allow.
pub fn version_negotiation_len(received: Long, supported_count: usize) usize {
    assert(supported_count > 0);
    return first_octet_len + version_len +
        connection_id_length_len + received.scid.len +
        connection_id_length_len + received.dcid.len +
        supported_count * version_len;
}

/// One connection ID after its length octet (RFC 8999 §5.1).
pub fn write_connection_id(writer: *Writer, connection_id: []const u8) core.writer.Error!void {
    assert(connection_id.len <= std.math.maxInt(u8));
    try writer.write_byte(@intCast(connection_id.len));
    try writer.write_bytes(connection_id);
}

const testing = std.testing;

/// A long header of an unknown version whose connection IDs are 255 and 21 octets. Test-only.
const long_connection_ids = "\xc5\xfa\xce\xb0\x0c\xff" ++ "\xd1" ** long_dcid_len ++ "\x15" ++
    "\x5c" ** long_scid_len ++ "\x01\x02\x03";

/// The longest connection ID a length octet carries, and one octet past version 1's. Test-only.
const long_dcid_len = 255;
const long_scid_len = 21;

test "§5.1: a long header of an unknown version parses with connection IDs past 20 octets" {
    const long = try read_long(long_connection_ids);
    try testing.expectEqual(0xc5, long.first_octet);
    try testing.expectEqual(0xfaceb00c, long.version);
    try testing.expectEqual(255, long.dcid.len);
    try testing.expectEqual(21, long.scid.len);
    try testing.expectEqual(0xd1, long.dcid[254]);
    try testing.expectEqual(0x5c, long.scid[0]);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, long.rest);
    try testing.expect(!long.is_version_negotiation());
}

test "§5.1: a long header cut anywhere before its end is truncated" {
    const header_len = (try read_long(long_connection_ids)).header_len();
    for (0..header_len) |len| {
        try testing.expectError(error.Truncated, read_long(long_connection_ids[0..len]));
    }
    const whole = try read_long(long_connection_ids[0..header_len]);
    try testing.expectEqual(0, whole.rest.len);
}

test "§5: the Header Form bit picks the reader, and the other reader refuses" {
    try testing.expectEqual(Form.long, form_of(0x80));
    try testing.expectEqual(Form.short, form_of(0x7f));
    try testing.expectError(error.WrongForm, read_long(&.{ 0x40, 0, 0, 0, 1, 0, 0 }));
    try testing.expectError(error.WrongForm, read_short(long_connection_ids, 4));
}

test "§5.2: a short header carries a connection ID of the length the caller issued" {
    const datagram = [_]u8{ 0x41, 0xaa, 0xbb, 0xcc, 0xdd, 0x99 };
    const short = try read_short(&datagram, 4);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, short.dcid);
    try testing.expectEqualSlices(u8, &.{0x99}, short.rest);
    // A zero-length connection ID leaves everything after the first octet to the version.
    try testing.expectEqual(5, (try read_short(&datagram, 0)).rest.len);
    try testing.expectError(error.Truncated, read_short(&datagram, 6));
    try testing.expectError(error.Truncated, read_short(&.{}, 0));
}

test "§6: a Version Negotiation packet echoes the connection IDs, swapped" {
    const received = try read_long(long_connection_ids);
    var buffer: [512]u8 = undefined;
    var writer = Writer.init(&buffer);
    try write_version_negotiation(&writer, 0x40, received, &.{ 0x00000001, 0xff00001d });
    const answer = try read_long(writer.written());
    try testing.expect(answer.is_version_negotiation());
    try testing.expectEqual(0xc0, answer.first_octet);
    try testing.expectEqualSlices(u8, received.scid, answer.dcid);
    try testing.expectEqualSlices(u8, received.dcid, answer.scid);
    const versions = try read_supported_versions(answer);
    try testing.expectEqual(2, versions.count());
    try testing.expectEqual(0x00000001, versions.at(0));
    try testing.expectEqual(0xff00001d, versions.at(1));
    try testing.expect(versions.contains(0xff00001d) and !versions.contains(2));
    // A buffer one octet short takes nothing.
    var short_writer = Writer.init(buffer[0 .. writer.written().len - 1]);
    try testing.expectError(error.NoSpaceLeft, write_version_negotiation(&short_writer, 0, received, &.{ 1, 2 }));
    try testing.expectEqual(0, short_writer.written().len);
}

test "§6: a list that is empty or holds a cut version is ignored" {
    const header = [_]u8{ 0x80, 0, 0, 0, 0, 1, 0xaa, 1, 0xbb };
    try testing.expectError(error.NoSupportedVersion, read_supported_versions(try read_long(&header)));
    for (1..version_len) |extra| {
        const cut = header ++ [_]u8{ 0, 0, 0, 1 } ++ [_]u8{0} ** version_len;
        const long = try read_long(cut[0 .. header.len + version_len + extra]);
        try testing.expectError(error.TruncatedSupportedVersion, read_supported_versions(long));
    }
    // RFC 8999 §6: the seven unused bits MUST be ignored on receipt.
    const any_bits = [_]u8{ 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectEqual(1, (try read_supported_versions(try read_long(&any_bits))).count());
}

/// Most octets a fuzz input carries: a long header with both connection IDs at their longest.
const fuzz_input_len_max = 600;

fn fuzz_read(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const datagram = input[0..smith.slice(&input)];
    const long = read_long(datagram) catch |failure| {
        const short_form = datagram.len > 0 and form_of(datagram[0]) == .short;
        try testing.expectEqual(if (short_form) error.WrongForm else error.Truncated, failure);
        return;
    };
    // Every octet of the datagram is in exactly one field.
    try testing.expectEqual(datagram.len, long.header_len() + long.rest.len);
    if (!long.is_version_negotiation()) return;
    const versions = read_supported_versions(long) catch return;
    try testing.expectEqual(long.rest.len, versions.count() * version_len);
}

test "fuzz: a long header accounts for every octet or is refused" {
    try testing.fuzz({}, fuzz_read, .{ .corpus = &.{
        core.fuzz.input(long_connection_ids),
        core.fuzz.input(&.{ 0x80, 0, 0, 0, 0, 1, 0xaa, 1, 0xbb, 0, 0, 0, 1 }),
        core.fuzz.input(&.{0xc0}),
    } });
    try core.fuzz.sweep(fuzz_read, null);
}
