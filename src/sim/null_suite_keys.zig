//! The null suite's keys. A key here is a name, a 32-bit checksum of what a real key would be
//! derived from, and this file holds everything done with one: the tag a sealed packet ends
//! with, the mask over its header, and which key set opens a 1-RTT packet. Split off
//! `null_suite.zig` for length. None of it is cryptography: the tag detects a changed octet and
//! proves nothing else, and the mask hides nothing from anyone who reads this file. Every integer
//! is taken octet by octet in network order, so one host's octets are every host's (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("crypto");

const Crc32 = std.hash.Crc32;
const Level = crypto.suite.Level;
const Role = crypto.suite.Role;
const KeySet = crypto.suite.KeySet;

/// Whether a level has keys in one direction.
pub const KeyState = enum { none, available, discarded };

/// The name of the key a packet's tag is computed under: the level, who wrote the packet, and at
/// the application level the key phase. At the Initial level it carries the name of the
/// connection ID the keys were installed from (RFC 9001 §5.2).
pub fn key_name(level: Level, writer: Role, phase: u32, initial_name: u32) u32 {
    var crc = Crc32.init();
    crc.update(&.{ @intFromEnum(level), @intFromEnum(writer) });
    if (level == .initial) crc.update(std.mem.asBytes(&std.mem.nativeToBig(u32, initial_name)));
    if (level == .application) crc.update(std.mem.asBytes(&std.mem.nativeToBig(u32, phase)));
    return crc.final();
}

/// RFC 9001 §6: the Key Phase bit starts at 0 and is toggled by each key update.
pub fn phase_bit(phase: u32) bool {
    return @as(u1, @truncate(phase)) == 1;
}

/// What a 1-RTT packet's key set is chosen from.
pub const Selection = struct {
    /// Byte 0 of the packet, unmasked.
    first_octet: u8,
    packet_number: u64,
    /// The reader's key phase, and whether it still holds the read keys of the phase before.
    phase: u32,
    previous_held: bool,
    /// The lowest packet number processed under the current phase, or null before any.
    current_phase_lowest: ?u64,
};

/// Which keys a 1-RTT packet is opened with, or null when they are not held. RFC 9001 §6.5: the
/// Key Phase bit picks the phase, and when it differs from the current one the packet number
/// decides between the phase before and the phase after.
pub fn key_set_of(selection: Selection) ?KeySet {
    const bit = selection.first_octet & crypto.constants.key_phase_bit != 0;
    if (bit == phase_bit(selection.phase)) return .current;
    const lowest = selection.current_phase_lowest orelse std.math.maxInt(u64);
    if (selection.packet_number >= lowest) return .next;
    return if (selection.previous_held and selection.phase > 0) .previous else null;
}

pub const tag_len = crypto.constants.aead_tag_len;
pub const sample_len = crypto.constants.header_protection_sample_len;
pub const sample_offset = crypto.constants.header_protection_sample_offset;
pub const mask_len = crypto.constants.header_protection_mask_len;

/// Four CRC-32s over the key's name, the packet number and the packet, each seeded differently.
/// `header_len` is part of what is checked, so moving an octet across the boundary changes it.
pub fn write_tag(tag: *[tag_len]u8, name: u32, packet_number: u64, packet: []const u8, header_len: usize) void {
    const words = tag_len / @sizeOf(u32);
    for (0..words) |index| {
        var crc = Crc32.init();
        crc.update(&.{@intCast(index)});
        crc.update(std.mem.asBytes(&std.mem.nativeToBig(u32, name)));
        crc.update(std.mem.asBytes(&std.mem.nativeToBig(u64, packet_number)));
        crc.update(std.mem.asBytes(&std.mem.nativeToBig(u64, header_len)));
        crc.update(packet);
        const word = std.mem.nativeToBig(u32, crc.final());
        @memcpy(tag[index * @sizeOf(u32) ..][0..@sizeOf(u32)], std.mem.asBytes(&word));
    }
}

/// The mask of a packet whose Packet Number field starts at `offset`: the first octets of the
/// sample RFC 9001 §5.4.2 places four octets past the field, under the name of the header
/// protection key.
pub fn mask_of(name: u32, packet: []const u8, offset: usize) [mask_len]u8 {
    assert(packet.len >= offset + sample_offset + sample_len);
    const sample = packet[offset + sample_offset ..][0..sample_len];
    const name_octets = std.mem.asBytes(&std.mem.nativeToBig(u32, name));
    var mask: [mask_len]u8 = undefined;
    for (&mask, 0..) |*octet, index| octet.* = sample[index] ^ name_octets[index % name_octets.len];
    return mask;
}

/// RFC 9001 §5.4.1: header protection covers four bits of a long header's byte 0 and five of a
/// short one's, and never the Header Form bit that says which.
pub fn protected_bits_of(first_octet: u8) u8 {
    const long = first_octet & crypto.constants.header_form_bit != 0;
    return if (long) crypto.constants.long_header_protected_bits else crypto.constants.short_header_protected_bits;
}

/// Masks byte 0 and the Packet Number field in place.
pub fn apply_mask(packet: []u8, offset: usize, packet_number_len: u8, mask: [mask_len]u8) void {
    assert(offset + packet_number_len <= packet.len);
    packet[0] ^= mask[0] & protected_bits_of(packet[0]);
    for (packet[offset..][0..packet_number_len], mask[1..][0..packet_number_len]) |*octet, mask_octet| {
        octet.* ^= mask_octet;
    }
}

const testing = std.testing;

test "the tag covers the name, the packet number, the header's length and every octet" {
    var first: [tag_len]u8 = undefined;
    var other: [tag_len]u8 = undefined;
    write_tag(&first, 7, 2, "header and payload", 6);
    write_tag(&other, 7, 2, "header and payload", 6);
    try testing.expectEqualSlices(u8, &first, &other);
    write_tag(&other, 8, 2, "header and payload", 6);
    try testing.expect(!std.mem.eql(u8, &first, &other));
    write_tag(&other, 7, 3, "header and payload", 6);
    try testing.expect(!std.mem.eql(u8, &first, &other));
    // The same octets with the header one octet longer are another packet.
    write_tag(&other, 7, 2, "header and payload", 7);
    try testing.expect(!std.mem.eql(u8, &first, &other));
    write_tag(&other, 7, 2, "header and paylaod", 6);
    try testing.expect(!std.mem.eql(u8, &first, &other));
    // The four words differ from each other, so the tag is not one checksum written four times.
    try testing.expect(!std.mem.eql(u8, first[0..4], first[4..8]));
}

test "§5.4.1: the mask covers four bits of a long header's byte 0 and five of a short one's" {
    const mask: [mask_len]u8 = @splat(0xff);
    var long = "\xc3\x01\x02\x03\x04".*;
    apply_mask(&long, 1, 4, mask);
    try testing.expectEqualSlices(u8, "\xcc\xfe\xfd\xfc\xfb", &long);
    var short = "\x41\xaa\x01\x02".*;
    apply_mask(&short, 2, 2, mask);
    // The connection ID between byte 0 and the Packet Number field is left alone.
    try testing.expectEqualSlices(u8, "\x5e\xaa\xfe\xfd", &short);
    // Applying it twice gives the octets back, which is how a receiver removes it.
    apply_mask(&short, 2, 2, mask);
    try testing.expectEqualSlices(u8, "\x41\xaa\x01\x02", &short);
}

test "§5.4.2: the sample starts four octets past the start of the Packet Number field" {
    // Twenty-two octets: a one-octet header, then the field at offset 1, so the sample is the
    // sixteen octets from offset 5.
    const packet = "\x40\x01\x02\x03\x04" ++ "\xa0\xa1\xa2\xa3\xa4" ++ "\x00" ** 12;
    const mask = mask_of(0, packet, 1);
    try testing.expectEqualSlices(u8, "\xa0\xa1\xa2\xa3\xa4", &mask);
    // The name of the header protection key is folded in, octet by octet, in network order.
    const named = mask_of(0x01020304, packet, 1);
    try testing.expectEqualSlices(u8, "\xa1\xa3\xa1\xa7\xa5", &named);
}

test "§6.5: the bit picks the phase, and the packet number picks between the one before and after" {
    const base: Selection = .{ .first_octet = 0x44, .packet_number = 9, .phase = 1, .previous_held = true, .current_phase_lowest = 10 };
    try testing.expectEqual(KeySet.current, key_set_of(base).?);
    var other = base;
    other.first_octet = 0x40;
    // Below the current phase's lowest number it is a delayed packet of the phase before.
    try testing.expectEqual(KeySet.previous, key_set_of(other).?);
    other.packet_number = 10;
    try testing.expectEqual(KeySet.next, key_set_of(other).?);
    // Nothing processed in the current phase yet, so nothing can be past it.
    other.current_phase_lowest = null;
    try testing.expectEqual(KeySet.previous, key_set_of(other).?);
    other.previous_held = false;
    try testing.expectEqual(null, key_set_of(other));
    // Phase 0 has no phase before it.
    other = .{ .first_octet = 0x44, .packet_number = 1, .phase = 0, .previous_held = true, .current_phase_lowest = 5 };
    try testing.expectEqual(null, key_set_of(other));
}

test "a key's name tells levels, writers, phases and connection IDs apart, and nothing else" {
    const name = key_name(.application, .client, 1, 7);
    try testing.expect(name != key_name(.application, .server, 1, 7));
    try testing.expect(name != key_name(.application, .client, 2, 7));
    try testing.expect(name != key_name(.handshake, .client, 1, 7));
    // RFC 9001 §6.1: only 1-RTT keys have phases, and only Initial keys follow a connection ID.
    try testing.expectEqual(name, key_name(.application, .client, 1, 8));
    try testing.expectEqual(key_name(.handshake, .client, 0, 7), key_name(.handshake, .client, 5, 8));
    try testing.expect(key_name(.initial, .client, 0, 7) != key_name(.initial, .client, 0, 8));
}
