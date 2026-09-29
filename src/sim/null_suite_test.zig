//! The tests of `null_suite.zig`, split out because a hand-written source file stays at or under
//! 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const crypto = @import("crypto");
const null_suite = @import("null_suite.zig");
const null_suite_keys = @import("null_suite_keys.zig");

const testing = std.testing;
const Level = crypto.suite.Level;
const Sealing = crypto.suite.Sealing;
const Opened = crypto.suite.Opened;
const KeySet = crypto.suite.KeySet;
const Version = crypto.suite.Version;
const NullSuite = null_suite.NullSuite;
const KeyState = null_suite.KeyState;
const tag_len = null_suite_keys.tag_len;
const sample_len = null_suite_keys.sample_len;
const sample_offset = null_suite_keys.sample_offset;

/// A client and a server over one connection ID, as the tests use them. Test-only.
const Pair = struct {
    client: NullSuite = .{},
    server: NullSuite = .{},

    fn init(pair: *Pair, dcid: []const u8) !void {
        try pair.client.suite().vtable.install_initial_keys(&pair.client, .client, dcid);
        try pair.server.suite().vtable.install_initial_keys(&pair.server, .server, dcid);
    }

    fn install(pair: *Pair, level: Level) void {
        pair.client.install(level);
        pair.server.install(level);
    }
};

/// RFC 9001 Appendix A.2's client Initial header, with its 4-octet packet number of 2, and a
/// short header over a 4-octet connection ID with a 2-octet packet number. Test-only.
const initial_header = "\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x44\x9e\x00\x00\x00\x02";
const short_header = "\x41\xaa\xbb\xcc\xdd\x9b\x32";
const short_header_phase_1 = "\x45\xaa\xbb\xcc\xdd\x9b\x33";
const sample_dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
const payload = "\x06\x00\x40\xf1\x01\x00\x00\xed\x03\x03\xeb\xf8\xfa\x56\xf1\x29\x39\xb9\x58\x4a";

/// Octets of the Packet Number field in each header above, the number the short one carries, and
/// the room the tests seal into. Test-only.
const initial_packet_number = 2;
const initial_packet_number_len = 4;
const short_packet_number_len = 2;
const short_packet_number = 0x9b32;
const sealed_len_max = 128;

/// Where the tests seal into, and open in place. Test-only.
var sealed: [sealed_len_max]u8 = @splat(0);

fn seal_initial(writer: *NullSuite, version: Version) ![]u8 {
    const len = try writer.suite().seal(.{
        .level = .initial,
        .version = version,
        .packet_number = initial_packet_number,
        .header = initial_header,
        .packet_number_len = initial_packet_number_len,
        .payload = payload,
    }, &sealed);
    return sealed[0..len];
}

fn seal_short(writer: *NullSuite, header: []const u8, packet_number: u64) ![]u8 {
    const len = try writer.suite().seal(.{
        .level = .application,
        .version = .v1,
        .packet_number = packet_number,
        .header = header,
        .packet_number_len = short_packet_number_len,
        .payload = payload,
    }, &sealed);
    return sealed[0..len];
}

fn open_initial(reader: *NullSuite, packet: []u8, version: Version) !Opened {
    return reader.suite().open(.{
        .level = .initial,
        .version = version,
        .packet = packet,
        .packet_number_offset = initial_header.len - initial_packet_number_len,
        .largest_packet_number = null,
    });
}

fn open_short(reader: *NullSuite, packet: []u8, largest: ?u64, lowest: ?u64) !Opened {
    return reader.suite().open(.{
        .level = .application,
        .version = .v1,
        .packet = packet,
        .packet_number_offset = short_header.len - short_packet_number_len,
        .largest_packet_number = largest,
        .current_phase_lowest = lowest,
    });
}

test "a sealed packet is its header, its payload and a 16-octet tag, and opens to the same octets" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    const packet = try seal_initial(&pair.client, .v1);
    try testing.expectEqual(initial_header.len + payload.len + tag_len, packet.len);
    // RFC 9001 §5.4.1: the mask covers four bits of a long header's byte 0 and the Packet Number
    // field, and nothing else of the header. The payload is copied.
    try testing.expectEqual(initial_header[0] & 0xf0, packet[0] & 0xf0);
    try testing.expectEqualSlices(u8, initial_header[1 .. initial_header.len - 4], packet[1 .. initial_header.len - 4]);
    try testing.expectEqualSlices(u8, payload, packet[initial_header.len..][0..payload.len]);
    try testing.expect(!std.mem.eql(u8, initial_header[initial_header.len - 4 ..], packet[initial_header.len - 4 ..][0..4]));
    const opened = try open_initial(&pair.server, packet, .v1);
    try testing.expectEqual(Opened{ .packet_number = 2, .packet_number_len = 4, .payload_len = payload.len, .key_set = .current }, opened);
    try testing.expectEqualSlices(u8, initial_header, packet[0..initial_header.len]);
}

test "§5.2: the Initial keys follow the connection ID and the role" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    var other: NullSuite = .{};
    try other.suite().vtable.install_initial_keys(&other, .server, "\x01\x02\x03\x04");
    var same_role: NullSuite = .{};
    try same_role.suite().vtable.install_initial_keys(&same_role, .client, sample_dcid);
    for ([_]*NullSuite{ &other, &same_role }) |reader| {
        try testing.expectError(error.Discarded, open_initial(reader, try seal_initial(&pair.client, .v1), .v1));
    }
    // A Retry changes the connection ID, and installing again changes the keys with it.
    try pair.server.suite().vtable.install_initial_keys(&pair.server, .server, "\x01\x02\x03\x04");
    try testing.expectError(error.Discarded, open_initial(&pair.server, try seal_initial(&pair.client, .v1), .v1));
}

test "RFC 9369 §3.3, §4.1: a packet sealed under one version's keys opens under that version's alone" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    // Neither has switched, so neither holds keys of version 2 (invariant 21).
    try testing.expectError(error.KeysUnavailable, seal_initial(&pair.client, .v2));
    try testing.expectError(error.KeysUnavailable, open_initial(&pair.server, try seal_initial(&pair.client, .v1), .v2));
    // The client switches, and a server that chose version 2 admits both at the Initial level.
    try pair.client.suite().vtable.switch_version(&pair.client, .v2);
    pair.server.versions = .{ .original = .v1, .negotiated = .v2 };
    _ = try open_initial(&pair.server, try seal_initial(&pair.client, .v2), .v2);
    try testing.expectError(error.Discarded, open_initial(&pair.server, try seal_initial(&pair.client, .v2), .v1));
    try testing.expectError(error.Discarded, open_initial(&pair.server, try seal_initial(&pair.client, .v1), .v2));
    try testing.expectEqual(1, pair.client.keys_unavailable);
    try testing.expectEqual(1, pair.server.keys_unavailable);
    // A client that holds the Handshake keys has read the server's CRYPTO octets, and switches no
    // more (RFC 9369 §4.1).
    var late: Pair = .{};
    try late.init(sample_dcid);
    late.install(.handshake);
    try testing.expectError(error.Refused, late.client.suite().vtable.switch_version(&late.client, .v2));
}

test "§4.9: a level with no keys, or with discarded ones, is refused by both calls" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    const vtable = pair.client.suite().vtable;
    try testing.expect(vtable.keys_available(&pair.client, .initial, .write));
    try testing.expect(!vtable.keys_available(&pair.client, .application, .read));
    try testing.expectError(error.KeysUnavailable, seal_short(&pair.client, short_header, 0x9b32));
    try testing.expectError(error.KeysUnavailable, vtable.update_keys(&pair.client));
    pair.install(.application);
    const packet = try seal_short(&pair.client, short_header, 0x9b32);
    vtable.discard_keys(&pair.server, .application);
    try testing.expectEqual(KeyState.discarded, pair.server.state_of(.application, .read));
    try testing.expectError(error.KeysUnavailable, open_short(&pair.server, packet, null, null));
    vtable.discard_keys(&pair.client, .initial);
    try testing.expectError(error.KeysUnavailable, seal_initial(&pair.client, .v1));
    // Invariant 21: each refusal is counted, three by the client and one by the server.
    try testing.expectEqual(3, pair.client.keys_unavailable);
    try testing.expectEqual(1, pair.server.keys_unavailable);
}

test "§5.5: a packet too short for the sample, or with any octet changed, is discarded" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    pair.install(.application);
    const whole = (try seal_short(&pair.client, short_header, 0x9b32)).len;
    // RFC 9001 §5.4.2: four octets past the Packet Number field, then sixteen of sample.
    const shortest = short_header.len - 2 + sample_offset + sample_len;
    try testing.expectError(error.Discarded, open_short(&pair.server, sealed[0 .. shortest - 1], null, null));
    for (0..whole) |index| {
        const packet = try seal_short(&pair.client, short_header, 0x9b32);
        // The Header Form bit decides how byte 0 is masked, and a long header is another packet.
        packet[index] ^= if (index == 0) 0x20 else 0x01;
        try testing.expectError(error.Discarded, open_short(&pair.server, packet, null, null));
    }
    const packet = try seal_short(&pair.client, short_header, 0x9b32);
    try testing.expectEqual(0x9b32, (try open_short(&pair.server, packet, null, null)).packet_number);
}

test "Appendix A.3: the packet number is recovered from the largest one processed" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    pair.install(.application);
    const packet = try seal_short(&pair.client, short_header, 0xa82f9b32);
    try testing.expectEqual(0xa82f9b32, (try open_short(&pair.server, packet, 0xa82f30ea, 0)).packet_number);
    // The same octets against another history are another number, which the tag refuses.
    const again = try seal_short(&pair.client, short_header, 0xa82f9b32);
    try testing.expectError(error.Discarded, open_short(&pair.server, again, 0x10, 0));
}

test "§6: a key update is detected as the next keys, answered, and leaves the old keys for a while" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    pair.install(.application);
    const client = pair.client.suite().vtable;
    const server = pair.server.suite().vtable;
    const delayed = try seal_short(&pair.client, short_header, 0x9b32);
    var kept: [sealed.len]u8 = undefined;
    @memcpy(kept[0..delayed.len], delayed);
    try client.update_keys(&pair.client);
    try testing.expect(client.key_phase(&pair.client) and !server.key_phase(&pair.server));
    // RFC 9001 §6.2: the bit differs and the number is not below the current phase, so the next
    // keys open it, and nothing moves until colibri answers.
    const updated = try seal_short(&pair.client, short_header_phase_1, 0x9b33);
    try testing.expectEqual(KeySet.next, (try open_short(&pair.server, updated, 0x9b32, 0x9b00)).key_set);
    try testing.expectEqual(0, pair.server.phase);
    try server.update_keys(&pair.server);
    try testing.expect(server.key_phase(&pair.server));
    // RFC 9001 §6.5: a packet the network delayed is below the new phase's lowest number, and the
    // previous keys open it, under the mask a key update never changes (§6.1).
    try testing.expectEqual(KeySet.previous, (try open_short(&pair.server, kept[0..delayed.len], 0x9b33, 0x9b33)).key_set);
    @memcpy(kept[0..delayed.len], try seal_short_phase_0(&pair));
    server.discard_previous_keys(&pair.server);
    try testing.expectError(error.Discarded, open_short(&pair.server, kept[0..delayed.len], 0x9b33, 0x9b33));
}

/// A packet sealed under the keys of phase 0 by a client that has since moved on. Test-only.
fn seal_short_phase_0(pair: *Pair) ![]u8 {
    var old: NullSuite = pair.client;
    old.phase = 0;
    return seal_short(&old, short_header, short_packet_number);
}

test "§6: the Key Phase bit repeats every second phase, and the keys do not" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    pair.install(.application);
    try pair.client.suite().vtable.update_keys(&pair.client);
    try pair.client.suite().vtable.update_keys(&pair.client);
    // Two phases on, the bit is 0 again, so a reader still in phase 0 picks its current keys,
    // and they are not the keys the packet was sealed under.
    try testing.expect(!pair.client.suite().vtable.key_phase(&pair.client));
    const packet = try seal_short(&pair.client, short_header, short_packet_number);
    try testing.expectError(error.Discarded, open_short(&pair.server, packet, null, 0));
}

test "§5.5, §6.3: a packet that seems to start a key update and fails its tag starts none" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    pair.install(.application);
    try pair.client.suite().vtable.update_keys(&pair.client);
    const forged = try seal_short(&pair.client, short_header_phase_1, 0x9b33);
    forged[forged.len - 1] ^= 0x01;
    try testing.expectError(error.Discarded, open_short(&pair.server, forged, 0x9b32, 0x9b00));
    try testing.expectEqual(0, pair.server.phase);
    try testing.expect(!pair.server.previous_held);
}

test "§6.6: both limits are reached at the number set, and a seal that fails costs nothing" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    pair.install(.application);
    pair.client.seals_left = 1;
    var small: [8]u8 = undefined;
    const sealing: Sealing = .{ .level = .application, .version = .v1, .packet_number = 1, .header = short_header, .packet_number_len = 2, .payload = payload };
    try testing.expectError(error.NoSpaceLeft, pair.client.suite().vtable.seal(&pair.client, sealing, &small));
    try testing.expectEqual(1, pair.client.seals_left);
    const packet = try seal_short(&pair.client, short_header, 0x9b32);
    try testing.expectError(error.ConfidentialityLimitReached, seal_short(&pair.client, short_header, 0x9b33));
    pair.server.open_failures_left = 1;
    packet[packet.len - 1] ^= 0x01;
    try testing.expectError(error.Discarded, open_short(&pair.server, packet, null, null));
    try testing.expectError(error.IntegrityLimitReached, open_short(&pair.server, packet, null, null));
}

test "invariant 25: a suite that refuses the Initial keys installs none" {
    var refusing: NullSuite = .{ .refuses_initial_keys = true };
    const vtable = refusing.suite().vtable;
    try testing.expectError(error.Unsupported, vtable.install_initial_keys(&refusing, .client, sample_dcid));
    try testing.expect(!vtable.keys_available(&refusing, .initial, .write));
}
