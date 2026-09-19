//! A `crypto.Suite` that performs no cryptography (decisions 9, 10 and 48, design §10). It is
//! test-only, lives in `src/sim/` and is never packaged: colibri's library carries no
//! implementation of either vtable and never will (CLAUDE.md non-negotiable 2).
//!
//! What it is for is the shape and the rules, not the secrecy. It is size-faithful: a sealed packet
//! is its header, its payload and a 16-octet tag, and byte 0 and the Packet Number field are masked
//! from a 16-octet sample that starts four octets past the field (RFC 9001 §5.3, §5.4.2). So the
//! Length of a long header, the 1200-octet minimum of RFC 9000 §14.1 and the anti-amplification
//! count all see the sizes a real suite produces. The payload itself is copied, not encrypted, so
//! a trace stays readable.
//!
//! It models keys as names, because colibri's connection logic is checked against it:
//!   - a level has keys in a direction, or never had them, or had them discarded (§4.9);
//!   - the Initial keys are a function of the role and of the connection ID they were installed
//!     from, so a packet sealed under one connection ID does not open under another (§5.2), and a
//!     client's packet does not open with a client's read keys;
//!   - a key update moves both directions to the next phase, keeps the previous read keys until
//!     colibri drops them, and changes what the tag is computed under while it leaves the mask
//!     alone, which is how the header protection key survives an update (§5.4, §6.1);
//!   - both AEAD limits of §6.6 exist, at numbers a test sets.
//! A tag is four CRC-32s over the key's name, the packet number, the header and the payload. It
//! detects a changed octet and proves nothing else.
//!
//! It reads no clock, draws no random number and allocates nothing, so one seed replays byte for
//! byte (invariants 4, 5 and 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("constants.zig");

const Crc32 = std.hash.Crc32;
const Level = crypto.suite.Level;
const Direction = crypto.suite.Direction;
const Role = crypto.suite.Role;
const KeySet = crypto.suite.KeySet;
const Sealing = crypto.suite.Sealing;
const Opening = crypto.suite.Opening;
const Opened = crypto.suite.Opened;

const null_suite_keys = @import("null_suite_keys.zig");

const tag_len = null_suite_keys.tag_len;
const sample_len = null_suite_keys.sample_len;
const sample_offset = null_suite_keys.sample_offset;
const mask_len = null_suite_keys.mask_len;
const write_tag = null_suite_keys.write_tag;
const apply_mask = null_suite_keys.apply_mask;
const protected_bits_of = null_suite_keys.protected_bits_of;

pub const KeyState = null_suite_keys.KeyState;

/// One endpoint's null suite, in storage the test places.
pub const NullSuite = struct {
    role: Role = .client,
    /// The state of each level's keys, by level and then by direction.
    keys: [crypto.suite.levels_count][crypto.suite.directions_count]KeyState = @splat(@splat(.none)),
    /// The name of the Initial keys: a checksum of the connection ID they were installed from.
    initial_name: u32 = 0,
    /// The key phase, which both directions share because an update moves both (RFC 9001 §6.1).
    phase: u32 = 0,
    /// Whether the read keys of the phase before are still held (RFC 9001 §6.5).
    previous_held: bool = false,
    /// Packets each limit of RFC 9001 §6.6 still permits. A test lowers one to reach it.
    seals_left: u64 = std.math.maxInt(u64),
    open_failures_left: u64 = std.math.maxInt(u64),
    /// Makes `install_initial_keys` refuse, as a suite without AES would (invariant 25).
    refuses_initial_keys: bool = false,
    /// Makes `retry_tag_write` refuse, as a suite written for clients alone would.
    writes_retry_tag: bool = true,

    pub fn suite(self: *NullSuite) crypto.Suite {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    /// Makes the keys of `level` available in both directions, which is what the TLS handshake
    /// does as it reaches the level (RFC 9001 §4.1.4). The simulator calls it; colibri cannot.
    pub fn install(self: *NullSuite, level: Level) void {
        assert(level != .initial);
        for (&self.keys[@intFromEnum(level)]) |*state| {
            assert(state.* == .none);
            state.* = .available;
        }
    }

    pub fn state_of(self: *const NullSuite, level: Level, direction: Direction) KeyState {
        return self.keys[@intFromEnum(level)][@intFromEnum(direction)];
    }

    /// The name of the key `writer` protects a packet with at `level` and `phase`.
    fn key_name(self: *const NullSuite, level: Level, writer: Role, phase: u32) u32 {
        return null_suite_keys.key_name(level, writer, phase, self.initial_name);
    }

    /// The mask of a packet, under a name that leaves the key phase out, because a key update
    /// never changes the header protection key (RFC 9001 §6.1).
    fn mask_of(self: *const NullSuite, level: Level, writer: Role, packet: []const u8, offset: usize) [mask_len]u8 {
        return null_suite_keys.mask_of(self.key_name(level, writer, 0), packet, offset);
    }

    /// Which keys a packet is opened with, or null when they are not held (RFC 9001 §6.5).
    fn key_set_of(self: *const NullSuite, opening: Opening, packet_number: u64) ?KeySet {
        if (opening.level != .application) return .current;
        return null_suite_keys.key_set_of(.{
            .first_octet = opening.packet[0],
            .packet_number = packet_number,
            .phase = self.phase,
            .previous_held = self.previous_held,
            .current_phase_lowest = opening.current_phase_lowest,
        });
    }

    /// Counts a packet that failed authentication (RFC 9001 §6.6) and says what `open` answers.
    fn count_failure(self: *NullSuite) crypto.suite.OpenError {
        if (self.open_failures_left == 0) return error.IntegrityLimitReached;
        self.open_failures_left -= 1;
        return error.Discarded;
    }
};

const table: crypto.suite.VTable = .{
    .install_initial_keys = install_initial_keys,
    .keys_available = keys_available,
    .seal = seal,
    .open = open,
    .retry_tag_valid = retry_tag_valid,
    .retry_tag_write = retry_tag_write,
    .update_keys = update_keys,
    .key_phase = key_phase,
    .discard_previous_keys = discard_previous_keys,
    .discard_keys = discard_keys,
};

fn from(context: *anyopaque) *NullSuite {
    return @ptrCast(@alignCast(context));
}

fn from_const(context: *const anyopaque) *const NullSuite {
    return @ptrCast(@alignCast(context));
}

fn install_initial_keys(context: *anyopaque, role: Role, dcid: []const u8) crypto.suite.InstallError!void {
    const self = from(context);
    if (self.refuses_initial_keys) return error.Unsupported;
    self.role = role;
    // RFC 9001 §5.2: the Initial keys derive from the Destination Connection ID, so a Retry, which
    // changes it, changes them.
    self.initial_name = Crc32.hash(dcid);
    self.keys[@intFromEnum(Level.initial)] = @splat(.available);
}

fn keys_available(context: *const anyopaque, level: Level, direction: Direction) bool {
    return from_const(context).state_of(level, direction) == .available;
}

fn seal(context: *anyopaque, sealing: Sealing, output: []u8) crypto.suite.SealError!usize {
    const self = from(context);
    if (self.state_of(sealing.level, .write) != .available) return error.KeysUnavailable;
    // RFC 9001 §6.6: past the confidentiality limit the keys protect nothing more.
    if (self.seals_left == 0) return error.ConfidentialityLimitReached;
    const header_len = sealing.header.len;
    const written = header_len + sealing.payload.len + tag_len;
    if (output.len < written) return error.NoSpaceLeft;
    self.seals_left -= 1;
    @memcpy(output[0..header_len], sealing.header);
    @memcpy(output[header_len..][0..sealing.payload.len], sealing.payload);
    const name = self.key_name(sealing.level, self.role, self.phase);
    write_tag(output[written - tag_len ..][0..tag_len], name, sealing.packet_number, output[0 .. written - tag_len], header_len);
    // RFC 9001 §5.4: header protection is applied after packet protection, over byte 0 and the
    // Packet Number field, from a sample of the protected payload.
    const packet_number_offset = header_len - sealing.packet_number_len;
    const mask = self.mask_of(sealing.level, self.role, output[0..written], packet_number_offset);
    apply_mask(output[0..written], packet_number_offset, sealing.packet_number_len, mask);
    return written;
}

fn open(context: *anyopaque, opening: Opening) crypto.suite.OpenError!Opened {
    const self = from(context);
    if (self.state_of(opening.level, .read) != .available) return error.KeysUnavailable;
    const packet = opening.packet;
    const offset = opening.packet_number_offset;
    // RFC 9001 §5.4.2: a packet too short for the sample is discarded before it is read.
    if (packet.len < offset + sample_offset + sample_len) return error.Discarded;
    // The peer wrote the packet, so the mask and the tag are under the peer's names.
    const mask = self.mask_of(opening.level, self.role.peer(), packet, offset);
    packet[0] ^= mask[0] & protected_bits_of(packet[0]);
    const packet_number_len = (packet[0] & crypto.constants.packet_number_len_mask) + 1;
    for (packet[offset..][0..packet_number_len], mask[1..][0..packet_number_len]) |*octet, mask_octet| {
        octet.* ^= mask_octet;
    }
    var reader = core.Reader.init(packet[offset..]);
    const truncated = crypto.packet_number.read(&reader, packet_number_len) catch unreachable;
    const packet_number = crypto.packet_number.decode(opening.largest_packet_number, truncated);
    const key_set = self.key_set_of(opening, packet_number) orelse return self.count_failure();
    const phase = switch (key_set) {
        .previous => self.phase - 1,
        .current => self.phase,
        .next => self.phase + 1,
    };
    const header_len = offset + packet_number_len;
    var expected: [tag_len]u8 = undefined;
    write_tag(&expected, self.key_name(opening.level, self.role.peer(), phase), packet_number, packet[0 .. packet.len - tag_len], header_len);
    if (!std.mem.eql(u8, &expected, packet[packet.len - tag_len ..])) return self.count_failure();
    return .{
        .packet_number = packet_number,
        .packet_number_len = packet_number_len,
        .payload_len = packet.len - tag_len - header_len,
        .key_set = key_set,
    };
}

fn retry_tag_valid(context: *const anyopaque, pseudo_packet: []const u8, tag: *const [tag_len]u8) bool {
    _ = context;
    var expected: [tag_len]u8 = undefined;
    write_tag(&expected, constants.null_suite_retry_name, 0, pseudo_packet, pseudo_packet.len);
    return std.mem.eql(u8, &expected, tag);
}

fn retry_tag_write(context: *const anyopaque, pseudo_packet: []const u8, tag: *[tag_len]u8) crypto.suite.RetryTagError!void {
    if (!from_const(context).writes_retry_tag) return error.Unsupported;
    write_tag(tag, constants.null_suite_retry_name, 0, pseudo_packet, pseudo_packet.len);
}

fn update_keys(context: *anyopaque) crypto.suite.UpdateError!void {
    const self = from(context);
    // RFC 9001 §6.1: only the 1-RTT keys are ever updated.
    if (self.state_of(.application, .write) != .available) return error.KeysUnavailable;
    self.phase += 1;
    self.previous_held = true;
}

fn key_phase(context: *const anyopaque) bool {
    return null_suite_keys.phase_bit(from_const(context).phase);
}

fn discard_previous_keys(context: *anyopaque) void {
    from(context).previous_held = false;
}

fn discard_keys(context: *anyopaque, level: Level) void {
    const self = from(context);
    self.keys[@intFromEnum(level)] = @splat(.discarded);
    if (level == .application) self.previous_held = false;
}

const testing = std.testing;

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

fn seal_initial(writer: *NullSuite) ![]u8 {
    const len = try writer.suite().seal(.{
        .level = .initial,
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
        .packet_number = packet_number,
        .header = header,
        .packet_number_len = short_packet_number_len,
        .payload = payload,
    }, &sealed);
    return sealed[0..len];
}

fn open_initial(reader: *NullSuite, packet: []u8) !Opened {
    return reader.suite().open(.{
        .level = .initial,
        .packet = packet,
        .packet_number_offset = initial_header.len - initial_packet_number_len,
        .largest_packet_number = null,
    });
}

fn open_short(reader: *NullSuite, packet: []u8, largest: ?u64, lowest: ?u64) !Opened {
    return reader.suite().open(.{
        .level = .application,
        .packet = packet,
        .packet_number_offset = short_header.len - short_packet_number_len,
        .largest_packet_number = largest,
        .current_phase_lowest = lowest,
    });
}

test "a sealed packet is its header, its payload and a 16-octet tag, and opens to the same octets" {
    var pair: Pair = .{};
    try pair.init(sample_dcid);
    const packet = try seal_initial(&pair.client);
    try testing.expectEqual(initial_header.len + payload.len + tag_len, packet.len);
    // RFC 9001 §5.4.1: the mask covers four bits of a long header's byte 0 and the Packet Number
    // field, and nothing else of the header. The payload is copied.
    try testing.expectEqual(initial_header[0] & 0xf0, packet[0] & 0xf0);
    try testing.expectEqualSlices(u8, initial_header[1 .. initial_header.len - 4], packet[1 .. initial_header.len - 4]);
    try testing.expectEqualSlices(u8, payload, packet[initial_header.len..][0..payload.len]);
    try testing.expect(!std.mem.eql(u8, initial_header[initial_header.len - 4 ..], packet[initial_header.len - 4 ..][0..4]));
    const opened = try open_initial(&pair.server, packet);
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
        try testing.expectError(error.Discarded, open_initial(reader, try seal_initial(&pair.client)));
    }
    // A Retry changes the connection ID, and installing again changes the keys with it.
    try pair.server.suite().vtable.install_initial_keys(&pair.server, .server, "\x01\x02\x03\x04");
    try testing.expectError(error.Discarded, open_initial(&pair.server, try seal_initial(&pair.client)));
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
    try testing.expectError(error.KeysUnavailable, seal_initial(&pair.client));
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
    const sealing: Sealing = .{ .level = .application, .packet_number = 1, .header = short_header, .packet_number_len = 2, .payload = payload };
    try testing.expectError(error.NoSpaceLeft, pair.client.suite().vtable.seal(&pair.client, sealing, &small));
    try testing.expectEqual(1, pair.client.seals_left);
    const packet = try seal_short(&pair.client, short_header, 0x9b32);
    try testing.expectError(error.ConfidentialityLimitReached, seal_short(&pair.client, short_header, 0x9b33));
    pair.server.open_failures_left = 1;
    packet[packet.len - 1] ^= 0x01;
    try testing.expectError(error.Discarded, open_short(&pair.server, packet, null, null));
    try testing.expectError(error.IntegrityLimitReached, open_short(&pair.server, packet, null, null));
}

test "§5.8: the Retry tag is a function of the pseudo-packet, and a suite may decline to write it" {
    var null_suite: NullSuite = .{};
    const vtable = null_suite.suite().vtable;
    var tag: [tag_len]u8 = undefined;
    try vtable.retry_tag_write(&null_suite, "\x08" ++ sample_dcid ++ "retry", &tag);
    try testing.expect(vtable.retry_tag_valid(&null_suite, "\x08" ++ sample_dcid ++ "retry", &tag));
    try testing.expect(!vtable.retry_tag_valid(&null_suite, "\x08" ++ sample_dcid ++ "retrz", &tag));
    // One host's tag is every host's: the checksums are taken over octets in network order.
    try testing.expectEqualSlices(u8, &retry_tag_expected, &tag);
    null_suite.writes_retry_tag = false;
    try testing.expectError(error.Unsupported, vtable.retry_tag_write(&null_suite, "retry", &tag));
}

test "invariant 25: a suite that refuses the Initial keys installs none" {
    var null_suite: NullSuite = .{ .refuses_initial_keys = true };
    const vtable = null_suite.suite().vtable;
    try testing.expectError(error.Unsupported, vtable.install_initial_keys(&null_suite, .client, sample_dcid));
    try testing.expect(!vtable.keys_available(&null_suite, .initial, .write));
}

/// The tag the test above produced on the host that wrote it, macOS on arm64, and must produce on
/// every other. It pins that the null suite's octets do not vary by host; it says nothing about
/// whether they are good ones. Test-only.
const retry_tag_expected = "\x50\x0d\xea\xf3\x9f\x93\xfd\x3b\x14\x40\xc3\x22\xdb\xde\xd4\xea".*;
