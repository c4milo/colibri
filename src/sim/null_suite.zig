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
const Version = crypto.suite.Version;

const null_suite_keys = @import("null_suite_keys.zig");
const null_suite_retry = @import("null_suite_retry.zig");
const null_suite_version = @import("null_suite_version.zig");

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
    /// The original and the negotiated version, which the test sets before the first packet.
    versions: null_suite_version.Versions = .{},
    /// Whether the read keys of the phase before are still held (RFC 9001 §6.5).
    previous_held: bool = false,
    /// Packets each limit of RFC 9001 §6.6 still permits. A test lowers one to reach it.
    seals_left: u64 = std.math.maxInt(u64),
    open_failures_left: u64 = std.math.maxInt(u64),
    /// Makes `install_initial_keys` refuse, as a suite without AES would (invariant 25).
    refuses_initial_keys: bool = false,
    /// Makes `retry_tag_write` refuse, as a suite written for clients alone would.
    writes_retry_tag: bool = true,
    /// Makes `retry_token_write` refuse, as a suite that offers no Retry would (decision 55).
    mints_retry_token: bool = true,
    /// How many calls asked for a level this suite holds no keys for. Invariant 21 has colibri
    /// ask only at levels it was told are available, so the QUIC simulator treats any count above
    /// zero as a violation rather than as a lost packet.
    keys_unavailable: u64 = 0,

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

    /// The name of the key `writer` protects a packet with at `level`, `phase` and `version`.
    fn key_name(self: *const NullSuite, level: Level, writer: Role, phase: u32, version: Version) u32 {
        return null_suite_keys.key_name(level, writer, phase, self.initial_name, version);
    }

    /// The mask of a packet, under a name that leaves the key phase out, because a key update
    /// never changes the header protection key (RFC 9001 §6.1).
    fn mask_of(self: *const NullSuite, level: Level, writer: Role, version: Version, packet: []const u8, offset: usize) [mask_len]u8 {
        return null_suite_keys.mask_of(self.key_name(level, writer, 0, version), packet, offset);
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

    /// Counts a call at a level without keys (invariant 21) and answers `failure`.
    fn unavailable(self: *NullSuite, failure: anytype) @TypeOf(failure) {
        self.keys_unavailable +|= 1;
        return failure;
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
    .switch_version = switch_version,
    .keys_available = keys_available,
    .seal = seal,
    .open = open,
    .retry_tag_valid = null_suite_retry.tag_valid,
    .retry_tag_write = null_suite_retry.tag_write,
    .retry_token_write = null_suite_retry.token_write,
    .retry_token_check = null_suite_retry.token_check,
    .update_keys = update_keys,
    .key_phase = key_phase,
    .discard_previous_keys = discard_previous_keys,
    .discard_keys = discard_keys,
};

/// `std.mem.zeroes(T)`, with every `NullSuite` inside `T` at its defaults instead: a suite's
/// versions have no zero value (decision 108). The checks whose storage starts zeroed use it.
pub fn zeroes_around_suites(comptime T: type) T {
    if (T == NullSuite) return .{};
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            var value: T = undefined;
            inline for (info.fields) |field| @field(value, field.name) = zeroes_around_suites(field.type);
            return value;
        },
        .array => |info| return @splat(zeroes_around_suites(info.child)),
        else => return std.mem.zeroes(T),
    }
}

pub fn from(context: *anyopaque) *NullSuite {
    return @ptrCast(@alignCast(context));
}

pub fn from_const(context: *const anyopaque) *const NullSuite {
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

fn switch_version(context: *anyopaque, version: Version) crypto.suite.SwitchError!void {
    const self = from(context);
    return self.versions.switch_to(self.role, self.state_of(.handshake, .read) != .none, version);
}

fn keys_available(context: *const anyopaque, level: Level, direction: Direction) bool {
    return from_const(context).state_of(level, direction) == .available;
}

fn seal(context: *anyopaque, sealing: Sealing, output: []u8) crypto.suite.SealError!usize {
    const self = from(context);
    if (self.state_of(sealing.level, .write) != .available) return self.unavailable(error.KeysUnavailable);
    // RFC 9369 §4.1: no keys exist for a version the level does not admit.
    if (!self.versions.admits(sealing.level, sealing.version)) return self.unavailable(error.KeysUnavailable);
    // RFC 9001 §6.6: past the confidentiality limit the keys protect nothing more.
    if (self.seals_left == 0) return error.ConfidentialityLimitReached;
    const header_len = sealing.header.len;
    const written = header_len + sealing.payload.len + tag_len;
    if (output.len < written) return error.NoSpaceLeft;
    self.seals_left -= 1;
    @memcpy(output[0..header_len], sealing.header);
    @memcpy(output[header_len..][0..sealing.payload.len], sealing.payload);
    const name = self.key_name(sealing.level, self.role, self.phase, sealing.version);
    write_tag(output[written - tag_len ..][0..tag_len], name, sealing.packet_number, output[0 .. written - tag_len], header_len);
    // RFC 9001 §5.4: header protection is applied after packet protection, over byte 0 and the
    // Packet Number field, from a sample of the protected payload.
    const packet_number_offset = header_len - sealing.packet_number_len;
    const mask = self.mask_of(sealing.level, self.role, sealing.version, output[0..written], packet_number_offset);
    apply_mask(output[0..written], packet_number_offset, sealing.packet_number_len, mask);
    return written;
}

fn open(context: *anyopaque, opening: Opening) crypto.suite.OpenError!Opened {
    const self = from(context);
    if (self.state_of(opening.level, .read) != .available) return self.unavailable(error.KeysUnavailable);
    if (!self.versions.admits(opening.level, opening.version)) return self.unavailable(error.KeysUnavailable);
    const packet = opening.packet;
    const offset = opening.packet_number_offset;
    // RFC 9001 §5.4.2: a packet too short for the sample is discarded before it is read.
    if (packet.len < offset + sample_offset + sample_len) return error.Discarded;
    // The peer wrote the packet, so the mask and the tag are under the peer's names.
    const mask = self.mask_of(opening.level, self.role.peer(), opening.version, packet, offset);
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
    write_tag(&expected, self.key_name(opening.level, self.role.peer(), phase, opening.version), packet_number, packet[0 .. packet.len - tag_len], header_len);
    if (!std.mem.eql(u8, &expected, packet[packet.len - tag_len ..])) return self.count_failure();
    return .{
        .packet_number = packet_number,
        .packet_number_len = packet_number_len,
        .payload_len = packet.len - tag_len - header_len,
        .key_set = key_set,
    };
}

fn update_keys(context: *anyopaque) crypto.suite.UpdateError!void {
    const self = from(context);
    // RFC 9001 §6.1: only the 1-RTT keys are ever updated.
    if (self.state_of(.application, .write) != .available) return self.unavailable(error.KeysUnavailable);
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

test {
    _ = @import("null_suite_test.zig");
}
