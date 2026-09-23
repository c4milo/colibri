//! The tests of `packet_build.zig`. The strong one is a round trip: a packet this file builds is
//! walked back by `connection_receive.zig` and read by `connection_frames.zig`, so every field of
//! the header is checked by the code that has to read it rather than by an expected byte string.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const tls = @import("tls");
const constants = @import("../../constants.zig");
const transport_parameters = @import("../../transport_parameters.zig");
const connection_module = @import("../connection.zig");
const identity_module = @import("../connection_identity.zig");
const keys = @import("../connection_keys.zig");
const receive = @import("../connection_receive.zig");
const frames = @import("../connection_frames.zig");
const packet_build = @import("packet_build.zig");
const packet_number = @import("../../packet/packet_number.zig");

const testing = std.testing;

/// How many bits an octet holds, which reading a multi-octet field shifts by (RFC 9000 §1.3).
const bits_per_octet: u4 = 8;
const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

pub var test_connection: Connection = undefined;
/// The endpoint that reads what `test_connection` built. A packet must be walked back by the
/// other side: RFC 9000 §12.3 gives each endpoint its own record of what it received, and
/// walking a packet into the space that sent it would see its own number as a duplicate.
pub var peer_connection: Connection = undefined;
var scratch: packet_build.DefaultScratch = .{};
var datagram: [constants.datagram_len_min]u8 = undefined;
pub var fake: Fake = undefined;
var round_trip: RoundTrip = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

const handshake_octet: u8 = 0x6d;
const handshake_len: usize = 32;
const handshake_octets: [handshake_len]u8 = @splat(handshake_octet);

/// A `crypto.Suite` whose protection is the identity. `seal` copies the header and the payload
/// and writes a tag of zeros; `open` takes them back apart. It holds no key, which is the point:
/// what the round trip checks is colibri's framing, not anyone's cryptography.
pub const RoundTrip = struct {
    /// RFC 9001 §6: the Key Phase bit this suite writes, which `update_keys` toggles.
    phase: bool = false,
    /// How many times `update_keys` was called, which a key update test reads.
    updates: usize = 0,
    /// Makes `update_keys` refuse, as a suite that offers no key update would.
    refuses_update: bool = false,
    /// Which key set `open` reports at the application level (RFC 9001 §6.5). A test sets it to
    /// drive §6.2's answer and §6.4's refusal; a real suite decides it from the Key Phase bit.
    opens_with: crypto.suite.KeySet = .current,
    /// RFC 9001 §6.6: packets these keys may still protect, or null for no limit.
    seals_left: ?usize = null,
    /// What a key update restores `seals_left` to, because §6.1 installs a new set of keys and
    /// §6.6 counts each set on its own.
    seals_per_key: ?usize = null,
    /// Makes `open` answer §6.6's integrity limit, which a test reaches with no forged packet.
    reached_integrity_limit: bool = false,
    /// How many times `seal` was entered, refusals included. RFC 9001 §6.6 has an endpoint
    /// "stop using those keys", so a test reads this to see that it did.
    seal_attempts: usize = 0,
    /// How many times colibri told this suite to forget the read keys of the phase before
    /// (RFC 9001 §6.5), which is what times that discard.
    previous_discards: usize = 0,

    pub fn init(held: *RoundTrip) void {
        held.* = .{};
    }

    pub fn suite(held: *RoundTrip) crypto.Suite {
        return .{ .context = held, .vtable = &vtable };
    }

    fn seal(context: *anyopaque, sealing: crypto.suite.Sealing, output: []u8) crypto.suite.SealError!usize {
        const held: *RoundTrip = @ptrCast(@alignCast(context));
        held.seal_attempts += 1;
        if (held.seals_left) |left| {
            // RFC 9001 §6.6: past the confidentiality limit "the endpoint MUST stop using those
            // keys", which is a refusal to protect anything more under them.
            if (left == 0) return error.ConfidentialityLimitReached;
            held.seals_left = left - 1;
        }
        const total = sealing.header.len + sealing.payload.len + constants.aead_tag_len;
        // RFC 9001 §5.3: a real suite would refuse here too, because the tag has nowhere to go.
        if (total > output.len) return error.NoSpaceLeft;
        @memcpy(output[0..sealing.header.len], sealing.header);
        @memcpy(output[sealing.header.len..][0..sealing.payload.len], sealing.payload);
        @memset(output[sealing.header.len + sealing.payload.len ..][0..constants.aead_tag_len], 0);
        return total;
    }

    fn open(context: *anyopaque, opening: crypto.suite.Opening) crypto.suite.OpenError!crypto.suite.Opened {
        const held: *RoundTrip = @ptrCast(@alignCast(context));
        // RFC 9001 §6.6: the integrity limit counts failures "across all keys" over a connection
        // and is reached whatever this packet holds.
        if (held.reached_integrity_limit) return error.IntegrityLimitReached;
        // RFC 9000 §17.2: byte 0's low two bits are the Packet Number Length less one. A real
        // suite reads them after removing header protection (RFC 9001 §5.4); this one has none.
        const number_len: u8 = (opening.packet[0] & constants.packet_number_len_mask) + 1;
        const protected = opening.packet.len - opening.packet_number_offset;
        // RFC 9001 §5.5: a packet too short to hold the number and a tag cannot authenticate.
        if (protected < number_len + constants.aead_tag_len) return error.Discarded;
        var number: u64 = 0;
        // Bounded by the field, which RFC 9000 §17.1 caps at four octets. The wire is network
        // byte order (§1.3), so the octets are read most significant first.
        for (opening.packet[opening.packet_number_offset..][0..number_len]) |octet| {
            number = (number << bits_per_octet) | octet;
        }
        return .{
            .packet_number = number,
            .packet_number_len = number_len,
            .payload_len = protected - number_len - constants.aead_tag_len,
            // RFC 9001 §6.5: only a 1-RTT packet has a phase to be read under, which
            // `crypto.Suite.open` asserts.
            .key_set = if (opening.level == .application) held.opens_with else .current,
        };
    }

    /// RFC 9001 §6.1: "The endpoint toggles the value of the Key Phase bit and uses the updated
    /// key and IV to protect all subsequent packets." Both directions move, as §6.1 requires.
    fn update_keys(context: *anyopaque) crypto.suite.UpdateError!void {
        const held: *RoundTrip = @ptrCast(@alignCast(context));
        // RFC 9001 §6: "an endpoint MAY initiate a key update", so a suite that offers none is
        // legal and `crypto.suite.UpdateError.Unsupported` is how it says so.
        if (held.refuses_update) return error.Unsupported;
        held.phase = !held.phase;
        held.updates += 1;
        // RFC 9001 §6.6 counts each set of keys on its own, so the new set starts over.
        held.seals_left = held.seals_per_key;
    }

    /// RFC 9001 §6.5: "old read keys and their corresponding secrets SHOULD be discarded."
    fn discard_previous_keys(context: *anyopaque) void {
        const held: *RoundTrip = @ptrCast(@alignCast(context));
        held.previous_discards += 1;
    }

    fn key_phase(context: *const anyopaque) bool {
        const held: *const RoundTrip = @ptrCast(@alignCast(context));
        return held.phase;
    }

    const vtable: crypto.suite.VTable = .{
        .install_initial_keys = unreachable_install,
        .keys_available = unreachable_available,
        .seal = seal,
        .open = open,
        .retry_tag_valid = unreachable_tag_valid,
        .retry_tag_write = unreachable_tag_write,
        .retry_token_write = unreachable_token_write,
        .retry_token_valid = unreachable_token_valid,
        .update_keys = update_keys,
        .key_phase = key_phase,
        .discard_previous_keys = discard_previous_keys,
        .discard_keys = unreachable_discard,
    };
};

fn unreachable_install(_: *anyopaque, _: crypto.suite.Role, _: []const u8) crypto.suite.InstallError!void {
    unreachable;
}
fn unreachable_available(_: *const anyopaque, _: Level, _: crypto.suite.Direction) bool {
    unreachable;
}
fn unreachable_tag_valid(
    _: *const anyopaque,
    _: []const u8,
    _: *const [crypto.constants.retry_integrity_tag_len]u8,
) bool {
    unreachable;
}
fn unreachable_token_write(_: *anyopaque, _: []const u8, _: u64, _: []u8) crypto.suite.TokenError!usize {
    unreachable;
}
fn unreachable_token_valid(_: *const anyopaque, _: []const u8, _: []const u8, _: u64) bool {
    unreachable;
}
fn unreachable_tag_write(
    _: *const anyopaque,
    _: []const u8,
    _: *[crypto.constants.retry_integrity_tag_len]u8,
) crypto.suite.RetryTagError!void {
    unreachable;
}
fn unreachable_discard(_: *anyopaque, _: Level) void {
    unreachable;
}

/// A provider that owes `owed` octets at `owed_level` and nothing anywhere else.
pub const Fake = struct {
    owed: []const u8 = "",
    owed_level: Level = .initial,

    pub fn provider(self: *Fake) tls.QuicProvider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }
    fn set_params(_: *anyopaque, _: []const u8) tls.quic_provider.TransportParamsError!void {}
    fn peer_params(_: *const anyopaque) ?[]const u8 {
        return null;
    }
    fn provide(_: *anyopaque, _: Level, _: []const u8) tls.quic_provider.ProvideError!void {}
    fn write(context: *anyopaque, level: Level, output: []u8) tls.quic_provider.WriteError!usize {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (level != self.owed_level or self.owed.len == 0) return 0;
        // RFC 9001 §4.1.3 lets a provider hand over what fits and keep the rest for the next
        // call, which is what makes a long flight fill a packet exactly.
        const written = @min(self.owed.len, output.len);
        @memcpy(output[0..written], self.owed[0..written]);
        self.owed = self.owed[written..];
        return written;
    }
    fn alpn(_: *const anyopaque) ?[]const u8 {
        return &tls.constants.alpn_h3;
    }
    fn complete(_: *const anyopaque) bool {
        return false;
    }
    fn alert_of(_: *anyopaque) ?tls.Alert {
        return null;
    }
    fn exported(_: *anyopaque, _: []const u8, _: ?[]const u8, _: []u8) tls.quic_provider.ExportError!void {
        // RFC 9846 §7.5 standardises the exporter without obliging a stack to offer one.
        return error.Unsupported;
    }
    const table: tls.QuicVTable = .{
        .set_transport_params = set_params,
        .peer_transport_params = peer_params,
        .provide_handshake = provide,
        .write_handshake = write,
        .negotiated_alpn = alpn,
        .handshake_complete = complete,
        .take_alert = alert_of,
        .export_keying_material = exported,
    };
};

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

pub fn open_connection() void {
    round_trip.init();
    fake = .{};
    open_one(&test_connection, .client);
    open_one(&peer_connection, .server);
}

fn open_one(connection: *Connection, role: connection_module.Role) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    // Both handshake levels, in both directions: a test about framing should never be stopped by
    // RFC 9001 §4.9's timing, which `connection_keys_test.zig` covers on its own.
    for ([_]Level{ .initial, .handshake }) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
}

/// Walks one built packet back as the other endpoint would, and returns what it opened.
pub fn walk_back(built: packet_build.Built) !receive.Opened {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..built.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const outcome = (try receive.next(&walk, &peer_connection, round_trip.suite())).?;
    // RFC 9000 §12.2: the Length field says where the packet ends, so a datagram holding one
    // packet is spent after it.
    std.debug.assert(try receive.next(&walk, &peer_connection, round_trip.suite()) == null);
    return outcome.opened;
}

pub fn build_at(level: Level) !?packet_build.Built {
    return build_at_instant(level, test_now_ns);
}

/// The same, at an instant a test chose, which RFC 9000 §13.2.1's acknowledgment delay turns on.
pub fn build_at_instant(level: Level, now_ns: u64) !?packet_build.Built {
    return packet_build.build(
        &test_connection,
        round_trip.suite(),
        fake.provider(),
        level,
        &scratch,
        &datagram,
        now_ns,
    );
}

test "RFC 9000 §17.2: a packet built at Initial is read back as one" {
    open_connection();
    fake = .{ .owed = &handshake_octets, .owed_level = .initial };
    const built = (try build_at(.initial)).?;
    try testing.expectEqual(0, built.packet_number);
    try testing.expect(built.ack_eliciting);
    // RFC 9002 §2: a CRYPTO frame elicits an acknowledgment, so the packet is in flight.
    try testing.expect(built.in_flight);

    // The round trip. Every field of the header is checked by the walk that has to read it.
    const opened = try walk_back(built);
    try testing.expectEqual(Level.initial, opened.level);
    try testing.expectEqual(0, opened.packet_number);

    // And the frames come back out, which is what proves the payload's offset.
    const report = try frames.process(&peer_connection, opened, test_now_ns);
    try testing.expectEqual(1, report.frames);
    try testing.expect(report.ack_eliciting);
    try testing.expectEqualSlices(
        u8,
        &handshake_octets,
        peer_connection.crypto_at(.initial).readable(),
    );
}

test "RFC 9001 §4.9: a level with nothing to send builds nothing" {
    open_connection();
    // The provider owes octets at Initial alone, so the Handshake level has nothing and the
    // space owes no acknowledgment yet.
    fake = .{ .owed = &handshake_octets, .owed_level = .initial };
    try testing.expectEqual(null, try build_at(.handshake));
}

test "RFC 9001 §4.9.1, invariant 21: a discarded level builds nothing" {
    open_connection();
    fake = .{ .owed = &handshake_octets, .owed_level = .initial };
    test_connection.keys.mark_discarded(.initial);
    // §4.9.1: "Endpoints MUST NOT send Initial packets after this point."
    try testing.expectEqual(null, try build_at(.initial));
}

test "RFC 9000 §12.3, invariant 17: each packet takes the next number of its space" {
    open_connection();
    fake = .{ .owed = &handshake_octets, .owed_level = .initial };
    const first = (try build_at(.initial)).?;
    fake = .{ .owed = &handshake_octets, .owed_level = .initial };
    const second = (try build_at(.initial)).?;
    try testing.expectEqual(0, first.packet_number);
    try testing.expectEqual(1, second.packet_number);
    // The spaces are independent (§12.3), so the Handshake level starts at zero of its own.
    fake = .{ .owed = &handshake_octets, .owed_level = .handshake };
    const other = (try build_at(.handshake)).?;
    try testing.expectEqual(0, other.packet_number);
}

test "RFC 9001 §5.4.2, decision 54: a short packet widens its number rather than padding" {
    // No frame this file writes reaches four octets short, so the rule is checked directly.
    // A one-octet payload under a one-octet number is two, and the sample needs four.
    const narrow: packet_number.Truncated = .{ .value = 7, .len = 1 };
    const widened = packet_build.widen_for_sample(7, narrow, 1);
    try testing.expectEqual(constants.protected_len_min - 1, widened.len);
    try testing.expectEqual(7, widened.value);

    // A payload that already reaches the floor is left alone, so an ordinary packet pays nothing.
    const untouched = packet_build.widen_for_sample(7, narrow, constants.protected_len_min);
    try testing.expectEqual(1, untouched.len);
    // And a number already wide enough is not narrowed: §17.1's width is a floor, not a target.
    const wide: packet_number.Truncated = .{ .value = 7, .len = constants.packet_number_len_max };
    try testing.expectEqual(constants.packet_number_len_max, packet_build.widen_for_sample(7, wide, 1).len);
}

test "decision 35: the scratch is the caller's and its size is a comptime parameter" {
    // §14.1's smallest allowed maximum datagram is what a caller gets by asking for no size.
    try testing.expectEqual(constants.datagram_len_min, packet_build.DefaultScratch.payload_len_max);
    const Small = packet_build.Scratch(constants.protected_len_min);
    try testing.expectEqual(constants.protected_len_min, Small.payload_len_max);
    // The header buffer is the same whatever the payload's size, because RFC 9000 §17.2 fixes
    // what a header can hold and only the frames vary.
    try testing.expectEqual(
        @sizeOf([constants.packet_header_len_max]u8),
        @sizeOf(@FieldType(Small, "header")),
    );
}

test "RFC 9000 §17.2: a long flight fills the datagram exactly and never past it" {
    open_connection();
    // More than one packet can hold, so the provider fills whatever room the header leaves. The
    // packet must come out exactly the size of the buffer: a header counted one octet short
    // would ask for an octet more than fits and `seal` would refuse it.
    fake = .{ .owed = &long_flight, .owed_level = .initial };
    const built = (try build_at(.initial)).?;
    try testing.expectEqual(datagram.len, built.len);

    // And it still reads back, which is what says the Length field matched the real payload.
    const opened = try walk_back(built);
    const report = try frames.process(&peer_connection, opened, test_now_ns);
    try testing.expectEqual(1, report.frames);
    try testing.expect(report.ack_eliciting);
}

/// Longer than the smallest allowed maximum datagram, so one packet cannot hold it.
pub const long_flight: [constants.datagram_len_min]u8 = @splat(handshake_octet);

/// Storage for the small-scratch case, which is what shows the comptime parameter binds.
const small_payload_len: usize = 16;
var small_scratch: packet_build.Scratch(small_payload_len) = .{};

test "RFC 9000 §17.3: a 1-RTT packet is built with a short header and read back" {
    open_connection();
    // The application level, which §17.3 gives a short header: no Version, no Source Connection
    // ID and no Length, so the packet is the rest of the datagram.
    for ([_]*Connection{ &test_connection, &peer_connection }) |connection| {
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
        // RFC 9001 §5.7 forbids opening a 1-RTT packet before the handshake completes.
        connection.handshake_complete = true;
    }
    fake = .{ .owed = &handshake_octets, .owed_level = .application };
    const built = (try build_at(.application)).?;
    try testing.expectEqual(0, built.packet_number);

    const opened = try walk_back(built);
    try testing.expectEqual(Level.application, opened.level);
    try testing.expectEqual(0, opened.packet_number);
    const report = try frames.process(&peer_connection, opened, test_now_ns);
    try testing.expectEqual(1, report.frames);
    try testing.expectEqualSlices(
        u8,
        &handshake_octets,
        peer_connection.crypto_at(.application).readable(),
    );
}

test "decision 35: a smaller scratch bounds the packet, not the datagram" {
    open_connection();
    // The datagram has room for 1,200 octets and the scratch holds sixteen, so the scratch is
    // what decides how much of a long flight one packet carries.
    fake = .{ .owed = &long_flight, .owed_level = .initial };
    const built = (try packet_build.build(
        &test_connection,
        round_trip.suite(),
        fake.provider(),
        .initial,
        &small_scratch,
        &datagram,
        test_now_ns,
    )).?;
    const header_and_tag = built.len - small_payload_len;
    try testing.expect(built.len < datagram.len);
    try testing.expect(header_and_tag > constants.aead_tag_len);

    // And what it carried still reads back, so the Length field matched the smaller payload.
    const opened = try walk_back(built);
    try testing.expectEqual(small_payload_len, opened.payload.len);
    _ = try frames.process(&peer_connection, opened, test_now_ns);
    try testing.expectEqual(small_payload_len - 3, peer_connection.crypto_at(.initial).readable().len);
}

test "RFC 9000 §17.3: a 1-RTT packet fills the datagram exactly, with no Length field" {
    open_connection();
    for ([_]*Connection{ &test_connection, &peer_connection }) |connection| {
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
        connection.handshake_complete = true;
    }
    // §17.3.1: a short header carries no Version, no Source Connection ID and no Length, so its
    // packet runs to the end of the datagram. A builder that counted a Length field, or missed
    // the Packet Number field, would leave the packet short of the buffer or ask for one octet
    // past it, and only a payload that fills the room can tell.
    fake = .{ .owed = &long_flight, .owed_level = .application };
    const built = (try build_at(.application)).?;
    try testing.expectEqual(datagram.len, built.len);

    const opened = try walk_back(built);
    try testing.expectEqual(Level.application, opened.level);
    _ = try frames.process(&peer_connection, opened, test_now_ns);
}
