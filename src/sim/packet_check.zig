//! The check that colibri's packet framing and a suite's packet protection fit each other
//! (design §8 step 7, decision 48). colibri frames and the suite protects, so the two agree on
//! three things no unit test of either sees: where the Packet Number field is, how long the
//! protected payload is once the tag is on it, and where one packet of a datagram ends and the
//! next begins (RFC 9000 §12.2, §17.2; RFC 9001 §5.3, §5.4).
//!
//! Each seed draws connection IDs, a number of key updates, and up to three packets in the order
//! §12.2 asks for: Initial, Handshake, 1-RTT. One endpoint writes each header with
//! `quic.packet.header_write`, picks the Packet Number field's length from what the peer has
//! acknowledged (Appendix A.2), and seals through the null suite into one datagram. The other
//! reads the datagram packet by packet, opens each through its own null suite, and must get back
//! the packet number, the header and the payload, with nothing left over. Then one octet of the
//! datagram is changed, and at least one packet must fail to open.
//!
//! This file's module imports no HTTP module, which is the first time the boundary of decision 5
//! is held by a build and not by a lint: `quic` is driven here with `h2`, `h3`, `hpack`, `qpack`
//! and `http` absent from the graph.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const constants = sim.constants;

const crypto = quic.crypto;
const Writer = quic.core.Writer;
const Level = crypto.suite.Level;
const Role = crypto.suite.Role;
const header = quic.packet.header;
const header_write = quic.packet.header_write;
const packet_number = quic.packet.packet_number;

/// The digest of every datagram and of what was opened from it, over `check_seeds_default` seeds.
/// It changes when a header writer, the packet number coding or the null suite changes, and is
/// committed with the new value after both build modes agree.
pub const census_crc32_expected: u32 = 0xf0818926;

/// The packets and the octets the same seeds produce.
pub const census_packets_expected: u64 = 512;
pub const census_octets_expected: u64 = 128_870;

/// How a seed failed.
pub const Violation = error{
    /// A packet the writer framed was refused by the reader.
    PacketNotRead,
    /// A packet was read as another type or at another level than it was written.
    PacketMisread,
    /// A packet sealed by one suite did not open in its peer.
    PacketNotOpened,
    /// The packet number recovered is not the one sealed (RFC 9000 Appendix A.2, A.3).
    PacketNumberWrong,
    /// The header or the payload opened is not the one sealed.
    PacketChanged,
    /// The packets' lengths do not add up to the datagram's (RFC 9000 §12.2).
    DatagramNotConsumed,
    /// Every packet of a datagram with a changed octet still opened.
    CorruptionOpened,
};

/// One packet as the writer drew it.
const Plan = struct {
    level: Level,
    full: u64,
    largest_acked: ?u64,
    /// The largest packet number the reader has processed, at or past what it acknowledged.
    largest_processed: ?u64,
    payload_len: usize,
    token_len: usize,
    /// Where the packet starts in the datagram, and where its header ends, once it is sealed.
    start: usize = 0,
    header_len: usize = 0,
    packet_number_len: u8 = 0,
};

/// The storage one run needs, which the caller places (decision 35).
pub const Storage = struct {
    client: sim.NullSuite,
    server: sim.NullSuite,
    plans: [constants.packet_check_packets_max]Plan,
    plans_len: usize,
    dcid: [quic.constants.connection_id_len_max]u8,
    dcid_len: usize,
    scid: [quic.constants.connection_id_len_max]u8,
    scid_len: usize,
    payload: [constants.packet_check_payload_len_max]u8,
    token: [constants.packet_check_token_len_max]u8,
    header: [constants.packet_check_datagram_len_max]u8,
    datagram: [constants.packet_check_datagram_len_max]u8,
    datagram_len: usize,
    received: [constants.packet_check_datagram_len_max]u8,

    pub const zeroed: Storage = std.mem.zeroes(Storage);

    fn suite_of(storage: *Storage, role: Role) *sim.NullSuite {
        return if (role == .client) &storage.client else &storage.server;
    }
};

/// What the check counted over every seed.
pub const Census = struct {
    seeds: u64 = 0,
    packets: u64 = 0,
    octets: u64 = 0,
    /// Packets by the length of their Packet Number field, 1 to 4 octets.
    by_packet_number_len: [quic.constants.packet_number_len_max]u64 = @splat(0),
    crc32: std.hash.Crc32 = std.hash.Crc32.init(),
};

/// Draws the connection IDs, installs the keys of every level on both sides, and performs the
/// same number of key updates on both, which is where a finished handshake leaves two endpoints.
fn prepare(storage: *Storage, random: *sim.Random) void {
    storage.client = .{};
    storage.server = .{};
    storage.dcid_len = random.between(0, storage.dcid.len);
    storage.scid_len = random.between(0, storage.scid.len);
    for (storage.dcid[0..storage.dcid_len]) |*octet| octet.* = @truncate(random.next());
    for (storage.scid[0..storage.scid_len]) |*octet| octet.* = @truncate(random.next());
    for (&storage.payload) |*octet| octet.* = @truncate(random.next());
    for (&storage.token) |*octet| octet.* = @truncate(random.next());
    for ([_]Role{ .client, .server }) |role| {
        const null_suite = storage.suite_of(role);
        const suite = null_suite.suite();
        suite.vtable.install_initial_keys(suite.context, role, storage.dcid[0..storage.dcid_len]) catch unreachable;
        null_suite.install(.handshake);
        null_suite.install(.application);
    }
    for (0..random.between(0, constants.packet_check_key_updates_max)) |_| {
        storage.client.suite().vtable.update_keys(&storage.client) catch unreachable;
        storage.server.suite().vtable.update_keys(&storage.server) catch unreachable;
    }
}

/// Draws the packets of one datagram, in the order RFC 9000 §12.2 asks for.
fn draw_plans(storage: *Storage, random: *sim.Random) void {
    storage.plans_len = 0;
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        // Every level is drawn or left out, and a datagram holds at least the last one.
        if (level != .application and random.below(constants.packet_check_one_in) == 0) continue;
        storage.plans[storage.plans_len] = draw_plan(level, random);
        storage.plans_len += 1;
    }
    assert(storage.plans_len >= 1 and storage.plans_len <= constants.packet_check_packets_max);
}

/// Draws one packet: its number, what the peer has acknowledged and processed, and its sizes.
fn draw_plan(level: Level, random: *sim.Random) Plan {
    const acked = random.below(constants.packet_check_one_in) == 0;
    const base = random.between(0, constants.packet_check_packet_number_base_max);
    const distance = draw_distance(random);
    // With nothing acknowledged every number from 0 counts as outstanding (Appendix A.2).
    const full = if (acked) base + distance else distance - 1;
    const lowest_processed = if (acked) base else 0;
    return .{
        .level = level,
        .full = full,
        .largest_acked = if (acked) base else null,
        // The reader has processed the number it acknowledged, or one past it and below this one.
        .largest_processed = if (full == 0) null else random.between(lowest_processed, full - 1),
        .payload_len = random.between(quic.constants.protected_len_min, constants.packet_check_payload_len_max),
        .token_len = if (level == .initial) random.between(0, constants.packet_check_token_len_max) else 0,
    };
}

/// How far a packet is ahead of the largest one acknowledged. The length of the Packet Number field
/// is drawn first and the distance inside the range that needs it, so every length is as likely
/// as the others: a field of `len` octets serves while twice the distance is below its window
/// (RFC 9000 §17.1).
fn draw_distance(random: *sim.Random) u64 {
    const factor = quic.constants.packet_number_range_factor;
    const len: u8 = @intCast(random.between(1, quic.constants.packet_number_len_max));
    const highest = crypto.packet_number.window_of(len) / factor - 1;
    const lowest = if (len == 1) 1 else crypto.packet_number.window_of(len - 1) / factor;
    return random.between(lowest, highest);
}

/// Frames and seals every planned packet into the datagram, as `sender`.
fn seal_datagram(storage: *Storage, sender: Role) void {
    storage.datagram_len = 0;
    for (storage.plans[0..storage.plans_len]) |*plan| {
        const truncated = packet_number.encode(plan.full, plan.largest_acked) catch unreachable;
        var writer = Writer.init(&storage.header);
        write_header(storage, plan.*, truncated, sender, &writer);
        const suite = storage.suite_of(sender).suite();
        const written = suite.seal(.{
            .level = plan.level,
            .packet_number = plan.full,
            .header = writer.written(),
            .packet_number_len = truncated.len,
            .payload = storage.payload[0..plan.payload_len],
        }, storage.datagram[storage.datagram_len..]) catch unreachable;
        plan.start = storage.datagram_len;
        plan.header_len = writer.written().len;
        plan.packet_number_len = truncated.len;
        storage.datagram_len += written;
    }
}

/// Writes the header of one packet. A packet from the client carries the client's connection ID
/// as its source, and one from the server the other way around (RFC 9000 §7.2).
fn write_header(storage: *Storage, plan: Plan, truncated: packet_number.Truncated, sender: Role, writer: *Writer) void {
    const to_server = sender == .client;
    const destination = if (to_server) storage.dcid[0..storage.dcid_len] else storage.scid[0..storage.scid_len];
    const source = if (to_server) storage.scid[0..storage.scid_len] else storage.dcid[0..storage.dcid_len];
    if (plan.level == .application) {
        const suite = storage.suite_of(sender).suite();
        return header_write.write_short(writer, .{
            .dcid = destination,
            .packet_number = truncated,
            // RFC 9001 §6: colibri writes the Key Phase bit the suite names, and then seals.
            .key_phase = suite.vtable.key_phase(suite.context),
        }) catch unreachable;
    }
    header_write.write_long(writer, .{
        .type = if (plan.level == .initial) .initial else .handshake,
        .dcid = destination,
        .scid = source,
        .token = storage.token[0..plan.token_len],
        .packet_number = truncated,
        .protected_payload_len = plan.payload_len + quic.constants.aead_tag_len,
    }) catch unreachable;
}

/// Reads and opens every packet of `datagram` as the peer of `sender`, and checks each against
/// its plan. Returns the packets that opened. A `strict` run is the datagram as it was sealed,
/// where anything short of every packet opening is a violation; the other is the datagram with an
/// octet changed, where a packet that fails is what is looked for.
fn open_datagram(storage: *Storage, sender: Role, datagram: []u8, strict: bool) Violation!usize {
    var offset: usize = 0;
    var opened_count: usize = 0;
    for (storage.plans[0..storage.plans_len]) |plan| {
        if (offset >= datagram.len) break;
        offset += open_packet(storage, sender, datagram[offset..], plan, strict) catch |violation| {
            if (strict) return violation;
            // One packet that does not open is what the run with a changed octet looks for, and
            // where a packet that was not read ends is unknown (RFC 9000 §12.2).
            return opened_count;
        };
        opened_count += 1;
    }
    if (strict and offset != datagram.len) return error.DatagramNotConsumed;
    return opened_count;
}

/// Reads and opens the packet at the start of `rest`, checks it against `plan`, and returns its
/// length, which is where the next packet of the datagram starts.
fn open_packet(storage: *Storage, sender: Role, rest: []u8, plan: Plan, strict: bool) Violation!usize {
    const short_dcid_len = if (sender == .client) storage.dcid_len else storage.scid_len;
    const packet = header.read(rest, short_dcid_len) catch return error.PacketNotRead;
    const framed = framed_of(packet) orelse return error.PacketMisread;
    if (framed.level != plan.level) return error.PacketMisread;
    const octets = rest[0..framed.packet_len];
    const suite = storage.suite_of(sender.peer()).suite();
    const opened = suite.open(.{
        .level = framed.level,
        .packet = octets,
        .packet_number_offset = framed.packet_number_offset,
        .largest_packet_number = plan.largest_processed,
        // Every packet the reader has processed was in the current phase.
        .current_phase_lowest = 0,
    }) catch return error.PacketNotOpened;
    // With an octet changed, the suite refusing the packet is the whole of what is checked: a
    // comparison here that caught the change would hide a suite that did not.
    if (strict) try check_opened(storage, plan, framed, octets, opened);
    return framed.packet_len;
}

/// What the reader reports of a protected packet, whichever header form it has.
const Framed = struct { level: Level, packet_number_offset: usize, packet_len: usize };

fn framed_of(packet: header.Packet) ?Framed {
    return switch (packet) {
        .long => |long| .{
            .level = switch (long.type) {
                .initial => .initial,
                .handshake => .handshake,
                .zero_rtt, .retry => return null,
            },
            .packet_number_offset = long.packet_number_offset,
            .packet_len = long.packet_len,
        },
        .short => |short| .{
            .level = .application,
            .packet_number_offset = short.packet_number_offset,
            .packet_len = short.packet_len,
        },
        .retry, .version_negotiation, .other_version => null,
    };
}

/// What was opened is what was sealed: the number, the header's fields and the payload.
fn check_opened(storage: *Storage, plan: Plan, framed: Framed, octets: []const u8, opened: crypto.suite.Opened) Violation!void {
    if (opened.packet_number != plan.full) return error.PacketNumberWrong;
    if (opened.packet_number_len != plan.packet_number_len) return error.PacketChanged;
    if (framed.packet_number_offset + opened.packet_number_len != plan.header_len) return error.PacketChanged;
    // RFC 9000 §17.2, §17.3.1: byte 0 says the same length once its protection is removed.
    const from_byte_0 = if (plan.level == .application)
        (header.unprotected_short(octets[0]) catch return error.PacketChanged).packet_number_len
    else
        header.unprotected_long(octets[0]) catch return error.PacketChanged;
    if (from_byte_0 != plan.packet_number_len) return error.PacketChanged;
    const payload = octets[plan.header_len..][0..opened.payload_len];
    if (!std.mem.eql(u8, payload, storage.payload[0..plan.payload_len])) return error.PacketChanged;
}

/// Runs one seed: seal, open, and open again with one octet changed.
fn run_once(storage: *Storage, seed: u64, census: *Census) Violation!void {
    var random = sim.Random.init(seed);
    prepare(storage, &random);
    draw_plans(storage, &random);
    const sender: Role = if (random.below(constants.packet_check_one_in) == 0) .client else .server;
    seal_datagram(storage, sender);
    const datagram = storage.datagram[0..storage.datagram_len];
    census.crc32.update(datagram);
    @memcpy(storage.received[0..datagram.len], datagram);
    const opened = try open_datagram(storage, sender, storage.received[0..datagram.len], true);
    assert(opened == storage.plans_len);
    // RFC 9001 §5.3: the header is the associated data and the payload is under the tag, so no
    // octet of a datagram can change and leave every packet opening.
    @memcpy(storage.received[0..datagram.len], datagram);
    const changed = random.below(datagram.len);
    storage.received[changed] ^= @as(u8, 1) << @intCast(random.below(@bitSizeOf(u8)));
    const after = try open_datagram(storage, sender, storage.received[0..datagram.len], false);
    if (after == storage.plans_len) return error.CorruptionOpened;
    census.seeds += 1;
    census.packets += storage.plans_len;
    census.octets += datagram.len;
    for (storage.plans[0..storage.plans_len]) |plan| census.by_packet_number_len[plan.packet_number_len - 1] += 1;
}

/// Runs the check over `[0, seeds)` and fills `census`.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        try run_once(storage, seed, census);
    }
    assert(census.seeds == seeds);
}

var check_storage: Storage = .zeroed;

test "what colibri frames and a suite seals, the peer reads, opens and gets back" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("packet check: seed 0x{x} broke {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Every length of the Packet Number field was drawn, so every branch of Appendix A.2 and
    // every width of the mask ran.
    for (census.by_packet_number_len) |count| try std.testing.expect(count > 0);
    try std.testing.expect(census.packets > census.seeds);
    try std.testing.expectEqual(census_packets_expected, census.packets);
    try std.testing.expectEqual(census_octets_expected, census.octets);
    try std.testing.expectEqual(census_crc32_expected, census.crc32.final());
}
