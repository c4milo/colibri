//! The check of design §8 step 8: two endpoints exchange sealed QUIC packets over the datagram
//! network, and everything that arrives opens.
//!
//! It is the first run in which the pieces of both halves meet. colibri frames a packet
//! (`quic.packet`), the null suite seals it (step 7), the network delays, drops, duplicates and
//! marks it (step 8), and the peer reads the datagram, opens the packet and compares it with what
//! was sent. What the check proves is that the three agree about sizes and about packet numbers
//! under reordering, and that one seed replays byte for byte.
//!
//! Reordering is what makes it worth running. RFC 9000 §17.1 has a sender encode a packet number
//! in a field short enough to save octets and long enough that the receiver recovers it "even if
//! the packet arrives after packets that are sent afterwards", and Appendix A.2 sizes the field
//! from the largest number the peer has acknowledged. Both endpoints are in this process, so the
//! check gives the sender exactly that number, and then requires every recovery to be exact. A
//! seed where one is not would say the rule, or colibri's reading of it, is wrong.
//!
//! The module this file belongs to imports `sim` and `quic` and no HTTP module, which is the
//! check of [decision 5](../../docs/decisions.md): QUIC is driven with nothing of HTTP in the
//! graph, held by the build and not by review.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const constants = sim.constants;

const crypto = quic.crypto;
const Writer = quic.core.Writer;
const Level = crypto.suite.Level;
const Endpoint = sim.network.Endpoint;
const Ecn = sim.network.Ecn;
const header = quic.packet.header;
const header_write = quic.packet.header_write;
const packet_number = quic.packet.packet_number;

/// The digest of every seed's run, and the counts beside it. They change when the network, the
/// null suite or a header writer changes, and are committed with the new values after both build
/// modes agree.
pub const census_crc32_expected: u32 = 0x1f31d87e;
pub const census_sent_expected: u64 = 16_384;
pub const census_delivered_expected: u64 = 16_398;

/// How a seed failed.
pub const Violation = error{
    /// A datagram the network delivered could not be read as a packet.
    DeliveredPacketNotRead,
    /// A datagram the network delivered did not open, though nothing corrupts octets here.
    DeliveredPacketNotOpened,
    /// The packet number recovered is not the one sent (RFC 9000 §17.1, Appendix A.3).
    PacketNumberWrong,
    /// The payload opened is not the one sealed.
    PayloadChanged,
    /// The network was asked to carry a datagram and had no slot, which is a harness defect.
    NetworkFull,
    /// The run ended with a datagram still in flight.
    RunNotDrained,
    /// The schedule's events did not all happen over the seeds, so the check proves less than it
    /// claims.
    ScheduleUnexercised,
};

/// A fault a test turns on to prove the check reports it. A check whose assertions never fire is
/// a check nothing proves, so each violation above has a fault here that produces it.
pub const Fault = enum {
    none,
    /// A node changes an octet of every datagram, which its tag must refuse.
    corrupt_octet,
    /// The sender writes a number in the payload that is not the one its header carries. It
    /// names an earlier packet of its own, which is in range, so only the comparison with what
    /// was recovered can catch it.
    misreport_packet_number,
    /// The sender fills the payload with octets the peer does not expect.
    scramble_payload,
    /// The run stops before everything in flight has arrived.
    skip_drain,
    /// The network loses nothing, duplicates nothing and marks nothing.
    perfect_network,
};

/// One endpoint of the exchange: its keys, its packet numbers, and what it has seen.
const Peer = struct {
    suite: sim.NullSuite,
    /// The next packet number this endpoint sends at each level (RFC 9000 §12.3).
    next_packet_number: [crypto.suite.levels_count]u64,
    /// The largest number the peer has opened at each level, which Appendix A.2 sizes the Packet
    /// Number field from. Both endpoints are in this process, so it is exact.
    acknowledged: [crypto.suite.levels_count]?u64,
    /// The largest number this endpoint has opened at each level, which Appendix A.3 recovers
    /// against.
    processed: [crypto.suite.levels_count]?u64,
};

/// The storage one run needs, which the caller places (decision 35).
pub const Storage = struct {
    /// What a test breaks on purpose. A run of the check leaves it `none`.
    fault: Fault,
    network: sim.Network,
    clock: sim.Clock,
    peers: [Endpoint.count]Peer,
    connection_id: [quic.constants.connection_id_len_max]u8,
    connection_id_len: usize,
    payload: [constants.network_check_payload_len_max]u8,
    header: [constants.network_datagram_len_max]u8,
    datagram: [constants.network_datagram_len_max]u8,

    pub const zeroed: Storage = std.mem.zeroes(Storage);

    fn peer_of(storage: *Storage, endpoint: Endpoint) *Peer {
        return &storage.peers[@intFromEnum(endpoint)];
    }
};

/// What the check counted over every seed.
pub const Census = struct {
    seeds: u64 = 0,
    sent: u64 = 0,
    delivered: u64 = 0,
    dropped: u64 = 0,
    duplicated: u64 = 0,
    reordered: u64 = 0,
    marked_congestion: u64 = 0,
    /// Deliveries recovered after a packet sent later had already been processed, which is a
    /// packet number rebuilt against a history that moved past it (RFC 9000 Appendix A.3).
    recovered_out_of_order: u64 = 0,
    crc32: std.hash.Crc32 = std.hash.Crc32.init(),
};

/// Draws the schedule of one seed: rates that leave most datagrams alone, and a delay spread
/// several times the interval between sends, so packets overtake each other.
fn draw_schedule(storage: *const Storage, random: *sim.Random) sim.network.Schedule {
    if (storage.fault == .perfect_network) return .{};
    return .{
        .drop = @intCast(random.between(0, constants.network_check_drop_max)),
        .duplicate = @intCast(random.between(0, constants.network_check_duplicate_max)),
        .mark_congestion = @intCast(random.between(0, constants.network_check_mark_max)),
        .delay_min_ns = constants.network_delay_min_ns,
        .delay_max_ns = constants.network_delay_max_ns,
    };
}

/// Sets both endpoints up as a finished handshake leaves them: Initial keys from the connection
/// ID, and the other two levels installed.
fn prepare(storage: *Storage, random: *sim.Random) void {
    storage.connection_id_len = random.between(1, storage.connection_id.len);
    for (storage.connection_id[0..storage.connection_id_len]) |*octet| octet.* = @truncate(random.next());
    for (&storage.payload) |*octet| octet.* = @truncate(random.next());
    for ([_]Endpoint{ .client, .server }) |endpoint| {
        const peer = storage.peer_of(endpoint);
        peer.suite = .{};
        const role: crypto.suite.Role = if (endpoint == .client) .client else .server;
        const suite = peer.suite.suite();
        suite.vtable.install_initial_keys(suite.context, role, storage.connection_id[0..storage.connection_id_len]) catch unreachable;
        peer.suite.install(.handshake);
        peer.suite.install(.application);
        peer.next_packet_number = @splat(0);
        peer.acknowledged = @splat(null);
        peer.processed = @splat(null);
    }
}

/// Frames, seals and sends one packet from `from` at the level the seed drew.
fn send_packet(storage: *Storage, from: Endpoint, level: Level, payload_len: usize, ecn: Ecn) Violation!void {
    const peer = storage.peer_of(from);
    const index = @intFromEnum(level);
    const full = peer.next_packet_number[index];
    // RFC 9000 §17.1, Appendix A.2: the field is sized from what the peer has acknowledged.
    const truncated = packet_number.encode(full, peer.acknowledged[index]) catch unreachable;
    var writer = Writer.init(&storage.header);
    write_header(storage, from, level, truncated, payload_len, &writer);
    // The payload carries the number the header encodes, so the peer compares what it recovered
    // with what was sent (RFC 9000 Appendix A.3).
    const misreport = storage.fault == .misreport_packet_number and full > 0;
    const reported = if (misreport) full - 1 else full;
    std.mem.writeInt(u64, storage.payload[0..constants.network_check_number_len], reported, .big);
    assert(payload_len >= constants.network_check_number_len);
    // The scramble changes what is sealed and not the pattern it is compared against, so it
    // leaves the reference the peer checks intact.
    const scramble = storage.fault == .scramble_payload;
    if (scramble) storage.payload[payload_len - 1] +%= 1;
    const suite = peer.suite.suite();
    const written = suite.seal(.{
        .level = level,
        .packet_number = full,
        .header = writer.written(),
        .packet_number_len = truncated.len,
        .payload = storage.payload[0..payload_len],
    }, &storage.datagram) catch unreachable;
    if (scramble) storage.payload[payload_len - 1] -%= 1;
    peer.next_packet_number[index] = full + 1;
    if (storage.fault == .corrupt_octet) storage.datagram[written - 1] +%= 1;
    if (storage.network.send(storage.clock.now_ns, from, storage.datagram[0..written], ecn) == .no_slot) {
        return error.NetworkFull;
    }
}

/// Writes one packet's header. Both endpoints use the one connection ID this check draws, which
/// is what a connection looks like before either issues another (RFC 9000 §5.1).
fn write_header(storage: *Storage, from: Endpoint, level: Level, truncated: packet_number.Truncated, payload_len: usize, writer: *Writer) void {
    const connection_id = storage.connection_id[0..storage.connection_id_len];
    if (level == .application) {
        const suite = storage.peer_of(from).suite.suite();
        return header_write.write_short(writer, .{
            .dcid = connection_id,
            .packet_number = truncated,
            .key_phase = suite.vtable.key_phase(suite.context),
        }) catch unreachable;
    }
    header_write.write_long(writer, .{
        .type = if (level == .initial) .initial else .handshake,
        .dcid = connection_id,
        .scid = connection_id,
        .packet_number = truncated,
        .protected_payload_len = payload_len + quic.constants.aead_tag_len,
    }) catch unreachable;
}

/// Reads and opens every datagram due for `to`, and checks each against what was sent.
fn receive_datagrams(storage: *Storage, to: Endpoint, census: *Census) Violation!void {
    // Each datagram takes a slot, so the network runs out before this loop does.
    for (0..constants.network_in_flight_max + 1) |_| {
        const delivery = storage.network.receive(storage.clock.now_ns, to) orelse return;
        census.crc32.update(delivery.octets);
        @memcpy(storage.datagram[0..delivery.octets.len], delivery.octets);
        try open_delivery(storage, to, storage.datagram[0..delivery.octets.len], census);
    }
    unreachable;
}

/// Opens one delivered datagram, which holds exactly one packet here, and compares it.
fn open_delivery(storage: *Storage, to: Endpoint, octets: []u8, census: *Census) Violation!void {
    const packet = header.read(octets, storage.connection_id_len) catch return error.DeliveredPacketNotRead;
    const framed = framed_of(packet) orelse return error.DeliveredPacketNotRead;
    const peer = storage.peer_of(to);
    const index = @intFromEnum(framed.level);
    const suite = peer.suite.suite();
    const opened = suite.open(.{
        .level = framed.level,
        .packet = octets,
        .packet_number_offset = framed.packet_number_offset,
        // RFC 9000 Appendix A.3: recovery is against what this endpoint has processed, which
        // reordering leaves behind what the peer has sent.
        .largest_packet_number = peer.processed[index],
        .current_phase_lowest = 0,
    }) catch return error.DeliveredPacketNotOpened;
    const sender = storage.peer_of(to.peer());
    const payload = octets[framed.packet_number_offset + opened.packet_number_len ..][0..opened.payload_len];
    if (payload.len < constants.network_check_number_len) return error.PayloadChanged;
    // The number the sender wrote inside the packet is the one the peer must have rebuilt from
    // the field's octets and its own history (RFC 9000 §17.1, Appendix A.3).
    const sent_number = std.mem.readInt(u64, payload[0..constants.network_check_number_len], .big);
    if (sent_number != opened.packet_number) return error.PacketNumberWrong;
    if (sent_number >= sender.next_packet_number[index]) return error.PacketNumberWrong;
    if (!std.mem.eql(u8, payload[constants.network_check_number_len..], storage.payload[constants.network_check_number_len..payload.len])) {
        return error.PayloadChanged;
    }
    // A number below what this endpoint has already processed was rebuilt against a history that
    // had moved past it, which is the case reordering creates.
    if (peer.processed[index]) |highest| {
        if (opened.packet_number < highest) census.recovered_out_of_order += 1;
    }
    peer.processed[index] = @max(peer.processed[index] orelse 0, opened.packet_number);
    // What a peer has acknowledged arrives on the return path, so an endpoint learns it when a
    // datagram comes back and not when its own packet is opened. RFC 9000 §13.2.1 lets an
    // acknowledgment be delayed, so this is the earliest a real endpoint could learn; a field
    // sized from it is the narrowest Appendix A.2 permits, which is the strict case for
    // recovery under reordering.
    peer.acknowledged[index] = sender.processed[index];
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

/// Runs one seed: both endpoints take turns sending, the clock moves, and everything in flight
/// arrives before the run ends.
fn run_once(storage: *Storage, seed: u64, census: *Census) Violation!void {
    var random = sim.Random.init(seed);
    storage.clock = sim.Clock.init();
    storage.network.init(seed, draw_schedule(storage, &random));
    prepare(storage, &random);
    for (0..constants.network_check_turns) |turn| {
        const from: Endpoint = if (turn % Endpoint.count == 0) .client else .server;
        const level = draw_level(&random);
        const payload_len = random.between(constants.network_check_number_len, constants.network_check_payload_len_max);
        const ecn: Ecn = if (random.below(constants.network_check_one_in) == 0) .ect_0 else .not_ect;
        try send_packet(storage, from, level, payload_len, ecn);
        storage.clock.advance(constants.network_check_turn_ns);
        for ([_]Endpoint{ .client, .server }) |to| try receive_datagrams(storage, to, census);
    }
    try drain(storage, census);
    add_to_census(storage, census);
}

/// The level one packet is sent at. The application level is the commonest, as it is on a
/// connection that has finished its handshake.
fn draw_level(random: *sim.Random) Level {
    return switch (random.below(constants.network_check_level_weights)) {
        0 => .initial,
        1 => .handshake,
        else => .application,
    };
}

/// Advances the clock to each arrival until nothing is in flight, so no run ends holding a
/// datagram and every seed's counts are final.
fn drain(storage: *Storage, census: *Census) Violation!void {
    // The fault leaves the datagrams where they are, so what reports the run is the count below
    // and not the fault itself.
    if (storage.fault != .skip_drain) {
        for (0..constants.network_in_flight_max + 1) |_| {
            const arrival_ns = storage.network.next_arrival_ns() orelse break;
            storage.clock.now_ns = @max(storage.clock.now_ns, arrival_ns);
            for ([_]Endpoint{ .client, .server }) |to| try receive_datagrams(storage, to, census);
        }
    }
    if (storage.network.in_flight_count() != 0) return error.RunNotDrained;
}

fn add_to_census(storage: *Storage, census: *Census) void {
    const counted = storage.network.census;
    census.seeds += 1;
    census.sent += counted.sent;
    census.delivered += counted.delivered;
    census.dropped += counted.dropped;
    census.duplicated += counted.duplicated;
    census.reordered += counted.reordered;
    census.marked_congestion += counted.marked_congestion;
}

/// Runs the check over `[0, seeds)` and fills `census`.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        try run_once(storage, seed, census);
    }
    failed_seed.* = null;
    // A run in which nothing was dropped, duplicated, reordered or marked would pass while
    // proving none of what this check claims.
    const unexercised = census.dropped == 0 or census.duplicated == 0 or
        census.reordered == 0 or census.marked_congestion == 0 or census.recovered_out_of_order == 0;
    if (unexercised) return error.ScheduleUnexercised;
    assert(census.seeds == seeds);
}

var check_storage: Storage = .zeroed;

test "sealed packets survive a network that delays, drops, duplicates and marks them" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("network check: seed 0x{x} broke {t}\n", .{ failed_seed orelse 0, failure });
        return failure;
    };
    try std.testing.expectEqual(census_sent_expected, census.sent);
    try std.testing.expectEqual(census_delivered_expected, census.delivered);
    try std.testing.expectEqual(census_crc32_expected, census.crc32.final());
    // Every event the schedule can produce happened, and reordering rebuilt thousands of packet
    // numbers against a history that had moved past them, each one exactly (Appendix A.3).
    try std.testing.expect(census.recovered_out_of_order > census.seeds);
    try std.testing.expect(census.delivered > census.sent - census.dropped);
}

/// The storage a fault test runs in, apart from the check's own. Test-only.
var fault_storage: Storage = .zeroed;

test "each fault the check can report is reported, so no assertion of it is unproved" {
    const cases = [_]struct { fault: Fault, violation: Violation }{
        .{ .fault = .corrupt_octet, .violation = error.DeliveredPacketNotOpened },
        .{ .fault = .misreport_packet_number, .violation = error.PacketNumberWrong },
        .{ .fault = .scramble_payload, .violation = error.PayloadChanged },
        .{ .fault = .skip_drain, .violation = error.RunNotDrained },
        .{ .fault = .perfect_network, .violation = error.ScheduleUnexercised },
    };
    for (cases) |case| {
        fault_storage.fault = case.fault;
        var census: Census = .{};
        var failed_seed: ?u64 = null;
        try std.testing.expectError(case.violation, run_check(&fault_storage, 1, &census, &failed_seed));
    }
    // With nothing broken the same one seed passes, so a fault and not the run is what failed.
    fault_storage.fault = .none;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    try run_check(&fault_storage, constants.check_seeds_default, &census, &failed_seed);
    try std.testing.expectEqual(null, failed_seed);
}
