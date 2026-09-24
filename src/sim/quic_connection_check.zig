//! The check of design §8 step 9e's piece 10: two colibri endpoints complete a handshake and move
//! one stream across the datagram network of step 8, with invariants 17 to 21 read after every
//! datagram and every step, over a range of seeds.
//!
//! Each endpoint is a `quic.Connection` with the null QUIC provider and the null suite
//! (`quic_endpoint.zig`). The network drops, duplicates and reorders by seed, so the handshake has
//! to finish through RFC 9002's loss recovery and the stream through §13.3's retransmission.
//!
//! What it proves is the part unit tests cannot: that the pieces agree over a whole connection.
//! A packet number is never reused (invariant 17), a server never sends past three times what it
//! received (18), a flow control limit never falls (19), every datagram goes to the one path's
//! connection ID (20), and no level is sealed or opened without its keys (21). A seed replays byte
//! for byte, which is invariant 5.
//!
//! The module this file belongs to imports `sim` and `quic` and no HTTP module, which is the check
//! of [decision 5](../../docs/decisions.md).
const std = @import("std");
const sim = @import("sim");
const quic = @import("quic");
const constants = sim.constants;
const quic_endpoint = @import("quic_endpoint.zig");
const quic_invariants = @import("quic_invariants.zig");
const quic_connection_run = @import("quic_connection_run.zig");

pub const run_seed = quic_connection_run.run_seed;

/// The digest of every seed's run and the counts beside it. They change when the network, the
/// null provider or suite, or colibri's connection changes, and are committed with the new values
/// after both build modes agree.
pub const census_crc32_expected: u32 = 0x8f7db94c;
pub const census_datagrams_expected: u64 = 13_942;
pub const census_packets_expected: u64 = 14_022;
pub const census_dropped_expected: u64 = 695;
pub const census_marked_expected: u64 = 545;

/// How a seed failed.
pub const Violation = quic_invariants.Violation || error{
    /// An endpoint stopped with a connection error or a refused send. Two colibri endpoints
    /// never give each other a reason to close, so any is a defect. `Storage.failure` says which.
    ConnectionError,
    /// The network was asked to carry a datagram and had no slot, which is a harness defect.
    NetworkFull,
    /// An endpoint was still sending at the bound on one step's sends.
    SendsExhausted,
    /// The run hit its step bound before the connection finished.
    StepsExhausted,
    /// Nothing was dropped over the seeds, so the check proved less than it claims.
    ScheduleUnexercised,
    /// An endpoint stopped marking ECT(0) because RFC 9000 §13.4.2.1's validation failed, over a
    /// network that marks nothing but ECN-CE.
    EcnValidationFailed,
};

/// One seed's counts.
pub const Result = struct {
    steps: u64 = 0,
    datagrams: u64 = 0,
    packets: u64 = 0,
    /// How long the run took, from the first instant to the last.
    finished_ns: u64 = 0,
    /// The client's smoothed round trip at the end (RFC 9002 §5.3).
    round_trip_ns: u64 = 0,
    /// The digest of every datagram either endpoint sent.
    octets_crc32: u32 = 0,
    /// Datagrams the adversary dropped.
    adversary_dropped: u64 = 0,
    /// The instant both endpoints had confirmed the handshake, from the run's start.
    handshake_ns: u64 = 0,
    /// How many times the server's path moved to its client's new address (RFC 9000 §9.3).
    migrations: u64 = 0,
};

/// What the whole run counted, which the test compares across build modes and hosts.
pub const Census = struct {
    crc32: u32 = 0,
    datagrams: u64 = 0,
    packets: u64 = 0,
    dropped: u64 = 0,
    duplicated: u64 = 0,
    reordered: u64 = 0,
    /// Datagrams the adversary dropped before the network saw them.
    adversary_dropped: u64 = 0,
    /// Datagrams the network marked ECN-CE (RFC 9000 §13.4).
    marked: u64 = 0,
    /// The longest any seed took to confirm the handshake at both endpoints.
    handshake_max_ns: u64 = 0,
    /// Rebinds the network made, datagrams it dropped for going to a lost binding, and moves the
    /// server made to follow.
    rebinds: u64 = 0,
    misrouted: u64 = 0,
    migrations: u64 = 0,
};

/// What a run's network does beside, or instead of, its random schedule.
pub const Adversary = enum {
    none,
    /// Drops every datagram whose packets are none of them ack-eliciting: ACK frames alone, as
    /// RFC 9002 §2 counts them. A sender then learns of no loss from an acknowledgment, and only
    /// what its probes carry sends a lost frame again (decisions 64 and 66). A run under it ends
    /// once the server has read the stream: the client's acknowledgment of it never arrives.
    drop_ack_only,
    /// The QUIC Interop Runner's handshakeloss network in place of the random schedule: its
    /// drop-rate scenario with `runner_drop`, `runner_drop_run_max` and `runner_delay_ns`.
    runner_handshake_loss,
    /// The random schedule, and a NAT that gives the client a new port `rebind_after_handshake_ns`
    /// after the handshake is confirmed and every `rebind_every_ns` after that, as the runner's
    /// rebind-port case does. The server follows its client (RFC 9000 §9.3, decision 72).
    rebind_port,
    /// The same, with a new host each time too, as the runner's rebind-addr case does.
    rebind_address,
};

/// When a rebinding run's NAT first gives the client a new binding, after the handshake is
/// confirmed, and how often after that. A NAT drops what the server sends to a binding it has
/// just replaced, so rebinds much closer than the round trip leave the server nothing it can
/// reach; the interval is five of the network's longest round trips, as the runner's 5 seconds
/// are many of its 30 ms ones.
pub const rebind_after_handshake_ns: u64 = 50_000_000;
pub const rebind_every_ns: u64 = 500_000_000;

/// The runner's handshakeloss scenario: 30% of datagrams dropped toward each endpoint, at most 3
/// in a row, and 15 ms each way.
pub const runner_drop: u32 = 300;
pub const runner_drop_run_max: u32 = 3;
pub const runner_delay_ns: u64 = 15_000_000;

/// A defect a test puts into a run, so each way the driver fails is shown to fail.
pub const Fault = enum {
    none,
    /// The server's provider raises an alert, which RFC 9001 §4.8 makes a connection error.
    server_alert,
    /// The server's suite reports a refusal before the run starts, which the first step's read
    /// of invariant 21 must report.
    keys_refused,
    /// The client's history already holds the number of its first Initial, so its first datagram
    /// repeats one, which the read of invariant 17 on every datagram must report.
    number_reused,
    /// The client supplies its stream's first octet changed, which the server's read must report
    /// (decision 61).
    wrong_octet,
    /// The network carries every datagram Not-ECT, as a path that clears the ECN field does,
    /// which RFC 9000 §13.4.2.1's validation must catch.
    ecn_cleared,
};

/// The storage one run needs, placed outside any stack frame (decision 35).
pub const Storage = struct {
    fault: Fault,
    adversary: Adversary,
    endpoints: [sim.network.Endpoint.count]quic_endpoint.Endpoint,
    histories: [sim.network.Endpoint.count]quic_invariants.History,
    network: sim.Network,
    /// The error an endpoint stopped with, for the trace of a failed seed.
    failure: ?quic_endpoint.Error,
};

/// The instant a run starts, and the longest step it takes when nothing is due sooner.
pub const start_ns: u64 = 1_000_000;
pub const idle_step_ns: u64 = 10_000_000;
/// How far the driver may step before it gives up, which bounds the run.
pub const steps_max: usize = 20_000;
/// How many datagrams one endpoint may send in one step. The congestion window stops it first.
pub const sends_per_step_max: usize = 64;
/// The highest rates a seed draws, out of `schedule_denominator`.
pub const drop_max: u64 = 100;
pub const duplicate_max: u64 = 100;
pub const mark_max: u64 = 100;

/// Runs the check over `[0, seeds)` and fills `census`.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    // Bounded by the caller's seed count.
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        const result = try run_seed(storage, seed);
        census.datagrams += result.datagrams;
        census.packets += result.packets;
        census.dropped += storage.network.census.dropped;
        census.duplicated += storage.network.census.duplicated;
        census.reordered += storage.network.census.reordered;
        census.marked += storage.network.census.marked_congestion;
        census.adversary_dropped += result.adversary_dropped;
        census.handshake_max_ns = @max(census.handshake_max_ns, result.handshake_ns);
        census.rebinds += storage.network.census.rebinds;
        census.misrouted += storage.network.census.misrouted;
        census.migrations += result.migrations;
        census.crc32 = combine(census.crc32, result);
    }
    failed_seed.* = null;
    // A run that lost nothing would pass while proving nothing of loss recovery.
    if (!exercised(storage.adversary, census)) return Violation.ScheduleUnexercised;
}

/// Whether the seeds did what the run's network is there to do: the random schedule dropped,
/// duplicated, reordered and marked, and an adversary dropped.
fn exercised(adversary: Adversary, census: *const Census) bool {
    const random = census.dropped > 0 and census.duplicated > 0 and census.reordered > 0 and census.marked > 0;
    return switch (adversary) {
        .none => random,
        .drop_ack_only => random and census.adversary_dropped > 0,
        .rebind_port, .rebind_address => random and census.rebinds > 0 and census.migrations > 0,
        // The runner's scenario delays every datagram alike and marks none, so drops are all it has.
        .runner_handshake_loss => census.dropped > 0,
    };
}

/// Folds one seed's counts into the digest, one field at a time, so struct padding is never read
/// (invariant 5).
fn combine(held: u32, result: Result) u32 {
    var digest = std.hash.Crc32.init();
    fold(&digest, held);
    fold(&digest, result.steps);
    fold(&digest, result.datagrams);
    fold(&digest, result.packets);
    fold(&digest, result.finished_ns);
    fold(&digest, result.round_trip_ns);
    fold(&digest, result.octets_crc32);
    return digest.final();
}

/// Feeds one value in network byte order, so the digest does not follow the host's (CLAUDE.md).
fn fold(digest: *std.hash.Crc32, value: u64) void {
    var octets: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, &octets, value, .big);
    digest.update(&octets);
}

var check_storage: Storage = undefined;

test "two endpoints finish a handshake and a stream over a lossy network, invariants 17 to 21 holding" {
    check_storage.fault = .none;
    check_storage.adversary = .none;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC connection check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    try std.testing.expectEqual(census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(census_packets_expected, census.packets);
    try std.testing.expectEqual(census_dropped_expected, census.dropped);
    try std.testing.expectEqual(census_marked_expected, census.marked);
    try std.testing.expectEqual(census_crc32_expected, census.crc32);
}

/// The storage a fault test runs in, apart from the check's own. Test-only.
var fault_storage: Storage = undefined;

test "each way the driver fails is reported, so no report of it is unproved" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    fault_storage.adversary = .none;
    // An endpoint that stops ends the run, and the run keeps the error it stopped with.
    fault_storage.fault = .server_alert;
    try std.testing.expectError(Violation.ConnectionError, run_check(&fault_storage, 1, &census, &failed_seed));
    try std.testing.expectEqual(error.TlsAlert, fault_storage.failure.?);
    // Each invariant is read during the run, after every step and every datagram.
    fault_storage.fault = .keys_refused;
    try std.testing.expectError(Violation.KeysUnavailable, run_check(&fault_storage, 1, &census, &failed_seed));
    fault_storage.fault = .number_reused;
    try std.testing.expectError(Violation.PacketNumberReused, run_check(&fault_storage, 1, &census, &failed_seed));
    // The server reads the client's stream and checks every octet it reads.
    fault_storage.fault = .wrong_octet;
    try std.testing.expectError(Violation.ConnectionError, run_check(&fault_storage, 1, &census, &failed_seed));
    try std.testing.expectEqual(error.TransferOctetWrong, fault_storage.failure.?);
    // Each endpoint's ECN validation is read when the run ends.
    fault_storage.fault = .ecn_cleared;
    try std.testing.expectError(Violation.EcnValidationFailed, run_check(&fault_storage, 1, &census, &failed_seed));
    // A check that dropped nothing proved nothing of loss recovery, and says so.
    fault_storage.fault = .none;
    try std.testing.expectError(Violation.ScheduleUnexercised, run_check(&fault_storage, 0, &census, &failed_seed));
}

/// The adversary check's census, pinned as the lossy check's is.
pub const adversary_census_crc32_expected: u32 = 0x0974863e;
pub const adversary_census_datagrams_expected: u64 = 5_132;
pub const adversary_census_dropped_expected: u64 = 1_665;

test "decisions 64 and 66: a network that drops every datagram of ACK frames alone loses no frame for good" {
    check_storage.fault = .none;
    check_storage.adversary = .drop_ack_only;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC adversary check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    try std.testing.expectEqual(adversary_census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(adversary_census_dropped_expected, census.adversary_dropped);
    try std.testing.expectEqual(adversary_census_crc32_expected, census.crc32);
}

/// The runner check's census, pinned as the lossy check's is. `handshake_max_ns` is the slowest
/// seed's handshake, which the doubling Probe Timeout of RFC 9002 §6.2.1 sets under this loss.
/// Decision 70 brought it from 10.4 to 8.4 seconds.
pub const runner_census_crc32_expected: u32 = 0x2dbc4723;
pub const runner_census_datagrams_expected: u64 = 4_178;
pub const runner_census_dropped_expected: u64 = 1_209;
pub const runner_census_handshake_max_ns_expected: u64 = 8_397_000_000;

test "the QUIC Interop Runner's handshakeloss network: every seed finishes" {
    check_storage.fault = .none;
    check_storage.adversary = .runner_handshake_loss;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC runner check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    try std.testing.expectEqual(runner_census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(runner_census_dropped_expected, census.dropped);
    try std.testing.expectEqual(runner_census_handshake_max_ns_expected, census.handshake_max_ns);
    try std.testing.expectEqual(runner_census_crc32_expected, census.crc32);
}

/// The rebinding checks' censuses, pinned as the lossy check's is. The server moved once for each
/// rebind: 276 of each in the port check and 275 in the address check.
pub const rebind_port_census_crc32_expected: u32 = 0x0fb2a063;
pub const rebind_port_census_datagrams_expected: u64 = 14_574;
pub const rebind_port_census_migrations_expected: u64 = 276;
pub const rebind_address_census_crc32_expected: u32 = 0x79c5e069;
pub const rebind_address_census_datagrams_expected: u64 = 14_380;
pub const rebind_address_census_migrations_expected: u64 = 275;

/// Runs the check under `adversary` and returns its census.
fn run_rebinding(adversary: Adversary) !Census {
    check_storage.fault = .none;
    check_storage.adversary = adversary;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC {t} check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ adversary, failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    return census;
}

test "decision 72: a NAT that gives the client a new port leaves the server following it" {
    const census = try run_rebinding(.rebind_port);
    try std.testing.expectEqual(rebind_port_census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(rebind_port_census_migrations_expected, census.migrations);
    try std.testing.expectEqual(rebind_port_census_crc32_expected, census.crc32);
}

test "decision 72: a NAT that gives the client a new host and port leaves the server following it" {
    const census = try run_rebinding(.rebind_address);
    try std.testing.expectEqual(rebind_address_census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(rebind_address_census_migrations_expected, census.migrations);
    try std.testing.expectEqual(rebind_address_census_crc32_expected, census.crc32);
}
