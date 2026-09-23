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
pub const census_crc32_expected: u32 = 0x1693a3d7;
pub const census_datagrams_expected: u64 = 13_986;
pub const census_packets_expected: u64 = 13_991;
pub const census_dropped_expected: u64 = 722;

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
};

/// What the whole run counted, which the test compares across build modes and hosts.
pub const Census = struct {
    crc32: u32 = 0,
    datagrams: u64 = 0,
    packets: u64 = 0,
    dropped: u64 = 0,
    duplicated: u64 = 0,
    reordered: u64 = 0,
};

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
};

/// The storage one run needs, placed outside any stack frame (decision 35).
pub const Storage = struct {
    fault: Fault,
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
        census.crc32 = combine(census.crc32, result);
    }
    failed_seed.* = null;
    // A run that lost nothing would pass while proving nothing of loss recovery.
    if (census.dropped == 0 or census.duplicated == 0 or census.reordered == 0) return Violation.ScheduleUnexercised;
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
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC connection check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    try std.testing.expectEqual(census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(census_packets_expected, census.packets);
    try std.testing.expectEqual(census_dropped_expected, census.dropped);
    try std.testing.expectEqual(census_crc32_expected, census.crc32);
}

/// The storage a fault test runs in, apart from the check's own. Test-only.
var fault_storage: Storage = undefined;

test "each way the driver fails is reported, so no report of it is unproved" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    // An endpoint that stops ends the run, and the run keeps the error it stopped with.
    fault_storage.fault = .server_alert;
    try std.testing.expectError(Violation.ConnectionError, run_check(&fault_storage, 1, &census, &failed_seed));
    try std.testing.expectEqual(error.TlsAlert, fault_storage.failure.?);
    // Each invariant is read during the run, after every step and every datagram.
    fault_storage.fault = .keys_refused;
    try std.testing.expectError(Violation.KeysUnavailable, run_check(&fault_storage, 1, &census, &failed_seed));
    fault_storage.fault = .number_reused;
    try std.testing.expectError(Violation.PacketNumberReused, run_check(&fault_storage, 1, &census, &failed_seed));
    // A check that dropped nothing proved nothing of loss recovery, and says so.
    fault_storage.fault = .none;
    try std.testing.expectError(Violation.ScheduleUnexercised, run_check(&fault_storage, 0, &census, &failed_seed));
}
