//! The check of design §8 step 10: RFC 9002's loss recovery driven over the datagram network,
//! under loss, under reordering, and through a path that swallows everything for a while.
//!
//! One endpoint sends, the other acknowledges. The sender is `quic.recovery`, whole: the round
//! trip estimator, the sent-packet tables, §6.1's two loss thresholds, §6.2's Probe Timeout,
//! NewReno and the pacer. The receiver is `quic.space`, which suppresses duplicates and writes
//! real ACK frames, so what the sender reads back is octets off the wire and not a struct handed
//! across.
//!
//! What it proves is the part unit tests cannot: that the pieces agree over a whole transfer. No
//! packet is ever both acknowledged and declared lost, nothing is left outstanding when the run
//! drains, the octets in flight never pass the congestion window, and the window never falls
//! under RFC 9002 §7.2's minimum. A seed replays byte for byte, which is invariant 5.
//!
//! The module this file belongs to imports `sim` and `quic` and no HTTP module, which is the
//! check of [decision 5](../../docs/decisions.md).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const constants = sim.constants;
const recovery_check_run = @import("recovery_check_run.zig");

pub const run_seed = recovery_check_run.run_seed;

const Network = sim.network.Network;
const Schedule = sim.network.Schedule;
const Recovery = quic.recovery.Recovery;
const Space = quic.space.Space;
const Record = quic.recovery_sent.Record;

/// The digest of every seed's run and the counts beside it. They change when the network, the
/// recovery code or the ACK writer changes, and are committed with the new values after both
/// build modes agree.
pub const census_crc32_expected: u32 = 0x2c3cc41a;
pub const census_sent_expected: u64 = 16_420;
pub const census_acknowledged_expected: u64 = 11_743;
pub const census_lost_expected: u64 = 4_677;

/// How a seed failed.
pub const Violation = error{
    /// A packet was acknowledged and also declared lost, or declared lost twice. RFC 9002 §6.1
    /// removes a packet from `sent_packets` either way, so neither can happen.
    PacketCountedTwice,
    /// The run drained with packets still outstanding, so the sender would wait forever.
    NotDrained,
    /// A packet went out that took the octets in flight past the congestion window. RFC 9002 §7
    /// bounds what a sender adds, not what is already outstanding: halving the window on a
    /// congestion event leaves more in flight than it allows, and the sender waits rather than
    /// unsending anything.
    WindowExceeded,
    /// The window fell under RFC 9002 §7.2's minimum.
    WindowUnderMinimum,
    /// A datagram the receiver took could not be read.
    DatagramNotRead,
    /// The network was asked to carry a datagram and had no slot, which is a harness defect.
    NetworkFull,
    /// The run hit its step bound with work still to do, so the check proves less than it claims.
    StepsExhausted,
    /// The scenarios did not all happen over the seeds, so the check proves less than it claims.
    ScenariosUnexercised,
};

/// The four paths a seed draws from.
pub const Scenario = enum(u2) {
    /// A quiet path: the estimator settles and the window grows.
    clean,
    /// One datagram in ten is dropped, which is what §6.1's thresholds exist for.
    loss,
    /// A delay range wider than the sending interval, which reorders and must not be read as
    /// loss by anything but §6.1.1's count of three.
    reorder,
    /// A stretch where the path swallows everything, which is what §7.6's persistent congestion
    /// is defined over.
    blackhole,

    pub fn schedule(scenario: Scenario) Schedule {
        return switch (scenario) {
            .clean => .{},
            .loss => .{ .drop = drop_rate },
            .reorder => .{ .delay_min_ns = reorder_delay_min_ns, .delay_max_ns = reorder_delay_max_ns },
            .blackhole => .{},
        };
    }
};

/// One seed's counts.
pub const Result = struct {
    scenario: Scenario,
    sent: u64 = 0,
    acknowledged: u64 = 0,
    lost: u64 = 0,
    probes: u64 = 0,
    /// The window at the end, and the smallest it reached.
    window: u64 = 0,
    window_min: u64 = 0,
    /// The smoothed estimate at the end, or zero where no sample was taken.
    smoothed_rtt_ns: u64 = 0,
    /// The digest of every octet the seed put on the path, so a change in what was sent moves
    /// the census even where the counts do not.
    octets_crc32: u32 = 0,
};

/// What the whole run counted, which a check compares across build modes and hosts.
pub const Census = struct {
    crc32: u32 = 0,
    sent: u64 = 0,
    acknowledged: u64 = 0,
    lost: u64 = 0,
    probes: u64 = 0,
    /// How many seeds drew each scenario, so an unexercised one is visible.
    scenarios: [scenario_count]u64 = @splat(0),
};

/// The storage one run needs, placed outside any stack frame.
pub const Storage = struct {
    sender: Recovery,
    receiver: Space,
    network: Network,
    lost: [quic.constants.sent_packets_max]Record,
    /// Whether the packet of that number is still outstanding as far as the harness knows, and
    /// whether it has been accounted for. The two together are what catch a packet leaving
    /// `sent_packets` twice.
    outstanding: [numbers_max]bool,
    settled: [numbers_max]bool,
    datagram: [constants.network_datagram_len_max]u8,

    pub const zeroed: Storage = std.mem.zeroes(Storage);
};

/// How many ack-eliciting packets of data one seed sends, and the octets each carries.
pub const packets_per_seed: usize = 64;
/// How many packet numbers a seed may use in all. The rest are RFC 9002 Appendix A.9's probes,
/// which carry no new data and go out when the Probe Timeout fires. A run that needs more than
/// this is not draining, and `StepsExhausted` is the right answer to it.
pub const numbers_max: usize = packets_per_seed * probe_numbers_factor;
/// How many times a seed's data packets the number space is, leaving the rest for probes.
pub const probe_numbers_factor: usize = 4;
pub const datagram_len: u16 = @intCast(quic.constants.datagram_len_min);
/// The first octet of a datagram says which of the two it is.
pub const kind_data: u8 = 0x01;
pub const kind_ack: u8 = 0x02;
/// One datagram in ten is dropped in the loss scenario, out of `schedule_denominator`.
pub const drop_rate: u32 = constants.schedule_denominator / drop_one_in;
pub const drop_one_in: u32 = 10;
/// A delay range several sending intervals wide, which is what reorders.
pub const reorder_delay_min_ns: u64 = 5_000_000;
pub const reorder_delay_max_ns: u64 = 60_000_000;
/// How long the blackhole scenario swallows everything, and when it starts.
pub const blackhole_from_ns: u64 = 200_000_000;
pub const blackhole_until_ns: u64 = 2_000_000_000;
/// How far the driver may step before it gives up, which bounds every loop below.
pub const steps_max: usize = 100_000;
/// The instant a run starts, and the smallest step it takes when nothing else is due.
pub const start_ns: u64 = 1_000_000;
pub const idle_step_ns: u64 = 1_000_000;
/// This endpoint's `ack_delay_exponent` (RFC 9000 §18.2), left at the default.
pub const ack_delay_exponent: u6 = 3;
pub const scenario_count: usize = @typeInfo(Scenario).@"enum".fields.len;

/// Runs the check over `[0, seeds)` and fills `census`.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    // Bounded by the caller's seed count.
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        const result = try run_seed(storage, seed);
        census.sent += result.sent;
        census.acknowledged += result.acknowledged;
        census.lost += result.lost;
        census.probes += result.probes;
        census.scenarios[@intFromEnum(result.scenario)] += 1;
        census.crc32 = combine(census.crc32, result);
    }
    failed_seed.* = null;
    std.debug.print("PROBE recovery sent={d} acked={d} lost={d} probes={d} scenarios={any} crc32=0x{x:0>8}\n", .{ census.sent, census.acknowledged, census.lost, census.probes, census.scenarios, census.crc32 });
    // A run in which nothing was lost, no probe fired, or a scenario never came up would pass
    // while proving none of what this check claims.
    if (census.lost == 0 or census.probes == 0) return Violation.ScenariosUnexercised;
    // Bounded by the four scenarios.
    for (census.scenarios) |count| {
        if (count == 0) return Violation.ScenariosUnexercised;
    }
}

/// Folds one seed's counts into the digest, so a change in any of them moves it. Each field is
/// fed in on its own: feeding the struct would feed its padding too, and padding is uninitialized
/// memory, which invariant 5 forbids a protocol path or a check from reading.
fn combine(held: u32, result: Result) u32 {
    var digest = std.hash.Crc32.init();
    fold(&digest, held);
    fold(&digest, @intFromEnum(result.scenario));
    fold(&digest, result.sent);
    fold(&digest, result.acknowledged);
    fold(&digest, result.lost);
    fold(&digest, result.probes);
    fold(&digest, result.window);
    fold(&digest, result.window_min);
    fold(&digest, result.smoothed_rtt_ns);
    fold(&digest, result.octets_crc32);
    return digest.final();
}

/// Feeds one value in network byte order, so the digest does not follow the host's (CLAUDE.md).
fn fold(digest: *std.hash.Crc32, value: u64) void {
    var octets: [@sizeOf(u64)]u8 = undefined;
    std.mem.writeInt(u64, &octets, value, .big);
    digest.update(&octets);
}

var check_storage: Storage = .zeroed;

test "loss recovery carries a transfer over loss, reordering and a blackhole" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("recovery check: seed 0x{x} broke {t}\n", .{ failed_seed orelse 0, failure });
        return failure;
    };
    try std.testing.expectEqual(census_sent_expected, census.sent);
    try std.testing.expectEqual(census_acknowledged_expected, census.acknowledged);
    try std.testing.expectEqual(census_lost_expected, census.lost);
    try std.testing.expectEqual(census_crc32_expected, census.crc32);
}
