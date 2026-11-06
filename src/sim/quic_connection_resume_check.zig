//! The QUIC connection check of `quic_connection_check.zig`, with the client resuming from an RFC
//! 9959 saved set (decision 149, design §8 step 35e): a network that loses little, under each
//! controller.
//! Every seed must finish its handshake and its stream with invariants 17 to 21 holding. Some
//! seeds must jump the window and some must retreat, or the network proved nothing of Careful
//! Resume, and each census is pinned.
const std = @import("std");
const quic = @import("quic");
const sim = @import("sim");
const constants = sim.constants;
const check = @import("quic_connection_check.zig");

const Census = check.Census;
const Storage = check.Storage;

/// The saved set's window for each controller, and the round trip of `light_loss`'s one delay each
/// way, saved at the run's start. Under CUBIC and NewReno the window is 120,000 octets: its jump of
/// 60,000 passes the window slow start has reached once the initial window is acknowledged, about
/// 35,000, or §3.3 leaves nothing to jump. Under BBRv3 it is 60,000: Appendix C's window is twice the
/// probing rate's BDP, and both fit the network's `network_in_flight_max` slots with the
/// acknowledgments.
const windowed_saved_len: u64 = 120_000;
const bbr_saved_len: u64 = 60_000;
/// One delay each way.
const round_trip_ns: u64 = check.light_delay_ns + check.light_delay_ns;

fn saved_for(controller: quic.CongestionController) quic.ResumeState {
    return .{
        .window_len = if (controller == .bbr) bbr_saved_len else windowed_saved_len,
        .rtt_ns = round_trip_ns,
        .saved_at_ns = check.start_ns,
    };
}

pub const cubic_census_crc32_expected: u32 = 0xd172ab1d;
pub const newreno_census_crc32_expected: u32 = 0xa6e99f3b;
pub const bbr_census_crc32_expected: u32 = 0x029edec0;

var check_storage: Storage align(@alignOf(Storage)) = undefined;

fn run_resumed(controller: quic.CongestionController) !Census {
    check_storage.fault = .none;
    check_storage.adversary = .light_loss;
    check_storage.controller = controller;
    check_storage.resumed_from = saved_for(controller);
    check_storage.logged = false;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    check.run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC resume {t} check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ controller, failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    return census;
}

fn expect_resumed(controller: quic.CongestionController, expected_crc32: u32) !void {
    const census = try run_resumed(controller);
    // RFC 9959 §3.3 and §3.5: the network both lets clients jump and makes some retreat.
    try std.testing.expect(census.resume_jumps > 0);
    try std.testing.expect(census.resume_retreats > 0);
    try std.testing.expect(census.resume_retreats <= census.resume_jumps);
    try std.testing.expectEqual(expected_crc32, census.crc32);
}

test "RFC 9959: a CUBIC client resumes from a saved set over a network that loses little" {
    try expect_resumed(.cubic, cubic_census_crc32_expected);
}

test "RFC 9959: a NewReno client resumes from a saved set over a network that loses little" {
    try expect_resumed(.newreno, newreno_census_crc32_expected);
}

test "RFC 9959 Appendix C: a BBRv3 client resumes from a saved set over a network that loses little" {
    try expect_resumed(.bbr, bbr_census_crc32_expected);
}
