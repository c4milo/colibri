//! The QUIC connection check of `quic_connection_check.zig`, with both endpoints running BBRv3
//! (decision 136, design §8 step 29b.4): the lossy network, and each adversary. Every seed must
//! finish its handshake and its stream with invariants 17 to 21 holding, as under CUBIC, and
//! each census is pinned.
const std = @import("std");
const sim = @import("sim");
const constants = sim.constants;
const check = @import("quic_connection_check.zig");

const Adversary = check.Adversary;
const Census = check.Census;
const Storage = check.Storage;

/// The censuses under BBRv3, pinned as `quic_connection_check.zig`'s are. The handshakeloss
/// network's runs carry one small request each, so they send as many datagrams as under CUBIC,
/// at other instants.
pub const census_crc32_expected: u32 = 0x962e54a4;
pub const census_datagrams_expected: u64 = 15_142;
pub const adversary_census_crc32_expected: u32 = 0xc4bf2719;
pub const runner_census_crc32_expected: u32 = 0x8a8d08e5;
pub const runner_census_datagrams_expected: u64 = 3_905;
pub const rebind_port_census_crc32_expected: u32 = 0x2f2dd4b5;
pub const rebind_address_census_crc32_expected: u32 = 0x5b481da0;

var check_storage: Storage align(@alignOf(Storage)) = undefined;

/// Runs the check under `adversary` with both endpoints on BBRv3, and returns its census.
fn run_bbr(adversary: Adversary) !Census {
    check_storage.fault = .none;
    check_storage.adversary = adversary;
    check_storage.controller = .bbr;
    check_storage.logged = false;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    check.run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC BBRv3 {t} check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ adversary, failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    return census;
}

test "decision 136: two BBRv3 endpoints finish a handshake and a stream over a lossy network" {
    const census = try run_bbr(.none);
    try std.testing.expectEqual(census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(census_crc32_expected, census.crc32);
}

test "decision 136: BBRv3 loses no frame for good when every datagram of ACK frames alone is dropped" {
    const census = try run_bbr(.drop_ack_only);
    try std.testing.expectEqual(adversary_census_crc32_expected, census.crc32);
}

test "decision 136: BBRv3 finishes every seed of the runner's handshakeloss network" {
    const census = try run_bbr(.runner_handshake_loss);
    try std.testing.expectEqual(runner_census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(runner_census_crc32_expected, census.crc32);
}

test "decision 136: BBRv3 follows a client that a NAT moves to a new port" {
    try std.testing.expectEqual(rebind_port_census_crc32_expected, (try run_bbr(.rebind_port)).crc32);
}

test "decision 136: BBRv3 follows a client that a NAT moves to a new host and port" {
    try std.testing.expectEqual(rebind_address_census_crc32_expected, (try run_bbr(.rebind_address)).crc32);
}
