//! The QUIC connection check of `quic_connection_check.zig`, with both endpoints running RFC 9002's
//! NewReno (decision 133 as amended, design §8 step 34): the lossy network, and each adversary.
//! Every seed must finish its handshake and its stream with invariants 17 to 21 holding, as under
//! CUBIC, and each census is pinned.
const std = @import("std");
const sim = @import("sim");
const constants = sim.constants;
const check = @import("quic_connection_check.zig");

const Adversary = check.Adversary;
const Census = check.Census;
const Storage = check.Storage;

/// The censuses under NewReno, pinned as `quic_connection_check.zig`'s are.
pub const census_crc32_expected: u32 = 0x7b05e404;
pub const census_datagrams_expected: u64 = 13_316;
pub const adversary_census_crc32_expected: u32 = 0x2be12464;
pub const runner_census_crc32_expected: u32 = 0x7d50767c;
pub const runner_census_datagrams_expected: u64 = 3_905;
pub const rebind_port_census_crc32_expected: u32 = 0xb42ef40f;
pub const rebind_address_census_crc32_expected: u32 = 0x24064aab;

var check_storage: Storage align(@alignOf(Storage)) = undefined;

/// Runs the check under `adversary` with both endpoints on NewReno, and returns its census.
fn run_newreno(adversary: Adversary) !Census {
    check_storage.fault = .none;
    check_storage.adversary = adversary;
    check_storage.controller = .newreno;
    check_storage.resumed_from = null;
    check_storage.logged = false;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    check.run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC NewReno {t} check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ adversary, failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    return census;
}

test "decision 133 as amended: two NewReno endpoints finish a handshake and a stream over a lossy network" {
    const census = try run_newreno(.none);
    try std.testing.expectEqual(census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(census_crc32_expected, census.crc32);
}

test "decision 133 as amended: NewReno loses no frame for good when every datagram of ACK frames alone is dropped" {
    const census = try run_newreno(.drop_ack_only);
    try std.testing.expectEqual(adversary_census_crc32_expected, census.crc32);
}

test "decision 133 as amended: NewReno finishes every seed of the runner's handshakeloss network" {
    const census = try run_newreno(.runner_handshake_loss);
    try std.testing.expectEqual(runner_census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(runner_census_crc32_expected, census.crc32);
}

test "decision 133 as amended: NewReno follows a client that a NAT moves to a new port" {
    try std.testing.expectEqual(rebind_port_census_crc32_expected, (try run_newreno(.rebind_port)).crc32);
}

test "decision 133 as amended: NewReno follows a client that a NAT moves to a new host and port" {
    try std.testing.expectEqual(rebind_address_census_crc32_expected, (try run_newreno(.rebind_address)).crc32);
}
