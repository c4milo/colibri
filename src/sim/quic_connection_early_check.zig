//! The QUIC connection check of `quic_connection_check.zig` under `cut_client_finished`: the
//! client's stream reaches the server before the Finished that completes the server's handshake
//! (RFC 9001 §5.7, https://github.com/c4milo/colibri/issues/153). It is a file of its own because
//! a hand-written source file stays at or under 500 lines (CLAUDE.md).
const std = @import("std");
const sim = @import("sim");
const constants = sim.constants;
const check = @import("quic_connection_check.zig");

/// The census of the check, pinned as `quic_connection_check.zig`'s are.
pub const census_crc32_expected: u32 = 0xe39d67d6;
pub const census_datagrams_expected: u64 = 2_304;
pub const census_cut_expected: u64 = 512;
pub const census_early_opened_expected: u64 = 512;
pub const census_finished_ns_expected: u64 = 38_400_000_000;

var check_storage: check.Storage align(@alignOf(check.Storage)) = undefined;

test "RFC 9001 §5.7: a server opens the 1-RTT packets that arrived before its handshake completed" {
    check_storage.fault = .none;
    check_storage.adversary = .cut_client_finished;
    check_storage.controller = .cubic;
    check_storage.resumed_from = null;
    check_storage.logged = false;
    var census: check.Census = .{};
    var failed_seed: ?u64 = null;
    check.run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("QUIC cut_client_finished check: seed 0x{x} broke {t}, endpoint error {?}\n", .{ failed_seed orelse 0, failure, check_storage.failure });
        return failure;
    };
    try std.testing.expectEqual(census_datagrams_expected, census.datagrams);
    try std.testing.expectEqual(census_cut_expected, census.adversary_dropped);
    try std.testing.expectEqual(census_early_opened_expected, census.early_opened);
    try std.testing.expectEqual(census_finished_ns_expected, census.finished_ns);
    try std.testing.expectEqual(census_crc32_expected, census.crc32);
}
