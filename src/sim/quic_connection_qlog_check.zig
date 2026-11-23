//! The QUIC connection check of `quic_connection_check.zig` with both endpoints writing a qlog
//! (decision 102). It is a file of its own because a hand-written source file stays at or under
//! 500 lines (CLAUDE.md). Each check must give the census it gives without a log, and its logs
//! must replay byte for byte.
const std = @import("std");
const sim = @import("sim");
const constants = sim.constants;
const check = @import("quic_connection_check.zig");
const early_check = @import("quic_connection_early_check.zig");

const Adversary = check.Adversary;
const Census = check.Census;
const Storage = check.Storage;

var check_storage: Storage align(@alignOf(Storage)) = undefined;

test "decision 102: every check gives the same census when both endpoints write a qlog" {
    // Each check's census without a log, and the logs it writes with one: their octets, the
    // digest of every record and the events read back. The logs change when an event or its
    // fields change, and are committed with the new values after both build modes agree.
    const checks = [_]struct { adversary: Adversary, crc32: u32, qlog_len: u64, qlog_crc32: u32, qlog_events: u64 }{
        .{ .adversary = .none, .crc32 = check.census_crc32_expected, .qlog_len = 9_107_533, .qlog_crc32 = 0x219ac158, .qlog_events = 46_059 },
        .{ .adversary = .drop_ack_only, .crc32 = check.adversary_census_crc32_expected, .qlog_len = 3_443_543, .qlog_crc32 = 0x04b32aa4, .qlog_events = 17_364 },
        .{ .adversary = .runner_handshake_loss, .crc32 = check.runner_census_crc32_expected, .qlog_len = 3_819_353, .qlog_crc32 = 0x3580cb1a, .qlog_events = 19_120 },
        .{ .adversary = .rebind_port, .crc32 = check.rebind_port_census_crc32_expected, .qlog_len = 9_543_149, .qlog_crc32 = 0xcc976708, .qlog_events = 47_834 },
        .{ .adversary = .rebind_address, .crc32 = check.rebind_address_census_crc32_expected, .qlog_len = 9_506_181, .qlog_crc32 = 0x68f21292, .qlog_events = 47_601 },
        .{ .adversary = .cut_client_finished, .crc32 = early_check.census_crc32_expected, .qlog_len = 2_889_216, .qlog_crc32 = 0x3da652c6, .qlog_events = 13_824 },
    };
    // Bounded by the checks above.
    for (checks) |logged| {
        check_storage.fault = .none;
        check_storage.adversary = logged.adversary;
        check_storage.controller = .cubic;
        check_storage.resumed_from = null;
        check_storage.logged = true;
        var census: Census = .{};
        var failed_seed: ?u64 = null;
        check.run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
            std.debug.print("QUIC {t} check with qlog: seed 0x{x} broke {t}, endpoint error {?}\n", .{ logged.adversary, failed_seed orelse 0, failure, check_storage.failure });
            return failure;
        };
        // The digest folds in every datagram's octets, so the same digest is the same datagrams.
        try std.testing.expectEqual(logged.crc32, census.crc32);
        // A seed replays its logs byte for byte (invariant 5).
        try std.testing.expectEqual(logged.qlog_len, census.qlog_len);
        try std.testing.expectEqual(logged.qlog_crc32, census.qlog_crc32);
        // Every record read back, which the check of each proves it read (`qlog_records.zig`).
        try std.testing.expectEqual(logged.qlog_events, census.qlog_events);
    }
}
