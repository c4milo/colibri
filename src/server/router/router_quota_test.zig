//! The test of the quota of the check of hidden routes on a long segment (decision 122 ruling 12,
//! design §8 step 21e). `zig build router-hidden-check` compiles it from
//! `../router_quota_check.zig`, in a test binary of its own.
//!
//! The check sets its quota from the octets that one walk reads (`router_hidden.zig`). A walk
//! reads the segment of each pass, so the quota counts the longest segment of the layout, and
//! the check reads that length from the layout's edges. This table holds one segment of
//! `long_segment_len` octets, and many walks read it at each node before it. The test proves
//! that the quota covers those reads: the table compiles.
//!
//! The mutation "segment_len_max = other.len" in `view_refusal` reads no edge. The quota then
//! counts only the octets of "other", and the compile fails with "evaluation exceeded ...
//! backwards branches". No smaller table of this kind catches it (design §8 step 21e).
//!
//! The compile takes about a minute on an M1 Pro at a load average of 5, and about three
//! minutes at a load average of 20. The compile of the cross-check takes about as long. The
//! step compiles the two binaries in parallel, so its wall time grows by the difference.
//!
//! The table has 257 routes:
//!   - 255 routes "/b/S/:x/wJ". J counts from 0 to 254. S holds `levels` segments, and the bit
//!     of J for each level, from the high bit, makes that segment "a" or the parameter ":pI". The
//!     route with each bit set holds one parameter more than a pattern holds, so it is not in the
//!     table.
//!   - "/:r/a.../X/:s" and "/:r/a.../X/*", with "a" at each level and X the long segment. The two
//!     routes share the edge X, so each walk of a route under "/b" reads X at each node before
//!     it.
//!
//! An earlier experiment wrote this table out as a literal list with a script: 8 levels, a
//! segment X of 8150 octets, and 7 parameters at most under "/b". The loops below build the same
//! table, in the same order.
const std = @import("std");
const router = @import("router.zig").router;
const PathParameters = @import("../path_parameters.zig").PathParameters;
const constants = @import("../constants.zig");
const support = @import("router_test_support.zig");

const testing = std.testing;
const Entry = struct { @import("http").method.Standard, []const u8, u8 };

/// The segments of S, each one "a" or a parameter.
const levels = 8;

/// The routes under "/b": one for each value of the `levels` bits but the value with each bit
/// set.
const branch_routes = (1 << levels) - 1;

/// The octets of the long segment X. Each pattern through it holds `constants.path_len_max`
/// octets at most, so a path can match it.
const long_segment_len = 8150;

/// The routes through X: one ends in a parameter, and one in the wildcard.
const long_routes = 2;

/// The long segment X.
const long_segment = "x" ** long_segment_len;

/// "/:r", then "a" at each level, then X.
const long_prefix = "/:r" ++ "/a" ** levels ++ "/" ++ long_segment;

/// The comptime branches that the build of one pattern under "/b" takes, at most.
const branches_per_pattern = 1000;

/// The pattern of route `route` under "/b". Comptime-only.
fn branch_pattern(comptime route: usize) []const u8 {
    var pattern: []const u8 = "/b";
    for (1..levels + 1) |level| {
        const bit = (route >> (levels - level)) & 1;
        pattern = pattern ++ if (bit == 1) std.fmt.comptimePrint("/:p{d}", .{level}) else "/a";
    }
    return pattern ++ std.fmt.comptimePrint("/:x/w{d}", .{route});
}

const table: [branch_routes + long_routes]Entry = build: {
    @setEvalBranchQuota(branch_routes * branches_per_pattern);
    var entries: [branch_routes + long_routes]Entry = undefined;
    for (0..branch_routes) |route| entries[route] = .{ .get, branch_pattern(route), 0 };
    entries[branch_routes] = .{ .get, long_prefix ++ "/:s", 0 };
    entries[branch_routes + 1] = .{ .get, long_prefix ++ "/*", 0 };
    break :build entries;
};

comptime {
    // The route with each bit set would hold `levels` + 1 parameters, one more than a pattern
    // holds.
    std.debug.assert(levels + 1 > constants.path_parameters_max);
    std.debug.assert(levels <= constants.path_parameters_max);
    std.debug.assert(long_prefix.len + "/:s".len <= constants.path_len_max);
}

test "decision 122: the quota of the check of hidden routes counts the longest segment" {
    const long = router(u8, table);
    try support.expect_not_found(long, "GET", "/b");
    var parameters: PathParameters = .{};
    try testing.expectEqual(0, long.match("GET", "/b" ++ "/a" ** levels ++ "/v/w0", &parameters).found);
    try testing.expectEqualStrings("v", parameters.get("x").?);
    const path = "/q" ++ "/a" ** levels ++ "/" ++ long_segment ++ "/v";
    try testing.expectEqual(0, long.match("GET", path, &parameters).found);
    try testing.expectEqualStrings("v", parameters.get("s").?);
}
