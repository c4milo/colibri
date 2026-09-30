//! A minimum rate over windows (decision 110): once started, each window of a fixed length must
//! bring a quota of octets, and the first window takes a grace period more. A window that ends
//! short of its quota is the meter's verdict. colibri reads no clock, so the meter moves only when
//! a caller hands it an instant.
//!
//! The windows follow one another: a window that brings its quota ends at its instant, and the
//! next starts there with nothing counted. So a peer cannot bank octets from one window for the
//! next.
const std = @import("std");
const assert = std.debug.assert;

pub const Meter = struct {
    /// The instant the current window ends, or null while the meter is stopped.
    window_end_ns: ?u64 = null,
    /// The octets the current window has brought.
    octets: u64 = 0,

    /// Starts the first window at `now_ns`, `grace_ns` and `window_ns` long.
    pub fn start(meter: *Meter, now_ns: u64, grace_ns: u64, window_ns: u64) void {
        assert(grace_ns > 0 and window_ns > 0);
        meter.window_end_ns = now_ns + grace_ns + window_ns;
        meter.octets = 0;
    }

    pub fn stop(meter: *Meter) void {
        meter.window_end_ns = null;
        meter.octets = 0;
    }

    pub fn running(meter: *const Meter) bool {
        return meter.window_end_ns != null;
    }

    /// Counts `octets` in the current window. The caller has moved the meter to the instant they
    /// arrived at, with `short`, so they count in the window they arrived in.
    pub fn count(meter: *Meter, octets: u64) void {
        if (meter.window_end_ns == null) return;
        meter.octets += octets;
    }

    /// The instant the meter next looks at a window: the current one's end, or the next one's once
    /// the current one holds its quota. Null while the meter is stopped.
    pub fn check_ns(meter: *const Meter, quota: u64, window_ns: u64) ?u64 {
        const end_ns = meter.window_end_ns orelse return null;
        return if (meter.octets >= quota) end_ns + window_ns else end_ns;
    }

    /// Moves the meter to `now_ns`, and returns whether a window that ended by then fell short of
    /// `quota`. A window ends at its instant, so octets that arrive then count in the next one.
    pub fn short(meter: *Meter, now_ns: u64, quota: u64, window_ns: u64) bool {
        assert(quota > 0 and window_ns > 0);
        const end_ns = meter.window_end_ns orelse return false;
        if (now_ns < end_ns) return false;
        if (meter.octets < quota) return true;
        meter.window_end_ns = end_ns + window_ns;
        meter.octets = 0;
        // Nothing counted in the window after it, so one that has ended too fell short.
        return now_ns >= end_ns + window_ns;
    }
};

const testing = std.testing;

/// The grace period, window and quota the tests use: 10 octets over each window of 5 ns, the
/// first 3 ns longer.
const test_grace_ns: u64 = 3;
const test_window_ns: u64 = 5;
const test_quota: u64 = 10;

test "decision 110: the first window takes the grace period, and a window short of its test_quota ends at its instant" {
    var meter: Meter = .{};
    try testing.expect(!meter.short(100, test_quota, test_window_ns));
    try testing.expectEqual(null, meter.check_ns(test_quota, test_window_ns));
    meter.start(0, test_grace_ns, test_window_ns);
    meter.count(test_quota - 1);
    try testing.expectEqual(test_grace_ns + test_window_ns, meter.check_ns(test_quota, test_window_ns).?);
    try testing.expect(!meter.short(test_grace_ns + test_window_ns - 1, test_quota, test_window_ns));
    try testing.expect(meter.short(test_grace_ns + test_window_ns, test_quota, test_window_ns));
}

test "decision 110: a window that brings its test_quota starts the next one with nothing counted" {
    var meter: Meter = .{};
    meter.start(0, test_grace_ns, test_window_ns);
    meter.count(test_quota);
    const first_end_ns = test_grace_ns + test_window_ns;
    // A meter whose window holds its test_quota looks next at the end of the window after it.
    try testing.expectEqual(first_end_ns + test_window_ns, meter.check_ns(test_quota, test_window_ns).?);
    try testing.expect(!meter.short(first_end_ns, test_quota, test_window_ns));
    // Octets that arrive at the first window's end count in the second.
    meter.count(test_quota - 1);
    try testing.expect(meter.short(first_end_ns + test_window_ns, test_quota, test_window_ns));
}

test "decision 110: a window that ended with its test_quota and one after it with nothing is short" {
    var meter: Meter = .{};
    meter.start(0, test_grace_ns, test_window_ns);
    meter.count(test_quota);
    const first_end_ns = test_grace_ns + test_window_ns;
    try testing.expect(!meter.short(first_end_ns + test_window_ns - 1, test_quota, test_window_ns));
    meter.start(0, test_grace_ns, test_window_ns);
    meter.count(test_quota);
    try testing.expect(meter.short(first_end_ns + test_window_ns, test_quota, test_window_ns));
}

test "decision 110: a stopped meter counts nothing and is never short" {
    var meter: Meter = .{};
    meter.start(0, test_grace_ns, test_window_ns);
    meter.stop();
    meter.count(test_quota);
    try testing.expect(!meter.running());
    try testing.expectEqual(0, meter.octets);
    try testing.expect(!meter.short(std.math.maxInt(u32), test_quota, test_window_ns));
}

const deadline = @import("deadline.zig");
const constants = @import("constants.zig");

/// One run of spec/lean's meter vectors: a meter started at `t0_ns` for `rate` octets a second
/// over windows of `window_ns`, the first `grace_ns` longer, and a peer that sends `peer_rate`
/// octets a second from `peer_start_ns` in whole units of `unit` octets. Test-only.
const Run = struct {
    rate: u32,
    window_ns: u64,
    grace_ns: u64,
    unit: u64,
    peer_rate: u64,
    t0_ns: u64,
    peer_start_ns: u64,
    windows: u64,

    /// The instant unit `m` arrives, counting from 1: the first instant by which the peer has sent
    /// its last octet.
    fn arrival_ns(run: *const Run, m: u64) u64 {
        const sent = @as(u128, m) * run.unit * constants.nanoseconds_per_second;
        return run.peer_start_ns + @as(u64, @intCast((sent + run.peer_rate - 1) / run.peer_rate));
    }

    /// The window that ends at `end_ns`, counting from 1.
    fn window_of(run: *const Run, end_ns: u64) u64 {
        return (end_ns - run.t0_ns - run.grace_ns) / run.window_ns;
    }
};

/// The events one run of the vectors takes at most: each unit its peer sends before the last
/// window ends, and each instant the meter looks at a window.
const run_events_max: usize = 4_096;

/// Drives a meter the way the server does. At a unit's arrival, `short` moves the meter to the
/// instant and then `count` counts the unit; at each instant `check_ns` names, `short` alone.
/// Returns the first window that fell short, or null when none of the run's windows did.
fn drive(run: *const Run) error{TestRunTooLong}!?u64 {
    const quota = deadline.quota(run.rate, run.window_ns);
    const last_end_ns = run.t0_ns + run.grace_ns + run.windows * run.window_ns;
    var meter: Meter = .{};
    meter.start(run.t0_ns, run.grace_ns, run.window_ns);
    // Units that arrived before the meter started count in no window.
    var m: u64 = 1;
    for (0..run_events_max) |_| {
        if (run.arrival_ns(m) >= run.t0_ns) break;
        m += 1;
    } else return error.TestRunTooLong;
    for (0..run_events_max) |_| {
        const arrival_ns = run.arrival_ns(m);
        const now_ns = @min(meter.check_ns(quota, run.window_ns).?, arrival_ns);
        if (now_ns >= last_end_ns) break;
        if (meter.short(now_ns, quota, run.window_ns)) return run.window_of(meter.window_end_ns.?);
        if (arrival_ns == now_ns) {
            meter.count(run.unit);
            m += 1;
        }
    } else return error.TestRunTooLong;
    if (meter.short(last_end_ns, quota, run.window_ns)) return run.window_of(meter.window_end_ns.?);
    return null;
}

test "decision 77: every meter vector of spec/lean is this meter's verdict" {
    // spec/lean/Colibri/Server/RateMeter.lean proves when a peer that sends whole units at twice
    // the rate or more is never short. For each peer below, the vectors name the first window the
    // proved model leaves short, and this meter, driven as the server drives it, must name it too.
    var lines = std.mem.splitScalar(u8, @embedFile("rate_vectors.txt"), '\n');
    var count: usize = 0;
    var shorts: usize = 0;
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "meter ")) continue;
        var fields = std.mem.tokenizeScalar(u8, line["meter ".len..], ' ');
        var values: [8]u64 = undefined;
        for (&values) |*value| value.* = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        const run: Run = .{
            .rate = @intCast(values[0]),
            .window_ns = values[1],
            .grace_ns = values[2],
            .unit = values[3],
            .peer_rate = values[4],
            .t0_ns = values[5],
            .peer_start_ns = values[6],
            .windows = values[7],
        };
        const answer = fields.next().?;
        const expected: ?u64 = if (std.mem.eql(u8, answer, "never")) null else try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        try testing.expectEqual(expected, try drive(&run));
        count += 1;
        shorts += @intFromBool(expected != null);
    }
    // Each limit, peer rate and start spec/lean/Vectors.lean names, and among them peers that fall
    // short in the first window, as the proof's `first_window_short` says, and in later ones.
    try testing.expectEqual(404, count);
    try testing.expectEqual(30, shorts);
}
