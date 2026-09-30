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
