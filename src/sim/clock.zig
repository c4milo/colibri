//! `Clock`, the simulator's instant (design §4.2, §10). colibri reads no clock: every function that
//! needs the current instant takes `now_ns`, and in the simulator that value comes from here. The
//! clock moves only when the harness advances it, by an amount the seed chose, so a run's instants
//! are a pure function of its seed.
const std = @import("std");
const assert = std.debug.assert;

pub const Clock = struct {
    /// Nanoseconds since the run began. A run starts at 0.
    now_ns: u64,

    pub fn init() Clock {
        return .{ .now_ns = 0 };
    }

    /// Moves the clock forward by `delta_ns`. Time never runs backward, and a run that would
    /// overflow 64 bits of nanoseconds, about 584 years, is a harness defect.
    pub fn advance(clock: *Clock, delta_ns: u64) void {
        const before = clock.now_ns;
        clock.now_ns = std.math.add(u64, clock.now_ns, delta_ns) catch unreachable;
        assert(clock.now_ns >= before);
    }
};

const testing = std.testing;

test "the clock starts at 0 and moves only forward by what it is told" {
    var clock = Clock.init();
    try testing.expectEqual(0, clock.now_ns);
    clock.advance(0);
    try testing.expectEqual(0, clock.now_ns);
    clock.advance(1_000_000);
    clock.advance(250);
    try testing.expectEqual(1_000_250, clock.now_ns);
}
