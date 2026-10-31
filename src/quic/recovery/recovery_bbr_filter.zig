//! BBRv3's windowed maximum filter (draft-ietf-ccwg-bbr-06 §5.5.5, §5.5.9). Part of design §8
//! step 29b.1.
//!
//! The draft's filter takes a value at a time and gives the largest value taken within the last
//! `window` times. Its times are counts that rise by one, the bandwidth probe cycles for
//! BBR.max_bw and the round trips for BBR.extra_acked, and each window is at most 10 of them.
//! So the filter keeps one slot for each time, the largest value of that time, and its answer is
//! exact. The draft says Kathleen Nichols' algorithm "can be" used, which keeps three samples and
//! gives an estimate.
const std = @import("std");
const assert = std.debug.assert;

/// A windowed maximum over at most `slots` consecutive times.
pub fn MaxFilter(comptime slots: u64) type {
    comptime assert(slots > 0);
    return struct {
        const Filter = @This();

        /// The largest value of each time, at the index `time % slots`.
        values: [slots]u64,
        /// The newest time a value was taken at.
        time: u64,

        /// The draft's `InitWindowedMaxFilter(value=0, time=0)`.
        pub fn init(filter: *Filter) void {
            filter.* = .{ .values = @splat(0), .time = 0 };
        }

        /// The draft's `UpdateWindowedMaxFilter`: takes `value` at `time`, which never falls, and
        /// returns the largest value taken within the last `window` times.
        pub fn update(filter: *Filter, value: u64, time: u64, window: u64) u64 {
            assert(time >= filter.time);
            assert(window > 0 and window <= slots);
            filter.advance(time);
            const at = time % slots;
            filter.values[at] = @max(filter.values[at], value);
            return filter.max(window);
        }

        /// Clears the slots of the times after the newest one, up to `time`. A slot that a time
        /// within the window does not reuse keeps its value, because `max` does not read it.
        fn advance(filter: *Filter, time: u64) void {
            const steps = @min(time - filter.time, slots);
            // Bounded: at most `slots` slots.
            for (1..steps + 1) |step| filter.values[(filter.time + step) % slots] = 0;
            filter.time = time;
        }

        /// The largest value taken within the last `window` times up to the newest one.
        pub fn max(filter: *const Filter, window: u64) u64 {
            assert(window > 0 and window <= slots);
            var largest: u64 = 0;
            // Bounded: at most `slots` slots. A time before 0 holds nothing.
            for (0..@min(window, filter.time + 1)) |back| {
                largest = @max(largest, filter.values[(filter.time - back) % slots]);
            }
            return largest;
        }
    };
}

const testing = std.testing;

test "§5.5.5: the filter keeps the largest value of the window and forgets older ones" {
    var filter: MaxFilter(2) = undefined;
    filter.init();
    try testing.expectEqual(5, filter.update(5, 0, 2));
    try testing.expectEqual(5, filter.update(3, 0, 2));
    // A new time keeps the previous time's largest value.
    try testing.expectEqual(5, filter.update(4, 1, 2));
    // Two times on, the value of time 0 is out of the window.
    try testing.expectEqual(4, filter.update(1, 2, 2));
    try testing.expectEqual(2, filter.update(2, 4, 2));
}

test "§5.5.9: a window shorter than the slots reads only its own times" {
    var filter: MaxFilter(10) = undefined;
    filter.init();
    _ = filter.update(9, 0, 10);
    _ = filter.update(4, 1, 10);
    // In Startup the window is 1 round: only the newest time counts.
    try testing.expectEqual(4, filter.max(1));
    try testing.expectEqual(9, filter.max(10));
    // Ten rounds after time 0, its value leaves the window.
    try testing.expectEqual(4, filter.update(0, 10, 10));
    try testing.expectEqual(0, filter.update(0, 25, 10));
}
