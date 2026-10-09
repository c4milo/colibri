//! The slots the endpoint asks for events, in the order calls changed them (decision 119): a
//! call that may give a slot something to report queues it, once, and `receive` asks the slot at
//! the front. So no call asks every slot, and the order follows the order of the calls alone,
//! which a seed replays. `server.zig` does not export this file.
const std = @import("std");
const assert = std.debug.assert;

/// A ring of slot numbers, each queued at most once.
pub const Ready = struct {
    numbers: []u32,
    queued: []bool,
    first: u32,
    len: u32,

    /// An empty ring with room for every slot: `numbers` and `queued` hold one entry for each.
    pub fn init(ready: *Ready, numbers: []u32, queued: []bool) void {
        assert(numbers.len == queued.len and numbers.len > 0);
        ready.* = .{ .numbers = numbers, .queued = queued, .first = 0, .len = 0 };
        @memset(queued, false);
    }

    /// Queues `slot` at the back, unless it is queued already.
    pub fn touch(ready: *Ready, slot: u32) void {
        assert(slot < ready.queued.len);
        if (ready.queued[slot]) return;
        // Each slot is queued once at most, so the ring has room for one more.
        assert(ready.len < ready.numbers.len);
        const at = (ready.first + ready.len) % @as(u32, @intCast(ready.numbers.len));
        ready.numbers[at] = slot;
        ready.queued[slot] = true;
        ready.len += 1;
    }

    /// The slot at the front, which leaves the ring, or null when none is queued.
    pub fn take(ready: *Ready) ?u32 {
        if (ready.len == 0) return null;
        const slot = ready.numbers[ready.first];
        assert(ready.queued[slot]);
        ready.queued[slot] = false;
        ready.first = (ready.first + 1) % @as(u32, @intCast(ready.numbers.len));
        ready.len -= 1;
        return slot;
    }

    /// Takes `slot` out wherever it is queued, for a slot that freed. Bounded by the ring's length.
    pub fn remove(ready: *Ready, slot: u32) void {
        if (!ready.queued[slot]) return;
        const count = ready.len;
        // Each queued slot is taken once and queued again unless it is `slot`, so the order of the
        // rest stays.
        for (0..count) |_| {
            const taken = ready.take().?;
            if (taken != slot) ready.touch(taken);
        }
        assert(!ready.queued[slot] and ready.len == count - 1);
    }
};

const testing = std.testing;
const test_slots: usize = 4;

test "decision 119: a slot is queued once, and slots come out in the order calls touched them" {
    var numbers: [test_slots]u32 = undefined;
    var queued: [test_slots]bool = undefined;
    var ready: Ready = undefined;
    ready.init(&numbers, &queued);
    try testing.expectEqual(null, ready.take());
    ready.touch(2);
    ready.touch(0);
    ready.touch(2);
    ready.touch(3);
    try testing.expectEqual(3, ready.len);
    try testing.expectEqual(2, ready.take().?);
    // A slot taken may be queued again, at the back.
    ready.touch(2);
    try testing.expectEqual(0, ready.take().?);
    try testing.expectEqual(3, ready.take().?);
    try testing.expectEqual(2, ready.take().?);
    try testing.expectEqual(null, ready.take());
}

test "decision 119: a slot that frees leaves the ring, and the others keep their order" {
    var numbers: [test_slots]u32 = undefined;
    var queued: [test_slots]bool = undefined;
    var ready: Ready = undefined;
    ready.init(&numbers, &queued);
    for ([_]u32{ 1, 3, 0, 2 }) |slot| ready.touch(slot);
    ready.remove(3);
    ready.remove(3);
    try testing.expectEqual(1, ready.take().?);
    try testing.expectEqual(0, ready.take().?);
    try testing.expectEqual(2, ready.take().?);
    try testing.expectEqual(null, ready.take());
}
