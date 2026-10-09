//! The soonest deadline among the endpoint's connections, kept without reading every connection
//! on each call (decision 119): a binary min-heap of the slots that have a deadline, ordered by the
//! instant and then by slot number, so ties come out the same on every run. A call that may move a
//! slot's deadline marks the slot stale, and the heap recomputes the stale slots, from each slot
//! alone, before it is read. `server.zig` does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const Ready = @import("endpoint_ready.zig").Ready;

/// A slot that is in no heap position.
const outside: u32 = std.math.maxInt(u32);

/// The children each node of a binary heap has.
const children: u32 = 2;

pub const DeadlineHeap = struct {
    /// Each slot's deadline as the heap last recomputed it, and its index in `order`, or
    /// `outside` when it has none.
    cached: []u64,
    position: []u32,
    /// The slots with a deadline, a binary min-heap by (`cached`, slot).
    order: []u32,
    len: u32,
    stale: Ready,

    /// An empty heap with room for every slot: each slice holds one entry for each.
    pub fn init(heap: *DeadlineHeap, cached: []u64, position: []u32, order: []u32, stale_numbers: []u32, stale_queued: []bool) void {
        assert(cached.len == position.len and position.len == order.len);
        assert(order.len == stale_numbers.len and order.len > 0);
        heap.cached = cached;
        heap.position = position;
        heap.order = order;
        heap.len = 0;
        heap.stale.init(stale_numbers, stale_queued);
        @memset(position, outside);
    }

    /// Notes that `slot`'s deadline may have moved: the next `flush` recomputes it.
    pub fn mark_stale(heap: *DeadlineHeap, slot: u32) void {
        heap.stale.touch(slot);
    }

    /// Recomputes each stale slot's deadline with `source.deadline_of(slot)`, which reads that slot
    /// alone. Bounded by the slots.
    pub fn flush(heap: *DeadlineHeap, source: anytype) void {
        for (0..heap.order.len) |_| {
            const slot = heap.stale.take() orelse break;
            heap.set(slot, source.deadline_of(slot));
        }
        assert(heap.stale.len == 0);
    }

    /// The soonest deadline of every slot, once `flush` has recomputed the stale ones.
    pub fn soonest(heap: *const DeadlineHeap) ?u64 {
        assert(heap.stale.len == 0);
        if (heap.len == 0) return null;
        return heap.cached[heap.order[0]];
    }

    /// Takes out the slot whose deadline is soonest, when it is at or before `now_ns`. The caller
    /// fires it and marks it stale, which leaves the rest of the heap as `flush` made it, so the
    /// caller may take the next before it flushes again.
    pub fn take_due(heap: *DeadlineHeap, now_ns: u64) ?u32 {
        if (heap.len == 0) return null;
        const slot = heap.order[0];
        if (heap.cached[slot] > now_ns) return null;
        heap.remove(slot);
        return slot;
    }

    /// Takes `slot` out of the heap and the stale ring, for a slot that freed.
    pub fn forget(heap: *DeadlineHeap, slot: u32) void {
        heap.stale.remove(slot);
        if (heap.position[slot] != outside) heap.remove(slot);
        assert(heap.position[slot] == outside);
    }

    /// Gives `slot` the deadline `at`, or takes it out when it has none.
    fn set(heap: *DeadlineHeap, slot: u32, at: ?u64) void {
        if (heap.position[slot] != outside) heap.remove(slot);
        const instant = at orelse return;
        heap.cached[slot] = instant;
        assert(heap.len < heap.order.len);
        heap.order[heap.len] = slot;
        heap.position[slot] = heap.len;
        heap.len += 1;
        heap.sift_up(heap.len - 1);
    }

    fn remove(heap: *DeadlineHeap, slot: u32) void {
        const index = heap.position[slot];
        assert(index < heap.len and heap.order[index] == slot);
        heap.len -= 1;
        heap.position[slot] = outside;
        if (index == heap.len) return;
        const last = heap.order[heap.len];
        heap.order[index] = last;
        heap.position[last] = index;
        heap.sift_up(index);
        heap.sift_down(heap.position[last]);
    }

    /// Whether the slot at `a` comes before the slot at `b`: the sooner instant, then the lower
    /// slot.
    fn before(heap: *const DeadlineHeap, a: u32, b: u32) bool {
        const slot_a = heap.order[a];
        const slot_b = heap.order[b];
        if (heap.cached[slot_a] != heap.cached[slot_b]) return heap.cached[slot_a] < heap.cached[slot_b];
        return slot_a < slot_b;
    }

    fn swap(heap: *DeadlineHeap, a: u32, b: u32) void {
        std.mem.swap(u32, &heap.order[a], &heap.order[b]);
        heap.position[heap.order[a]] = a;
        heap.position[heap.order[b]] = b;
    }

    fn sift_up(heap: *DeadlineHeap, start: u32) void {
        var index = start;
        // Bounded: each step halves the index.
        for (0..heap.order.len) |_| {
            if (index == 0) return;
            const parent = (index - 1) / children;
            if (!heap.before(index, parent)) return;
            heap.swap(index, parent);
            index = parent;
        }
    }

    fn sift_down(heap: *DeadlineHeap, start: u32) void {
        var index = start;
        // Bounded: each step doubles the index.
        for (0..heap.order.len) |_| {
            const left = children * index + 1;
            if (left >= heap.len) return;
            const right = left + 1;
            const child = if (right < heap.len and heap.before(right, left)) right else left;
            if (!heap.before(child, index)) return;
            heap.swap(index, child);
            index = child;
        }
    }
};

const testing = std.testing;
const test_slots: usize = 6;

/// Slots whose deadlines a test sets by hand. Test-only.
const TestSource = struct {
    deadlines: [test_slots]?u64 = @splat(null),

    fn deadline_of(source: *const TestSource, slot: u32) ?u64 {
        return source.deadlines[slot];
    }

    /// The soonest deadline, read from every slot: what the heap must agree with.
    fn scan(source: *const TestSource) ?u64 {
        var soonest: ?u64 = null;
        for (source.deadlines) |at| {
            const instant = at orelse continue;
            if (soonest == null or instant < soonest.?) soonest = instant;
        }
        return soonest;
    }
};

const TestHeap = struct {
    cached: [test_slots]u64 = undefined,
    position: [test_slots]u32 = undefined,
    order: [test_slots]u32 = undefined,
    stale_numbers: [test_slots]u32 = undefined,
    stale_queued: [test_slots]bool = undefined,
    heap: DeadlineHeap = undefined,

    fn init(storage: *TestHeap) void {
        storage.heap.init(&storage.cached, &storage.position, &storage.order, &storage.stale_numbers, &storage.stale_queued);
    }
};

test "decision 119: the heap's soonest deadline is the one every slot holds, after each change" {
    var source: TestSource = .{};
    var storage: TestHeap = .{};
    storage.init();
    const heap = &storage.heap;
    heap.flush(&source);
    try testing.expectEqual(null, heap.soonest());
    // Every slot gets a deadline, some move, some go: each step marks the slot it changed.
    const steps = [_]struct { slot: u32, at: ?u64 }{
        .{ .slot = 3, .at = 50 },   .{ .slot = 1, .at = 70 }, .{ .slot = 5, .at = 20 },
        .{ .slot = 0, .at = 90 },   .{ .slot = 5, .at = 95 }, .{ .slot = 2, .at = 10 },
        .{ .slot = 2, .at = null }, .{ .slot = 4, .at = 40 }, .{ .slot = 3, .at = 30 },
    };
    for (steps) |step| {
        source.deadlines[step.slot] = step.at;
        heap.mark_stale(step.slot);
        heap.flush(&source);
        try testing.expectEqual(source.scan(), heap.soonest());
    }
}

test "decision 119: due slots come out soonest first, and a tie goes to the lower slot" {
    var source: TestSource = .{};
    var storage: TestHeap = .{};
    storage.init();
    const heap = &storage.heap;
    for ([_]u32{ 4, 1, 3 }, [_]u64{ 20, 20, 10 }) |slot, at| {
        source.deadlines[slot] = at;
        heap.mark_stale(slot);
    }
    heap.flush(&source);
    try testing.expectEqual(null, heap.take_due(9));
    try testing.expectEqual(3, heap.take_due(25).?);
    try testing.expectEqual(1, heap.take_due(25).?);
    try testing.expectEqual(4, heap.take_due(25).?);
    try testing.expectEqual(null, heap.take_due(25));
    try testing.expectEqual(null, heap.soonest());
}

test "decision 119: a slot that frees leaves the heap and the stale ring" {
    var source: TestSource = .{};
    var storage: TestHeap = .{};
    storage.init();
    const heap = &storage.heap;
    source.deadlines[2] = 5;
    source.deadlines[0] = 8;
    heap.mark_stale(2);
    heap.mark_stale(0);
    heap.flush(&source);
    heap.forget(2);
    try testing.expectEqual(8, heap.soonest().?);
    heap.mark_stale(0);
    heap.forget(0);
    heap.flush(&source);
    try testing.expectEqual(null, heap.soonest());
}
