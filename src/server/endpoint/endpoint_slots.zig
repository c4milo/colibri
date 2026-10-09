//! The endpoint's slots (decision 119): which hold a connection, the generation each is in, and
//! the free ones, which a new connection takes oldest first. TCP slots come first, then QUIC
//! slots, so a TCP connection's slot indexes a program's own array of sockets. `server.zig` does
//! not export this file.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");

const ConnectionHandle = event.ConnectionHandle;

/// Which transport a slot serves.
pub const Kind = enum { tcp, quic };

/// The generation a slot's first connection has. 0 names no connection.
const generation_first: u32 = 1;

/// A ring of free slot numbers, oldest first. It holds every slot of its kind at most once.
const FreeRing = struct {
    numbers: []u32,
    first: u32,
    len: u32,

    fn push(ring: *FreeRing, slot: u32) void {
        assert(ring.len < ring.numbers.len);
        const at = (ring.first + ring.len) % @as(u32, @intCast(ring.numbers.len));
        ring.numbers[at] = slot;
        ring.len += 1;
    }

    fn take(ring: *FreeRing) ?u32 {
        if (ring.len == 0) return null;
        const slot = ring.numbers[ring.first];
        ring.first = (ring.first + 1) % @as(u32, @intCast(ring.numbers.len));
        ring.len -= 1;
        return slot;
    }
};

pub const Slots = struct {
    /// Each slot's generation, and whether a connection holds it.
    generations: []u32,
    live: []bool,
    tcp_count: u32,
    free_tcp: FreeRing,
    free_quic: FreeRing,

    /// Every slot free, the first `tcp_count` TCP and the rest QUIC. `free` holds one number for
    /// each slot.
    pub fn init(slots: *Slots, generations: []u32, live: []bool, free: []u32, tcp_count: u32) void {
        assert(generations.len == live.len and live.len == free.len);
        assert(tcp_count <= generations.len);
        slots.* = .{
            .generations = generations,
            .live = live,
            .tcp_count = tcp_count,
            .free_tcp = .{ .numbers = free[0..tcp_count], .first = 0, .len = 0 },
            .free_quic = .{ .numbers = free[tcp_count..], .first = 0, .len = 0 },
        };
        @memset(generations, generation_first);
        @memset(live, false);
        for (0..generations.len) |slot| slots.ring_of(@intCast(slot)).push(@intCast(slot));
    }

    /// The handle of a free slot of `kind`, which now holds a connection, or null when none is
    /// free.
    pub fn take(slots: *Slots, kind: Kind) ?ConnectionHandle {
        const ring = switch (kind) {
            .tcp => &slots.free_tcp,
            .quic => &slots.free_quic,
        };
        const slot = ring.take() orelse return null;
        assert(!slots.live[slot] and slots.kind_of(slot) == kind);
        slots.live[slot] = true;
        return .{ .slot = slot, .generation = slots.generations[slot] };
    }

    /// Frees the slot `handle` names, whose connection ended: its generation advances, so the
    /// handle and every id on it name nothing, and the slot joins the free ones last.
    pub fn release(slots: *Slots, handle: ConnectionHandle) void {
        assert(slots.resolve(handle) != null);
        const slot = handle.slot;
        slots.live[slot] = false;
        // 0 names no connection, so a generation that wraps skips it.
        slots.generations[slot] +%= 1;
        if (slots.generations[slot] == 0) slots.generations[slot] = generation_first;
        slots.ring_of(slot).push(slot);
    }

    /// The slot `handle` names, when a connection holds it and the handle is of that connection's
    /// generation, or null for a handle of an ended connection.
    pub fn resolve(slots: *const Slots, handle: ConnectionHandle) ?u32 {
        // A slot past the endpoint's is no handle the endpoint gave: the program's error.
        assert(handle.slot < slots.generations.len);
        if (!slots.live[handle.slot]) return null;
        if (slots.generations[handle.slot] != handle.generation) return null;
        return handle.slot;
    }

    /// The handle of the connection slot `slot` holds now.
    pub fn handle_of(slots: *const Slots, slot: u32) ConnectionHandle {
        assert(slots.live[slot]);
        return .{ .slot = slot, .generation = slots.generations[slot] };
    }

    pub fn kind_of(slots: *const Slots, slot: u32) Kind {
        assert(slot < slots.generations.len);
        return if (slot < slots.tcp_count) .tcp else .quic;
    }

    fn ring_of(slots: *Slots, slot: u32) *FreeRing {
        return switch (slots.kind_of(slot)) {
            .tcp => &slots.free_tcp,
            .quic => &slots.free_quic,
        };
    }
};

const testing = std.testing;

/// Two TCP slots and three QUIC slots. Test-only.
const test_tcp: u32 = 2;
const test_slots: usize = 5;

fn test_init(slots: *Slots, storage: anytype) void {
    slots.init(&storage.generations, &storage.live, &storage.free, test_tcp);
}

const TestStorage = struct {
    generations: [test_slots]u32 = undefined,
    live: [test_slots]bool = undefined,
    free: [test_slots]u32 = undefined,
};

test "decision 119: TCP slots come first, and each kind is taken oldest free first" {
    var storage: TestStorage = .{};
    var slots: Slots = undefined;
    test_init(&slots, &storage);
    try testing.expectEqual(0, slots.take(.tcp).?.slot);
    try testing.expectEqual(1, slots.take(.tcp).?.slot);
    try testing.expectEqual(null, slots.take(.tcp));
    try testing.expectEqual(2, slots.take(.quic).?.slot);
    try testing.expectEqual(3, slots.take(.quic).?.slot);
    // A freed slot goes last, behind the slots that were free before it.
    slots.release(slots.handle_of(2));
    try testing.expectEqual(4, slots.take(.quic).?.slot);
    try testing.expectEqual(2, slots.take(.quic).?.slot);
    try testing.expectEqual(null, slots.take(.quic));
}

test "decision 119: a released slot's handle names nothing, and its next connection a new generation" {
    var storage: TestStorage = .{};
    var slots: Slots = undefined;
    test_init(&slots, &storage);
    const first = slots.take(.tcp).?;
    try testing.expectEqual(first.slot, slots.resolve(first).?);
    try testing.expectEqual(1, first.generation);
    slots.release(first);
    try testing.expectEqual(null, slots.resolve(first));
    // The other TCP slot is older, so it goes first; then the freed one, in its next generation.
    _ = slots.take(.tcp).?;
    const again = slots.take(.tcp).?;
    try testing.expectEqual(first.slot, again.slot);
    try testing.expectEqual(2, again.generation);
    try testing.expectEqual(null, slots.resolve(first));
    try testing.expectEqual(again.slot, slots.resolve(again).?);
}

test "decision 119: a generation that wraps skips 0, which names no connection" {
    var storage: TestStorage = .{};
    var slots: Slots = undefined;
    test_init(&slots, &storage);
    const handle = slots.take(.quic).?;
    storage.generations[handle.slot] = std.math.maxInt(u32);
    slots.release(.{ .slot = handle.slot, .generation = std.math.maxInt(u32) });
    try testing.expectEqual(1, storage.generations[handle.slot]);
}
