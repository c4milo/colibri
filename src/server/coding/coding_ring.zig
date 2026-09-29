//! Where a coded response's octets wait (decision 101, design §8 step 17e): the ring of its
//! encoder's slot, and how far the response has written and freed it. Both counts run from the
//! response's start, so an octet's place in the ring is its count modulo the ring's length.
//!
//! h11 and h2 free octets as they copy them into the connection's output. h3 frees them only once
//! the peer acknowledges them, because QUIC reads them in place for as long as it may send them
//! again (RFC 9000 §3.1, decision 57).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// The octets of one encoder's ring.
pub const Octets = [constants.encoder_ring_len]u8;

pub const Ring = struct {
    /// Octets the encoder wrote into the ring, and octets freed, since the response started.
    written: u64 = 0,
    freed: u64 = 0,

    /// Octets written and not yet freed.
    pub fn held(ring: Ring) usize {
        assert(ring.freed <= ring.written);
        const held_len = ring.written - ring.freed;
        assert(held_len <= constants.encoder_ring_len);
        return @intCast(held_len);
    }

    /// The free octets after the last one written, up to the ring's end: where the encoder writes
    /// next.
    pub fn room(ring: Ring, octets: *Octets) []u8 {
        const start = place(ring.written);
        const free_len = octets.len - ring.held();
        return octets[start..][0..@min(free_len, octets.len - start)];
    }

    /// Counts the `len` octets the encoder wrote at the front of `room`.
    pub fn wrote(ring: *Ring, len: usize) void {
        assert(len <= constants.encoder_ring_len - ring.held());
        ring.written += len;
    }

    /// The octets held, from the oldest, up to the ring's end.
    pub fn oldest(ring: Ring, octets: *const Octets) []const u8 {
        const start = place(ring.freed);
        return octets[start..][0..@min(ring.held(), octets.len - start)];
    }

    /// Frees the `len` oldest octets held.
    pub fn free(ring: *Ring, len: usize) void {
        assert(len <= ring.held());
        ring.freed += len;
    }

    fn place(count: u64) usize {
        return @intCast(count % constants.encoder_ring_len);
    }
};

const testing = std.testing;

/// A ring's octets, outside any stack frame. Test-only.
threadlocal var test_octets: Octets align(@alignOf(Octets)) = undefined;

test "decision 101: the encoder writes after the octets held, and they leave oldest first" {
    var ring: Ring = .{};
    try testing.expectEqual(test_octets.len, ring.room(&test_octets).len);
    try testing.expectEqual(0, ring.oldest(&test_octets).len);
    @memcpy(ring.room(&test_octets)[0..5], "hello");
    ring.wrote(5);
    try testing.expectEqualStrings("hello", ring.oldest(&test_octets));
    try testing.expectEqual(test_octets.len - 5, ring.room(&test_octets).len);
    ring.free(2);
    try testing.expectEqualStrings("llo", ring.oldest(&test_octets));
    try testing.expectEqual(3, ring.held());
}

test "decision 101: the octets held and the room each stop at the ring's end, and go on from its start" {
    const tail_len = 4;
    // Written and freed up to four octets short of the end.
    var ring: Ring = .{ .written = test_octets.len - tail_len, .freed = test_octets.len - tail_len };
    try testing.expectEqual(tail_len, ring.room(&test_octets).len);
    @memcpy(ring.room(&test_octets), "abcd");
    ring.wrote(tail_len);
    // Past the end, the room starts again at the ring's start, short of the octets held.
    try testing.expectEqual(test_octets.len - tail_len, ring.room(&test_octets).len);
    @memcpy(ring.room(&test_octets)[0..2], "ef");
    ring.wrote(2);
    try testing.expectEqualStrings("abcd", ring.oldest(&test_octets));
    ring.free(tail_len);
    try testing.expectEqualStrings("ef", ring.oldest(&test_octets));
    // A full ring has no room until an octet is freed.
    ring.wrote(ring.room(&test_octets).len);
    try testing.expectEqual(test_octets.len, ring.held());
    try testing.expectEqual(0, ring.room(&test_octets).len);
    ring.free(1);
    try testing.expectEqual(1, ring.room(&test_octets).len);
}
