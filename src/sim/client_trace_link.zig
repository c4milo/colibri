//! One direction of the client trace run's TCP link (decision 105): octets arrive in the order
//! they were sent, as TCP delivers them (RFC 9113 §2), each write after the link's delay. The
//! receiver takes what arrived, and what it does not consume stays for its next read.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const limits = sim.constants.client_trace;

pub const Error = error{
    /// The link holds more than `tcp_queue_len_max` octets or `tcp_chunks_max` writes, which a
    /// run of three exchanges never does.
    LinkFull,
};

/// One write: where it ends in the queue, and the instant it arrives.
const Chunk = struct {
    end: usize,
    arrival_ns: u64,
};

pub const Direction = struct {
    octets: [limits.tcp_queue_len_max]u8,
    len: usize,
    chunks: [limits.tcp_chunks_max]Chunk,
    chunks_len: usize,

    pub fn clear(direction: *Direction) void {
        direction.len = 0;
        direction.chunks_len = 0;
    }

    /// Sends `octets`, which arrive at `arrival_ns`, after every octet sent before them.
    pub fn push(direction: *Direction, octets: []const u8, arrival_ns: u64) Error!void {
        if (octets.len == 0) return;
        if (direction.len + octets.len > direction.octets.len) return error.LinkFull;
        if (direction.chunks_len == direction.chunks.len) return error.LinkFull;
        // Writes arrive in order, so none arrives before one sent earlier.
        if (direction.chunks_len > 0) assert(direction.chunks[direction.chunks_len - 1].arrival_ns <= arrival_ns);
        @memcpy(direction.octets[direction.len..][0..octets.len], octets);
        direction.len += octets.len;
        direction.chunks[direction.chunks_len] = .{ .end = direction.len, .arrival_ns = arrival_ns };
        direction.chunks_len += 1;
    }

    /// The octets that have arrived by `now_ns` and the receiver has not consumed.
    pub fn arrived(direction: *Direction, now_ns: u64) []u8 {
        var end: usize = 0;
        for (direction.chunks[0..direction.chunks_len]) |chunk| {
            if (chunk.arrival_ns > now_ns) break;
            end = chunk.end;
        }
        return direction.octets[0..end];
    }

    /// Drops the first `len` octets, which the receiver consumed.
    pub fn consume(direction: *Direction, len: usize) void {
        if (len == 0) return;
        assert(len <= direction.len);
        std.mem.copyForwards(u8, &direction.octets, direction.octets[len..direction.len]);
        direction.len -= len;
        var kept: usize = 0;
        for (direction.chunks[0..direction.chunks_len]) |chunk| {
            if (chunk.end <= len) continue;
            direction.chunks[kept] = .{ .end = chunk.end - len, .arrival_ns = chunk.arrival_ns };
            kept += 1;
        }
        direction.chunks_len = kept;
    }

    /// The instant the next octets arrive after `now_ns`, or null.
    pub fn next_arrival_ns(direction: *const Direction, now_ns: u64) ?u64 {
        for (direction.chunks[0..direction.chunks_len]) |chunk| {
            if (chunk.arrival_ns > now_ns) return chunk.arrival_ns;
        }
        return null;
    }
};

const testing = std.testing;

/// A direction the test fills, outside any stack frame. Test-only.
var test_direction: Direction align(@alignOf(Direction)) = undefined;

test "octets arrive in order after their delay, and what is not consumed stays" {
    test_direction.clear();
    try test_direction.push("abc", 10);
    try test_direction.push("de", 20);
    try testing.expectEqualStrings("", test_direction.arrived(9));
    try testing.expectEqualStrings("abc", test_direction.arrived(10));
    test_direction.consume(2);
    try testing.expectEqualStrings("c", test_direction.arrived(10));
    try testing.expectEqual(@as(?u64, 20), test_direction.next_arrival_ns(10));
    try testing.expectEqualStrings("cde", test_direction.arrived(20));
}
