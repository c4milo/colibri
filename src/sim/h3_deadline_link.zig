//! The link from the server to the peer of an h3 deadline run (`h3_deadline_run.zig`). Most plans
//! give it no rate, and it carries each datagram at the instant the server wrote it. A slow link
//! carries `rate` octets a second, one datagram at a time, behind a queue of `link_queue_len`
//! datagrams, and drops the datagram that finds the queue full, as a router with a short buffer
//! does. So the server's octets wait on the link and not on the peer, which is honest.
//!
//! The link from the peer to the server has no rate: the peer's acknowledgments arrive at once.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const limits = sim.constants.h3_deadline;

/// Octets of the largest datagram the link carries, as the simulator's network does. colibri
/// writes none longer than RFC 9000 §14.1's 1,200.
pub const datagram_len_max: usize = sim.constants.network_datagram_len_max;

pub const Link = struct {
    /// Octets a second, or 0 for a link with no rate.
    rate: u32,
    datagrams: [limits.link_queue_len][datagram_len_max]u8,
    lens: [limits.link_queue_len]usize,
    /// The instant each datagram arrives at.
    arrives_ms: [limits.link_queue_len]u64,
    /// The oldest datagram the link holds, and how many it holds.
    first: usize,
    held: usize,
    /// The instant the link has carried the last datagram it took.
    free_ms: u64,
    /// The datagrams the link dropped because its queue was full.
    dropped: u32,

    pub fn init(link: *Link, rate: u32) void {
        link.rate = rate;
        link.first = 0;
        link.held = 0;
        link.free_ms = 0;
        link.dropped = 0;
    }

    /// Takes a datagram the server wrote at `now_ms`, or drops it when the queue is full.
    pub fn take(link: *Link, octets: []const u8, now_ms: u64) void {
        assert(octets.len > 0 and octets.len <= datagram_len_max);
        if (link.held == limits.link_queue_len) {
            link.dropped += 1;
            return;
        }
        const slot = (link.first + link.held) % limits.link_queue_len;
        @memcpy(link.datagrams[slot][0..octets.len], octets);
        link.lens[slot] = octets.len;
        // One datagram at a time: this one starts once the link has carried the one before it.
        link.free_ms = @max(now_ms, link.free_ms) + carry_ms(link.rate, octets.len);
        link.arrives_ms[slot] = link.free_ms;
        link.held += 1;
    }

    /// The oldest datagram, when it has arrived by `now_ms`. The octets stay until the next `take`.
    pub fn next(link: *Link, now_ms: u64) ?[]u8 {
        if (link.held == 0 or link.arrives_ms[link.first] > now_ms) return null;
        const slot = link.first;
        link.first = (link.first + 1) % limits.link_queue_len;
        link.held -= 1;
        return link.datagrams[slot][0..link.lens[slot]];
    }

    /// The instant the oldest datagram arrives at, or null when the link holds none.
    pub fn arrival_ms(link: *const Link) ?u64 {
        return if (link.held == 0) null else link.arrives_ms[link.first];
    }
};

/// How long a link of `rate` octets a second takes to carry `len` octets, in milliseconds,
/// rounded up. A link with no rate takes none.
pub fn carry_ms(rate: u32, len: usize) u64 {
    if (rate == 0) return 0;
    return (len * limits.ms_per_s + rate - 1) / rate;
}

const testing = std.testing;

/// The rate and the datagram of the tests: 1,000 octets a second and 250 octets, so the link
/// carries one datagram in 250 ms.
const test_rate: u32 = 1_000;
const test_len: usize = 250;
const test_carry_ms: u64 = 250;

var test_link: Link align(@alignOf(Link)) = undefined;

test "a link with no rate carries a datagram at the instant it took it" {
    const link = &test_link;
    link.init(0);
    const datagram: [test_len]u8 = @splat('a');
    link.take(&datagram, 7);
    try testing.expectEqual(7, link.arrival_ms().?);
    try testing.expectEqualSlices(u8, &datagram, link.next(7).?);
    try testing.expectEqual(null, link.next(7));
    try testing.expectEqual(null, link.arrival_ms());
}

test "a slow link carries one datagram at a time, in order, and drops what finds its queue full" {
    const link = &test_link;
    link.init(test_rate);
    var datagram: [test_len]u8 = undefined;
    // Two more than the queue holds: the link drops the last two.
    for (0..limits.link_queue_len + 2) |index| {
        datagram = @splat(@intCast('a' + index));
        link.take(&datagram, 0);
    }
    try testing.expectEqual(2, link.dropped);
    for (0..limits.link_queue_len) |index| {
        const arrives_ms = (index + 1) * test_carry_ms;
        try testing.expectEqual(arrives_ms, link.arrival_ms().?);
        try testing.expectEqual(null, link.next(arrives_ms - 1));
        const carried = link.next(arrives_ms).?;
        try testing.expectEqual(test_len, carried.len);
        try testing.expectEqual(@as(u8, @intCast('a' + index)), carried[0]);
    }
    try testing.expectEqual(null, link.arrival_ms());
    // A link that stood idle starts the next datagram when it takes it.
    const later_ms = 10 * limits.link_queue_len * test_carry_ms;
    link.take(&datagram, later_ms);
    try testing.expectEqual(later_ms + test_carry_ms, link.arrival_ms().?);
    try testing.expectEqual(1, carry_ms(test_rate, 1));
    try testing.expectEqual(0, carry_ms(0, test_len));
}
