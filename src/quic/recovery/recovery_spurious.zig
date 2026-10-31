//! Spurious loss episodes (draft-ietf-ccwg-bbr-06 §5.5.11). Part of design §8 step 29b.3.
//!
//! A loss episode is spurious when "no packets marked lost in that loss recovery episode were
//! actually lost" (§5.5.11). In QUIC that shows when the peer acknowledges every packet the
//! episode declared lost: RFC 9438 §4.9.2 says a QUIC sender "can easily determine a spurious
//! fast retransmit if a QUIC packet is acknowledged after it has been marked as lost". RFC 9002
//! drops the record of a lost packet, so this file keeps the numbers the episode declared lost.
//!
//! An episode is RFC 9002's recovery period (§7.3.2), from the congestion event that starts it
//! to the one that starts the next. Only the application space's numbers fit in the list, at
//! most `spurious_loss_numbers_max` of them. An episode that declares more, or declares a loss in
//! another space, is never found spurious (the owner's rulings of 2026-10-31).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const recovery_congestion = @import("recovery_congestion.zig");

const numbers_max = constants.limits.spurious_loss_numbers_max;

pub const Spurious = struct {
    /// The application space's packet numbers the episode declared lost.
    numbers: [numbers_max]u64,
    count: u8,
    /// One bit for each of `numbers`: whether the peer has acknowledged it since.
    acknowledged: u32,
    /// Whether the episode can no longer be found spurious: it declared a loss the list cannot
    /// hold, or it was found spurious already.
    overflowed: bool,

    pub fn init(spurious: *Spurious) void {
        spurious.* = .{ .numbers = @splat(0), .count = 0, .acknowledged = 0, .overflowed = false };
    }

    /// A congestion event started a new recovery period, which ends the old episode.
    pub fn on_episode_start(spurious: *Spurious) void {
        spurious.init();
    }

    /// RFC 9002 §6.1 declared packet `number` of the application space lost, or of another space
    /// when `application` is false.
    pub fn on_lost(spurious: *Spurious, application: bool, number: u64) void {
        if (!application or spurious.count == numbers_max) {
            spurious.overflowed = true;
            return;
        }
        spurious.numbers[spurious.count] = number;
        spurious.count += 1;
        assert(spurious.count <= numbers_max);
    }

    /// Losses the caller could not name, such as records that did not fit its slice.
    pub fn on_unnamed_loss(spurious: *Spurious) void {
        spurious.overflowed = true;
    }

    /// The peer acknowledged the application space's packets `smallest` to `largest`. True when
    /// that makes the episode spurious: every packet it declared lost is now acknowledged. It is
    /// true once an episode: the episode is then over, and no later loss in it is counted.
    pub fn on_acknowledged(spurious: *Spurious, smallest: u64, largest: u64) bool {
        assert(smallest <= largest);
        if (spurious.count == 0 or spurious.overflowed) return false;
        // Bounded: at most `numbers_max` numbers.
        for (spurious.numbers[0..spurious.count], 0..) |number, at| {
            if (number >= smallest and number <= largest) spurious.acknowledged |= @as(u32, 1) << @intCast(at);
        }
        const all: u32 = if (spurious.count == @bitSizeOf(u32)) std.math.maxInt(u32) else (@as(u32, 1) << @intCast(spurious.count)) - 1;
        if (spurious.acknowledged != all) return false;
        spurious.init();
        spurious.overflowed = true;
        return true;
    }
};

/// RFC 9002 Appendix B.6's `OnCongestionEvent`, which also starts a new episode when it starts a
/// new recovery period. Both of `Recovery`'s congestion events, a loss and an increase in the
/// peer's ECN-CE count, come here.
pub fn on_congestion_event(congestion: *recovery_congestion.Congestion, spurious: *Spurious, sent_at_ns: u64, now_ns: u64) void {
    const started_before = congestion.recovery_started_at_ns;
    congestion.on_congestion_event(sent_at_ns, now_ns);
    if (congestion.recovery_started_at_ns != started_before) spurious.on_episode_start();
}

const testing = std.testing;

test "§5.5.11: an episode is spurious once every packet it declared lost is acknowledged" {
    var spurious: Spurious = undefined;
    spurious.init();
    spurious.on_episode_start();
    spurious.on_lost(true, 7);
    spurious.on_lost(true, 9);
    try testing.expect(!spurious.on_acknowledged(8, 8));
    try testing.expect(!spurious.on_acknowledged(7, 7));
    try testing.expect(spurious.on_acknowledged(9, 12));
    // Once found, the episode is over: a repeated acknowledgment finds nothing, and a later loss
    // in the same recovery period cannot make it spurious again.
    try testing.expect(!spurious.on_acknowledged(7, 9));
    spurious.on_lost(true, 20);
    try testing.expect(!spurious.on_acknowledged(20, 20));
}

test "§5.5.11: an episode with no loss, or a loss the list cannot hold, is never spurious" {
    var spurious: Spurious = undefined;
    spurious.init();
    try testing.expect(!spurious.on_acknowledged(0, 100));
    spurious.on_lost(false, 3);
    spurious.on_lost(true, 4);
    try testing.expect(!spurious.on_acknowledged(0, 100));
    spurious.on_episode_start();
    for (0..numbers_max + 1) |number| spurious.on_lost(true, number);
    try testing.expect(!spurious.on_acknowledged(0, 100));
    spurious.on_episode_start();
    spurious.on_lost(true, 5);
    spurious.on_unnamed_loss();
    try testing.expect(!spurious.on_acknowledged(0, 100));
}

test "§5.5.11: a full list of numbers can be found spurious" {
    var spurious: Spurious = undefined;
    spurious.init();
    for (0..numbers_max) |number| spurious.on_lost(true, 2 * number);
    try testing.expect(!spurious.on_acknowledged(0, 2 * numbers_max - 4));
    try testing.expect(spurious.on_acknowledged(2 * numbers_max - 2, 2 * numbers_max - 2));
}

test "§5.5.11: a new episode forgets the old one's losses" {
    var spurious: Spurious = undefined;
    spurious.init();
    spurious.on_lost(true, 1);
    spurious.on_episode_start();
    spurious.on_lost(true, 2);
    try testing.expect(spurious.on_acknowledged(2, 2));
}
