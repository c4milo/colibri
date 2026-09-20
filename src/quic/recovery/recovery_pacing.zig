//! Pacing (RFC 9002 §7.7). Part of design §8 step 10.
//!
//! A congestion window says how much may be outstanding, not how fast it may go out. Handed a
//! window of ten datagrams a sender may put all ten on the path at once, which is a burst the
//! path did not ask for and a queue somewhere has to hold. §7.7 requires a sender to either pace
//! or bound its bursts, and colibri paces.
//!
//! It is the leaky bucket §7.7 names. The bucket holds octets, fills at the rate §7.7 gives —
//! the congestion window spread over a round trip, times a factor a little above one so a moving
//! round trip does not leave the window underused — and a packet may go out when the bucket
//! holds its octets. The bucket's capacity is the burst §7.7 permits, which is the initial
//! congestion window.
//!
//! **A packet carrying only ACK frames is not paced**, which §7.7 asks for: delaying an
//! acknowledgment delays the peer's own loss recovery. The caller sends those without asking
//! here, so nothing in this file has to know what a frame is.
//!
//! It reads no clock. Every instant is a parameter (non-negotiable 3), and the arithmetic is
//! integer throughout, so one seed replays byte-identically (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// What the rate is computed from, which the caller holds elsewhere: the congestion window of
/// `recovery_congestion.zig`, the smoothed estimate of `rtt.zig`, and the burst §7.7 permits.
pub const Rate = struct {
    window_len: u64,
    smoothed_rtt_ns: u64,
    /// RFC 9002 §7.7: a sender SHOULD limit bursts to the initial congestion window, so that is
    /// what the bucket holds at most.
    burst_len: u64,
};

pub const Pacer = struct {
    /// The octets the bucket holds, which a packet spends when it goes out.
    credit_len: u64,
    /// When the bucket was last brought up to date, or null before anything has been sent.
    filled_at_ns: ?u64,

    /// A fresh pacer is full, so the first window may go out as the burst §7.7 permits.
    pub fn init(pacer: *Pacer, rate: Rate) void {
        pacer.credit_len = rate.burst_len;
        pacer.filled_at_ns = null;
    }

    /// Brings the bucket up to `now_ns`, adding what the rate earned since it was last filled.
    pub fn refill(pacer: *Pacer, now_ns: u64, rate: Rate) void {
        const filled_at_ns = pacer.filled_at_ns orelse {
            pacer.filled_at_ns = now_ns;
            return;
        };
        // The caller works forward in time, so an instant behind the last one is its own error
        // and not a peer's input (invariant 24).
        assert(now_ns >= filled_at_ns);
        const earned = earned_len(now_ns - filled_at_ns, rate);
        const held = @min(rate.burst_len, pacer.credit_len +| earned);
        // The mark moves by what the octets actually counted cost, not to `now_ns`, so the
        // fraction of an octet the division drops stays owed and refilling often earns what
        // refilling once would. A full bucket has nothing owed, so its mark moves the whole way.
        pacer.filled_at_ns = if (held == rate.burst_len) now_ns else filled_at_ns +| cost_ns(earned, rate);
        pacer.credit_len = held;
    }

    /// Whether a packet of `sent_len` octets may go out now (RFC 9002 §7.7). The caller has
    /// already refilled the bucket at this instant.
    pub fn may_send(pacer: *const Pacer, sent_len: u64) bool {
        return pacer.credit_len >= sent_len;
    }

    /// Spends the octets of a packet that has gone out.
    pub fn on_sent(pacer: *Pacer, sent_len: u64) void {
        pacer.credit_len -|= sent_len;
    }

    /// When a packet of `sent_len` octets will be able to go out, or null when it already can.
    /// RFC 9002 §7.8: a sender held here is pacing limited rather than application limited, so
    /// what it is waiting for is not a reason to hold the congestion window back.
    pub fn next_send_at_ns(pacer: *const Pacer, sent_len: u64, rate: Rate) ?u64 {
        if (pacer.may_send(sent_len)) return null;
        const filled_at_ns = pacer.filled_at_ns orelse return null;
        return filled_at_ns +| wait_ns(sent_len - pacer.credit_len, rate);
    }
};

/// The octets the rate earns over `elapsed_ns`: `N * congestion_window * elapsed / smoothed_rtt`
/// (RFC 9002 §7.7). It is computed in 128 bits and brought back down, because the window times
/// an elapsed time in nanoseconds passes what 64 bits hold on an ordinary path.
fn earned_len(elapsed_ns: u64, rate: Rate) u64 {
    if (rate.smoothed_rtt_ns == 0) return rate.burst_len;
    const scaled: u128 = @as(u128, rate.window_len) * elapsed_ns * constants.pacing_rate_numerator;
    const divisor: u128 = @as(u128, rate.smoothed_rtt_ns) * constants.pacing_rate_denominator;
    return @intCast(@min(scaled / divisor, rate.burst_len));
}

/// How long the rate takes to earn `wanted_len` octets, which is `earned_len` inverted. `round`
/// says which way the division goes: a wait rounds up, so it is never short enough to send
/// early, and time already spent rounds down, so nothing is charged twice.
fn inverted_ns(wanted_len: u64, rate: Rate, round: Round) u64 {
    if (rate.window_len == 0) return std.math.maxInt(u64);
    const scaled: u128 = @as(u128, wanted_len) * rate.smoothed_rtt_ns * constants.pacing_rate_denominator;
    const divisor: u128 = @as(u128, rate.window_len) * constants.pacing_rate_numerator;
    const quotient: u128 = if (round == .up) (scaled + divisor - 1) / divisor else scaled / divisor;
    return @intCast(@min(quotient, std.math.maxInt(u64)));
}

const Round = enum { up, down };

/// How long the rate takes to earn `wanted_len` octets, rounded up.
fn wait_ns(wanted_len: u64, rate: Rate) u64 {
    assert(wanted_len > 0);
    return inverted_ns(wanted_len, rate, .up);
}

/// How much of the elapsed time `earned` octets account for, rounded down.
fn cost_ns(earned: u64, rate: Rate) u64 {
    return inverted_ns(earned, rate, .down);
}

const testing = std.testing;

/// The pacer the tests drive. Test-only.
var test_pacer: Pacer = undefined;
/// A path whose window is ten datagrams over a 100 ms round trip, so the rate earns one datagram
/// every 8 ms: 100 ms divided by ten datagrams, and then by the 5/4 of §7.7. Every instant is
/// written whole in nanoseconds, because the magic-numbers rule reads a constant's whole value.
const test_datagram_len: u64 = 1_200;
const test_window_len: u64 = 12_000;
const test_round_trip_ns: u64 = 100_000_000;
const test_per_datagram_ns: u64 = 8_000_000;
const test_now_ns: u64 = 10_000_000_000;
const test_rate: Rate = .{
    .window_len = test_window_len,
    .smoothed_rtt_ns = test_round_trip_ns,
    .burst_len = test_window_len,
};

test "§7.7: a fresh pacer holds the burst and spends it" {
    test_pacer.init(test_rate);
    // RFC 9002 §7.7: the burst is the initial congestion window, so the first window goes out
    // without waiting, and nothing past it does.
    try testing.expect(test_pacer.may_send(test_window_len));
    try testing.expect(!test_pacer.may_send(test_window_len + 1));
    test_pacer.on_sent(test_window_len);
    try testing.expectEqual(0, test_pacer.credit_len);
    try testing.expect(!test_pacer.may_send(1));
    // A pacer that has never been refilled has no instant to earn from, so the first refill
    // only marks where time starts and earns nothing however late it is.
    test_pacer.init(test_rate);
    test_pacer.on_sent(test_datagram_len);
    test_pacer.refill(test_now_ns, test_rate);
    try testing.expectEqual(test_window_len - test_datagram_len, test_pacer.credit_len);
}

test "§7.7: the bucket fills at the window spread over a round trip" {
    test_pacer.init(test_rate);
    // The first refill only marks where time starts, because nothing has been sent yet.
    test_pacer.refill(test_now_ns, test_rate);
    try testing.expectEqual(test_window_len, test_pacer.credit_len);
    test_pacer.on_sent(test_window_len);
    // One datagram's worth of time earns one datagram.
    test_pacer.refill(test_now_ns + test_per_datagram_ns, test_rate);
    try testing.expectEqual(test_datagram_len, test_pacer.credit_len);
    try testing.expect(test_pacer.may_send(test_datagram_len));
    try testing.expect(!test_pacer.may_send(test_datagram_len + 1));
    // A round trip earns a whole window, and the bucket holds no more than the burst however
    // long it is left to fill.
    test_pacer.on_sent(test_datagram_len);
    test_pacer.refill(test_now_ns + test_per_datagram_ns + test_round_trip_ns, test_rate);
    try testing.expectEqual(test_window_len, test_pacer.credit_len);
    test_pacer.refill(test_now_ns + test_per_datagram_ns + 2 * test_round_trip_ns, test_rate);
    try testing.expectEqual(test_window_len, test_pacer.credit_len);
}

test "§7.7: a wider window and a shorter round trip both pace faster" {
    test_pacer.init(test_rate);
    test_pacer.refill(test_now_ns, test_rate);
    test_pacer.on_sent(test_window_len);
    // Twice the window earns twice as much over the same time.
    var wider = test_rate;
    wider.window_len = 2 * test_window_len;
    test_pacer.refill(test_now_ns + test_per_datagram_ns, wider);
    try testing.expectEqual(2 * test_datagram_len, test_pacer.credit_len);
    // Half the round trip does too.
    test_pacer.init(test_rate);
    test_pacer.refill(test_now_ns, test_rate);
    test_pacer.on_sent(test_window_len);
    var shorter = test_rate;
    shorter.smoothed_rtt_ns = test_round_trip_ns / 2;
    test_pacer.refill(test_now_ns + test_per_datagram_ns, shorter);
    try testing.expectEqual(2 * test_datagram_len, test_pacer.credit_len);
}

test "§7.7: the wait for a packet is when the rate will have earned it" {
    test_pacer.init(test_rate);
    test_pacer.refill(test_now_ns, test_rate);
    // With the burst in hand there is nothing to wait for.
    try testing.expectEqual(null, test_pacer.next_send_at_ns(test_datagram_len, test_rate));
    test_pacer.on_sent(test_window_len);
    // Empty, one datagram costs the interval §7.7 computes, and two cost twice it.
    try testing.expectEqual(test_now_ns + test_per_datagram_ns, test_pacer.next_send_at_ns(test_datagram_len, test_rate));
    try testing.expectEqual(test_now_ns + 2 * test_per_datagram_ns, test_pacer.next_send_at_ns(2 * test_datagram_len, test_rate));
    // Partly filled, only the shortfall is waited for: half a datagram in hand leaves half to
    // earn, and the wait is half the interval.
    test_pacer.refill(test_now_ns + test_per_datagram_ns / 2, test_rate);
    const waited = test_pacer.next_send_at_ns(test_datagram_len, test_rate).?;
    try testing.expectEqual(test_now_ns + test_per_datagram_ns, waited);
    // The wait rounds up, so an instant one nanosecond short of it cannot send.
    var tight = test_pacer;
    tight.refill(waited - 1, test_rate);
    try testing.expect(!tight.may_send(test_datagram_len));
    tight.refill(waited, test_rate);
    try testing.expect(tight.may_send(test_datagram_len));
    // A size the rate does not divide evenly shows the rounding: one octet past a datagram
    // costs 8,006,667 ns, and at 8,006,666 the bucket is one octet short.
    test_pacer.init(test_rate);
    test_pacer.refill(test_now_ns, test_rate);
    test_pacer.on_sent(test_window_len);
    const odd_len = test_datagram_len + 1;
    const odd_ns: u64 = 8_006_667;
    try testing.expectEqual(test_now_ns + odd_ns, test_pacer.next_send_at_ns(odd_len, test_rate));
    var early = test_pacer;
    early.refill(test_now_ns + odd_ns - 1, test_rate);
    try testing.expect(!early.may_send(odd_len));
    test_pacer.refill(test_now_ns + odd_ns, test_rate);
    try testing.expect(test_pacer.may_send(odd_len));
}

test "§7.7: a path with no estimate yet paces nothing" {
    // Before the first round trip sample there is no rate to spread a window over, so the burst
    // is what bounds sending and the bucket refills whole.
    var unmeasured = test_rate;
    unmeasured.smoothed_rtt_ns = 0;
    test_pacer.init(unmeasured);
    test_pacer.refill(test_now_ns, unmeasured);
    test_pacer.on_sent(test_window_len);
    test_pacer.refill(test_now_ns + 1, unmeasured);
    try testing.expectEqual(test_window_len, test_pacer.credit_len);
}

test "§7.7: refilling often earns what refilling once earns" {
    // The rate is a division, and a division over many small steps drops a fraction at every
    // one. The mark moves by what the octets counted actually cost, so the fraction stays owed
    // and the two paths arrive at the same credit.
    test_pacer.init(test_rate);
    test_pacer.refill(test_now_ns, test_rate);
    test_pacer.on_sent(test_window_len);
    var often = test_pacer;
    // A thousand steps of a microsecond each, which is one datagram's interval in total.
    const step_ns: u64 = 1_000;
    const steps: u64 = test_per_datagram_ns / step_ns;
    for (1..steps + 1) |step| often.refill(test_now_ns + step * step_ns, test_rate);
    test_pacer.refill(test_now_ns + test_per_datagram_ns, test_rate);
    try testing.expectEqual(test_datagram_len, test_pacer.credit_len);
    try testing.expectEqual(test_pacer.credit_len, often.credit_len);
}
