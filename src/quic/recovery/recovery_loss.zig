//! Which packets are lost (RFC 9002 §6.1 and Appendix A.10). Part of design §8 step 10.
//!
//! A packet is lost when a later packet in the same space has been acknowledged and one of two
//! things is true: three packets were acknowledged after it (§6.1.1's packet threshold), or it
//! was sent longer than a threshold ago (§6.1.2's time threshold). Neither is a certainty; both
//! are the point at which waiting longer costs more than resending.
//!
//! **The lost packets are a run at the front of the table, and that is what makes this cheap.**
//! Both thresholds rise with the packet number: a packet the time threshold spares is newer than
//! one it does not, and a packet the count spares has a higher number than one it does not. So
//! the walk stops at the first packet that survives, and everything taken out is one range.
//! `recovery_sent.zig` holds the records in packet number order, which is what that relies on.
//!
//! It reads no clock and it decides nothing about the congestion window. `now_ns` and the loss
//! delay are parameters (non-negotiable 3), and what a loss does to the window is §7's.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const recovery_sent = @import("recovery_sent.zig");

const Record = recovery_sent.Record;

/// What one detection pass found (RFC 9002 Appendix A.10).
pub const Detected = struct {
    /// How many packets were declared lost, and the octets of the ones that were in flight.
    count: usize,
    in_flight_len: u64,
    /// RFC 9002 Appendix B.8's `sent_time_of_last_loss`: when the newest lost packet that was in
    /// flight was sent, or null when none was. §7 starts a congestion event from it.
    latest_sent_at_ns: ?u64,
    /// RFC 9002 §6.1.2: when the oldest packet that survived this pass will become old enough to
    /// be declared lost, so the caller can set a timer for it. Null when none survived.
    loss_time_ns: ?u64,
    /// RFC 9002 §7.6.2's two packets: the send instants of the oldest and newest ack-eliciting
    /// packets in an unbroken run of loss, counting only those sent after the first round trip
    /// sample. Both null when no such run was found.
    persistent_first_ns: ?u64,
    persistent_last_ns: ?u64,
    /// How many records were written to the caller's slice, and how many did not fit. A caller
    /// that wants every one passes a slice as long as its table.
    written: usize,
    unwritten: usize,

    pub fn none() Detected {
        return .{
            .count = 0,
            .in_flight_len = 0,
            .latest_sent_at_ns = null,
            .loss_time_ns = null,
            .persistent_first_ns = null,
            .persistent_last_ns = null,
            .written = 0,
            .unwritten = 0,
        };
    }

    /// Whether the run of loss covers `duration_ns`, which is RFC 9002 §7.6.2's test that the
    /// span between its two packets exceeds the persistent congestion duration of §7.6.1.
    pub fn is_persistent_congestion(detected: Detected, duration_ns: u64) bool {
        const first_ns = detected.persistent_first_ns orelse return false;
        // The two are set together, so a run with a first has a last.
        const last_ns = detected.persistent_last_ns.?;
        assert(last_ns >= first_ns);
        // RFC 9002 §7.6.2 requires two ack-eliciting packets and needs no separate test for it:
        // a run that found one spans nothing, and nothing never exceeds a duration.
        return last_ns - first_ns > duration_ns;
    }
};

/// Declares lost what RFC 9002 §6.1's two thresholds reach, takes those records out of `table`,
/// and writes as many of them as fit into `lost`. `largest_acknowledged` is the largest number
/// the peer has ever acknowledged in this space, `now_ns` the instant the caller is working at,
/// `loss_delay_ns` §6.1.2's threshold from `Rtt.loss_delay_ns`, and `first_sample_at_ns` RFC 9002
/// Appendix A.3's `first_rtt_sample`, which §7.6.2 requires a packet to have been sent after
/// before it may count toward persistent congestion.
pub fn detect(
    table: anytype,
    largest_acknowledged: u64,
    now_ns: u64,
    loss_delay_ns: u64,
    first_sample_at_ns: ?u64,
    lost: []Record,
) Detected {
    // RFC 9002 Appendix A.10: packets sent before this instant are deemed lost.
    const lost_before_ns = now_ns -| loss_delay_ns;
    var pass = Pass.start(first_sample_at_ns, lost);
    var walk = table.iterator();
    // Bounded by the table, whose capacity is a named limit.
    while (walk.next()) |held| {
        // RFC 9002 §6.1: a packet is declared lost only once a later one in the same space has
        // been acknowledged, so nothing above the largest acknowledged is even considered.
        if (held.number > largest_acknowledged) break;
        if (!is_lost(held, largest_acknowledged, lost_before_ns)) {
            // RFC 9002 §6.1.2: the oldest survivor is when the timer should next fire, and the
            // walk ends there because every later packet is younger and higher numbered.
            pass.found.loss_time_ns = held.sent_at_ns +| loss_delay_ns;
            break;
        }
        take(held, &pass);
    }
    if (pass.found.count > 0) {
        // The lost packets are a run at the front, so one range takes them all out.
        const removed = table.remove_range(0, pass.latest_number);
        assert(removed.count == pass.found.count);
    }
    pass.found.persistent_first_ns = pass.run.first_ns;
    pass.found.persistent_last_ns = pass.run.last_ns;
    return pass.found;
}

/// Whether RFC 9002 §6.1's two thresholds reach `held`.
fn is_lost(held: Record, largest_acknowledged: u64, lost_before_ns: u64) bool {
    // RFC 9002 §6.1.2: sent a threshold amount of time in the past.
    if (held.sent_at_ns <= lost_before_ns) return true;
    // RFC 9002 §6.1.1: three packets acknowledged after it. The count stands in for reordering,
    // and Appendix A.10 notes it assumes the sender left no gaps in its numbers, which colibri
    // does not: `space.zig` hands out every number in turn.
    return largest_acknowledged >= held.number +| constants.loss_packet_threshold;
}

/// The run of ack-eliciting loss RFC 9002 §7.6.2 measures, and what breaks it.
const Run = struct {
    first_ns: ?u64,
    last_ns: ?u64,
    /// The number of the last packet added, so a gap in the numbers can be seen.
    previous_number: ?u64,
};

/// What one call to `detect` accumulates, held together so each step below takes one parameter.
const Pass = struct {
    found: Detected,
    run: Run,
    /// The largest number declared lost so far, which is what the removal range ends at.
    latest_number: u64,
    first_sample_at_ns: ?u64,
    lost: []Record,

    fn start(first_sample_at_ns: ?u64, lost: []Record) Pass {
        return .{
            .found = Detected.none(),
            .run = .{ .first_ns = null, .last_ns = null, .previous_number = null },
            .latest_number = 0,
            .first_sample_at_ns = first_sample_at_ns,
            .lost = lost,
        };
    }
};

/// Adds one lost packet to what was found.
fn take(held: Record, pass: *Pass) void {
    pass.found.count += 1;
    pass.latest_number = held.number;
    if (held.in_flight) {
        pass.found.in_flight_len += held.sent_len;
        // RFC 9002 Appendix B.8: the congestion event starts from the newest in-flight loss, and
        // the walk is in packet number order, so the last one seen is the newest.
        pass.found.latest_sent_at_ns = held.sent_at_ns;
    }
    if (pass.found.written < pass.lost.len) {
        pass.lost[pass.found.written] = held;
        pass.found.written += 1;
    } else {
        pass.found.unwritten += 1;
    }
    extend(held, pass);
}

/// Extends RFC 9002 §7.6.2's run of loss, or starts it over where the run is broken.
fn extend(held: Record, pass: *Pass) void {
    // RFC 9002 §7.6.2: the two packets MUST be ack-eliciting, because a receiver need only
    // acknowledge those, so a run of other packets says nothing about the path.
    if (!held.ack_eliciting) return;
    // RFC 9002 §7.6.2 and Appendix B.8: only packets sent after the first round trip sample
    // count, because before it the Probe Timeout rests on §6.2.2's initial estimate and may be
    // far longer than the path really is.
    const sampled_at_ns = pass.first_sample_at_ns orelse return;
    if (held.sent_at_ns <= sampled_at_ns) return;
    // RFC 9002 §7.6.2: no packet sent between the two may have been acknowledged. One that was
    // is no longer in the table, which shows as a gap in the numbers, and the run starts over.
    const follows = if (pass.run.previous_number) |previous| held.number == previous +| 1 else false;
    if (!follows) pass.run.first_ns = held.sent_at_ns;
    pass.run.last_ns = held.sent_at_ns;
    pass.run.previous_number = held.number;
}

const testing = std.testing;

/// The table the tests drive, and a slice long enough to take every record out of it. Test-only.
const test_capacity: usize = 8;
const TestTable = recovery_sent.Sent(test_capacity);
var test_table: TestTable = undefined;
var test_lost: [test_capacity]Record = undefined;
/// A packet size the tests can add up by eye, and the instants they measure from.
const test_len: u16 = 100;
const test_first_sent_at_ns: u64 = 200;
const test_send_interval_ns: u64 = 100;
const test_sampled_at_ns: u64 = 100;
const test_loss_delay_ns: u64 = 50;

/// An ack-eliciting packet in flight, numbered `number` and sent `number` intervals in.
fn eliciting(number: u64) Record {
    return .{
        .number = number,
        .sent_at_ns = test_first_sent_at_ns + number * test_send_interval_ns,
        .sent_len = test_len,
        .ack_eliciting = true,
        .in_flight = true,
    };
}

/// A packet carrying only ACK, and no PADDING (RFC 9002 §2): neither ack-eliciting nor in
/// flight. PADDING alone would make it in flight, which is the other half of §2's definition.
fn acknowledgment_only(number: u64) Record {
    var held = eliciting(number);
    held.ack_eliciting = false;
    held.in_flight = false;
    return held;
}

/// Fills the table with `count` ack-eliciting packets numbered from zero. Test-only.
fn fill(count: u64) !void {
    test_table.init();
    for (0..count) |number| try test_table.record(eliciting(number));
}

/// An instant every packet in the table was sent well before. Test-only.
const test_long_after_ns: u64 = 100_000;

test "§6.1.1: three packets acknowledged after one declare it lost" {
    try fill(4);
    // The peer acknowledged 3, which leaves 0, 1 and 2 outstanding. Only 0 is three below it.
    _ = test_table.remove_range(3, 3);
    const found = detect(&test_table, 3, test_first_sent_at_ns, test_loss_delay_ns, null, &test_lost);
    try testing.expectEqual(1, found.count);
    try testing.expectEqual(test_len, found.in_flight_len);
    try testing.expectEqual(test_first_sent_at_ns, found.latest_sent_at_ns);
    try testing.expectEqual(0, test_lost[0].number);
    try testing.expectEqual(2, test_table.count());
    // RFC 9002 §6.1.2: 1 survived, so the timer is set for when it will be old enough.
    try testing.expectEqual(eliciting(1).sent_at_ns + test_loss_delay_ns, found.loss_time_ns);
}

test "§6.1.2: a packet sent a threshold ago is lost whatever the count says" {
    try fill(4);
    _ = test_table.remove_range(3, 3);
    // Far enough ahead that every remaining packet was sent before `now - loss_delay`.
    const found = detect(&test_table, 3, test_long_after_ns, test_loss_delay_ns, null, &test_lost);
    try testing.expectEqual(3, found.count);
    try testing.expectEqual(3 * test_len, found.in_flight_len);
    try testing.expectEqual(eliciting(2).sent_at_ns, found.latest_sent_at_ns);
    // Nothing survived, so there is nothing to set a timer for.
    try testing.expectEqual(null, found.loss_time_ns);
    try testing.expectEqual(0, test_table.count());
}

test "§6.1: nothing above the largest acknowledged is declared lost" {
    try fill(4);
    // The peer acknowledged 1. Packets 2 and 3 are above it, so however old they are they are
    // not lost: no later packet in this space has been acknowledged.
    _ = test_table.remove_range(1, 1);
    const found = detect(&test_table, 1, test_long_after_ns, test_loss_delay_ns, null, &test_lost);
    try testing.expectEqual(1, found.count);
    try testing.expectEqual(0, test_lost[0].number);
    try testing.expectEqual(2, test_table.count());
    try testing.expectEqual(2, test_table.oldest().?.number);
    // A second pass finds nothing: everything left is above the largest acknowledged, which is
    // what keeps a repeated or reordered ACK from declaring the same packets lost twice.
    const again = detect(&test_table, 1, test_long_after_ns, test_loss_delay_ns, null, &test_lost);
    try testing.expectEqual(0, again.count);
    try testing.expectEqual(null, again.loss_time_ns);
    try testing.expectEqual(2, test_table.count());
}

test "§7.2: a lost packet not in flight is counted but weighs nothing" {
    test_table.init();
    try test_table.record(acknowledgment_only(0));
    try test_table.record(eliciting(1));
    try test_table.record(eliciting(2));
    _ = test_table.remove_range(2, 2);
    const found = detect(&test_table, 2, test_long_after_ns, test_loss_delay_ns, null, &test_lost);
    try testing.expectEqual(2, found.count);
    // RFC 9002 Appendix B.8: only the octets in flight come off, and the congestion event starts
    // from the newest loss that was in flight rather than from the newest loss.
    try testing.expectEqual(test_len, found.in_flight_len);
    try testing.expectEqual(eliciting(1).sent_at_ns, found.latest_sent_at_ns);
}

test "A.10: a caller's slice shorter than the loss is told what did not fit" {
    try fill(5);
    _ = test_table.remove_range(4, 4);
    var room: [2]Record = undefined;
    const found = detect(&test_table, 4, test_long_after_ns, test_loss_delay_ns, null, &room);
    // Every lost packet still leaves the table and still counts; the slice bounds only what the
    // caller is handed back.
    try testing.expectEqual(4, found.count);
    try testing.expectEqual(2, found.written);
    try testing.expectEqual(2, found.unwritten);
    try testing.expectEqual(0, room[0].number);
    try testing.expectEqual(1, room[1].number);
    try testing.expectEqual(0, test_table.count());
}

test "§7.6.2: an unbroken run of ack-eliciting loss is a span" {
    try fill(6);
    const found = detect(&test_table, 5, test_long_after_ns, test_loss_delay_ns, test_sampled_at_ns, &test_lost);
    try testing.expectEqual(6, found.count);
    try testing.expectEqual(eliciting(0).sent_at_ns, found.persistent_first_ns);
    try testing.expectEqual(eliciting(5).sent_at_ns, found.persistent_last_ns);
    // The span is five intervals, so a duration below it establishes persistent congestion and
    // one at or above it does not.
    const span_ns = 5 * test_send_interval_ns;
    try testing.expect(found.is_persistent_congestion(span_ns - 1));
    try testing.expect(!found.is_persistent_congestion(span_ns));
}

test "§7.6.2: a packet acknowledged between the two breaks the run" {
    test_table.init();
    // 2 was acknowledged earlier, so it is not in the table: the numbers jump, and the run that
    // 0 and 1 began cannot reach 3 and 4.
    for ([_]u64{ 0, 1, 3, 4 }) |number| try test_table.record(eliciting(number));
    const found = detect(&test_table, 4, test_long_after_ns, test_loss_delay_ns, test_sampled_at_ns, &test_lost);
    try testing.expectEqual(4, found.count);
    try testing.expectEqual(eliciting(3).sent_at_ns, found.persistent_first_ns);
    try testing.expectEqual(eliciting(4).sent_at_ns, found.persistent_last_ns);
    // One interval, where the unbroken run would have measured four.
    try testing.expect(found.is_persistent_congestion(test_send_interval_ns - 1));
    try testing.expect(!found.is_persistent_congestion(test_send_interval_ns));
}

test "§7.6.2: a run needs two ack-eliciting packets sent after the first sample" {
    // Before any round trip sample there is no run at all, whatever was lost.
    try fill(6);
    const unsampled = detect(&test_table, 5, test_long_after_ns, test_loss_delay_ns, null, &test_lost);
    try testing.expectEqual(6, unsampled.count);
    try testing.expectEqual(null, unsampled.persistent_first_ns);
    try testing.expect(!unsampled.is_persistent_congestion(0));
    // A sample taken after the last send leaves nothing that counts either.
    try fill(6);
    const late = detect(&test_table, 5, test_long_after_ns, test_loss_delay_ns, test_long_after_ns, &test_lost);
    try testing.expectEqual(null, late.persistent_last_ns);
    // One packet is not two, so a run of one is not a span however long the duration.
    test_table.init();
    try test_table.record(eliciting(0));
    try test_table.record(acknowledgment_only(1));
    const single = detect(&test_table, 1, test_long_after_ns, test_loss_delay_ns, test_sampled_at_ns, &test_lost);
    try testing.expectEqual(2, single.count);
    try testing.expectEqual(single.persistent_first_ns, single.persistent_last_ns);
    try testing.expect(!single.is_persistent_congestion(0));
}
