//! What an acknowledgment does to loss recovery (RFC 9002 Appendix A.7). Part of design §8
//! step 10.
//!
//! One ACK frame can do five things at once: take packets out of flight, measure the round trip,
//! report ECN-CE the path marked, reveal packets old enough to declare lost, and let the
//! congestion window grow. Appendix A.7 runs them in that order and so does this.
//!
//! It is a file of its own because `recovery.zig` holds the state and this is the longest of the
//! five entry points. Every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const frame_ack = @import("../frame/frame_ack.zig");
const rtt_estimator = @import("../rtt.zig");
const space = @import("../space/space.zig");
const recovery = @import("recovery.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_loss = @import("recovery_loss.zig");
const recovery_sent = @import("recovery_sent.zig");
const recovery_ecn = @import("recovery_ecn.zig");

const Kind = space.Kind;
const Record = recovery_sent.Record;
const Recovery = recovery.Recovery;
const Utilization = recovery_congestion.Utilization;

/// What one ACK frame said, with the peer's `ack_delay_exponent` already applied. The exponent
/// is a transport parameter (RFC 9000 §18.2) the connection holds and this layer does not.
pub const Ack = struct {
    ranges: frame_ack.AckRanges,
    delay_ns: u64,
    /// The counts the frame carried, when its type was 0x03 (RFC 9000 §19.3.2).
    ecn: ?frame_ack.EcnCounts,
};

/// What the acknowledgment did.
pub const Outcome = struct {
    /// How many packets it took out of flight, and their octets.
    acknowledged: usize,
    in_flight_len: u64,
    /// How many of those packets' records were written to the caller's slice, and how many did
    /// not fit. A caller that wants every one passes a slice as long as the space's table.
    written: usize,
    unwritten: usize,
    /// Whether it produced a round trip sample (RFC 9002 §5.1 allows one per ACK at most).
    rtt_sampled: bool,
    /// What the detection pass it triggered found.
    lost: recovery_loss.Detected,
};

/// RFC 9002 Appendix A.7's `OnAckReceived`. `used` is RFC 9002 §7.8's judgement, which only the
/// caller can make: whether the window or the application bounded what was sent.
///
/// The records of the packets it acknowledges go into `acknowledged`, every one and not only the
/// largest, in the order the frame names its ranges, which RFC 9000 §19.3.1 puts "in descending
/// packet number order".
/// RFC 9000 §3.1 moves a stream to "Data Recvd" once all its data is acknowledged, and only the
/// records say which stream octets each packet carried. The records declared lost go into
/// `lost`, as `recovery_loss.detect` writes them.
pub fn on_ack_received(
    held: *Recovery,
    kind: Kind,
    ack: Ack,
    used: Utilization,
    now_ns: u64,
    acknowledged: []Record,
    lost: []Record,
) Outcome {
    const at = @intFromEnum(kind);
    // RFC 9002 Appendix A.7: the largest acknowledged only ever rises, because an older ACK can
    // arrive after a newer one. Whether it rose is what RFC 9000 §13.4.2.1 judges an ECN count by.
    const largest_is_new = held.largest_acknowledged[at] == null or
        ack.ranges.largest_acknowledged > held.largest_acknowledged[at].?;
    held.largest_acknowledged[at] = if (held.largest_acknowledged[at]) |already|
        @max(already, ack.ranges.largest_acknowledged)
    else
        ack.ranges.largest_acknowledged;

    const removed = take(held, kind, ack, acknowledged);
    var outcome: Outcome = .{
        .acknowledged = removed.count,
        .in_flight_len = removed.in_flight_len,
        .written = removed.written,
        .unwritten = removed.unwritten,
        .rtt_sampled = false,
        .lost = recovery_loss.Detected.none(),
    };
    // RFC 9002 Appendix A.7: nothing to do when the ACK named only packets already accounted for.
    if (removed.count == 0) return outcome;

    outcome.rtt_sampled = sample(held, ack, removed, now_ns);
    process_ecn(held, kind, ack, removed, largest_is_new, now_ns);
    outcome.lost = held.detect(kind, now_ns, lost);
    grow(held, removed, used);

    // RFC 9002 Appendix A.7: the backoff starts again once the peer has validated the address,
    // because a probe that was answered is no longer evidence of a path that will not answer.
    if (held.timer.peer_completed_address_validation) held.timer.pto_count = 0;
    held.timer.spaces[at].ack_eliciting_in_flight = held.table_of(kind).ack_eliciting_count() > 0;
    // RFC 9002 Appendix A.7 ends with `SetLossDetectionTimer`.
    held.timer.armed_at_ns = now_ns;
    return outcome;
}

/// Takes every number the frame named out of the space's table, and writes their records into
/// `acknowledged` one range after another.
fn take(held: *Recovery, kind: Kind, ack: Ack, acknowledged: []Record) recovery_sent.Removed {
    var total = recovery_sent.Removed.none();
    var walk = ack.ranges.iterator();
    // Bounded: RFC 9000 §19.3's ranges are bounded by the frame's own ACK Range Count, and the
    // reader the iterator holds cannot run past the octets it was given.
    while (walk.next()) |range| {
        assert(total.written <= acknowledged.len);
        const into = acknowledged[total.written..];
        const removed = held.table_of(kind).remove_range_into(range.smallest, range.largest, into);
        total.count += removed.count;
        total.written += removed.written;
        total.unwritten += removed.unwritten;
        total.in_flight_len += removed.in_flight_len;
        // RFC 9000 §13.4.2.1 counts over the whole frame, not over one range of it.
        total.ect_0 += removed.ect_0;
        total.ect_1 += removed.ect_1;
        if (removed.any_ack_eliciting) total.any_ack_eliciting = true;
        const largest = removed.largest orelse continue;
        if (total.largest == null or largest > total.largest.?) {
            total.largest = largest;
            total.largest_sent_at_ns = removed.largest_sent_at_ns;
            total.record = removed.record;
        }
    }
    return total;
}

/// RFC 9002 §5.1 and Appendix A.7: one sample per ACK, and only when the largest the frame named
/// is itself newly acknowledged and at least one newly acknowledged packet was ack-eliciting.
fn sample(held: *Recovery, ack: Ack, removed: recovery_sent.Removed, now_ns: u64) bool {
    const largest = removed.largest orelse return false;
    if (largest != ack.ranges.largest_acknowledged) return false;
    if (!removed.any_ack_eliciting) return false;
    assert(now_ns >= removed.largest_sent_at_ns);
    held.rtt.update(.{
        .rtt_ns = now_ns - removed.largest_sent_at_ns,
        .ack_delay_ns = ack.delay_ns,
        .handshake_confirmed = held.timer.handshake_confirmed,
        .taken_at_ns = now_ns,
    });
    return true;
}

/// RFC 9000 §13.4.2.1's validation, then RFC 9002 Appendix B.7's `ProcessECN`: a rise in the
/// peer's ECN-CE count is a congestion event, which is the path reporting congestion without
/// having had to drop anything. The counts are judged before they are used, because §13.4.2.1
/// says "An endpoint that receives an ACK frame with ECN counts therefore validates the counts
/// before using them."
fn process_ecn(
    held: *Recovery,
    kind: Kind,
    ack: Ack,
    removed: recovery_sent.Removed,
    largest_is_new: bool,
    now_ns: u64,
) void {
    const at = @intFromEnum(kind);
    const state = &held.ecn[at];
    switch (recovery_ecn.validate(state, ack.ecn, removed, largest_is_new)) {
        // §13.4.2.2: "If validation fails, then the endpoint MUST disable ECN." The counts that
        // failed are not taken: they are what the endpoint stopped believing.
        .failed => {
            held.ecn_path.on_failed();
            return;
        },
        // §13.4.2.1: a frame that did not raise the largest acknowledged is not judged, and its
        // counts are older than what is already held.
        .not_judged => return,
        .passed => held.ecn_path.on_passed(removed.ect_0 +| removed.ect_1),
    }
    const counts = ack.ecn orelse return;
    const rose = counts.ecn_ce > state.reported.ecn_ce;
    state.accept(counts);
    if (!rose) return;
    held.congestion.on_congestion_event(removed.largest_sent_at_ns, now_ns);
}

/// RFC 9002 Appendix B.5's `OnPacketsAcked`, over what this frame took out of flight.
fn grow(held: *Recovery, removed: recovery_sent.Removed, used: Utilization) void {
    // Appendix B.5 walks the packets one at a time and each one asks the same two questions of
    // the same instant, so the octets are added once. The record kept is the largest, which is
    // the one whose send instant decides whether the recovery period still holds, and the caller
    // has already returned when nothing was removed. Appendix B.5's `if (!acked_packet.in_flight)`
    // needs no test of its own here: octets that were not in flight sum to nothing, and adding
    // nothing to the window is what skipping them does.
    const largest = removed.record.?;
    held.congestion.on_ack(largest.sent_at_ns, removed.in_flight_len, used);
}

const testing = std.testing;

/// The recovery state these tests drive, and room for what one ACK takes out. Test-only.
var test_recovery: Recovery = undefined;
var test_acknowledged: [constants.sent_packets_max]Record = undefined;
var test_lost: [constants.sent_packets_max]Record = undefined;
const test_datagram_len: u16 = 1_200;
const test_start_ns: u64 = 1_000_000_000;
const test_interval_ns: u64 = 1_000_000;

/// RFC 9000 §19.3.1 encodes each range after the first as a Gap and an ACK Range Length, the
/// next range's largest being `previous_smallest - gap - 2`. The first range covers 3 and 4, and
/// these two octets name 0 and 1, so packet 2 is the one left out.
const split_largest: u64 = 4;
const split_first_range: u64 = 1;
const split_octets = [_]u8{ 0, 1 };
const split_acknowledged: usize = 4;

fn split_ack() Ack {
    const ranges: frame_ack.AckRanges = .{
        .largest_acknowledged = split_largest,
        .first_range = split_first_range,
        .octets = &split_octets,
        .count = 1,
    };
    return .{ .ranges = ranges, .delay_ns = 0, .ecn = null };
}

/// Sends packets 0 to `count - 1`, each carrying CRYPTO octets at an offset of its own, so a
/// test can tell one record from another by more than its number. Test-only.
fn send_numbered(count: u64) !void {
    for (0..count) |number| {
        const at_ns = test_start_ns + number * test_interval_ns;
        try test_recovery.on_packet_sent(.application, .{
            .number = number,
            .sent_at_ns = at_ns,
            .sent_len = test_datagram_len,
            .ack_eliciting = true,
            .in_flight = true,
            .carries = .crypto,
            .data_offset = number * test_datagram_len,
            .data_len = test_datagram_len,
        }, at_ns);
    }
}

test "A.7: every packet an ACK takes out reaches the caller, not only the largest" {
    test_recovery.init(test_datagram_len);
    try send_numbered(split_largest + 1);
    const at_ns = test_start_ns + test_interval_ns * (split_largest + 1);
    const outcome = on_ack_received(&test_recovery, .application, split_ack(), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(split_acknowledged, outcome.acknowledged);
    try testing.expectEqual(split_acknowledged, outcome.written);
    try testing.expectEqual(0, outcome.unwritten);
    // RFC 9000 §19.3.1 names the ranges "in descending packet number order", and a range's
    // records come out in ascending order within it.
    var numbers: [split_acknowledged]u64 = undefined;
    for (test_acknowledged[0..split_acknowledged], &numbers) |held, *number| number.* = held.number;
    try testing.expectEqualSlices(u64, &.{ 3, 4, 0, 1 }, &numbers);
    // The whole record reaches the caller, which is what lets it say which octets arrived.
    try testing.expectEqual(3 * test_datagram_len, test_acknowledged[0].data_offset);
}

test "A.7: a slice too short for the acknowledgment is told how many records did not fit" {
    test_recovery.init(test_datagram_len);
    try send_numbered(split_largest + 1);
    const at_ns = test_start_ns + test_interval_ns * (split_largest + 1);
    const outcome = on_ack_received(&test_recovery, .application, split_ack(), .full, at_ns, test_acknowledged[0..1], &test_lost);
    // The slice bounds what is written, never what leaves flight.
    try testing.expectEqual(split_acknowledged, outcome.acknowledged);
    try testing.expectEqual(1, outcome.written);
    try testing.expectEqual(split_acknowledged - 1, outcome.unwritten);
    try testing.expectEqual(3, test_acknowledged[0].number);
}
