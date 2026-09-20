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
    /// Whether it produced a round trip sample (RFC 9002 §5.1 allows one per ACK at most).
    rtt_sampled: bool,
    /// What the detection pass it triggered found.
    lost: recovery_loss.Detected,
};

/// RFC 9002 Appendix A.7's `OnAckReceived`. `used` is RFC 9002 §7.8's judgement, which only the
/// caller can make: whether the window or the application bounded what was sent.
pub fn on_ack_received(
    held: *Recovery,
    kind: Kind,
    ack: Ack,
    used: Utilization,
    now_ns: u64,
    lost: []Record,
) Outcome {
    const at = @intFromEnum(kind);
    // RFC 9002 Appendix A.7: the largest acknowledged only ever rises, because an older ACK can
    // arrive after a newer one.
    held.largest_acknowledged[at] = if (held.largest_acknowledged[at]) |already|
        @max(already, ack.ranges.largest_acknowledged)
    else
        ack.ranges.largest_acknowledged;

    const removed = take(held, kind, ack);
    var outcome: Outcome = .{
        .acknowledged = removed.count,
        .in_flight_len = removed.in_flight_len,
        .rtt_sampled = false,
        .lost = recovery_loss.Detected.none(),
    };
    // RFC 9002 Appendix A.7: nothing to do when the ACK named only packets already accounted for.
    if (removed.count == 0) return outcome;

    outcome.rtt_sampled = sample(held, ack, removed, now_ns);
    if (ack.ecn) |counts| process_ecn(held, kind, counts, removed, now_ns);
    outcome.lost = held.detect(kind, now_ns, lost);
    grow(held, removed, used);

    // RFC 9002 Appendix A.7: the backoff starts again once the peer has validated the address,
    // because a probe that was answered is no longer evidence of a path that will not answer.
    if (held.timer.peer_completed_address_validation) held.timer.pto_count = 0;
    held.timer.spaces[at].ack_eliciting_in_flight = held.table_of(kind).ack_eliciting_count() > 0;
    return outcome;
}

/// Takes every number the frame named out of the space's table.
fn take(held: *Recovery, kind: Kind, ack: Ack) recovery_sent.Removed {
    var total = recovery_sent.Removed.none();
    var walk = ack.ranges.iterator();
    // Bounded: RFC 9000 §19.3's ranges are bounded by the frame's own ACK Range Count, and the
    // reader the iterator holds cannot run past the octets it was given.
    while (walk.next()) |range| {
        const removed = held.table_of(kind).remove_range(range.smallest, range.largest);
        total.count += removed.count;
        total.in_flight_len += removed.in_flight_len;
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

/// RFC 9002 Appendix B.7's `ProcessECN`: a rise in the peer's ECN-CE count is a congestion event,
/// which is the path reporting congestion without having had to drop anything.
fn process_ecn(
    held: *Recovery,
    kind: Kind,
    counts: frame_ack.EcnCounts,
    removed: recovery_sent.Removed,
    now_ns: u64,
) void {
    const at = @intFromEnum(kind);
    if (counts.ecn_ce <= held.ecn_ce_counts[at]) return;
    held.ecn_ce_counts[at] = counts.ecn_ce;
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
