//! RFC 9000 §13.4.2's ECN validation: whether the counts a peer reports can be believed, and what
//! happens when they cannot.
//!
//! **colibri marks nothing.** §13.4.2 has an endpoint "set an ECT(0) codepoint in the IP header
//! of early outgoing packets", and the IP header is the caller's — colibri owns no socket
//! (non-negotiable 1). So the caller says what it marked, one record at a time, and this file
//! judges what comes back against it. `enabled` is the answer §13.4.2.2 asks for: once validation
//! fails the endpoint "stops setting the ECT codepoint in IP packets that it sends", which is a
//! thing the caller does and colibri only reports.
//!
//! **The counts are per space and the verdict is per path.** §13.4.2 validates "for each network
//! path", and §19.3.2 carries the counts per packet number space, so the state below is one per
//! space and the endpoint holds a single answer over them.
const std = @import("std");
const assert = std.debug.assert;
const frame_ack = @import("../frame/frame_ack.zig");
const recovery_sent = @import("recovery_sent.zig");

const EcnCounts = frame_ack.EcnCounts;
const Removed = recovery_sent.Removed;
const Ecn = recovery_sent.Ecn;

/// What RFC 9000 §13.4.2.1 made of one ACK frame.
pub const Verdict = enum {
    /// Every check §13.4.2.1 states passed, so the counts may be used.
    passed,
    /// §13.4.2.1: "An endpoint MUST NOT fail ECN validation as a result of processing an ACK
    /// frame that does not increase the largest acknowledged packet number." A reordered frame is
    /// not judged, and its counts are not taken either: they are older than what is held.
    not_judged,
    /// §13.4.2.2: "If validation fails, then the endpoint MUST disable ECN."
    failed,
};

/// What one packet number space remembers for §13.4.2.1's comparison.
pub const State = struct {
    /// The counts of the last ACK frame whose validation passed, which §13.4.2.1 measures the
    /// next frame's increase against.
    reported: EcnCounts,
    /// Packets this endpoint sent in this space with each ECT codepoint. §13.4.2.1 fails a frame
    /// whose reported total "exceeds the total number of packets sent with each corresponding ECT
    /// codepoint", which is what these two hold.
    sent_ect_0: u64,
    sent_ect_1: u64,

    pub fn init(state: *State) void {
        state.* = .{
            .reported = .{ .ect_0 = 0, .ect_1 = 0, .ecn_ce = 0 },
            .sent_ect_0 = 0,
            .sent_ect_1 = 0,
        };
    }

    /// Counts one packet this endpoint sent under `ecn` (RFC 9000 §13.4). ECN-CE is not among
    /// them: §13.4 has a sender mark ECT(0) or ECT(1), and the network is what sets ECN-CE.
    pub fn on_packet_sent(state: *State, ecn: Ecn) void {
        switch (ecn) {
            .ect_0 => state.sent_ect_0 +|= 1,
            .ect_1 => state.sent_ect_1 +|= 1,
            .not_ect, .ecn_ce => {},
        }
    }

    /// Records the counts of a frame that passed, which the next frame is measured against.
    pub fn accept(state: *State, counts: EcnCounts) void {
        assert(counts.ecn_ce >= state.reported.ecn_ce);
        state.reported = counts;
    }
};

/// RFC 9000 §13.4.2.1's checks over one ACK frame. `counts` is what the frame carried, or null
/// when its type was 0x02 and it carried none; `removed` is what it newly acknowledged; and
/// `largest_is_new` is whether it raised the largest acknowledged packet number.
pub fn validate(state: *const State, counts: ?EcnCounts, removed: Removed, largest_is_new: bool) Verdict {
    // §13.4.2.1: "Validating ECN counts from reordered ACK frames can result in failure. An
    // endpoint MUST NOT fail ECN validation as a result of processing an ACK frame that does not
    // increase the largest acknowledged packet number."
    if (!largest_is_new) return .not_judged;
    const held = counts orelse {
        // §13.4.2.1: "If an ACK frame newly acknowledges a packet that the endpoint sent with
        // either the ECT(0) or ECT(1) codepoint set, ECN validation fails if the corresponding
        // ECN counts are not present in the ACK frame."
        if (removed.ect_0 > 0 or removed.ect_1 > 0) return .failed;
        return .passed;
    };
    // §13.4.2.1: "ECN validation can fail if the received total count for either ECT(0) or ECT(1)
    // exceeds the total number of packets sent with each corresponding ECT codepoint. In
    // particular, validation will fail when an endpoint receives a non-zero ECN count
    // corresponding to an ECT codepoint that it never applied."
    if (held.ect_0 > state.sent_ect_0) return .failed;
    if (held.ect_1 > state.sent_ect_1) return .failed;
    return remarking_verdict(state, held, removed);
}

/// §13.4.2.1's two sums, which "can detect remarking of ECN-CE markings by the network". The rise
/// in ECN-CE is offered to each of them, because the section states the two checks separately and
/// a packet marked ECT(0) that arrives ECN-CE raises the one count and not the other.
fn remarking_verdict(state: *const State, held: EcnCounts, removed: Removed) Verdict {
    const ce_rise = held.ecn_ce -| state.reported.ecn_ce;
    // "ECN validation also fails if the sum of the increase in ECT(0) and ECN-CE counts is less
    // than the number of newly acknowledged packets that were originally sent with an ECT(0)
    // marking."
    if (held.ect_0 -| state.reported.ect_0 +| ce_rise < removed.ect_0) return .failed;
    // "Similarly, ECN validation fails if the sum of the increases to ECT(1) and ECN-CE counts is
    // less than the number of newly acknowledged packets sent with an ECT(1) marking."
    if (held.ect_1 -| state.reported.ect_1 +| ce_rise < removed.ect_1) return .failed;
    return .passed;
}

test {
    _ = @import("recovery_ecn_test.zig");
}
