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
//! path", and §19.3.2 carries the counts per packet number space, so `State` is one per space and
//! `Path` is the endpoint's single answer over them.
//!
//! **A path is tested before it is trusted.** Decision 69 follows Appendix A.4: the first marked
//! packets are a test, and past it the endpoint marks only once an acknowledgment shows a marked
//! packet arrived.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
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

/// RFC 9000 Appendix A.4's states of a path: "On paths with a "testing" or "capable" state, the
/// endpoint sends packets with an ECT marking ... otherwise, the endpoint sends unmarked packets."
pub const PathState = enum { testing, unknown, capable, failed };

/// What one path remembers of its ECN test (decision 69).
pub const Path = struct {
    state: PathState,
    /// Packets sent marked while testing, which `ecn_testing_packets` bounds.
    tested_packets: u64,
    /// The instant the first marked packet went out, or null before one has. The test ends
    /// `ecn_testing_probe_timeouts` PTOs after it.
    testing_since_ns: ?u64,
    /// Whether an ACK frame that passed validation acknowledged a packet sent marked, which is
    /// what Appendix A.4 asks before an unknown path becomes capable.
    marked_acknowledged: bool,

    pub fn init(path: *Path) void {
        path.* = .{ .state = .testing, .tested_packets = 0, .testing_since_ns = null, .marked_acknowledged = false };
    }

    /// Whether the next datagram carries ECT(0). The test ends at the first datagram after its
    /// packets or its period are spent. `probe_timeout_ns` is RFC 9002 §6.2.1's period now.
    pub fn marks(path: *Path, now_ns: u64, probe_timeout_ns: u64) bool {
        if (path.state == .testing and path.testing_spent(now_ns, probe_timeout_ns)) {
            // Appendix A.4: "After the testing period ends, the ECN state for the path becomes
            // "unknown"."
            path.state = .unknown;
        }
        return path.state == .testing or path.state == .capable;
    }

    /// RFC 9000 §13.4.2: "the first ten outgoing packets on a path, or ... a period of three
    /// PTOs", whichever is spent first (decision 69).
    fn testing_spent(path: *const Path, now_ns: u64, probe_timeout_ns: u64) bool {
        if (path.tested_packets >= constants.ecn_testing_packets) return true;
        const since_ns = path.testing_since_ns orelse return false;
        return now_ns -| since_ns >= constants.ecn_testing_probe_timeouts *| probe_timeout_ns;
    }

    /// Counts one packet sent marked ECT at `now_ns`.
    pub fn on_marked_sent(path: *Path, now_ns: u64) void {
        assert(path.state == .testing or path.state == .capable);
        if (path.state != .testing) return;
        if (path.testing_since_ns == null) path.testing_since_ns = now_ns;
        path.tested_packets +|= 1;
    }

    /// An ACK frame whose counts passed §13.4.2.1, which newly acknowledged `marked` packets
    /// sent with an ECT codepoint.
    pub fn on_passed(path: *Path, marked: u64) void {
        if (marked > 0) path.marked_acknowledged = true;
        // Appendix A.4: "From the "unknown" state, successful validation of the ECN counts in an
        // ACK frame ... causes the ECN state for the path to become "capable", unless no marked
        // packet has been acknowledged."
        if (path.state == .unknown and path.marked_acknowledged) path.state = .capable;
    }

    /// §13.4.2.2: "If validation fails, then the endpoint MUST disable ECN." No state leaves it.
    pub fn on_failed(path: *Path) void {
        path.state = .failed;
    }
};

test {
    _ = @import("recovery_ecn_test.zig");
}
