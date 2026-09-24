//! The tests of `recovery_ecn.zig`: RFC 9000 §13.4.2.1's checks, one case per sentence, and the
//! path's test of decision 69.
const std = @import("std");
const constants = @import("../constants.zig");
const frame_ack = @import("../frame/frame_ack.zig");
const recovery_sent = @import("recovery_sent.zig");
const recovery_ecn = @import("recovery_ecn.zig");

const testing = std.testing;
const EcnCounts = frame_ack.EcnCounts;
const Removed = recovery_sent.Removed;
const Verdict = recovery_ecn.Verdict;

var test_state: recovery_ecn.State = undefined;

/// What an ACK frame newly acknowledged, as the counts §13.4.2.1 reads off it.
fn acknowledged(ect_0: usize, ect_1: usize) Removed {
    var held = Removed.none();
    held.count = ect_0 + ect_1;
    held.ect_0 = ect_0;
    held.ect_1 = ect_1;
    return held;
}

fn counts_of(ect_0: u64, ect_1: u64, ecn_ce: u64) EcnCounts {
    return .{ .ect_0 = ect_0, .ect_1 = ect_1, .ecn_ce = ecn_ce };
}

/// Says this endpoint marked `ect_0` packets ECT(0) and `ect_1` packets ECT(1).
fn marked(ect_0: u64, ect_1: u64) void {
    test_state.init();
    for (0..ect_0) |_| test_state.on_packet_sent(.ect_0);
    for (0..ect_1) |_| test_state.on_packet_sent(.ect_1);
}

test "RFC 9000 §13.4: only the two ECT codepoints count as marked" {
    test_state.init();
    // §13.4 has a sender set ECT(0) or ECT(1); the network is what sets ECN-CE, and Not-ECT is
    // the absence of marking.
    test_state.on_packet_sent(.not_ect);
    test_state.on_packet_sent(.ecn_ce);
    try testing.expectEqual(0, test_state.sent_ect_0);
    try testing.expectEqual(0, test_state.sent_ect_1);
    test_state.on_packet_sent(.ect_0);
    test_state.on_packet_sent(.ect_1);
    try testing.expectEqual(1, test_state.sent_ect_0);
    try testing.expectEqual(1, test_state.sent_ect_1);
}

test "RFC 9000 §13.4.2.1: a frame that does not raise the largest acknowledged is not judged" {
    marked(0, 0);
    // "An endpoint MUST NOT fail ECN validation as a result of processing an ACK frame that does
    // not increase the largest acknowledged packet number." These counts would fail every check.
    const impossible = counts_of(9, 9, 9);
    try testing.expectEqual(Verdict.not_judged, recovery_ecn.validate(&test_state, impossible, acknowledged(1, 1), false));
}

test "RFC 9000 §13.4.2.1: a marked packet acknowledged without counts fails" {
    marked(1, 0);
    // "If an ACK frame newly acknowledges a packet that the endpoint sent with either the ECT(0)
    // or ECT(1) codepoint set, ECN validation fails if the corresponding ECN counts are not
    // present in the ACK frame."
    try testing.expectEqual(Verdict.failed, recovery_ecn.validate(&test_state, null, acknowledged(1, 0), true));
    marked(0, 1);
    try testing.expectEqual(Verdict.failed, recovery_ecn.validate(&test_state, null, acknowledged(0, 1), true));
    // A frame with no counts that acknowledged nothing marked asks nothing of them.
    marked(0, 0);
    try testing.expectEqual(Verdict.passed, recovery_ecn.validate(&test_state, null, acknowledged(0, 0), true));
}

test "RFC 9000 §13.4.2.1: a count above what this endpoint marked fails" {
    marked(1, 0);
    // "validation will fail when an endpoint receives a non-zero ECN count corresponding to an
    // ECT codepoint that it never applied."
    try testing.expectEqual(Verdict.failed, recovery_ecn.validate(&test_state, counts_of(1, 1, 0), acknowledged(1, 0), true));
    // "ECN validation can fail if the received total count for either ECT(0) or ECT(1) exceeds
    // the total number of packets sent with each corresponding ECT codepoint."
    try testing.expectEqual(Verdict.failed, recovery_ecn.validate(&test_state, counts_of(2, 0, 0), acknowledged(1, 0), true));
    // The total it did mark is believable.
    try testing.expectEqual(Verdict.passed, recovery_ecn.validate(&test_state, counts_of(1, 0, 0), acknowledged(1, 0), true));
}

test "RFC 9000 §13.4.2.1: an increase smaller than what was newly acknowledged fails" {
    marked(2, 0);
    // "ECN validation also fails if the sum of the increase in ECT(0) and ECN-CE counts is less
    // than the number of newly acknowledged packets that were originally sent with an ECT(0)
    // marking." Two were acknowledged and the counts rose by one.
    try testing.expectEqual(Verdict.failed, recovery_ecn.validate(&test_state, counts_of(1, 0, 0), acknowledged(2, 0), true));
    // The rise in ECN-CE counts toward it: a packet marked ECT(0) that arrived ECN-CE raises the
    // one count and not the other.
    try testing.expectEqual(Verdict.passed, recovery_ecn.validate(&test_state, counts_of(1, 0, 1), acknowledged(2, 0), true));

    // "Similarly, ECN validation fails if the sum of the increases to ECT(1) and ECN-CE counts is
    // less than the number of newly acknowledged packets sent with an ECT(1) marking."
    marked(0, 2);
    try testing.expectEqual(Verdict.failed, recovery_ecn.validate(&test_state, counts_of(0, 1, 0), acknowledged(0, 2), true));
    try testing.expectEqual(Verdict.passed, recovery_ecn.validate(&test_state, counts_of(0, 1, 1), acknowledged(0, 2), true));
}

test "RFC 9000 §13.4.2.1: the increase is measured from the last frame that passed" {
    marked(4, 0);
    const first = counts_of(2, 0, 0);
    try testing.expectEqual(Verdict.passed, recovery_ecn.validate(&test_state, first, acknowledged(2, 0), true));
    test_state.accept(first);
    // "It performs this validation by comparing newly received counts against those from the last
    // successfully processed ACK frame", so a total that did not move is no increase at all.
    try testing.expectEqual(Verdict.failed, recovery_ecn.validate(&test_state, first, acknowledged(2, 0), true));
    try testing.expectEqual(Verdict.passed, recovery_ecn.validate(&test_state, counts_of(4, 0, 0), acknowledged(2, 0), true));
}

test "RFC 9000 §13.4.2.1: counts larger than what was acknowledged are permitted" {
    marked(4, 0);
    // "It is therefore possible for the total increase in ECT(0), ECT(1), and ECN-CE counts to be
    // greater than the number of packets that are newly acknowledged by an ACK frame. This is why
    // ECN counts are permitted to be larger than the total number of packets that are
    // acknowledged."
    try testing.expectEqual(Verdict.passed, recovery_ecn.validate(&test_state, counts_of(4, 0, 0), acknowledged(1, 0), true));
}

var test_path: recovery_ecn.Path = undefined;

/// A Probe Timeout the path tests use, and the instant their first marked packet goes out.
/// Test-only.
const test_probe_timeout_ns: u64 = 1_000_000_000;
const test_start_ns: u64 = 5_000;

/// Sends `count` marked packets at `now_ns`, each after asking whether it may mark. Test-only.
fn send_marked(count: u64, now_ns: u64) !void {
    for (0..count) |_| {
        try testing.expect(test_path.marks(now_ns, test_probe_timeout_ns));
        test_path.on_marked_sent(now_ns);
    }
}

test "decision 69: the test ends after ten marked packets, and the path marks again once one is acknowledged" {
    test_path.init();
    try send_marked(constants.ecn_testing_packets, test_start_ns);
    // RFC 9000 Appendix A.4: past the test the path is unknown, which sends unmarked packets.
    try testing.expect(!test_path.marks(test_start_ns, test_probe_timeout_ns));
    try testing.expectEqual(recovery_ecn.PathState.unknown, test_path.state);
    // "unless no marked packet has been acknowledged": a frame that passed and acknowledged no
    // marked packet leaves the path unknown.
    test_path.on_passed(0);
    try testing.expect(!test_path.marks(test_start_ns, test_probe_timeout_ns));
    test_path.on_passed(1);
    try testing.expectEqual(recovery_ecn.PathState.capable, test_path.state);
    try testing.expect(test_path.marks(test_start_ns, test_probe_timeout_ns));
}

test "decision 69: the test ends three PTOs after the first marked packet" {
    test_path.init();
    // No marked packet has gone out, so no period has started, however late the first one is.
    try testing.expect(test_path.marks(test_start_ns, test_probe_timeout_ns));
    try send_marked(1, test_start_ns);
    const end_ns = test_start_ns + constants.ecn_testing_probe_timeouts * test_probe_timeout_ns;
    try testing.expect(test_path.marks(end_ns - 1, test_probe_timeout_ns));
    try testing.expect(!test_path.marks(end_ns, test_probe_timeout_ns));
}

test "decision 69: a marked packet acknowledged during the test makes the path capable at the next frame that passes" {
    test_path.init();
    try send_marked(1, test_start_ns);
    test_path.on_passed(1);
    // Still testing: Appendix A.4 makes a path capable from unknown, which comes after the test.
    try testing.expectEqual(recovery_ecn.PathState.testing, test_path.state);
    try send_marked(constants.ecn_testing_packets - 1, test_start_ns);
    try testing.expect(!test_path.marks(test_start_ns, test_probe_timeout_ns));
    test_path.on_passed(0);
    try testing.expect(test_path.marks(test_start_ns, test_probe_timeout_ns));
}

test "RFC 9000 §13.4.2.2: a failed path never marks again" {
    test_path.init();
    try send_marked(constants.ecn_testing_packets, test_start_ns);
    try testing.expect(!test_path.marks(test_start_ns, test_probe_timeout_ns));
    test_path.on_passed(1);
    try testing.expect(test_path.marks(test_start_ns, test_probe_timeout_ns));
    test_path.on_failed();
    try testing.expect(!test_path.marks(test_start_ns, test_probe_timeout_ns));
    test_path.on_passed(1);
    try testing.expect(!test_path.marks(test_start_ns, test_probe_timeout_ns));
}
