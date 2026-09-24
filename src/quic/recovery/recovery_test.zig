//! The five entry points of RFC 9002 driven together (design §8 step 10). The pieces are tested
//! where they live; this covers what only shows when they are wired up: an acknowledgment that
//! measures the path, grows the window and reveals loss in one pass, and the timer that follows.
const std = @import("std");
const constants = @import("../constants.zig");
const space = @import("../space/space.zig");
const frame_ack = @import("../frame/frame_ack.zig");
const recovery = @import("recovery.zig");
const recovery_ack = @import("recovery_ack.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_sent = @import("recovery_sent.zig");

const Kind = space.Kind;
const Record = recovery_sent.Record;
const testing = std.testing;

/// The recovery state the tests drive, and room for everything one pass can acknowledge or
/// declare lost.
var test_recovery: recovery.Recovery = undefined;
var test_acknowledged: [constants.sent_packets_max]Record = undefined;
var test_lost: [constants.sent_packets_max]Record = undefined;
/// A path of 1200-octet datagrams. Every instant is written whole in nanoseconds, because the
/// magic-numbers rule reads a constant's whole value.
const test_datagram_len: u16 = 1_200;
const test_start_ns: u64 = 1_000_000_000;
const test_round_trip_ns: u64 = 100_000_000;
/// Far enough past any send that the time threshold of §6.1.2 reaches every packet.
const test_long_after_ns: u64 = 100_000_000_000;

fn eliciting(number: u64, sent_at_ns: u64) Record {
    return .{
        .number = number,
        .sent_at_ns = sent_at_ns,
        .sent_len = test_datagram_len,
        .ack_eliciting = true,
        .in_flight = true,
    };
}

/// One ACK range, from `smallest` to `largest` inclusive, with no ECN section. Test-only.
fn one_range(smallest: u64, largest: u64) frame_ack.AckRanges {
    return .{
        .largest_acknowledged = largest,
        .first_range = largest - smallest,
        .octets = &.{},
        .count = 0,
    };
}

fn ack_of(smallest: u64, largest: u64) recovery_ack.Ack {
    return .{ .ranges = one_range(smallest, largest), .delay_ns = 0, .ecn = null };
}

/// Sends `count` ack-eliciting packets `interval_ns` apart from `from_ns`, numbered from
/// `first`. The instants must not go backwards across calls, because the pacer is one for the
/// connection and refilling it at an earlier instant is the caller's own error. Test-only.
fn send(kind: Kind, first: u64, count: u64, from_ns: u64, interval_ns: u64) !void {
    for (0..count) |step| {
        const at_ns = from_ns + step * interval_ns;
        try test_recovery.on_packet_sent(kind, eliciting(first + step, at_ns), at_ns);
    }
}

/// A packet carrying only PADDING: RFC 9002 §2 counts it toward the octets in flight but the
/// peer owes no acknowledgment for it. Test-only.
fn padding_only(number: u64, sent_at_ns: u64) Record {
    var held = eliciting(number, sent_at_ns);
    held.ack_eliciting = false;
    return held;
}

/// The common case: `count` packets one round trip apart from the start, numbered from zero.
fn send_spaced(kind: Kind, count: u64) !void {
    try send(kind, 0, count, test_start_ns, test_round_trip_ns);
}

/// Sends `count` packets the caller marked ECT(0) (RFC 9000 §13.4), which is what makes the
/// peer's ECT(0) count believable under §13.4.2.1. Test-only.
fn send_marked(kind: Kind, first: u64, count: u64, from_ns: u64) !void {
    for (0..count) |step| {
        const at_ns = from_ns + step * test_round_trip_ns;
        var record = eliciting(first + step, at_ns);
        record.ecn = .ect_0;
        try test_recovery.on_packet_sent(kind, record, at_ns);
    }
}

test "A.5: a sent packet is outstanding, counted and paced" {
    test_recovery.init(test_datagram_len);
    const window = test_recovery.congestion.window;
    try testing.expectEqual(0, test_recovery.in_flight_len());
    try send_spaced(.application, 3);
    // The octets in flight are the sum over the spaces, held in no second place.
    try testing.expectEqual(3 * test_datagram_len, test_recovery.in_flight_len());
    try testing.expectEqual(window - 3 * test_datagram_len, test_recovery.congestion.available_len(test_recovery.in_flight_len()));
    // RFC 9002 Appendix A.8 arms a probe for a space with something outstanding, measured from
    // the last packet the peer must acknowledge.
    const held = test_recovery.timer.spaces[@intFromEnum(Kind.application)];
    try testing.expect(held.ack_eliciting_in_flight);
    try testing.expectEqual(test_start_ns + 2 * test_round_trip_ns, held.last_ack_eliciting_sent_at_ns);
    // RFC 9002 places no bound on `sent_packets`; colibri's is named and fails closed.
    const filled_at_ns = test_start_ns + 2 * test_round_trip_ns;
    try send(.application, 3, constants.sent_packets_max - 3, filled_at_ns, 0);
    const past_it = eliciting(constants.sent_packets_max, filled_at_ns);
    try testing.expectError(recovery.Error.Full, test_recovery.on_packet_sent(.application, past_it, filled_at_ns));
}

test "A.7: an acknowledgment measures the path, takes packets out and grows the window" {
    test_recovery.init(test_datagram_len);
    test_recovery.timer.handshake_confirmed = true;
    try send_spaced(.application, 2);
    const window = test_recovery.congestion.window;
    // The ACK names both, and the largest is newly acknowledged, so §5.1 takes one sample.
    const at_ns = test_start_ns + test_round_trip_ns + test_round_trip_ns / 2;
    const outcome = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 1), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(2, outcome.acknowledged);
    try testing.expectEqual(2 * test_datagram_len, outcome.in_flight_len);
    try testing.expect(outcome.rtt_sampled);
    try testing.expectEqual(test_round_trip_ns / 2, test_recovery.rtt.smoothed_ns);
    try testing.expectEqual(0, test_recovery.in_flight_len());
    // RFC 9002 §7.3.1: in slow start the window grows by what was acknowledged.
    try testing.expectEqual(window + 2 * test_datagram_len, test_recovery.congestion.window);
    // RFC 9002 Appendix A.8: with nothing outstanding and the address validated, no timer.
    try testing.expect(!test_recovery.timer.spaces[@intFromEnum(Kind.application)].ack_eliciting_in_flight);
    test_recovery.timer.peer_completed_address_validation = true;
    try testing.expectEqual(null, test_recovery.next_timer());
}

test "§5.1: a repeated acknowledgment measures nothing" {
    test_recovery.init(test_datagram_len);
    try send_spaced(.application, 2);
    const at_ns = test_start_ns + test_round_trip_ns * 2;
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 1), .full, at_ns, &test_acknowledged, &test_lost);
    const smoothed_ns = test_recovery.rtt.smoothed_ns;
    // The same frame again names nothing the table still holds, so §5.1 has nothing to measure
    // and the estimate does not move.
    const again = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 1), .full, at_ns + 1, &test_acknowledged, &test_lost);
    try testing.expectEqual(0, again.acknowledged);
    try testing.expect(!again.rtt_sampled);
    try testing.expectEqual(smoothed_ns, test_recovery.rtt.smoothed_ns);
    // RFC 9002 Appendix A.7: the largest acknowledged only rises, so an older frame does not
    // lower it and cannot make an outstanding packet look acknowledged.
    try testing.expectEqual(1, test_recovery.largest_acknowledged[@intFromEnum(Kind.application)]);
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 0), .full, at_ns + 2, &test_acknowledged, &test_lost);
    try testing.expectEqual(1, test_recovery.largest_acknowledged[@intFromEnum(Kind.application)]);
    // RFC 9002 Appendix A.7 returns where nothing was newly acknowledged, so a repeat carrying a
    // higher ECN-CE count is not a congestion event either: the frame says nothing new. RFC 9000
    // §13.4.2.1 would not judge it anyway, because it does not raise the largest acknowledged.
    const window = test_recovery.congestion.window;
    var marked = ack_of(0, 1);
    marked.ecn = .{ .ect_0 = 2, .ect_1 = 0, .ecn_ce = 9 };
    _ = recovery_ack.on_ack_received(&test_recovery, .application, marked, .full, at_ns + 3, &test_acknowledged, &test_lost);
    try testing.expectEqual(window, test_recovery.congestion.window);
    try testing.expectEqual(0, test_recovery.ecn[@intFromEnum(Kind.application)].reported.ecn_ce);
}

test "§5.1: a sample needs the largest named and an ack-eliciting packet" {
    test_recovery.init(test_datagram_len);
    try send_spaced(.application, 3);
    // The frame names 2 as its largest but 2 is not in the table, because it was acknowledged
    // before. What is newly acknowledged is older, so §5.1 refuses the sample.
    _ = test_recovery.table_of(.application).remove_range(2, 2);
    const at_ns = test_start_ns + test_round_trip_ns * 4;
    const stale = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 2), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(2, stale.acknowledged);
    try testing.expect(!stale.rtt_sampled);
    try testing.expect(!test_recovery.rtt.has_sample());
    // A packet carrying only ACK frames is not ack-eliciting, so acknowledging one alone
    // measures nothing either.
    test_recovery.init(test_datagram_len);
    var quiet = eliciting(0, test_start_ns);
    quiet.ack_eliciting = false;
    quiet.in_flight = false;
    try test_recovery.on_packet_sent(.application, quiet, test_start_ns);
    const silent = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 0), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(1, silent.acknowledged);
    try testing.expect(!silent.rtt_sampled);
}

test "A.7: an acknowledgment that reveals loss halves the window" {
    test_recovery.init(test_datagram_len);
    try send_spaced(.application, 5);
    const window = test_recovery.congestion.window;
    // The peer acknowledges 4 alone. RFC 9002 §6.1.1's threshold reaches 0 and 1, and §6.1.2's
    // reaches the rest, because every one went out a round trip apart.
    const at_ns = test_start_ns + test_round_trip_ns * 5;
    const outcome = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(4, 4), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(1, outcome.acknowledged);
    try testing.expectEqual(4, outcome.lost.count);
    try testing.expectEqual(4 * test_datagram_len, outcome.lost.in_flight_len);
    try testing.expectEqual(0, test_recovery.in_flight_len());
    // RFC 9002 Appendix B.8: losing packets in flight is a congestion event, and B.6 halves the
    // window. The acknowledged packet does not grow it, because it went out before the period.
    try testing.expectEqual(window / 2, test_recovery.congestion.window);
    try testing.expectEqual(window / 2, test_recovery.congestion.slow_start_threshold);
    try testing.expectEqual(at_ns, test_recovery.congestion.recovery_started_at_ns);
}

test "B.7: a rise in the peer's ECN-CE count is a congestion event" {
    test_recovery.init(test_datagram_len);
    // RFC 9000 §13.4.2.1 measures the peer's counts against what this endpoint marked, so the
    // packets go out ECT(0) and the counts that come back are ones it could have produced.
    try send_marked(.application, 0, 2, test_start_ns);
    const window = test_recovery.congestion.window;
    const at_ns = test_start_ns + test_round_trip_ns * 2;
    var marked = ack_of(0, 1);
    marked.ecn = .{ .ect_0 = 2, .ect_1 = 0, .ecn_ce = 1 };
    _ = recovery_ack.on_ack_received(&test_recovery, .application, marked, .full, at_ns, &test_acknowledged, &test_lost);
    // RFC 9002 Appendix B.7: the path reported congestion without dropping anything, and the
    // window halves for it just as it would for loss.
    try testing.expectEqual(window / 2, test_recovery.congestion.window);
    try testing.expectEqual(1, test_recovery.ecn[@intFromEnum(Kind.application)].reported.ecn_ce);
    // A count that has not risen is not a second event.
    try send_marked(.application, 2, 2, at_ns);
    const halved = test_recovery.congestion.window;
    var repeated = ack_of(2, 3);
    repeated.ecn = .{ .ect_0 = 4, .ect_1 = 0, .ecn_ce = 1 };
    _ = recovery_ack.on_ack_received(&test_recovery, .application, repeated, .full, at_ns + 2 * test_round_trip_ns, &test_acknowledged, &test_lost);
    try testing.expect(test_recovery.congestion.window >= halved);
    try testing.expectEqual(at_ns, test_recovery.congestion.recovery_started_at_ns);
}

test "A.9: a probe timeout asks for two packets and backs the next one off" {
    test_recovery.init(test_datagram_len);
    test_recovery.timer.handshake_confirmed = true;
    test_recovery.timer.peer_completed_address_validation = true;
    try send_spaced(.application, 1);
    const timer = test_recovery.next_timer().?;
    try testing.expectEqual(.probe, timer.mode);
    try testing.expectEqual(Kind.application, timer.space);
    const action = test_recovery.on_timeout(timer.at_ns, &test_lost);
    try testing.expectEqual(constants.probe_packets, action.probe.count);
    try testing.expectEqual(Kind.application, action.probe.space);
    try testing.expectEqual(1, test_recovery.timer.pto_count);
    // RFC 9002 §6.2.1: the next timeout is twice as far out.
    const backed_off = test_recovery.next_timer().?;
    try testing.expectEqual(timer.at_ns - test_start_ns, (backed_off.at_ns - test_start_ns) / 2);
    // The packet is still outstanding, so the probe did not take it out of flight.
    try testing.expectEqual(test_datagram_len, test_recovery.in_flight_len());
}

test "A.9: a loss timeout declares the packet lost and rearms" {
    test_recovery.init(test_datagram_len);
    test_recovery.timer.handshake_confirmed = true;
    // Ten milliseconds apart, so one round trip later the time threshold of §6.1.2 — nine
    // eighths of 100 ms — reaches 0 and spares 1, and §6.1.1's count of three reaches neither.
    const test_close_ns: u64 = 10_000_000;
    try send(.application, 0, 3, test_start_ns, test_close_ns);
    const at_ns = test_start_ns + 2 * test_close_ns + test_round_trip_ns;
    const outcome = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(2, 2), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(1, outcome.lost.count);
    const timer = test_recovery.next_timer().?;
    try testing.expectEqual(.loss, timer.mode);
    try testing.expectEqual(outcome.lost.loss_time_ns, timer.at_ns);
    // At that instant the survivor is old enough, and the timer has nothing left to arm.
    const action = test_recovery.on_timeout(timer.at_ns, &test_lost);
    try testing.expectEqual(1, action.lost.found.count);
    try testing.expectEqual(Kind.application, action.lost.space);
    try testing.expectEqual(1, test_lost[0].number);
    try testing.expectEqual(0, test_recovery.in_flight_len());
    try testing.expectEqual(null, test_recovery.timer.spaces[@intFromEnum(Kind.application)].loss_time_ns);
}

test "§7.6: a long enough span of loss puts the window back to the minimum" {
    test_recovery.init(test_datagram_len);
    test_recovery.timer.handshake_confirmed = true;
    // One round trip sample first, because §7.6.2 counts only packets sent after it.
    try send_spaced(.initial, 1);
    _ = recovery_ack.on_ack_received(&test_recovery, .initial, ack_of(0, 0), .full, test_start_ns + test_round_trip_ns, &test_acknowledged, &test_lost);
    try testing.expect(test_recovery.rtt.has_sample());
    // Then a run of ack-eliciting packets a round trip apart, every one of them lost. Sixteen
    // of them span fifteen round trips, which is past §7.6.1's three Probe Timeouts.
    const run: u64 = 16;
    try send(.application, 0, run, test_start_ns + 2 * test_round_trip_ns, test_round_trip_ns);
    // One more far later, whose acknowledgment is what reveals the rest as lost.
    try send(.application, run, 1, test_long_after_ns, 0);
    const at_ns = test_long_after_ns + test_round_trip_ns;
    const outcome = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(run, run), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(run, outcome.lost.count);
    try testing.expect(outcome.lost.is_persistent_congestion(test_recovery.rtt.persistent_congestion_ns()));
    // RFC 9002 Appendix B.8 puts the window at the minimum and ends the recovery period, and
    // Appendix A.7 then runs `OnPacketsAcked` over what this same frame acknowledged. With no
    // period left to hold it, that packet grows the minimum window by its own octets — which is
    // what the two texts say together, so it is pinned rather than hidden.
    try testing.expectEqual(null, test_recovery.congestion.recovery_started_at_ns);
    try testing.expectEqual(test_recovery.congestion.minimum_window() + test_datagram_len, test_recovery.congestion.window);
    // Without that last acknowledgment the window is the minimum and nothing else.
    try testing.expectEqual(test_recovery.congestion.minimum_window(), test_recovery.congestion.window - test_datagram_len);
}

test "A.11: discarding a space gives up its packets and what it armed" {
    test_recovery.init(test_datagram_len);
    try send_spaced(.initial, 2);
    try send(.handshake, 0, 1, test_start_ns + 2 * test_round_trip_ns, 0);
    test_recovery.timer.pto_count = 3;
    try testing.expectEqual(3 * test_datagram_len, test_recovery.in_flight_len());
    test_recovery.discard_space(.initial);
    // RFC 9002 Appendix A.11: they are neither acknowledged nor lost; they stop counting.
    try testing.expectEqual(test_datagram_len, test_recovery.in_flight_len());
    try testing.expect(!test_recovery.timer.spaces[@intFromEnum(Kind.initial)].ack_eliciting_in_flight);
    try testing.expectEqual(null, test_recovery.largest_acknowledged[@intFromEnum(Kind.initial)]);
    try testing.expectEqual(0, test_recovery.timer.pto_count);
    // The other space is untouched.
    try testing.expect(test_recovery.timer.spaces[@intFromEnum(Kind.handshake)].ack_eliciting_in_flight);
}

test "A.6: a datagram lifts the anti-amplification limit" {
    test_recovery.init(test_datagram_len);
    try send_spaced(.initial, 1);
    test_recovery.timer.at_anti_amplification_limit = true;
    // RFC 9002 Appendix A.8: a server that may send nothing sets no timer.
    try testing.expectEqual(null, test_recovery.next_timer());
    test_recovery.on_datagram_received();
    try testing.expect(test_recovery.next_timer() != null);
}

test "§7.7: what may go out is the smaller of the window and what the pacer has earned" {
    test_recovery.init(test_datagram_len);
    const burst = test_recovery.pacer.credit_len;
    // A fresh pacer holds the burst, and the window starts the same size, so neither binds yet.
    try testing.expectEqual(burst, test_recovery.available_len());
    // A window wider than the burst leaves the pacer as what binds, which is §7.7's whole point:
    // the window says how much may be outstanding, not how fast it may leave.
    test_recovery.congestion.window = 4 * burst;
    try testing.expectEqual(burst, test_recovery.available_len());
    // Sending spends the pacer, and what may go out falls with it rather than with the window.
    try send_spaced(.application, 1);
    try testing.expectEqual(burst - test_datagram_len, test_recovery.available_len());
    try testing.expect(test_recovery.congestion.available_len(test_recovery.in_flight_len()) > test_recovery.available_len());
}

test "A.8: a space holding only PADDING owes no acknowledgment and arms no probe" {
    test_recovery.init(test_datagram_len);
    test_recovery.timer.handshake_confirmed = true;
    test_recovery.timer.peer_completed_address_validation = true;
    try test_recovery.on_packet_sent(.application, padding_only(0, test_start_ns), test_start_ns);
    // RFC 9002 §2: it counts toward the octets in flight, so the congestion window feels it.
    try testing.expectEqual(test_datagram_len, test_recovery.in_flight_len());
    // But the peer owes nothing for it, so RFC 9002 Appendix A.8 arms no Probe Timeout.
    try testing.expect(!test_recovery.timer.spaces[@intFromEnum(Kind.application)].ack_eliciting_in_flight);
    try testing.expectEqual(null, test_recovery.next_timer());
    // One ack-eliciting packet beside it does arm one.
    try test_recovery.on_packet_sent(.application, eliciting(1, test_start_ns), test_start_ns);
    try testing.expect(test_recovery.timer.spaces[@intFromEnum(Kind.application)].ack_eliciting_in_flight);
    try testing.expect(test_recovery.next_timer() != null);
}

test "A.9: with nothing outstanding the probe is the single anti-deadlock packet" {
    test_recovery.init(test_datagram_len);
    // RFC 9002 Appendix A.8: a client whose address the server has not validated arms a probe
    // even with nothing outstanding, and Appendix A.9 sends one packet rather than two. A padded
    // packet that elicits nothing is what sets the timer (Appendix A.5), and it is counted from.
    try test_recovery.on_packet_sent(.handshake, padding_only(0, test_start_ns), test_start_ns);
    const timer = test_recovery.next_timer().?;
    try testing.expectEqual(test_start_ns + test_recovery.rtt.probe_timeout_ns(false), timer.at_ns);
    try testing.expectEqual(.probe, timer.mode);
    try testing.expectEqual(Kind.initial, timer.space);
    const action = test_recovery.on_timeout(timer.at_ns, &test_lost);
    try testing.expectEqual(1, action.probe.count);
    try testing.expectEqual(Kind.initial, action.probe.space);
    // RFC 9002 Appendix A.9 sets the timer again as it goes off, and §6.2.1 doubles the period.
    const again = test_recovery.next_timer().?;
    try testing.expectEqual(timer.at_ns + 2 * test_recovery.rtt.probe_timeout_ns(false), again.at_ns);
    // With something outstanding it is the two of a real Probe Timeout.
    try send_spaced(.initial, 1);
    const armed = test_recovery.next_timer().?;
    try testing.expectEqual(constants.probe_packets, test_recovery.on_timeout(armed.at_ns, &test_lost).probe.count);
}

test "A.7: an acknowledgment sets the timer again, which the anti-deadlock probe counts from" {
    test_recovery.init(test_datagram_len);
    try send_spaced(.initial, 1);
    const at_ns = test_start_ns + test_round_trip_ns;
    _ = recovery_ack.on_ack_received(&test_recovery, .initial, ack_of(0, 0), .full, at_ns, &test_acknowledged, &test_lost);
    // Nothing is outstanding and the address is not validated, so this is the anti-deadlock probe.
    const timer = test_recovery.next_timer().?;
    try testing.expectEqual(at_ns + test_recovery.rtt.probe_timeout_ns(false), timer.at_ns);
}

test "A.7: the backoff starts again only once the peer has validated the address" {
    test_recovery.init(test_datagram_len);
    try send_spaced(.initial, 2);
    test_recovery.timer.pto_count = 3;
    const at_ns = test_start_ns + 2 * test_round_trip_ns;
    // RFC 9002 Appendix A.7: a client unsure whether the server has validated its address keeps
    // its backoff, because an answered probe is not yet evidence the path will answer again.
    _ = recovery_ack.on_ack_received(&test_recovery, .initial, ack_of(0, 0), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(3, test_recovery.timer.pto_count);
    test_recovery.timer.peer_completed_address_validation = true;
    _ = recovery_ack.on_ack_received(&test_recovery, .initial, ack_of(1, 1), .full, at_ns + 1, &test_acknowledged, &test_lost);
    try testing.expectEqual(0, test_recovery.timer.pto_count);
}

test "RFC 9000 §13.4.2.2: validation failing disables ECN and takes no counts" {
    test_recovery.init(test_datagram_len);
    try send_marked(.application, 0, 2, test_start_ns);
    try testing.expect(test_recovery.ecn_permitted());
    const at_ns = test_start_ns + test_round_trip_ns * 2;
    const window = test_recovery.congestion.window;

    // §13.4.2.1: a count for ECT(1), "an ECT codepoint that it never applied".
    var forged = ack_of(0, 1);
    forged.ecn = .{ .ect_0 = 2, .ect_1 = 1, .ecn_ce = 0 };
    _ = recovery_ack.on_ack_received(&test_recovery, .application, forged, .full, at_ns, &test_acknowledged, &test_lost);
    // §13.4.2.2: "If validation fails, then the endpoint MUST disable ECN."
    try testing.expect(!test_recovery.ecn_permitted());
    // §13.4.2.1 validates "before using them", so a frame that failed leaves nothing behind and
    // RFC 9002 Appendix B.7's congestion event does not follow from counts nobody believed.
    try testing.expectEqual(0, test_recovery.ecn[@intFromEnum(Kind.application)].reported.ect_0);
    try testing.expect(test_recovery.congestion.window >= window);
}

test "RFC 9000 §13.4.2.1: an increase smaller than the packets acknowledged fails" {
    test_recovery.init(test_datagram_len);
    try send_marked(.application, 0, 2, test_start_ns);
    const at_ns = test_start_ns + test_round_trip_ns * 2;

    // Two packets marked ECT(0) are newly acknowledged and the counts rose by one, which is
    // "the sum of the increase in ECT(0) and ECN-CE counts ... less than the number of newly
    // acknowledged packets that were originally sent with an ECT(0) marking".
    var short = ack_of(0, 1);
    short.ecn = .{ .ect_0 = 1, .ect_1 = 0, .ecn_ce = 0 };
    _ = recovery_ack.on_ack_received(&test_recovery, .application, short, .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expect(!test_recovery.ecn_permitted());
}

/// RFC 9000 §19.3.1 encodes each range after the first as a gap and a length, where
/// `largest = previous_smallest - gap - 2`. These two octets name one more range at zero.
const two_range_gap: u8 = 1;
const two_range_len: u8 = 0;
const two_range_octets = [_]u8{ two_range_gap, two_range_len };

/// An ACK naming `largest` on its own and zero on its own, in two ranges. Test-only.
fn ack_of_two(largest: u64) recovery_ack.Ack {
    return .{
        .ranges = .{
            .largest_acknowledged = largest,
            .first_range = 0,
            .octets = &two_range_octets,
            .count = 1,
        },
        .delay_ns = 0,
        .ecn = null,
    };
}

test "RFC 9000 §13.4.2.1: the markings are counted over the frame, not over one range" {
    test_recovery.init(test_datagram_len);
    try send_marked(.application, 0, 4, test_start_ns);
    const at_ns = test_start_ns + test_round_trip_ns * 4;

    // Two ranges, each naming one packet marked ECT(0), so the frame newly acknowledges two of
    // them. A count that rose by one is less than that, which §13.4.2.1 fails.
    var short = ack_of_two(3);
    short.ecn = .{ .ect_0 = 1, .ect_1 = 0, .ecn_ce = 0 };
    _ = recovery_ack.on_ack_received(&test_recovery, .application, short, .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expect(!test_recovery.ecn_permitted());
}

test "decision 66: a PTO takes the oldest ack-eliciting packets in flight, and no more" {
    test_recovery.init(test_datagram_len);
    // A packet of PADDING alone first, which carries nothing a probe could send again.
    try test_recovery.on_packet_sent(.application, padding_only(0, test_start_ns), test_start_ns);
    try send(.application, 1, 3, test_start_ns, test_round_trip_ns);
    const window = test_recovery.congestion.window;
    const taken = test_recovery.declare_oldest_lost(.application, constants.probe_packets, &test_lost);
    try testing.expectEqual(constants.probe_packets, taken);
    try testing.expectEqual(1, test_lost[0].number);
    try testing.expectEqual(2, test_lost[1].number);
    // The newest and the PADDING stay, and the timer still waits on the newest.
    const table = test_recovery.table_of(.application);
    try testing.expectEqual(2, table.count());
    try testing.expect(table.remove(3) != null);
    try testing.expect(test_recovery.timer.spaces[@intFromEnum(Kind.application)].ack_eliciting_in_flight);
    // RFC 9002 §6.2.4 names "an unnecessary rate reduction" as the risk, and colibri takes none.
    try testing.expectEqual(window, test_recovery.congestion.window);
}

test "decision 66: with every ack-eliciting packet taken, the timer waits on none" {
    test_recovery.init(test_datagram_len);
    try send(.application, 0, 1, test_start_ns, test_round_trip_ns);
    try testing.expectEqual(1, test_recovery.declare_oldest_lost(.application, constants.probe_packets, &test_lost));
    try testing.expect(!test_recovery.timer.spaces[@intFromEnum(Kind.application)].ack_eliciting_in_flight);
    try testing.expectEqual(0, test_recovery.in_flight_len());
}
