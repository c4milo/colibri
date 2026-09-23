//! The one loss detection timer of RFC 9002 Appendix A.8, and the Probe Timeout of §6.2 it falls
//! back to. Part of design §8 step 10.
//!
//! QUIC runs one timer for all of loss detection, and what it means depends on what is
//! outstanding. If any space has a packet that will age into loss, the timer is that instant and
//! its expiry declares the packet lost. Otherwise it is the Probe Timeout: the point at which an
//! endpoint that has heard nothing sends something to make the peer acknowledge, which is how a
//! tail of lost packets is discovered when no later acknowledgment will arrive to reveal it.
//!
//! Choosing the timer is a pure function of what the spaces hold, so it is written as one. It
//! takes no clock (non-negotiable 3) and holds nothing: `recovery.zig` keeps the state and hands
//! it over.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const rtt_estimator = @import("../rtt.zig");
const space = @import("../space/space.zig");

const Rtt = rtt_estimator.Rtt;
const Kind = space.Kind;

/// Why the timer is set (RFC 9002 Appendix A.9 branches on it).
pub const Mode = enum {
    /// RFC 9002 §6.1.2: a packet will be old enough to declare lost at this instant.
    loss,
    /// RFC 9002 §6.2: nothing more will be learned by waiting, so send something that must be
    /// acknowledged.
    probe,
};

pub const Timer = struct {
    at_ns: u64,
    mode: Mode,
    /// Which space the timer is for. Appendix A.9 acts on that space alone.
    space: Kind,
};

/// What one packet number space contributes (RFC 9002 Appendix A.3).
pub const SpaceState = struct {
    /// `loss_time[space]`: when the oldest packet that survived the last detection pass becomes
    /// old enough to be declared lost, or null when none survived.
    loss_time_ns: ?u64 = null,
    /// `time_of_last_ack_eliciting_packet[space]`: when this endpoint last sent a packet in this
    /// space that the peer must acknowledge, or null when it has sent none.
    last_ack_eliciting_sent_at_ns: ?u64 = null,
    /// Whether any ack-eliciting packet is still outstanding in this space, which is what the
    /// Probe Timeout is armed against.
    ack_eliciting_in_flight: bool = false,
};

/// Everything Appendix A.8 reads outside the round trip estimator.
pub const State = struct {
    spaces: [constants.packet_number_spaces]SpaceState,
    /// RFC 9002 Appendix A.3's `pto_count`: how many probes have been sent without hearing back.
    pto_count: u6 = 0,
    /// RFC 9001 §4.1.2: whether the handshake is confirmed, which is what lets the Application
    /// Data space arm a probe at all.
    handshake_confirmed: bool = false,
    /// Whether this endpoint holds Handshake keys, which decides which space an anti-deadlock
    /// probe goes in.
    has_handshake_keys: bool = false,
    /// RFC 9002 Appendix A.8's `PeerCompletedAddressValidation`. A client assumes a server
    /// validates implicitly; a server has validated once it has received a Handshake
    /// acknowledgment or the handshake is confirmed.
    peer_completed_address_validation: bool = false,
    /// RFC 9000 §8.1: whether this endpoint may send nothing more until it receives more. A
    /// timer would only fire on something it cannot answer, so none is set.
    at_anti_amplification_limit: bool = false,
    /// The instant RFC 9002 Appendix A.8's `SetLossDetectionTimer` last ran: when a packet in
    /// flight was sent (A.5), an acknowledgment took packets out (A.7), or the timer went off
    /// (A.9). The anti-deadlock probe counts from it ("Anti-deadlock PTO starts from the current
    /// time"). colibri answers the timer whenever asked, and an instant read at each question
    /// would move the probe later every time. Null until the first of them.
    armed_at_ns: ?u64 = null,
};

/// The instant the timer should next fire, or null when none should be set (RFC 9002
/// Appendix A.8's `SetLossDetectionTimer`).
pub fn next(state: State, rtt: Rtt) ?Timer {
    // RFC 9002 Appendix A.8: time threshold loss detection comes first, because a packet already
    // known to be ageing into loss is nearer than any probe.
    if (earliest_loss(state)) |timer| return timer;
    // RFC 9002 Appendix A.8: a server that may send nothing sets no timer.
    if (state.at_anti_amplification_limit) return null;
    // RFC 9002 Appendix A.8: with nothing outstanding to detect and the peer's address validated
    // there is nothing to probe for either.
    if (!any_ack_eliciting_in_flight(state) and state.peer_completed_address_validation) return null;
    return probe(state, rtt);
}

/// The nearest `loss_time` across the spaces (RFC 9002 Appendix A.8's `GetLossTimeAndSpace`).
fn earliest_loss(state: State) ?Timer {
    var found: ?Timer = null;
    // Bounded: RFC 9000 §12.3 defines three spaces and `packet_number_spaces` names the count.
    for (state.spaces, 0..) |held, index| {
        const at_ns = held.loss_time_ns orelse continue;
        if (found) |already| {
            if (at_ns >= already.at_ns) continue;
        }
        found = .{ .at_ns = at_ns, .mode = .loss, .space = @enumFromInt(index) };
    }
    return found;
}

fn any_ack_eliciting_in_flight(state: State) bool {
    // Bounded by the three spaces of RFC 9000 §12.3.
    for (state.spaces) |held| {
        if (held.ack_eliciting_in_flight) return true;
    }
    return false;
}

/// The Probe Timeout and the space it is for (RFC 9002 Appendix A.8's `GetPtoTimeAndSpace`).
fn probe(state: State, rtt: Rtt) ?Timer {
    const duration_ns = backed_off(rtt.probe_timeout_ns(false), state.pto_count);
    if (!any_ack_eliciting_in_flight(state)) {
        // RFC 9002 Appendix A.8: this is the anti-deadlock probe, which only a client with an
        // unvalidated address sends, and it starts from when the timer was set because nothing
        // is outstanding to measure from. A Handshake packet proves address ownership; without
        // those keys a padded Initial earns the server more anti-amplification credit.
        assert(!state.peer_completed_address_validation);
        const armed_at_ns = state.armed_at_ns orelse return null;
        const kind: Kind = if (state.has_handshake_keys) .handshake else .initial;
        return .{ .at_ns = armed_at_ns +| duration_ns, .mode = .probe, .space = kind };
    }
    return soonest_probe(state, rtt, duration_ns);
}

/// The nearest probe across the spaces that have something outstanding.
fn soonest_probe(state: State, rtt: Rtt, duration_ns: u64) ?Timer {
    var found: ?Timer = null;
    // Bounded by the three spaces of RFC 9000 §12.3, in the order Appendix A.8 walks them.
    for (state.spaces, 0..) |held, index| {
        if (!held.ack_eliciting_in_flight) continue;
        const kind: Kind = @enumFromInt(index);
        // RFC 9002 Appendix A.8: the Application Data space is skipped until the handshake is
        // confirmed, and the walk stops there because no later space follows it.
        if (kind == .application and !state.handshake_confirmed) break;
        const at_ns = probe_at(held, state, rtt, duration_ns, kind) orelse continue;
        if (found) |already| {
            if (at_ns >= already.at_ns) continue;
        }
        found = .{ .at_ns = at_ns, .mode = .probe, .space = kind };
    }
    return found;
}

/// When one space's probe would fire.
fn probe_at(held: SpaceState, state: State, rtt: Rtt, duration_ns: u64, kind: Kind) ?u64 {
    const sent_at_ns = held.last_ack_eliciting_sent_at_ns orelse return null;
    var period_ns = duration_ns;
    // RFC 9002 Appendix A.8: the Application Data space carries the peer's `max_ack_delay`,
    // backed off with the rest, because only there may the peer hold an acknowledgment back on
    // purpose. §6.2.1 sets that term to zero in the other two.
    if (kind == .application) {
        period_ns +|= backed_off(rtt.peer_max_ack_delay_ns, state.pto_count);
    }
    return sent_at_ns +| period_ns;
}

/// RFC 9002 §6.2.1: the timeout doubles for each probe sent without hearing back, which is what
/// keeps a run of probes from filling a path that is not answering.
fn backed_off(period_ns: u64, pto_count: u6) u64 {
    const shift = @min(pto_count, constants.probe_timeout_backoff_max);
    return period_ns *| (@as(u64, 1) << shift);
}

const testing = std.testing;

/// The state and estimator the tests drive. Test-only.
var test_state: State = undefined;
var test_rtt: Rtt = undefined;
/// An estimator whose Probe Timeout is 200 ms outside the Application Data space and 225 ms in
/// it: 100 ms smoothed, four times a 25 ms variation, and the peer's 25 ms on top. Every one is
/// written whole in nanoseconds, because the magic-numbers rule reads a constant's whole value.
const test_smoothed_ns: u64 = 100_000_000;
const test_variation_ns: u64 = 25_000_000;
const test_probe_ns: u64 = 200_000_000;
const test_application_probe_ns: u64 = 225_000_000;
/// Instants the tests order by eye: ten seconds in, and a send one second before that.
const test_now_ns: u64 = 10_000_000_000;
const test_sent_at_ns: u64 = 9_000_000_000;

fn reset() void {
    test_rtt.init();
    test_rtt.smoothed_ns = test_smoothed_ns;
    test_rtt.variation_ns = test_variation_ns;
    test_state = .{ .spaces = @splat(.{}) };
}

/// Puts an ack-eliciting packet in flight in `kind`, sent `test_sent_at_ns` ago. Test-only.
fn in_flight(kind: Kind) void {
    const at = @intFromEnum(kind);
    test_state.spaces[at].ack_eliciting_in_flight = true;
    test_state.spaces[at].last_ack_eliciting_sent_at_ns = test_sent_at_ns;
}

test "A.8: a packet ageing into loss is nearer than any probe" {
    reset();
    in_flight(.initial);
    // With only a probe to set, the timer is the probe.
    try testing.expectEqual(Mode.probe, next(test_state, test_rtt).?.mode);
    // A loss time in any space takes it over, whatever the probe would have been.
    test_state.spaces[@intFromEnum(Kind.handshake)].loss_time_ns = test_now_ns;
    const found = next(test_state, test_rtt).?;
    try testing.expectEqual(Mode.loss, found.mode);
    try testing.expectEqual(Kind.handshake, found.space);
    try testing.expectEqual(test_now_ns, found.at_ns);
    // The nearest across the spaces is the one that is set.
    test_state.spaces[@intFromEnum(Kind.initial)].loss_time_ns = test_now_ns - 1;
    try testing.expectEqual(Kind.initial, next(test_state, test_rtt).?.space);
    // RFC 9002 Appendix A.8 checks the loss time before the anti-amplification limit, so a
    // server that may send nothing still sets a timer for a packet it already knows is ageing.
    test_state.at_anti_amplification_limit = true;
    try testing.expectEqual(Mode.loss, next(test_state, test_rtt).?.mode);
}

test "A.8: no timer is set where nothing could answer it" {
    reset();
    in_flight(.initial);
    // RFC 9002 Appendix A.8: a server at the anti-amplification limit may send nothing, so a
    // probe would fire on something it cannot do.
    test_state.at_anti_amplification_limit = true;
    try testing.expectEqual(null, next(test_state, test_rtt));
    // With nothing outstanding and the peer's address validated there is nothing to detect.
    reset();
    test_state.peer_completed_address_validation = true;
    try testing.expectEqual(null, next(test_state, test_rtt));
}

test "A.8: with nothing outstanding an unvalidated client probes from when the timer was set" {
    reset();
    // Nothing has set the timer yet, so there is no instant to count from.
    try testing.expectEqual(null, next(test_state, test_rtt));
    // RFC 9002 Appendix A.8: the anti-deadlock probe starts from the instant the timer was set,
    // because nothing is outstanding to measure from. Without Handshake keys it is a padded
    // Initial, which earns the server more anti-amplification credit.
    test_state.armed_at_ns = test_now_ns;
    const initial = next(test_state, test_rtt).?;
    try testing.expectEqual(Mode.probe, initial.mode);
    try testing.expectEqual(Kind.initial, initial.space);
    try testing.expectEqual(test_now_ns + test_probe_ns, initial.at_ns);
    // With them it is a Handshake packet, which proves address ownership.
    test_state.has_handshake_keys = true;
    try testing.expectEqual(Kind.handshake, next(test_state, test_rtt).?.space);
}

test "A.8: a probe is measured from the last packet the peer must acknowledge" {
    reset();
    in_flight(.handshake);
    const found = next(test_state, test_rtt).?;
    try testing.expectEqual(Kind.handshake, found.space);
    try testing.expectEqual(test_sent_at_ns + test_probe_ns, found.at_ns);
    // A space that sent an ack-eliciting packet earlier but has nothing outstanding now — which
    // is every space once its packets are acknowledged — contributes nothing, however much
    // nearer its probe would have been.
    test_state.spaces[@intFromEnum(Kind.initial)].last_ack_eliciting_sent_at_ns = test_sent_at_ns - 1;
    try testing.expectEqual(Kind.handshake, next(test_state, test_rtt).?.space);
    // Put something outstanding in it and it wins, because its probe is the nearer.
    in_flight(.initial);
    test_state.spaces[@intFromEnum(Kind.initial)].last_ack_eliciting_sent_at_ns = test_sent_at_ns - 1;
    try testing.expectEqual(Kind.initial, next(test_state, test_rtt).?.space);
}

test "A.8: the Application Data space waits for the handshake and carries the peer's delay" {
    reset();
    in_flight(.application);
    // RFC 9002 Appendix A.8: until the handshake is confirmed that space is skipped, and here
    // nothing else is outstanding, so no timer is set at all.
    try testing.expectEqual(null, next(test_state, test_rtt));
    // A space before it still sets one, and the walk stops at Application Data rather than
    // passing it.
    in_flight(.handshake);
    const before = next(test_state, test_rtt).?;
    try testing.expectEqual(Kind.handshake, before.space);
    try testing.expectEqual(test_sent_at_ns + test_probe_ns, before.at_ns);
    // Once confirmed the space arms, and §6.2.1 puts the peer's max_ack_delay on it alone — so
    // it is the later of the two and the Handshake space still wins.
    reset();
    in_flight(.application);
    test_state.handshake_confirmed = true;
    const after = next(test_state, test_rtt).?;
    try testing.expectEqual(Kind.application, after.space);
    try testing.expectEqual(test_sent_at_ns + test_application_probe_ns, after.at_ns);
}

test "§6.2.1: the timeout doubles for each probe and stops doubling at a named limit" {
    reset();
    in_flight(.initial);
    test_state.pto_count = 1;
    try testing.expectEqual(test_sent_at_ns + 2 * test_probe_ns, next(test_state, test_rtt).?.at_ns);
    test_state.pto_count = 3;
    try testing.expectEqual(test_sent_at_ns + 8 * test_probe_ns, next(test_state, test_rtt).?.at_ns);
    // The peer's delay is backed off with the rest in the Application Data space.
    reset();
    in_flight(.application);
    test_state.handshake_confirmed = true;
    test_state.pto_count = 1;
    try testing.expectEqual(test_sent_at_ns + 2 * test_application_probe_ns, next(test_state, test_rtt).?.at_ns);
    // Past the named limit the doubling stops rather than overflowing.
    reset();
    in_flight(.initial);
    test_state.pto_count = constants.probe_timeout_backoff_max;
    const capped = next(test_state, test_rtt).?.at_ns;
    test_state.pto_count = std.math.maxInt(u6);
    try testing.expectEqual(capped, next(test_state, test_rtt).?.at_ns);
}
