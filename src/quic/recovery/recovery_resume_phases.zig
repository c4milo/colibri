//! Careful Resume's phases (RFC 9959 §3.2 to §3.6, decision 149) under the window-based
//! controllers, CUBIC and NewReno. Part of design §8 step 35b. BBRv3 follows Appendix C, which is
//! 35c's: until then a BBRv3 connection stays in the Reconnaissance Phase, which changes nothing.
//!
//! `Recovery` calls in at three places: after it records an application packet in flight, after an
//! ACK frame, and when a congestion event starts a recovery period. Only the application space
//! counts, because RFC 9959 measures the data a connection carries after its handshake.
//!
//! It reads no clock: every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const recovery_module = @import("recovery.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_resume = @import("recovery_resume.zig");
const space = @import("../space/space.zig");

const Recovery = recovery_module.Recovery;
const Resume = recovery_resume.Resume;

/// Whether the connection's controller is one §3's window rules apply to.
fn windowed(recovery: *const Recovery) bool {
    return recovery.congestion.state != .bbr;
}

/// Whether the phase holds the window, so the controller's own growth is skipped: §3.3 sets the
/// window to the jump, and §3.5 says "The CWND MUST NOT be increased in the Safe Retreat Phase."
pub fn holds_window(recovery: *const Recovery) bool {
    const phase = recovery.careful_resume.phase;
    return windowed(recovery) and (phase == .unvalidated or phase == .safe_retreat);
}

/// After an application packet in flight of number `number` was recorded.
pub fn on_packet_sent(recovery: *Recovery, number: u64) void {
    const held = &recovery.careful_resume;
    if (!windowed(recovery) or held.phase != .unvalidated) return;
    if (held.first_unvalidated == null) held.first_unvalidated = number;
    held.last_unvalidated = number;
    // §3.3: "The sender enters the Validating Phase when the flight_size equals the CWND", which
    // in octets is "when the remaining unused CWND is less than one maximum-sized packet".
    const in_flight_len = recovery.in_flight_len();
    if (in_flight_len +| recovery.congestion.max_datagram_len > recovery.congestion.window) leave_unvalidated(recovery);
}

/// After an ACK frame took `acknowledged_len` application octets out of flight, before loss
/// detection, so a Safe Retreat the same frame starts halves a PipeSize that holds them.
pub fn on_acknowledged(recovery: *Recovery, acknowledged_len: u64) void {
    const held = &recovery.careful_resume;
    if (!windowed(recovery)) return;
    switch (held.phase) {
        .off => {},
        // §3.2: the initial data the path is confirmed by.
        .reconnaissance => held.acknowledged_len +|= acknowledged_len,
        // §3.3, §3.4 and §3.5: "The variable PipeSize is increased by the volume of data that is
        // newly acknowledged by each received ACK."
        .unvalidated, .validating, .safe_retreat => held.pipe_len +|= acknowledged_len,
    }
}

/// After an ACK frame was processed at `now_ns`, its losses included: the phase it ends.
pub fn on_ack(recovery: *Recovery, now_ns: u64) void {
    const held = &recovery.careful_resume;
    if (!windowed(recovery)) return;
    const largest = recovery.largest_acknowledged[@intFromEnum(space.Kind.application)] orelse return;
    switch (held.phase) {
        .off => {},
        .reconnaissance => on_ack_reconnaissance(recovery, now_ns),
        .unvalidated => {
            // §3.3: the phase ends on the acknowledgment of "the first packet number (or higher)
            // that was sent in the Unvalidated Phase", or once "more than one RTT has elapsed".
            const first_acknowledged = if (held.first_unvalidated) |first| largest >= first else false;
            const rtt_passed = now_ns -| held.unvalidated_at_ns > recovery.rtt.smoothed_ns;
            if (first_acknowledged or rtt_passed) leave_unvalidated(recovery);
        },
        // §3.4: the phase ends once "the last packet number (or higher) that was sent in the
        // Unvalidated Phase" is acknowledged.
        .validating => if (largest >= held.last_unvalidated.?) {
            held.phase = .off;
        },
        // §3.5: the phase ends once the last unvalidated packet is acknowledged.
        .safe_retreat => if (largest >= held.last_unvalidated.?) leave_safe_retreat(recovery),
    }
}

/// §3.2: the path is confirmed once the initial data is acknowledged with no congestion, and the
/// round trip did not shrink to half of the saved one.
fn on_ack_reconnaissance(recovery: *Recovery, now_ns: u64) void {
    const held = &recovery.careful_resume;
    const initial_len = recovery_congestion.initial_window(recovery.congestion.max_datagram_len);
    // §3.2: "When the sender has received an ACK that acknowledges all the initial data (usually
    // the IW) without reported congestion, it MAY then enter the Unvalidated Phase."
    if (held.acknowledged_len < initial_len) return;
    // §3.2: "If the minimum RTT recorded in the Reconnaissance Phase is less than or equal to
    // (saved_rtt / 2) ... the sender MUST stop using Careful Resume".
    if (recovery.rtt.min_ns <= held.saved.rtt_ns / constants.protocol.resume_rtt_shrink_divisor) {
        held.phase = .off;
        return;
    }
    // §4.2.1: "A current RTT that is more than ten times the saved_rtt is indicative of a path
    // change."
    if (recovery.rtt.min_ns > held.saved.rtt_ns *| constants.policy.resume_rtt_growth_factor_max) {
        held.phase = .off;
        return;
    }
    enter_unvalidated(recovery, now_ns);
}

/// §3.3's entry: PipeSize starts at the flight size, and the window jumps to at most half the
/// saved window and max_jump.
fn enter_unvalidated(recovery: *Recovery, now_ns: u64) void {
    const held = &recovery.careful_resume;
    const jump_len = @min(held.bounds.jump_len_max, held.saved.window_len / constants.protocol.resume_jump_divisor);
    // A jump to no more than the window the controller already has changes nothing, so the
    // connection goes on under normal congestion control (§3.7).
    if (jump_len <= recovery.congestion.window) {
        held.phase = .off;
        return;
    }
    held.pipe_len = recovery.in_flight_len();
    held.unvalidated_at_ns = now_ns;
    held.first_unvalidated = null;
    held.last_unvalidated = null;
    recovery.congestion.set_window(jump_len);
    held.phase = .unvalidated;
    assert(recovery.congestion.window == jump_len);
}

/// §3.3's "check flight_size": the window falls to PipeSize and Careful Resume ends when the
/// jump was not used, and otherwise the window is the flight size and the Validating Phase
/// starts.
fn leave_unvalidated(recovery: *Recovery) void {
    const held = &recovery.careful_resume;
    assert(held.phase == .unvalidated);
    const flight_len = recovery.in_flight_len();
    const initial_len = recovery_congestion.initial_window(recovery.congestion.max_datagram_len);
    if (flight_len < initial_len or flight_len <= held.pipe_len or held.last_unvalidated == null) {
        // §3.3: "resets the CWND to the PipeSize ... In the absence of detected congestion, the
        // CWND is not reduced below the IW."
        recovery.congestion.set_window(@max(held.pipe_len, initial_len));
        held.phase = .off;
        return;
    }
    // §3.3: "Otherwise, the CWND MUST be set to the flight_size".
    recovery.congestion.set_window(flight_len);
    held.phase = .validating;
}

/// A congestion event started a recovery period (RFC 9002 Appendix B.6), after the controller
/// reduced its window.
pub fn on_congestion_event(recovery: *Recovery) void {
    const held = &recovery.careful_resume;
    if (!windowed(recovery)) return;
    switch (held.phase) {
        .off, .safe_retreat => {},
        // §3.2: "If the sender detects congestion ... The sender stops using Careful Resume".
        .reconnaissance => held.phase = .off,
        // §3.3 and §3.4: congestion in the Unvalidated or the Validating Phase enters the Safe
        // Retreat Phase.
        .unvalidated, .validating => enter_safe_retreat(recovery),
    }
}

/// §3.5's entry: the saved set goes, and "The CWND MUST be reduced to no more than
/// (PipeSize/2)", held at RFC 9002 §7.2's minimum.
fn enter_safe_retreat(recovery: *Recovery) void {
    const held = &recovery.careful_resume;
    held.retreated = true;
    const window = @max(held.pipe_len / constants.protocol.resume_retreat_divisor, recovery.congestion.minimum_window());
    recovery.congestion.set_window(@min(window, recovery.congestion.window));
    held.phase = .safe_retreat;
    // §3.5: with no unvalidated packet in flight there is nothing to drain.
    if (held.last_unvalidated == null) leave_safe_retreat(recovery);
}

/// §3.5's exit: "the ssthresh MUST be set to no larger than the most recently measured PipeSize *
/// Beta", with Beta the controller's own decrease.
fn leave_safe_retreat(recovery: *Recovery) void {
    const held = &recovery.careful_resume;
    const congestion = &recovery.congestion;
    const beta: struct { numerator: u64, denominator: u64 } = switch (congestion.state) {
        .cubic => .{ .numerator = constants.recovery.cubic.beta_numerator, .denominator = constants.recovery.cubic.beta_denominator },
        .newreno => .{ .numerator = constants.recovery.newreno.loss_reduction_numerator, .denominator = constants.recovery.newreno.loss_reduction_denominator },
        .bbr => unreachable,
    };
    const threshold = held.pipe_len / beta.denominator * beta.numerator;
    congestion.slow_start_threshold = @min(congestion.slow_start_threshold, @max(threshold, congestion.minimum_window()));
    held.phase = .off;
}

/// §3.6: "A sender that experiences persistent congestion ... ceases to use Careful Resume."
pub fn on_persistent_congestion(recovery: *Recovery) void {
    recovery.careful_resume.phase = .off;
}

test {
    _ = @import("recovery_resume_phases_test.zig");
}
