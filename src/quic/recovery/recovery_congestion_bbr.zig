//! Where `Recovery` gives BBRv3 its events (draft-ietf-ccwg-bbr-06 §5.2). Part of design §8 step
//! 29b.4.
//!
//! RFC 9002's loss recovery finds what was acknowledged and lost, and when a recovery period
//! starts. Under BBRv3 each of those is also one of the draft's events: an ACK frame
//! (§5.2.3), a lost packet (§5.2.4), the start of loss recovery (§5.6.4.4), a spurious episode
//! (§5.2.5) and a send (§5.2.2). Each function here does nothing under CUBIC, so `Recovery`
//! calls them without asking which controller runs.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const recovery_module = @import("recovery.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_delivery = @import("recovery_delivery.zig");
const recovery_sent = @import("recovery_sent.zig");
const recovery_spurious = @import("recovery_spurious.zig");
const recovery_pacing = @import("recovery_pacing.zig");
const recovery_bbr = @import("recovery_bbr/recovery_bbr.zig");

const Recovery = recovery_module.Recovery;
const Bbr = recovery_bbr.Bbr;

/// BBRv3's state, or null under CUBIC.
fn bbr_of(recovery: *Recovery) ?*Bbr {
    return switch (recovery.congestion.state) {
        .bbr => |*state| state,
        .cubic, .newreno => null,
    };
}

/// The draft's `C.*` values at `now_ns`.
fn path_of(recovery: *Recovery, state: *const Bbr, now_ns: u64, window_limited: bool, in_recovery: bool) recovery_bbr.Path {
    return .{
        .now_ns = now_ns,
        .in_flight_len = recovery.in_flight_len(),
        .delivered_len = recovery.delivery.delivered_len,
        .window_limited = window_limited,
        .in_recovery = in_recovery,
        .datagram_len = recovery.congestion.max_datagram_len,
        .initial_window_len = recovery_congestion.initial_window(recovery.congestion.max_datagram_len),
        .send_quantum_len = state.send_quantum_len,
    };
}

/// BBRv3 set `C.cwnd`, and the window the sender reads follows it.
fn take_window(recovery: *Recovery, state: *const Bbr, now_ns: u64) void {
    recovery.congestion.window = state.window_len;
    recovery.congestion.latest_ns = @max(recovery.congestion.latest_ns, now_ns);
}

/// §5.2.3's `UpdateOnACK`, for an ACK frame whose newest packet went out at `newest_sent_at_ns`.
/// `used` is RFC 9002 §7.8's judgement, which is `C.is_cwnd_limited`.
pub fn on_ack(recovery: *Recovery, sample: recovery_delivery.Sample, newest_sent_at_ns: u64, used: recovery_congestion.Utilization, now_ns: u64) void {
    const state = bbr_of(recovery) orelse return;
    assert(state.window_len == recovery.congestion.window);
    const path = path_of(recovery, state, now_ns, used == .full, recovery.congestion.in_recovery(newest_sent_at_ns));
    state.on_ack(sample, path, &recovery.delivery);
    const smoothed_rtt_ns: ?u64 = if (recovery.rtt.has_sample()) recovery.rtt.smoothed_ns else null;
    state.update_controls(sample, path, smoothed_rtt_ns);
    take_window(recovery, state, now_ns);
}

/// §5.2.4: each packet one detection pass of `kind` declared lost.
pub fn on_lost(recovery: *Recovery, application: bool, lost: []const recovery_sent.Record, now_ns: u64) void {
    const state = bbr_of(recovery) orelse return;
    const path = path_of(recovery, state, now_ns, false, recovery.congestion.recovery_started_at_ns != null);
    // Bounded: the caller's slice.
    for (lost) |record| state.on_packet_lost(record, recovery.delivery.lost_len, application, path);
    take_window(recovery, state, now_ns);
}

/// RFC 9002 Appendix B.6's `OnCongestionEvent`, for both of `Recovery`'s congestion events: it
/// starts a spurious loss episode (`recovery_spurious.zig`), and BBRv3's `OnEnterFastRecovery`
/// (§5.6.4.4), when it starts a new recovery period.
pub fn on_congestion_event(recovery: *Recovery, sent_at_ns: u64, now_ns: u64) void {
    const started = recovery_spurious.on_congestion_event(&recovery.congestion, &recovery.spurious, sent_at_ns, now_ns);
    if (!started) return;
    const state = bbr_of(recovery) orelse return;
    state.on_enter_recovery(path_of(recovery, state, now_ns, false, true));
}

/// RFC 9002 §7.6: persistent congestion. BBRv3 saves its state first, as §5.6.4.4's
/// `OnEnterRTO` does, and RFC 9002 then sets the window to the minimum.
pub fn on_persistent_congestion(recovery: *Recovery, now_ns: u64) void {
    if (bbr_of(recovery)) |state| state.on_enter_rto(path_of(recovery, state, now_ns, false, true));
    recovery.congestion.on_persistent_congestion();
}

/// §5.2.5: the frame showed the loss episode spurious.
pub fn on_spurious(recovery: *Recovery, now_ns: u64) void {
    const state = bbr_of(recovery) orelse return;
    state.on_spurious_loss(path_of(recovery, state, now_ns, false, false));
    take_window(recovery, state, now_ns);
}

/// §5.2.2's `OnTransmit`, before a packet in flight goes out.
pub fn on_transmit(recovery: *Recovery, now_ns: u64) void {
    const state = bbr_of(recovery) orelse return;
    state.on_transmit(path_of(recovery, state, now_ns, false, false), &recovery.delivery);
    recovery.congestion.latest_ns = @max(recovery.congestion.latest_ns, now_ns);
}

/// The pacer's rate under BBRv3: §5.6.2's pacing rate, in octets a second, with §5.6.3's send
/// quantum as the burst. Null under CUBIC, whose rate is RFC 9002 §7.7's.
pub fn rate(recovery: *const Recovery) ?recovery_pacing.Rate {
    const state = switch (recovery.congestion.state) {
        .bbr => |*state| state,
        .cubic, .newreno => return null,
    };
    return .{
        .period_len = state.pacing_rate,
        .period_ns = core.constants.nanoseconds_per_second,
        .numerator = 1,
        .denominator = 1,
        .burst_len = state.send_quantum_len,
    };
}

test {
    _ = @import("recovery_congestion_bbr_test.zig");
}
