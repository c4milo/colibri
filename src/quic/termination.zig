//! How a connection ends (RFC 9000 §10): the idle timeout of §10.1, and the closing and
//! draining states of §10.2. Part of design §8 step 9.
//!
//! Every instant is a parameter and nothing here reads a clock (design §4.2), so a caller asks
//! two questions and acts on the answers: has the connection been idle too long, and may
//! anything still be sent. The Probe Timeout is a parameter too. RFC 9000 §10.1 and §10.2 both
//! size themselves on it, and RFC 9002 computes it in step 10, so this file takes it rather than
//! guessing it.
//!
//! The three states after `active` are the RFC's, and the difference between them is what may be
//! sent. In `closing` an endpoint answers incoming packets with a CONNECTION_CLOSE frame and
//! nothing else (§10.2.1). In `draining` it sends nothing at all (§10.2.2). In `closed` the
//! caller discards the connection.
//!
//! Stateless Reset (§10.3) is not here: it needs the token a peer issued, which arrives with the
//! connection ID work, and an endpoint that has discarded its state has nothing left to reset
//! from.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// Where a connection is in its life (RFC 9000 §10.2).
pub const State = enum {
    /// Packets are sent and received as usual.
    active,
    /// RFC 9000 §10.2.1: entered after sending a CONNECTION_CLOSE frame. Only that frame is
    /// sent, in answer to incoming packets.
    closing,
    /// RFC 9000 §10.2.2: entered after receiving a CONNECTION_CLOSE frame. Nothing is sent.
    draining,
    /// The closing or draining period is over and the caller discards the connection state.
    closed,
};

/// Why a connection ended, which a caller reports to its application.
pub const Reason = enum {
    /// RFC 9000 §10.1: idle for longer than the effective timeout, and closed silently — no
    /// CONNECTION_CLOSE frame is sent, because the peer has stopped listening too.
    idle,
    /// This endpoint sent a CONNECTION_CLOSE frame (§10.2).
    closed_locally,
    /// The peer sent one (§10.2.2).
    closed_by_peer,
    /// RFC 9000 §6.2: a client abandoned the connection attempt, because the server answered
    /// with a Version Negotiation packet and colibri speaks one version. Nothing is sent: the
    /// server kept no state to close, and the client holds no key to seal a CONNECTION_CLOSE.
    abandoned,
    /// RFC 9000 §9.3.2: the peer's new address failed validation and no validated one was left,
    /// so the connection closed silently.
    path_failed,
};

/// What a caller may do now.
pub const Permission = enum {
    /// Anything: the connection is active.
    send_anything,
    /// A CONNECTION_CLOSE frame, in answer to a packet just received (§10.2.1).
    send_close,
    /// Nothing (§10.2.2, and after the period ends).
    send_nothing,
};

pub const Termination = struct {
    state: State,
    /// Set once the state leaves `active`.
    reason: ?Reason,
    /// The idle timeout the two endpoints advertised, in nanoseconds, or null when both disabled
    /// it: RFC 9000 §10.1's minimum of the two values, or the sole non-zero one. §10.1's floor of
    /// three times the current Probe Timeout moves with the round trip, so it is applied when the
    /// timeout is asked for, from the PTO the caller passes.
    idle_timeout_ns: ?u64,
    /// The instant the idle timer last restarted (§10.1).
    idle_since_ns: u64,
    /// Whether an ack-eliciting packet has gone out since the last one was received and
    /// processed. RFC 9000 §10.1 restarts the timer on a send only when none has.
    ack_eliciting_sent_since_receive: bool,
    /// The instant the closing or draining period began, and how long it lasts (§10.2).
    closing_since_ns: u64,
    closing_period_ns: u64,
    /// Packets received while closing, which the answers are rate limited against (§10.2.1).
    packets_received_closing: u64,
    /// The count at which the next CONNECTION_CLOSE goes out.
    answer_at_packet: u64,

    pub fn init(termination: *Termination, idle_timeout_ns: ?u64, now_ns: u64) void {
        termination.* = .{
            .state = .active,
            .reason = null,
            .idle_timeout_ns = idle_timeout_ns,
            .idle_since_ns = now_ns,
            .ack_eliciting_sent_since_receive = false,
            .closing_since_ns = 0,
            .closing_period_ns = 0,
            .packets_received_closing = 0,
            .answer_at_packet = 1,
        };
    }

    /// The effective idle timeout of RFC 9000 §10.1, in nanoseconds: the minimum of the two
    /// values advertised in milliseconds, or the sole non-zero one, and null when both are 0.
    /// It is never below three times the Probe Timeout, which §10.1 requires so that several
    /// probes can be sent and lost before the connection is given up.
    pub fn effective_idle_timeout_ns(local_ms: u64, peer_ms: u64, probe_timeout_ns: u64) ?u64 {
        return floored(advertised_idle_timeout_ns(local_ms, peer_ms), probe_timeout_ns);
    }

    /// RFC 9000 §10.1's minimum of the two advertised values, or the sole non-zero one, in
    /// nanoseconds, and null when both are 0.
    pub fn advertised_idle_timeout_ns(local_ms: u64, peer_ms: u64) ?u64 {
        const advertised_ms = if (local_ms == 0 or peer_ms == 0) @max(local_ms, peer_ms) else @min(local_ms, peer_ms);
        if (advertised_ms == 0) return null;
        return advertised_ms *| constants.nanoseconds_per_millisecond;
    }

    /// RFC 9000 §10.1: "endpoints MUST increase the idle timeout period to be at least three
    /// times the current Probe Timeout (PTO)".
    fn floored(advertised_ns: ?u64, probe_timeout_ns: u64) ?u64 {
        const held = advertised_ns orelse return null;
        return @max(held, probe_timeout_ns *| constants.close_probe_timeouts);
    }

    /// RFC 9000 §10.1: the timer restarts when a packet from the peer is received and processed.
    pub fn on_packet_received(termination: *Termination, now_ns: u64) void {
        if (termination.state == .active) {
            termination.idle_since_ns = now_ns;
            termination.ack_eliciting_sent_since_receive = false;
            return;
        }
        // RFC 9000 §10.2.1: a closing endpoint counts what arrives, because its answers are
        // rate limited against that count.
        if (termination.state == .closing) termination.packets_received_closing += 1;
    }

    /// RFC 9000 §10.1: the timer restarts on sending an ack-eliciting packet, but only when no
    /// other ack-eliciting packet has been sent since a packet was last received. Restarting on
    /// every send would let an endpoint that only talks keep a dead connection open.
    pub fn on_ack_eliciting_sent(termination: *Termination, now_ns: u64) void {
        if (termination.state != .active) return;
        if (termination.ack_eliciting_sent_since_receive) return;
        termination.idle_since_ns = now_ns;
        termination.ack_eliciting_sent_since_receive = true;
    }

    /// Whether the connection has been idle past its effective timeout (RFC 9000 §10.1), with
    /// `probe_timeout_ns` the current PTO.
    pub fn is_idle_timed_out(termination: *const Termination, now_ns: u64, probe_timeout_ns: u64) bool {
        if (termination.state != .active) return false;
        const timeout_ns = floored(termination.idle_timeout_ns, probe_timeout_ns) orelse return false;
        assert(now_ns >= termination.idle_since_ns);
        return now_ns - termination.idle_since_ns >= timeout_ns;
    }

    /// The instant RFC 9000 §10.1's idle timeout expires, or null when none is armed. It is the
    /// deadline design §4.2 has colibri return and the caller honour, and `is_idle_timed_out`
    /// is the same rule asked at an instant.
    pub fn idle_deadline_ns(termination: *const Termination, probe_timeout_ns: u64) ?u64 {
        if (termination.state != .active) return null;
        const timeout_ns = floored(termination.idle_timeout_ns, probe_timeout_ns) orelse return null;
        return termination.idle_since_ns +| timeout_ns;
    }

    /// The instant RFC 9000 §10.2's closing or draining period ends, or null while neither runs.
    pub fn period_deadline_ns(termination: *const Termination) ?u64 {
        const waiting = termination.state == .closing or termination.state == .draining;
        if (!waiting) return null;
        return termination.closing_since_ns +| termination.closing_period_ns;
    }

    /// RFC 9000 §10.1: the connection is silently closed and its state discarded. Nothing is
    /// sent, so there is no closing period to wait out.
    pub fn on_idle_timeout(termination: *Termination) void {
        assert(termination.state == .active);
        termination.state = .closed;
        termination.reason = .idle;
    }

    /// RFC 9000 §6.2: "A client that supports only this version of QUIC MUST abandon the current
    /// connection attempt if it receives a Version Negotiation packet." Like an idle timeout it
    /// is silent, so there is no closing period to wait out.
    pub fn on_abandoned(termination: *Termination) void {
        assert(termination.state == .active);
        termination.state = .closed;
        termination.reason = .abandoned;
        assert(termination.permission() == .send_nothing);
    }

    /// RFC 9000 §9.3.2: "If an endpoint has no state about the last validated peer address, it
    /// MUST close the connection silently by discarding all connection state."
    pub fn on_path_failed(termination: *Termination) void {
        assert(termination.state == .active);
        termination.state = .closed;
        termination.reason = .path_failed;
        assert(termination.permission() == .send_nothing);
    }

    /// RFC 9000 §10.2, §10.2.1: this endpoint sent a CONNECTION_CLOSE frame and enters the
    /// closing state. `probe_timeout_ns` sizes the period, which §10.2 puts at three PTOs.
    pub fn on_close_sent(termination: *Termination, now_ns: u64, probe_timeout_ns: u64) void {
        if (termination.state != .active) return;
        termination.enter(.closing, .closed_locally, now_ns, probe_timeout_ns);
    }

    /// RFC 9000 §10.2, §10.2.2: the peer sent a CONNECTION_CLOSE frame, so this endpoint enters
    /// the draining state and sends nothing further. A closing endpoint moves to draining too,
    /// which is what ends the exchange §10.2.2 warns about.
    pub fn on_close_received(termination: *Termination, now_ns: u64, probe_timeout_ns: u64) void {
        if (termination.state == .draining or termination.state == .closed) return;
        const reason: Reason = termination.reason orelse .closed_by_peer;
        // A connection already closing keeps the instant its period began: §10.2 measures from
        // the immediate close, and moving to draining is not a second one.
        const since_ns = if (termination.state == .closing) termination.closing_since_ns else now_ns;
        termination.enter(.draining, reason, since_ns, probe_timeout_ns);
    }

    fn enter(termination: *Termination, state: State, reason: Reason, since_ns: u64, probe_timeout_ns: u64) void {
        termination.state = state;
        termination.reason = reason;
        termination.closing_since_ns = since_ns;
        // RFC 9000 §10.2: the states persist for at least three times the current PTO, so a
        // delayed or reordered packet meets a connection that still knows what it was.
        termination.closing_period_ns = probe_timeout_ns *| constants.close_probe_timeouts;
    }

    /// Ends the closing or draining period once it has run its course (RFC 9000 §10.2), after
    /// which the caller discards the connection state.
    pub fn on_instant(termination: *Termination, now_ns: u64) void {
        const waiting = termination.state == .closing or termination.state == .draining;
        if (!waiting) return;
        assert(now_ns >= termination.closing_since_ns);
        if (now_ns - termination.closing_since_ns >= termination.closing_period_ns) {
            termination.state = .closed;
        }
    }

    /// What may be sent now. In `closing` a CONNECTION_CLOSE frame is owed only in answer to an
    /// incoming packet, and RFC 9000 §10.2.1 asks that those answers be rate limited, so one
    /// goes out on a progressively rarer count of packets received.
    pub fn permission(termination: *Termination) Permission {
        switch (termination.state) {
            .active => return .send_anything,
            .draining, .closed => return .send_nothing,
            .closing => {},
        }
        if (termination.packets_received_closing < termination.answer_at_packet) return .send_nothing;
        // The next answer waits for twice as many packets, which is the "progressively
        // increasing number of received packets" §10.2.1 offers.
        termination.answer_at_packet *|= constants.close_answer_backoff;
        return .send_close;
    }
};

test {
    _ = @import("termination_test.zig");
}
