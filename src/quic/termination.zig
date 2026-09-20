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
    /// The effective idle timeout in nanoseconds, or null when both endpoints disabled it.
    /// RFC 9000 §10.1: the minimum of the two advertised values, or the sole non-zero one.
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
        const advertised_ms = if (local_ms == 0 or peer_ms == 0) @max(local_ms, peer_ms) else @min(local_ms, peer_ms);
        if (advertised_ms == 0) return null;
        const advertised_ns = advertised_ms *| constants.nanoseconds_per_millisecond;
        // RFC 9000 §10.1: endpoints MUST increase the period to at least three times the PTO.
        return @max(advertised_ns, probe_timeout_ns *| constants.close_probe_timeouts);
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

    /// Whether the connection has been idle past its effective timeout (RFC 9000 §10.1).
    pub fn is_idle_timed_out(termination: *const Termination, now_ns: u64) bool {
        if (termination.state != .active) return false;
        const timeout_ns = termination.idle_timeout_ns orelse return false;
        assert(now_ns >= termination.idle_since_ns);
        return now_ns - termination.idle_since_ns >= timeout_ns;
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

const testing = std.testing;

/// The connection the tests drive, and the instants they use. Test-only.
var test_termination: Termination = undefined;
const millisecond_ns = constants.nanoseconds_per_millisecond;
const test_pto_milliseconds = 100;
const test_pto_ns = test_pto_milliseconds * millisecond_ns;
/// Three probe timeouts, which is how long a closing or draining period lasts. Test-only.
const closing_period_ns = constants.close_probe_timeouts * test_pto_ns;

test "§10.1: the effective timeout is the minimum of the two, or the one that is set" {
    const pto = 0;
    try testing.expectEqual(5 * millisecond_ns, Termination.effective_idle_timeout_ns(5, 30, pto).?);
    try testing.expectEqual(5 * millisecond_ns, Termination.effective_idle_timeout_ns(30, 5, pto).?);
    // RFC 9000 §18.2: 0 disables it at that endpoint, so the other's value stands alone.
    try testing.expectEqual(30 * millisecond_ns, Termination.effective_idle_timeout_ns(0, 30, pto).?);
    try testing.expectEqual(30 * millisecond_ns, Termination.effective_idle_timeout_ns(30, 0, pto).?);
    // Both at 0 disables it entirely.
    try testing.expectEqual(null, Termination.effective_idle_timeout_ns(0, 0, pto));
    // RFC 9000 §10.1: the period is raised to three PTOs when the advertised value is smaller.
    try testing.expectEqual(closing_period_ns, Termination.effective_idle_timeout_ns(1, 1, test_pto_ns).?);
    const long_ms = 10 * constants.close_probe_timeouts * test_pto_milliseconds;
    try testing.expectEqual(long_ms * millisecond_ns, Termination.effective_idle_timeout_ns(long_ms, 0, test_pto_ns).?);
}

test "§10.1: a packet received restarts the timer, and the connection closes silently" {
    const timeout_ns = 10 * millisecond_ns;
    test_termination.init(timeout_ns, 0);
    try testing.expect(!test_termination.is_idle_timed_out(timeout_ns - 1));
    // One nanosecond short is not idle; the timeout itself is.
    try testing.expect(test_termination.is_idle_timed_out(timeout_ns));
    test_termination.on_packet_received(timeout_ns - 1);
    try testing.expect(!test_termination.is_idle_timed_out(timeout_ns));
    try testing.expect(test_termination.is_idle_timed_out(2 * timeout_ns));
    // RFC 9000 §10.1: the connection is silently closed, so nothing is sent.
    test_termination.on_idle_timeout();
    try testing.expectEqual(State.closed, test_termination.state);
    try testing.expectEqual(Reason.idle, test_termination.reason.?);
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
    // A timeout both endpoints disabled never fires.
    test_termination.init(null, 0);
    try testing.expect(!test_termination.is_idle_timed_out(std.math.maxInt(u32)));
}

test "§10.1: sending restarts the timer once, until something is received again" {
    const timeout_ns = 10 * millisecond_ns;
    test_termination.init(timeout_ns, 0);
    test_termination.on_ack_eliciting_sent(5 * millisecond_ns);
    try testing.expect(!test_termination.is_idle_timed_out(timeout_ns));
    // A second send restarts nothing: an endpoint that only talks cannot hold a dead
    // connection open.
    test_termination.on_ack_eliciting_sent(12 * millisecond_ns);
    try testing.expect(test_termination.is_idle_timed_out(15 * millisecond_ns));
    // Receiving clears that, so the next send restarts the timer again.
    test_termination.on_packet_received(14 * millisecond_ns);
    test_termination.on_ack_eliciting_sent(20 * millisecond_ns);
    try testing.expect(!test_termination.is_idle_timed_out(29 * millisecond_ns));
    try testing.expect(test_termination.is_idle_timed_out(30 * millisecond_ns));
}

test "§10.2.1: sending a close enters the closing state, which answers and then ends" {
    test_termination.init(null, 0);
    try testing.expectEqual(Permission.send_anything, test_termination.permission());
    test_termination.on_close_sent(0, test_pto_ns);
    try testing.expectEqual(State.closing, test_termination.state);
    try testing.expectEqual(Reason.closed_locally, test_termination.reason.?);
    // Nothing is sent until a packet arrives to answer.
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
    test_termination.on_packet_received(millisecond_ns);
    try testing.expectEqual(Permission.send_close, test_termination.permission());
    // RFC 9000 §10.2.1: the answers thin out, so the next waits for more packets.
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
    test_termination.on_packet_received(2 * millisecond_ns);
    try testing.expectEqual(Permission.send_close, test_termination.permission());
    test_termination.on_packet_received(3 * millisecond_ns);
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
    test_termination.on_packet_received(4 * millisecond_ns);
    try testing.expectEqual(Permission.send_close, test_termination.permission());
    // RFC 9000 §10.2: the state lasts three PTOs, and the caller then discards it.
    test_termination.on_instant(closing_period_ns - 1);
    try testing.expectEqual(State.closing, test_termination.state);
    test_termination.on_instant(closing_period_ns);
    try testing.expectEqual(State.closed, test_termination.state);
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
}

test "§10.2.2: receiving a close enters the draining state, which sends nothing" {
    test_termination.init(null, 0);
    test_termination.on_close_received(0, test_pto_ns);
    try testing.expectEqual(State.draining, test_termination.state);
    try testing.expectEqual(Reason.closed_by_peer, test_termination.reason.?);
    // RFC 9000 §10.2.2: nothing is sent, whatever arrives.
    for (0..4) |index| {
        test_termination.on_packet_received(index * millisecond_ns);
        try testing.expectEqual(Permission.send_nothing, test_termination.permission());
    }
    test_termination.on_instant(closing_period_ns);
    try testing.expectEqual(State.closed, test_termination.state);
}

test "§10.2: time passing closes nothing that has not closed itself" {
    test_termination.init(null, 0);
    // An active connection has no period to run out, so no instant ends it.
    test_termination.on_instant(std.math.maxInt(u32));
    try testing.expectEqual(State.active, test_termination.state);
    try testing.expectEqual(Permission.send_anything, test_termination.permission());
    try testing.expectEqual(null, test_termination.reason);
    // One that has closed by timing out stays closed rather than being reopened.
    test_termination.init(millisecond_ns, 0);
    test_termination.on_idle_timeout();
    test_termination.on_instant(std.math.maxInt(u32));
    try testing.expectEqual(State.closed, test_termination.state);
}

test "§10.2.2: a draining endpoint is silent even when it was answering before" {
    test_termination.init(null, 0);
    test_termination.on_close_sent(0, test_pto_ns);
    // A packet arrives while closing, which is enough for an answer, and none is taken.
    test_termination.on_packet_received(millisecond_ns);
    // The peer's close arrives first, and draining owes nothing however many were counted.
    test_termination.on_close_received(2 * millisecond_ns, test_pto_ns);
    try testing.expectEqual(State.draining, test_termination.state);
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
}

test "§10.2.2: a closing endpoint that hears a close drains, keeping why and when it began" {
    test_termination.init(null, 0);
    test_termination.on_close_sent(millisecond_ns, test_pto_ns);
    test_termination.on_packet_received(2 * millisecond_ns);
    try testing.expectEqual(Permission.send_close, test_termination.permission());
    // The peer's close ends the exchange §10.2.2 warns about: nothing more is sent.
    test_termination.on_close_received(3 * millisecond_ns, test_pto_ns);
    try testing.expectEqual(State.draining, test_termination.state);
    // The reason stays this endpoint's own, and the period still runs from the close it sent.
    try testing.expectEqual(Reason.closed_locally, test_termination.reason.?);
    try testing.expectEqual(millisecond_ns, test_termination.closing_since_ns);
    test_termination.on_packet_received(4 * millisecond_ns);
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
    test_termination.on_instant(millisecond_ns + closing_period_ns);
    try testing.expectEqual(State.closed, test_termination.state);
}

test "§10.1, §10.2: a connection that is closing is not idle, and does not close twice" {
    test_termination.init(millisecond_ns, 0);
    test_termination.on_close_sent(0, test_pto_ns);
    // The idle timer belongs to an active connection alone.
    try testing.expect(!test_termination.is_idle_timed_out(std.math.maxInt(u32)));
    // A second close changes nothing, and neither does a send.
    test_termination.on_close_sent(millisecond_ns, test_pto_ns);
    try testing.expectEqual(Reason.closed_locally, test_termination.reason.?);
    test_termination.on_ack_eliciting_sent(millisecond_ns);
    try testing.expectEqual(State.closing, test_termination.state);
    // Once closed, a peer's close is not a second transition.
    test_termination.on_instant(closing_period_ns);
    test_termination.on_close_received(closing_period_ns, test_pto_ns);
    try testing.expectEqual(State.closed, test_termination.state);
}

/// Every event a caller can raise on a connection, for the table below. `on_idle_timeout` is not
/// one: it asserts the connection is active, which is a contract point and not a transition.
/// Test-only.
const Event = enum {
    packet_received,
    ack_eliciting_sent,
    close_sent,
    close_received,
    period_elapsed,

    fn raise(event: Event, termination: *Termination, now_ns: u64) void {
        switch (event) {
            .packet_received => termination.on_packet_received(now_ns),
            .ack_eliciting_sent => termination.on_ack_eliciting_sent(now_ns),
            .close_sent => termination.on_close_sent(now_ns, test_pto_ns),
            .close_received => termination.on_close_received(now_ns, test_pto_ns),
            .period_elapsed => termination.on_instant(now_ns),
        }
    }
};

/// Puts a connection in `state`, however it has to be reached. Test-only.
fn in_state(state: State) Termination {
    var termination: Termination = undefined;
    termination.init(null, 0);
    switch (state) {
        .active => {},
        .closing => termination.on_close_sent(0, test_pto_ns),
        .draining => termination.on_close_received(0, test_pto_ns),
        .closed => {
            termination.on_close_received(0, test_pto_ns);
            termination.on_instant(closing_period_ns);
        },
    }
    assert(termination.state == state);
    return termination;
}

test "§10: every event in every state lands where the transition table says" {
    // The whole table, one row per state and one column per event. A machine this small is
    // checked by enumeration rather than by argument: nothing here is a sample.
    const table = [_]struct { from: State, event: Event, to: State }{
        .{ .from = .active, .event = .packet_received, .to = .active },
        .{ .from = .active, .event = .ack_eliciting_sent, .to = .active },
        .{ .from = .active, .event = .close_sent, .to = .closing },
        .{ .from = .active, .event = .close_received, .to = .draining },
        // RFC 9000 §10.2: an active connection has no period, so time alone ends nothing.
        .{ .from = .active, .event = .period_elapsed, .to = .active },

        .{ .from = .closing, .event = .packet_received, .to = .closing },
        .{ .from = .closing, .event = .ack_eliciting_sent, .to = .closing },
        // RFC 9000 §10.2.1: already closing, so a second close changes nothing.
        .{ .from = .closing, .event = .close_sent, .to = .closing },
        // RFC 9000 §10.2.2: the peer's close moves a closing endpoint to draining.
        .{ .from = .closing, .event = .close_received, .to = .draining },
        .{ .from = .closing, .event = .period_elapsed, .to = .closed },

        .{ .from = .draining, .event = .packet_received, .to = .draining },
        .{ .from = .draining, .event = .ack_eliciting_sent, .to = .draining },
        // RFC 9000 §10.2.2: a draining endpoint sends nothing, so it cannot send a close.
        .{ .from = .draining, .event = .close_sent, .to = .draining },
        .{ .from = .draining, .event = .close_received, .to = .draining },
        .{ .from = .draining, .event = .period_elapsed, .to = .closed },

        // A closed connection is the end: nothing reopens it.
        .{ .from = .closed, .event = .packet_received, .to = .closed },
        .{ .from = .closed, .event = .ack_eliciting_sent, .to = .closed },
        .{ .from = .closed, .event = .close_sent, .to = .closed },
        .{ .from = .closed, .event = .close_received, .to = .closed },
        .{ .from = .closed, .event = .period_elapsed, .to = .closed },
    };
    // Every state and event pair appears exactly once, so the table is the whole function.
    const states = @typeInfo(State).@"enum".fields.len;
    const events = @typeInfo(Event).@"enum".fields.len;
    try testing.expectEqual(states * events, table.len);
    for (table, 0..) |row, index| {
        for (table[index + 1 ..]) |other| {
            try testing.expect(row.from != other.from or row.event != other.event);
        }
        var termination = in_state(row.from);
        row.event.raise(&termination, closing_period_ns);
        try testing.expectEqual(row.to, termination.state);
        // RFC 9000 §10.2.2: nothing is sent once draining begins, whatever event led there.
        if (termination.state == .draining or termination.state == .closed) {
            try testing.expectEqual(Permission.send_nothing, termination.permission());
        }
    }
}
