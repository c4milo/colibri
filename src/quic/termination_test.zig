//! The tests of `termination.zig`.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const termination_module = @import("termination.zig");

const Termination = termination_module.Termination;
const State = termination_module.State;
const Reason = termination_module.Reason;
const Permission = termination_module.Permission;

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
    try testing.expect(!test_termination.is_idle_timed_out(timeout_ns - 1, 0));
    // One nanosecond short is not idle; the timeout itself is.
    try testing.expect(test_termination.is_idle_timed_out(timeout_ns, 0));
    test_termination.on_packet_received(timeout_ns - 1);
    try testing.expect(!test_termination.is_idle_timed_out(timeout_ns, 0));
    try testing.expect(test_termination.is_idle_timed_out(2 * timeout_ns, 0));
    // RFC 9000 §10.1: the connection is silently closed, so nothing is sent.
    test_termination.on_idle_timeout();
    try testing.expectEqual(State.closed, test_termination.state);
    try testing.expectEqual(Reason.idle, test_termination.reason.?);
    try testing.expectEqual(Permission.send_nothing, test_termination.permission());
    // A timeout both endpoints disabled never fires.
    test_termination.init(null, 0);
    try testing.expect(!test_termination.is_idle_timed_out(std.math.maxInt(u32), 0));
}

test "§10.1: sending restarts the timer once, until something is received again" {
    const timeout_ns = 10 * millisecond_ns;
    test_termination.init(timeout_ns, 0);
    test_termination.on_ack_eliciting_sent(5 * millisecond_ns);
    try testing.expect(!test_termination.is_idle_timed_out(timeout_ns, 0));
    // A second send restarts nothing: an endpoint that only talks cannot hold a dead
    // connection open.
    test_termination.on_ack_eliciting_sent(12 * millisecond_ns);
    try testing.expect(test_termination.is_idle_timed_out(15 * millisecond_ns, 0));
    // Receiving clears that, so the next send restarts the timer again.
    test_termination.on_packet_received(14 * millisecond_ns);
    test_termination.on_ack_eliciting_sent(20 * millisecond_ns);
    try testing.expect(!test_termination.is_idle_timed_out(29 * millisecond_ns, 0));
    try testing.expect(test_termination.is_idle_timed_out(30 * millisecond_ns, 0));
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
    try testing.expect(!test_termination.is_idle_timed_out(std.math.maxInt(u32), 0));
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

test "§10.1: the timeout is never less than three Probe Timeouts, whatever was advertised" {
    const timeout_ns = 10 * millisecond_ns;
    test_termination.init(timeout_ns, 0);
    // Three PTOs of 100 ms outlast the 10 ms advertised, so 10 ms of silence is not idle yet.
    try testing.expect(!test_termination.is_idle_timed_out(timeout_ns, test_pto_ns));
    try testing.expectEqual(closing_period_ns, test_termination.idle_deadline_ns(test_pto_ns).?);
    try testing.expect(test_termination.is_idle_timed_out(closing_period_ns, test_pto_ns));
}
