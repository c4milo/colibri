//! When colibri next wants to be called, and what happens when that instant arrives.
//!
//! **colibri sets no timer.** Design §4.2: "colibri never sets a timer. It returns the instant at
//! which it next wants to be called, and the caller arranges that." Five deadlines exist across a
//! connection, each armed by the piece that owns it; what is here is the earliest of them, and
//! the one call that fires whichever have come due.
//!
//! **Every deadline is acted on here.** Decision 59 has the connection run RFC 9002 Appendix
//! A.9's `OnLossDetectionTimeout` too, which needs storage for the packets it declares lost:
//! decision 35 leaves that with the caller, so `on_instant` takes it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const key_update = @import("connection_key_update.zig");
const connection_recovery = @import("connection_recovery.zig");
const connection_flow = @import("connection_flow.zig");

const Connection = connection_module.Connection;
const Suite = crypto.Suite;

/// Which deadline is nearest. Each names the section that armed it.
pub const Kind = enum {
    /// RFC 9002 Appendix A.8: time threshold loss detection, or the Probe Timeout.
    loss,
    /// RFC 9000 §10.1: the idle timeout.
    idle,
    /// RFC 9000 §10.2: the end of the closing or draining period.
    period,
    /// RFC 9000 §8.2.4: the PATH_CHALLENGE this endpoint is waiting on.
    path,
    /// RFC 9001 §6.5: the read keys of the phase before this one.
    previous_keys,
    /// RFC 9000 §13.2.1: the max_ack_delay this endpoint advertised, measured from the oldest
    /// ack-eliciting packet it has not acknowledged.
    acknowledgment,
    /// RFC 9000 §4.1: a flow control limited endpoint with nothing in flight owes its BLOCKED
    /// frames again.
    blocked,
};

pub const Deadline = struct {
    at_ns: u64,
    kind: Kind,
};

/// The instant colibri next wants `on_instant`, or null when nothing is armed. `kind` is what
/// made it the nearest, which a caller reads for a trace and nothing turns on.
pub fn next(connection: *Connection) ?Deadline {
    // RFC 9002 Appendix A.8's `SetLossDetectionTimer` decides between a loss time and a probe,
    // and answers null when neither is armed.
    var earliest = of(connection_recovery.loss_deadline_ns(connection), .loss);
    earliest = nearer(earliest, of(connection.termination.idle_deadline_ns(idle_probe_timeout_ns(connection)), .idle));
    earliest = nearer(earliest, of(connection.termination.period_deadline_ns(), .period));
    earliest = nearer(earliest, of(connection.path.challenge_deadline_ns(), .path));
    earliest = nearer(earliest, of(key_update.previous_keys_deadline_ns(connection), .previous_keys));
    earliest = nearer(earliest, of(acknowledgment_deadline_ns(connection), .acknowledgment));
    earliest = nearer(earliest, of(connection_flow.blocked_deadline_ns(connection), .blocked));
    return earliest;
}

/// The instant an ACK is owed by (RFC 9000 §13.2.1). The application space alone: §13.2.1 has
/// every ack-eliciting Initial and Handshake packet acknowledged "immediately", which
/// `Space.receive` records, so those two are owed at once and want no timer for it.
fn acknowledgment_deadline_ns(connection: *const Connection) ?u64 {
    const space = &connection.spaces[@intFromEnum(core.Level.application)];
    return space.ack_deadline_ns(connection.max_ack_delay_ns());
}

/// What the instant set off. More than one can come due at once, so this is a set and not a
/// choice: a connection idle past its timeout may also have a probe owed.
pub const Fired = struct {
    /// RFC 9002 Appendix A.9: the loss detection timer went off, and the packets it declared lost
    /// are owed again or the probes it asked for are owed.
    loss: bool = false,
    /// RFC 9000 §10.1: the connection was idle past its effective timeout and is now closed,
    /// silently — no CONNECTION_CLOSE goes out, because the peer has stopped listening too.
    idle: bool = false,
    /// RFC 9000 §10.2: the closing or draining period ended, so the caller discards the state.
    period: bool = false,
    /// RFC 9000 §8.2.4: the outstanding PATH_CHALLENGE was abandoned, which is the only way path
    /// validation fails.
    path: bool = false,
    /// RFC 9001 §6.5: the read keys of the phase before were discarded.
    previous_keys: bool = false,
    /// RFC 9000 §4.1: the BLOCKED frames are owed again, and the next `send` carries them.
    blocked: bool = false,
};

/// Fires whichever deadlines `now_ns` has reached. `scratch` holds the packets the loss timer
/// declares lost. An error is `connection_recovery`'s, and the caller closes the connection with
/// `connection_recovery.connection_error_code`.
pub fn on_instant(
    connection: *Connection,
    suite: Suite,
    scratch: *connection_recovery.Scratch,
    now_ns: u64,
) connection_recovery.Error!Fired {
    var fired: Fired = .{};
    // RFC 9000 §10.1 closes the connection silently, and §10.2's period belongs to a connection
    // that closed deliberately, so the two cannot both be running.
    if (connection.termination.is_idle_timed_out(now_ns, idle_probe_timeout_ns(connection))) {
        connection.termination.on_idle_timeout();
        fired.idle = true;
    }
    const state_before = connection.termination.state;
    connection.termination.on_instant(now_ns);
    fired.period = connection.termination.state != state_before;
    fired.path = connection.path.on_instant(now_ns);
    const keys_before = connection.key_phase.previous_held;
    key_update.on_instant(connection, suite, now_ns);
    fired.previous_keys = keys_before and !connection.key_phase.previous_held;
    fired.blocked = fire_blocked(connection, now_ns);
    // Last, so an error leaves every other deadline fired. A connection the ones above closed
    // runs no loss detection (`connection_recovery.loss_deadline_ns`).
    fired.loss = try connection_recovery.on_loss_timer(connection, now_ns, scratch);
    assert(!fired.idle or !fired.period);
    return fired;
}

/// RFC 9000 §10.1's "current Probe Timeout", which the idle timeout is never less than three of.
/// It includes the peer's max_ack_delay, as the closing period's does (§10.2).
fn idle_probe_timeout_ns(connection: *const Connection) u64 {
    return connection.recovery.rtt.probe_timeout_ns(true);
}

/// Owes the BLOCKED frames again once their deadline has come (RFC 9000 §4.1).
fn fire_blocked(connection: *Connection, now_ns: u64) bool {
    const at_ns = connection_flow.blocked_deadline_ns(connection) orelse return false;
    if (now_ns < at_ns) return false;
    connection_flow.on_blocked_deadline(connection);
    return true;
}

/// One optional instant as a deadline of `kind`.
fn of(at_ns: ?u64, kind: Kind) ?Deadline {
    const held = at_ns orelse return null;
    return .{ .at_ns = held, .kind = kind };
}

/// The nearer of two deadlines, either of which may be absent. A tie keeps the one already held,
/// so the order `next` asks in is what breaks it and the answer is the same every run.
fn nearer(held: ?Deadline, other: ?Deadline) ?Deadline {
    const candidate = other orelse return held;
    const already = held orelse return candidate;
    return if (candidate.at_ns < already.at_ns) candidate else already;
}

test {
    _ = @import("connection_timer_test.zig");
}
