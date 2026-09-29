//! What a caller reads of a connection's idle timeout (RFC 9000 §10.1), and the keep-alive RFC
//! 9000 §10.1.2 describes, for a caller that acts before the timeout: an HTTP/3 client opens a new
//! connection for new requests when one approaches it, and keeps one open while responses are
//! outstanding (RFC 9114 §5.1). Part of design §8 step 17g.
const std = @import("std");
const assert = std.debug.assert;
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;

/// The instant the idle timeout expires if nothing arrives or goes out first (RFC 9000 §10.1), or
/// null when none is armed. `connection_timer.next` names the same instant.
pub fn deadline_ns(connection: *const Connection) ?u64 {
    return connection.termination.idle_deadline_ns(probe_timeout_ns(connection));
}

/// The effective idle timeout (RFC 9000 §10.1): the smaller of the two sides' max_idle_timeout,
/// and at least three probe timeouts, or null when neither side set one.
pub fn timeout_ns(connection: *const Connection) ?u64 {
    const deadline = deadline_ns(connection) orelse return null;
    assert(deadline >= connection.termination.idle_since_ns);
    return deadline - connection.termination.idle_since_ns;
}

/// The current probe timeout (RFC 9002 §6.2.1), max_ack_delay counted, as the idle timeout reads
/// it: RFC 9000 §10.1 floors the timeout at three of them.
pub fn probe_timeout_ns(connection: *const Connection) u64 {
    return connection.recovery.rtt.probe_timeout_ns(true);
}

/// Has the next packet at the application level elicit an acknowledgment, carrying a PING when
/// nothing else in it does. RFC 9000 §10.1.2: "An endpoint might need to send ack-eliciting
/// packets to avoid an idle timeout if it is expecting response data but does not have or is
/// unable to send application data." The packet waits for the congestion window as any other
/// does (RFC 9002 §7), and any ack-eliciting packet at the level answers the call.
pub fn owe_keep_alive(connection: *Connection) void {
    // RFC 9000 §10.1: only an active connection has an idle timer to restart.
    assert(connection.termination.state == .active);
    // RFC 9001 §5.7: the application level carries nothing before the handshake completes.
    assert(connection.handshake_complete);
    connection.keep_alive_owed = true;
}

/// Whether the keep-alive the caller asked for has not gone out yet.
pub fn keep_alive_owed(connection: *const Connection) bool {
    return connection.keep_alive_owed;
}
