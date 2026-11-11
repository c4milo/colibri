//! When a server connection over TCP has finished, when its caller closes the transport, and why
//! colibri closed it, split off `connection.zig` because a hand-written source file stays at or
//! under 500 lines (CLAUDE.md).
const std = @import("std");
const assert = std.debug.assert;
const close_reason_module = @import("../close_reason.zig");
const connection_module = @import("connection.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");

const Connection = connection_module.Connection;
const CloseReason = close_reason_module.CloseReason;
const Limit = close_reason_module.Limit;

/// Whether the caller closes the transport now: the connection has finished and `send` has written
/// everything, over TLS the `close_notify` too (RFC 9846 §6.1), or the alert of a failure.
pub fn should_close(connection: *const Connection) bool {
    // Decision 110: once its linger has passed, a connection closes with octets still owed.
    if (connection.clock.lingered) return true;
    if (connection.output_len > 0) return false;
    return switch (connection.phase) {
        // Nothing is said before a protocol serves the connection, and a deadline closes it.
        .handshake, .choosing => false,
        .closed => true,
        .open => finished(connection) and
            (connection.config.tls == null or connection.close_sent or failure_sent(connection)) and
            // RFC 9112 §9.6: a staged close closes in full once its bound passes.
            (!staged(connection) or connection.clock.half_closed),
    };
}

/// Whether the connection closes in stages (RFC 9112 §9.6, decision 160): h11 closed after a
/// response with its request's body unread, and nothing else ended the connection.
pub fn staged(connection: *const Connection) bool {
    if (connection.phase != .open or connection.stopped or connection.peer_closed) return false;
    const session = switch (connection.session) {
        .h11 => |*session| session,
        .h2, .none => return false,
    };
    // A failure ends the connection at once: `connection_internal.fail` and a deadline's cut stop
    // it, so a session that failed never reaches this line.
    assert(session.failure == null);
    return session.phase == .closed and session.reader.open();
}

/// Whether the engine reports `half_close` now: the connection closes in stages, and the response
/// is out, over TLS with the `close_notify` (RFC 9846 §6.1).
pub fn should_half_close(connection: *const Connection) bool {
    if (connection.clock.half_close_since_ns != null or connection.output_len > 0) return false;
    if (!staged(connection) or !finished(connection)) return false;
    return connection.config.tls == null or connection.close_sent;
}

/// The engine reported `half_close` at `now_ns`, from which `half_close_ns` runs (decision 160).
pub fn half_close(connection: *Connection, now_ns: u64) void {
    assert(should_half_close(connection));
    connection.clock.half_close_since_ns = now_ns;
}

/// Whether the connection has nothing more to say but what `output` holds: it failed or was
/// stopped, its protocol closed, or it was asked to end and no request is open.
pub fn finished(connection: *const Connection) bool {
    if (connection.phase != .open) return connection.phase == .closed;
    // What the protocol owes, such as h11's error response or h2's GOAWAY, goes out first.
    if (protocol_pending(connection)) return false;
    if (connection.stopped) return true;
    const idle = switch (connection.session) {
        .h2 => connection_h2.idle(connection),
        .h11 => connection_h11.idle(connection),
        // An open connection has a protocol.
        .none => unreachable,
    };
    if (idle and (connection.shutting_down or connection.peer_closed)) return true;
    return switch (connection.session) {
        .h2 => connection.session.h2.has_failed() and !connection.session.h2.has_pending(),
        .h11 => connection.session.h11.should_close(),
        .none => unreachable,
    };
}

/// Whether the protocol owes octets `write_owed` has not written yet.
fn protocol_pending(connection: *const Connection) bool {
    return switch (connection.session) {
        .h2 => connection.session.h2.has_pending(),
        .h11 => connection.session.h11.has_pending(),
        .none => false,
    };
}

/// Whether the record layer failed and `send` has written the alert the provider owed.
fn failure_sent(connection: *const Connection) bool {
    return switch (connection.session) {
        // RFC 9846 §5.2 and §6.2: the connection ends with the alert, so it closes once the alert
        // is out.
        .h2 => connection.session.h2.tls_failed and !connection.session.h2.handshake_owed,
        .h11 => connection.session.h11.tls_failed and !connection.session.h11.handshake_owed,
        .none => false,
    };
}

/// Why colibri closed the connection on its own, or null (`close_reason.zig`).
pub fn close_reason(connection: *const Connection) ?CloseReason {
    const passed = connection.clock.timed_out orelse {
        const limit = passed_limit(connection) orelse return null;
        return .{ .limit = limit };
    };
    // A deadline stops the connection, which then opens no record and reads no frame, and a limit
    // the peer passed stops the deadlines: the two never both end one connection.
    assert(passed_limit(connection) == null);
    return .{ .timeout = passed };
}

/// The limit the peer passed, which ended the connection, or null.
fn passed_limit(connection: *const Connection) ?Limit {
    switch (connection.session) {
        // Each of h2's limits is the server's limit of the same name.
        .h2 => |*session| switch (session.failure_limit orelse return null) {
            inline else => |limit| return @field(Limit, @tagName(limit)),
        },
        // h11 names its failure with an error: the limit it keeps on records, or the provider's
        // limit on KeyUpdates.
        .h11 => |*session| {
            const failure = session.failure orelse return null;
            if (failure == error.RecordsWithoutData) return .records_without_data;
            if (failure == error.KeyUpdates) return .key_updates;
            return null;
        },
        .none => return null,
    }
}
