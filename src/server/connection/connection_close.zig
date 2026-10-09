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
            (connection.config.tls == null or connection.close_sent or failure_sent(connection)),
    };
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
    return .{ .deadline = passed };
}

/// The limit the peer passed, which ended the connection, or null.
fn passed_limit(connection: *const Connection) ?Limit {
    switch (connection.session) {
        // Each of h2's limits is the server's limit of the same name.
        .h2 => |*session| switch (session.failure_limit orelse return null) {
            inline else => |limit| return @field(Limit, @tagName(limit)),
        },
        // h11 names its failure with an error, and the one limit it keeps is on records.
        .h11 => |*session| {
            const failure = session.failure orelse return null;
            return if (failure == error.RecordsWithoutData) .records_without_data else null;
        },
        .none => return null,
    }
}
