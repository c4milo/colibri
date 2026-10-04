//! What a client QUIC connection's other files and the channel call on it, and no program does
//! (design §8 step 17f). The module's root exports none of these, so `QuicConnection` keeps as
//! methods only the calls a program makes.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const quic_connection = @import("quic_connection.zig");

const QuicConnection = quic_connection.QuicConnection;

/// Takes no new request from here on, and owes the caller the `draining` event.
pub fn start_draining(connection: *QuicConnection) void {
    if (connection.draining) return;
    connection.draining = true;
    connection.owed.draining = true;
}

/// Ends the connection on a failure: every exchange it holds ends, and what QUIC owes, such as
/// its CONNECTION_CLOSE, still goes out.
pub fn fail(connection: *QuicConnection) void {
    connection.stopped = true;
    connection.failed = true;
    const transport = &connection.transport;
    // RFC 9000 §10.2: an active connection that ends owes its CONNECTION_CLOSE, unless h3 or
    // QUIC already owes one. The loss timer's refusals owe none, and RFC 9000 §20.1 closes
    // them with INTERNAL_ERROR.
    if (transport.termination.state == .active and !quic.connection_close.owes(transport)) {
        quic.connection_close.owe(transport, quic.connection_close.transport(quic.error_code.internal_error, null));
    }
    // RFC 9000 §10.2.1: a connection that closes sends only its CONNECTION_CLOSE from here on,
    // so no stream reads an exchange's octets again.
    for (&connection.slots.slots) |*slot| slot.holds_octets = false;
    connection.slots.end_all(.refused, .closed);
    assert(connection.slots.idle());
}

/// Owes the server a CONNECTION_CLOSE carrying h3's `code` (RFC 9000 §10.2, RFC 9114 §8).
pub fn close_quic(connection: *QuicConnection, code: u64) void {
    quic.connection_close.owe(&connection.transport, .{
        .layer = .application,
        .error_code = code,
        // RFC 9000 §19.19: only a transport close carries the Frame Type field.
        .frame_type = null,
        .reason = "",
    });
}
