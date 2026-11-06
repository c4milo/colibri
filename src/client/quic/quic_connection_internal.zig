//! What a client QUIC connection's files and the pool call on it, and no program does (design §8
//! step 17f). `QuicConnection` keeps as methods the calls that the module's other files make.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../constants.zig");
const quic_connection = @import("quic_connection.zig");
const quic_h3 = @import("quic_connection_h3.zig");

const QuicConnection = quic_connection.QuicConnection;
const Config = quic_connection.Config;
const Parameters = quic.transport_parameters.Parameters;

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
    quic_h3.note_heads(connection);
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

/// The margin before the idle deadline RFC 9114 §5.1's rules act at: one PTO (RFC 9002 §6.2.1)
/// and at least `quic_idle_margin_ns_min`, as the owner ruled on 2026-09-28, and at most the
/// effective idle timeout `timeout_ns` over `quic_idle_margin_timeout_divisor`.
pub fn idle_margin_ns(transport: *const quic.Connection, timeout_ns: u64) u64 {
    const margin = @max(constants.policy.quic_idle_margin_ns_min, quic.connection_idle.probe_timeout_ns(transport));
    return @min(margin, timeout_ns / constants.policy.quic_idle_margin_timeout_divisor);
}

/// What the client grants the server (RFC 9000 §18.2): its receive pool of `capacity` octets for
/// the responses on the streams it opens, and h3's unidirectional streams (RFC 9114 §6.2).
pub fn parameters(config: *const Config, capacity: u64) Parameters {
    var held = Parameters.initial();
    // RFC 9000 §4.1: flow control keeps a sender within "a receiver's buffer capacity", and the
    // pool is all the client holds (decision 61), so no window grants more than it.
    held.initial_max_data = capacity;
    held.initial_max_stream_data_bidi_local = capacity;
    held.initial_max_stream_data_uni = @min(constants.policy.quic_stream_window, capacity);
    held.initial_max_streams_uni = h3.constants.limits.uni_streams_max;
    held.max_idle_timeout_ms = config.idle_timeout_ms;
    return held;
}
