//! What a server connection over TCP owes its transport, whether it reads or serves any more, and
//! whether it takes what a response waits to write, which the server's engine asks to report
//! `send`, `close` and `writable` and to end the requests a connection stopped serving (decision
//! 119). Split out of `connection.zig` for length;
//! `server.zig` does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("connection.zig");
const connection_close = @import("connection_close.zig");
const connection_coding = @import("connection_coding.zig");
const connection_h2 = @import("connection_h2.zig");
const connection_output = @import("connection_output.zig");
const internal = @import("connection_internal.zig");

const Connection = connection_module.Connection;
const Number = event.Number;

/// Whether `send` would write an octet now: what `send` writes, asked without writing it, in the
/// order `send` writes it.
pub fn should_send(connection: *Connection) bool {
    // Decision 176: records a lent output sealed, and a send left, go out first.
    if (connection_output.sealed_unlent(connection)) return true;
    // The TLS flight's records go out first, whatever else holds.
    if (connection.records_len > 0) return true;
    // Before a protocol serves the connection, and after it closed, `send` writes the flight alone.
    if (connection.phase != .open) return false;
    // RFC 9846 §6: after the record layer failed, the alert the provider owes is all that goes out.
    if (record_failed(connection)) return handshake_owed(connection);
    // RFC 9110 §10.1.1: the 100 a request expects is in the output already, because the engine
    // asks after a `receive`, which writes it.
    // Decision 176: octets a lend gave the socket are no debt of a new `send`.
    if (connection_output.unlent_len(connection) > 0) return true;
    if (protocol_pending(connection)) return true;
    if (connection_coding.ring_owed(connection)) return true;
    // RFC 9846 §6.1: "Each party MUST send a "close_notify" alert before closing its write side".
    return connection.config.tls != null and !connection.close_sent and connection_close.finished(connection);
}

/// Whether the connection reads no more of what the transport brings: it stopped or closed, the
/// peer's close_notify ended its data (RFC 9846 §6.1), or h11 closed (RFC 9112 §9.6).
pub fn reads_no_input(connection: *const Connection) bool {
    if (stops_requests(connection) or connection.peer_closed) return true;
    return connection.session == .h11 and connection.session.h11.phase == .closed;
}

/// Whether a `receive` with no octets can report an event or change the connection beyond its
/// deadlines (design §8 step 56). The engine polls a connection after each call that may have
/// changed it, and most such polls find nothing. Each source of an event that `receive_event`
/// reads without octets says true here. Only an open h11 connection in cleartext can say false;
/// every other connection reads as before.
pub fn reads_with_no_input(connection: *const Connection) bool {
    // h2, a connection with no protocol yet, and TLS's records and plaintext read from what
    // earlier calls left, so they read again. The test comes first, so h2 pays one compare.
    if (connection.session != .h11 or connection.config.tls != null) return true;
    // RFC 9110 §10.1.1: the 100 a request expects goes out on a call.
    if (connection.continue_owed != null) return true;
    // Decision 103: a response made whole since the last call is reported first.
    if (connection.done_owed.len > 0) return true;
    return h11_reads_with_no_input(connection, &connection.session.h11);
}

/// `reads_with_no_input` for h11 in cleartext, whose `receive` reads only the octets it is given.
/// With none, a head, a body, a discarded body and a tunnel read nothing: a body's decoder takes
/// only the octets of the call, and gives back what it could not decode, which then waits unread.
fn h11_reads_with_no_input(connection: *const Connection, session: *const h11.Connection) bool {
    // Decision 110: h2 alone ends a request on a body or send deadline and owes its `cancelled`
    // (`connection_bodies.cancel_stream`, `connection_sends.cancel_stream`).
    assert(connection.bodies.cancelled_len == 0);
    // A cleartext connection names h11 once its first octets chose it, and a closed one reads
    // nothing past the 100 and the `done` that the caller tested.
    assert(connection.phase == .open or connection.phase == .closed);
    // Decision 119 as amended: while octets wait unread, a call with none reads nothing.
    if (connection.unread_len > 0) return false;
    // The `end` of a body h11 read whole is owed with no octet.
    return session.end_owed;
}

/// Whether the connection serves no more of its requests: it stopped or closed. A peer that
/// closed its side after a request still waits for the response.
pub fn stops_requests(connection: *const Connection) bool {
    return connection.stopped or connection.phase == .closed;
}

/// Whether the record layer failed (RFC 9846 §6), which a seal that fails says with no error.
pub fn record_failed(connection: *const Connection) bool {
    return switch (connection.session) {
        .h2 => connection.session.h2.tls_failed,
        .h11 => connection.session.h11.tls_failed,
        .none => false,
    };
}

/// Whether the TLS provider owes handshake octets: the alert of a failure (RFC 9846 §6). The
/// provider writes the answer to a KeyUpdate only in front of the next record of data (RFC 9846
/// §4.7.3).
fn handshake_owed(connection: *const Connection) bool {
    return switch (connection.session) {
        .h2 => connection.session.h2.handshake_owed,
        .h11 => connection.session.h11.handshake_owed,
        .none => false,
    };
}

/// Whether the protocol owes octets `send` writes on its own: h2's preface and replies, or h11's
/// error response.
fn protocol_pending(connection: *const Connection) bool {
    return switch (connection.session) {
        .h2 => connection.session.h2.has_pending(),
        .h11 => connection.session.h11.has_pending(),
        .none => false,
    };
}

/// Whether the output holds nothing `send` has not taken: what a head or a trailer section that
/// found no room waits for.
pub fn takes_empty(connection: *const Connection) bool {
    return connection.output_len == 0;
}

/// Whether the response to request `id` takes more of the `waiting_len` octets of content its
/// program waits to write: room in a coded response's ring, a chunk's room in h11's output, or
/// what h2's windows let a DATA frame carry (RFC 9113 §6.9.1, decision 110's floor).
pub fn takes_content(connection: *Connection, id: Number, waiting_len: usize) bool {
    if (connection_coding.coded_of(connection, id)) |coded| {
        return !coded.finishing and coded.room_len(connection.config.encoders.?) > 0;
    }
    const room_len = internal.room(connection).len;
    return switch (connection.session) {
        // RFC 9112 §7.1: a chunk is its size line, its data and a CRLF, and the last chunk may
        // follow it.
        .h11 => |*session| if (session.writer.kind == .chunked)
            room_len > constants.limits.chunk_framing_len_max + constants.protocol.last_chunk_len
        else
            room_len > 0,
        .h2 => |*session| session.sendable_len(connection_h2.stream_of(id) catch return false, room_len, waiting_len) > 0,
        .none => false,
    };
}

/// Whether the response to request `id` takes its trailer section: an empty output, after a coded
/// response's ring wrote its last octets (RFC 9110 §6.5).
pub fn takes_trailers(connection: *Connection, id: Number) bool {
    const coded = connection_coding.coded_of(connection, id) orelse return takes_empty(connection);
    return coded.finished and coded.ring.held() == 0;
}
