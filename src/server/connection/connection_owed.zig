//! What a server connection over TCP owes its transport, whether it reads or serves any more, and
//! whether it takes what a response waits to write, which the server's endpoint asks to report
//! `send`, `close` and `writable` and to end the requests a connection stopped serving (decision
//! 119). Split out of `connection.zig` for length;
//! `server.zig` does not export this file.
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("connection.zig");
const connection_close = @import("connection_close.zig");
const connection_coding = @import("connection_coding.zig");
const connection_h2 = @import("connection_h2.zig");
const internal = @import("connection_internal.zig");

const Connection = connection_module.Connection;
const Number = event.Number;

/// Whether `send` would write an octet now: what `send` writes, asked without writing it, in the
/// order `send` writes it.
pub fn owes_octets(connection: *Connection) bool {
    // The TLS flight's records go out first, whatever else holds.
    if (connection.records_len > 0) return true;
    // Before a protocol serves the connection, and after it closed, `send` writes the flight alone.
    if (connection.phase != .open) return false;
    // RFC 9846 §6: after the record layer failed, the alert the provider owes is all that goes out.
    if (record_failed(connection)) return handshake_owed(connection);
    // RFC 9110 §10.1.1: the 100 a request expects is in the output already, because the endpoint
    // asks after a `receive`, which writes it.
    if (connection.output_len > 0) return true;
    if (protocol_pending(connection)) return true;
    // RFC 9846 §4.7.3: a KeyUpdate's reply goes out before the next record opens.
    if (connection.config.tls != null and handshake_owed(connection)) return true;
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

/// Whether the TLS provider owes handshake octets: a KeyUpdate's reply, or the alert of a failure.
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
            room_len > constants.chunk_framing_len_max + constants.last_chunk_len
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
