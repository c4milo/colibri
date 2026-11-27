//! The bytes a server connection over TCP lends its socket (decision 176, design §8 step 79).
//! `lend` gives the socket what the connection owes, where the connection holds it, and `took`
//! drops what the socket's send took. In cleartext the bytes are the front of `output`. Over TLS
//! they are the records sealed into the TLS session's `sealed`, and `copy_sealed` hands those to
//! a program that sends from a copy. Split off `connection.zig`, which stays under 500 lines.
const std = @import("std");
const assert = std.debug.assert;
const connection_module = @import("connection.zig");
const connection_tls = @import("connection_tls.zig");
const connection_continue = @import("connection_continue.zig");
const connection_coding = @import("connection_coding.zig");
const connection_deadline = @import("connection_deadline.zig");
const connection_sends = @import("connection_sends.zig");
const internal = @import("connection_internal.zig");
const tls_session = @import("tls_session.zig");

const Connection = connection_module.Connection;
const TlsSession = tls_session.TlsSession;

/// Lends the socket what the connection owes it at `now_ns`. What the protocol owes is written
/// first, as `send` writes it. Over TLS it is sealed after the records that an earlier send left.
/// The bytes stay where they are until `took`, and the connection writes only after them. A
/// second lend before `took` returns the same bytes from the same front, and those written
/// since, for a socket that has not started its send.
pub fn lend(connection: *Connection, now_ns: u64) []const u8 {
    const lent_before = connection.lent_len;
    _ = connection_deadline.fire(connection, now_ns);
    _ = connection_continue.write(connection);
    _ = internal.write_owed(connection, now_ns);
    connection_coding.drain(connection);
    const owed = owed_octets(connection, now_ns);
    // Decision 176: a lend never moves or drops bytes an earlier one gave.
    assert(owed.len >= lent_before);
    connection.lent_len = owed.len;
    connection_deadline.observe(connection, now_ns);
    return owed;
}

/// The bytes the socket sends next: the output in cleartext, and over TLS the records sealed
/// from it after those a send left.
fn owed_octets(connection: *Connection, now_ns: u64) []const u8 {
    if (connection.config.tls == null) return connection.output[0..connection.output_len];
    const session = connection.tls_session.?;
    session.sealed_len += connection_tls.send(connection, session.sealed[session.sealed_len..], now_ns);
    return session.sealed[0..session.sealed_len];
}

/// The socket's send took the first `sent` of the bytes `lend` lent, at `now_ns`: 0 for a send
/// that failed or never went. They leave the front, and what is left moves there. The send meter
/// counts them before the deadlines fire (decision 110).
pub fn took(connection: *Connection, sent: usize, now_ns: u64) void {
    assert(sent <= connection.lent_len);
    connection.lent_len = 0;
    if (connection.config.tls == null) {
        internal.take_output(connection, sent);
    } else drop_sealed(connection.tls_session.?, sent);
    connection_sends.count(connection, sent);
    _ = connection_deadline.fire(connection, now_ns);
    connection_deadline.observe(connection, now_ns);
}

/// Over TLS, writes into `output` the records an earlier `lend` sealed and no send took, then
/// what `connection_tls.send` writes after them, and returns the bytes written.
pub fn copy_sealed(connection: *Connection, output: []u8, now_ns: u64) usize {
    const session = connection.tls_session.?;
    const copied = @min(output.len, session.sealed_len);
    @memcpy(output[0..copied], session.sealed[0..copied]);
    drop_sealed(session, copied);
    // Records left wait for the next call, so nothing is sealed in front of them.
    if (session.sealed_len > 0) return copied;
    return copied + connection_tls.send(connection, output[copied..], now_ns);
}

/// The bytes of `output` that no lend gave the socket: in cleartext those after the lent ones,
/// and over TLS all of them, since a lend seals them into the session's `sealed`. Once the
/// transport closed, the output holds none, and a send may still hold what it was lent.
pub fn unlent_len(connection: *const Connection) usize {
    if (connection.config.tls != null) return connection.output_len;
    assert(connection.phase == .closed or connection.lent_len <= connection.output_len);
    return connection.output_len -| connection.lent_len;
}

/// Whether records that a `lend` sealed wait for the socket.
pub fn sealed_owed(connection: *const Connection) bool {
    const session = connection.tls_session orelse return false;
    return session.sealed_len > 0;
}

/// Whether sealed records wait that no lend gave the socket: those a send left.
pub fn sealed_unlent(connection: *const Connection) bool {
    const session = connection.tls_session orelse return false;
    return session.sealed_len > connection.lent_len;
}

/// Drops the first `sent` sealed bytes, which a send took, and moves the rest to the front.
fn drop_sealed(session: *TlsSession, sent: usize) void {
    assert(sent <= session.sealed_len);
    @memmove(session.sealed[0 .. session.sealed_len - sent], session.sealed[sent..session.sealed_len]);
    session.sealed_len -= sent;
}
