//! What the files of the server's TCP connection call on it between themselves, and no caller of
//! the module does: opening its protocol's session, reading the protocol, the room in its output,
//! and its failure. `server.zig` does not export this file, so a program reaches none of it
//! (design §8 step 17f).
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");
const connection_module = @import("connection.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");
const connection_bodies = @import("connection_bodies.zig");
const connection_config = @import("connection_config.zig");
const connection_coding = @import("connection_coding.zig");
const h2 = @import("h2");

const Connection = connection_module.Connection;
const Error = connection_module.Error;
const Protocol = event.Protocol;
const Received = event.Received;

/// The transport closed: nothing more is read or written, and over TLS the session's secrets are
/// wiped. The `done` of each response written whole stays owed, which a server's endpoint reports
/// before the connection's `ended` (INV-30); `Connection.transport_closed` drops them too. A
/// second call changes nothing.
pub fn close_transport(connection: *Connection) void {
    if (connection.phase == .open and connection.session == .h11) _ = connection.session.h11.transport_closed();
    connection.phase = .closed;
    connection.stopped = true;
    connection.output_len = 0;
    connection.records_len = 0;
    connection.update_held_len = 0;
    connection_coding.forget_all(connection);
    // chapulin's close wipes every secret, and is safe on a session that closed or failed.
    if (connection.config.tls != null) connection.tls_server.close();
}

/// Makes the protocol's connection, which then serves this one.
pub fn open_session(connection: *Connection, chosen: Protocol) void {
    switch (chosen) {
        .h2 => {
            connection.session = .{ .h2 = undefined };
            connection.session.h2.init(.server);
            connection.session.h2.data_frame_len_min = connection.config.limits.data_frame_len_min;
            connection.session.h2.limit_peer_streams(connection.config.limits.requests_max);
        },
        .h11 => {
            connection.session = .{ .h11 = undefined };
            connection.session.h11.init(.server, .{ .decoders = connection.config.decoders });
        },
        // RFC 9114 §3.1: h3 runs over QUIC alone, which `QuicConnection` serves.
        .h3 => unreachable,
    }
    connection.phase = .open;
    assert(connection.protocol().? == chosen);
    // A shutdown the caller asked for while the TLS handshake ran reaches the protocol now.
    if (connection.shutting_down) shut_session(connection);
}

/// Has the open protocol end the connection once its requests are answered: h2 sends GOAWAY (RFC
/// 9113 §6.8), and h11 closes after the current response (RFC 9112 §9.6).
pub fn shut_session(connection: *Connection) void {
    assert(connection.phase == .open);
    switch (connection.session) {
        .h2 => connection.session.h2.shutdown(h2.constants.error_no_error),
        .h11 => connection_h11.shutdown(connection),
        // An open connection has a protocol.
        .none => unreachable,
    }
}

/// Whether this connection's request bodies may arrive in units, which decision 110 as amended
/// bounds the body rate by: over TLS, in h2, or while its first octets may still choose h2. h11 in
/// cleartext reads a body octet by octet, so a connection that chose it keeps any rate.
pub fn whole_units(connection: *const Connection) bool {
    if (connection.config.tls != null) return true;
    return switch (connection.session) {
        .h2 => true,
        .h11 => false,
        .none => connection_config.whole_units(connection.config),
    };
}

/// Reads at most one event from the protocol's octets, and the octets before it that mean
/// nothing to the caller.
pub fn read_protocol(connection: *Connection, plaintext: []const u8, now_ns: u64) Error!Received {
    if (connection.stopped) return .{ .consumed = 0, .event = null };
    return switch (connection.session) {
        .h2 => connection_h2.receive(connection, plaintext, now_ns),
        .h11 => |*session| {
            const reading_body = session.phase == .body;
            const received = try connection_h11.receive(connection, plaintext);
            // Decision 110: the octets h11 reads of a body, its framing included, are the
            // body's.
            if (reading_body) connection_bodies.count(connection, connection.current_id, received.consumed);
            return received;
        },
        // `receive` reads the protocol only once the connection is open.
        .none => unreachable,
    };
}

/// Adds `written` octets the protocol owed to the output. When a WINDOW_UPDATE was owed, it is
/// among them.
pub fn take_owed(connection: *Connection, written: usize, update_owed: bool) void {
    connection.output_len += written;
    // Decision 110 as amended: a WINDOW_UPDATE written now is out once these octets are.
    if (update_owed and written > 0) connection.update_held_len = connection.output_len;
}

/// Ends the connection on a failure: nothing more is read, and what it owes goes out.
pub fn fail(connection: *Connection) Error {
    connection.stopped = true;
    // RFC 9113 §5.4.1, RFC 9112 §9.6 and RFC 9846 §6: after a connection error nothing more is
    // read, and the connection closes once what it owes is out.
    return error.ConnectionFailed;
}

/// Drops the first `written` octets of `output`, which `send` has taken.
pub fn take_output(connection: *Connection, written: usize) void {
    assert(written <= connection.output_len);
    std.mem.copyForwards(u8, &connection.output, connection.output[written..connection.output_len]);
    connection.output_len -= written;
    connection.records_len -= @min(connection.records_len, written);
    connection.update_held_len -= @min(connection.update_held_len, written);
}

/// Drops the protocol's octets the last event pointed into.
pub fn drop_read_plaintext(connection: *Connection) void {
    const read = connection.plain_in_read;
    assert(read <= connection.plain_in_len);
    std.mem.copyForwards(u8, &connection.plain_in, connection.plain_in[read..connection.plain_in_len]);
    connection.plain_in_len -= read;
    connection.plain_in_read = 0;
}

/// The room left in `output`.
pub fn room(connection: *Connection) []u8 {
    return connection.output[connection.output_len..];
}

/// Writes what the protocol owes on its own, such as its preface, the acknowledgments and a
/// GOAWAY, after what `output` holds. Returns whether it wrote anything. `send` calls it first.
pub fn write_owed(connection: *Connection, now_ns: u64) bool {
    if (connection.phase != .open) return false;
    const free = room(connection);
    const update_owed = connection.session == .h2 and connection.session.h2.owes_window_update();
    const written = switch (connection.session) {
        .h2 => connection.session.h2.write_pending(free, now_ns),
        .h11 => connection.session.h11.write_pending(free) catch 0,
        // An open connection has a protocol.
        .none => unreachable,
    };
    take_owed(connection, written, update_owed);
    return written > 0;
}
