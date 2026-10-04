//! What the files of the client's TCP connection call on it between themselves, and no caller of
//! the module does: opening its protocol's session, reading the protocol, the room in its output,
//! what it owes the caller, and its failure. `client.zig` does not export this file, so a program
//! reaches none of it (design §8 step 17f).
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");
const alt_svc = @import("../alt_svc.zig");
const connection_module = @import("connection.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");

const Connection = connection_module.Connection;
const Protocol = event.Protocol;

/// Makes the protocol's connection, which then serves this one.
pub fn open_session(connection: *Connection, chosen: Protocol) void {
    switch (chosen) {
        .h2 => {
            connection.session = .{ .h2 = undefined };
            connection.session.h2.init(.client);
        },
        .h11 => {
            connection.session = .{ .h11 = undefined };
            connection.session.h11.init(.client, .{});
        },
        // h3 runs over QUIC (`QuicConnection`), never over this connection's TCP.
        .h3 => unreachable,
    }
    connection.phase = .open;
    connection.owed.connected = true;
    assert(connection.protocol().? == chosen);
}

/// Reads the protocol's octets until an exchange ends, or the octets run out, and returns
/// the octets taken.
pub fn read_protocol(connection: *Connection, plaintext: []const u8, now_ns: u64) usize {
    if (connection.stopped) return 0;
    return switch (connection.session) {
        .h2 => connection_h2.receive(connection, plaintext, now_ns),
        .h11 => connection_h11.receive(connection, plaintext),
        // `receive` reads the protocol only once the connection is open.
        .none => unreachable,
    };
}

/// Takes the ticket the server issued, if any, and owes the caller its event. Over TLS only.
pub fn collect_ticket(connection: *Connection) void {
    assert(connection.config.tls != null);
    const issued = connection.tls_client.take_ticket() orelse return;
    wipe_ticket(connection);
    connection.ticket = issued;
    connection.owed.ticket = true;
}

pub fn wipe_ticket(connection: *Connection) void {
    if (connection.ticket) |*held| held.wipe();
    connection.ticket = null;
    connection.owed.ticket = false;
}

/// Keeps what the Alt-Svc lines of a final response's `section` say, from its regular line
/// `first` on.
pub fn note_alt_svc(connection: *Connection, section: *const http.FieldSection, first: u32) void {
    // RFC 9114 §3.1.2: h3 cannot reach an "http" origin, which a cleartext connection serves.
    if (connection.config.tls == null) return;
    const host = alt_svc.host_of(connection.config.authority);
    connection.alt_svc = alt_svc.from_section(section, first, host) orelse return;
}

/// Takes no new request from here on, and owes the caller the `draining` event.
pub fn start_draining(connection: *Connection) void {
    if (connection.draining) return;
    connection.draining = true;
    connection.owed.draining = true;
}

/// Ends the connection on a failure: every exchange it holds ends, nothing more is read, and
/// what it owes goes out.
pub fn fail(connection: *Connection) void {
    // RFC 9113 §5.4.1, RFC 9112 §9.6 and RFC 9846 §6: after a connection error nothing more is
    // read, and the connection closes once what it owes is out.
    connection.stopped = true;
    connection.failed = true;
    connection.slots.end_all(.refused, .closed);
    assert(connection.slots.idle());
}

/// Whether the protocol owes octets `write_owed` has not written yet.
pub fn protocol_pending(connection: *const Connection) bool {
    return switch (connection.session) {
        .h2 => connection.session.h2.has_pending(),
        .h11 => connection.session.h11.has_pending(),
        .none => false,
    };
}

/// Drops the first `written` octets of `output`, which `send` has taken.
pub fn take_output(connection: *Connection, written: usize) void {
    assert(written <= connection.output_len);
    std.mem.copyForwards(u8, &connection.output, connection.output[written..connection.output_len]);
    connection.output_len -= written;
    connection.records_len -= @min(connection.records_len, written);
}

/// Drops the first `read` octets of the protocol's plaintext, which the protocol has taken.
pub fn take_plaintext(connection: *Connection, read: usize) void {
    assert(read <= connection.plain_in_len);
    std.mem.copyForwards(u8, &connection.plain_in, connection.plain_in[read..connection.plain_in_len]);
    connection.plain_in_len -= read;
}

/// The room left in `output`.
pub fn room(connection: *Connection) []u8 {
    return connection.output[connection.output_len..];
}

/// Whether the connection has nothing more to write but what `output` holds and, over TLS,
/// its `close_notify`.
pub fn finished(connection: *const Connection) bool {
    return connection.owed.closed_reported and !protocol_pending(connection);
}

/// Writes what the protocol owes on its own, such as its preface, the acknowledgments and a
/// GOAWAY, after what `output` holds. Returns whether it wrote anything. `send` calls it first.
pub fn write_owed(connection: *Connection, now_ns: u64) bool {
    if (connection.phase != .open) return false;
    const free = room(connection);
    const written = switch (connection.session) {
        .h2 => connection.session.h2.write_pending(free, now_ns),
        .h11 => connection.session.h11.write_pending(free) catch 0,
        // An open connection has a protocol.
        .none => unreachable,
    };
    connection.output_len += written;
    return written > 0;
}
