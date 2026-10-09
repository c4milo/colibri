//! The TCP slots of the server's endpoint (`endpoint_held.zig`, decision 119): a connection the
//! program accepted, the octets its socket read, the event a TCP slot owes the program and in what
//! order, the octets its connection owes the socket, and how it closes and ends. The program owns
//! each socket: the endpoint names the slot in a `send` event when its connection owes octets, and
//! in a `close` event when the program closes the socket. Split out of `endpoint_held.zig` for
//! length; `server.zig` does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const connection_internal = @import("../connection/connection_internal.zig");
const connection_owed = @import("../connection/connection_owed.zig");
const endpoint_requests = @import("endpoint_requests.zig");
const endpoint_held = @import("endpoint_held.zig");
const endpoint_held_events = @import("endpoint_held_events.zig");

const Held = endpoint_held.Held;
const Connection = connection_module.Connection;
const Event = event.Event;
const ConnectionHandle = event.ConnectionHandle;
const Entry = endpoint_requests.Entry;

/// Whether a TCP connection the program accepted runs TLS.
pub const Security = enum { cleartext, tls };

/// Octets a TCP connection's socket read, which chapulin may open in place.
pub const StreamOctets = struct { connection: ConnectionHandle, octets: []u8 };

/// A TCP slot's open requests: as many as an h2 connection holds at once.
pub const TcpTable = endpoint_requests.Table(constants.tcp_requests_max);

/// Whether a TCP slot's socket is open, or who closed it: the endpoint, with a `close` event, or
/// the program, with `transport_closed`.
pub const Transport = enum(u8) { open, closed_by_endpoint, closed_by_program };

/// Starts a connection on a socket the program accepted, in a free TCP slot, or returns null
/// when none is free, after `shutdown`, when `versions` allows no TCP version, or when chapulin
/// refuses to start its session. The program closes the socket on null.
pub fn accept(held: *Held, security: Security, now_ns: u64) ?ConnectionHandle {
    assert(held.slots.tcp_count > 0);
    // An endpoint that serves no TCP version builds no TCP configuration to read.
    if (held.shutting_down or !held.served.tcp) return null;
    assert(security == .cleartext or held.tcp_configs.secure.tls != null);
    const handle = held.slots.take(.tcp) orelse return null;
    const slot = handle.slot;
    const config = switch (security) {
        .cleartext => &held.tcp_configs.cleartext,
        .tls => &held.tcp_configs.secure,
    };
    const seconds = held.connections.seconds_at(now_ns);
    held.tcp[slot].init(config, held.connections.random, seconds, now_ns) catch |failure| {
        // `init` refuses the versions and the limits `build` already took, so chapulin alone may
        // refuse here: it starts no session from the values (RFC 9846 §9.2).
        assert(failure == error.TlsRefused);
        held.slots.release(handle);
        return null;
    };
    table_of(held, slot).init();
    held.transports[slot] = .open;
    held.send_outstanding[slot] = false;
    held.failed[slot] = false;
    held.room[slot] = 0;
    endpoint_held.touch(held, slot);
    return handle;
}

/// Hands octets a socket read to the slot's connection, and returns what it consumed with the
/// event it reported, if any. Octets of a handle that names no connection, or of a connection that
/// reads no more, are consumed and dropped, as a read that finished after `close` is.
pub fn take_stream(held: *Held, input: StreamOctets, now_ns: u64) event.Received {
    assert(input.connection.slot < held.slots.tcp_count);
    const dropped: event.Received = .{ .consumed = input.octets.len, .event = null };
    const slot = held.slots.resolve(input.connection) orelse return dropped;
    if (held.transports[slot] != .open) return dropped;
    const table = table_of(held, slot);
    // INV-30: the program's own cancel is reported before the input that might name its request
    // again, and the input waits for the next call.
    if (endpoint_held_events.owed_cancel(table)) |number| {
        endpoint_held.touch(held, slot);
        return .{ .consumed = 0, .event = endpoint_held_events.ending(input.connection, table, number, .program) };
    }
    const connection = &held.tcp[slot];
    defer endpoint_held.touch(held, slot);
    const received = connection.receive(input.octets, now_ns) catch {
        // The connection reads nothing more, and `ended` says it failed.
        held.failed[slot] = true;
        return dropped;
    };
    // A read may carry the peer's WINDOW_UPDATE, which gives a waiting response room.
    if (received.consumed > 0 or connection.plain_in_read > 0) held.room[slot] +%= 1;
    const consumed = if (connection_owed.reads_no_input(connection)) input.octets.len else received.consumed;
    const reported = received.event orelse return .{ .consumed = consumed, .event = null };
    return .{ .consumed = consumed, .event = endpoint_held_events.pass(held, slot, table, reported, @This()) };
}

/// The next event TCP slot `slot` owes the program: the program's own cancels first, then what its
/// connection reports, then a `cancelled` for each request a stopped connection left open, then a
/// `writable`, then `send` or `close`, and last its `ended`.
pub fn poll(held: *Held, slot: u32, now_ns: u64) ?Event {
    // INV-31: the connection's `receive` fires and observes its deadlines (decision 110).
    endpoint_held.changed(held, slot);
    const handle = held.slots.handle_of(slot);
    const table = table_of(held, slot);
    if (endpoint_held_events.owed_cancel(table)) |number| return endpoint_held_events.ending(handle, table, number, .program);
    const connection = &held.tcp[slot];
    if (connection_event(held, slot, connection, table, now_ns)) |reported| return reported;
    if (connection_owed.stops_requests(connection)) {
        // INV-30: a request the connection ended without an ending of its own ends here.
        if (table.first()) |entry| return endpoint_held_events.ending(handle, table, entry.number, .closed);
    }
    if (endpoint_held_events.writable_of(held, slot, table, @This())) |reported| return reported;
    return transport_event(held, slot, connection);
}

/// The next event of the connection in `slot` that a request of its table owns. A connection
/// whose transport closed still reports the `done` of each response it wrote whole.
fn connection_event(held: *Held, slot: u32, connection: *Connection, table: *TcpTable, now_ns: u64) ?Event {
    // Bounded: every event ends a request, or reads a frame the plaintext holds.
    for (0..constants.tcp_events_per_poll_max) |_| {
        const received = connection.receive(&.{}, now_ns) catch {
            held.failed[slot] = true;
            continue;
        };
        if (connection.plain_in_read > 0) held.room[slot] +%= 1;
        const reported = received.event orelse return null;
        if (endpoint_held_events.pass(held, slot, table, reported, @This())) |passed| return passed;
    }
    // More events than one call reads: the slot comes back for the rest.
    held.ready.touch(slot);
    return null;
}

/// The slot's `send`, once for each debt, while the socket is open; its `close` once the
/// connection has finished; and its `ended` once the socket closed and every request ended.
fn transport_event(held: *Held, slot: u32, connection: *Connection) ?Event {
    const handle = held.slots.handle_of(slot);
    if (held.transports[slot] != .open) return end(held, slot, connection);
    if (!held.send_outstanding[slot] and connection_owed.owes_octets(connection)) {
        held.send_outstanding[slot] = true;
        return .{ .send = handle };
    }
    if (!connection.should_close()) return null;
    held.transports[slot] = .closed_by_endpoint;
    connection_internal.close_transport(connection);
    return .{ .close = handle };
}

/// Ends the connection in `slot`, whose socket closed and whose requests have all ended: the slot
/// frees, its generation advancing.
fn end(held: *Held, slot: u32, connection: *Connection) Event {
    // INV-30: a connection whose transport closed stopped, and gave each request an ending first.
    assert(connection.phase == .closed and table_of(held, slot).len() == 0);
    const handle = held.slots.handle_of(slot);
    const reason = connection.close_reason();
    const failed = (held.failed[slot] or connection_owed.record_failed(connection)) and reason == null;
    held.heap.forget(slot);
    held.ready.remove(slot);
    held.failed[slot] = false;
    held.send_outstanding[slot] = false;
    held.transports[slot] = .open;
    held.slots.release(handle);
    return .{ .ended = .{ .connection = handle, .reason = reason, .failed = failed } };
}

/// Writes into `output` what the connection `handle` names owes its socket, and returns the octets
/// written: 0 for a handle that names none, or a socket that closed. A call that leaves room in
/// `output` ends the `send`, and the next poll reports another while the connection owes more.
pub fn send_stream(held: *Held, handle: ConnectionHandle, output: []u8, now_ns: u64) usize {
    assert(handle.slot < held.slots.tcp_count);
    const slot = held.slots.resolve(handle) orelse return 0;
    if (held.transports[slot] != .open) return 0;
    const written = held.tcp[slot].send(output, now_ns);
    // A send writes a coded ring's octets out, which frees room for more of the response.
    held.room[slot] +%= 1;
    if (written < output.len) held.send_outstanding[slot] = false;
    endpoint_held.touch(held, slot);
    return written;
}

/// The program closed the socket of the connection `handle` names, or it failed: nothing more is
/// read or written. The `done` of each response written whole, the `cancelled` of each other
/// request and the connection's `ended` follow, and no `close`.
pub fn transport_closed(held: *Held, handle: ConnectionHandle) void {
    assert(handle.slot < held.slots.tcp_count);
    const slot = held.slots.resolve(handle) orelse return;
    if (held.transports[slot] != .open) return;
    connection_internal.close_transport(&held.tcp[slot]);
    held.transports[slot] = .closed_by_program;
    endpoint_held.touch(held, slot);
}

/// Whether the connection in `slot` now takes what request `entry` waits to write.
pub fn takes(held: *Held, slot: u32, entry: *const Entry) bool {
    const connection = &held.tcp[slot];
    return switch (entry.waiting_for) {
        .empty => connection_owed.takes_empty(connection),
        .content => connection_owed.takes_content(connection, entry.number, entry.waiting_len),
        .trailers => connection_owed.takes_trailers(connection, entry.number),
        // A TCP connection writes a head into its output alone, which an empty output takes.
        .head => unreachable,
    };
}

/// Refuses a request the slot's table has no room for.
pub fn refuse(held: *Held, slot: u32, number: event.Number) void {
    held.tcp[slot].cancel(number);
}

pub fn table_of(held: *Held, slot: u32) *TcpTable {
    assert(held.slots.kind_of(slot) == .tcp);
    return &held.tcp_tables[slot];
}
