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

/// What `accept` takes of a TCP socket the program accepted: whether its connection runs TLS,
/// which it does unless the program opts out with `.tls = false`.
pub const Accepted = struct { tls: bool = true };

/// Bytes a TCP connection's socket read, which chapulin may open in place.
pub const StreamBytes = struct { connection: ConnectionHandle, bytes: []u8 };

/// A TCP slot's open requests: as many as an h2 connection holds at once.
pub const TcpTable = endpoint_requests.Table(constants.tcp_requests_max, constants.tcp_request_number_step);

/// Whether a TCP slot's socket is open, or who closed it: the endpoint, with a `close` event, or
/// the program, with `transport_closed`.
pub const Transport = enum(u8) { open, closed_by_endpoint, closed_by_program };

/// Starts a connection on a socket the program accepted, in a free TCP slot, or returns null
/// when none is free, after `shutdown`, when `versions` allows no TCP version, or when chapulin
/// refuses to start its session. The program closes the socket on null.
pub fn accept(held: *Held, socket: Accepted, now_ns: u64) ?ConnectionHandle {
    assert(held.slots.tcp_count > 0);
    // An endpoint that serves no TCP version builds no TCP configuration to read.
    if (held.shutting_down or !held.served.tcp) return null;
    assert(!socket.tls or held.tcp_configs.secure.tls != null);
    const handle = held.slots.take(.tcp) orelse return null;
    const slot = handle.slot;
    const config = if (socket.tls) &held.tcp_configs.secure else &held.tcp_configs.cleartext;
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
/// event it reported, if any. The program's own cancels, then the `send` of octets the output
/// holds, come first, with nothing consumed. Octets of a handle that names no connection, or of a
/// connection that reads no more, are consumed and dropped, as a read that finished after `close`
/// is.
pub fn take_stream(held: *Held, input: StreamBytes, now_ns: u64) event.ReceiveResult {
    assert(input.connection.slot < held.slots.tcp_count);
    const dropped: event.ReceiveResult = .{ .consumed = input.bytes.len, .event = null };
    const slot = held.slots.resolve(input.connection) orelse return dropped;
    if (held.transports[slot] != .open) return dropped;
    const table = table_of(held, slot);
    // INV-30: the program's own cancel is reported before the input that might name its request
    // again, and the input waits for the next call.
    if (endpoint_held_events.owed_cancel(table)) |number| {
        endpoint_held.touch(held, slot);
        return .{ .consumed = 0, .event = endpoint_held_events.ending(input.connection, table, number, .program) };
    }
    if (send_first(held, slot)) |reported| return .{ .consumed = 0, .event = reported };
    // No octets, and nothing changed the connection since it read nothing at this instant: the
    // call would read nothing again, and the slot's last poll asked it everything else.
    if (input.bytes.len == 0 and reads_nothing(held, slot, now_ns)) return .{ .consumed = 0, .event = null };
    const connection = &held.tcp[slot];
    endpoint_held.touch(held, slot);
    const received = connection.receive(input.bytes, now_ns) catch {
        // The connection reads nothing more, and `ended` says it failed.
        held.failed[slot] = true;
        return dropped;
    };
    note_read(held, slot, received, now_ns);
    // A read may carry the peer's WINDOW_UPDATE, which gives a waiting response room.
    if (received.consumed > 0 or connection.plain_in_read > 0) held.room[slot] +%= 1;
    const consumed = if (connection_owed.reads_no_input(connection)) input.bytes.len else received.consumed;
    const reported = received.event orelse return .{ .consumed = consumed, .event = null };
    return .{ .consumed = consumed, .event = endpoint_held_events.pass(held, slot, table, reported, @This()) };
}

/// The next event TCP slot `slot` owes the program: the program's own cancels first, then the
/// `send` of octets its output holds, then what its connection reports, then a `cancelled` for each
/// request a stopped connection left open, then a `writable`, then `send` or `close`, and last its
/// `ended`.
pub fn poll(held: *Held, slot: u32, now_ns: u64) ?Event {
    // INV-31: the connection's `receive` fires and observes its deadlines (decision 110).
    endpoint_held.changed(held, slot);
    const handle = held.slots.handle_of(slot);
    const table = table_of(held, slot);
    if (endpoint_held_events.owed_cancel(table)) |number| return endpoint_held_events.ending(handle, table, number, .program);
    if (send_first(held, slot)) |reported| return reported;
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
        if (reads_nothing(held, slot, now_ns)) return null;
        const received = connection.receive(&.{}, now_ns) catch {
            held.failed[slot] = true;
            continue;
        };
        note_read(held, slot, received, now_ns);
        if (connection.plain_in_read > 0) held.room[slot] +%= 1;
        const reported = received.event orelse return null;
        if (endpoint_held_events.pass(held, slot, table, reported, @This())) |passed| return passed;
    }
    // More events than one call reads: the slot comes back for the rest.
    held.ready.touch(slot);
    return null;
}

/// The `send` of octets the output of the connection in `slot` holds, which the endpoint reports
/// before it reads the connection. A read observes the connection's deadlines, and an h2 stream's
/// send meter waits while the output holds octets (decision 110 as amended), so octets a write left
/// there for the program would pause the meter after each write, which then starts again with a
/// grace period, and a peer that opens its window an octet at a time would never be cut.
fn send_first(held: *Held, slot: u32) ?Event {
    if (held.transports[slot] != .open or held.send_outstanding[slot]) return null;
    if (held.tcp[slot].output_len == 0) return null;
    held.send_outstanding[slot] = true;
    return .{ .send = held.slots.handle_of(slot) };
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
    // A connection whose transport closed reports each response it wrote whole.
    held.empty_read_ns[slot] = null;
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
    // The request comes from a read that reported it, so no note says the connection read
    // nothing, and the cancel changes the connection before any `receive` that note would skip.
    assert(held.empty_read_ns[slot] == null);
    held.tcp[slot].cancel(number);
}

/// Whether the connection in `slot` read nothing at `now_ns`, and no call changed it since: a
/// `receive` with no octets now would read nothing again. Its deadlines fired and were observed at
/// that instant (decision 110), so the call would change none of them.
fn reads_nothing(held: *const Held, slot: u32, now_ns: u64) bool {
    const read_ns = held.empty_read_ns[slot] orelse return false;
    return read_ns == now_ns;
}

/// Notes whether the `receive` the connection in `slot` just made read nothing: it took no octet,
/// reported no event, and its protocol read none of the plaintext the connection holds. A call
/// that read something may leave more to read, such as h2 frames past `frames_per_receive_max`.
fn note_read(held: *Held, slot: u32, received: event.ConnectionResult, now_ns: u64) void {
    const read_nothing = received.consumed == 0 and received.event == null and held.tcp[slot].plain_in_read == 0;
    held.empty_read_ns[slot] = if (read_nothing) now_ns else null;
}

pub fn table_of(held: *Held, slot: u32) *TcpTable {
    assert(held.slots.kind_of(slot) == .tcp);
    return &held.tcp_tables[slot];
}
