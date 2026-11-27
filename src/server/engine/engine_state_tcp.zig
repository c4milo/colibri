//! The TCP slots of the server's engine (`engine_state.zig`, decision 119): a connection the
//! program accepted, the octets its socket read, the event a TCP slot owes the program and in what
//! order, the octets its connection owes the socket, and how it closes and ends. The program owns
//! each socket: the engine names the slot in a `send` event when its connection owes octets, and
//! in a `close` event when the program closes the socket. Split out of `engine_state.zig` for
//! length; `server.zig` does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const connection_internal = @import("../connection/connection_internal.zig");
const connection_owed = @import("../connection/connection_owed.zig");
const connection_close = @import("../connection/connection_close.zig");
const connection_output = @import("../connection/connection_output.zig");
const engine_requests = @import("engine_requests.zig");
const engine_state = @import("engine_state.zig");
const engine_state_events = @import("engine_state_events.zig");

const State = engine_state.State;
const Connection = connection_module.Connection;
const Event = event.Event;
const ConnectionHandle = event.ConnectionHandle;
const Entry = engine_requests.Entry;

/// What `accept` takes of a TCP socket the program accepted: whether its connection runs TLS,
/// which it does unless the program opts out with `.tls = false`.
pub const Accepted = struct { tls: bool = true };

/// Bytes a TCP connection's socket read, which chapulin may open in place.
pub const StreamBytes = struct { connection: ConnectionHandle, bytes: []u8 };

/// What `take_stream` took of its octets, and whether it wrote an event into the engine's
/// `event` (design §8 step 58).
pub const Taken = struct { consumed: usize, reported: bool };

/// A TCP slot's open requests: as many as an h2 connection holds at once.
pub const TcpTable = engine_requests.Table(constants.limits.tcp_requests_max, constants.protocol.tcp_request_number_step);

/// Whether a TCP slot's socket is open, or who closed it: the engine, with a `close` event, or
/// the program, with `transport_closed`.
pub const Transport = enum(u8) { open, closed_by_engine, closed_by_program };

/// Starts a connection on a socket the program accepted, in a free TCP slot, or returns null
/// when none is free, when no TLS session is free for a socket over TLS (decision 167), after
/// `shutdown`, when `versions` allows no TCP version, or when chapulin refuses to start its
/// session. The program closes the socket on null.
pub fn accept(state: *State, socket: Accepted, now_ns: u64) ?ConnectionHandle {
    assert(state.slots.tcp_count > 0);
    // An engine that serves no TCP version builds no TCP configuration to read.
    if (state.shutting_down or !state.served.tcp) return null;
    assert(!socket.tls or state.tcp_configs.secure.tls != null);
    // Decision 167: a connection over TLS runs in a session of the program's buffer, and none
    // is free while each is held.
    const session = if (socket.tls) (state.tls_sessions.take() orelse return null) else null;
    const handle = state.slots.take(.tcp) orelse {
        if (session) |taken| state.tls_sessions.put(taken);
        return null;
    };
    const slot = handle.slot;
    const config = if (socket.tls) &state.tcp_configs.secure else &state.tcp_configs.cleartext;
    const seconds = state.connections.seconds_at(now_ns);
    state.tcp[slot].init(config, session, seconds, now_ns) catch |failure| {
        // `init` refuses the versions and the limits `build` already took, so chapulin alone may
        // refuse here: it starts no session from the values (RFC 9846 §9.2).
        assert(failure == error.TlsRefused);
        if (session) |taken| state.tls_sessions.put(taken);
        state.slots.release(handle);
        return null;
    };
    table_of(state, slot).init();
    state.transports[slot] = .open;
    state.send_outstanding[slot] = false;
    state.failed[slot] = false;
    state.room[slot] = 0;
    engine_state.touch(state, slot);
    return handle;
}

/// Hands octets a socket read to the slot's connection, and returns what it consumed and whether
/// it wrote an event into the engine's `event`. The program's own cancels, then the `send` of
/// octets the output holds, come first, with nothing consumed. Octets of a handle that names no
/// connection, or of a connection that reads no more, are consumed and dropped, as a read that
/// finished after `close` is.
pub fn take_stream(state: *State, input: StreamBytes, now_ns: u64) Taken {
    assert(input.connection.slot < state.slots.tcp_count);
    const dropped: Taken = .{ .consumed = input.bytes.len, .reported = false };
    const slot = state.slots.resolve(input.connection) orelse return dropped;
    if (state.transports[slot] != .open) return dropped;
    const table = table_of(state, slot);
    // INV-30: the program's own cancel is reported before the input that might name its request
    // again, and the input waits for the next call.
    if (engine_state_events.owed_cancel(table)) |number| {
        engine_state.touch(state, slot);
        state.event = engine_state_events.ending(input.connection, table, number, .program);
        return .{ .consumed = 0, .reported = true };
    }
    if (send_first(state, slot)) return .{ .consumed = 0, .reported = true };
    // No octets, and nothing changed the connection since it read nothing at this instant: the
    // call would read nothing again, and the slot's last poll asked it everything else.
    if (input.bytes.len == 0 and reads_nothing(state, slot, now_ns)) return .{ .consumed = 0, .reported = false };
    const connection = &state.tcp[slot];
    engine_state.touch(state, slot);
    const received = connection.receive(input.bytes, now_ns) catch {
        // The connection reads nothing more, and `ended` says it failed.
        state.failed[slot] = true;
        return dropped;
    };
    note_read(state, slot, &received, now_ns);
    // A read may carry the peer's WINDOW_UPDATE, which gives a waiting response room.
    if (received.consumed > 0 or connection.plain_in_read > 0) state.room[slot] +%= 1;
    const consumed = if (connection_owed.reads_no_input(connection)) input.bytes.len else received.consumed;
    const reported = if (received.event) |*reported| reported else return .{ .consumed = consumed, .reported = false };
    return .{ .consumed = consumed, .reported = engine_state_events.pass(state, slot, table, reported, @This()) };
}

/// Writes the next event TCP slot `slot` owes the program into the engine's `event`, and returns
/// whether it owes one: the program's own cancels first, then the `send` of octets its output
/// holds, then what its connection reports, then a `cancelled` for each request a stopped
/// connection left open, then a `writable`, then `send` or `close`, and last its `ended`.
pub fn poll(state: *State, slot: u32, now_ns: u64) bool {
    // INV-31: the connection's `receive` fires and observes its deadlines (decision 110).
    engine_state.changed(state, slot);
    const handle = state.slots.handle_of(slot);
    const table = table_of(state, slot);
    if (engine_state_events.owed_cancel(table)) |number| {
        state.event = engine_state_events.ending(handle, table, number, .program);
        return true;
    }
    if (send_first(state, slot)) return true;
    const connection = &state.tcp[slot];
    if (connection_event(state, slot, connection, table, now_ns)) return true;
    if (connection_owed.stops_requests(connection)) {
        // INV-30: a request the connection ended without an ending of its own ends here.
        if (table.first()) |entry| {
            state.event = engine_state_events.ending(handle, table, entry.number, .closed);
            return true;
        }
    }
    if (engine_state_events.writable_of(state, slot, table, @This())) return true;
    return transport_event(state, slot, connection, now_ns);
}

/// Writes the next event of the connection in `slot` that a request of its table owns into the
/// engine's `event`, and returns whether one came. A connection whose transport closed still
/// reports the `done` of each response it wrote whole.
fn connection_event(state: *State, slot: u32, connection: *Connection, table: *TcpTable, now_ns: u64) bool {
    // Bounded: every event ends a request, or reads a frame the plaintext holds.
    for (0..constants.limits.tcp_events_per_poll_max) |_| {
        if (reads_nothing(state, slot, now_ns)) return false;
        const received = connection.receive(&.{}, now_ns) catch {
            state.failed[slot] = true;
            continue;
        };
        note_read(state, slot, &received, now_ns);
        if (connection.plain_in_read > 0) state.room[slot] +%= 1;
        const reported = if (received.event) |*reported| reported else return false;
        if (engine_state_events.pass(state, slot, table, reported, @This())) return true;
    }
    // More events than one call reads: the slot comes back for the rest.
    state.ready.touch(slot);
    return false;
}

/// The `send` of octets the output of the connection in `slot` holds, which the engine reports
/// before it reads the connection. A read observes the connection's deadlines, and an h2 stream's
/// send meter waits while the output holds octets (decision 110 as amended), so octets a write left
/// there for the program would pause the meter after each write, which then starts again with a
/// grace period, and a peer that opens its window an octet at a time would never be cut.
fn send_first(state: *State, slot: u32) bool {
    if (state.transports[slot] != .open or state.send_outstanding[slot]) return false;
    if (state.tcp[slot].output_len == 0) return false;
    state.send_outstanding[slot] = true;
    state.event = .{ .send = state.slots.handle_of(slot) };
    return true;
}

/// The slot's `send`, once for each debt, while the socket is open; its `half_close` at `now_ns`
/// once the response of a staged close is out; its `close` once the connection has finished; and
/// its `ended` once the socket closed and every request ended.
fn transport_event(state: *State, slot: u32, connection: *Connection, now_ns: u64) bool {
    const handle = state.slots.handle_of(slot);
    if (state.transports[slot] != .open) {
        // Decision 176: a send still reads what the connection lent, so the slot holds it.
        if (connection.lent_len > 0) return false;
        state.event = end(state, slot, connection);
        return true;
    }
    if (!state.send_outstanding[slot] and connection_owed.should_send(connection)) {
        state.send_outstanding[slot] = true;
        state.event = .{ .send = handle };
        return true;
    }
    // RFC 9112 §9.6: the write side closes first, and the bound runs from the event.
    if (connection_close.should_half_close(connection)) {
        connection_close.half_close(connection, now_ns);
        state.event = .{ .half_close = handle };
        return true;
    }
    if (!connection.should_close()) return false;
    state.transports[slot] = .closed_by_engine;
    connection_internal.close_transport(connection);
    // A connection whose transport closed reports each response it wrote whole.
    state.empty_read_ns[slot] = null;
    state.event = .{ .close = handle };
    return true;
}

/// Ends the connection in `slot`, whose socket closed and whose requests have all ended: the slot
/// frees, its generation advancing.
fn end(state: *State, slot: u32, connection: *Connection) Event {
    // INV-30: a connection whose transport closed stopped, and gave each request an ending first.
    assert(connection.phase == .closed and table_of(state, slot).len() == 0);
    const handle = state.slots.handle_of(slot);
    const reason = connection.close_reason();
    const failed = (state.failed[slot] or connection_owed.record_failed(connection)) and reason == null;
    state.heap.forget(slot);
    state.ready.remove(slot);
    state.failed[slot] = false;
    state.send_outstanding[slot] = false;
    state.transports[slot] = .open;
    // Decision 167: the slot gives its TLS session back. `close_transport` ran when the transport
    // closed, and its close wiped every secret, so none waits for the next connection.
    if (connection.tls_session) |session| state.tls_sessions.put(session);
    connection.tls_session = null;
    state.slots.release(handle);
    return .{ .ended = .{ .connection = handle, .reason = reason, .failed = failed } };
}

/// Writes into `output` what the connection `handle` names owes its socket, and returns the octets
/// written: 0 for a handle that names none, or a socket that closed. A call that leaves room in
/// `output` ends the `send`, and the next poll reports another while the connection owes more.
pub fn send_stream(state: *State, handle: ConnectionHandle, output: []u8, now_ns: u64) usize {
    assert(handle.slot < state.slots.tcp_count);
    const slot = state.slots.resolve(handle) orelse return 0;
    if (state.transports[slot] != .open) return 0;
    const written = state.tcp[slot].send(output, now_ns);
    // A send writes a coded ring's octets out, which frees room for more of the response.
    state.room[slot] +%= 1;
    if (written < output.len) state.send_outstanding[slot] = false;
    engine_state.touch(state, slot);
    return written;
}

/// Lends the program what the connection `handle` names owes its socket, where the connection
/// holds it (decision 176): empty for a handle that names none, or a socket that closed. The
/// octets stay in place until `sent_stream`.
pub fn output_stream(state: *State, handle: ConnectionHandle, now_ns: u64) []const u8 {
    assert(handle.slot < state.slots.tcp_count);
    const slot = state.slots.resolve(handle) orelse return &.{};
    if (state.transports[slot] != .open) return &.{};
    const owed = connection_output.lend(&state.tcp[slot], now_ns);
    // A lend writes a coded ring's octets out, which frees room for more of the response.
    state.room[slot] +%= 1;
    engine_state.touch(state, slot);
    return owed;
}

/// The send of what `output_stream` lent took its first `sent` octets. The rest stays owed, and
/// the next poll reports a `send` while the connection owes octets. After the socket closed, the
/// slot frees once this call came (decision 176).
pub fn sent_stream(state: *State, handle: ConnectionHandle, sent: usize, now_ns: u64) void {
    assert(handle.slot < state.slots.tcp_count);
    // The slot of a connection that lent octets frees only after this call, so only a call for
    // an empty lend can name a connection that has ended.
    const slot = state.slots.resolve(handle) orelse return assert(sent == 0);
    const connection = &state.tcp[slot];
    assert(sent <= connection.lent_len);
    if (state.transports[slot] == .open) {
        connection_output.took(connection, sent, now_ns);
        // What the send took frees room in the output for a response that waits.
        state.room[slot] +%= 1;
    } else connection.lent_len = 0;
    state.send_outstanding[slot] = false;
    engine_state.touch(state, slot);
}

/// The program closed the socket of the connection `handle` names, or it failed: nothing more is
/// read or written. The `done` of each response written whole, the `cancelled` of each other
/// request and the connection's `ended` follow, and no `close`.
pub fn transport_closed(state: *State, handle: ConnectionHandle) void {
    assert(handle.slot < state.slots.tcp_count);
    const slot = state.slots.resolve(handle) orelse return;
    if (state.transports[slot] != .open) return;
    connection_internal.close_transport(&state.tcp[slot]);
    state.transports[slot] = .closed_by_program;
    engine_state.touch(state, slot);
}

/// Whether the connection in `slot` now takes what request `entry` waits to write.
pub fn takes(state: *State, slot: u32, entry: *const Entry) bool {
    const connection = &state.tcp[slot];
    return switch (entry.waiting_for) {
        .empty => connection_owed.takes_empty(connection),
        .content => connection_owed.takes_content(connection, entry.number, entry.waiting_len),
        .trailers => connection_owed.takes_trailers(connection, entry.number),
        // A TCP connection writes a head into its output alone, which an empty output takes.
        .head => unreachable,
        // A TCP connection copies the content inside `write_body`, so it holds none to release.
        .release => unreachable,
    };
}

/// Refuses a request the slot's table has no room for.
pub fn refuse(state: *State, slot: u32, number: event.Number) void {
    // The request comes from a read that reported it, so no note says the connection read
    // nothing, and the cancel changes the connection before any `receive` that note would skip.
    assert(state.empty_read_ns[slot] == null);
    state.tcp[slot].cancel(number);
}

/// Whether the connection in `slot` read nothing at `now_ns`, and no call changed it since: a
/// `receive` with no octets now would read nothing again. Its deadlines fired and were observed at
/// that instant (decision 110), so the call would change none of them.
fn reads_nothing(state: *const State, slot: u32, now_ns: u64) bool {
    const read_ns = state.empty_read_ns[slot] orelse return false;
    return read_ns == now_ns;
}

/// Notes whether the `receive` the connection in `slot` just made read nothing: it took no octet,
/// reported no event, and its protocol read none of the plaintext the connection holds. A call
/// that read something may leave more to read, such as h2 frames past `frames_per_receive_max`.
fn note_read(state: *State, slot: u32, received: *const event.ConnectionResult, now_ns: u64) void {
    const read_nothing = received.consumed == 0 and received.event == null and state.tcp[slot].plain_in_read == 0;
    state.empty_read_ns[slot] = if (read_nothing) now_ns else null;
}

pub fn table_of(state: *State, slot: u32) *TcpTable {
    assert(state.slots.kind_of(slot) == .tcp);
    return &state.tcp_tables[slot];
}
