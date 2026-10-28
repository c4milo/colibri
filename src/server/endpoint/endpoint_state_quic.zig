//! The QUIC slots of the server's endpoint (`endpoint_state.zig`, decision 119): what the endpoint
//! does with a datagram, the event a QUIC slot owes the program and in what order, how a QUIC
//! connection ends, and the datagrams the slots owe. Split out of `endpoint_state.zig` for length;
//! `server.zig` does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const internal = @import("../quic/quic_connection_internal.zig");
const quic_connection_h3_room = @import("../quic/quic_connection_h3_room.zig");
const endpoint_requests = @import("endpoint_requests.zig");
const endpoint_state = @import("endpoint_state.zig");
const endpoint_state_events = @import("endpoint_state_events.zig");

const State = endpoint_state.State;
const QuicConnection = quic_connection.QuicConnection;
const PeerAddress = quic_connection.PeerAddress;
const Sent = quic_connection.Sent;
const Ecn = quic.connection_receive.Datagram.Ecn;
const Event = event.Event;
const Entry = endpoint_requests.Entry;
const Wait = endpoint_requests.Wait;

/// A QUIC slot's open requests: as many as a QUIC connection holds at once.
pub const QuicTable = endpoint_requests.Table(constants.quic_requests_max, constants.quic_request_number_step);

/// A datagram the UDP socket read, which the suite opens in place, with its ECN codepoint and the
/// address it came from (decision 72).
pub const Datagram = struct {
    bytes: []u8,
    ecn: Ecn = .not_ect,
    from: PeerAddress,
};

/// Takes a datagram, which the connection its first packet names takes, or which starts one. A
/// datagram is taken whole.
pub fn take_datagram(state: *State, datagram: Datagram, now_ns: u64) usize {
    assert(state.quic_tables.len > 0);
    // An endpoint with no identity, or with h3 turned off, serves no QUIC connection.
    if (!state.served.quic) return datagram.bytes.len;
    const accepting = !state.shutting_down;
    const slot = state.connections.receive(datagram.bytes, datagram.ecn, datagram.from, now_ns, accepting) orelse return datagram.bytes.len;
    state.room[slot] +%= 1;
    endpoint_state.touch(state, slot);
    return datagram.bytes.len;
}

/// The next event QUIC slot `slot` owes the program: the program's own cancels first, then what
/// its connection reports, then a `cancelled` for each request a stopped connection left open,
/// then a `writable`, and last its `ended`.
pub fn poll(state: *State, slot: u32, now_ns: u64) ?Event {
    // INV-31: the connection's `receive` fires and observes its deadlines (decision 110), which
    // can move them, and a read can owe the peer more credit.
    endpoint_state.changed(state, slot);
    const handle = state.slots.handle_of(slot);
    const table = table_of(state, slot);
    if (endpoint_state_events.owed_cancel(table)) |number| return endpoint_state_events.ending(handle, table, number, .program);
    const connection = state.connections.at(slot);
    if (connection_event(state, slot, connection, table, now_ns)) |reported| return reported;
    if (connection.stopped) {
        // INV-30: a request the connection ended without an ending of its own ends here.
        if (table.first()) |entry| return endpoint_state_events.ending(handle, table, entry.number, .closed);
    }
    if (endpoint_state_events.writable_of(state, slot, table, @This())) |reported| return reported;
    if (internal.ended(connection)) return end(state, slot, connection);
    return null;
}

/// The next event of the connection in `slot` that a request of its table owns.
fn connection_event(state: *State, slot: u32, connection: *QuicConnection, table: *QuicTable, now_ns: u64) ?Event {
    // Bounded: every event reads an octet the pool holds, or ends a request.
    for (0..constants.quic_events_per_read_max) |_| {
        const received = connection.receive(now_ns) catch {
            state.failed[slot] = true;
            continue;
        };
        const reported = received.event orelse return null;
        if (endpoint_state_events.pass(state, slot, table, reported, @This())) |passed| return passed;
    }
    // More events than one call reads: the slot comes back for the rest.
    state.ready.touch(slot);
    return null;
}

/// Ends the connection in `slot`, whose requests have all ended: its secrets are wiped, its log
/// goes back, and the slot frees, its generation advancing.
fn end(state: *State, slot: u32, connection: *QuicConnection) Event {
    // INV-30: a connection stops before it ends, and a stopped one gave each of its requests an
    // ending first.
    assert(connection.stopped and table_of(state, slot).len() == 0);
    const handle = state.slots.handle_of(slot);
    const reason = connection.close_reason();
    const ended: event.Ended = .{ .connection = handle, .reason = reason, .failed = state.failed[slot] and reason == null };
    internal.transport_closed(connection);
    state.connections.close_log(connection);
    state.heap.forget(slot);
    state.ready.remove(slot);
    state.sendable.remove(slot);
    state.failed[slot] = false;
    state.slots.release(handle);
    return .{ .ended = ended };
}

/// Writes into `output` the next datagram the endpoint owes: a Version Negotiation or Retry
/// packet first, then those of the connections a call changed, in turn. Null when it owes none.
pub fn send_datagram(state: *State, output: []u8, now_ns: u64) ?Sent {
    if (state.connections.replies.take(output)) |reply| return reply;
    // Bounded: each slot queued now is asked once.
    for (0..state.sendable.len) |_| {
        const slot = state.sendable.take() orelse break;
        // A slot leaves the ring when its connection ends.
        assert(state.slots.live[slot]);
        const connection = state.connections.at(slot);
        const sent = internal.send(connection, output, now_ns);
        // INV-31: a send moves the connection's timers, and may write a 100 (Continue) it owed
        // even when it sends nothing. One that failed owes the program its endings.
        state.heap.mark_stale(slot);
        if (connection.stopped) state.ready.touch(slot);
        const datagram = sent orelse continue;
        // A connection that sent may owe more: it is asked again after the others.
        state.sendable.touch(slot);
        return datagram;
    }
    return null;
}

/// What a head or a trailer section that found no room waits for: a run, when its response held
/// as many as it can, or else every run acknowledged, when the section was larger than the room
/// its kept frames left, so that it either fits or is refused as too large.
pub fn wait_for_head(state: *State, slot: u32, number: event.Number, wait: Wait) Wait {
    return if (quic_connection_h3_room.takes_head(state.connections.at(slot), number)) .empty else wait;
}

/// Whether the connection in `slot` now takes what request `entry` waits to write.
pub fn takes(state: *State, slot: u32, entry: *const Entry) bool {
    const connection = state.connections.at(slot);
    return switch (entry.waiting_for) {
        .head => quic_connection_h3_room.takes_head(connection, entry.number),
        .content => quic_connection_h3_room.takes_content(connection, entry.number),
        .trailers => quic_connection_h3_room.takes_trailers(connection, entry.number),
        .empty => quic_connection_h3_room.takes_any(connection, entry.number),
    };
}

/// Refuses a request the slot's table has no room for.
pub fn refuse(state: *State, slot: u32, number: event.Number) void {
    state.connections.at(slot).cancel(number);
}

pub fn table_of(state: *State, slot: u32) *QuicTable {
    assert(state.slots.kind_of(slot) == .quic);
    return &state.quic_tables[slot - state.slots.tcp_count];
}
