//! What the endpoint holds and what it owes its program (decision 119): the slots and their
//! connections, the slots a call changed, the soonest deadline, and each open request's word.
//! `receive` asks the slots in the ready ring for one event at a time, and each call by id finds
//! its connection through the slot's generation and its request through the slot's table. Every
//! request ends with one `done` or `cancelled` before its connection's `ended` (INV-30). `server.zig`
//! does not export this file. Split out of `endpoint.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const deadline = @import("../deadline.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const internal = @import("../quic/quic_connection_internal.zig");
const quic_connection_h3_room = @import("../quic/quic_connection_h3_room.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const endpoint_connections = @import("endpoint_connections.zig");
const endpoint_config = @import("endpoint_config.zig");
const endpoint_slots = @import("endpoint_slots.zig");
const endpoint_ready = @import("endpoint_ready.zig");
const endpoint_deadline_heap = @import("endpoint_deadline_heap.zig");
const endpoint_requests = @import("endpoint_requests.zig");

const QuicConnection = quic_connection.QuicConnection;
const ReceiveStorage = quic_connection.ReceiveStorage;
const PeerAddress = quic_connection.PeerAddress;
const Sent = quic_connection.Sent;
const Ecn = quic.connection_receive.Datagram.Ecn;
const Event = event.Event;
const Id = event.Id;
const ConnectionHandle = event.ConnectionHandle;
const SendError = connection_errors.SendError;
const Entry = endpoint_requests.Entry;
const Wait = endpoint_requests.Wait;

/// A QUIC slot's open requests: as many as a QUIC connection holds at once.
pub const QuicTable = endpoint_requests.Table(constants.quic_requests_max);

/// A datagram the UDP socket read, which the suite opens in place, with its ECN codepoint and the
/// address it came from (decision 72).
pub const Datagram = struct {
    octets: []u8,
    ecn: Ecn = .not_ect,
    from: PeerAddress,
};

/// What `receive` takes: nothing new, to read what the endpoint owes, or a datagram.
pub const Input = union(enum) {
    none,
    datagram: Datagram,
};

/// The arrays `EndpointOf` places, which the endpoint borrows: one entry for each slot, or for
/// each QUIC slot.
pub const Storage = struct {
    quic: []QuicConnection,
    pools: []const ReceiveStorage,
    quic_tables: []QuicTable,
    generations: []u32,
    live: []bool,
    free: []u32,
    failed: []bool,
    room: []u32,
    ready_numbers: []u32,
    ready_queued: []bool,
    send_numbers: []u32,
    send_queued: []bool,
    cached: []u64,
    position: []u32,
    order: []u32,
    stale_numbers: []u32,
    stale_queued: []bool,
};

pub const Held = struct {
    connections: endpoint_connections.Connections,
    slots: endpoint_slots.Slots,
    ready: endpoint_ready.Ready,
    /// The slots a call changed since `send_datagram` last found them owing no datagram: only a
    /// call changes what a connection owes.
    sendable: endpoint_ready.Ready,
    heap: endpoint_deadline_heap.DeadlineHeap,
    quic_tables: []QuicTable,
    /// Whether colibri closed each slot's connection because its peer broke a protocol rule.
    failed: []bool,
    /// Each slot's room counter, which moves with each datagram its connection takes: only the
    /// peer's acknowledgments free a response's runs and its ring (RFC 9000 §3.1). A request that
    /// found no room waits for the counter to move (`writable`).
    room: []u32,
    /// The program asked every connection to end, so no new one starts.
    shutting_down: bool,
    /// `closed` was reported once every connection had ended.
    closed_reported: bool,

    /// Holds no connection. The endpoint stays where it is: the slots' table and the connections
    /// hold pointers into it.
    pub fn init(held: *Held, config: *const endpoint_config.Config, quic_config: *const quic_connection.Config, storage: Storage, random: tls.Random, now_seconds: u64, now_ns: u64) void {
        assert(storage.quic.len == storage.quic_tables.len and storage.quic.len == storage.generations.len);
        assert(storage.generations.len == storage.failed.len and storage.failed.len == storage.room.len);
        held.slots.init(storage.generations, storage.live, storage.free, 0);
        held.connections.init(config, quic_config, storage.quic, storage.pools, &held.slots, random, now_seconds, now_ns);
        held.ready.init(storage.ready_numbers, storage.ready_queued);
        held.sendable.init(storage.send_numbers, storage.send_queued);
        held.heap.init(storage.cached, storage.position, storage.order, storage.stale_numbers, storage.stale_queued);
        held.quic_tables = storage.quic_tables;
        held.failed = storage.failed;
        held.room = storage.room;
        @memset(storage.room, 0);
        held.shutting_down = false;
        held.closed_reported = false;
        @memset(storage.failed, false);
    }

    /// Takes what `input` brings, then reports the next event any connection owes, if one does.
    pub fn receive(held: *Held, input: Input, now_ns: u64) event.Received {
        const consumed: usize = switch (input) {
            .none => 0,
            .datagram => |datagram| held.take_datagram(datagram, now_ns),
        };
        return .{ .consumed = consumed, .event = held.next_event(now_ns) };
    }

    fn take_datagram(held: *Held, datagram: Datagram, now_ns: u64) usize {
        const accepting = !held.shutting_down;
        const slot = held.connections.receive(datagram.octets, datagram.ecn, datagram.from, now_ns, accepting) orelse return datagram.octets.len;
        held.room[slot] +%= 1;
        held.touch(slot);
        return datagram.octets.len;
    }

    /// Asks each slot in the ready ring for an event, the front first, and reports the first one
    /// a slot gives. A slot that gives one goes to the back; one that gives none leaves the ring.
    fn next_event(held: *Held, now_ns: u64) ?Event {
        const queued = held.ready.len;
        // Bounded: each slot queued now is asked once.
        for (0..queued) |_| {
            const slot = held.ready.take() orelse break;
            const reported = held.poll(slot, now_ns) orelse continue;
            if (held.slots.live[slot]) held.ready.touch(slot);
            return reported;
        }
        return held.closed_event();
    }

    /// `closed`, once, when the program shut the endpoint down and no connection is left.
    fn closed_event(held: *Held) ?Event {
        if (!held.shutting_down or held.closed_reported) return null;
        if (held.slots.holding() > 0) return null;
        held.closed_reported = true;
        return .closed;
    }

    /// The next event slot `slot` owes the program: the program's own cancels first, then what its
    /// connection reports, then a `cancelled` for each request a stopped connection left open, and
    /// last its `ended`.
    fn poll(held: *Held, slot: u32, now_ns: u64) ?Event {
        assert(held.slots.live[slot]);
        // INV-31: the connection's `receive` fires and observes its deadlines (decision 110), which
        // can move them, and a read can owe the peer more credit.
        held.changed(slot);
        const handle = held.slots.handle_of(slot);
        const table = held.table_of(slot);
        if (owed_cancel(table)) |number| return ending(handle, table, number, .program);
        const connection = held.connections.at(slot);
        if (held.connection_event(slot, connection, table, now_ns)) |reported| return reported;
        if (connection.stopped) {
            // INV-30: a request the connection ended without an ending of its own ends here.
            if (table.first()) |entry| return ending(handle, table, entry.number, .closed);
        }
        if (held.writable_of(slot, table)) |entry| {
            return .{ .writable = .{ .id = .{ .connection = handle, .number = entry.number }, .user_data = entry.user_data } };
        }
        if (internal.ended(connection)) return held.end(slot, connection);
        return null;
    }

    /// The next event of the connection in `slot`, with its id naming the connection and its
    /// request's word. An event of a request the table does not hold is dropped.
    fn connection_event(held: *Held, slot: u32, connection: *QuicConnection, table: *QuicTable, now_ns: u64) ?Event {
        // Bounded: every event reads an octet the pool holds, or ends a request.
        for (0..constants.quic_events_per_read_max) |_| {
            const received = connection.receive(now_ns) catch {
                held.failed[slot] = true;
                continue;
            };
            const reported = received.event orelse return null;
            if (held.pass(slot, table, reported)) |passed| return passed;
        }
        // More events than one call reads: the slot comes back for the rest.
        held.ready.touch(slot);
        return null;
    }

    /// `reported`, as the program reads it, or null for an event of no request the table holds.
    fn pass(held: *Held, slot: u32, table: *QuicTable, reported: Event) ?Event {
        const handle = held.slots.handle_of(slot);
        switch (reported) {
            .request => |request| {
                var head = request;
                head.id.connection = handle;
                if (table.find(request.id.number) != null) return null;
                _ = table.add(request.id.number) orelse {
                    // The table holds as many requests as the connection, so this fails closed
                    // for a connection that held more: the request is refused, and never reported.
                    held.connections.at(slot).cancel(request.id.number);
                    return null;
                };
                return .{ .request = head };
            },
            .body => |body| {
                const entry = table.find(body.id.number) orelse return null;
                return .{ .body = .{ .id = id_on(handle, body.id), .user_data = entry.user_data, .octets = body.octets, .end = body.end } };
            },
            .trailers => |trailers| {
                const entry = table.find(trailers.id.number) orelse return null;
                return .{ .trailers = .{ .id = id_on(handle, trailers.id), .user_data = entry.user_data, .fields = trailers.fields } };
            },
            .done => |done| {
                const entry = table.find(done.id.number) orelse return null;
                const user_data = entry.user_data;
                table.remove(done.id.number);
                return .{ .done = .{ .id = id_on(handle, done.id), .user_data = user_data } };
            },
            .cancelled => |cancelled| {
                if (table.find(cancelled.id.number) == null) return null;
                return ending(handle, table, cancelled.id.number, cancelled.reason);
            },
            // A connection reports none of these: the endpoint does.
            .writable, .send, .close, .ended, .closed => unreachable,
        }
    }

    /// Ends the connection in `slot`, whose requests have all ended: its secrets are wiped, its log
    /// goes back, and the slot frees, its generation advancing.
    fn end(held: *Held, slot: u32, connection: *QuicConnection) Event {
        // INV-30: a connection stops before it ends, and a stopped one gave each of its requests
        // an ending first.
        assert(connection.stopped and held.table_of(slot).len() == 0);
        const handle = held.slots.handle_of(slot);
        const reason = connection.close_reason();
        const ended: event.Ended = .{ .connection = handle, .reason = reason, .failed = held.failed[slot] and reason == null };
        internal.transport_closed(connection);
        held.connections.close_log(connection);
        held.heap.forget(slot);
        held.ready.remove(slot);
        held.sendable.remove(slot);
        held.failed[slot] = false;
        held.slots.release(handle);
        return .{ .ended = ended };
    }

    /// Writes the head of the response to request `id`. One with no room waits for `writable`.
    pub fn respond(held: *Held, id: Id, response: event.Response) SendError!void {
        const slot = try held.request_slot(id);
        defer held.touch(slot);
        held.connections.at(slot).respond(id.number, response) catch |failure| {
            if (failure == error.NoSpaceLeft) held.arm(slot, id.number, held.wait_for_head(slot, id.number, .head));
            return failure;
        };
        held.unarm(slot, id.number);
    }

    /// Takes content of the response to request `id`. A take of less than the whole waits for
    /// `writable`.
    pub fn write_body(held: *Held, id: Id, content: event.Content) SendError!usize {
        const slot = try held.request_slot(id);
        defer held.touch(slot);
        const taken = held.connections.at(slot).write_body(id.number, content) catch |failure| {
            if (failure == error.Blocked) held.arm(slot, id.number, .content);
            return failure;
        };
        if (taken < content.octets.len) held.arm(slot, id.number, .content) else held.unarm(slot, id.number);
        return taken;
    }

    /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5). One with no room
    /// for its frame, or that waits for a coded response's last octets, waits for `writable`.
    pub fn write_trailers(held: *Held, id: Id, fields: []const http.Field) SendError!void {
        const slot = try held.request_slot(id);
        defer held.touch(slot);
        held.connections.at(slot).write_trailers(id.number, fields) catch |failure| {
            if (failure == error.Blocked) held.arm(slot, id.number, .trailers);
            if (failure == error.NoSpaceLeft) held.arm(slot, id.number, held.wait_for_head(slot, id.number, .trailers));
            return failure;
        };
        held.unarm(slot, id.number);
    }

    /// Notes that request `number` found no room for `wait`: its `writable` comes once the slot's
    /// room counter moves and the connection takes it.
    fn arm(held: *Held, slot: u32, number: event.Number, wait: Wait) void {
        const entry = held.table_of(slot).find(number).?;
        entry.waiting_since = held.room[slot];
        entry.waiting_for = wait;
    }

    /// A write of request `number` found room, so the request waits for none.
    fn unarm(held: *Held, slot: u32, number: event.Number) void {
        held.table_of(slot).find(number).?.waiting_since = null;
    }

    /// What a head or a trailer section that found no room waits for: a run, when its response
    /// held as many as it can, or else every run acknowledged, when the section was larger than
    /// the room its kept frames left, so that it either fits or is refused as too large.
    fn wait_for_head(held: *Held, slot: u32, number: event.Number, wait: Wait) Wait {
        return if (quic_connection_h3_room.takes_head(held.connections.at(slot), number)) .empty else wait;
    }

    /// The first request of `slot` whose wait the connection now takes, which waits no more. A
    /// request whose room counter moved and which the connection still cannot take waits for the
    /// next move, so `writable` comes once for each move of room at most.
    fn writable_of(held: *Held, slot: u32, table: *QuicTable) ?*Entry {
        const room = held.room[slot];
        const connection = held.connections.at(slot);
        var open = table.in_use.iterator(.{});
        // Bounded by the table's capacity.
        while (open.next()) |index| {
            const entry = &table.entries[index];
            const since = entry.waiting_since orelse continue;
            if (since == room) continue;
            if (!takes(connection, entry)) {
                entry.waiting_since = room;
                continue;
            }
            entry.waiting_since = null;
            return entry;
        }
        return null;
    }

    /// Ends request `id` before its response is whole. Its `cancelled` follows, and nothing more of
    /// it. An id that names no open request is ignored.
    pub fn cancel(held: *Held, id: Id) void {
        const slot = held.request_slot(id) catch return;
        held.connections.at(slot).cancel(id.number);
        held.table_of(slot).find(id.number).?.cancel_owed = true;
        held.touch(slot);
    }

    /// Sets the word each later event of request `id` carries.
    pub fn set_user_data(held: *Held, id: Id, user_data: usize) error{RequestUnknown}!void {
        const slot = try held.request_slot(id);
        held.table_of(slot).find(id.number).?.user_data = user_data;
    }

    /// Replaces one connection's limits (decision 110).
    pub fn set_deadlines(held: *Held, connection: ConnectionHandle, deadlines: deadline.Deadlines) error{ DeadlineInvalid, ConnectionUnknown }!void {
        // RFC 9000 §10.2: "Once its closing or draining state ends, an endpoint SHOULD discard all
        // connection state", so the handle of a connection that ended names none.
        const slot = held.slots.resolve(connection) orelse return error.ConnectionUnknown;
        defer held.touch(slot);
        return held.connections.at(slot).set_deadlines(deadlines);
    }

    /// The server_name the connection's client sent (RFC 9846 §9.2), or null.
    pub fn server_name(held: *Held, connection: ConnectionHandle) ?[]const u8 {
        const slot = held.slots.resolve(connection) orelse return null;
        return held.connections.at(slot).server_name();
    }

    /// Ends every connection once the requests it holds are answered, and starts no new one.
    /// `closed` follows once every connection has ended.
    pub fn shutdown(held: *Held, now_ns: u64) void {
        held.shutting_down = true;
        // Bounded by the slots, once for the endpoint's life.
        for (held.slots.live, 0..) |live, slot| {
            if (!live) continue;
            held.connections.at(@intCast(slot)).shutdown(now_ns);
            held.touch(@intCast(slot));
        }
    }

    /// Writes into `output` the next datagram the endpoint owes: a Version Negotiation or Retry
    /// packet first, then those of the connections a call changed, in turn. Null when it owes none.
    pub fn send_datagram(held: *Held, output: []u8, now_ns: u64) ?Sent {
        if (held.connections.replies.take(output)) |reply| return reply;
        // Bounded: each slot queued now is asked once.
        for (0..held.sendable.len) |_| {
            const slot = held.sendable.take() orelse break;
            // A slot leaves the ring when its connection ends.
            assert(held.slots.live[slot]);
            const connection = held.connections.at(slot);
            const sent = internal.send(connection, output, now_ns);
            // INV-31: a send moves the connection's timers, and may write a 100 (Continue) it
            // owed even when it sends nothing. One that failed owes the program its endings.
            held.heap.mark_stale(slot);
            if (connection.stopped) held.ready.touch(slot);
            const datagram = sent orelse continue;
            // A connection that sent may owe more: it is asked again after the others.
            held.sendable.touch(slot);
            return datagram;
        }
        return null;
    }

    /// The soonest instant any connection wants `on_instant` at, or null for none.
    pub fn deadline_ns(held: *Held) ?u64 {
        held.heap.flush(held);
        return held.heap.soonest();
    }

    /// Fires the deadlines `now_ns` has reached, in the connections whose deadline it reached.
    pub fn on_instant(held: *Held, now_ns: u64) void {
        held.heap.flush(held);
        // Bounded: each slot is taken once, and a slot fired is stale, which the heap holds no
        // more until the next flush.
        for (0..held.slots.live.len) |_| {
            const slot = held.heap.take_due(now_ns) orelse break;
            const connection = held.connections.at(slot);
            // INV-31: no call changed the slot since the flush, so it wants the instant the heap
            // held for it.
            assert(internal.deadline_ns(connection) == held.heap.cached[slot]);
            internal.on_instant(connection, now_ns);
            held.touch(slot);
        }
    }

    /// The deadline of the connection in `slot`, read from that connection alone: what the heap
    /// recomputes a stale slot from.
    pub fn deadline_of(held: *Held, slot: u32) ?u64 {
        if (!held.slots.live[slot]) return null;
        return internal.deadline_ns(held.connections.at(slot));
    }

    /// Notes that a call changed `slot`: it may owe the program an event, it may owe a datagram,
    /// and its deadline may have moved.
    fn touch(held: *Held, slot: u32) void {
        held.ready.touch(slot);
        held.changed(slot);
    }

    /// Notes that the connection in `slot` may owe a datagram, and that its deadline may have
    /// moved.
    fn changed(held: *Held, slot: u32) void {
        held.heap.mark_stale(slot);
        held.sendable.touch(slot);
    }

    /// The slot of the connection that holds request `id`, when the request is open and not
    /// cancelled by the program.
    fn request_slot(held: *Held, id: Id) error{RequestUnknown}!u32 {
        // RFC 9110 §3.4: a response answers a request, so `id` names one still open.
        return held.open_slot(id) orelse error.RequestUnknown;
    }

    fn open_slot(held: *Held, id: Id) ?u32 {
        const slot = held.slots.resolve(id.connection) orelse return null;
        const entry = held.table_of(slot).find(id.number) orelse return null;
        if (entry.cancel_owed) return null;
        return slot;
    }

    fn table_of(held: *Held, slot: u32) *QuicTable {
        assert(held.slots.kind_of(slot) == .quic);
        return &held.quic_tables[slot - held.slots.tcp_count];
    }
};

/// Whether `connection` now takes what request `entry` waits to write.
fn takes(connection: *QuicConnection, entry: *const Entry) bool {
    return switch (entry.waiting_for) {
        .head => quic_connection_h3_room.takes_head(connection, entry.number),
        .content => quic_connection_h3_room.takes_content(connection, entry.number),
        .trailers => quic_connection_h3_room.takes_trailers(connection, entry.number),
        .empty => quic_connection_h3_room.takes_any(connection, entry.number),
    };
}

/// The number of a request whose `cancelled` the program's own `cancel` owes, or null.
fn owed_cancel(table: *QuicTable) ?event.Number {
    var open = table.in_use.iterator(.{});
    // Bounded by the table's capacity.
    while (open.next()) |index| {
        if (table.entries[index].cancel_owed) return table.entries[index].number;
    }
    return null;
}

/// Request `number`'s `cancelled` for `reason`, which ends it: it leaves the table.
fn ending(handle: ConnectionHandle, table: *QuicTable, number: event.Number, reason: event.CancelReason) Event {
    const user_data = table.find(number).?.user_data;
    table.remove(number);
    return .{ .cancelled = .{ .id = .{ .connection = handle, .number = number }, .user_data = user_data, .reason = reason } };
}

/// `id`, naming the connection `handle` holds.
fn id_on(handle: ConnectionHandle, id: Id) Id {
    return .{ .connection = handle, .number = id.number };
}
