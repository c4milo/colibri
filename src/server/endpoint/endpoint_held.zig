//! What the endpoint holds and what it owes its program (decision 119): the slots and their
//! connections, the slots a call changed, the soonest deadline, and each open request's word.
//! `receive` asks the slots in the ready ring for one event at a time, and each call by id finds
//! its connection through the slot's generation and its request through the slot's table. Every
//! request ends with one `done` or `cancelled` before its connection's `ended` (INV-30). What a
//! QUIC slot does is in `endpoint_held_quic.zig`, and what every slot does with its connection's
//! events in `endpoint_held_events.zig`. `server.zig` does not export these files. Split out of
//! `endpoint.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const quic = @import("quic");
const tls = @import("tls");
const event = @import("../event.zig");
const deadline = @import("../deadline.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const internal = @import("../quic/quic_connection_internal.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const endpoint_connections = @import("endpoint_connections.zig");
const endpoint_config = @import("endpoint_config.zig");
const endpoint_slots = @import("endpoint_slots.zig");
const endpoint_ready = @import("endpoint_ready.zig");
const endpoint_deadline_heap = @import("endpoint_deadline_heap.zig");
const endpoint_requests = @import("endpoint_requests.zig");
const endpoint_held_quic = @import("endpoint_held_quic.zig");

const QuicConnection = quic_connection.QuicConnection;
const ReceiveStorage = quic_connection.ReceiveStorage;
const Sent = quic_connection.Sent;
const Event = event.Event;
const Id = event.Id;
const ConnectionHandle = event.ConnectionHandle;
const SendError = connection_errors.SendError;
const Entry = endpoint_requests.Entry;
const Wait = endpoint_requests.Wait;

pub const QuicTable = endpoint_held_quic.QuicTable;
pub const Datagram = endpoint_held_quic.Datagram;

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
            .datagram => |datagram| endpoint_held_quic.take_datagram(held, datagram, now_ns),
        };
        return .{ .consumed = consumed, .event = held.next_event(now_ns) };
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

    /// The next event slot `slot` owes the program, asked of its kind of slot.
    fn poll(held: *Held, slot: u32, now_ns: u64) ?Event {
        assert(held.slots.live[slot]);
        return endpoint_held_quic.poll(held, slot, now_ns);
    }

    /// Writes the head of the response to request `id`. One with no room waits for `writable`.
    pub fn respond(held: *Held, id: Id, response: event.Response) SendError!void {
        const slot = try held.request_slot(id);
        defer touch(held, slot);
        held.connections.at(slot).respond(id.number, response) catch |failure| {
            if (failure == error.NoSpaceLeft) held.arm(slot, id.number, endpoint_held_quic.wait_for_head(held, slot, id.number, .head));
            return failure;
        };
        held.unarm(slot, id.number);
    }

    /// Takes content of the response to request `id`. A take of less than the whole waits for
    /// `writable`.
    pub fn write_body(held: *Held, id: Id, content: event.Content) SendError!usize {
        const slot = try held.request_slot(id);
        defer touch(held, slot);
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
        defer touch(held, slot);
        held.connections.at(slot).write_trailers(id.number, fields) catch |failure| {
            if (failure == error.Blocked) held.arm(slot, id.number, .trailers);
            if (failure == error.NoSpaceLeft) held.arm(slot, id.number, endpoint_held_quic.wait_for_head(held, slot, id.number, .trailers));
            return failure;
        };
        held.unarm(slot, id.number);
    }

    /// Notes that request `number` found no room for `wait`: its `writable` comes once the slot's
    /// room counter moves and the connection takes it.
    fn arm(held: *Held, slot: u32, number: event.Number, wait: Wait) void {
        const entry = held.entry_of(slot, number).?;
        entry.waiting_since = held.room[slot];
        entry.waiting_for = wait;
    }

    /// A write of request `number` found room, so the request waits for none.
    fn unarm(held: *Held, slot: u32, number: event.Number) void {
        held.entry_of(slot, number).?.waiting_since = null;
    }

    /// Ends request `id` before its response is whole. Its `cancelled` follows, and nothing more of
    /// it. An id that names no open request is ignored.
    pub fn cancel(held: *Held, id: Id) void {
        const slot = held.request_slot(id) catch return;
        held.connections.at(slot).cancel(id.number);
        held.entry_of(slot, id.number).?.cancel_owed = true;
        touch(held, slot);
    }

    /// Sets the word each later event of request `id` carries.
    pub fn set_user_data(held: *Held, id: Id, user_data: usize) error{RequestUnknown}!void {
        const slot = try held.request_slot(id);
        held.entry_of(slot, id.number).?.user_data = user_data;
    }

    /// Replaces one connection's limits (decision 110).
    pub fn set_deadlines(held: *Held, connection: ConnectionHandle, deadlines: deadline.Deadlines) error{ DeadlineInvalid, ConnectionUnknown }!void {
        // RFC 9000 §10.2: "Once its closing or draining state ends, an endpoint SHOULD discard all
        // connection state", so the handle of a connection that ended names none.
        const slot = held.slots.resolve(connection) orelse return error.ConnectionUnknown;
        defer touch(held, slot);
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
            touch(held, @intCast(slot));
        }
    }

    /// Writes into `output` the next datagram the endpoint owes, and names where it goes.
    pub fn send_datagram(held: *Held, output: []u8, now_ns: u64) ?Sent {
        return endpoint_held_quic.send_datagram(held, output, now_ns);
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
            touch(held, slot);
        }
    }

    /// The deadline of the connection in `slot`, read from that connection alone: what the heap
    /// recomputes a stale slot from.
    pub fn deadline_of(held: *Held, slot: u32) ?u64 {
        if (!held.slots.live[slot]) return null;
        return internal.deadline_ns(held.connections.at(slot));
    }

    /// The slot of the connection that holds request `id`, when the request is open and not
    /// cancelled by the program.
    fn request_slot(held: *Held, id: Id) error{RequestUnknown}!u32 {
        // RFC 9110 §3.4: a response answers a request, so `id` names one still open.
        return held.open_slot(id) orelse error.RequestUnknown;
    }

    fn open_slot(held: *Held, id: Id) ?u32 {
        const slot = held.slots.resolve(id.connection) orelse return null;
        const entry = held.entry_of(slot, id.number) orelse return null;
        if (entry.cancel_owed) return null;
        return slot;
    }

    /// The table entry of request `number` on `slot`, or null.
    fn entry_of(held: *Held, slot: u32, number: event.Number) ?*Entry {
        return endpoint_held_quic.table_of(held, slot).find(number);
    }
};

/// Notes that a call changed `slot`: it may owe the program an event, it may owe a datagram,
/// and its deadline may have moved.
pub fn touch(held: *Held, slot: u32) void {
    held.ready.touch(slot);
    changed(held, slot);
}

/// Notes that the connection in `slot` may owe a datagram, and that its deadline may have
/// moved.
pub fn changed(held: *Held, slot: u32) void {
    held.heap.mark_stale(slot);
    held.sendable.touch(slot);
}
