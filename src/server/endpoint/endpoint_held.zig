//! What the endpoint holds and what it owes its program (decision 119): the slots and their
//! connections, the slots a call changed, the soonest deadline, and each open request's word.
//! `receive` asks the slots in the ready ring for one event at a time, and each call by id finds
//! its connection through the slot's generation and its request through the slot's table. Every
//! request ends with one `done` or `cancelled` before its connection's `ended` (INV-30). What a
//! TCP slot does is in `endpoint_held_tcp.zig`, what a QUIC slot does in `endpoint_held_quic.zig`,
//! and what every slot does with its connection's events in `endpoint_held_events.zig`. `server.zig` does not export these files. Split out of
//! `endpoint.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const quic = @import("quic");
const tls = @import("tls");
const event = @import("../event.zig");
const deadline = @import("../deadline.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const connection_module = @import("../connection/connection.zig");
const internal = @import("../quic/quic_connection_internal.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const endpoint_connections = @import("endpoint_connections.zig");
const endpoint_config = @import("endpoint_config.zig");
const endpoint_slots = @import("endpoint_slots.zig");
const endpoint_ready = @import("endpoint_ready.zig");
const endpoint_deadline_heap = @import("endpoint_deadline_heap.zig");
const endpoint_requests = @import("endpoint_requests.zig");
const endpoint_held_quic = @import("endpoint_held_quic.zig");
const endpoint_held_tcp = @import("endpoint_held_tcp.zig");

const QuicConnection = quic_connection.QuicConnection;
const Connection = connection_module.Connection;
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
pub const TcpTable = endpoint_held_tcp.TcpTable;
pub const Transport = endpoint_held_tcp.Transport;
pub const Security = endpoint_held_tcp.Security;
pub const StreamOctets = endpoint_held_tcp.StreamOctets;

/// What `receive` takes: nothing new, to read what the endpoint owes, octets a TCP connection's
/// socket read, or a datagram.
pub const Input = union(enum) {
    none,
    stream: StreamOctets,
    datagram: Datagram,
};

/// The arrays `EndpointOf` places, which the endpoint borrows: one entry for each slot, or for
/// each TCP or QUIC slot.
pub const Storage = struct {
    tcp: []Connection,
    tcp_tables: []TcpTable,
    transports: []Transport,
    send_outstanding: []bool,
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
    /// Each TCP slot's connection, open requests, socket, and whether its `send` waits for the
    /// program's `send_stream`, at the slot's number.
    tcp: []Connection,
    tcp_tables: []TcpTable,
    transports: []Transport,
    send_outstanding: []bool,
    /// The configurations a TCP connection borrows, and the transports the endpoint serves.
    tcp_configs: *const endpoint_config.TcpConfigs,
    served: endpoint_config.Served,
    quic_tables: []QuicTable,
    /// Whether colibri closed each slot's connection because its peer broke a protocol rule.
    failed: []bool,
    /// Each slot's room counter, which moves with each call that may free room in its connection: a
    /// datagram, whose acknowledgments alone free a QUIC response's runs and ring (RFC 9000 §3.1),
    /// and a TCP read, which may carry a WINDOW_UPDATE, or send. A request that found no room
    /// waits for the counter to move (`writable`).
    room: []u32,
    /// The program asked every connection to end, so no new one starts.
    shutting_down: bool,
    /// `closed` was reported once every connection had ended.
    closed_reported: bool,

    /// Holds no connection. The endpoint stays where it is: the slots' table and the connections
    /// hold pointers into it.
    pub fn init(held: *Held, config: *const endpoint_config.Config, built: Built, storage: Storage, random: tls.Random, now_seconds: u64, now_ns: u64) void {
        assert(storage.tcp.len + storage.quic.len == storage.generations.len);
        assert(storage.tcp.len == storage.tcp_tables.len and storage.tcp.len == storage.transports.len);
        assert(storage.quic.len == storage.quic_tables.len and storage.tcp.len == storage.send_outstanding.len);
        assert(storage.generations.len == storage.failed.len and storage.failed.len == storage.room.len);
        held.slots.init(storage.generations, storage.live, storage.free, @intCast(storage.tcp.len));
        held.tcp = storage.tcp;
        held.tcp_tables = storage.tcp_tables;
        held.transports = storage.transports;
        held.send_outstanding = storage.send_outstanding;
        held.tcp_configs = built.tcp;
        held.served = built.served;
        const quic_config = built.quic;
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
            // A TCP connection reads its own octets first, and an event they bring comes first.
            .stream => |octets| taken: {
                const taken = endpoint_held_tcp.take_stream(held, octets, now_ns);
                if (taken.event != null) return taken;
                break :taken taken.consumed;
            },
            .datagram => |datagram| endpoint_held_quic.take_datagram(held, datagram, now_ns),
        };
        return .{ .consumed = consumed, .event = held.next_event(now_ns) };
    }

    /// Starts a connection on a TCP socket the program accepted, or returns null.
    pub fn accept(held: *Held, security: Security, now_ns: u64) ?ConnectionHandle {
        return endpoint_held_tcp.accept(held, security, now_ns);
    }

    /// Writes what a TCP connection owes its socket into `output`.
    pub fn send_stream(held: *Held, connection: ConnectionHandle, output: []u8, now_ns: u64) usize {
        return endpoint_held_tcp.send_stream(held, connection, output, now_ns);
    }

    /// A TCP connection's socket closed.
    pub fn transport_closed(held: *Held, connection: ConnectionHandle) void {
        endpoint_held_tcp.transport_closed(held, connection);
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
        if (held.is_tcp(slot)) return endpoint_held_tcp.poll(held, slot, now_ns);
        return endpoint_held_quic.poll(held, slot, now_ns);
    }

    /// Writes the head of the response to request `id`. One with no room waits for `writable`.
    pub fn respond(held: *Held, id: Id, response: event.Response) SendError!void {
        const slot = try held.request_slot(id);
        defer touch(held, slot);
        const answered = if (held.is_tcp(slot)) held.tcp[slot].respond(id.number, response) else held.connections.at(slot).respond(id.number, response);
        answered catch |failure| {
            if (failure == error.NoSpaceLeft) held.arm(slot, id.number, held.wait_for_head(slot, id.number, .head), 0);
            return failure;
        };
        held.unarm(slot, id.number);
    }

    /// Takes content of the response to request `id`. A take of less than the whole waits for
    /// `writable`.
    pub fn write_body(held: *Held, id: Id, content: event.Content) SendError!usize {
        const slot = try held.request_slot(id);
        defer touch(held, slot);
        const written = if (held.is_tcp(slot)) held.tcp[slot].write_body(id.number, content) else held.connections.at(slot).write_body(id.number, content);
        const taken = written catch |failure| {
            if (failure == error.Blocked) held.arm(slot, id.number, .content, content.octets.len);
            // h2's end of content alone, with no room for its frame.
            if (failure == error.NoSpaceLeft) held.arm(slot, id.number, held.wait_for_head(slot, id.number, .content), 0);
            return failure;
        };
        if (taken < content.octets.len) held.arm(slot, id.number, .content, content.octets.len - taken) else held.unarm(slot, id.number);
        return taken;
    }

    /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5). One with no room
    /// for its frame, or that waits for a coded response's last octets, waits for `writable`.
    pub fn write_trailers(held: *Held, id: Id, fields: []const http.Field) SendError!void {
        const slot = try held.request_slot(id);
        defer touch(held, slot);
        const ended = if (held.is_tcp(slot)) held.tcp[slot].write_trailers(id.number, fields) else held.connections.at(slot).write_trailers(id.number, fields);
        ended catch |failure| {
            if (failure == error.Blocked) held.arm(slot, id.number, .trailers, 0);
            if (failure == error.NoSpaceLeft) held.arm(slot, id.number, held.wait_for_head(slot, id.number, .trailers), 0);
            return failure;
        };
        held.unarm(slot, id.number);
    }

    /// Notes that request `number` found no room for `wait`: its `writable` comes once the slot's
    /// room counter moves and the connection takes it.
    fn arm(held: *Held, slot: u32, number: event.Number, wait: Wait, waiting_len: usize) void {
        const entry = held.entry_of(slot, number).?;
        entry.waiting_since = held.room[slot];
        entry.waiting_for = wait;
        entry.waiting_len = std.math.cast(u32, waiting_len) orelse std.math.maxInt(u32);
    }

    /// What a head or a trailer section that found no room waits for. A TCP connection writes it
    /// into its output alone, which takes it once empty; a QUIC slot's kind says.
    fn wait_for_head(held: *Held, slot: u32, number: event.Number, wait: Wait) Wait {
        if (held.is_tcp(slot)) return .empty;
        return endpoint_held_quic.wait_for_head(held, slot, number, wait);
    }

    /// A write of request `number` found room, so the request waits for none.
    fn unarm(held: *Held, slot: u32, number: event.Number) void {
        held.entry_of(slot, number).?.waiting_since = null;
    }

    /// Ends request `id` before its response is whole. Its `cancelled` follows, and nothing more of
    /// it. An id that names no open request is ignored.
    pub fn cancel(held: *Held, id: Id) void {
        const slot = held.request_slot(id) catch return;
        if (held.is_tcp(slot)) held.tcp[slot].cancel(id.number) else held.connections.at(slot).cancel(id.number);
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
        if (held.is_tcp(slot)) return held.tcp[slot].set_deadlines(deadlines);
        return held.connections.at(slot).set_deadlines(deadlines);
    }

    /// The server_name the connection's client sent (RFC 9846 §9.2), or null.
    pub fn server_name(held: *Held, connection: ConnectionHandle) ?[]const u8 {
        const slot = held.slots.resolve(connection) orelse return null;
        if (held.is_tcp(slot)) return held.tcp[slot].server_name();
        return held.connections.at(slot).server_name();
    }

    /// Ends every connection once the requests it holds are answered, and starts no new one.
    /// `closed` follows once every connection has ended.
    pub fn shutdown(held: *Held, now_ns: u64) void {
        held.shutting_down = true;
        // Bounded by the slots, once for the endpoint's life.
        for (held.slots.live, 0..) |live, slot| {
            if (!live) continue;
            const index: u32 = @intCast(slot);
            if (held.is_tcp(index)) {
                // A TCP connection's shutdown takes no instant, and observes it at the next call.
                held.tcp[index].shutdown();
                held.tcp[index].on_instant(now_ns);
            } else {
                held.connections.at(index).shutdown(now_ns);
            }
            touch(held, index);
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
            // INV-31: no call changed the slot since the flush, so it wants the instant the heap
            // held for it.
            assert(held.deadline_of(slot) == held.heap.cached[slot]);
            if (held.is_tcp(slot)) held.tcp[slot].on_instant(now_ns) else internal.on_instant(held.connections.at(slot), now_ns);
            touch(held, slot);
        }
    }

    /// The deadline of the connection in `slot`, read from that connection alone: what the heap
    /// recomputes a stale slot from.
    pub fn deadline_of(held: *Held, slot: u32) ?u64 {
        if (!held.slots.live[slot]) return null;
        if (held.is_tcp(slot)) return held.tcp[slot].deadline_ns();
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
        if (held.is_tcp(slot)) return endpoint_held_tcp.table_of(held, slot).find(number);
        return endpoint_held_quic.table_of(held, slot).find(number);
    }

    fn is_tcp(held: *const Held, slot: u32) bool {
        return held.slots.kind_of(slot) == .tcp;
    }
};

/// Notes that a call changed `slot`: it may owe the program an event, it may owe a datagram,
/// and its deadline may have moved.
pub fn touch(held: *Held, slot: u32) void {
    held.ready.touch(slot);
    changed(held, slot);
}

/// Notes that the connection in `slot` may owe octets, and that its deadline may have moved. A
/// QUIC slot goes in the ring `send_datagram` asks; a TCP slot's octets bring a `send` event.
pub fn changed(held: *Held, slot: u32) void {
    held.heap.mark_stale(slot);
    if (held.slots.kind_of(slot) == .quic) held.sendable.touch(slot);
}

/// What `endpoint_config.build` filled, which the endpoint's connections borrow.
pub const Built = struct {
    quic: *const quic_connection.Config,
    tcp: *const endpoint_config.TcpConfigs,
    served: endpoint_config.Served,
};
