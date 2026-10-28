//! What the endpoint holds and what it owes its program (decision 119): the slots and their
//! connections, the slots a call changed, the soonest deadline, and each open request's word.
//! `receive` asks the slots in the ready ring for one event at a time, and each call by id finds
//! its connection through the slot's generation and its request through the slot's table. Every
//! request ends with one `done` or `cancelled` before its connection's `ended` (INV-30). What a
//! TCP slot does is in `endpoint_state_tcp.zig`, what a QUIC slot does in `endpoint_state_quic.zig`,
//! and what every slot does with its connection's events in `endpoint_state_events.zig`. `server.zig` does not export these files. Split out of
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
const endpoint_state_quic = @import("endpoint_state_quic.zig");
const endpoint_state_tcp = @import("endpoint_state_tcp.zig");

const QuicConnection = quic_connection.QuicConnection;
const Connection = connection_module.Connection;
const ReceiveStorage = quic_connection.ReceiveStorage;
const Sent = quic_connection.Sent;
const Event = event.Event;
const RequestId = event.RequestId;
const ConnectionHandle = event.ConnectionHandle;
const SendError = connection_errors.SendError;
const Entry = endpoint_requests.Entry;
const Wait = endpoint_requests.Wait;

pub const QuicTable = endpoint_state_quic.QuicTable;
pub const Datagram = endpoint_state_quic.Datagram;
pub const TcpTable = endpoint_state_tcp.TcpTable;
pub const Transport = endpoint_state_tcp.Transport;
pub const Accepted = endpoint_state_tcp.Accepted;
pub const StreamBytes = endpoint_state_tcp.StreamBytes;

/// What `receive` takes: nothing new, to read what the endpoint owes, octets a TCP connection's
/// socket read, or a datagram.
pub const Input = union(enum) {
    none,
    stream: StreamBytes,
    datagram: Datagram,
};

/// The arrays `EndpointOf` places, which the endpoint borrows: one entry for each slot, or for
/// each TCP or QUIC slot.
pub const Storage = struct {
    tcp: []Connection,
    tcp_tables: []TcpTable,
    transports: []Transport,
    send_outstanding: []bool,
    empty_read_ns: []?u64,
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

pub const State = struct {
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
    /// For each TCP slot, the instant of its connection's last `receive` when that call took no
    /// octet, reported nothing and left the protocol nothing read. A `receive` with no octets at
    /// that instant reads nothing again, so the endpoint does not make it. Null once a call
    /// changed the connection (`touch`).
    empty_read_ns: []?u64,
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
    pub fn init(state: *State, config: *const endpoint_config.Config, built: Built, storage: Storage, random: tls.Random, now_seconds: u64, now_ns: u64) void {
        assert(storage.tcp.len + storage.quic.len == storage.generations.len);
        assert(storage.tcp.len == storage.tcp_tables.len and storage.tcp.len == storage.transports.len);
        assert(storage.quic.len == storage.quic_tables.len and storage.tcp.len == storage.send_outstanding.len);
        assert(storage.generations.len == storage.failed.len and storage.failed.len == storage.room.len);
        assert(storage.tcp.len == storage.empty_read_ns.len);
        state.slots.init(storage.generations, storage.live, storage.free, @intCast(storage.tcp.len));
        state.tcp = storage.tcp;
        state.tcp_tables = storage.tcp_tables;
        state.transports = storage.transports;
        state.send_outstanding = storage.send_outstanding;
        state.empty_read_ns = storage.empty_read_ns;
        @memset(storage.empty_read_ns, null);
        state.tcp_configs = built.tcp;
        state.served = built.served;
        const quic_config = built.quic;
        state.connections.init(config, quic_config, storage.quic, storage.pools, &state.slots, random, now_seconds, now_ns);
        state.ready.init(storage.ready_numbers, storage.ready_queued);
        state.sendable.init(storage.send_numbers, storage.send_queued);
        state.heap.init(storage.cached, storage.position, storage.order, storage.stale_numbers, storage.stale_queued);
        state.quic_tables = storage.quic_tables;
        state.failed = storage.failed;
        state.room = storage.room;
        @memset(storage.room, 0);
        state.shutting_down = false;
        state.closed_reported = false;
        @memset(storage.failed, false);
    }

    /// Takes what `input` brings, then reports the next event any connection owes, if one does.
    pub fn receive(state: *State, input: Input, now_ns: u64) event.ReceiveResult {
        const consumed: usize = switch (input) {
            .none => 0,
            // The event `take_stream` reports comes first: the slot's own, or one its octets bring.
            .stream => |octets| taken: {
                const taken = endpoint_state_tcp.take_stream(state, octets, now_ns);
                if (taken.event != null) return taken;
                break :taken taken.consumed;
            },
            .datagram => |datagram| endpoint_state_quic.take_datagram(state, datagram, now_ns),
        };
        return .{ .consumed = consumed, .event = state.next_event(now_ns) };
    }

    /// Starts a connection on a TCP socket the program accepted, or returns null.
    pub fn accept(state: *State, socket: Accepted, now_ns: u64) ?ConnectionHandle {
        return endpoint_state_tcp.accept(state, socket, now_ns);
    }

    /// Writes what a TCP connection owes its socket into `output`.
    pub fn send_stream(state: *State, connection: ConnectionHandle, output: []u8, now_ns: u64) usize {
        return endpoint_state_tcp.send_stream(state, connection, output, now_ns);
    }

    /// A TCP connection's socket closed.
    pub fn transport_closed(state: *State, connection: ConnectionHandle) void {
        endpoint_state_tcp.transport_closed(state, connection);
    }

    /// Asks each slot in the ready ring for an event, the front first, and reports the first one
    /// a slot gives. A slot that gives one goes to the back; one that gives none leaves the ring.
    fn next_event(state: *State, now_ns: u64) ?Event {
        const queued = state.ready.len;
        // Bounded: each slot queued now is asked once.
        for (0..queued) |_| {
            const slot = state.ready.take() orelse break;
            const reported = state.poll(slot, now_ns) orelse continue;
            if (state.slots.live[slot]) state.ready.touch(slot);
            return reported;
        }
        return state.closed_event();
    }

    /// `closed`, once, when the program shut the endpoint down and no connection is left.
    fn closed_event(state: *State) ?Event {
        if (!state.shutting_down or state.closed_reported) return null;
        if (state.slots.holding() > 0) return null;
        state.closed_reported = true;
        return .closed;
    }

    /// The next event slot `slot` owes the program, asked of its kind of slot.
    fn poll(state: *State, slot: u32, now_ns: u64) ?Event {
        assert(state.slots.live[slot]);
        if (state.is_tcp(slot)) return endpoint_state_tcp.poll(state, slot, now_ns);
        return endpoint_state_quic.poll(state, slot, now_ns);
    }

    /// Writes the head of the response to request `id`. One with no room waits for `writable`.
    pub fn respond(state: *State, id: RequestId, response: event.Response) SendError!void {
        const slot = try state.request_slot(id);
        defer touch(state, slot);
        const answered = if (state.is_tcp(slot)) state.tcp[slot].respond(id.number, response) else state.connections.at(slot).respond(id.number, response);
        answered catch |failure| {
            if (failure == error.NoSpaceLeft) state.arm(slot, id.number, state.wait_for_head(slot, id.number, .head), 0);
            return failure;
        };
        state.unarm(slot, id.number);
    }

    /// Takes content of the response to request `id`. A take of less than the whole waits for
    /// `writable`.
    pub fn write_body(state: *State, id: RequestId, content: event.ResponseBody) SendError!usize {
        const slot = try state.request_slot(id);
        defer touch(state, slot);
        const written = if (state.is_tcp(slot)) state.tcp[slot].write_body(id.number, content) else state.connections.at(slot).write_body(id.number, content);
        const taken = written catch |failure| {
            if (failure == error.Blocked) state.arm(slot, id.number, .content, content.bytes.len);
            // h2's end of content alone, with no room for its frame.
            if (failure == error.NoSpaceLeft) state.arm(slot, id.number, state.wait_for_head(slot, id.number, .content), 0);
            return failure;
        };
        if (taken < content.bytes.len) state.arm(slot, id.number, .content, content.bytes.len - taken) else state.unarm(slot, id.number);
        return taken;
    }

    /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5). One with no room
    /// for its frame, or that waits for a coded response's last octets, waits for `writable`.
    pub fn write_trailers(state: *State, id: RequestId, fields: []const http.Field) SendError!void {
        const slot = try state.request_slot(id);
        defer touch(state, slot);
        const ended = if (state.is_tcp(slot)) state.tcp[slot].write_trailers(id.number, fields) else state.connections.at(slot).write_trailers(id.number, fields);
        ended catch |failure| {
            if (failure == error.Blocked) state.arm(slot, id.number, .trailers, 0);
            if (failure == error.NoSpaceLeft) state.arm(slot, id.number, state.wait_for_head(slot, id.number, .trailers), 0);
            return failure;
        };
        state.unarm(slot, id.number);
    }

    /// Notes that request `number` found no room for `wait`: its `writable` comes once the slot's
    /// room counter moves and the connection takes it.
    fn arm(state: *State, slot: u32, number: event.Number, wait: Wait, waiting_len: usize) void {
        const len = std.math.cast(u32, waiting_len) orelse std.math.maxInt(u32);
        const since = state.room[slot];
        if (state.is_tcp(slot)) {
            endpoint_state_tcp.table_of(state, slot).wait(number, since, wait, len);
        } else {
            endpoint_state_quic.table_of(state, slot).wait(number, since, wait, len);
        }
    }

    /// What a head or a trailer section that found no room waits for. A TCP connection writes it
    /// into its output alone, which takes it once empty; a QUIC slot's kind says.
    fn wait_for_head(state: *State, slot: u32, number: event.Number, wait: Wait) Wait {
        if (state.is_tcp(slot)) return .empty;
        return endpoint_state_quic.wait_for_head(state, slot, number, wait);
    }

    /// A write of request `number` found room, so the request waits for none.
    fn unarm(state: *State, slot: u32, number: event.Number) void {
        if (state.is_tcp(slot)) {
            const table = endpoint_state_tcp.table_of(state, slot);
            table.stop_waiting(table.find(number).?);
        } else {
            const table = endpoint_state_quic.table_of(state, slot);
            table.stop_waiting(table.find(number).?);
        }
    }

    /// Ends request `id` before its response is whole. Its `cancelled` follows, and nothing more of
    /// it. An id that names no open request is ignored.
    pub fn cancel(state: *State, id: RequestId) void {
        const slot = state.request_slot(id) catch return;
        if (state.is_tcp(slot)) state.tcp[slot].cancel(id.number) else state.connections.at(slot).cancel(id.number);
        if (state.is_tcp(slot)) endpoint_state_tcp.table_of(state, slot).owe_cancel(id.number) else endpoint_state_quic.table_of(state, slot).owe_cancel(id.number);
        touch(state, slot);
    }

    /// Sets the word each later event of request `id` carries.
    pub fn set_user_data(state: *State, id: RequestId, user_data: usize) error{RequestUnknown}!void {
        const slot = try state.request_slot(id);
        state.entry_of(slot, id.number).?.user_data = user_data;
    }

    /// Replaces one connection's limits (decision 110).
    pub fn set_timeouts(state: *State, connection: ConnectionHandle, deadlines: deadline.Timeouts) error{ TimeoutInvalid, ConnectionUnknown }!void {
        // RFC 9000 §10.2: "Once its closing or draining state ends, an endpoint SHOULD discard all
        // connection state", so the handle of a connection that ended names none.
        const slot = state.slots.resolve(connection) orelse return error.ConnectionUnknown;
        defer touch(state, slot);
        if (state.is_tcp(slot)) return state.tcp[slot].set_timeouts(deadlines);
        return state.connections.at(slot).set_timeouts(deadlines);
    }

    /// The server_name the connection's client sent (RFC 9846 §9.2), or null.
    pub fn server_name(state: *State, connection: ConnectionHandle) ?[]const u8 {
        const slot = state.slots.resolve(connection) orelse return null;
        if (state.is_tcp(slot)) return state.tcp[slot].server_name();
        return state.connections.at(slot).server_name();
    }

    /// Ends every connection once the requests it holds are answered, and starts no new one.
    /// `closed` follows once every connection has ended.
    pub fn shutdown(state: *State, now_ns: u64) void {
        state.shutting_down = true;
        // Bounded by the slots, once for the endpoint's life.
        for (state.slots.live, 0..) |live, slot| {
            if (!live) continue;
            const index: u32 = @intCast(slot);
            if (state.is_tcp(index)) {
                // A TCP connection's shutdown takes no instant, and observes it at the next call.
                state.tcp[index].shutdown();
                state.tcp[index].on_instant(now_ns);
            } else {
                state.connections.at(index).shutdown(now_ns);
            }
            touch(state, index);
        }
    }

    /// Writes into `output` the next datagram the endpoint owes, and names where it goes.
    pub fn send_datagram(state: *State, output: []u8, now_ns: u64) ?Sent {
        return endpoint_state_quic.send_datagram(state, output, now_ns);
    }

    /// The soonest instant any connection wants `on_instant` at, or null for none.
    pub fn deadline_ns(state: *State) ?u64 {
        state.heap.flush(state);
        return state.heap.soonest();
    }

    /// Fires the deadlines `now_ns` has reached, in the connections whose deadline it reached.
    pub fn on_instant(state: *State, now_ns: u64) void {
        state.heap.flush(state);
        // Bounded: each slot is taken once, and a slot fired is stale, which the heap holds no
        // more until the next flush.
        for (0..state.slots.live.len) |_| {
            const slot = state.heap.take_due(now_ns) orelse break;
            // INV-31: no call changed the slot since the flush, so it wants the instant the heap
            // held for it.
            assert(state.deadline_of(slot) == state.heap.cached[slot]);
            if (state.is_tcp(slot)) state.tcp[slot].on_instant(now_ns) else internal.on_instant(state.connections.at(slot), now_ns);
            touch(state, slot);
        }
    }

    /// The deadline of the connection in `slot`, read from that connection alone: what the heap
    /// recomputes a stale slot from.
    pub fn deadline_of(state: *State, slot: u32) ?u64 {
        if (!state.slots.live[slot]) return null;
        if (state.is_tcp(slot)) return state.tcp[slot].deadline_ns();
        return internal.deadline_ns(state.connections.at(slot));
    }

    /// The slot of the connection that holds request `id`, when the request is open and not
    /// cancelled by the program.
    fn request_slot(state: *State, id: RequestId) error{RequestUnknown}!u32 {
        // RFC 9110 §3.4: a response answers a request, so `id` names one still open.
        return state.open_slot(id) orelse error.RequestUnknown;
    }

    fn open_slot(state: *State, id: RequestId) ?u32 {
        const slot = state.slots.resolve(id.connection) orelse return null;
        const entry = state.entry_of(slot, id.number) orelse return null;
        if (entry.cancel_owed) return null;
        return slot;
    }

    /// The table entry of request `number` on `slot`, or null.
    fn entry_of(state: *State, slot: u32, number: event.Number) ?*Entry {
        if (state.is_tcp(slot)) return endpoint_state_tcp.table_of(state, slot).find(number);
        return endpoint_state_quic.table_of(state, slot).find(number);
    }

    fn is_tcp(state: *const State, slot: u32) bool {
        return state.slots.kind_of(slot) == .tcp;
    }
};

/// Notes that a call changed `slot`: it may owe the program an event, it may owe a datagram,
/// and its deadline may have moved. A TCP connection's `receive` may read something again.
pub fn touch(state: *State, slot: u32) void {
    state.ready.touch(slot);
    changed(state, slot);
    if (state.slots.kind_of(slot) == .tcp) state.empty_read_ns[slot] = null;
}

/// Notes that the connection in `slot` may owe octets, and that its deadline may have moved. A
/// QUIC slot goes in the ring `send_datagram` asks; a TCP slot's octets bring a `send` event.
pub fn changed(state: *State, slot: u32) void {
    state.heap.mark_stale(slot);
    if (state.slots.kind_of(slot) == .quic) state.sendable.touch(slot);
}

/// What `endpoint_config.build` filled, which the endpoint's connections borrow.
pub const Built = struct {
    quic: *const quic_connection.Config,
    tcp: *const endpoint_config.TcpConfigs,
    served: endpoint_config.Served,
};
