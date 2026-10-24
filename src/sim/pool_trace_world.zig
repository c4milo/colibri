//! The world of the pool trace run (decision 105 as decision 125 extends it, design §8 step 22): a
//! `client.ConnectionPoolOf(.{ .quic = false })` of two or three TCP slots, which speaks h11 in cleartext,
//! and a `server.Endpoint` that accepts each connection the pool opens and answers each request
//! as the seed's plan says. Each slot has a socket: a pipe each way between the pool's connection
//! and the endpoint's. The caller writes what a connection owes when the pool says `send`, and the
//! server when the endpoint says `send`.
//!
//! The run moves in instants. At each the caller makes, cancels or shuts down as the plan says,
//! then the pool takes one turn and the server one: each reads what its sockets hold and reports
//! what it owes. A response thus arrives an instant after its request, and a cancel may come
//! while the request is in flight. The world calls its observer after each act and each event, so
//! the run logs each step of the model apart. No clock is read and no deadline passes: every call
//! takes the instant 0.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const client = @import("client");
const server = @import("server");
const sim = @import("sim");
const plan_module = @import("pool_trace_plan.zig");

const Random = sim.Random;
const limits = sim.constants.pool_trace;
const Plan = plan_module.Plan;

pub const ConnectionPool = client.ConnectionPoolOf(.{ .quic = false });
const Endpoint = server.EndpointOf(.{ .tcp_connections = limits.endpoint_slots, .quic_connections = 0 });
const memory_len = ConnectionPool.memory_bytes(.{ .tcp_connections = limits.slots_max, .requests = limits.requests_max });
const now_ns: u64 = 0;
const ok: u16 = 200;
const http_port: u16 = 80;
const address_octet: u8 = 0x0a;
const ipv4_len: usize = 4;
/// The field that ends a connection after its response (RFC 9112 §9.6).
const close_fields = [_]server.Header{.{ .name = "connection", .value = "close" }};

pub const Error = error{
    /// A pipe, a table or an endpoint's slot had no room, which a plan within its limits never
    /// fills.
    NoRoom,
    /// The endpoint or the pool refused what an honest caller does.
    Refused,
    /// One side reported more than `turn_events_max` events in one turn.
    TooManyEvents,
};

/// Octets in flight one way between two connections.
pub const Pipe = struct {
    octets: [limits.pipe_len]u8 = undefined,
    len: usize = 0,

    fn push(pipe: *Pipe, octets: []const u8) Error!void {
        if (octets.len > pipe.octets.len - pipe.len) return error.NoRoom;
        @memcpy(pipe.octets[pipe.len..][0..octets.len], octets);
        pipe.len += octets.len;
    }

    fn take(pipe: *Pipe, consumed: usize) void {
        assert(consumed <= pipe.len);
        std.mem.copyForwards(u8, &pipe.octets, pipe.octets[consumed..pipe.len]);
        pipe.len -= consumed;
    }

    /// Room for one write of a connection.
    fn room(pipe: *Pipe) []u8 {
        return pipe.octets[pipe.len..];
    }
};

/// A slot's socket: the pool's connection, the endpoint's, and a pipe each way.
pub const Socket = struct {
    connected: bool = false,
    client: client.ConnectionHandle = .{ .slot = 0, .generation = 0 },
    server: server.ConnectionHandle = .{ .slot = 0, .generation = 0 },
    to_server: Pipe = .{},
    to_client: Pipe = .{},
    /// The server closed its side, and the pool hears it once it read what is in flight.
    server_closed: bool = false,
    /// Times the pool opened this slot.
    opens: u32 = 0,
};

pub const World = struct {
    plan: Plan,
    random: Random,
    pool: ConnectionPool,
    pool_memory: [memory_len]u8 align(ConnectionPool.memory_alignment),
    endpoint: Endpoint,
    endpoint_config: server.Config,
    client_config: client.Config,
    addresses: [1]client.Address,
    sockets: [limits.slots_max]Socket,
    paths: [limits.requests_max][path_len]u8,
    requests: [limits.requests_max]client.Request,
    responses: [limits.requests_max]client.Response,
    bodies: [limits.requests_max][limits.body_len]u8,
    ids: [limits.requests_max]?client.RequestId,
    cancelled: [limits.requests_max]bool,
    reported: [limits.requests_max]bool,
    /// Times a server passed each request to its application, and the slot and the pool's
    /// generation of the connection that did last.
    processed: [limits.requests_max]u8,
    processed_on: [limits.requests_max]?client.ConnectionHandle,
    instant: u32,
    shut: bool,
    closed: bool,

    pub fn init(world: *World, seed: u64) !void {
        world.random = Random.init(seed);
        world.plan.draw(&world.random);
        // Decision 125: h11 alone, so each TCP connection holds one exchange at a time.
        world.endpoint_config = .{ .protocols = .{ .h2 = false } };
        world.client_config = .{ .authority = "pool.test", .protocols = .{ .h2 = false, .h3 = false } };
        try world.endpoint.init(&world.endpoint_config, tls.Random.init(&world.random, fill), 0, now_ns);
        const octets: [ipv4_len]u8 = @splat(address_octet);
        world.addresses = .{client.Address.of(&octets, 0)};
        const options: client.Options = .{ .tcp_connections = @intCast(world.plan.slots), .requests = @intCast(world.plan.requests) };
        // Decision 125 ruling 2: the pool takes the memory its options need, and no more.
        const memory = world.pool_memory[0..ConnectionPool.memory_bytes(options)];
        try world.pool.init(memory, &world.client_config, .{ .addresses = &world.addresses, .port = http_port }, options, null);
        world.sockets = @splat(.{});
        world.ids = @splat(null);
        world.cancelled = @splat(false);
        world.reported = @splat(false);
        world.processed = @splat(0);
        world.processed_on = @splat(null);
        world.instant = 0;
        world.shut = false;
        world.closed = false;
        for (0..world.plan.requests) |index| world.prepare(index);
    }

    fn prepare(world: *World, index: usize) void {
        const path = std.fmt.bufPrint(&world.paths[index], "/{d}", .{index}) catch unreachable;
        world.requests[index] = .{ .method = if (world.plan.post[index]) "POST" else "GET", .path = path };
        world.responses[index] = .{ .body = &world.bodies[index] };
    }

    /// The caller's acts at this instant, then one turn of the pool and one of the server. The
    /// world calls `observer.observe()` after each act and each event.
    pub fn step(world: *World, observer: anytype) !void {
        for (0..world.plan.requests) |index| {
            world.act(index);
            try observer.observe();
        }
        if (world.instant == world.plan.shutdown_at and !world.shut) {
            world.shut = true;
            world.pool.shutdown();
            try observer.observe();
        }
        try world.client_turn(observer);
        try world.server_turn(observer);
        world.instant += 1;
    }

    fn act(world: *World, index: usize) void {
        if (world.plan.make_at[index] == world.instant and world.ids[index] == null and !world.shut) {
            world.ids[index] = world.pool.request(&world.requests[index], &world.responses[index]) catch null;
        }
        const cancel_at = world.plan.cancel_at[index] orelse return;
        if (cancel_at != world.instant or world.ids[index] == null) return;
        if (world.reported[index] or world.cancelled[index]) return;
        world.pool.cancel(world.ids[index].?);
        world.cancelled[index] = true;
    }

    /// The pool reads what each socket holds, then reports what it owes with no octets.
    fn client_turn(world: *World, observer: anytype) !void {
        for (world.sockets[0..world.plan.slots]) |*socket| {
            if (socket.connected and socket.to_client.len > 0) {
                try world.client_read(socket);
                try observer.observe();
            }
            // The server closed its side, and the pool read what was in flight before it.
            if (socket.connected and socket.server_closed and socket.to_client.len == 0) {
                const connection = socket.client;
                socket.* = .{ .opens = socket.opens };
                world.pool.transport_closed(connection);
                try observer.observe();
            }
        }
        // Bounded: each pass reports one of the finitely many events.
        for (0..limits.turn_events_max) |_| {
            const event = world.pool.receive(.none, now_ns).event orelse return;
            try world.on_client_event(event);
            try observer.observe();
        }
        return error.TooManyEvents;
    }

    fn client_read(world: *World, socket: *Socket) Error!void {
        const input: client.Input = .{ .stream = .{ .connection = socket.client, .bytes = socket.to_client.octets[0..socket.to_client.len] } };
        const received = world.pool.receive(input, now_ns);
        socket.to_client.take(received.consumed);
        if (received.event) |event| try world.on_client_event(event);
    }

    fn on_client_event(world: *World, event: client.Event) Error!void {
        switch (event) {
            .open => |open| try world.connect(open),
            .send => |connection| try world.client_send(connection),
            .close => |connection| world.client_close(connection),
            .connected, .ticket => {},
            .finished => |finished| world.reported[world.index_of(finished.response)] = true,
            .closed => world.closed = true,
        }
    }

    /// Connects the socket of the slot an `open` names, unless the plan fails the slot's first
    /// connect, and starts the pool's connection on it.
    fn connect(world: *World, open: client.Open) Error!void {
        const socket = &world.sockets[open.connection.slot];
        socket.opens += 1;
        if (socket.opens == 1 and world.plan.connect_fails[open.connection.slot]) {
            world.pool.transport_closed(open.connection);
            return;
        }
        const accepted = world.endpoint.accept(.cleartext, now_ns) orelse return error.NoRoom;
        socket.* = .{ .connected = true, .client = open.connection, .server = accepted, .opens = socket.opens };
        world.pool.start_tcp(open.connection, tls.Random.init(&world.random, fill), 0, null) catch return error.Refused;
    }

    /// Writes what the pool's connection owes, until a write leaves room.
    fn client_send(world: *World, connection: client.ConnectionHandle) Error!void {
        const socket = &world.sockets[connection.slot];
        // Bounded: each pass writes an octet or leaves room.
        for (0..limits.pipe_len + 1) |_| {
            const room = socket.to_server.room();
            const written = world.pool.send_stream(connection, room, now_ns);
            socket.to_server.len += written;
            if (written < room.len) return;
        }
        return error.NoRoom;
    }

    /// The pool is done with the connection, and the caller closes its socket: the server hears
    /// the close, and what was in flight reaches no one.
    fn client_close(world: *World, connection: client.ConnectionHandle) void {
        const socket = &world.sockets[connection.slot];
        if (!socket.connected or socket.client.generation != connection.generation) return;
        world.endpoint.transport_closed(socket.server);
        socket.* = .{ .opens = socket.opens };
    }

    /// The endpoint reads what each socket holds, then reports what it owes with no octets.
    fn server_turn(world: *World, observer: anytype) !void {
        for (world.sockets[0..world.plan.slots]) |*socket| {
            if (!socket.connected or socket.server_closed or socket.to_server.len == 0) continue;
            const input: server.Input = .{ .stream = .{ .connection = socket.server, .bytes = socket.to_server.octets[0..socket.to_server.len] } };
            const received = world.endpoint.receive(input, now_ns);
            socket.to_server.take(received.consumed);
            if (received.event) |event| try world.on_server_event(event);
            try observer.observe();
        }
        // Bounded: each pass reports one of the finitely many events.
        for (0..limits.turn_events_max) |_| {
            const event = world.endpoint.receive(.none, now_ns).event orelse return;
            try world.on_server_event(event);
            try observer.observe();
        }
        return error.TooManyEvents;
    }

    fn on_server_event(world: *World, event: server.Event) Error!void {
        switch (event) {
            .request => |request| try world.answer(request),
            .send => |connection| try world.server_send(connection),
            .close => |connection| if (world.socket_of(connection)) |socket| {
                socket.server_closed = true;
            },
            .body, .trailers, .cancelled, .done, .writable, .ended, .closed => {},
        }
    }

    /// The server processes the request and answers it as the plan says.
    fn answer(world: *World, request: server.Request) Error!void {
        const socket = world.socket_of(request.id.connection) orelse return error.Refused;
        const index = index_of_path(request.path orelse return error.Refused);
        world.processed[index] += 1;
        world.processed_on[index] = socket.client;
        switch (world.plan.answers[index]) {
            .respond => world.endpoint.respond(request.id, .{ .status = ok, .end = true }) catch return error.Refused,
            .close => world.endpoint.respond(request.id, .{ .status = ok, .headers = &close_fields, .end = true }) catch return error.Refused,
            .@"break" => {
                // The server closes before any of the response: the pool hears the close once it
                // read what is in flight.
                world.endpoint.transport_closed(socket.server);
                socket.server_closed = true;
            },
        }
    }

    fn server_send(world: *World, connection: server.ConnectionHandle) Error!void {
        const socket = world.socket_of(connection) orelse return;
        // Bounded: each pass writes an octet or leaves room.
        for (0..limits.pipe_len + 1) |_| {
            const room = socket.to_client.room();
            const written = world.endpoint.send_stream(connection, room, now_ns);
            socket.to_client.len += written;
            if (written < room.len) return;
        }
        return error.NoRoom;
    }

    fn socket_of(world: *World, connection: server.ConnectionHandle) ?*Socket {
        for (world.sockets[0..world.plan.slots]) |*socket| {
            if (socket.connected and socket.server == connection) return socket;
        }
        return null;
    }

    /// The index of the exchange whose response is at `response`, which the world placed.
    pub fn index_of(world: *const World, response: *const client.Response) usize {
        const index = (@intFromPtr(response) - @intFromPtr(&world.responses[0])) / @sizeOf(client.Response);
        assert(index < world.plan.requests and &world.responses[index] == response);
        return index;
    }
};

/// Octets of a request's path: "/" and its index.
const path_len: usize = 4;

/// The exchange a request's path "/<index>" names.
fn index_of_path(path: []const u8) usize {
    assert(path.len > 1 and path[0] == '/');
    return std.fmt.parseInt(usize, path[1..], decimal_base) catch unreachable;
}

const decimal_base: u8 = 10;

pub fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}
