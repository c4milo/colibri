//! One connection of the test-only client, on the `client` module (design §8 step 21c): the
//! plan's exchanges handed to a `client.Pool` with TCP alone, which speaks h2 or h11 and runs TLS
//! itself. `client_loop.zig` is the socket around it, and these tests run it against §9's server in
//! one process.
//!
//! Every exchange of the plan is requested at once, so h2 multiplexes them and h11 pipelines them
//! as decision 88 allows, and the pool is shut down at once: its connection ends after its last
//! exchange, h2 with its GOAWAY (RFC 9113 §6.8), and the pool reports `closed` once no
//! connection is left. The pool asks for each socket with an `open` event and is done with it
//! at a `close` event. An exchange a connection refused unprocessed moves to the next connection,
//! on a socket of its own (decision 100).
//!
//! A pool of several TCP slots (decision 125) opens a socket for each slot whose connection an
//! exchange needs: h11 takes one exchange at a time on each. Each slot has its own socket, and
//! the session keeps what the pool asked of each.
//!
//! Time is a value, never a clock: each step reports an instant `tick_ns` after the last (design
//! §4.2, invariant 6).
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const tls = @import("tls");
const constants = @import("../constants.zig");
const client_exchange = @import("client_exchange.zig");

const Exchange = client_exchange.Exchange;
const Plan = client_exchange.Plan;

/// What one step did. What the pool asked of each slot's socket is in `Session.asked`.
pub const Step = struct {
    /// Octets of the caller's input the pool consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// The pool reported `closed`: every exchange ended, and no connection is left.
    done: bool,
};

/// What the pool asked of one slot's socket since the caller last took it.
pub const Asked = struct {
    /// The pool is done with the socket: the caller sends what it holds, then closes it.
    close: bool = false,
    /// Where the slot's next socket goes, or null. The caller closes the last socket before it
    /// opens this one.
    open: ?client.Address = null,
};

/// The TCP slots a session's pool holds at most.
const slots_max = constants.client_tcp_connections_max;

/// The response content of each exchange of one connection, which `client` fills.
pub const Bodies = [constants.requests_max][constants.response_content_len_max]u8;

/// One connection's client state, in storage the caller places. The pool stays in place after
/// `init`: the TLS configuration it built points into it.
pub const Session = struct {
    pool: client.Pool,
    /// The TCP slots the pool holds, which `init` takes in its options.
    slots: u32,
    /// Each slot's connection, as the pool's last `open` for the slot named it (decision 125).
    /// Generation 0 names none.
    connections: [slots_max]client.ConnectionHandle,
    /// What the pool asked of each slot's socket since the caller last took it.
    asked: [slots_max]Asked,
    /// The server's one address, which the pool reads for each socket it asks for.
    addresses: [1]client.Address,
    exchanges: [constants.requests_max]Exchange,
    requests_count: u32,
    /// What each connection's start takes: the source its TLS session draws from, and the instant
    /// chapulin judges the server's chain at, in seconds since 1970-01-01T00:00:00Z.
    random: tls.Random,
    now_seconds: u64,
    /// The instant the next step passes (design §4.2).
    now_ns: u64,
    /// Whether the pool's `closed` event arrived.
    closed: bool,
    /// The protocol of the connection that last reported `connected`, and the sockets the pool
    /// asked for.
    protocol: ?client.Protocol,
    opens: u32,

    /// Makes a pool of `options` in `memory` that has opened nothing, with every exchange of
    /// `plans` requested, to the server at `address`, whose port is 0, and `port`. `memory`,
    /// `config`, `plans` and `bodies` must outlive the session.
    pub fn init(
        session: *Session,
        memory: []align(client.Pool.memory_alignment) u8,
        options: client.Options,
        config: *const client.Config,
        address: client.Address,
        port: u16,
        random: tls.Random,
        now_seconds: u64,
        plans: []const Plan,
        bodies: *Bodies,
    ) !void {
        assert(plans.len > 0 and plans.len <= constants.requests_max);
        assert(address.port == 0);
        assert(options.tcp_connections > 0 and options.tcp_connections <= slots_max);
        session.requests_count = 0;
        session.addresses = .{address};
        try session.pool.init(memory, config, .{ .addresses = &session.addresses, .port = port }, options, null);
        session.slots = options.tcp_connections;
        session.random = random;
        session.now_seconds = now_seconds;
        session.now_ns = 0;
        session.closed = false;
        session.protocol = null;
        session.opens = 0;
        session.asked = @splat(.{});
        session.connections = @splat(.{ .slot = 0, .generation = 0 });
        for (plans, session.exchanges[0..plans.len], bodies[0..plans.len]) |plan, *exchange, *body| {
            exchange.* = .init(plan, body);
            exchange.id = try session.pool.request(&exchange.request, &exchange.response);
            session.requests_count += 1;
        }
        // The pool takes no request after `shutdown`, so the requests come first.
        session.pool.shutdown();
    }

    /// Consumes what it can of `input`, the octets `slot`'s socket read and the caller still
    /// holds, and writes what it can into `output`. A null `slot` passes no octets and writes
    /// none, and reports what the pool owes of its own. Over TLS the pool opens records in place
    /// in `input`.
    pub fn step(session: *Session, slot: ?u32, input: []u8, output: []u8) Step {
        session.now_ns += constants.tick_ns;
        const carried = slot orelse {
            assert(input.len == 0 and output.len == 0);
            _ = session.read(null, input);
            return .{ .consumed = 0, .written = 0, .done = session.closed };
        };
        assert(carried < session.slots);
        var consumed = session.read(carried, input);
        // The step writes what the connection owes each time, so it needs no `send` event.
        const written = session.pool.send_stream(session.connections[carried], output, session.now_ns);
        // After a send the pool reads again, with the octets the caller still holds: h11 reads
        // a held octet only once the response before it ends (decision 119).
        consumed += session.read(carried, input[consumed..]);
        return .{ .consumed = consumed, .written = written, .done = session.closed };
    }

    /// What the pool asked of `slot`'s socket since the last call, which this call clears.
    pub fn take_asked(session: *Session, slot: u32) Asked {
        assert(slot < session.slots);
        const asked = session.asked[slot];
        session.asked[slot] = .{};
        return asked;
    }

    /// The socket the pool asked for in `slot` connected, so the pool starts its connection on
    /// it. False when chapulin refused the start: the attempt ends, and the caller closes the
    /// socket, since the pool owes no `close` for a connection that never started.
    pub fn started(session: *Session, slot: u32) bool {
        assert(slot < session.slots);
        session.pool.start_tcp(session.connections[slot], session.random, session.now_seconds, null) catch return false;
        return true;
    }

    /// Reads events, passing the octets `slot`'s socket still holds each time, until the pool
    /// consumes nothing and reports nothing. A null `slot` passes no octets.
    fn read(session: *Session, slot: ?u32, input: []u8) usize {
        var consumed: usize = 0;
        // Bounded: each pass consumes an octet or reports one of the finitely many events.
        for (0..input.len + session.slots * constants.requests_max * constants.steps_per_read_max) |_| {
            const held = input[consumed..];
            const passed: client.Input = if (slot != null and held.len > 0) .{ .stream = .{ .connection = session.connections[slot.?], .octets = held } } else .none;
            const received = session.pool.receive(passed, session.now_ns);
            consumed += received.consumed;
            const reported = received.event orelse {
                if (received.consumed == 0) return consumed;
                continue;
            };
            session.record(reported);
        }
        return consumed;
    }

    fn record(session: *Session, reported: client.Event) void {
        switch (reported) {
            .finished => |ended| session.exchange_of(ended.id).finished = true,
            // The client offers no ticket, so it keeps none it is given.
            .ticket => |connection| if (session.pool.take_ticket(connection)) |ticket| {
                var held = ticket;
                held.wipe();
            },
            .closed => session.closed = true,
            .connected => |connected| session.protocol = connected.protocol,
            // The pool holds no receive pool, so it offers TCP alone.
            .open => |open| {
                assert(open.transport == .tcp and open.connection.slot < session.slots);
                session.connections[open.connection.slot] = open.connection;
                session.asked[open.connection.slot].open = open.to;
                session.opens += 1;
            },
            .close => |connection| session.asked_close(connection),
            .send => {},
        }
    }

    /// The pool is done with `connection`. One whose `open` the caller has not taken never had a
    /// socket, so the caller opens none for it. Any other is its slot's socket.
    fn asked_close(session: *Session, connection: client.ConnectionHandle) void {
        const asked = &session.asked[connection.slot];
        if (asked.open != null and session.connections[connection.slot].generation == connection.generation) {
            asked.open = null;
            return;
        }
        asked.close = true;
    }

    fn exchange_of(session: *Session, id: client.Id) *Exchange {
        for (session.exchanges[0..session.requests_count]) |*exchange| {
            if (exchange.id == id) return exchange;
        }
        unreachable; // The pool reports only the exchanges `init` requested.
    }

    /// Whether every exchange ended the way a working peer ends one.
    pub fn succeeded(session: *const Session) bool {
        for (session.exchanges[0..session.requests_count]) |*exchange| {
            if (!exchange.succeeded()) return false;
        }
        return true;
    }

    /// The exchanges of the plan, as they stand.
    pub fn exchanges_held(session: *const Session) []const Exchange {
        return session.exchanges[0..session.requests_count];
    }

    /// `slot`'s socket ended before the pool was done with it: the peer closed it, it failed, or
    /// its connect failed. In h11 the close ends a body that runs until it (RFC 9112 §6.3 rule
    /// 8), and every exchange left ends or moves. The next step reads what the pool asks for then.
    pub fn peer_closed(session: *Session, slot: u32) void {
        assert(slot < session.slots);
        session.pool.transport_closed(session.connections[slot]);
    }
};

const testing = std.testing;
const server_session = @import("../server/server_session.zig");
const entropy = @import("../entropy.zig");
const client_options = @import("client_options.zig");

/// The server's session, which holds the one connection the client opens. Test-only.
const ServerSession = server_session.SessionOf(1);

/// The two sessions the tests run, their bodies, and the octets each has written that the other
/// has not read. Placed outside any stack frame. Test-only.
var test_client: Session align(@alignOf(Session)) = undefined;
var test_memory: [client.Pool.memory_bytes(.{})]u8 align(client.Pool.memory_alignment) = undefined;
var test_server: ServerSession align(@alignOf(ServerSession)) = undefined;
/// Decision 117: the server names no version, and reads it from the client's first octets.
var test_server_config: server_session.server.Config align(@alignOf(server_session.server.Config)) = .{};
var test_bodies: Bodies align(@alignOf(Bodies)) = undefined;
var test_to_server: [constants.write_buffer_len]u8 = @splat(0);
var test_to_client: [constants.write_buffer_len]u8 = @splat(0);
var test_config: client.Config align(@alignOf(client.Config)) = .{ .authority = "localhost" };
/// The server's address, which no socket reads: the test passes the octets itself. Test-only.
const test_octets: [client_options.ipv4_octets]u8 = @splat(0);
const test_address = client.Address.of(&test_octets, 0);

/// Most rounds a test exchanges octets for, which bounds its loop. Test-only.
const test_rounds_max: u32 = 4096;

/// The instant of the server's last step, a tick after the one before. Test-only.
var test_server_now_ns: u64 = 0;
/// The octets the step that reported the pool's `close` wrote, once one did. Test-only.
var test_close_written: ?usize = null;

fn test_drop(buffer: []u8, len: usize, consumed: usize) usize {
    std.mem.copyForwards(u8, buffer[0 .. len - consumed], buffer[consumed..len]);
    return len - consumed;
}

/// Starts the server's session with one connection accepted in cleartext. Test-only.
fn test_start_server() !void {
    test_server_now_ns = 0;
    try test_server.init(&test_server_config, entropy.random(), test_server_now_ns);
    try testing.expect(test_server.accept(0, .cleartext, null, test_server_now_ns));
}

/// Runs the client against the server until the client is done or neither moves. The one socket
/// the pool asks for connects at once, to the server's one accepted connection. Test-only.
fn test_run() !u32 {
    var to_server_len: usize = 0;
    var to_client_len: usize = 0;
    var opens: u32 = 0;
    test_close_written = null;
    for (0..test_rounds_max) |round| {
        const stepped = test_client.step(0, test_to_client[0..to_client_len], test_to_server[to_server_len..]);
        to_client_len = test_drop(&test_to_client, to_client_len, stepped.consumed);
        to_server_len += stepped.written;
        const asked = test_client.take_asked(0);
        const opened: u32 = @intFromBool(asked.open != null);
        if (opened > 0) try testing.expect(test_client.started(0));
        opens += opened;
        if (asked.close) test_close_written = stepped.written;
        test_server_now_ns += constants.tick_ns;
        const served = test_server.step(0, test_to_server[0..to_server_len], test_to_client[to_client_len..], test_server_now_ns);
        to_server_len = test_drop(&test_to_server, to_server_len, served.consumed);
        to_client_len += served.written;
        const moved = stepped.consumed + stepped.written + served.consumed + served.written + opened;
        // The server has one connection, so the pool asks for one socket alone.
        try testing.expect(opens <= 1);
        if (stepped.done or moved == 0) return @intCast(round + 1);
    }
    return test_rounds_max;
}

test "h2: every exchange of the plan shares the connection, and content past the window goes out" {
    client_exchange.fill_content();
    // Decision 117: the server names no version and reads h2 from the client's preface.
    try test_start_server();
    test_config = .{ .authority = "localhost", .versions = .{ .h11 = false } };
    // RFC 9113 §6.9.2: a stream starts with 65,535 octets of window.
    const content_len = 3 * 65_535;
    try test_client.init(&test_memory, .{}, &test_config, test_address, constants.default_port, entropy.random(), 0, &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "POST", .path = "/upload", .content_len = content_len },
    }, &test_bodies);
    try testing.expect(try test_run() < test_rounds_max);
    try testing.expect(test_client.succeeded() and test_client.closed);
    try testing.expectEqual(client.Protocol.h2, test_client.protocol.?);
    const upload = &test_client.exchanges[1];
    try testing.expectEqual(content_len, upload.response.content_sent);
    try testing.expectEqual(client_exchange.content_crc32(content_len), upload.sent_crc32());
    try testing.expectEqual(constants.response_status, upload.response.status);
    try testing.expectEqualStrings(constants.response_body, test_client.exchanges[0].response.content_received());
    // RFC 9113 §6.8: the step that writes the GOAWAY reads again after it, and reports the close,
    // so the caller closes the socket once the GOAWAY is sent.
    try testing.expect(test_close_written.? > 0);
}

test "h11: the exchanges go out in order, and the connection ends after the last" {
    client_exchange.fill_content();
    // Decision 117: the server names no version and reads h11 from the client's first octets.
    try test_start_server();
    test_config = .{ .authority = "localhost", .versions = .{ .h2 = false } };
    try test_client.init(&test_memory, .{}, &test_config, test_address, constants.default_port, entropy.random(), 0, &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "GET", .path = "/index.html", .content_len = 0 },
    }, &test_bodies);
    try testing.expect(try test_run() < test_rounds_max);
    try testing.expect(test_client.succeeded() and test_client.closed);
    try testing.expectEqual(client.Protocol.h11, test_client.protocol.?);
    for (test_client.exchanges_held()) |*exchange| {
        try testing.expectEqual(constants.response_status, exchange.response.status);
    }
}

/// A request with no content, and how many of them the pipelining test makes. Test-only.
const test_get: Plan = .{ .method = "GET", .path = "/", .content_len = 0 };
const test_pipelined: usize = 3;
/// A response with one octet of content (RFC 9112 §6.3 rule 6). Test-only.
const test_short_response = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";

test "decision 119: one step reads every pipelined h11 response the socket holds" {
    client_exchange.fill_content();
    test_config = .{ .authority = "localhost", .versions = .{ .h2 = false } };
    try test_client.init(&test_memory, .{}, &test_config, test_address, constants.default_port, entropy.random(), 0, &(.{test_get} ** test_pipelined), &test_bodies);
    // The pool asks for its socket, which connects at once, and its connection writes the
    // requests.
    _ = test_client.step(0, test_to_client[0..0], &test_to_server);
    try testing.expect(test_client.take_asked(0).open != null);
    try testing.expect(test_client.started(0));
    try testing.expect(test_client.step(0, test_to_client[0..0], &test_to_server).written > 0);
    // h11 reads a held response only once the one before it ends, so the step passes the octets
    // it still holds after each event.
    const held = test_short_response ** test_pipelined;
    @memcpy(test_to_client[0..held.len], held);
    const stepped = test_client.step(0, test_to_client[0..held.len], &test_to_server);
    try testing.expectEqual(held.len, stepped.consumed);
    try testing.expect(test_client.succeeded());
}
