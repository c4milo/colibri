//! The sockets around `client_session.zig`: the test-only client of design §9, which
//! `tools/h2_interop.sh` runs against other implementations' servers. `zig build http-client --
//! --port <port> --get <path> --post <path> <octets>` runs it.
//!
//! Each connection of a run is a `client.Pool` with TCP alone (design §8 step 21c). It speaks
//! cleartext h2 with prior knowledge (RFC 9113 §3.3) or h11, or with `--tls` whichever ALPN selects
//! over TLS, which the module runs through colibri's `tls.record.Client` (RFC 9113 §3.2, decision
//! 82). With `--pool` the run is one pool that adds QUIC instead (`pool_loop.zig`).
//!
//! No call here waits but the loop's `tick` (decisions 46 and 58,
//! https://github.com/c4milo/colibri/issues/61). One thread holds every pool of a run on one
//! Rotor loop, and each TCP slot of a pool holds one socket at a time (`pool_tcp.zig`): a
//! connect, then at most one receive and one send in flight, and a close at the end. A socket the
//! pool asks for while the slot's last one closes waits for that close. A slow peer holds up
//! nothing but its own pool. The one wait that ends a run is `client_wait_ns` with no event.
//!
//! Nothing here allocates: the loop, every socket and buffer, and the memory each pool holds its
//! TCP connections in are in static storage sized by `constants.zig`. Each pool takes a slice of
//! that memory as large as `--tcp-connections` needs (decision 35 as amended). Nothing here reads
//! a clock: the timeout is the loop's.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const client = @import("client");
const h11 = @import("h11");
const constants = @import("../constants.zig");
const client_options = @import("client_options.zig");
const client_session = @import("client_session.zig");
const client_exchange = @import("client_exchange.zig");
const client_tls = @import("../tls/client_tls.zig");
const pool_loop = @import("pool_loop.zig");
const pool_tcp = @import("pool_tcp.zig");
const entropy = @import("../entropy.zig");
const alpn = @import("../alpn.zig");

const Run = client_options.Run;
const Session = client_session.Session;

/// Why a connection did not end with every exchange answered and its pool closed: the last end
/// of a socket the pool did not ask for, as `pool_tcp` names it, a pool that never
/// started, or the run's wait running out.
const Failure = enum { none, failed, open_failed, refused_start, timed_out };

/// The bits of an operation's user data that name what it does, below the index of the connection
/// it belongs to: each socket's `base` is its connection's index shifted past them.
const kind_bits = @bitSizeOf(pool_tcp.Kind);

const loop_options: rotor.Loop.Options = .{
    .operations = constants.client_sockets_max * @typeInfo(pool_tcp.Kind).@"enum".fields.len,
};

/// One connection of a run, as the command line counts them: a pool, and a socket for each of
/// its TCP slots.
const Connection = struct {
    session: Session,
    /// The sockets of the pool's slots, slot 0 first, in `sockets`.
    sockets: []pool_tcp.Socket,
    failure: Failure,

    /// Whether the pool or one of its sockets still has something to do.
    fn running(connection: *const Connection) bool {
        if (connection.failure == .refused_start) return false;
        if (!connection.session.closed) return true;
        for (connection.sockets) |*socket| {
            if (socket.state != .idle) return true;
        }
        return false;
    }

    /// Whether the pool closed with every exchange answered, and every socket it opened ended
    /// before the run did.
    fn succeeded(connection: *const Connection) bool {
        if (connection.failure == .timed_out or connection.failure == .refused_start) return false;
        return connection.session.closed and connection.session.succeeded();
    }
};

/// The loop and the connections, in static storage: each pool is large, and a run holds up to
/// the limit of them. The QUIC connection inside each pool is never written, so the system gives
/// its pages no memory.
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var loop: rotor.Loop align(@alignOf(rotor.Loop)) = undefined;
var events: [loop_options.operations]rotor.Event align(@alignOf(rotor.Event)) = undefined;
var connections: [constants.client_connections_max]Connection align(@alignOf(Connection)) = undefined;
var sockets: [constants.client_sockets_max]pool_tcp.Socket align(@alignOf(pool_tcp.Socket)) = undefined;
/// The memory every pool of the run holds its TCP connections and its exchanges in, a slice of it
/// each. A run that holds fewer pools gives each more.
var pool_memory: [client_options.pool_memory_len]u8 align(client.Pool.memory_alignment) = undefined;
/// The TCP slots each pool of the run holds, which maps a socket's index to its pool and slot.
var slots_per_pool: u32 = 1;
/// The response content of every exchange of every connection. Most of it is never touched, so
/// the system gives it no memory.
var bodies: [constants.client_connections_max]client_session.Bodies align(@alignOf(client_session.Bodies)) = undefined;

/// What every pool of the run borrows: the authority, the versions, the TLS value when `--tls`
/// names a root, and the codings.
var pool_config: client.Config align(@alignOf(client.Config)) = .{ .authority = "localhost" };
/// The decoders every connection of a `--coded` run shares, a pool for each coding (decision 101 as
/// amended), and the codings it offers. `br` goes first, with no weight: h2o 2.2.5 codes no coding
/// the request names with a weight, and a peer that reads weights still takes the one it has.
var decoders: client.DefaultDecoderPool align(@alignOf(client.DefaultDecoderPool)) = .{};
var zstd_decoders: client.ZstdDecoderPool(coded_decoders) align(@alignOf(client.ZstdDecoderPool(coded_decoders))) = undefined;
var br_decoders: client.BrotliDecoderPool(coded_decoders) align(@alignOf(client.BrotliDecoderPool(coded_decoders))) = undefined;
const offered_codings = [_]client.Coding{ .br, .zstd, .gzip, .deflate };
/// The `zstd` and `br` decoders a run holds, each 8 MB or 16 MiB: two coded responses of each at
/// once. An exchange past them offers the codings left.
const coded_decoders: usize = 2;
var tls_anchors: client_tls.Anchors align(@alignOf(client_tls.Anchors)) = undefined;

/// Starts every connection of `run`, serves them until each pool is closed, and returns how
/// many finished with every exchange answered.
fn run_connections(run: *const Run) !u32 {
    assert(run.connections_count > 0 and run.connections_count <= constants.client_connections_max);
    assert(run.plans_count > 0);
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    slots_per_pool = run.tcp_connections;
    const live = connections[0..run.connections_count];
    for (live, 0..) |*connection, index| start_connection(connection, index, run);
    for (0..constants.client_ticks_max) |_| {
        if (!try turn(live)) break;
    }
    // A run that ends with a pool not closed, or a socket still open, ran out of time or of
    // ticks.
    for (live) |*connection| {
        if (connection.failure == .refused_start) continue;
        if (connection.running()) connection.failure = .timed_out;
        for (connection.sockets, 0..) |*socket, slot| {
            socket.close_now(&loop);
            // The pool wipes its TLS session's secrets, whether its connection finished or not.
            connection.session.peer_closed(@intCast(slot));
        }
    }
    loop.cancel_all();
    try loop.drain(&events);
    var succeeded: u32 = 0;
    for (live) |*connection| succeeded += @intFromBool(connection.succeeded());
    return succeeded;
}

/// Waits for events and does what each asks. False when no connection has anything left to do, or
/// none moved for the whole wait, which means the peers left are not answering.
fn turn(live: []Connection) !bool {
    var running: usize = 0;
    for (live) |*connection| running += @intFromBool(connection.running());
    if (running == 0) return false;
    const count = try loop.tick(&events, constants.client_wait_ns);
    if (count == 0) return false;
    for (events[0..count]) |event| on_event(live, event);
    return true;
}

/// Starts one connection of the run: a pool with every exchange of the plan requested, which
/// asks for its first socket at once.
fn start_connection(connection: *Connection, index: usize, run: *const Run) void {
    connection.failure = .none;
    const slots = run.tcp_connections;
    connection.sockets = sockets[index * slots ..][0..slots];
    for (connection.sockets, index * slots..) |*socket, socket_index| socket.init(@as(u64, socket_index) << kind_bits);
    const plans = run.plans[0..run.plans_count];
    const address = client.Address.of(&run.address, 0);
    const options = client_options.pool_options(run);
    connection.session.init(memory_of(index, options), options, &pool_config, address, run.port, entropy.random(), run.now_seconds, plans, &bodies[index]) catch {
        connection.failure = .refused_start;
        return;
    };
    step_session(connection);
}

/// The slice of `pool_memory` that pool `index` of a run of `options` holds.
fn memory_of(index: usize, options: client.Options) []align(client.Pool.memory_alignment) u8 {
    const len = std.mem.alignForward(usize, client.Pool.memory_bytes(options), client.Pool.memory_alignment);
    // `client_options.slots_ok` admits no run whose pools need more.
    assert((index + 1) * len <= pool_memory.len);
    return @alignCast(pool_memory[index * len ..][0..len]);
}

fn on_event(live: []Connection, event: rotor.Event) void {
    const socket_index: u32 = @intCast(event.user_data >> kind_bits);
    const connection = &live[socket_index / slots_per_pool];
    const slot = socket_index % slots_per_pool;
    on_happened(connection, slot, connection.sockets[slot].on_event(&loop, event));
    step_session(connection);
}

/// Tells the pool what the event of `slot`'s socket meant.
fn on_happened(connection: *Connection, slot: u32, happened: pool_tcp.Happened) void {
    switch (happened) {
        .none => {},
        // A start chapulin refuses ends the attempt, and the pool owes no `close` event for a
        // connection that never started, so the socket closes here.
        .connected => if (!connection.session.started(slot)) connection.sockets[slot].close(&loop),
        .failed => socket_ended(connection, slot, .failed),
        .open_failed => socket_ended(connection, slot, .open_failed),
    }
}

/// `slot`'s socket ended before the pool was done with it, which the pool hears. In h11 a peer's
/// close may end a response, so it is a failure only if the run fails.
fn socket_ended(connection: *Connection, slot: u32, failure: Failure) void {
    connection.failure = failure;
    connection.session.peer_closed(slot);
}

/// Steps the pool until it stops moving, then hands each socket its receive and its send.
fn step_session(connection: *Connection) void {
    // Bounded: each pass reads, writes or does what the pool asked, or stops.
    for (0..constants.steps_per_read_max) |_| {
        if (!step_once(connection)) break;
    }
    for (connection.sockets) |*socket| socket.arm(&loop);
}

/// Steps the pool once with no socket's octets, then once for each socket that carries a
/// connection, and does what the pool asked of each socket: the close first, then the open.
/// Returns whether anything moved.
fn step_once(connection: *Connection) bool {
    var none: [0]u8 = .{};
    // What the pool owes of its own: its first `open`, and what a socket's event changed.
    _ = connection.session.step(null, none[0..], none[0..]);
    var moved = false;
    for (0..connection.sockets.len) |slot| moved = step_slot(connection, @intCast(slot)) or moved;
    for (0..connection.sockets.len) |slot| moved = do_asked(connection, @intCast(slot)) or moved;
    return moved;
}

/// Steps the pool with the octets `slot`'s socket read and the room it has, while it carries the
/// slot's connection. Returns whether the step read or wrote an octet.
fn step_slot(connection: *Connection, slot: u32) bool {
    const socket = &connection.sockets[slot];
    if (!socket.carrying()) return false;
    const room = socket.room();
    // A full output waits for the send in flight, whose event steps the pool again.
    if (room.len == 0) return false;
    const step = connection.session.step(slot, socket.unread(), room);
    socket.consume(step.consumed);
    socket.wrote(step.written);
    return step.consumed + step.written > 0;
}

/// Does what the pool asked of `slot`'s socket. Returns whether it asked anything.
fn do_asked(connection: *Connection, slot: u32) bool {
    const asked = connection.session.take_asked(slot);
    if (asked.close) connection.sockets[slot].close(&loop);
    if (asked.open) |to| open_socket(connection, slot, to);
    return asked.close or asked.open != null;
}

/// Opens the socket the pool asked for in `slot`, or tells the pool the system gave none.
fn open_socket(connection: *Connection, slot: u32, to: client.Address) void {
    if (!connection.sockets[slot].open(&loop, rotor_address(to))) socket_ended(connection, slot, .open_failed);
}

/// The socket address the pool named, in Rotor's form: IPv4, the one family the command line
/// names.
fn rotor_address(address: client.Address) rotor.Address {
    assert(address.len == client_options.ipv4_octets);
    return rotor.Address.ipv4(address.octets[0..client_options.ipv4_octets].*, address.port);
}

/// Prints one line per exchange of every connection, then the count of each ending.
fn report(run: *const Run, succeeded: u32) void {
    for (connections[0..run.connections_count], 0..) |*connection, index| {
        const session = &connection.session;
        for (session.exchanges_held()) |*exchange| {
            std.debug.print("connection={d} ", .{index});
            exchange.print(protocol_name(session.protocol));
        }
        if (!connection.succeeded()) {
            std.debug.print("connection={d} failure={t} succeeded={}\n", .{ index, connection.failure, session.succeeded() });
        }
    }
    if (run.tcp_connections > 1) {
        var opens: u32 = 0;
        for (connections[0..run.connections_count]) |*connection| opens += connection.session.opens;
        std.debug.print("http-client: tcp_connections={d} opens={d}\n", .{ run.tcp_connections, opens });
    }
    std.debug.print("http-client: connections={d} succeeded={d} failed={d}\n", .{
        run.connections_count, succeeded, run.connections_count - succeeded,
    });
}

/// The exit status of a run in which a connection did not finish, and of a command line the
/// client could not read.
const exit_failed: u8 = 1;
const exit_usage: u8 = 2;

/// Runs the client and exits 0 when every connection finished with every exchange answered.
pub fn main(init: std.process.Init.Minimal) !void {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.skip();
    const run = client_options.read_run(&arguments) orelse {
        std.debug.print(client_options.usage, .{});
        std.process.exit(exit_usage);
    };
    client_exchange.fill_content();
    pool_config = .{ .authority = run.authority, .versions = versions_of(&run) };
    if (run.coded) {
        // The CPU features stdx's decoders use, asked of the CPU once, here and not in colibri.
        const features = h11.coding.Features.detect();
        decoders.storage().reset(features);
        zstd_decoders.storage().reset(features);
        br_decoders.storage().reset(features);
        pool_config.codings = &offered_codings;
        pool_config.decoders = decoders.storage();
        pool_config.zstd_decoders = zstd_decoders.storage();
        pool_config.br_decoders = br_decoders.storage();
    }
    // Each pool builds its TLS configuration from the value, with the protocols its versions
    // allow (decision 120). The name the server's certificate must carry is the authority the
    // requests name.
    if (run.anchor_prefix) |prefix| pool_config.tls = try client_tls.read(&tls_anchors, prefix, run.authority);
    if (run.pool) {
        if (!try pool_loop.run_pool(&run, &pool_config)) std.process.exit(exit_failed);
        return;
    }
    const succeeded = try run_connections(&run);
    report(&run, succeeded);
    if (succeeded != run.connections_count) std.process.exit(exit_failed);
}

/// The protocol a report names, or "none" for a connection that never connected.
fn protocol_name(protocol: ?client.Protocol) []const u8 {
    const spoken = protocol orelse return "none";
    return @tagName(spoken);
}

/// The versions a connection of `run` allows. In cleartext it is the run's protocol alone, which
/// the connection speaks from the start (decision 117). Over TLS with no `--h11` it is every
/// version: the client offers `h2` and then `http/1.1`, ALPN chooses, and a server that selects no
/// protocol is spoken to in h11 (decision 88), which a connection does only while its versions
/// allow h11.
fn versions_of(run: *const Run) client.Versions {
    const over_tls = run.anchor_prefix != null;
    return switch (run.protocol) {
        .h2 => if (over_tls) .{} else .{ .h11 = false },
        .h11 => .{ .h2 = false },
    };
}

const testing = std.testing;

/// The versions of a run that speaks `protocol`, over TLS when `anchor_prefix` names the root's
/// files. Test-only.
fn versions_for(protocol: alpn.Protocol, anchor_prefix: ?[]const u8) client.Versions {
    var run: Run = undefined;
    run.protocol = protocol;
    run.anchor_prefix = anchor_prefix;
    return versions_of(&run);
}

test "the command line's protocol is the one version a connection allows in cleartext" {
    try testing.expectEqual(client.Versions{ .h11 = false }, versions_for(.h2, null));
    try testing.expectEqual(client.Versions{ .h2 = false }, versions_for(.h11, null));
}

test "decision 88: over TLS with no --h11, a connection allows h11 for a server that selects nothing" {
    try testing.expectEqual(client.Versions{}, versions_for(.h2, "root"));
    try testing.expectEqual(client.Versions{ .h2 = false }, versions_for(.h11, "root"));
}

/// A request with no content, which the loop's tests make. Test-only.
const test_plan = [_]client_exchange.Plan{.{ .method = "GET", .path = "/", .content_len = 0 }};
const test_octets: [client_options.ipv4_octets]u8 = @splat(0);

/// The first connection of a run, its pool in cleartext h11 with the plan's one exchange
/// requested, and the `open` its first step reports. Test-only.
fn test_connection() !*Connection {
    client_exchange.fill_content();
    pool_config = .{ .authority = "localhost", .versions = .{ .h2 = false } };
    const connection = &connections[0];
    connection.failure = .none;
    slots_per_pool = 1;
    connection.sockets = sockets[0..1];
    connection.sockets[0].init(0);
    const address = client.Address.of(&test_octets, 0);
    try connection.session.init(memory_of(0, .{}), .{}, &pool_config, address, constants.default_port, entropy.random(), 0, &test_plan, &bodies[0]);
    var none: [0]u8 = .{};
    _ = connection.session.step(null, &none, &none);
    try testing.expect(connection.session.take_asked(0).open != null);
    return connection;
}

/// The connection of `test_connection`, started on its socket, and holding its exchange, which
/// it has not written: the test reads `connected` from the pool with no send. Test-only.
fn test_carrying() !*Connection {
    const connection = try test_connection();
    try testing.expect(connection.session.started(0));
    // In cleartext the connection reports `connected`, and the pool hands it the exchange.
    const reported = connection.session.pool.receive(.none, 0).event orelse return error.TestUnexpectedResult;
    try testing.expect(reported == .connected);
    return connection;
}

test "a socket that fails before its pool is done tells the pool, which asks for another" {
    const connection = try test_carrying();
    on_happened(connection, 0, .failed);
    try testing.expectEqual(Failure.failed, connection.failure);
    // RFC 9113 §8.7: the request was never written, so it moves to another connection, and the
    // pool asks for a socket to carry it.
    var none: [0]u8 = .{};
    _ = connection.session.step(null, &none, &none);
    try testing.expect(connection.session.take_asked(0).open != null);
}

test "a socket the system never gave ends the pool's attempt, and the exchange with it" {
    const connection = try test_connection();
    on_happened(connection, 0, .open_failed);
    var none: [0]u8 = .{};
    const stepped = connection.session.step(null, &none, &none);
    try testing.expect(stepped.done and connection.session.take_asked(0).open == null);
    try testing.expectEqual(.refused, connection.session.exchanges[0].response.outcome);
}

test "a socket the pool asks for while its last one closes waits for that close" {
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    const connection = try test_carrying();
    on_happened(connection, 0, .failed);
    // The socket that failed is closing, and its close's event has not arrived.
    connection.sockets[0].state = .closing;
    try testing.expect(step_once(connection));
    try testing.expectEqual(.closing, connection.sockets[0].state);
    try testing.expect(connection.sockets[0].open_pending != null);
}
