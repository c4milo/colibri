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
//! Rotor loop, and each pool holds one socket at a time (`pool_tcp.zig`): a connect, then at
//! most one receive and one send in flight, and a close at the end. A socket the pool asks for
//! while its last one closes waits for that close. A slow peer holds up nothing but its own
//! pool. The one wait that ends a run is `client_wait_ns` with no event.
//!
//! Nothing here allocates: the loop and every pool and buffer are in static storage sized by
//! `constants.zig`. Nothing here reads a clock: the timeout is the loop's.
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
    .operations = constants.client_connections_max * @typeInfo(pool_tcp.Kind).@"enum".fields.len,
};

/// One connection of a run, as the command line counts them: a pool, and the one socket it holds
/// at a time.
const Connection = struct {
    session: Session,
    socket: pool_tcp.Socket,
    failure: Failure,

    /// Whether the pool or its socket still has something to do.
    fn running(connection: *const Connection) bool {
        if (connection.failure == .refused_start) return false;
        return !connection.session.closed or connection.socket.state != .idle;
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
        connection.socket.close_now(&loop);
        // The pool wipes its TLS session's secrets, whether its connection finished or not.
        connection.session.peer_closed();
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
    connection.socket.init(@as(u64, index) << kind_bits);
    const plans = run.plans[0..run.plans_count];
    const address = client.Address.of(&run.address, 0);
    connection.session.init(&pool_config, address, run.port, entropy.random(), run.now_seconds, plans, &bodies[index]) catch {
        connection.failure = .refused_start;
        return;
    };
    step_session(connection);
}

fn on_event(live: []Connection, event: rotor.Event) void {
    const connection = &live[@intCast(event.user_data >> kind_bits)];
    on_happened(connection, connection.socket.on_event(&loop, event));
    step_session(connection);
}

/// Tells the pool what a socket's event meant.
fn on_happened(connection: *Connection, happened: pool_tcp.Happened) void {
    switch (happened) {
        .none => {},
        // A start chapulin refuses ends the attempt, and the pool owes no `close` event for a
        // connection that never started, so the socket closes here.
        .connected => if (!connection.session.started()) connection.socket.close(&loop),
        .failed => socket_ended(connection, .failed),
        .open_failed => socket_ended(connection, .open_failed),
    }
}

/// The socket ended before the pool was done with it, which the pool hears. In h11 a peer's
/// close may end a response, so it is a failure only if the run fails.
fn socket_ended(connection: *Connection, failure: Failure) void {
    connection.failure = failure;
    connection.session.peer_closed();
}

/// Steps the pool until it stops moving, then hands the socket its receive and its send.
fn step_session(connection: *Connection) void {
    // Bounded: each pass reads, writes or does what the pool asked, or stops.
    for (0..constants.steps_per_read_max) |_| {
        if (!step_once(connection)) break;
    }
    connection.socket.arm(&loop);
}

/// Steps the pool once, and does what it asked of the socket: the close first, then the open.
/// The step passes the octets the socket read and the room it has, while it carries the pool's
/// connection. Returns whether anything moved.
fn step_once(connection: *Connection) bool {
    const socket = &connection.socket;
    var none: [0]u8 = .{};
    const carrying = socket.carrying();
    const room = if (carrying) socket.room() else none[0..];
    // A full output waits for the send in flight, whose event steps the pool again.
    if (carrying and room.len == 0) return false;
    const step = connection.session.step(if (carrying) socket.unread() else none[0..], room);
    if (carrying) {
        socket.consume(step.consumed);
        socket.wrote(step.written);
    }
    assert(carrying or step.consumed + step.written == 0);
    if (step.close) socket.close(&loop);
    if (step.open) |to| open_socket(connection, to);
    return step.consumed + step.written > 0 or step.close or step.open != null;
}

/// Opens the socket the pool asked for, or tells the pool the system gave none.
fn open_socket(connection: *Connection, to: client.Address) void {
    if (!connection.socket.open(&loop, rotor_address(to))) socket_ended(connection, .open_failed);
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
    connection.socket.init(0);
    const address = client.Address.of(&test_octets, 0);
    try connection.session.init(&pool_config, address, constants.default_port, entropy.random(), 0, &test_plan, &bodies[0]);
    var none: [0]u8 = .{};
    try testing.expect(connection.session.step(&none, &none).open != null);
    return connection;
}

/// The connection of `test_connection`, started on its socket, and holding its exchange, which
/// it has not written: the test reads `connected` from the pool with no send. Test-only.
fn test_carrying() !*Connection {
    const connection = try test_connection();
    try testing.expect(connection.session.started());
    // In cleartext the connection reports `connected`, and the pool hands it the exchange.
    const reported = connection.session.pool.receive(.none, 0).event orelse return error.TestUnexpectedResult;
    try testing.expect(reported == .connected);
    return connection;
}

test "a socket that fails before its pool is done tells the pool, which asks for another" {
    const connection = try test_carrying();
    on_happened(connection, .failed);
    try testing.expectEqual(Failure.failed, connection.failure);
    // RFC 9113 §8.7: the request was never written, so it moves to another connection, and the
    // pool asks for a socket to carry it.
    var none: [0]u8 = .{};
    try testing.expect(connection.session.step(&none, &none).open != null);
}

test "a socket the system never gave ends the pool's attempt, and the exchange with it" {
    const connection = try test_connection();
    on_happened(connection, .open_failed);
    var none: [0]u8 = .{};
    const stepped = connection.session.step(&none, &none);
    try testing.expect(stepped.done and stepped.open == null);
    try testing.expectEqual(.refused, connection.session.exchanges[0].response.outcome);
}

test "a socket the pool asks for while its last one closes waits for that close" {
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    const connection = try test_carrying();
    on_happened(connection, .failed);
    // The socket that failed is closing, and its close's event has not arrived.
    connection.socket.state = .closing;
    try testing.expect(step_once(connection));
    try testing.expectEqual(.closing, connection.socket.state);
    try testing.expect(connection.socket.open_pending != null);
}
