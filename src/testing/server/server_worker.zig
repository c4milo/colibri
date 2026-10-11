//! One worker of the test-only server (`../server.zig`): a core's Rotor loop, its listening socket
//! and its connections, in a fixed array. A worker keeps one accept in flight while it has a free
//! slot, hands each event to the connection it names (`server_socket.zig`), and wakes each
//! connection whose deadline has passed. Split off `../server.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const h11 = @import("h11");
const server = @import("server");
const constants = @import("../constants.zig");
const entropy = @import("../entropy.zig");
const h11_echo = @import("../h11/h11_echo.zig");
const server_mode = @import("server_mode.zig");
const server_socket = @import("server_socket.zig");

const Connection = server_socket.Connection;
const Kind = server_socket.Kind;
const kind_bits = server_socket.kind_bits;

/// The user data of the one accept a worker keeps in flight. No slot's user data reaches it.
const accept_user_data: u64 = std.math.maxInt(u64);

/// The operations a worker's loop holds in flight: an accept, and for each connection a receive,
/// a send and a close.
const loop_options: rotor.Loop.Options = .{
    .operations = constants.connections_per_worker_max * server_socket.operations_per_connection + 1,
};

/// One worker: a core's loop, listener and connections. One thread touches these fields, and the
/// loop's memory, aligned to a cache line or more, keeps the next worker off this one's lines.
pub const Worker = struct {
    /// Which of `workers` this is, which picks its slots' echoes.
    index: usize,
    loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(@max(rotor.memory_alignment, constants.cache_line_bytes)),
    loop: rotor.Loop,
    listener: rotor.Descriptor,
    accepting: bool,
    connections: [constants.connections_per_worker_max]Connection,
    events: [loop_options.operations]rotor.Event,
    /// The h11 decoders the worker's connections share, and their buffer (decisions 91 and 98).
    decoders: h11.coding.Pool(constants.h11_decoders_per_worker),
    decoded: [constants.h11_decoded_len]u8,
    /// The encoders the worker's connections code responses with under `--coded` (decision 101).
    encoders: server.EncoderPool(constants.encoders_per_worker, server.constants.encoder_level_default),
    /// What every connection of the worker borrows: the TLS configuration or none, the protocol a
    /// cleartext connection speaks, and the decoders.
    config: server.Config,
};

/// The workers, in static storage: each is large, and there is one per core at most.
pub var workers: [constants.workers_max]Worker align(@alignOf(Worker)) = undefined;

comptime {
    // The loop's memory leads the struct, so its alignment is the struct's, and every worker
    // starts and ends on a cache line.
    assert(@alignOf(Worker) >= constants.cache_line_bytes);
    assert(@sizeOf(Worker) % constants.cache_line_bytes == 0);
    assert(loop_options.operations <= rotor.constants.batch_max);
    assert(constants.connections_per_worker_max < accept_user_data >> kind_bits);
}

/// Where each connection slot of each worker keeps its echo in the `--echo` mode. Apart from the
/// sessions, so the mode costs every other one nothing, and mapped by the operating system only
/// when a connection touches it.
var echoes: [constants.workers_max][constants.connections_per_worker_max]h11_echo.Echo align(@alignOf(h11_echo.Echo)) = undefined;

/// Binds the listener of each of the first `count` workers, before any worker runs, and returns
/// the port they share. With a `port` of 0 the first takes the port the kernel chooses, and the
/// others bind that one (https://github.com/c4milo/colibri/issues/94).
pub fn bind_listeners(port: u16, count: usize) !u16 {
    assert(count >= 1 and count <= constants.workers_max);
    var bound = port;
    for (workers[0..count], 0..) |*worker, index| {
        const address = rotor.Address.ipv4(server_mode.listen_address, bound);
        worker.listener = try rotor.sync.listen(&address, .{ .backlog = constants.kernel_backlog, .reuse_port = true });
        const local = try rotor.sync.local_address(worker.listener);
        // SO_REUSEPORT: each worker's listener has the port of the first.
        assert(index == 0 or local.port == bound);
        bound = local.port;
    }
    assert(bound != 0);
    return bound;
}

/// Serves connections on `workers[index]`, whose listener is bound, until the process is stopped.
pub fn run(index: usize) !void {
    const worker = &workers[index];
    worker.index = index;
    // Rotor's rule: the loop belongs to the thread that starts it.
    try worker.loop.init(&worker.loop_memory, loop_options);
    defer worker.loop.deinit();
    defer rotor.sync.close_now(worker.listener);
    for (&worker.connections) |*connection| connection.live = false;
    worker.accepting = false;
    // The CPU features stdx's decoders use, asked of the CPU once, here and not in colibri.
    worker.decoders.storage().reset(h11.coding.Features.detect());
    worker.config = .{
        .tls = server_mode.tls_shared,
        .versions = server_mode.versions,
        .decoders = worker.decoders.storage(),
        .decoded = &worker.decoded,
        .h3_alternative = server_mode.h3_alternative,
    };
    if (server_mode.coded_mode) {
        worker.encoders.reset(server.Features.detect());
        worker.config.codings = &server_mode.served_codings;
        worker.config.encoders = worker.encoders.encoders();
    }
    while (true) try turn(worker);
}

/// One turn of the loop: an accept when a slot is free, one tick and its events, then the
/// connections whose deadline has passed.
fn turn(worker: *Worker) !void {
    arm_accept(worker);
    const count = try worker.loop.tick(&worker.events, wait_ns(worker));
    const now_ns = worker.loop.now_ns();
    for (worker.events[0..count]) |event| on_event(worker, event, now_ns);
    wake(worker, now_ns);
}

/// How long the next tick may wait: until the soonest deadline of a live connection, and never
/// longer than Rotor's longest wait.
fn wait_ns(worker: *const Worker) u64 {
    const now_ns = worker.loop.now_ns();
    var wait: u64 = rotor.constants.wait_ns_max;
    for (&worker.connections) |*connection| {
        if (!connection.live or connection.close_submitted or connection.failed) continue;
        const deadline_ns = connection.session.deadline_ns() orelse continue;
        wait = @min(wait, deadline_ns -| now_ns);
    }
    return wait;
}

/// Hands each live connection whose deadline has passed the instant, and sends what it then owes.
fn wake(worker: *Worker, now_ns: u64) void {
    for (&worker.connections, 0..) |*connection, slot| {
        if (!connection.live or connection.close_submitted or connection.failed) continue;
        const deadline_ns = connection.session.deadline_ns() orelse continue;
        if (deadline_ns > now_ns) continue;
        connection.session.on_instant(now_ns);
        connection.step(now_ns);
        connection.arm(&worker.loop, slot);
    }
}

fn on_event(worker: *Worker, event: rotor.Event, now_ns: u64) void {
    if (event.user_data == accept_user_data) return on_accept(worker, event, now_ns);
    const slot: usize = @intCast(event.user_data >> kind_bits);
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data)));
    const connection = &worker.connections[slot];
    assert(connection.live);
    switch (kind) {
        .receive => connection.on_received(event, now_ns),
        .send => connection.on_sent(event, now_ns),
        .close => connection.closed = true,
    }
    if (connection.closed and !connection.receiving and !connection.sending) {
        // Over TLS this wipes the session's secrets.
        connection.session.connection.transport_closed();
        connection.live = false;
        return;
    }
    connection.arm(&worker.loop, slot);
}

/// Keeps one accept in flight while a slot is free. A worker with every slot taken leaves new
/// connections in the kernel's backlog until one frees.
fn arm_accept(worker: *Worker) void {
    if (worker.accepting or free_slot(worker) == null) return;
    const taken = worker.loop.submit(&.{rotor.Operation.accept(accept_user_data, worker.listener, false)}, &.{});
    assert(taken == 1);
    worker.accepting = true;
}

/// Takes the connection an accept delivered into a free slot, at `now_ns`.
fn on_accept(worker: *Worker, event: rotor.Event, now_ns: u64) void {
    worker.accepting = false;
    const descriptor: rotor.Descriptor = @intCast(event.outcome() catch return);
    const slot = free_slot(worker) orelse unreachable; // `arm_accept` waits for one.
    const connection = &worker.connections[slot];
    connection.open(descriptor);
    // `server_options.read` refuses `--echo` but for h11 in cleartext.
    const echo: ?*h11_echo.Echo = if (server_mode.echo_mode) &echoes[worker.index][slot] else null;
    connection.session.init(&worker.config, entropy.random(), echo, now_ns) catch {
        connection.failed = true;
    };
    connection.arm(&worker.loop, slot);
}

/// The index of a slot this worker can put a connection in.
fn free_slot(worker: *Worker) ?usize {
    for (&worker.connections, 0..) |*connection, index| {
        if (!connection.live) return index;
    }
    return null;
}

const testing = std.testing;
const tls = @import("tls");
const alpn = @import("../alpn.zig");
const cpu = @import("../cpu.zig");

/// An identity of the right lengths that nothing signs with: the test's handshake never runs.
/// Each certificate is an empty DER SEQUENCE. Test-only.
const test_der = [_]u8{ der_sequence_tag, 0 };
const der_sequence_tag: u8 = 0x30;
const test_chain = [_][]const u8{&test_der};
const test_private_key: [tls.constants.p256_private_key_len]u8 = @splat(1);
const test_public_key: [tls.constants.p256_public_key_len]u8 = @splat(1);
const test_cookie: [tls.constants.server_key_len]u8 = @splat(1);

test "with port 0, every worker's listener has the port the kernel chose for the first" {
    const count = 3;
    const bound = try bind_listeners(0, count);
    defer for (workers[0..count]) |*worker| rotor.sync.close_now(worker.listener);
    try testing.expect(bound != 0);
    for (workers[0..count]) |*worker| {
        try testing.expectEqual(bound, (try rotor.sync.local_address(worker.listener)).port);
    }
}

test "a TLS connection's session is wiped when its slot is freed" {
    try server_mode.tls_config.init(.{
        .ecdsa_p256 = .{ .chain = &test_chain, .public_key = &test_public_key, .private_key = &test_private_key },
        .cookie_key = &test_cookie,
        .alpn = &alpn.alpn_both,
        .cpu = cpu.probe(),
    });
    const worker = &workers[0];
    const slot: usize = 0;
    worker.config = .{ .tls = &server_mode.tls_config };
    const connection = &worker.connections[slot];
    connection.* = undefined;
    connection.live = true;
    connection.receiving = false;
    connection.sending = false;
    connection.closed = false;
    try connection.session.init(&worker.config, entropy.random(), null, 0);
    try testing.expect(connection.session.connection.tls_server.session.recordState() != .closed);
    // Rotor's close of the connection is its last operation: the slot is freed on it.
    on_event(worker, .{ .user_data = server_socket.user_data(slot, .close), .result = 0, .flags = .{} }, 0);
    try testing.expect(!connection.live);
    try testing.expectEqual(.closed, connection.session.connection.tls_server.session.recordState());
}
