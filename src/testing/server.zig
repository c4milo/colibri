//! The socket around `server_session.zig`: the server of design §9, which `tools/h2spec.sh` runs
//! the pinned h2spec against and h2load measures. Each connection is a connection of colibri's
//! `server` module (design §8 step 17a). `zig build http-server -- --port <port>` runs it in
//! cleartext, speaking h2 with prior knowledge (RFC 9113 §3.3), or h11 with `--h11` (design §8
//! step 15d). With `--tls <identity-prefix>` it serves TLS instead, and `server` runs each
//! handshake through `tls.record.Server`. Over TLS it offers `h2` and `http/1.1` through ALPN, or
//! `http/1.1` alone with `--h11`, and each connection speaks what its handshake selected (decision
//! 88).
//!
//! One worker per core, sharing nothing. Each worker has its own Rotor loop and its own listening
//! socket on the same port, bound with SO_REUSEPORT, so the kernel hands each new connection to
//! one worker and no worker reads another's memory: no lock, no atomic and no queue between cores
//! (CLAUDE.md, Performance). A worker holds its connections in a fixed array.
//!
//! No call here waits but the loop's `tick`, one system call per turn (decisions 46 and 58). A
//! worker keeps one accept in flight while it has a free slot, and each connection at most one
//! receive, one send and, at its end, one close. A peer that stops reading holds up only its own
//! connection: its octets wait in that connection's buffer.
//!
//! A receive writes into `received`, and its octets are appended to `input` when its event
//! arrives. The session consumes `input` from the front, which moves what is left, and Rotor owns
//! a receive's buffer until its final event (its rule 3), so a receive never targets `input`.
//! A send reads `output[output_sent..output_len]`, and the session only appends after that.
//!
//! This file holds no protocol rule: it reads octets into a buffer, hands them to a session,
//! writes back what the session produced, and closes when the session says it is done (RFC 9113
//! §5.4.1). Nothing here allocates: every worker, connection and buffer is in static storage
//! sized by `constants.zig`, and each loop runs on memory its worker holds.
//!
//! The TLS mode runs one worker. chapulin's generator is one process-wide state with no lock
//! (its `drbg.h`), so two threads must not run handshakes at once.
const std = @import("std");
const entropy = @import("entropy.zig");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");
const alpn = @import("alpn.zig");
const server_session = @import("server_session.zig");
const server_options = @import("server_options.zig");
const h11 = @import("h11");
const h11_echo = @import("h11/h11_echo.zig");
const server_identity = @import("tls/server_identity.zig");
const server = @import("server");
const tls = @import("tls");

const Session = server_session.Session;
const Protocol = alpn.Protocol;

/// What an operation a connection has in flight does. It rides in the operation's user data,
/// below the connection's slot.
const Kind = enum(u8) { receive, send, close };
const kind_bits = @bitSizeOf(Kind);

/// The user data of the one accept a worker keeps in flight. No slot's user data reaches it.
const accept_user_data: u64 = std.math.maxInt(u64);

/// The operations a worker's loop holds in flight: an accept, and for each connection a receive,
/// a send and a close.
const operations_per_connection: u32 = @typeInfo(Kind).@"enum".fields.len;
const loop_options: rotor.Loop.Options = .{
    .operations = constants.connections_per_worker_max * operations_per_connection + 1,
};

/// One connection a worker serves: the session, the octets read but not consumed, and the octets
/// the session produced that the socket has not taken yet. Over TLS, both hold records.
const Connection = struct {
    descriptor: rotor.Descriptor,
    session: Session,
    /// Where the receive in flight writes (see the header).
    received: [constants.wire_read_len]u8,
    input: [constants.wire_read_len]u8,
    input_len: usize,
    output: [constants.write_buffer_len]u8,
    /// Octets of `output` the session has produced.
    output_len: usize,
    /// Octets of `output` the socket has taken, which are always the first ones.
    output_sent: usize,
    /// The operations in flight. A slot is free again once it is closed and none is.
    receiving: bool,
    sending: bool,
    close_submitted: bool,
    closed: bool,
    /// Whether this slot holds a connection.
    live: bool,
    /// Whether the session is done, so the octets left are the last the peer gets.
    closing: bool,
    /// Whether the connection ends now, with nothing more sent: the peer left or a call failed.
    failed: bool,
};

/// One worker: a core's loop, listener and connections. One thread touches these fields, and the
/// loop's memory, aligned to a cache line or more, keeps the next worker off this one's lines.
const Worker = struct {
    /// Which of `workers` this is, which picks its slots' echoes.
    index: usize,
    loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(@max(rotor.memory_alignment, constants.cache_line_bytes)),
    loop: rotor.Loop,
    listener: rotor.Descriptor,
    accepting: bool,
    connections: [constants.connections_per_worker_max]Connection,
    events: [loop_options.operations]rotor.Event,
    /// The decoders the worker's h11 connections share, and the buffer they decode into
    /// (decisions 91 and 98).
    decoders: h11.coding.Pool(constants.h11_decoders_per_worker),
    decoded: [constants.h11_decoded_len]u8,
    /// The encoders the worker's connections code responses with in the `--coded` mode (decision
    /// 101).
    encoders: server.EncoderPool(constants.encoders_per_worker, server.constants.encoder_level_default),
    /// What every connection of the worker borrows: the TLS configuration or none, the protocol a
    /// cleartext connection speaks, and the decoders.
    config: server.Config,
};

/// The workers, in static storage: each is large, and there is one per core at most.
var workers: [constants.workers_max]Worker align(@alignOf(Worker)) = undefined;

comptime {
    // The loop's memory leads the struct, so its alignment is the struct's, and every worker
    // starts and ends on a cache line.
    assert(@alignOf(Worker) >= constants.cache_line_bytes);
    assert(@sizeOf(Worker) % constants.cache_line_bytes == 0);
    assert(loop_options.operations <= rotor.constants.batch_max);
    assert(constants.connections_per_worker_max < accept_user_data >> kind_bits);
}

/// The TLS mode's configuration, which `main` converts once when `--tls` names an identity and
/// every connection borrows, and the storage it points into.
var tls_shared: ?*const tls.record.ServerConfig = null;
var tls_config: tls.record.ServerConfig align(@alignOf(tls.record.ServerConfig)) = undefined;
var tls_identity: server_identity.Storage align(@alignOf(server_identity.Storage)) = undefined;

/// Runs one worker per core until the process is stopped, every one listening on `port`.
pub fn listen_and_serve(port: u16) !void {
    const cores = std.Thread.getCpuCount() catch 1;
    // One worker in the TLS mode: see the header.
    const count = if (tls_shared != null) 1 else @max(1, @min(cores, constants.workers_max));
    var threads: [constants.workers_max]?std.Thread = @splat(null);
    for (1..count) |index| {
        threads[index] = std.Thread.spawn(.{}, run_worker, .{ index, port }) catch null;
    }
    // The main thread is a worker too, so a one-core host spawns nothing.
    try run_worker(0, port);
    for (threads[1..count]) |thread| {
        if (thread) |handle| handle.join();
    }
}

/// Serves connections on `workers[index]` until the process is stopped.
fn run_worker(index: usize, port: u16) !void {
    const worker = &workers[index];
    worker.index = index;
    // Rotor's rule: the loop belongs to the thread that starts it.
    try worker.loop.init(&worker.loop_memory, loop_options);
    defer worker.loop.deinit();
    const address = rotor.Address.ipv4(listen_address, port);
    worker.listener = try rotor.sync.listen(&address, .{ .backlog = constants.kernel_backlog, .reuse_port = true });
    defer rotor.sync.close_now(worker.listener);
    if (index == 0) std.debug.print("http-server: listening on port {d}, rotor backend {t}\n", .{ port, rotor.backend() });
    for (&worker.connections) |*connection| connection.live = false;
    worker.accepting = false;
    // The CPU features stdx's decoders use, asked of the CPU once, here and not in colibri.
    worker.decoders.storage().reset(h11.coding.Features.detect());
    worker.config = .{
        .tls = tls_shared,
        .cleartext = switch (cleartext_protocol) {
            .h2 => .h2,
            .h11 => .h11,
        },
        .decoders = worker.decoders.storage(),
        .decoded = &worker.decoded,
        .h3_alternative = h3_alternative,
    };
    if (coded_mode) {
        worker.encoders.reset(server.coding_pool.Features.detect());
        worker.config.codings = &served_codings;
        worker.config.encoders = worker.encoders.encoders();
    }
    while (true) try turn(worker);
}

/// One turn of the loop: an accept when a slot is free, then one tick and its events.
fn turn(worker: *Worker) !void {
    arm_accept(worker);
    const count = try worker.loop.tick(&worker.events, rotor.constants.wait_ns_max);
    for (worker.events[0..count]) |event| on_event(worker, event);
}

fn on_event(worker: *Worker, event: rotor.Event) void {
    if (event.user_data == accept_user_data) return on_accept(worker, event);
    const slot: usize = @intCast(event.user_data >> kind_bits);
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data)));
    const connection = &worker.connections[slot];
    assert(connection.live);
    switch (kind) {
        .receive => on_received(connection, event),
        .send => on_sent(connection, event),
        .close => connection.closed = true,
    }
    if (connection.closed and !connection.receiving and !connection.sending) {
        // Over TLS this wipes the session's secrets.
        connection.session.connection.transport_closed();
        connection.live = false;
        return;
    }
    arm(worker, slot);
}

/// Keeps one accept in flight while a slot is free. A worker with every slot taken leaves new
/// connections in the kernel's backlog until one frees.
fn arm_accept(worker: *Worker) void {
    if (worker.accepting or free_slot(worker) == null) return;
    const taken = worker.loop.submit(&.{rotor.Operation.accept(accept_user_data, worker.listener, false)}, &.{});
    assert(taken == 1);
    worker.accepting = true;
}

/// Takes the connection an accept delivered into a free slot.
fn on_accept(worker: *Worker, event: rotor.Event) void {
    worker.accepting = false;
    const descriptor: rotor.Descriptor = @intCast(event.outcome() catch return);
    const slot = free_slot(worker) orelse unreachable; // `arm_accept` waits for one.
    const connection = &worker.connections[slot];
    connection.descriptor = descriptor;
    connection.input_len = 0;
    connection.output_len = 0;
    connection.output_sent = 0;
    connection.receiving = false;
    connection.sending = false;
    connection.close_submitted = false;
    connection.closed = false;
    connection.closing = false;
    connection.failed = false;
    connection.live = true;
    // `server_options.read` refuses `--echo` but for h11 in cleartext.
    const echo: ?*h11_echo.Echo = if (echo_mode) &echoes[worker.index][slot] else null;
    connection.session.init(&worker.config, entropy.random(), echo) catch {
        connection.failed = true;
    };
    arm(worker, slot);
}

/// The index of a slot this worker can put a connection in.
fn free_slot(worker: *Worker) ?usize {
    for (&worker.connections, 0..) |*connection, index| {
        if (!connection.live) return index;
    }
    return null;
}

/// Appends what a receive read to the input and steps the session over it. A receive of no
/// octets is the peer closing its side, which ends the connection.
fn on_received(connection: *Connection, event: rotor.Event) void {
    connection.receiving = false;
    const read = event.outcome() catch 0;
    if (read == 0) {
        connection.failed = true;
        return;
    }
    assert(read <= connection.input.len - connection.input_len);
    @memcpy(connection.input[connection.input_len..][0..read], connection.received[0..read]);
    connection.input_len += read;
    step(connection);
}

/// Counts what a send took, and steps the session: the room the send freed may be what it
/// waited for.
fn on_sent(connection: *Connection, event: rotor.Event) void {
    connection.sending = false;
    const sent = event.outcome() catch {
        connection.failed = true;
        return;
    };
    connection.output_sent += sent;
    assert(connection.output_sent <= connection.output_len);
    // Every octet is gone and no send is in flight, so the buffer starts again at its front.
    if (connection.output_sent == connection.output_len) {
        connection.output_len = 0;
        connection.output_sent = 0;
    }
    step(connection);
}

/// Submits what the connection needs next: its close once it is failed or finished and drained,
/// otherwise a send of what is owed and a receive while there is room for more.
fn arm(worker: *Worker, slot: usize) void {
    const connection = &worker.connections[slot];
    if (connection.close_submitted) return;
    const drained = connection.output_sent == connection.output_len;
    if (connection.failed or (connection.closing and drained)) return submit(worker, slot, .close);
    if (!connection.sending and !drained) submit(worker, slot, .send);
    const room = connection.input.len - connection.input_len;
    if (!connection.receiving and !connection.closing and room > 0) submit(worker, slot, .receive);
}

/// Submits one operation for the connection in `slot`. The loop holds one of each kind for every
/// connection, so it always has room.
fn submit(worker: *Worker, slot: usize, kind: Kind) void {
    const connection = &worker.connections[slot];
    const user_data = (@as(u64, slot) << kind_bits) | @intFromEnum(kind);
    const operation = switch (kind) {
        .receive => blk: {
            const room = connection.input.len - connection.input_len;
            connection.receiving = true;
            break :blk rotor.Operation.receive(user_data, connection.descriptor, connection.received[0..@min(room, connection.received.len)]);
        },
        .send => blk: {
            connection.sending = true;
            break :blk rotor.Operation.send(user_data, connection.descriptor, connection.output[connection.output_sent..connection.output_len]);
        },
        // Rotor's close cancels the connection's receive and send first.
        .close => blk: {
            connection.close_submitted = true;
            break :blk rotor.Operation.close(user_data, connection.descriptor);
        },
    };
    const taken = worker.loop.submit(&.{operation}, &.{});
    assert(taken == 1);
}

/// Steps the session until it stops moving, appending what it writes to the output buffer.
fn step(connection: *Connection) void {
    if (connection.failed or connection.close_submitted) return;
    for (0..constants.steps_per_read_max) |_| {
        const room = connection.output[connection.output_len..];
        if (room.len == 0) return;
        const stepped = connection.session.step(connection.input[0..connection.input_len], room);
        connection.output_len += stepped.written;
        consume(connection, stepped.consumed);
        if (stepped.done) {
            connection.closing = true;
            return;
        }
        if (stepped.consumed == 0 and stepped.written == 0) return;
    }
}

/// Drops the `consumed` octets the session took, moving what is left to the front.
fn consume(connection: *Connection, consumed: usize) void {
    assert(consumed <= connection.input_len);
    if (consumed == 0) return;
    std.mem.copyForwards(u8, &connection.input, connection.input[consumed..connection.input_len]);
    connection.input_len -= consumed;
}

/// What the command line asked for, which `main` sets before any worker starts.
var cleartext_protocol: Protocol align(@alignOf(Protocol)) = .h2;
var listen_address: [server_options.ipv4_octets]u8 = server_options.loopback_octets;
var echo_mode: bool = false;
/// Whether responses are coded (`--coded`), in gzip or deflate, gzip first.
var coded_mode: bool = false;
const served_codings = [_]server.Coding{ .gzip, .deflate };
/// The h3 endpoint each TLS connection advertises (`--h3-port`), or null.
var h3_alternative: ?server.Alternative align(@alignOf(?server.Alternative)) = null;

/// Where each connection slot of each worker keeps its echo in the `--echo` mode. Apart from the
/// sessions, so the mode costs every other one nothing, and mapped by the operating system only
/// when a connection touches it.
var echoes: [constants.workers_max][constants.connections_per_worker_max]h11_echo.Echo align(@alignOf(h11_echo.Echo)) = undefined;

/// Runs the server: `zig build http-server -- [options]` (`server_options.zig`).
pub fn main(init: std.process.Init.Minimal) !void {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.skip();
    const options = server_options.read(&arguments) orelse {
        std.debug.print(server_options.usage, .{});
        std.process.exit(exit_usage);
    };
    cleartext_protocol = options.protocol;
    listen_address = options.address;
    echo_mode = options.echo;
    coded_mode = options.coded;
    if (options.h3_port) |port| h3_alternative = .{ .port = port };
    if (options.identity_prefix) |prefix| try load_tls(prefix, options.protocol);
    try listen_and_serve(options.port);
}

/// Loads the identity, converts what every TLS connection borrows, and runs chapulin's check on
/// the identity once. With `--h11` the server offers `http/1.1` alone.
fn load_tls(prefix: []const u8, protocol: Protocol) !void {
    server_identity.seed(&tls_identity);
    const protocols: []const []const u8 = if (protocol == .h11) &alpn.alpn_h11 else &alpn.alpn_both;
    try tls_config.init(try server_identity.load(prefix, &tls_identity, protocols));
    try tls_config.check(entropy.random());
    tls_shared = &tls_config;
}

/// The exit status of a run asked for something this build cannot do.
const exit_usage: u8 = 2;

const testing = std.testing;

/// An identity of the right lengths that nothing signs with: the test's handshake never runs.
/// Each certificate is an empty DER SEQUENCE. Test-only.
const test_der = [_]u8{ der_sequence_tag, 0 };
const der_sequence_tag: u8 = 0x30;
const test_chain = [_][]const u8{&test_der};
const test_private_key: [tls.constants.p256_private_key_len]u8 = @splat(1);
const test_public_key: [tls.constants.p256_public_key_len]u8 = @splat(1);
const test_cookie: [tls.constants.server_key_len]u8 = @splat(1);

test "a TLS connection's session is wiped when its slot is freed" {
    try tls_config.init(.{
        .ecdsa_p256 = .{ .chain = &test_chain, .public_key = &test_public_key, .private_key = &test_private_key },
        .cookie_key = &test_cookie,
        .alpn = &alpn.alpn_both,
    });
    const worker = &workers[0];
    const slot: usize = 0;
    worker.config = .{ .tls = &tls_config };
    const connection = &worker.connections[slot];
    connection.* = undefined;
    connection.live = true;
    connection.receiving = false;
    connection.sending = false;
    connection.closed = false;
    try connection.session.init(&worker.config, entropy.random(), null);
    try testing.expect(connection.session.connection.tls_server.session.recordState() != .closed);
    // Rotor's close of the connection is its last operation: the slot is freed on it.
    const user_data = (@as(u64, slot) << kind_bits) | @intFromEnum(Kind.close);
    on_event(worker, .{ .user_data = user_data, .result = 0, .flags = .{} });
    try testing.expect(!connection.live);
    try testing.expectEqual(.closed, connection.session.connection.tls_server.session.recordState());
}
