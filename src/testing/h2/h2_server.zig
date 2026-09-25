//! The socket around `h2_session.zig`: the h2 server of design §9, which `tools/h2spec.sh` runs
//! the pinned h2spec against and h2load measures. `zig build h2-server -- --port <port>` runs it
//! in cleartext with prior knowledge (RFC 9113 §3.3). With `--tls <identity-prefix>` it serves h2
//! over TLS (§3.2) instead, through chapulin's record-mode server and `h2_tls.zig`, which needs a
//! build given `-Dchapulin-server` (design §8 step 5).
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
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");
const h2_session = @import("h2_session.zig");
const h2_tls = @import("h2_tls.zig");
const server_identity = @import("../tls/server_identity.zig");

const Session = h2_session.Session;

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
/// the session produced that the socket has not taken yet.
const Connection = struct {
    descriptor: rotor.Descriptor,
    session: Session,
    /// The TLS layer the connection runs over, or null in cleartext. Its octets are records, and
    /// `input` and `output` hold them as they cross the socket.
    layer: ?*h2_tls.Layer,
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
    loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(@max(rotor.memory_alignment, constants.cache_line_bytes)),
    loop: rotor.Loop,
    listener: rotor.Descriptor,
    accepting: bool,
    connections: [constants.connections_per_worker_max]Connection,
    events: [loop_options.operations]rotor.Event,
};

/// The workers, in static storage: each is large, and there is one per core at most.
var workers: [constants.workers_max]Worker = undefined;

comptime {
    // The loop's memory leads the struct, so its alignment is the struct's, and every worker
    // starts and ends on a cache line.
    assert(@alignOf(Worker) >= constants.cache_line_bytes);
    assert(@sizeOf(Worker) % constants.cache_line_bytes == 0);
    assert(loop_options.operations <= rotor.constants.batch_max);
    assert(constants.connections_per_worker_max < accept_user_data >> kind_bits);
}

/// The TLS mode's shared state, which `main` loads when `--tls` names an identity, and one TLS
/// layer per connection slot of the one worker the mode runs.
var tls_shared: ?h2_tls.Shared = null;
var tls_identity: server_identity.Storage = undefined;
var tls_layers: [constants.connections_per_worker_max]h2_tls.Layer = undefined;

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
    // Rotor's rule: the loop belongs to the thread that starts it.
    try worker.loop.init(&worker.loop_memory, loop_options);
    defer worker.loop.deinit();
    const address = rotor.Address.ipv4(loopback_octets, port);
    worker.listener = try rotor.sync.listen(&address, .{ .backlog = constants.kernel_backlog, .reuse_port = true });
    defer rotor.sync.close_now(worker.listener);
    if (index == 0) std.debug.print("h2-server: listening on port {d}, rotor backend {t}\n", .{ port, rotor.backend() });
    for (&worker.connections) |*connection| connection.live = false;
    worker.accepting = false;
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
    connection.session.init();
    connection.input_len = 0;
    connection.output_len = 0;
    connection.output_sent = 0;
    connection.receiving = false;
    connection.sending = false;
    connection.close_submitted = false;
    connection.closed = false;
    connection.closing = false;
    connection.failed = false;
    connection.layer = null;
    connection.live = true;
    if (tls_shared) |*shared| {
        connection.layer = start_tls(slot, shared) catch blk: {
            connection.failed = true;
            break :blk null;
        };
    }
    arm(worker, slot);
}

/// Gives a new connection the TLS layer of its slot, ready to read a ClientHello.
fn start_tls(index: usize, shared: *const h2_tls.Shared) !*h2_tls.Layer {
    if (comptime !h2_tls.available) unreachable; // `main` refuses `--tls` without chapulin.
    const layer = &tls_layers[index];
    try h2_tls.start(layer, shared);
    return layer;
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

/// Steps the connection's session over its input, cleartext or through its TLS layer.
fn step(connection: *Connection) void {
    if (connection.failed or connection.close_submitted) return;
    if (connection.layer) |layer| {
        step_tls(connection, layer) catch {
            connection.failed = true;
        };
    } else step_session(connection);
}

/// Steps the session until it stops moving, appending what it writes to the output buffer.
fn step_session(connection: *Connection) void {
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

/// Steps a TLS connection: records in from `input`, records out into `output` (`h2_tls.zig`).
fn step_tls(connection: *Connection, layer: *h2_tls.Layer) !void {
    if (comptime !h2_tls.available) unreachable; // No layer exists without chapulin.
    const stepped = try h2_tls.step(
        layer,
        &connection.session,
        connection.input[0..connection.input_len],
        connection.output[connection.output_len..],
    );
    connection.output_len += stepped.written;
    consume(connection, stepped.consumed);
    if (stepped.done) connection.closing = true;
}

/// Drops the `consumed` octets the session took, moving what is left to the front.
fn consume(connection: *Connection, consumed: usize) void {
    assert(consumed <= connection.input_len);
    if (consumed == 0) return;
    std.mem.copyForwards(u8, &connection.input, connection.input[consumed..connection.input_len]);
    connection.input_len -= consumed;
}

/// The address the server listens on: the loopback, because it serves tests alone. RFC 1122
/// §3.2.1.3 reserves 127.0.0.0/8 for the local host.
const loopback_octets = [_]u8{ loopback_first, 0, 0, 1 };
const loopback_first: u8 = 127;

/// The command-line options, as `tools/h2spec.sh` passes them: the port, and the prefix of the
/// identity files `tools/h2_interop/tls_identity.go` wrote, which turns the TLS mode on.
const port_option = "--port";
const tls_option = "--tls";

/// What the command line asked for.
const Options = struct {
    port: u16 = constants.default_port,
    identity_prefix: ?[]const u8 = null,
};

/// Runs the server: `zig build h2-server -- --port <port> [--tls <identity-prefix>]`.
pub fn main(init: std.process.Init.Minimal) !void {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.skip();
    const options = read_options(&arguments);
    if (options.identity_prefix) |prefix| try load_tls(prefix);
    try listen_and_serve(options.port);
}

/// Reads `--port` and `--tls`, each followed by its value. An unreadable port is the default.
fn read_options(arguments: *std.process.Args.Iterator) Options {
    var options: Options = .{};
    for (0..constants.arguments_max) |_| {
        const argument = arguments.next() orelse break;
        const value = arguments.next() orelse break;
        if (std.mem.eql(u8, argument, port_option)) {
            options.port = std.fmt.parseInt(u16, value, constants.port_radix) catch constants.default_port;
        }
        if (std.mem.eql(u8, argument, tls_option)) options.identity_prefix = value;
    }
    return options;
}

/// Loads what every TLS connection shares, and runs chapulin's boot check on the identity once.
fn load_tls(prefix: []const u8) !void {
    if (comptime !h2_tls.available) {
        std.debug.print("h2-server: built without chapulin; pass -Dchapulin-server=<checkout>\n", .{});
        std.process.exit(exit_usage);
    }
    try server_identity.seed(&tls_identity);
    const shared: h2_tls.Shared = .{
        .identity = try server_identity.load(prefix, &tls_identity),
        .cookie_key = &tls_identity.cookie_key,
    };
    // `ch_srv_check` reads the configuration alone, so the first slot's server carries it.
    const probe = &tls_layers[0];
    probe.server.init(.{ .identity = shared.identity, .cookie_key = shared.cookie_key, .receive = &probe.receive });
    try probe.server.check();
    tls_shared = shared;
}

/// The exit status of a run asked for something this build cannot do.
const exit_usage: u8 = 2;
