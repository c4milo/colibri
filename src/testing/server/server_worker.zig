//! One worker of the test-only server (`../server.zig`): a core's Rotor loop, its listening socket,
//! its sockets in a fixed array, and one session, whose endpoint serves every connection of the
//! worker (`server_session.zig`, design §8 step 21b.6).
//!
//! Each turn waits in the loop's `tick` until an operation ends or the endpoint's next deadline
//! passes. It hands each event to the socket it names (`server_socket.zig`), hands the endpoint
//! the instant when a deadline is due, steps every entry a socket or the endpoint named, and last
//! submits what each socket it changed needs next. A socket whose peer closed first tells the
//! endpoint, which ends its connection.
//!
//! A socket and its entry in the session share an index, and the worker accepts from the kernel
//! only while a socket is free. Every connection the endpoint holds belongs to a socket that is
//! not free, so a free socket implies a free slot in the endpoint.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const h11 = @import("h11");
const server = @import("server");
const constants = @import("../constants.zig");
const entropy = @import("../entropy.zig");
const h11_echo = @import("../h11/h11_echo.zig");
const server_mode = @import("server_mode.zig");
const server_session = @import("server_session.zig");
const server_socket = @import("server_socket.zig");

const Socket = server_socket.Socket;
const Kind = server_socket.Kind;
const kind_bits = server_socket.kind_bits;
const Touched = std.bit_set.IntegerBitSet(constants.connections_per_worker_max);

/// The user data of the one accept a worker keeps in flight. No socket's user data reaches it.
pub const accept_user_data: u64 = std.math.maxInt(u64);

/// The operations a worker's loop holds in flight: an accept, and for each socket a receive, a
/// send and a close.
const loop_options: rotor.Loop.Options = .{
    .operations = constants.connections_per_worker_max * server_socket.operations_per_socket + 1,
};

/// Steps one turn takes at most. A step that leaves its entry pending is taken again, so this
/// only bounds the loop, and what it leaves keeps the next tick from waiting.
const steps_per_turn_max: usize = constants.connections_per_worker_max * constants.steps_per_read_max;

/// One worker: a core's loop, listener, sockets and session. One thread touches these fields
/// once the worker runs, and the loop's memory, aligned to a cache line or more, keeps the next
/// worker off this one's lines.
pub const Worker = struct {
    /// Which of `workers` this is, which picks its sockets' echoes.
    index: usize,
    loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(@max(rotor.memory_alignment, constants.cache_line_bytes)),
    loop: rotor.Loop,
    listener: rotor.Descriptor,
    accepting: bool,
    sockets: [constants.connections_per_worker_max]Socket,
    /// The sockets this turn changed, which it arms at its end.
    touched: Touched,
    events: [loop_options.operations]rotor.Event,
    /// The h11 decoders the worker's connections share, and their buffer (decisions 91 and 98).
    decoders: h11.coding.Pool(constants.h11_decoders_per_worker),
    decoded: [constants.h11_decoded_len]u8,
    /// The encoders the worker's connections code responses with under `--coded` (decision 101).
    encoders: server.EncoderPool(constants.encoders_per_worker, server.constants.encoder_level_default),
    /// What the worker's endpoint serves under: the identity or none, the versions, and the
    /// decoders.
    config: server.Config,
    /// The endpoint and what each socket's connection owes. It stays where `start` found it.
    session: server_session.Session,
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

/// Where each socket of each worker keeps its echo in the `--echo` mode. Apart from the
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

/// Prepares `workers[index]` and starts its endpoint under what the command line asked for
/// (`server_mode.zig`). The main thread calls it for every worker before a listener is bound, so
/// an identity the endpoint refuses ends the run before a peer can connect.
pub fn start(index: usize) server.StartError!void {
    const worker = &workers[index];
    worker.index = index;
    for (&worker.sockets) |*socket| socket.live = false;
    worker.accepting = false;
    worker.touched = Touched.initEmpty();
    // The CPU features stdx's decoders use, asked of the CPU once, here and not in colibri.
    worker.decoders.storage().reset(h11.coding.Features.detect());
    worker.config = .{
        .tls = server_mode.identity,
        .protocols = server_mode.versions,
        .decoders = worker.decoders.storage(),
        .decoded = &worker.decoded,
        .h3_alternative = server_mode.h3_alternative,
    };
    if (server_mode.coded_mode) {
        worker.encoders.reset(server.Features.detect());
        worker.config.codings = &server_mode.served_codings;
        worker.config.encoders = worker.encoders.encoders();
    }
    // The loop starts on the worker's own thread, later, so no instant is read yet. The endpoint
    // takes this one for its tickets' clock alone, and the server issues no ticket.
    try worker.session.init(&worker.config, entropy.random(), 0);
}

/// Serves connections on `workers[index]`, which `start` prepared and whose listener is bound,
/// until the process is stopped.
pub fn run(index: usize) !void {
    const worker = &workers[index];
    // Rotor's rule: the loop belongs to the thread that starts it.
    try worker.loop.init(&worker.loop_memory, loop_options);
    defer worker.loop.deinit();
    defer rotor.sync.close_now(worker.listener);
    while (true) try turn(worker);
}

/// One turn of the loop: an accept when a socket is free, one tick, what its events ask for, and
/// then the operations each socket it changed needs next.
fn turn(worker: *Worker) !void {
    arm_accept(worker);
    const deadline_ns = worker.session.deadline_ns();
    const count = try worker.loop.tick(&worker.events, wait_ns(worker, deadline_ns, worker.loop.now_ns()));
    const now_ns = worker.loop.now_ns();
    handle(worker, worker.events[0..count], deadline_ns, now_ns);
    arm(worker);
}

/// How long the tick after `now_ns` may wait: until `deadline_ns`, the soonest deadline of a
/// connection, and never longer than Rotor's longest wait. No time while the session has work
/// left.
pub fn wait_ns(worker: *const Worker, deadline_ns: ?u64, now_ns: u64) u64 {
    if (!worker.session.settled()) return 0;
    const at_ns = deadline_ns orelse return rotor.constants.wait_ns_max;
    return @min(rotor.constants.wait_ns_max, at_ns -| now_ns);
}

/// What a turn does with its tick's events at `now_ns`, with no call on the loop: each event goes
/// to its socket, the endpoint gets the instant when `deadline_ns`, read before the tick, has
/// passed, and every entry an event named is stepped.
pub fn handle(worker: *Worker, events: []const rotor.Event, deadline_ns: ?u64, now_ns: u64) void {
    for (events) |event| on_event(worker, event, now_ns);
    const due = if (deadline_ns) |at_ns| at_ns <= now_ns else false;
    // With no deadline due the endpoint has nothing to fire, so the call is skipped.
    if (due or worker.session.undrained) worker.session.on_instant(now_ns);
    serve(worker, now_ns);
}

fn on_event(worker: *Worker, event: rotor.Event, now_ns: u64) void {
    if (event.user_data == accept_user_data) return on_accept(worker, event, now_ns);
    const index: usize = @intCast(event.user_data >> kind_bits);
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data)));
    const socket = &worker.sockets[index];
    assert(socket.live);
    switch (kind) {
        .receive => socket.on_received(event),
        .send => socket.on_sent(event),
        .close => socket.closed = true,
    }
    // The peer closed first, or the socket failed: the endpoint ends the connection.
    if (socket.failed) worker.session.peer_closed(index, now_ns);
    worker.session.mark(index);
}

/// Keeps one accept in flight while a socket is free. A worker with every socket taken leaves
/// new connections in the kernel's backlog until one frees.
fn arm_accept(worker: *Worker) void {
    if (worker.accepting or free_socket(worker) == null) return;
    const taken = worker.loop.submit(&.{rotor.Operation.accept(accept_user_data, worker.listener, false)}, &.{});
    assert(taken == 1);
    worker.accepting = true;
}

/// Takes the socket an accept delivered into a free entry, at `now_ns`, and starts its
/// connection in the endpoint.
fn on_accept(worker: *Worker, event: rotor.Event, now_ns: u64) void {
    worker.accepting = false;
    const descriptor: rotor.Descriptor = @intCast(event.outcome() catch return);
    const index = free_socket(worker) orelse unreachable; // `arm_accept` waits for one.
    const socket = &worker.sockets[index];
    socket.open(descriptor);
    // `server_options.read` refuses `--echo` but for h11 in cleartext.
    const echo: ?*h11_echo.Echo = if (server_mode.echo_mode) &echoes[worker.index][index] else null;
    const security: server.Security = if (server_mode.identity != null) .tls else .cleartext;
    // A free socket implies a free slot, so the endpoint refuses only a session chapulin does
    // not start.
    if (!worker.session.accept(index, security, echo, now_ns)) socket.failed = true;
    worker.session.mark(index);
}

/// The index of an entry this worker can put a socket in.
pub fn free_socket(worker: *Worker) ?usize {
    for (&worker.sockets, 0..) |*socket, index| {
        if (!socket.live) return index;
    }
    return null;
}

/// Steps every entry a socket or the endpoint named, until none is named.
fn serve(worker: *Worker, now_ns: u64) void {
    for (0..steps_per_turn_max) |_| {
        const index = worker.session.next_pending() orelse return;
        serve_entry(worker, index, now_ns);
    }
}

/// Steps the session over the socket at `index`: its unread octets go in, and what its connection
/// owes is appended to its output. A socket with no room left waits for its send's event. A
/// socket Rotor has finished with, whose connection the endpoint has ended, frees its entry.
fn serve_entry(worker: *Worker, index: usize, now_ns: u64) void {
    const socket = &worker.sockets[index];
    if (!socket.live) return;
    if (socket.finished() and !worker.session.entries[index].attached) {
        socket.live = false;
        return;
    }
    worker.touched.set(index);
    if (socket.stopped()) return;
    const room = socket.room();
    if (room.len > 0) {
        const stepped = worker.session.step(index, socket.unread(), room, now_ns);
        socket.wrote(stepped.written);
        socket.consume(stepped.consumed);
    }
    // The endpoint closed the connection: the socket closes once its octets are out.
    if (worker.session.entries[index].closing) socket.closing = true;
}

/// Submits what each socket this turn changed needs next.
fn arm(worker: *Worker) void {
    for (0..constants.connections_per_worker_max) |_| {
        const index = worker.touched.toggleFirstSet() orelse return;
        const socket = &worker.sockets[index];
        if (socket.live) socket.arm(&worker.loop, index);
    }
}

test {
    _ = @import("server_worker_test.zig");
}
