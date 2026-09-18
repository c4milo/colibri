//! The socket around `h2_session.zig`: the cleartext prior-knowledge h2 server of design §9, which
//! `tools/h2spec.sh` runs the pinned h2spec against and h2load measures. `zig build h2-server --
//! --port <port>` runs it.
//!
//! One worker per core, sharing nothing. Each worker opens its own listening socket on the same
//! port, which `reuse_address` gives it by setting SO_REUSEPORT, so the kernel hands each new
//! connection to one worker and no worker reads another's memory: no lock, no atomic and no queue
//! between cores (CLAUDE.md, Performance). A worker holds its connections in a fixed array and
//! waits on its listener and all of them in one `poll` call.
//!
//! No call here blocks. `poll` says which sockets are ready, and every read and write carries
//! MSG_DONTWAIT, so a peer that stops reading takes back only what it has room for and the octets
//! left over wait in that connection's buffer. One slow peer cannot hold up the other connections
//! its worker serves, and no worker can hold up another.
//!
//! This is the only file in the tree that opens a socket, and it holds no protocol rule: it reads
//! octets into a buffer, hands them to a session, writes back what the session produced, and closes
//! when the session says it is done (RFC 9113 §5.4.1).
//!
//! Nothing here allocates: every worker, connection and buffer is in static storage sized by
//! `constants.zig`, and each worker's `Io` is given a failing allocator, because no call here
//! starts an asynchronous task.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const constants = @import("constants.zig");
const h2_session = @import("h2_session.zig");

const Io = std.Io;
const Session = h2_session.Session;
const posix = std.posix;

/// One connection a worker serves: the session, the octets read but not consumed, and the octets
/// the session produced that the socket has not taken yet.
const Connection = struct {
    stream: Io.net.Stream,
    session: Session,
    input: [constants.read_buffer_len]u8,
    input_len: usize,
    output: [constants.write_buffer_len]u8,
    /// Octets of `output` the session has produced.
    output_len: usize,
    /// Octets of `output` the socket has taken, which are always the first ones.
    output_sent: usize,
    /// Whether this slot holds a connection.
    live: bool,
    /// Whether the session is done, so the octets left are the last the peer gets.
    closing: bool,
};

/// One worker: a core's listener, its connections, and the poll set covering both. One thread
/// touches these fields, and `padding` keeps the next worker off this one's last cache line.
const Worker = struct {
    threaded: Io.Threaded,
    listener: Io.net.Server,
    connections: [constants.connections_per_worker_max]Connection,
    /// The listener first, then one entry per live connection, rebuilt before every `poll`.
    poll_set: [constants.connections_per_worker_max + 1]posix.pollfd,
    /// Which connection each poll entry after the first belongs to.
    polled: [constants.connections_per_worker_max]usize,
    polled_len: usize,
    padding: [padding_len]u8,
};

/// What a worker holds before its padding, and the padding that rounds it to a cache line.
const worker_body_len = @sizeOf(Io.Threaded) + @sizeOf(Io.net.Server) +
    constants.connections_per_worker_max * @sizeOf(Connection) +
    (constants.connections_per_worker_max + 1) * @sizeOf(posix.pollfd) +
    constants.connections_per_worker_max * @sizeOf(usize) + @sizeOf(usize);
const padding_len = constants.cache_line_bytes - worker_body_len % constants.cache_line_bytes;

/// The workers, in static storage: each is large, and there is one per core at most.
var workers: [constants.workers_max]Worker align(constants.cache_line_bytes) = undefined;

comptime {
    assert(@sizeOf(Worker) % constants.cache_line_bytes == 0);
}

/// Runs one worker per core until the process is stopped, every one listening on `port`.
pub fn listen_and_serve(port: u16) !void {
    const cores = std.Thread.getCpuCount() catch 1;
    const count = @max(1, @min(cores, constants.workers_max));
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
    worker.threaded = .init(std.mem.Allocator.failing, .{});
    defer worker.threaded.deinit();
    const io = worker.threaded.io();
    const address = try Io.net.IpAddress.parseIp4(loopback_address, port);
    // `reuse_address` sets SO_REUSEPORT on POSIX, which is what lets every worker hold a listener
    // on one port and leaves the kernel to pick the worker a connection lands on.
    worker.listener = try address.listen(io, .{
        .reuse_address = true,
        .kernel_backlog = constants.kernel_backlog,
    });
    defer worker.listener.deinit(io);
    for (&worker.connections) |*connection| connection.live = false;
    worker.polled_len = 0;
    while (true) poll_once(worker, io);
}

/// Waits for the listener or a connection, then does what each ready socket asks for.
fn poll_once(worker: *Worker, io: Io) void {
    build_poll_set(worker);
    _ = posix.poll(worker.poll_set[0 .. worker.polled_len + 1], -1) catch return;
    for (0..worker.polled_len) |entry| {
        const events = worker.poll_set[entry + 1].revents;
        if (events == 0) continue;
        const connection = &worker.connections[worker.polled[entry]];
        serve_connection(connection, events) catch close_connection(connection, io);
    }
    if (worker.poll_set[0].revents != 0) accept_connection(worker, io);
}

/// Fills the poll set: the listener, then every live connection, each asking for what it can use.
fn build_poll_set(worker: *Worker) void {
    worker.poll_set[0] = .{
        .fd = worker.listener.socket.handle,
        .events = if (free_slot(worker) != null) posix.POLL.IN else 0,
        .revents = 0,
    };
    var entries: usize = 0;
    for (&worker.connections, 0..) |*connection, index| {
        if (!connection.live) continue;
        var events: i16 = 0;
        if (connection.output_sent < connection.output_len) events |= posix.POLL.OUT;
        if (!connection.closing and connection.input_len < connection.input.len) {
            events |= posix.POLL.IN;
        }
        worker.poll_set[entries + 1] = .{
            .fd = connection.stream.socket.handle,
            .events = events,
            .revents = 0,
        };
        worker.polled[entries] = index;
        entries += 1;
    }
    worker.polled_len = entries;
}

/// Takes one connection from the listener. One per wakeup: the listening socket waits for a peer
/// when none is there, and `poll` says so again while the kernel holds more.
fn accept_connection(worker: *Worker, io: Io) void {
    {
        const index = free_slot(worker) orelse return;
        const stream = worker.listener.accept(io) catch return;
        const connection = &worker.connections[index];
        connection.stream = stream;
        connection.session.init();
        connection.input_len = 0;
        connection.output_len = 0;
        connection.output_sent = 0;
        connection.closing = false;
        connection.live = true;
    }
}

/// The index of a slot this worker can put a connection in.
fn free_slot(worker: *Worker) ?usize {
    for (&worker.connections, 0..) |*connection, index| {
        if (!connection.live) return index;
    }
    return null;
}

/// Reads what the socket has, steps the session over it, and writes what the socket will take.
fn serve_connection(connection: *Connection, events: i16) !void {
    if (events & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) return error.PeerClosed;
    if (events & posix.POLL.IN != 0) try read_input(connection);
    step_session(connection);
    // The write does not wait, so it is worth trying whatever `poll` said: what the socket cannot
    // take now stays in the buffer and goes out when it says POLLOUT.
    try write_output(connection);
    if (connection.closing and connection.output_sent == connection.output_len) {
        return error.SessionDone;
    }
}

/// Reads once into the room the input buffer has left, without waiting.
fn read_input(connection: *Connection) !void {
    const room = connection.input[connection.input_len..];
    assert(room.len > 0);
    const read = std.c.recv(connection.stream.socket.handle, room.ptr, room.len, std.c.MSG.DONTWAIT);
    if (read < 0) return if (would_block()) {} else error.PeerClosed;
    // A read of no octets is the peer closing its side, which ends this connection.
    if (read == 0) return error.PeerClosed;
    connection.input_len += @intCast(read);
}

/// Steps the session until it stops moving, appending what it writes to the output buffer.
fn step_session(connection: *Connection) void {
    for (0..constants.steps_per_read_max) |_| {
        const room = connection.output[connection.output_len..];
        if (room.len == 0) return;
        const step = connection.session.step(connection.input[0..connection.input_len], room);
        connection.output_len += step.written;
        consume(connection, step.consumed);
        if (step.done) {
            connection.closing = true;
            return;
        }
        if (step.consumed == 0 and step.written == 0) return;
    }
}

/// Writes what the session produced, taking what the socket will hold and keeping the rest. The
/// call does not wait, so a peer that has stopped reading holds up nothing else.
fn write_output(connection: *Connection) !void {
    while (connection.output_sent < connection.output_len) {
        const rest = connection.output[connection.output_sent..connection.output_len];
        const sent = std.c.send(connection.stream.socket.handle, rest.ptr, rest.len, std.c.MSG.DONTWAIT);
        if (sent < 0) return if (would_block()) {} else error.PeerClosed;
        connection.output_sent += @intCast(sent);
    }
    // Every octet is gone, so the buffer starts again at its front.
    connection.output_len = 0;
    connection.output_sent = 0;
}

/// Whether the last call failed only because the socket had nothing to give or no room to take.
/// POSIX lets EWOULDBLOCK equal EAGAIN, and on the hosts colibri runs on it does.
fn would_block() bool {
    return std.c._errno().* == @intFromEnum(std.c.E.AGAIN);
}

/// Drops the `consumed` octets the session took, moving what is left to the front.
fn consume(connection: *Connection, consumed: usize) void {
    assert(consumed <= connection.input_len);
    if (consumed == 0) return;
    const rest = connection.input_len - consumed;
    for (0..rest) |index| connection.input[index] = connection.input[consumed + index];
    connection.input_len = rest;
}

/// Closes a connection and frees its slot.
fn close_connection(connection: *Connection, io: Io) void {
    if (!connection.live) return;
    connection.stream.close(io);
    connection.live = false;
}

/// The address the server listens on: the loopback, because it serves tests alone.
const loopback_address = "127.0.0.1";

/// The command-line option that names the port, as `tools/h2spec.sh` passes it.
const port_option = "--port";

/// Runs the server: `zig build h2-server -- --port <port>`, or `default_port` when none is given.
pub fn main(init: std.process.Init.Minimal) !void {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.skip();
    try listen_and_serve(read_port(&arguments));
}

/// The port `--port` names, or `default_port`.
fn read_port(arguments: *std.process.Args.Iterator) u16 {
    var wanted = false;
    for (0..constants.arguments_max) |_| {
        const argument = arguments.next() orelse break;
        if (wanted) {
            return std.fmt.parseInt(u16, argument, constants.port_radix) catch constants.default_port;
        }
        wanted = std.mem.eql(u8, argument, port_option);
    }
    return constants.default_port;
}
