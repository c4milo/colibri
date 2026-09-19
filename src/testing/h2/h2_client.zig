//! The socket around `h2_client_session.zig`: the test-only h2 client of design §9, which
//! `tools/h2_interop.sh` runs against other implementations' servers. `zig build h2-client --
//! --port <port> --get <path> --post <path> <octets>` runs it.
//!
//! It speaks cleartext h2 with prior knowledge (RFC 9113 §3.3). h2 over TLS joins when a provider
//! that takes octets in and returns octets fills `tls.Provider`; the one colibri's checks link
//! (decision 10) reads its socket through a callback that must block, so it cannot sit under this
//! loop yet. Design §8 step 5 records what is owed.
//!
//! No call here blocks but `poll`. Every socket is O_NONBLOCK from before it connects: `connect`
//! answers EINPROGRESS and `poll` says when it finished, a read takes what the socket holds and a
//! write takes what it has room for. One thread holds every connection of a run in one `poll` set,
//! so a slow peer holds up nothing but its own connection, and the thread sleeps only when no
//! socket is ready. The one wait that ends a run is `client_poll_timeout_ms` with no socket ready.
//!
//! Nothing here allocates: every connection and buffer is in static storage sized by
//! `constants.zig`. Nothing here reads a clock: the timeout is the kernel's.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const h2_client_exchange = @import("h2_client_exchange.zig");
const h2_client_session = @import("h2_client_session.zig");

const Plan = h2_client_exchange.Plan;
const Session = h2_client_session.Session;
const posix = std.posix;

/// Why a connection ended without its session finishing.
const Failure = enum { none, connect_refused, peer_closed, socket_error, timed_out };

/// One connection of a run: the session, the octets read but not consumed, and the octets the
/// session produced that the socket has not taken yet.
const Connection = struct {
    socket: posix.socket_t,
    session: Session,
    input: [constants.read_buffer_len]u8,
    input_len: usize,
    output: [constants.write_buffer_len]u8,
    output_len: usize,
    output_sent: usize,
    state: enum { connecting, open, closed },
    failure: Failure,
};

/// What the command line asked for.
const Run = struct {
    address: []const u8,
    port: u16,
    authority: []const u8,
    connections_count: u32,
    plans: [constants.exchanges_max]Plan,
    plans_count: u32,
};

/// The connections, in static storage: each is large, and a run holds up to the limit of them.
var connections: [constants.client_connections_max]Connection = undefined;
var poll_set: [constants.client_connections_max]posix.pollfd = undefined;
/// Which connection each poll entry belongs to.
var polled: [constants.client_connections_max]usize = undefined;

/// Opens every connection of `run`, serves them until each is closed, and returns how many
/// finished with every exchange answered.
fn run_connections(run: *const Run) u32 {
    assert(run.connections_count > 0 and run.connections_count <= constants.client_connections_max);
    assert(run.plans_count > 0);
    const live = connections[0..run.connections_count];
    for (live) |*connection| open_connection(connection, run);
    for (0..constants.client_polls_max) |_| {
        if (!poll_once(live)) break;
    }
    var succeeded: u32 = 0;
    for (live) |*connection| {
        // A run that ends with a connection still open ran out of `poll` calls.
        close_connection(connection, .timed_out);
        if (connection.failure == .none and connection.session.succeeded()) succeeded += 1;
    }
    return succeeded;
}

/// Waits for any socket, then does what each ready one asks for. False when no connection is left
/// open, or none moved for the whole timeout, which means the peers left are not answering.
fn poll_once(live: []Connection) bool {
    const entries = build_poll_set(live);
    if (entries == 0) return false;
    const ready = posix.poll(poll_set[0..entries], constants.client_poll_timeout_ms) catch 0;
    if (ready == 0) return false;
    for (poll_set[0..entries], polled[0..entries]) |entry, index| {
        if (entry.revents != 0) serve_connection(&live[index], entry.revents);
    }
    return true;
}

/// Fills the poll set with every connection still open, each asking for what it can use.
fn build_poll_set(live: []Connection) usize {
    var entries: usize = 0;
    for (live, 0..) |*connection, index| {
        if (connection.state == .closed) continue;
        var events: i16 = 0;
        const has_output = connection.output_sent < connection.output_len;
        // A socket that is still connecting says so by becoming writable.
        if (connection.state == .connecting or has_output) events |= posix.POLL.OUT;
        if (connection.state == .open and connection.input_len < connection.input.len) {
            events |= posix.POLL.IN;
        }
        poll_set[entries] = .{ .fd = connection.socket, .events = events, .revents = 0 };
        polled[entries] = index;
        entries += 1;
    }
    return entries;
}

/// Makes a non-blocking socket and starts its connect, which `poll` reports the end of.
fn open_connection(connection: *Connection, run: *const Run) void {
    connection.session.init("http", run.authority, run.plans[0..run.plans_count]);
    connection.input_len = 0;
    connection.output_len = 0;
    connection.output_sent = 0;
    connection.state = .closed;
    connection.failure = .socket_error;
    const address = std.Io.net.IpAddress.parseIp4(run.address, run.port) catch return;
    const socket = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
    if (socket < 0) return;
    connection.socket = socket;
    connection.state = .connecting;
    const nonblocking: c_int = @bitCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
    if (std.c.fcntl(socket, std.c.F.SETFL, nonblocking) < 0) return close_connection(connection, .socket_error);
    const peer: std.c.sockaddr.in = .{
        // The wire is network byte order whatever the host's is.
        .port = std.mem.nativeToBig(u16, address.ip4.port),
        .addr = @bitCast(address.ip4.bytes),
    };
    const started = std.c.connect(socket, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
    if (started < 0 and !in_progress()) return close_connection(connection, .connect_refused);
    connection.failure = .none;
}

/// Does what a ready socket asks for: finishes the connect, reads, steps the session, writes.
fn serve_connection(connection: *Connection, events: i16) void {
    assert(connection.state != .closed);
    if (connection.state == .connecting) {
        if (!connect_finished(connection)) return close_connection(connection, .connect_refused);
        connection.state = .open;
    } else if (events & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
        return close_connection(connection, .socket_error);
    }
    const readable = events & (posix.POLL.IN | posix.POLL.HUP) != 0;
    const peer_open = !readable or read_input(connection);
    const done = step_session(connection);
    // The write does not wait, so it is worth trying whatever `poll` said: what the socket cannot
    // take now stays in the buffer and goes out when it says POLLOUT.
    if (!write_output(connection)) return close_connection(connection, .socket_error);
    const flushed = connection.output_sent == connection.output_len;
    if (done and flushed) return close_connection(connection, .none);
    if (!peer_open) close_connection(connection, .peer_closed);
}

/// Whether the connect `poll` reported the end of succeeded, which SO_ERROR says.
fn connect_finished(connection: *Connection) bool {
    var failure: c_int = 0;
    var failure_len: std.c.socklen_t = @sizeOf(c_int);
    const got = std.c.getsockopt(connection.socket, std.c.SOL.SOCKET, std.c.SO.ERROR, &failure, &failure_len);
    return got == 0 and failure == 0;
}

/// Reads once into the room the input buffer has left, without waiting. False when the peer has
/// closed its side or the socket failed.
fn read_input(connection: *Connection) bool {
    const room = connection.input[connection.input_len..];
    if (room.len == 0) return true;
    const read = std.c.recv(connection.socket, room.ptr, room.len, std.c.MSG.DONTWAIT);
    if (read < 0) return would_block();
    // A read of no octets is the peer closing its side.
    if (read == 0) return false;
    connection.input_len += @intCast(read);
    return true;
}

/// Steps the session until it stops moving, appending what it writes to the output buffer.
/// True when the session is finished.
fn step_session(connection: *Connection) bool {
    for (0..constants.steps_per_read_max) |_| {
        const room = connection.output[connection.output_len..];
        if (room.len == 0) return false;
        const step = connection.session.step(connection.input[0..connection.input_len], room);
        connection.output_len += step.written;
        const rest = connection.input_len - step.consumed;
        std.mem.copyForwards(u8, connection.input[0..rest], connection.input[step.consumed..connection.input_len]);
        connection.input_len = rest;
        if (step.done) return true;
        if (step.consumed == 0 and step.written == 0) return false;
    }
    return false;
}

/// Writes what the session produced, taking what the socket will hold and keeping the rest. False
/// when the socket failed.
fn write_output(connection: *Connection) bool {
    for (0..constants.steps_per_read_max) |_| {
        if (connection.output_sent == connection.output_len) break;
        const rest = connection.output[connection.output_sent..connection.output_len];
        const sent = std.c.send(connection.socket, rest.ptr, rest.len, std.c.MSG.DONTWAIT);
        if (sent < 0) return would_block();
        connection.output_sent += @intCast(sent);
    }
    if (connection.output_sent < connection.output_len) return true;
    // Every octet is gone, so the buffer starts again at its front.
    connection.output_len = 0;
    connection.output_sent = 0;
    return true;
}

/// Closes a connection and records why. A connection already closed keeps its reason.
fn close_connection(connection: *Connection, failure: Failure) void {
    if (connection.state == .closed) return;
    _ = std.c.close(connection.socket);
    connection.state = .closed;
    connection.failure = failure;
}

/// Whether the last call failed only because the socket had nothing to give or no room to take.
/// POSIX lets EWOULDBLOCK equal EAGAIN, and on the hosts colibri runs on it does.
fn would_block() bool {
    return std.c._errno().* == @intFromEnum(std.c.E.AGAIN);
}

/// Whether the last `connect` is still under way, which is how a non-blocking one starts.
fn in_progress() bool {
    return std.c._errno().* == @intFromEnum(std.c.E.INPROGRESS);
}

/// Prints one line per exchange of every connection, then the count of each ending.
fn report(run: *const Run, succeeded: u32) void {
    for (connections[0..run.connections_count], 0..) |*connection, index| {
        const session = &connection.session;
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            std.debug.print(exchange_format, .{
                index,                     exchange.stream_id,
                exchange.plan.method,      exchange.plan.path,
                exchange.status,           exchange.interim_count,
                exchange.content_sent,     exchange.sent_crc32.final(),
                exchange.content_received, exchange.received_crc32.final(),
                exchange.outcome,          exchange.error_code,
            });
        }
        if (connection.failure != .none or session.failed) {
            std.debug.print("connection={d} failure={t} h2_failed={}\n", .{ index, connection.failure, session.failed });
        }
    }
    std.debug.print("h2-client: connections={d} succeeded={d} failed={d}\n", .{
        run.connections_count, succeeded, run.connections_count - succeeded,
    });
}

const exchange_format = "connection={d} stream={d} {s} {s} status={d} interim={d} sent={d} " ++
    "sent_crc32=0x{x:0>8} received={d} received_crc32=0x{x:0>8} outcome={t} error_code={d}\n";

const usage =
    \\usage: h2-client [--address <ipv4>] [--port <port>] [--authority <name>]
    \\                 [--connections <count>] (--get <path> | --post <path> <octets>)...
    \\
;

/// The exit status of a run in which a connection did not finish, and of a command line the
/// client could not read.
const exit_failed: u8 = 1;
const exit_usage: u8 = 2;

/// Runs the client and exits 0 when every connection finished with every exchange answered.
pub fn main(init: std.process.Init.Minimal) !void {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.skip();
    const run = read_run(&arguments) orelse {
        std.debug.print(usage, .{});
        std.process.exit(exit_usage);
    };
    const succeeded = run_connections(&run);
    report(&run, succeeded);
    if (succeeded != run.connections_count) std.process.exit(exit_failed);
}

/// Reads the command line, or returns null when it names nothing to do or something unreadable.
fn read_run(arguments: *std.process.Args.Iterator) ?Run {
    var run: Run = .{
        .address = "127.0.0.1",
        .port = constants.default_port,
        .authority = "localhost",
        .connections_count = 1,
        .plans = undefined,
        .plans_count = 0,
    };
    for (0..constants.client_arguments_max) |_| {
        const option = arguments.next() orelse break;
        const value = arguments.next() orelse return null;
        read_option(&run, option, value, arguments) orelse return null;
    }
    const connections_ok = run.connections_count > 0 and run.connections_count <= constants.client_connections_max;
    return if (run.plans_count > 0 and connections_ok) run else null;
}

/// Applies one option and its value, or returns null when the client does not know the option.
fn read_option(run: *Run, option: []const u8, value: []const u8, arguments: *std.process.Args.Iterator) ?void {
    const eql = std.mem.eql;
    if (eql(u8, option, "--get")) return add_plan(run, .{ .method = "GET", .path = value, .content_len = 0 });
    if (eql(u8, option, "--post")) {
        const octets = arguments.next() orelse return null;
        const content_len = read_number(octets) orelse return null;
        if (content_len > constants.request_content_len_max) return null;
        return add_plan(run, .{ .method = "POST", .path = value, .content_len = content_len });
    }
    if (eql(u8, option, "--address")) {
        run.address = value;
    } else if (eql(u8, option, "--authority")) {
        run.authority = value;
    } else if (eql(u8, option, "--port")) {
        run.port = std.math.cast(u16, read_number(value) orelse return null) orelse return null;
    } else if (eql(u8, option, "--connections")) {
        run.connections_count = read_number(value) orelse return null;
    } else return null;
}

/// A decimal number from the command line, or null when it is not one.
fn read_number(text: []const u8) ?u32 {
    return std.fmt.parseInt(u32, text, constants.port_radix) catch null;
}

/// Appends one exchange to the plan, or returns null when the plan is full or the path is empty.
fn add_plan(run: *Run, plan: Plan) ?void {
    if (run.plans_count == constants.exchanges_max or plan.path.len == 0) return null;
    run.plans[run.plans_count] = plan;
    run.plans_count += 1;
}
