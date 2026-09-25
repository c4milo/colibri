//! The socket around `h2_client_session.zig`: the test-only h2 client of design §9, which
//! `tools/h2_interop.sh` runs against other implementations' servers. `zig build h2-client --
//! --port <port> --get <path> --post <path> <octets>` runs it.
//!
//! It speaks cleartext h2 with prior knowledge (RFC 9113 §3.3). h2 over TLS joins when colibri's
//! client links chapulin's record-mode client, as its server links the record-mode server
//! (decision 82). Design §8 step 5 records what is owed.
//!
//! No call here waits but the loop's `tick` (decisions 46 and 58,
//! https://github.com/c4milo/colibri/issues/61). One thread holds every connection of a run on
//! one Rotor loop: a connect, then at most one receive and one send in flight, and a close at the
//! end. A slow peer holds up nothing but its own connection. The one wait that ends a run is
//! `client_wait_ns` with no event.
//!
//! As in the server, a receive writes into `received` and its octets are appended to `input` when
//! its event arrives, because the session moves what is left of `input` and Rotor owns a receive's
//! buffer until its final event.
//!
//! Nothing here allocates: the loop and every connection and buffer are in static storage sized by
//! `constants.zig`. Nothing here reads a clock: the timeout is the loop's.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");
const h2_client_exchange = @import("h2_client_exchange.zig");
const h2_client_session = @import("h2_client_session.zig");

const Plan = h2_client_exchange.Plan;
const Session = h2_client_session.Session;

/// Why a connection ended without its session finishing.
const Failure = enum { none, connect_refused, peer_closed, socket_error, timed_out };

/// What an operation a connection has in flight does. It rides in the operation's user data,
/// below the connection's index.
const Kind = enum(u8) { connect, receive, send, close };
const kind_bits = @bitSizeOf(Kind);

const loop_options: rotor.Loop.Options = .{
    .operations = constants.client_connections_max * @typeInfo(Kind).@"enum".fields.len,
};

/// One connection of a run: the session, the octets read but not consumed, and the octets the
/// session produced that the socket has not taken yet.
const Connection = struct {
    descriptor: rotor.Descriptor,
    /// The peer, which the connect in flight reads until its event (Rotor's rule 3).
    address: rotor.Address,
    session: Session,
    received: [constants.read_buffer_len]u8,
    input: [constants.read_buffer_len]u8,
    input_len: usize,
    output: [constants.write_buffer_len]u8,
    output_len: usize,
    output_sent: usize,
    state: enum { connecting, open, closing, closed },
    /// The operations in flight, which must all end before the loop does.
    connecting: bool,
    receiving: bool,
    sending: bool,
    failure: Failure,
};

/// What the command line asked for.
const Run = struct {
    address: [ipv4_octets]u8,
    port: u16,
    authority: []const u8,
    connections_count: u32,
    plans: [constants.exchanges_max]Plan,
    plans_count: u32,
};

/// The loop and the connections, in static storage: each connection is large, and a run holds up
/// to the limit of them.
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var loop: rotor.Loop = undefined;
var events: [loop_options.operations]rotor.Event = undefined;
var connections: [constants.client_connections_max]Connection = undefined;

/// Opens every connection of `run`, serves them until each is closed, and returns how many
/// finished with every exchange answered.
fn run_connections(run: *const Run) !u32 {
    assert(run.connections_count > 0 and run.connections_count <= constants.client_connections_max);
    assert(run.plans_count > 0);
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    const live = connections[0..run.connections_count];
    for (live, 0..) |*connection, index| open_connection(connection, index, run);
    for (0..constants.client_ticks_max) |_| {
        if (!try turn(live)) break;
    }
    // A run that ends with a connection still open ran out of time or of ticks.
    for (live, 0..) |*connection, index| {
        if (connection.state == .open or connection.state == .connecting) close_connection(connection, index, .timed_out);
    }
    loop.cancel_all();
    try loop.drain(&events);
    var succeeded: u32 = 0;
    for (live) |*connection| {
        if (connection.failure == .none and connection.session.succeeded()) succeeded += 1;
    }
    return succeeded;
}

/// Waits for events and does what each asks. False when every connection is closed, or none
/// moved for the whole wait, which means the peers left are not answering.
fn turn(live: []Connection) !bool {
    var open: usize = 0;
    for (live) |*connection| {
        if (connection.state != .closed) open += 1;
    }
    if (open == 0) return false;
    const count = try loop.tick(&events, constants.client_wait_ns);
    if (count == 0) return false;
    for (events[0..count]) |event| on_event(live, event);
    return true;
}

fn on_event(live: []Connection, event: rotor.Event) void {
    const index: usize = @intCast(event.user_data >> kind_bits);
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data)));
    const connection = &live[index];
    switch (kind) {
        .connect => on_connected(connection, index, event),
        .receive => on_received(connection, index, event),
        .send => on_sent(connection, index, event),
        .close => connection.state = .closed,
    }
    if (connection.state == .open) arm(connection, index);
}

/// Makes a socket and starts its connect, whose event the loop delivers.
fn open_connection(connection: *Connection, index: usize, run: *const Run) void {
    connection.session.init("http", run.authority, run.plans[0..run.plans_count]);
    connection.input_len = 0;
    connection.output_len = 0;
    connection.output_sent = 0;
    connection.connecting = false;
    connection.receiving = false;
    connection.sending = false;
    connection.state = .closed;
    connection.failure = .socket_error;
    connection.address = rotor.Address.ipv4(run.address, run.port);
    connection.descriptor = rotor.sync.open_socket(.ipv4) catch return;
    connection.state = .connecting;
    connection.failure = .none;
    connection.connecting = true;
    submit(rotor.Operation.connect(user_data(index, .connect), connection.descriptor, &connection.address));
}

/// The connect finished: the session writes its preface once it succeeded.
fn on_connected(connection: *Connection, index: usize, event: rotor.Event) void {
    connection.connecting = false;
    _ = event.outcome() catch return close_connection(connection, index, .connect_refused);
    connection.state = .open;
    step_session(connection, index);
}

/// Appends what a receive read to the input and steps the session. A receive of no octets is the
/// peer closing its side.
fn on_received(connection: *Connection, index: usize, event: rotor.Event) void {
    connection.receiving = false;
    if (connection.state != .open) return;
    const read = event.outcome() catch return close_connection(connection, index, .socket_error);
    if (read == 0) return close_connection(connection, index, .peer_closed);
    assert(read <= connection.input.len - connection.input_len);
    @memcpy(connection.input[connection.input_len..][0..read], connection.received[0..read]);
    connection.input_len += read;
    step_session(connection, index);
}

/// Counts what a send took, and steps the session, which may have waited for the room.
fn on_sent(connection: *Connection, index: usize, event: rotor.Event) void {
    connection.sending = false;
    if (connection.state != .open) return;
    const sent = event.outcome() catch return close_connection(connection, index, .socket_error);
    connection.output_sent += sent;
    assert(connection.output_sent <= connection.output_len);
    // Every octet is gone and no send is in flight, so the buffer starts again at its front.
    if (connection.output_sent == connection.output_len) {
        connection.output_len = 0;
        connection.output_sent = 0;
    }
    step_session(connection, index);
}

/// Submits a send of what is owed and a receive while there is room for more.
fn arm(connection: *Connection, index: usize) void {
    if (!connection.sending and connection.output_sent < connection.output_len) {
        connection.sending = true;
        const owed = connection.output[connection.output_sent..connection.output_len];
        submit(rotor.Operation.send(user_data(index, .send), connection.descriptor, owed));
    }
    const room = connection.input.len - connection.input_len;
    if (!connection.receiving and room > 0) {
        connection.receiving = true;
        const into = connection.received[0..@min(room, connection.received.len)];
        submit(rotor.Operation.receive(user_data(index, .receive), connection.descriptor, into));
    }
}

fn user_data(index: usize, kind: Kind) u64 {
    return (@as(u64, index) << kind_bits) | @intFromEnum(kind);
}

/// Submits one operation. The loop holds one of each kind for every connection, so it always has
/// room.
fn submit(operation: rotor.Operation) void {
    const taken = loop.submit(&.{operation}, &.{});
    assert(taken == 1);
}

/// Steps the session until it stops moving, appending what it writes to the output buffer. A
/// session that finished with every octet written closes its connection.
fn step_session(connection: *Connection, index: usize) void {
    for (0..constants.steps_per_read_max) |_| {
        const room = connection.output[connection.output_len..];
        if (room.len == 0) return;
        const step = connection.session.step(connection.input[0..connection.input_len], room);
        connection.output_len += step.written;
        const rest = connection.input_len - step.consumed;
        std.mem.copyForwards(u8, connection.input[0..rest], connection.input[step.consumed..connection.input_len]);
        connection.input_len = rest;
        if (step.done) {
            if (connection.output_sent == connection.output_len and !connection.sending) close_connection(connection, index, .none);
            return;
        }
        if (step.consumed == 0 and step.written == 0) return;
    }
}

/// Closes a connection and records why: Rotor's close cancels its receive and send first. A
/// connection already closing keeps its reason.
fn close_connection(connection: *Connection, index: usize, failure: Failure) void {
    if (connection.state == .closing or connection.state == .closed) return;
    connection.state = .closing;
    connection.failure = failure;
    submit(rotor.Operation.close(user_data(index, .close), connection.descriptor));
}

/// How many octets an IPv4 address has (RFC 791 §3.1).
const ipv4_octets: usize = 4;

/// The address a run connects to unless `--address` names another: the loopback, which RFC 1122
/// §3.2.1.3 reserves for the local host.
const loopback_octets = [ipv4_octets]u8{ loopback_first, 0, 0, 1 };
const loopback_first: u8 = 127;

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
    const succeeded = try run_connections(&run);
    report(&run, succeeded);
    if (succeeded != run.connections_count) std.process.exit(exit_failed);
}

/// Reads the command line, or returns null when it names nothing to do or something unreadable.
fn read_run(arguments: *std.process.Args.Iterator) ?Run {
    var run: Run = .{
        .address = loopback_octets,
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
        run.address = read_address(value) orelse return null;
    } else if (eql(u8, option, "--authority")) {
        run.authority = value;
    } else if (eql(u8, option, "--port")) {
        run.port = std.math.cast(u16, read_number(value) orelse return null) orelse return null;
    } else if (eql(u8, option, "--connections")) {
        run.connections_count = read_number(value) orelse return null;
    } else return null;
}

/// An IPv4 address from the command line, or null when it is not one.
fn read_address(text: []const u8) ?[ipv4_octets]u8 {
    const address = std.Io.net.IpAddress.parseIp4(text, 0) catch return null;
    return address.ip4.bytes;
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
