//! The socket around `client_session.zig`: the test-only client of design §9, which
//! `tools/h2_interop.sh` runs against other implementations' servers. `zig build http-client --
//! --port <port> --get <path> --post <path> <octets>` runs it.
//!
//! Each connection runs on the `client` module (design §8 step 17c). It speaks cleartext h2 with
//! prior knowledge (RFC 9113 §3.3) or h11, or with `--tls` whichever ALPN selects over TLS, which
//! the module runs through colibri's `tls.record.Client` (RFC 9113 §3.2, decision 82).
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
const client = @import("client");
const constants = @import("../constants.zig");
const client_options = @import("client_options.zig");
const client_session = @import("client_session.zig");
const client_exchange = @import("client_exchange.zig");
const client_tls = @import("../tls/client_tls.zig");
const origin_loop = @import("origin_loop.zig");
const entropy = @import("../entropy.zig");
const alpn = @import("../alpn.zig");

const Run = client_options.Run;
const Session = client_session.Session;

/// Why a connection ended without its session finishing.
const Failure = enum { none, connect_refused, peer_closed, socket_error, timed_out, refused_start };

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
    /// Over TLS its octets are records, and `input` and `output` hold them as they cross the
    /// socket, so each holds a whole record.
    session: Session,
    received: [constants.wire_read_len]u8,
    input: [constants.wire_read_len]u8,
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

/// The loop and the connections, in static storage: each connection is large, and a run holds up
/// to the limit of them.
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var loop: rotor.Loop align(@alignOf(rotor.Loop)) = undefined;
var events: [loop_options.operations]rotor.Event align(@alignOf(rotor.Event)) = undefined;
var connections: [constants.client_connections_max]Connection align(@alignOf(Connection)) = undefined;
/// The response content of every exchange of every connection. Most of it is never touched, so
/// the system gives it no memory.
var bodies: [constants.client_connections_max]client_session.Bodies align(@alignOf(client_session.Bodies)) = undefined;

/// What every connection of the run borrows, and the root the TLS mode trusts, which `main` loads
/// when `--tls` names one.
var client_config: client.Config align(@alignOf(client.Config)) = .{ .authority = "localhost" };
var tls_anchors: client_tls.Anchors align(@alignOf(client_tls.Anchors)) = undefined;

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
        .close => {
            connection.state = .closed;
            // The module wipes the TLS session's secrets, whether the connection finished or not.
            connection.session.connection.transport_closed();
        },
    }
    if (connection.state == .open) arm(connection, index);
}

/// Makes a socket and starts its connect, whose event the loop delivers.
fn open_connection(connection: *Connection, index: usize, run: *const Run) void {
    connection.input_len = 0;
    connection.output_len = 0;
    connection.output_sent = 0;
    connection.connecting = false;
    connection.receiving = false;
    connection.sending = false;
    connection.state = .closed;
    connection.failure = .refused_start;
    const plans = run.plans[0..run.plans_count];
    connection.session.init(&client_config, entropy.random(), run.now_seconds, plans, &bodies[index]) catch return;
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
    if (read == 0) return close_connection(connection, index, if (connection.session.peer_closed()) .none else .peer_closed);
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
        consume(connection, step.consumed);
        if (step.done) return close_when_sent(connection, index);
        if (step.consumed == 0 and step.written == 0) return;
    }
}

/// Closes a connection whose session is done, once the socket has taken every octet.
fn close_when_sent(connection: *Connection, index: usize) void {
    if (connection.output_sent == connection.output_len and !connection.sending) close_connection(connection, index, .none);
}

/// Drops the `consumed` octets the session took, moving what is left to the front.
fn consume(connection: *Connection, consumed: usize) void {
    assert(consumed <= connection.input_len);
    const rest = connection.input_len - consumed;
    std.mem.copyForwards(u8, connection.input[0..rest], connection.input[consumed..connection.input_len]);
    connection.input_len = rest;
}

/// Closes a connection and records why: Rotor's close cancels its receive and send first. A
/// connection already closing keeps its reason.
fn close_connection(connection: *Connection, index: usize, failure: Failure) void {
    if (connection.state == .closing or connection.state == .closed) return;
    connection.state = .closing;
    connection.failure = failure;
    submit(rotor.Operation.close(user_data(index, .close), connection.descriptor));
}

/// Prints one line per exchange of every connection, then the count of each ending.
fn report(run: *const Run, succeeded: u32) void {
    for (connections[0..run.connections_count], 0..) |*connection, index| {
        const session = &connection.session;
        for (session.exchanges_held()) |*exchange| {
            std.debug.print("connection={d} ", .{index});
            exchange.print(protocol_name(session.protocol));
        }
        if (connection.failure != .none or !session.succeeded()) {
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
    client_config = .{ .authority = run.authority, .cleartext = protocol_of(run.protocol) };
    if (run.anchor_prefix) |prefix| try load_tls(prefix, &run);
    if (run.origin) {
        if (!try origin_loop.run_origin(&run, &client_config, &tls_anchors)) std.process.exit(exit_failed);
        return;
    }
    const succeeded = try run_connections(&run);
    report(&run, succeeded);
    if (succeeded != run.connections_count) std.process.exit(exit_failed);
}

/// Loads what every TLS connection of the run shares. The name the server's certificate must carry
/// is the authority the requests name, and `--h11` offers `http/1.1` alone.
fn load_tls(prefix: []const u8, run: *const Run) !void {
    const protocols: []const []const u8 = if (run.protocol == .h11) &alpn.alpn_h11 else &alpn.alpn_both;
    client_config.tls = try client_tls.load(&tls_anchors, prefix, run.authority, protocols);
}

/// The protocol a report names, or "none" for a connection that never connected.
fn protocol_name(protocol: ?client.Protocol) []const u8 {
    const spoken = protocol orelse return "none";
    return @tagName(spoken);
}

/// The module's name for the protocol the command line chose.
fn protocol_of(chosen: alpn.Protocol) client.Protocol {
    return switch (chosen) {
        .h2 => .h2,
        .h11 => .h11,
    };
}

const testing = std.testing;

test "the command line's protocol is the module's" {
    try testing.expectEqual(client.Protocol.h2, protocol_of(.h2));
    try testing.expectEqual(client.Protocol.h11, protocol_of(.h11));
}
