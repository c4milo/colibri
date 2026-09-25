//! The socket around `client_session.zig`: the test-only client of design §9, which
//! `tools/h2_interop.sh` runs against other implementations' servers. `zig build http-client --
//! --port <port> --get <path> --post <path> <octets>` runs it.
//!
//! It speaks cleartext h2 with prior knowledge (RFC 9113 §3.3), or with `--tls` h2 over TLS
//! through chapulin's record-mode client (RFC 9113 §3.2, decision 82, `client_tls.zig`).
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
const client_options = @import("client_options.zig");
const client_session = @import("client_session.zig");
const client_tls = @import("../tls/client_tls.zig");
const session_module = @import("../session.zig");

const Run = client_options.Run;
const Session = client_session.Session;

/// Why a connection ended without its session finishing.
const Failure = enum { none, connect_refused, peer_closed, socket_error, timed_out, tls_failed };

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
    /// The TLS layer the connection runs over, or null in cleartext. Its octets are records, and
    /// `input` and `output` hold them as they cross the socket, so each holds a whole record.
    layer: ?*client_tls.Layer,
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
var loop: rotor.Loop = undefined;
var events: [loop_options.operations]rotor.Event = undefined;
var connections: [constants.client_connections_max]Connection = undefined;

/// The TLS mode's shared state, which `main` loads when `--tls` names a root, and one TLS layer per
/// connection.
var tls_shared: ?client_tls.Shared = null;
var tls_anchors: client_tls.Anchors = undefined;
var tls_layers: [constants.client_connections_max]client_tls.Layer = undefined;

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
            if (connection.layer) |layer| finish_tls(layer);
        },
    }
    if (connection.state == .open) arm(connection, index);
}

/// Makes a socket and starts its connect, whose event the loop delivers.
fn open_connection(connection: *Connection, index: usize, run: *const Run) void {
    connection.session.init(run.protocol, request_scheme(), run.authority, run.plans[0..run.plans_count]);
    connection.layer = null;
    connection.input_len = 0;
    connection.output_len = 0;
    connection.output_sent = 0;
    connection.connecting = false;
    connection.receiving = false;
    connection.sending = false;
    connection.state = .closed;
    connection.failure = .socket_error;
    if (tls_shared) |*shared| connection.layer = start_tls(index, shared) catch {
        connection.failure = .tls_failed;
        return;
    };
    connection.address = rotor.Address.ipv4(run.address, run.port);
    connection.descriptor = rotor.sync.open_socket(.ipv4) catch return;
    connection.state = .connecting;
    connection.failure = .none;
    connection.connecting = true;
    submit(rotor.Operation.connect(user_data(index, .connect), connection.descriptor, &connection.address));
}

/// RFC 9113 §8.3.1: `:scheme` names the URI scheme, which is "https" over TLS (RFC 9110 §4.2.2).
fn request_scheme() []const u8 {
    return if (tls_shared == null) "http" else "https";
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
    if (connection.layer) |layer| return step_tls(connection, index, layer);
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

/// Steps a TLS connection: records in from `input`, records out into `output`
/// (`client_tls.zig`).
fn step_tls(connection: *Connection, index: usize, layer: *client_tls.Layer) void {
    if (comptime !client_tls.available) unreachable; // `main` refuses `--tls` without chapulin.
    const stepped = client_tls.step(
        layer,
        &connection.session,
        connection.input[0..connection.input_len],
        connection.output[connection.output_len..],
    ) catch |failure| {
        client_tls.print_failure(layer, index, failure);
        return close_connection(connection, index, .tls_failed);
    };
    connection.output_len += stepped.written;
    consume(connection, stepped.consumed);
    if (stepped.done) close_when_sent(connection, index);
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

/// Gives a connection the TLS layer of its index, with its ClientHello staged.
fn start_tls(index: usize, shared: *const client_tls.Shared) !*client_tls.Layer {
    if (comptime !client_tls.available) unreachable; // `main` refuses `--tls` without chapulin.
    const layer = &tls_layers[index];
    try client_tls.start(layer, shared);
    return layer;
}

/// Wipes what a TLS connection's session still holds, once its connection is closed.
fn finish_tls(layer: *client_tls.Layer) void {
    if (comptime !client_tls.available) unreachable; // No layer exists without chapulin.
    client_tls.finish(layer);
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
        for (session.exchanges()) |*exchange| {
            std.debug.print(exchange_format, .{
                index,                     exchange.stream_id,
                exchange.plan.method,      exchange.plan.path,
                exchange.status,           exchange.interim_count,
                exchange.content_sent,     exchange.sent_crc32.final(),
                exchange.content_received, exchange.received_crc32.final(),
                exchange.outcome,          exchange.error_code,
            });
        }
        if (connection.failure != .none or session.failed()) {
            std.debug.print("connection={d} failure={t} protocol_failed={}\n", .{ index, connection.failure, session.failed() });
        }
    }
    std.debug.print("http-client: connections={d} succeeded={d} failed={d}\n", .{
        run.connections_count, succeeded, run.connections_count - succeeded,
    });
}

const exchange_format = "connection={d} stream={d} {s} {s} status={d} interim={d} sent={d} " ++
    "sent_crc32=0x{x:0>8} received={d} received_crc32=0x{x:0>8} outcome={t} error_code={d}\n";

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
    if (run.anchor_prefix) |prefix| try load_tls(prefix, &run);
    const succeeded = try run_connections(&run);
    report(&run, succeeded);
    if (succeeded != run.connections_count) std.process.exit(exit_failed);
}

/// Loads what every TLS connection of the run shares. The name the server's certificate must carry
/// is the authority the requests name, and `--h11` offers `http/1.1` alone.
fn load_tls(prefix: []const u8, run: *const Run) !void {
    if (comptime !client_tls.available) {
        std.debug.print("http-client: built without chapulin; pass -Dchapulin-client=<checkout>\n", .{});
        std.process.exit(exit_usage);
    }
    const protocols: []const []const u8 = if (run.protocol == .h11) &session_module.alpn_h11 else &session_module.alpn_both;
    tls_shared = try client_tls.load(&tls_anchors, prefix, run.authority, run.now_seconds, protocols);
}

const testing = std.testing;

/// One anchor whose name and key are each an empty DER SEQUENCE: the test's handshake never runs.
/// Test-only.
const test_der = [_]u8{ der_sequence_tag, 0 };
const der_sequence_tag: u8 = 0x30;
/// An instant chapulin accepts. A constant because no file under `src/` may read a clock.
/// Test-only.
const test_now_seconds: u64 = 1_780_000_000;

test "a TLS connection's session is wiped when its connection closes" {
    if (!client_tls.available) return error.SkipZigTest;
    const anchors = [_]client_tls.Anchor{.{
        .name = &test_der,
        .name_len = test_der.len,
        .spki = &test_der,
        .spki_len = test_der.len,
    }};
    const shared: client_tls.Shared = .{ .anchors = &anchors, .hostname = "localhost", .now_seconds = test_now_seconds };
    const connection = &connections[0];
    connection.* = undefined;
    connection.state = .closing;
    connection.layer = try start_tls(0, &shared);
    try testing.expect(client_tls.session_state(&tls_layers[0]) != client_tls.chapulin_closed);
    // Rotor's close of the connection is its last operation.
    on_event(connections[0..1], .{ .user_data = user_data(0, .close), .result = 0, .flags = .{} });
    try testing.expectEqual(.closed, connection.state);
    try testing.expectEqual(client_tls.chapulin_closed, client_tls.session_state(&tls_layers[0]));
}

test "RFC 9113 §8.3.1: a run's requests name https over TLS and http in cleartext" {
    if (!client_tls.available) return error.SkipZigTest;
    const saved = tls_shared;
    defer tls_shared = saved;
    tls_shared = null;
    try testing.expectEqualStrings("http", request_scheme());
    const anchors = [_]client_tls.Anchor{.{
        .name = &test_der,
        .name_len = test_der.len,
        .spki = &test_der,
        .spki_len = test_der.len,
    }};
    tls_shared = .{ .anchors = &anchors, .hostname = "localhost", .now_seconds = test_now_seconds };
    try testing.expectEqualStrings("https", request_scheme());
}
