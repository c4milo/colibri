//! The tests of a `.hosted` `colibri.Client` against a `.hosted` `colibri.Server` on one fake host
//! (decision 159, design §8 step 44h). The test is the host of both objects. It copies the octets
//! of each send to the receive of the other object, and each datagram to the other object's
//! receive of datagrams. It moves its clock only when neither object has work. So a GET and a POST
//! run over h11, h2 and h3 through `request` and the handler, with no socket and no thread.
//!
//! The tests of one hosted object against octets that the test writes are in `fake_host_test.zig`.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const client = @import("client");
const testdata = @import("testdata");
const constants = @import("constants.zig");
const host = @import("host.zig");
const server_module = @import("server.zig");
const client_module = @import("client.zig");
const client_loop = @import("client_loop.zig");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

const testing = std.testing;

/// The rounds a test runs at most, and the room each turn writes into.
const rounds_max = 512;
const operations_len = 32;
/// The octets on their way to one object at most: what one send carries, and what one receive
/// leaves behind.
const pipe_len = constants.limits.socket_output_len + constants.limits.socket_input_len;

/// RFC 9110 §15.3.1: 200 (OK), and §15.6.1: 500 (Internal Server Error).
const ok: client.Status = .ok;
const internal_server_error: server.Status = .internal_server_error;
/// The body that a POST sends, which the route `/echo` answers with.
const note = "a note for the server";

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .post, "/echo", fixture.Echo, .{ .whole_body = true } },
    },
};
const Router = server.Router(void, routes, .{ .requests = fixture.requests_max, .response_bytes = fixture.response_bytes, .body_bytes = fixture.request_body_bytes });

fn greet(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", "text/plain");
    try response.body().writeAll(fixture.greeting);
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}

/// A hosted server and a hosted client, each with one TCP socket and QUIC, which the tests place
/// outside any stack frame. Test-only.
const PairServer = server_module.Server(.{ .tcp_connections = 1, .quic_connections = 1 }, .hosted);
const PairClient = client_module.Client(.{ .tcp_connections = 1, .requests = fixture.requests_max }, .hosted);
var pair_server: PairServer align(@alignOf(PairServer)) = undefined;
var pair_client: PairClient align(@alignOf(PairClient)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};
var pair: Pair align(@alignOf(Pair)) = .{};
var handler: Handler align(@alignOf(Handler)) = .{};
/// The source of the server, and the source of the client.
var counters: [sides]support.Counter align(@alignOf(support.Counter)) = @splat(.{});

const Side = enum(u1) { client, server };
const sides = @typeInfo(Side).@"enum".fields.len;

/// The address that each side reads the datagrams of the other from. The server reads the
/// client's from 127.0.0.1 and a port that the test chose, and the client reads the server's from
/// its destination.
const client_port: u16 = 50_000;

fn address_of(side: Side) server.Address {
    var address = fixture.loopback_ipv4[0];
    address.port = if (side == .client) client_port else fixture.https_port;
    return address;
}

fn peer_of(side: Side) Side {
    return if (side == .client) .server else .client;
}

/// The octets on their way to one object over the TCP connection.
const Pipe = struct {
    bytes: [pipe_len]u8 = undefined,
    len: usize = 0,
    /// The receive that the reader has in flight.
    receive: ?host.Operation = null,
    /// The writer closed its socket, so the reader reads 0 octets after the last one.
    ended: bool = false,
};

/// The fake host of the two objects: one TCP connection and one UDP path between them.
const Pair = struct {
    now_ns: u64 = 0,
    /// The octets on their way to each side, by the side that reads them.
    pipes: [sides]Pipe = @splat(.{}),
    /// The server's accept in flight, and each side's receive of datagrams in flight.
    accept: ?host.OperationId = null,
    datagram_receives: [sides]?host.OperationId = @splat(null),
    /// The host's own memory for one datagram, which it lends for one `complete`.
    datagram: [constants.limits.udp_datagram_len_max]u8 = undefined,
    /// A completion came in this round.
    completed: bool = false,

    /// Gives `side` one completion at the host's instant.
    fn complete(host_pair: *Pair, side: Side, completion: host.Completion) void {
        host_pair.completed = true;
        switch (side) {
            .client => pair_client.complete(&completion, host_pair.now_ns),
            .server => pair_server.complete(&completion, host_pair.now_ns),
        }
    }

    /// Does one operation that a turn of `side` wrote.
    fn perform(host_pair: *Pair, side: Side, operation: host.Operation) void {
        const index = @intFromEnum(side);
        switch (operation.kind) {
            .accept => host_pair.accept = operation.id,
            .connect => host_pair.connect(operation.id),
            .receive => host_pair.pipes[index].receive = operation,
            .send => |written| host_pair.send(side, operation.id, written.bytes),
            .shutdown_send => host_pair.shutdown_send(side, operation.id),
            .close => host_pair.close(side, operation.id),
            .cancel => |named| host_pair.cancel(side, named.target),
            .receive_datagram => host_pair.datagram_receives[index] = operation.id,
            .send_datagram => |written| {
                // The host of each object sends no segments (`Features`).
                assert(written.segment_bytes == 0);
                host_pair.carry(side, operation.id, written.bytes, written.ecn);
            },
        }
    }

    /// Joins the client's connect and the server's accept. With no accept in flight the listener
    /// takes no connection.
    fn connect(host_pair: *Pair, id: host.OperationId) void {
        const accept = host_pair.accept orelse return host_pair.complete(.client, .{ .id = id, .result = .{ .failed = .refused } });
        host_pair.accept = null;
        host_pair.pipes = @splat(.{});
        host_pair.complete(.server, .{ .id = accept, .result = .accepted });
        host_pair.complete(.client, .{ .id = id, .result = .connected });
    }

    /// Copies the octets of a send into the pipe to its peer, as many as fit.
    fn send(host_pair: *Pair, side: Side, id: host.OperationId, bytes: []const u8) void {
        const pipe = &host_pair.pipes[@intFromEnum(peer_of(side))];
        const count = @min(bytes.len, pipe.bytes.len - pipe.len);
        assert(count > 0);
        @memcpy(pipe.bytes[pipe.len..][0..count], bytes[0..count]);
        pipe.len += count;
        host_pair.complete(side, .{ .id = id, .result = .{ .sent = @intCast(count) } });
    }

    /// Closes the write side of the socket of `side`: its peer reads the end of the octets, and its
    /// own receive goes on (RFC 9112 §9.6).
    fn shutdown_send(host_pair: *Pair, side: Side, id: host.OperationId) void {
        host_pair.pipes[@intFromEnum(peer_of(side))].ended = true;
        host_pair.complete(side, .{ .id = id, .result = .shut_down });
    }

    /// Closes the socket of `side`. The close ends the socket's receive first (decision 159, rule
    /// 1), and its peer then reads the end of the octets.
    fn close(host_pair: *Pair, side: Side, id: host.OperationId) void {
        const own = &host_pair.pipes[@intFromEnum(side)];
        if (own.receive) |receive| {
            own.receive = null;
            host_pair.complete(side, .{ .id = receive.id, .result = .canceled });
        }
        host_pair.pipes[@intFromEnum(peer_of(side))].ended = true;
        host_pair.complete(side, .{ .id = id, .result = .closed });
    }

    /// Ends the accept or the receive of datagrams that `target` names. A target that already
    /// ended names nothing, and the host does nothing.
    fn cancel(host_pair: *Pair, side: Side, target: host.OperationId) void {
        if (side == .server) {
            if (host_pair.accept) |accept| {
                if (accept == target) {
                    host_pair.accept = null;
                    return host_pair.complete(side, .{ .id = target, .result = .canceled });
                }
            }
        }
        const receive = host_pair.datagram_receives[@intFromEnum(side)] orelse return;
        if (receive != target) return;
        host_pair.datagram_receives[@intFromEnum(side)] = null;
        host_pair.complete(side, .{ .id = target, .result = .canceled });
    }

    /// Carries one datagram to the peer of `side`, which reads it during `complete` alone. A peer
    /// with no receive in flight loses it.
    fn carry(host_pair: *Pair, side: Side, id: host.OperationId, bytes: []const u8, ecn: server.Ecn) void {
        const peer = peer_of(side);
        if (host_pair.datagram_receives[@intFromEnum(peer)]) |receive| {
            const lent = host_pair.datagram[0..bytes.len];
            @memcpy(lent, bytes);
            host_pair.complete(peer, .{ .id = receive, .more = true, .result = .{ .datagram = .{ .bytes = lent, .from = address_of(side), .ecn = ecn } } });
        }
        host_pair.complete(side, .{ .id = id, .result = .{ .datagram_sent = @intCast(bytes.len) } });
    }

    /// Gives the receive of `side` the octets on their way to it, or their end.
    fn deliver(host_pair: *Pair, side: Side) void {
        const pipe = &host_pair.pipes[@intFromEnum(side)];
        const receive = pipe.receive orelse return;
        if (pipe.len == 0 and !pipe.ended) return;
        const buffer = receive.kind.receive.buffer;
        const count = @min(pipe.len, buffer.len);
        @memcpy(buffer[0..count], pipe.bytes[0..count]);
        std.mem.copyForwards(u8, &pipe.bytes, pipe.bytes[count..pipe.len]);
        pipe.len -= count;
        pipe.receive = null;
        // A read of 0 octets means that the peer closed its side.
        host_pair.complete(side, .{ .id = receive.id, .result = .{ .received = @intCast(count) } });
    }

    /// One round: a turn of each object that has not stopped, each operation that the turn wrote,
    /// and the octets on their way. When no completion came and neither object has work, the
    /// clock moves to the earliest instant that a turn named (decision 159, rule 5).
    fn round(host_pair: *Pair) !void {
        var operations: [operations_len]host.Operation = undefined;
        host_pair.completed = false;
        var waits: [sides]host.Wait = @splat(.none);
        if (!pair_server.stopped()) {
            const turned = pair_server.turn(host_pair.now_ns, &operations);
            for (operations[0..turned.operations]) |operation| host_pair.perform(.server, operation);
            waits[@intFromEnum(Side.server)] = turned.wait;
        }
        if (!pair_client.stopped()) {
            const turned = pair_client.turn(host_pair.now_ns, &operations);
            for (operations[0..turned.operations]) |operation| host_pair.perform(.client, operation);
            waits[@intFromEnum(Side.client)] = turned.wait;
        }
        host_pair.deliver(.server);
        host_pair.deliver(.client);
        if (host_pair.completed) return;
        const at_ns = earliest(&waits) orelse return;
        host_pair.now_ns = @max(host_pair.now_ns, at_ns);
    }

    /// Runs rounds until `ended()` holds.
    fn run_until(host_pair: *Pair, comptime ended: fn () bool) !void {
        for (0..rounds_max) |_| {
            if (ended()) return;
            try host_pair.round();
        }
        return error.RoundsExhausted;
    }
};

/// The earliest instant that `waits` names, or null when one asks for a turn at once or none
/// names an instant.
fn earliest(waits: []const host.Wait) ?u64 {
    var at_ns: ?u64 = null;
    for (waits) |wait| {
        switch (wait) {
            .now => return null,
            .none => {},
            .at_ns => |named| at_ns = @min(at_ns orelse named, named),
        }
    }
    return at_ns;
}

/// The program's handler: it counts each exchange that ended, keeps the protocol of the
/// connection, and cancels `dropped` from `on_finished` when the test names one.
const Handler = struct {
    exchanges: [fixture.requests_max]fixture.Exchange = @splat(.{}),
    requested: u32 = 0,
    finished: u32 = 0,
    connected: ?client.Protocol = null,
    dropped: ?client.RequestId = null,

    /// Hands the client one request, with `body` as its whole body.
    fn request(program: *Handler, method: []const u8, path: []const u8, body: []const u8) !client.RequestId {
        const exchange = &program.exchanges[program.requested];
        exchange.request = .{ .method = method, .path = path, .body = body };
        exchange.response = .{ .body = &exchange.body };
        const id = try pair_client.request(&exchange.request, &exchange.response);
        program.requested += 1;
        return id;
    }

    pub fn on_finished(program: *Handler, running: *PairClient, _: client.Finished) void {
        assert(running == &pair_client);
        program.finished += 1;
        const dropped = program.dropped orelse return;
        program.dropped = null;
        running.cancel(dropped, pair.now_ns);
    }

    pub fn on_connected(program: *Handler, _: *PairClient, connected: client.Connected) void {
        program.connected = connected.protocol;
    }
};

/// The instant of each `init`: the test identity's Unix seconds, and the host's instant, which a
/// first turn does not repeat.
const started: server.Timestamp = .{ .unix_seconds = fixture.now_seconds, .monotonic_ns = started_ns };
const started_ns: u64 = 7_000_000_000;
const second_ns: u64 = 1_000_000_000;

/// Starts the server over TLS with the test identity, and the client of `protocols`, at
/// `started`. The host opened the listener, the server's UDP socket and the client's UDP socket
/// of IPv4.
fn start(protocols: client.Protocols) !void {
    counters = @splat(.{});
    router = .{};
    pair = .{ .now_ns = started.monotonic_ns };
    handler = .{};
    try pair_server.init(&.{
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .random = counters[@intFromEnum(Side.server)].random(),
        .now = started,
        .sockets = .{ .datagram = .{} },
    }, &router, &context);
    try pair_client.init(&.{
        .destination = fixture.loopback(fixture.https_port),
        .pool = fixture.pool_config(protocols, true),
        .random = counters[@intFromEnum(Side.client)].random(),
        .now = started,
        .datagram = .{ .ipv4 = .{} },
    }, &handler);
}

/// Stops the client and then the server, as a host does: each `shutdown`, then rounds until
/// `stopped()` holds, then `deinit`.
fn stop() !void {
    pair_client.shutdown();
    try pair.run_until(client_stopped);
    pair_client.deinit();
    pair_server.shutdown();
    try pair.run_until(server_stopped);
    pair_server.deinit();
}

fn client_stopped() bool {
    return pair_client.stopped();
}

fn server_stopped() bool {
    return pair_server.stopped();
}

fn each_exchange_ended() bool {
    return handler.finished == handler.requested;
}

fn one_exchange_ended() bool {
    return handler.finished == 1;
}

fn connection_taken() bool {
    return handler.connected != null;
}

/// Runs a GET and a POST through `request` and the handler over a client of `protocols`, and
/// checks that `expected` carried them and that each response arrived whole.
fn get_and_post(protocols: client.Protocols, expected: client.Protocol) !void {
    try start(protocols);
    _ = try handler.request("GET", "/greeting", "");
    _ = try handler.request("POST", "/echo", note);
    try pair.run_until(each_exchange_ended);
    try testing.expectEqual(expected, handler.connected.?);
    const got = &handler.exchanges[0].response;
    try testing.expectEqual(ok, got.status);
    try testing.expectEqualStrings(fixture.greeting, got.body_received());
    const posted = &handler.exchanges[1].response;
    try testing.expectEqualStrings(note, posted.body_received());
    try testing.expectEqual(note.len, posted.body_sent);
    try stop();
}

test "decision 159 as amended: a hosted server and client start at the Timestamp of init" {
    try start(.{ .h3 = false });
    // Before any turn, each counts the Unix seconds from `started` (non-negotiable 3).
    const later_ns = started.monotonic_ns + 3 * second_ns;
    try testing.expectEqual(started.monotonic_ns, pair_server.now_ns);
    try testing.expectEqual(started.unix_seconds + 3, pair_server.engine.state.connections.seconds_at(later_ns));
    try testing.expectEqual(started.unix_seconds + 3, client_loop.unix_seconds(&pair_client, later_ns));
    try stop();
}

test "decision 159: a hosted client and server run a GET and a POST over h11" {
    try get_and_post(.{ .h2 = false, .h3 = false }, .h11);
}

test "decision 159: a hosted client and server run a GET and a POST over h2" {
    try get_and_post(.{ .h3 = false }, .h2);
}

test "decision 159: a hosted client and server run a GET and a POST over h3" {
    try get_and_post(.{ .prefer = .quic }, .h3);
}

test "decision 156 ruling 12: an exchange cancelled before its request left gives no finished" {
    try start(.{ .h3 = false });
    _ = try handler.request("GET", "/greeting", "");
    const dropped = try handler.request("GET", "/greeting", "");
    pair_client.cancel(dropped, pair.now_ns);
    try pair.run_until(one_exchange_ended);
    try stop();
    // The handler got the first exchange alone, and the second one's response was never written.
    try testing.expectEqual(1, handler.finished);
    try testing.expectEqualStrings(fixture.greeting, handler.exchanges[0].response.body_received());
    try testing.expectEqual(client.Result.pending, handler.exchanges[1].response.result);
}

test "decision 156 ruling 12: an exchange cancelled on an open connection gives no finished" {
    try start(.{ .h3 = false });
    _ = try handler.request("GET", "/greeting", "");
    const dropped = try handler.request("GET", "/greeting", "");
    // The connection took both exchanges, so the cancel ends a stream (RFC 9113 §8.1).
    try pair.run_until(connection_taken);
    pair_client.cancel(dropped, pair.now_ns);
    try pair.run_until(one_exchange_ended);
    try stop();
    try testing.expectEqual(1, handler.finished);
    try testing.expectEqual(client.Result.pending, handler.exchanges[1].response.result);
}

test "decision 156 ruling 12: a handler cancels an exchange from on_finished" {
    try start(.{ .h3 = false });
    _ = try handler.request("GET", "/greeting", "");
    handler.dropped = try handler.request("GET", "/greeting", "");
    try pair.run_until(one_exchange_ended);
    try stop();
    // The cancel came inside a turn, and the handler got no `finished` for the second exchange.
    try testing.expectEqual(null, handler.dropped);
    try testing.expectEqual(1, handler.finished);
}
