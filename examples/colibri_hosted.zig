//! Example: a program hosts a `colibri.Server` and a `colibri.Client` on its own loop. Each
//! object is `.hosted` (decision 159): it does no I/O and reads no clock. Each turn, an object
//! writes the operations that it needs into the program's storage, and the program gives back one
//! completion for each.
//!
//! The program here is the host of both objects at once. It joins them over `link.zig`, in
//! memory: a connect of the client meets the accept of the server, and the octets of each send go
//! to the receive of the other object. A real program does the same operations on its own sockets
//! and its own loop, such as libxev, `std.Io` or Rotor. docs/usage.md shows how.
//!
//! The run goes in this order:
//! 1. The program starts the server with the test identity and the router, and the client with
//!    the server's destination and a pool over TLS. A hosted object takes the program's
//!    source of randomness. Here it is one seed, so each run sends the same octets.
//! 2. The program hands the client two GETs, and turns both objects until each exchange ended.
//!    ALPN selects h2.
//! 3. The program changes the server's ticket key between two calls. The tickets that the server
//!    already sent still resume, because the server keeps the key before it.
//! 4. The program calls `shutdown` on the client and turns it until `stopped()`, then does the
//!    same for the server, and calls each `deinit`.
//!
//! The rules of the host (decision 159): it calls `turn` and `complete` on one thread, never from
//! inside the handler, and calls `turn` again at the instant that its `Wait` names.
//!
//! Run it with `zig build example-colibri_hosted`, or every example with `zig build examples`.
const std = @import("std");
const assert = std.debug.assert;
const colibri = @import("colibri");
const server = colibri.server;
const client = colibri.client;
const tls = @import("tls");
const platform = @import("platform");
const identity = @import("testdata");
const link_module = @import("link.zig");
// chapulin's hook, which every program that links `tls` defines.
const program = @import("tls_program.zig");

comptime {
    _ = program;
}

const Side = link_module.Side;
const sides = std.enums.values(Side).len;

/// A server of one TCP connection and no QUIC, and a client of one TCP connection and two
/// requests. The host opened no UDP socket, so neither speaks h3.
const Server = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);
const Client = colibri.Client(.{ .quic = false, .tcp_connections = 1, .requests = 2 }, .hosted);
var hosted_server: Server align(@alignOf(Server)) = undefined;
var hosted_client: Client align(@alignOf(Client)) = undefined;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
    },
};
const Router = server.Router(void, routes, .{ .requests = 2 });
var router: Router align(@alignOf(Router)) = .{};
var router_context: void = {};

/// The link between the two objects, and the host's state.
var link: link_module.Link align(@alignOf(link_module.Link)) = undefined;
var hosted: Host align(@alignOf(Host)) = .{};
var exchanges: Exchanges align(@alignOf(Exchanges)) = .{};

/// The one seed of the run. A real program passes its operating system's entropy.
const seed = 0x636f_6c69_6272_69;
var generator: std.Random.DefaultPrng align(@alignOf(std.Random.DefaultPrng)) = .init(seed);

fn fill(state: *std.Random.DefaultPrng, buffer: []u8) void {
    state.fill(buffer);
}

/// The origin the client names, the root it trusts for it, and the server's address, which no
/// socket uses.
const origin = "localhost";
const anchors = [_]tls.Anchor{.{ .subject = identity.root_name, .spki = identity.root_spki }};
const loopback = [_]u8{ 127, 0, 0, 1 };
const server_addresses = [_]client.Address{.of(&loopback, 0)};
/// The port of an "https" origin (RFC 9110 §4.2.2).
const https_port: u16 = 443;

const greeting = "hello from a hosted colibri\n";
/// RFC 9110 §15.3.1: 200 (OK), and §15.6.1: 500 (Internal Server Error).
const ok: client.Status = .ok;
const internal_server_error: server.Status = .internal_server_error;

/// The turns of the run, at most, and the room of each turn.
const rounds_max = 4096;
const operations_len = Server.operations_max + Server.sockets_max + Client.operations_max + Client.sockets_max;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    const random = tls.Random.init(&generator, fill);
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    try hosted_server.init(&.{
        .identity = .{ .chain = identity.chain_pem, .key = identity.key_pem },
        .cpu = cpu,
        .random = random,
        .now = .{ .unix_seconds = identity.now_seconds, .monotonic_ns = link.now_ns(.server) },
    }, &router, &router_context);
    try hosted_client.init(&.{
        .destination = .{ .addresses = &server_addresses, .port = https_port },
        .pool = .{
            .authority = origin,
            .protocols = .{ .h3 = false },
            .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .cpu = cpu },
        },
        .random = random,
        .now = .{ .unix_seconds = identity.now_seconds, .monotonic_ns = link.now_ns(.client) },
    }, &exchanges);
    for (&exchanges.responses, &exchanges.bodies) |*response, *body| {
        response.* = .{ .body = body };
        _ = try hosted_client.request(&exchanges.request, response);
    }
    try run_until(each_exchange_ended);
    if (exchanges.protocol != .h2) return error.ProtocolWrong;
    for (&exchanges.responses) |*response| {
        if (response.result != .response or response.status != ok) return error.ResponseWrong;
        if (!std.mem.eql(u8, greeting, response.body_received())) return error.ResponseWrong;
    }
    // A server that runs for weeks changes its ticket key between two calls (decision 161 as
    // amended). The tickets sealed under the current key still resume until the next change.
    var next_ticket_key: [tls.constants.protocol.server_key_len]u8 = undefined;
    generator.fill(&next_ticket_key);
    hosted_server.set_ticket_key(&next_ticket_key);
    std.crypto.secureZero(u8, &next_ticket_key);
    hosted_client.shutdown();
    try run_until(client_stopped);
    hosted_client.deinit();
    hosted_server.shutdown();
    try run_until(server_stopped);
    hosted_server.deinit();
    std.debug.print("colibri_hosted: two GETs over h2 between a hosted client and a hosted server\n", .{});
}

/// What the program keeps for its two exchanges, and what its handler records.
const Exchanges = struct {
    request: client.Request = .{ .method = "GET", .path = "/greeting" },
    responses: [2]client.Response = undefined,
    bodies: [2][64]u8 = undefined,
    finished: u32 = 0,
    protocol: ?client.Protocol = null,

    /// `turn` calls it for each exchange that ended.
    pub fn on_finished(self: *Exchanges, _: *Client, _: client.Finished) void {
        self.finished += 1;
    }

    pub fn on_connected(self: *Exchanges, _: *Client, connected: client.Connected) void {
        self.protocol = connected.protocol;
    }
};

fn each_exchange_ended() bool {
    return exchanges.finished == exchanges.responses.len;
}

fn client_stopped() bool {
    return hosted_client.stopped();
}

fn server_stopped() bool {
    return hosted_server.stopped();
}

/// Turns both objects until `ended()` holds.
fn run_until(comptime ended: fn () bool) !void {
    for (0..rounds_max) |_| {
        if (ended()) return;
        try hosted.round();
    }
    return error.RoundsExhausted;
}

/// One side's TCP socket: the receive and the send in flight, and whether the peer closed.
const Socket = struct {
    receive: ?colibri.Operation = null,
    send: ?colibri.Operation = null,
    ended: bool = false,
};

/// The program's host of both objects.
const Host = struct {
    sockets: [sides]Socket = @splat(.{}),
    /// The server's accept in flight.
    accept: ?colibri.OperationId = null,
    /// A completion came in this round.
    completed: bool = false,

    /// One round: a turn of each object that has not stopped, each operation that the turn
    /// wrote, then the octets on the link. When no completion came, the program waits on the
    /// loop until the earliest instant that a turn named.
    fn round(self: *Host) !void {
        var operations: [operations_len]colibri.Operation = undefined;
        var waits: [sides]colibri.Wait = @splat(.none);
        self.completed = false;
        if (!hosted_server.stopped()) {
            const turned = hosted_server.turn(link.now_ns(.server), &operations);
            for (operations[0..turned.operations]) |operation| try self.perform(.server, operation);
            waits[@intFromEnum(Side.server)] = turned.wait;
        }
        if (!hosted_client.stopped()) {
            const turned = hosted_client.turn(link.now_ns(.client), &operations);
            for (operations[0..turned.operations]) |operation| try self.perform(.client, operation);
            waits[@intFromEnum(Side.client)] = turned.wait;
        }
        for (std.enums.values(Side)) |side| try self.deliver(side);
        if (self.completed or link.pending()) return;
        try self.wait(&waits);
    }

    /// Gives `side` one completion at the instant of its loop.
    fn complete(self: *Host, side: Side, completion: colibri.Completion) void {
        self.completed = true;
        switch (side) {
            .client => hosted_client.complete(&completion, link.now_ns(.client)),
            .server => hosted_server.complete(&completion, link.now_ns(.server)),
        }
    }

    /// Does one operation that a turn of `side` wrote.
    fn perform(self: *Host, side: Side, operation: colibri.Operation) !void {
        const socket = &self.sockets[@intFromEnum(side)];
        switch (operation.kind) {
            .accept => self.accept = operation.id,
            .connect => self.connect(operation.id),
            .receive => socket.receive = operation,
            .send => {
                socket.send = operation;
                try self.send(side);
            },
            .shutdown_send => self.shutdown_send(side, operation.id),
            .close => self.close(side, operation.id),
            .cancel => |named| self.cancel(side, named.target),
            // The host opened no UDP socket, so no object writes a datagram.
            .receive_datagram, .send_datagram => unreachable,
        }
    }

    /// Joins the client's connect and the server's accept.
    fn connect(self: *Host, id: colibri.OperationId) void {
        const accept = self.accept orelse return self.complete(.client, .{ .id = id, .result = .{ .failed = .refused } });
        self.accept = null;
        self.sockets = @splat(.{});
        self.complete(.server, .{ .id = accept, .result = .accepted });
        self.complete(.client, .{ .id = id, .result = .connected });
    }

    /// Puts the octets of the send of `side` on the link, as many as the peer's queue takes. A
    /// send that finds no room waits for the next round.
    fn send(self: *Host, side: Side) !void {
        const socket = &self.sockets[@intFromEnum(side)];
        const operation = socket.send orelse return;
        const bytes = operation.kind.send.bytes;
        const room = link_module.queue_len_max - link.queue_lens[@intFromEnum(side.other())];
        const count = @min(bytes.len, room);
        if (count == 0) return;
        try link.send(side, bytes[0..count]);
        socket.send = null;
        self.complete(side, .{ .id = operation.id, .result = .{ .sent = @intCast(count) } });
    }

    /// Closes the write side of the socket of `side`: its peer reads the end of the octets, and
    /// its own receive goes on (RFC 9112 §9.6).
    fn shutdown_send(self: *Host, side: Side, id: colibri.OperationId) void {
        self.sockets[@intFromEnum(side.other())].ended = true;
        self.complete(side, .{ .id = id, .result = .shut_down });
    }

    /// Closes the socket of `side`: its receive, and a send that waits for room on the link, end
    /// first (decision 159, rule 1). Its peer then reads the end of the octets.
    fn close(self: *Host, side: Side, id: colibri.OperationId) void {
        const socket = &self.sockets[@intFromEnum(side)];
        if (socket.receive) |receive| {
            socket.receive = null;
            self.complete(side, .{ .id = receive.id, .result = .canceled });
        }
        if (socket.send) |held| {
            socket.send = null;
            self.complete(side, .{ .id = held.id, .result = .canceled });
        }
        self.sockets[@intFromEnum(side.other())].ended = true;
        self.complete(side, .{ .id = id, .result = .closed });
    }

    /// Ends the server's accept, which `shutdown` cancels. A target that ended names nothing.
    fn cancel(self: *Host, side: Side, target: colibri.OperationId) void {
        const accept = self.accept orelse return;
        if (side != .server or accept != target) return;
        self.accept = null;
        self.complete(.server, .{ .id = target, .result = .canceled });
    }

    /// Gives the receive of `side` the octets on the link, or their end, and retries its send.
    fn deliver(self: *Host, side: Side) !void {
        try self.send(side);
        const socket = &self.sockets[@intFromEnum(side)];
        const receive = socket.receive orelse return;
        const input = try link.receive(side);
        if (input.len == 0 and !socket.ended) return;
        const buffer = receive.kind.receive.buffer;
        const count = @min(input.len, buffer.len);
        @memcpy(buffer[0..count], input[0..count]);
        link.consume(side, count);
        socket.receive = null;
        // A read of 0 octets means that the peer closed its side.
        self.complete(side, .{ .id = receive.id, .result = .{ .received = @intCast(count) } });
    }

    /// Waits on the loop until the earliest instant that a turn named. Both loops run on this
    /// thread, so the time passes for both objects.
    fn wait(self: *Host, waits: []const colibri.Wait) !void {
        _ = self;
        var wait_ns: ?u64 = null;
        for (waits, std.enums.values(Side)) |named, side| {
            switch (named) {
                .now => return,
                .none => {},
                .at_ns => |at_ns| wait_ns = @min(wait_ns orelse std.math.maxInt(u64), at_ns -| link.now_ns(side)),
            }
        }
        // Each object waits for a completion that only the other object can cause.
        try link.wait(.server, wait_ns orelse return error.Stalled);
    }
};

/// Answers a GET of `/greeting`.
fn greet(_: *void, _: *server.RequestContext, _: *const server.Request, response: *server.ResponseWriter) !void {
    try response.header("content-type", "text/plain");
    try response.body().writeAll(greeting);
    try response.end();
}

/// Answers 500 when a route's function fails.
fn on_error(_: *void, _: *server.RequestContext, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}
