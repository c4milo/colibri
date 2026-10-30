//! The server of `client_exchange.zig`. This file is not an example by itself: it holds what the
//! client example runs against.
//!
//! The server is one `server.Endpoint` with one TCP slot and no UDP socket, so every datagram of
//! the client's QUIC connection is lost. It answers a GET with a greeting and a POST with its own
//! content. It answers 405, 404 or 501 to a request that no route serves, and it issues a
//! resumption ticket on its connection. Its router calls the function of each route, as the
//! router of `server_exchange.zig` does. It runs over the stream link, on the server's loop. `docs/usage.md` shows the server's calls with
//! the server example, so the comments here are short.
const std = @import("std");
const server = @import("server");
const tls = @import("tls");
const identity = @import("testdata");
const program = @import("tls_program.zig");
const link_module = @import("link.zig");

const Link = link_module.Link;

pub const greeting = "hello from colibri over TCP\n";
pub const note = "a note the client posts, which the server sends back\n";
pub const content_type = "text/plain; charset=utf-8";

/// The octets the server writes before it sends them, at most.
const output_len = 16384;

/// Events the server takes in one turn, and calls to `send_stream` one `send` event takes, at most.
const events_per_turn_max = 64;
const sends_per_event_max = 8;

/// The requests the client sends, and the sockets it connects.
const requests_count = 5;
const connections_count = 1;

/// Unix seconds, at which the server issues its tickets. A program reads them from its clock.
const now_seconds = identity.now_seconds;

pub const Error = error{
    /// What arrived is not what was sent.
    ExchangeWrong,
    /// A connection still owed octets after `sends_per_event_max` calls to `send_stream`.
    SendUnfinished,
};

/// The server's table of routes, which the compiler builds.
const routes = server.router(void, .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .post, "/echo", Echo, .{ .whole_body = true } },
    },
});

/// One request at a time, with room for the POST's content.
const Router = @TypeOf(routes).Of(.{ .requests = 1, .response_bytes = 256, .body_bytes = note.len });

/// One TCP connection at a time, and no QUIC connection: this server has no UDP socket.
const Endpoint = server.EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 });
const chain = [_][]const u8{ identity.leaf, identity.root };

// The endpoint holds hundreds of kilobytes, so it lives outside the stack.
var link: *Link = undefined;
var output: [output_len]u8 = undefined;
var cookie_key: [tls.constants.protocol.server_key_len]u8 = undefined;
var ticket_key: [tls.constants.protocol.server_key_len]u8 = undefined;
var config: server.Config align(@alignOf(server.Config)) = undefined;
var endpoint: Endpoint align(@alignOf(Endpoint)) = undefined;
/// The connection of the socket the client connected, once the listener accepted it.
var accepted: ?server.ConnectionHandle align(@alignOf(server.ConnectionHandle)) = null;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};
/// Responses that are whole, sockets the endpoint said to close, and connections that are over.
var answered: u32 = 0;
var closes: u32 = 0;
var ended: u32 = 0;

/// Starts the server's endpoint on the stream link the example holds.
pub fn init(stream: *Link, cpu: tls.Cpu) !void {
    link = stream;
    program.fill(&cookie_key);
    program.fill(&ticket_key);
    config = .{
        .tls = .{
            .ecdsa_p256 = .{
                .chain = &chain,
                .public_key = identity.public_key,
                .private_key = identity.private_key,
            },
            .cookie_key = &cookie_key,
            .ticket_key = &ticket_key,
            .cpu = cpu,
        },
    };
    try endpoint.init(&config, program.random(), now_seconds, link.now_ns(.server));
}

/// The listener accepts the socket the client connected.
pub fn accept() !void {
    if (accepted != null) return error.ExchangeWrong;
    accepted = endpoint.accept(.{}, link.now_ns(.server)) orelse return error.ExchangeWrong;
}

/// One turn of the server: fire its deadlines, pass the endpoint the octets the socket read, and
/// act on every event it reports.
pub fn turn() !void {
    const input = try link.receive(.server);
    const now_ns = link.now_ns(.server);
    endpoint.on_instant(now_ns);
    const connection = accepted orelse return;
    var consumed: usize = 0;
    for (0..events_per_turn_max) |_| {
        const read: server.StreamBytes = .{ .connection = connection, .bytes = input[consumed..] };
        const received = endpoint.receive(.{ .stream = read }, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try serve(event, now_ns);
    }
    link.consume(.server, consumed);
}

fn serve(event: server.Event, now_ns: u64) !void {
    switch (event) {
        .request => |request| std.debug.print("server: {s} {s}\n", .{ request.method, request.target }),
        // A request is over: its response was sent, or it was cancelled.
        .finished => |finished| answered += @intFromBool(finished.result == .sent),
        else => {},
    }
    // The router answers each request, and hands back the events of the connection.
    switch (router.handle(&context, &endpoint, event)) {
        .taken => {},
        .event => |other| switch (other) {
            .send => |connection| try flush(connection, now_ns),
            .close => closes += 1,
            .ended => |connection| {
                if (connection.failed or connection.reason != null) return error.ExchangeWrong;
                ended += 1;
            },
            // Only a shutdown ends in `closed`.
            else => unreachable,
        },
    }
}

fn greet(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", content_type);
    try response.body().writeAll(greeting);
    try response.end();
}

/// Sends the POST's content back, once all of it arrived.
const Echo = struct {
    pub fn on_request(_: *void, _: *void, _: *const server.Request, _: void, _: void, _: *server.ResponseWriter) !void {}

    pub fn on_body(_: *void, _: *void, content: *std.Io.Reader, response: *server.ResponseWriter) !void {
        try response.header("content-type", content_type);
        try response.body().writeAll(content.buffered());
        try response.end();
    }
};

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = 500;
}

fn flush(connection: server.ConnectionHandle, now_ns: u64) !void {
    if (connection != accepted.?) return error.ExchangeWrong;
    for (0..sends_per_event_max) |_| {
        const written = endpoint.send_stream(connection, &output, now_ns);
        try link.send(.server, output[0..written]);
        if (written < output.len) return;
    }
    return error.SendUnfinished;
}

/// The soonest instant the endpoint wants `on_instant` at, or null.
pub fn deadline_ns() ?u64 {
    return endpoint.deadline_ns();
}

/// Whether the server's one connection is over.
pub fn over() bool {
    return ended == connections_count;
}

/// Whether the server answered each request whole, said to close its socket once, and saw its
/// connection end.
pub fn check() bool {
    if (answered == requests_count and closes == connections_count and ended == connections_count) return true;
    std.debug.print("client_peer: answered {d}, closes {d}, ended {d}\n", .{ answered, closes, ended });
    return false;
}
