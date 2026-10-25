//! The server of `client_exchange.zig`. This file is not an example by itself: it holds what the
//! client example runs against.
//!
//! The server is one `server.Endpoint` with one TCP slot and no UDP socket, so every datagram of
//! the client's QUIC connection is lost. It answers a GET with a greeting and a POST with its own
//! content. It answers 405, 404 or 501 to a request that no route serves, and it issues a
//! resumption ticket on its connection. Each of its routes names the
//! function that answers the request, where the routes of `server_exchange.zig` name an enum. It
//! runs over the stream link, on the server's loop. `docs/usage.md` shows the server's calls with
//! the server example, so the comments here are short.
const std = @import("std");
const assert = std.debug.assert;
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

/// What a route of this server names: the function that answers the request.
const Handler = *const fn (request: server.Request, parameters: *const server.PathParameters) anyerror!void;

/// The server's table of routes, which the compiler builds.
const router = server.router(Handler, .{
    .{ .get, "/greeting", greet },
    .{ .post, "/echo", echo },
});

/// One TCP connection at a time, and no QUIC connection: this server has no UDP socket.
const Endpoint = server.EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 });
const chain = [_][]const u8{ identity.leaf, identity.root };

// The endpoint holds hundreds of kilobytes, so it lives outside the stack.
var link: *Link = undefined;
var output: [output_len]u8 = undefined;
var cookie_key: [tls.constants.server_key_len]u8 = undefined;
var ticket_key: [tls.constants.server_key_len]u8 = undefined;
var config: server.Config align(@alignOf(server.Config)) = undefined;
var endpoint: Endpoint align(@alignOf(Endpoint)) = undefined;
/// The connection of the socket the client connected, once the listener accepted it.
var accepted: ?server.ConnectionHandle align(@alignOf(server.ConnectionHandle)) = null;
/// Written by each `match`.
var parameters: server.PathParameters align(@alignOf(server.PathParameters)) = .{};
/// The content of the POST, which the server sends back once the request ends.
var posted: [note.len]u8 = undefined;
var posted_len: usize = 0;
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
        .request => |request| try take_request(request),
        .body => |body| {
            if (posted_len + body.bytes.len > posted.len) return error.ExchangeWrong;
            @memcpy(posted[posted_len..][0..body.bytes.len], body.bytes);
            posted_len += body.bytes.len;
            if (body.end) try answer(body.id, posted[0..posted_len]);
        },
        // A request is over: its response was sent, or it was cancelled.
        .finished => |finished| answered += @intFromBool(finished.result == .sent),
        .send => |connection| try flush(connection, now_ns),
        .close => closes += 1,
        .ended => |connection| {
            if (connection.failed or connection.reason != null) return error.ExchangeWrong;
            ended += 1;
        },
        .trailers, .writable => {},
        // Only a shutdown ends in `closed`.
        .closed => unreachable,
    }
}

/// Calls the function of the route that the request's method and path match, or refuses the
/// request.
fn take_request(request: server.Request) !void {
    std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
    switch (router.match(request.method, request.path orelse "", &parameters)) {
        .found => |handler| try handler(request, &parameters),
        // RFC 9110 §15.5.6: a 405 carries an Allow field, which lists the methods of the path.
        .method_not_allowed => |allowed| try endpoint.respond(request.id, .{
            .status = 405,
            .headers = &.{.{ .name = "allow", .value = allowed }},
            .end = true,
        }),
        .not_found => try endpoint.respond(request.id, .{ .status = 404, .end = true }),
        // RFC 9110 §9.1: no route names the method.
        .not_implemented => try endpoint.respond(request.id, .{ .status = 501, .end = true }),
    }
}

fn greet(request: server.Request, _: *const server.PathParameters) anyerror!void {
    try answer(request.id, greeting);
}

/// The content follows in `body` events, and the server answers at its end.
fn echo(_: server.Request, _: *const server.PathParameters) anyerror!void {}

fn answer(id: server.RequestId, content: []const u8) !void {
    var digits: [8]u8 = undefined;
    const length = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable;
    try endpoint.respond(id, .{
        .status = 200,
        .headers = &.{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "content-length", .value = length },
        },
        .end = false,
    });
    const taken = try endpoint.write_body(id, .{ .bytes = content, .end = true });
    assert(taken == content.len);
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
