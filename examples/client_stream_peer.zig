//! The server of `client_stream.zig`. This file is not an example by itself: it holds what the
//! stream example runs against.
//!
//! The server is one `server.Engine` with one TCP slot in cleartext, which reads h2 from the
//! client's preface (decision 117). It answers the gRPC-shaped POST at its head, then sends back
//! each piece of the request's body as it arrives, reads the request's trailer section, and ends
//! the response with a trailer section that carries `grpc-status` once the request's body ends. It answers any other request with
//! 404. `docs/usage.md` shows the server's calls with the server example, so the comments here
//! are short.
const std = @import("std");
const server = @import("server");
const http = @import("http");
const program = @import("tls_program.zig");
const link_module = @import("link.zig");

const Link = link_module.Link;

/// The method and the path of the call, and the content type of its messages.
pub const path = "/echo.Echo/Chat";
pub const content_type = "application/grpc";
/// The request's trailer field, which says how many messages the call sent.
pub const count_trailer = "x-message-count";
pub const count_value = "3";

/// The octets the server writes before it sends them, at most.
const output_len = 16384;

/// Events the server takes in one turn, and calls to `send_stream` one `send` event takes, at most.
const events_per_turn_max = 64;
const sends_per_event_max = 4;

/// The octets of the request's body the server keeps, which it sends back from its own memory:
/// the engine may read them until the request's `finished`.
const echo_len_max = 1024;

pub const Error = error{
    /// What arrived is not what was sent.
    ExchangeWrong,
    /// A connection still owed octets after `sends_per_event_max` calls to `send_stream`.
    SendUnfinished,
};

/// One TCP connection, and no QUIC connection.
const Engine = server.Engine(.{ .tcp_connections = 1, .quic_connections = 0 });

// The engine holds hundreds of kilobytes, so it lives outside the stack.
var link: *Link = undefined;
var output: [output_len]u8 = undefined;
var config: server.Config align(@alignOf(server.Config)) = .{};
var engine: Engine align(@alignOf(Engine)) = undefined;
/// The connection of the socket the client connected, once the listener accepted it.
var accepted: ?server.ConnectionHandle align(@alignOf(server.ConnectionHandle)) = null;
/// The call's id, and the octets of its body the server sent back.
var call: ?server.RequestId align(@alignOf(server.RequestId)) = null;
var echo: [echo_len_max]u8 = undefined;
var echo_len: usize = 0;
/// Whether the call's trailer section named its messages, responses that are whole, and
/// connections that are over.
var counted: bool = false;
var answered: u32 = 0;
var ended: u32 = 0;

/// Starts the server's engine on the stream link the example holds.
pub fn init(stream: *Link) !void {
    link = stream;
    try engine.init(&config, program.random(), .{ .ns = link.now_ns(.server), .unix_seconds = 0 });
}

/// The listener accepts the socket the client connected.
pub fn accept() !void {
    if (accepted != null) return error.ExchangeWrong;
    accepted = engine.accept(.{ .tls = false }, link.now_ns(.server)) orelse return error.ExchangeWrong;
}

/// The client closed its socket, and the engine hears it.
pub fn closed() void {
    const connection = accepted orelse return;
    engine.transport_closed(connection);
    accepted = null;
}

/// One turn of the server: fire its deadlines, pass the engine the octets the socket read, and
/// act on every event it reports.
pub fn turn() !void {
    const input = try link.receive(.server);
    const now_ns = link.now_ns(.server);
    engine.on_instant(now_ns);
    var consumed: usize = 0;
    for (0..events_per_turn_max) |_| {
        // With no socket, `.none` reports what the engine owes: the end of the connection.
        const read: server.Input = if (accepted) |connection| .{ .stream = .{ .connection = connection, .bytes = input[consumed..] } } else .none;
        const received = engine.receive(read, now_ns);
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
        .request => |request| try answer(request),
        .body => |body| try send_back(body),
        .trailers => |trailers| try read_trailers(trailers),
        .finished => |finished| answered += @intFromBool(finished.result == .sent),
        .send => |connection| try flush(connection, now_ns),
        .ended => |connection| {
            if (connection.failed) return error.ExchangeWrong;
            ended += 1;
        },
        // The client closes the socket, so the server is never the first to say `close`, and
        // it reads each request whole, so it never closes in stages (decision 160).
        .half_close, .close => return error.ExchangeWrong,
        // Each write of the server finds room.
        .writable => return error.ExchangeWrong,
        // Only a shutdown ends in `closed`.
        .closed => unreachable,
    }
}

/// Answers the call at its head, before its body: the response's head goes out now, and its
/// body follows the request's (RFC 9113 §8.1).
fn answer(request: server.Request) !void {
    const target = request.path orelse "";
    if (!std.mem.eql(u8, request.method, "POST") or !std.mem.eql(u8, target, path) or call != null) {
        return engine.respond(request.id, .{ .status = .not_found, .end = true });
    }
    call = request.id;
    const headers = [_]server.Header{.{ .name = "content-type", .value = content_type }};
    try engine.respond(request.id, .{ .status = .ok, .headers = &headers, .end = false });
}

/// Sends back a piece of the call's body as soon as it arrives, from the server's own memory,
/// and ends the response once the body ends.
fn send_back(body: server.RequestBody) !void {
    if (call == null or body.id != call.?) return error.ExchangeWrong;
    if (echo_len + body.bytes.len > echo.len) return error.ExchangeWrong;
    const piece = echo[echo_len..][0..body.bytes.len];
    @memcpy(piece, body.bytes);
    echo_len += piece.len;
    if (piece.len > 0) {
        const written = try engine.write_body(body.id, .{ .bytes = piece, .end = false });
        if (written != piece.len) return error.ExchangeWrong;
    }
    if (body.end) try end_call(body.id);
}

/// Ends the response with `grpc-status` in its trailer section.
fn end_call(id: server.RequestId) !void {
    const trailers = [_]http.Field{.{ .name = "grpc-status", .value = "0" }};
    try engine.write_trailers(id, &trailers);
}

/// Reads the call's trailer section, which ends its body (RFC 9113 §8.1), and ends the response.
fn read_trailers(trailers: server.Trailers) !void {
    if (call == null or trailers.id != call.?) return error.ExchangeWrong;
    const count = trailers.headers.find(count_trailer) orelse return error.ExchangeWrong;
    if (!std.mem.eql(u8, count.value, count_value)) return error.ExchangeWrong;
    counted = true;
    try end_call(trailers.id);
}

fn flush(connection: server.ConnectionHandle, now_ns: u64) !void {
    if (connection != accepted.?) return error.ExchangeWrong;
    for (0..sends_per_event_max) |_| {
        const written = engine.send_stream(connection, &output, now_ns);
        try link.send(.server, output[0..written]);
        if (written < output.len) return;
    }
    return error.SendUnfinished;
}

/// The soonest instant the engine wants `on_instant` at, or null.
pub fn deadline_ns() ?u64 {
    return engine.deadline_ns();
}

/// Whether the server's one connection is over.
pub fn over() bool {
    return ended == 1;
}

/// Whether the server answered the call whole, read `sent` octets of its body and its trailer
/// section, and saw its connection end.
pub fn check(sent: []const u8) bool {
    if (counted and answered == 1 and ended == 1 and std.mem.eql(u8, echo[0..echo_len], sent)) return true;
    std.debug.print("client_stream_peer: counted {}, answered {d}, ended {d}, echoed {d} octets\n", .{ counted, answered, ended, echo_len });
    return false;
}
