//! The server of `client_pool.zig`. This file is not an example by itself: it holds what the pool
//! example runs against.
//!
//! The server is one `server.Endpoint` with four TCP slots in cleartext, which names no version
//! and reads h11 from the client's first octets (decision 117). Each socket the client connects is
//! one stream of the link, and the listener accepts it. The server answers each GET of
//! `/greeting` with a greeting. `docs/usage.md` shows the server's calls with the server example,
//! so the comments here are short.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const program = @import("tls_program.zig");
const link_module = @import("link_streams.zig");

const StreamsLink = link_module.StreamsLink;
const streams_max = link_module.streams_max;

pub const greeting = "hello from colibri over one of four connections\n";

/// The octets the server writes before it sends them, at most.
const output_len = 16384;

/// Events the server takes from one stream in one turn, and calls to `send_stream` one `send`
/// event takes, at most.
const events_per_stream_max = 64;
const sends_per_event_max = 4;

pub const Error = error{
    /// What arrived is not what was sent.
    ExchangeWrong,
    /// A connection still owed octets after `sends_per_event_max` calls to `send_stream`.
    SendUnfinished,
};

/// One TCP connection for each stream of the link, and no QUIC connection.
const Endpoint = server.EndpointOf(.{ .tcp_connections = streams_max, .quic_connections = 0 });

// The endpoint holds hundreds of kilobytes, so it lives outside the stack.
var link: *StreamsLink = undefined;
var output: [output_len]u8 = undefined;
var config: server.Config align(@alignOf(server.Config)) = .{};
var endpoint: Endpoint align(@alignOf(Endpoint)) = undefined;
/// The connection of each stream's socket, once the listener accepted it.
var accepted: [streams_max]?server.ConnectionHandle align(@alignOf(server.ConnectionHandle)) = @splat(null);
/// Responses that are whole, and connections that are over.
var answered: u32 = 0;
var ended: u32 = 0;

/// Starts the server's endpoint on the stream link the example holds.
pub fn init(streams: *StreamsLink) !void {
    link = streams;
    try endpoint.init(&config, program.random(), 0, link.now_ns(.server));
}

/// The listener accepts the socket the client connected on `stream`.
pub fn accept(stream: usize) !void {
    if (accepted[stream] != null) return error.ExchangeWrong;
    accepted[stream] = endpoint.accept(.{ .tls = false }, link.now_ns(.server)) orelse return error.ExchangeWrong;
}

/// The client closed the socket of `stream`, and the endpoint hears it.
pub fn closed(stream: usize) void {
    const connection = accepted[stream] orelse return;
    endpoint.transport_closed(connection);
    accepted[stream] = null;
}

/// One turn of the server: fire its deadlines, pass the endpoint the octets each socket read, and
/// act on every event it reports.
pub fn turn() !void {
    try link.receive(.server);
    const now_ns = link.now_ns(.server);
    endpoint.on_instant(now_ns);
    for (0..streams_max) |stream| try read(stream, now_ns);
    // What the endpoint reports with no octets: the ends of the connections the client closed.
    for (0..events_per_stream_max) |_| {
        const event = endpoint.receive(.none, now_ns).event orelse break;
        try serve(event, now_ns);
    }
}

fn read(stream: usize, now_ns: u64) !void {
    const connection = accepted[stream] orelse return;
    const input = link.queue(stream, .server);
    var consumed: usize = 0;
    for (0..events_per_stream_max) |_| {
        const octets: server.StreamBytes = .{ .connection = connection, .bytes = input[consumed..] };
        const received = endpoint.receive(.{ .stream = octets }, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try serve(event, now_ns);
    }
    link.consume(stream, .server, consumed);
}

fn serve(event: server.Event, now_ns: u64) !void {
    switch (event) {
        .request => |request| try answer(request),
        .finished => |finished| answered += @intFromBool(finished.result == .sent),
        .send => |connection| try flush(connection, now_ns),
        .ended => |connection| {
            if (connection.failed) return error.ExchangeWrong;
            ended += 1;
        },
        // The client closes each socket, so the server is never the first to say `close`.
        .close => return error.ExchangeWrong,
        .body, .trailers, .writable => {},
        // Only a shutdown ends in `closed`.
        .closed => unreachable,
    }
}

/// Answers a GET of `/greeting` with the greeting, and any other request with 404.
fn answer(request: server.Request) !void {
    const path = request.path orelse "";
    if (!std.mem.eql(u8, request.method, "GET") or !std.mem.eql(u8, path, "/greeting")) {
        return endpoint.respond(request.id, .{ .status = 404, .end = true });
    }
    var digits: [8]u8 = undefined;
    const length = std.fmt.bufPrint(&digits, "{d}", .{greeting.len}) catch unreachable;
    try endpoint.respond(request.id, .{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = length }},
        .end = false,
    });
    const taken = try endpoint.write_body(request.id, .{ .bytes = greeting, .end = true });
    assert(taken == greeting.len);
}

/// Writes what `connection` owes into its stream.
fn flush(connection: server.ConnectionHandle, now_ns: u64) !void {
    const stream = stream_of(connection) orelse return error.ExchangeWrong;
    for (0..sends_per_event_max) |_| {
        const written = endpoint.send_stream(connection, &output, now_ns);
        try link.send(stream, .server, output[0..written]);
        if (written < output.len) return;
    }
    return error.SendUnfinished;
}

fn stream_of(connection: server.ConnectionHandle) ?usize {
    for (accepted, 0..) |held, stream| {
        if (held != null and held.? == connection) return stream;
    }
    return null;
}

/// The soonest instant the endpoint wants `on_instant` at, or null.
pub fn deadline_ns() ?u64 {
    return endpoint.deadline_ns();
}

/// Whether every connection the client opened is over.
pub fn over(opened: u32) bool {
    return ended == opened;
}

/// Whether the server answered `requests` requests whole and saw `opened` connections end.
pub fn check(requests: u32, opened: u32) bool {
    if (answered == requests and ended == opened) return true;
    std.debug.print("client_pool_peer: answered {d}, ended {d}\n", .{ answered, ended });
    return false;
}
