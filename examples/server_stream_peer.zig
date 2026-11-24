//! The client of `server_stream.zig`. This file is not an example by itself: it holds what the
//! stream route example runs against.
//!
//! The client is one `client.ConnectionPool(.{ .quic = false })`, which speaks h2 in cleartext with
//! prior knowledge (decision 117). It sends one gRPC-shaped POST whose request body and response
//! body are streamed (decision 153). The request body holds three messages, which the client hands
//! the pool in three pieces:
//! 1. the first message, and the first octets of the second;
//! 2. the rest of the second message;
//! 3. the third message, which ends the body.
//!
//! So the server's route gets the second message cut across two body events. The client hands each
//! next piece only once the replies to the whole messages before it came back. So each reply must
//! leave the server before the request's body ends. `client_stream.zig` shows the client's calls,
//! so the comments here are short.
const std = @import("std");
const client = @import("client");
const program = @import("tls_program.zig");
const link_module = @import("link.zig");

const Link = link_module.Link;

/// The path of the call, and the content type of its messages.
pub const path = "/greeter.Greeter/Greet";
pub const content_type = "application/grpc";

/// The prefix of each gRPC message: a flag octet, then the payload's length in four octets, most
/// significant first.
pub const prefix_len = 1 + @sizeOf(u32);

/// The names the client sends, one in each message, and the words before the name in each reply.
pub const names = [_][]const u8{ "Ada Lovelace", "Grace Hopper", "Barbara Liskov" };
pub const greeting = "hello, ";

/// The message that two pieces cut, and the octets of its payload in the first piece.
const cut_message = 1;
const cut_payload_len = 5;

comptime {
    // The cut falls inside the payload, so neither piece holds the message whole.
    std.debug.assert(cut_payload_len > 0 and cut_payload_len < names[cut_message].len);
}

/// The request body: each name as a message. The replies the server owes: `greeting` and each
/// name as a message, in the same order.
const request_body = frame_all("");
const replies = frame_all(greeting);

/// The end of each piece in the request body, and the replies the server can write once it read
/// the piece: one for each message that the piece made whole.
const piece_ends = [_]usize{
    messages_len("", cut_message) + prefix_len + cut_payload_len,
    messages_len("", cut_message + 1),
    messages_len("", names.len),
};
const replies_after = [_]usize{ cut_message, cut_message + 1, names.len };

/// The origin, and its port: 80 for "http" (RFC 9110 §4.2.1).
const origin = "localhost";
const server_port = 80;
const server_host = [_]u8{ 192, 0, 2, 1 };
const server_addresses = [_]client.Address{.init(&server_host, 0)};

/// The octets of the response body the client holds at a time: fewer than a reply, so a reply
/// comes in more than one piece. The octets of the response's headers, and of its trailers.
const piece_len = 16;
const section_len = 256;

/// Calls of `send_stream` for one `send`, at most: one turn's frames fit in one output.
const sends_per_debt_max = 4;

pub const Error = error{
    /// What arrived is not what the server owes.
    ExchangeWrong,
};

const ConnectionPool = client.ConnectionPool(.{ .quic = false });
var pool: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
var pool_memory: [ConnectionPool.memory_bytes(.{})]u8 align(ConnectionPool.memory_alignment) = undefined;
var config: client.Config align(@alignOf(client.Config)) = undefined;

var link: *Link = undefined;
/// What `send_stream` writes, which the link then sends.
var output: [client.constants.limits.stream_output_len_min]u8 = undefined;

/// Calls of `receive` for one read of the socket, at most. Each call takes one octet or more of
/// the link's queue, or reports an event and takes no octet, or ends the loop.
const receive_calls_max = (link_module.queue_len_max + 1) * (ConnectionPool.receive_events_without_input_max(.{}) + 1);

/// The call. Both of its bodies go in pieces, so `body` is empty and the response's `body` holds
/// one piece at a time.
const call: client.Request = .{
    .method = "POST",
    .path = path,
    .headers = &.{.{ .name = "content-type", .value = content_type }},
    .streamed = .{ .request = true, .response = true },
};
var piece: [piece_len]u8 = undefined;
var header_buffer: [section_len]u8 = undefined;
var trailer_buffer: [section_len]u8 = undefined;
var response: client.Response align(@alignOf(client.Response)) = .{
    .body = &piece,
    .headers = .{ .buffer = &header_buffer },
    .trailers = .{ .buffer = &trailer_buffer },
};
var call_id: client.RequestId align(@alignOf(client.RequestId)) = @enumFromInt(0);

/// The connection of the socket, once the pool opened it.
var socket: ?client.ConnectionHandle align(@alignOf(client.ConnectionHandle)) = null;

/// What the client saw: the pieces it handed and the pool took, the octets of the replies, and
/// whether the call finished, the socket closed and the shut-down pool is over.
var handed: usize = 0;
var taken: usize = 0;
var heard_headers: bool = false;
var received_len: usize = 0;
var finished: bool = false;
var socket_closed: bool = false;
var pool_closed: bool = false;

/// Starts the pool on the stream link the example holds, requests the call, and hands it the
/// first piece. The server's listener accepted the socket the link stands for.
pub fn init(stream: *Link) !void {
    link = stream;
    config = .{ .authority = origin, .protocols = .{ .h11 = false, .h3 = false }, .cpu_features = .detect() };
    const known: client.Destination = .{ .addresses = &server_addresses, .port = server_port };
    try pool.init(&pool_memory, &config, &known, null);
    call_id = try pool.request(&call, &response);
    try hand_next();
}

/// Hands the pool the next piece of the request body. The pool holds one piece of a request at a
/// time, so the piece before must be taken. Each reply the server owes for it must be back too.
fn hand_next() !void {
    if (handed == piece_ends.len or taken < handed) return;
    if (handed > 0 and received_len < messages_len(greeting, replies_after[handed - 1])) return;
    const start = if (handed == 0) 0 else piece_ends[handed - 1];
    const end: client.PieceEnd = if (handed + 1 == piece_ends.len) .last else .more;
    // The pool copies none of the piece: `request_body` stays in place until its `body_taken`.
    try pool.write_body(call_id, request_body[start..piece_ends[handed]], end);
    handed += 1;
}

/// One turn of the client: pass the pool what the socket read, until it consumes nothing and
/// reports nothing. With no socket it passes `.none`, which reports what the pool owes.
pub fn turn() !void {
    const input = try link.receive(.client);
    const now_ns = link.now_ns(.client);
    var consumed: usize = 0;
    for (0..receive_calls_max) |_| {
        const held = input[consumed..];
        const read: client.Input = if (socket != null and held.len > 0) .{ .stream = .{ .connection = socket.?, .bytes = held } } else .none;
        const result = pool.receive(read, now_ns);
        consumed += result.consumed;
        const event = result.event orelse {
            if (result.consumed == 0) break;
            continue;
        };
        try report(event, now_ns);
        // A closed socket reads nothing more.
        if (event == .close) consumed = input.len;
    }
    link.consume(.client, consumed);
}

/// Acts on one event of the pool.
fn report(event: client.Event, now_ns: u64) !void {
    switch (event) {
        .open => |open| try open_socket(open),
        .send => |connection| try send_owed(connection, now_ns),
        .close => |connection| close_socket(connection),
        .connected => |connected| if (connected.protocol != .h2) return error.ExchangeWrong,
        .headers => |id| try on_headers(id),
        // The connection reads the piece no more: its memory is the program's again.
        .body_taken => |id| {
            if (id != call_id) return error.ExchangeWrong;
            taken += 1;
            try hand_next();
        },
        .body => |held| try on_piece(held),
        .finished => |ended| try on_finished(ended),
        // A pool in cleartext gets no ticket.
        .ticket => return error.ExchangeWrong,
        .closed => pool_closed = true,
    }
}

/// The response's head arrived, with the first reply.
fn on_headers(id: client.RequestId) !void {
    if (id != call_id or response.status != .ok) return error.ExchangeWrong;
    const kind = response.headers.get("content-type") orelse "";
    if (!std.mem.eql(u8, kind, content_type)) return error.ExchangeWrong;
    heard_headers = true;
}

/// `body` holds a piece of the replies. It must be the next octets the server owes, and come
/// only from a reply to a message the server could read whole. The client then releases it.
fn on_piece(held: client.Event.Piece) !void {
    if (held.id != call_id or !heard_headers) return error.ExchangeWrong;
    if (received_len + held.len > messages_len(greeting, replies_after[handed - 1])) return error.ExchangeWrong;
    if (!std.mem.eql(u8, response.body[0..held.len], replies[received_len..][0..held.len])) return error.ExchangeWrong;
    received_len += held.len;
    pool.release_body(held.id);
    try hand_next();
}

/// The call ended: the trailers must say it succeeded.
fn on_finished(ended: client.Finished) !void {
    if (ended.response.result != .response) return error.ExchangeWrong;
    const status = ended.response.trailers.get("grpc-status") orelse return error.ExchangeWrong;
    if (!std.mem.eql(u8, status, "0")) return error.ExchangeWrong;
    finished = true;
    pool.shutdown();
}

/// Starts the connection an `open` event named. The link stands where the socket would be, and is
/// connected from the start.
fn open_socket(open: client.Open) !void {
    if (socket != null) return error.ExchangeWrong;
    socket = open.connection;
    pool.start_tcp(open.connection, program.random(), 0, null) catch return error.ExchangeWrong;
}

fn send_owed(connection: client.ConnectionHandle, now_ns: u64) !void {
    for (0..sends_per_debt_max) |_| {
        const written = pool.send_stream(connection, &output, now_ns);
        try link.send(.client, output[0..written]);
        if (written < output.len) return;
    }
    return error.ExchangeWrong;
}

/// Closes the socket. The server hears the close at its next turn.
fn close_socket(connection: client.ConnectionHandle) void {
    std.debug.assert(std.meta.eql(socket, connection));
    socket = null;
    socket_closed = true;
}

/// Whether the client closed its socket.
pub fn closed() bool {
    return socket_closed;
}

/// Whether the shut-down pool is over.
pub fn over() bool {
    return pool_closed;
}

/// The soonest instant the pool wants `on_instant` at, or null.
pub fn deadline_ns() ?u64 {
    return pool.deadline_ns();
}

/// Whether every reply came back whole and in order, the pool took every piece, and the trailers
/// said the call succeeded.
pub fn check() bool {
    if (finished and received_len == replies.len and taken == piece_ends.len) return true;
    std.debug.print("server_stream_peer: finished {}, taken {d}, received {d} octets\n", .{ finished, taken, received_len });
    return false;
}

/// The octets of the first `count` messages, each a prefix and `before` and a name.
fn messages_len(comptime before: []const u8, count: usize) usize {
    var len: usize = 0;
    for (names[0..count]) |name| len += prefix_len + before.len + name.len;
    return len;
}

/// Each name after `before` as a gRPC message, one after another, at comptime. The flag octet is
/// 0, for no compression.
fn frame_all(comptime before: []const u8) [messages_len(before, names.len)]u8 {
    var all: [messages_len(before, names.len)]u8 = undefined;
    for (names, 0..) |name, index| {
        const message = all[messages_len(before, index)..messages_len(before, index + 1)];
        message[0] = 0;
        std.mem.writeInt(u32, message[1..prefix_len], before.len + name.len, .big);
        @memcpy(message[prefix_len..][0..before.len], before);
        @memcpy(message[prefix_len + before.len ..], name);
    }
    return all;
}
