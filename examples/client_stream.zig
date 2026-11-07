//! Example: a client streams a gRPC-shaped call both ways through a pool, over h2 in cleartext.
//!
//! A streamed exchange sends its request body in pieces and reads its response body in pieces
//! (decision 153). The pool copies no piece. The program keeps each request piece in place until
//! the pool reports it taken, and each response piece arrives in the program's own `body`, which
//! the program gives back before the next one arrives. The call is a chat of gRPC messages: each
//! message is a frame of one flag octet, a length of four octets and its payload (gRPC's "Length-
//! Prefixed-Message").
//!
//! The run goes in this order:
//! 1. The program requests the POST with both bodies streamed, and hands it the first message.
//! 2. The server answers at the request's head. The pool reports `headers`, and then `body_taken`
//!    once the connection has written the message.
//! 3. The server sends back each message as it arrives. Each `body` event says how much of it is
//!    in the program's `body`, which holds 16 octets. The program copies the piece out and
//!    releases it.
//! 4. Once a message came back whole, the program hands the next, so its request body goes on
//!    after the response's head (RFC 9113 §8.1). The last message ends the request's body, and
//!    the request's trailer section follows it (decision 152).
//! 5. The server ends the response with `grpc-status` in its trailers. The pool reports
//!    `finished`, and the program calls `shutdown`.
//!
//! The server is in `client_stream_peer.zig`. The link of `link.zig` stands where a program's
//! socket would be, and `tls_program.zig` holds what any program that links `tls` defines once.
//!
//! The program checks that each message came back octet for octet, in the order sent, and the
//! trailer. Anything else exits with an error, which is how `zig build examples` and CI know the
//! example still works.
//!
//! Run it with `zig build example-client_stream`, or every example with `zig build examples`.
const std = @import("std");
const client = @import("client");
const program = @import("tls_program.zig");
const peer = @import("client_stream_peer.zig");
const link_module = @import("link.zig");

const Link = link_module.Link;

/// Turns of the client and the server before the example gives up.
const turns_max = 256;

/// The longest either side sleeps when nothing waits, in nanoseconds: 100 ms.
const wait_ns_max: u64 = 100_000_000;

/// Calls of `send_stream` for one `send`, at most: one turn's frames fit in one output.
const sends_per_debt_max = 4;

/// The origin, and its port: 80 for "http" (RFC 9110 §4.2.1).
const origin = "localhost";
const server_port = 80;
const server_host = [_]u8{ 192, 0, 2, 1 };
const server_addresses = [_]client.Address{.of(&server_host, 0)};

/// The octets of the response body the program holds at a time: fewer than a message, so a
/// message comes back in more than one piece.
const piece_len = 16;
/// The octets of the response's headers, and of its trailers, the program holds.
const section_len = 256;

/// The messages of the chat, each sent as a gRPC frame: a flag octet of 0, for no compression,
/// the payload's length in four octets, most significant first, and the payload.
const payloads = [_][]const u8{ "hello from the client", "a second message", "and the last one, which ends the call" };
const frame_header_len = 1 + @sizeOf(u32);
/// The frames one after another: what the client sends, and what the server sends back.
const chat = frame_all();

pub const Error = error{
    /// The pool was not closed within `turns_max` turns.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
};

// The pool speaks h2 with prior knowledge over TCP alone (decision 117), so it holds no QUIC state
// (decision 124).
const ConnectionPool = client.ConnectionPool(.{ .quic = false });
var pool: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
var pool_memory: [ConnectionPool.memory_bytes(.{})]u8 align(ConnectionPool.memory_alignment) = undefined;
var client_config: client.Config align(@alignOf(client.Config)) = .{
    .authority = origin,
    .protocols = .{ .h11 = false, .h3 = false },
};

var link: Link align(@alignOf(Link)) = undefined;
/// What `send_stream` writes, which the link then sends.
var output: [client.constants.limits.stream_output_len_min]u8 = undefined;

/// Calls of `receive` for one read of the socket, at most. Each call takes one octet or more of
/// the link's queue, or reports an event and takes no octet, or ends the loop.
const receive_calls_max = (link_module.queue_len_max + 1) * (ConnectionPool.receive_events_without_input_max(.{}) + 1);

/// The call. Both of its bodies go in pieces, so `body` is empty and the response's `body` holds
/// one piece at a time. Its trailer section goes after the last piece, and says how many messages
/// the call sent.
const call: client.Request = .{
    .method = "POST",
    .path = peer.path,
    .headers = &.{.{ .name = "content-type", .value = peer.content_type }},
    .streamed = .{ .request = true, .response = true },
    .trailers = &.{.{ .name = peer.count_trailer, .value = peer.count_value }},
};
var piece: [piece_len]u8 = undefined;
var header_buffer: [section_len]u8 = undefined;
var trailer_buffer: [section_len]u8 = undefined;
var response: client.Response align(@alignOf(client.Response)) = .{
    .body = &piece,
    .headers = .{ .buffer = &header_buffer },
    .trailers = .{ .buffer = &trailer_buffer },
};
var call_id: client.RequestId align(@alignOf(client.RequestId)) = 0;

/// The connection of the socket, once the pool opened it.
var socket: ?client.ConnectionHandle align(@alignOf(client.ConnectionHandle)) = null;

/// What the client saw: the messages it handed and the pool took, the octets of the response
/// body, and whether the call finished and the shut-down pool is over.
var handed: u32 = 0;
var taken: u32 = 0;
var heard_headers: bool = false;
var received: [chat.len]u8 = undefined;
var received_len: usize = 0;
var finished: bool = false;
var pool_closed: bool = false;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    try peer.init(&link);
    const known: client.Destination = .{ .addresses = &server_addresses, .port = server_port };
    try pool.init(&pool_memory, &client_config, known, null);
    call_id = try pool.request(&call, &response);
    try hand_next();
    for (0..turns_max) |_| {
        try client_turn();
        try peer.turn();
        if (pool_closed and peer.over()) return check();
        // No octet waits for either side. A program sleeps here until the socket has octets or a
        // deadline passes, whichever comes first.
        if (!link.pending()) try link.wait(.client, sleep_ns());
    }
    return error.ExchangeUnfinished;
}

/// Hands the pool the next message, once the one before was taken and came back whole: the pool
/// holds one piece of a request at a time.
fn hand_next() !void {
    if (handed == payloads.len or taken < handed) return;
    if (received_len < end_of(handed)) return;
    const last = handed + 1 == payloads.len;
    // The pool copies none of the message: `chat` stays in place until its `body_taken`.
    try pool.write_body(call_id, chat[end_of(handed)..end_of(handed + 1)], last);
    handed += 1;
}

/// The octets of the chat before message `index`.
fn end_of(index: usize) usize {
    var len: usize = 0;
    for (payloads[0..index]) |payload| len += frame_header_len + payload.len;
    return len;
}

/// One turn of the client: pass the pool what the socket read, until it consumes nothing and
/// reports nothing. With no socket it passes `.none`, which reports what the pool owes.
fn client_turn() !void {
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
        // The response's status and headers arrived, before any of its body.
        .headers => |id| try on_headers(id),
        // The connection reads the message no more: its memory is the program's again.
        .body_taken => |id| {
            if (id != call_id) return error.ExchangeWrong;
            taken += 1;
            try hand_next();
        },
        // `body` holds a piece of the response, which `on_piece` copies out and releases.
        .body => |held| try on_piece(held),
        .finished => |ended| try on_finished(ended),
        // A pool in cleartext gets no ticket.
        .ticket => return error.ExchangeWrong,
        // The shut-down pool is over: the call ended and the connection closed.
        .closed => pool_closed = true,
    }
}

/// The response's head arrived. `get` reads the first header of a name, and an iterator walks
/// each header in the order it arrived.
fn on_headers(id: client.RequestId) !void {
    if (id != call_id or response.status != .ok) return error.ExchangeWrong;
    const kind = response.headers.get("content-type") orelse "";
    if (!std.mem.eql(u8, kind, peer.content_type)) return error.ExchangeWrong;
    var lines: client.Headers.Iterator = response.headers.iterator();
    var content_types: usize = 0;
    // Bounded: each header takes octets of the buffer, which holds `section_len`.
    for (0..section_len) |_| {
        const line = lines.next() orelse break;
        if (std.ascii.eqlIgnoreCase(line.name, "content-type")) content_types += 1;
    }
    if (content_types != 1) return error.ExchangeWrong;
    heard_headers = true;
}

/// `body` holds a piece of the response. The program copies it out and releases it, and the
/// pool reads no more of the response until then.
fn on_piece(held: client.Event.Piece) !void {
    if (held.id != call_id or !heard_headers) return error.ExchangeWrong;
    if (received_len + held.len > received.len) return error.ExchangeWrong;
    @memcpy(received[received_len..][0..held.len], response.body[0..held.len]);
    received_len += held.len;
    pool.release_body(held.id);
    try hand_next();
}

/// The call ended: every message came back, and the trailers say it succeeded.
fn on_finished(ended: client.Finished) !void {
    if (ended.response.result != .response) return error.ExchangeWrong;
    const status = ended.response.trailers.get("grpc-status") orelse return error.ExchangeWrong;
    if (!std.mem.eql(u8, status, "0")) return error.ExchangeWrong;
    finished = true;
    pool.shutdown();
}

/// Connects the socket for the connection an `open` event named, and starts the connection on it.
fn open_socket(open: client.Open) !void {
    if (socket != null) return error.ExchangeWrong;
    socket = open.connection;
    // The link stands where the socket would be: the server's listener accepts it.
    try peer.accept();
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

/// Closes the socket: the server hears the close.
fn close_socket(connection: client.ConnectionHandle) void {
    std.debug.assert(std.meta.eql(socket, connection));
    peer.closed();
    socket = null;
}

/// How long both sides may sleep: until the server's next deadline, and never longer than
/// `wait_ns_max`. A pool with TCP alone has no deadline of its own.
fn sleep_ns() u64 {
    var wait_ns: u64 = wait_ns_max;
    if (peer.deadline_ns()) |deadline_ns| wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.server));
    // A wait of 0 would poll, so the shortest sleep is one nanosecond.
    return @max(wait_ns, 1);
}

/// Every message came back whole and in order, and the server read each one.
fn check() Error!void {
    const whole = std.mem.eql(u8, received[0..received_len], &chat);
    if (finished and whole and taken == payloads.len and peer.check(&chat)) {
        std.debug.print("client_stream: every message came back as sent\n", .{});
        return;
    }
    std.debug.print("client_stream: finished {}, taken {d}, received {d} octets\n", .{ finished, taken, received_len });
    return error.ExchangeWrong;
}

/// Each payload as a gRPC frame, one after another, at comptime.
fn frame_all() [end_of(payloads.len)]u8 {
    var all: [end_of(payloads.len)]u8 = undefined;
    for (payloads, 0..) |payload, index| {
        const frame = all[end_of(index)..end_of(index + 1)];
        frame[0] = 0;
        std.mem.writeInt(u32, frame[1..frame_header_len], payload.len, .big);
        @memcpy(frame[frame_header_len..], payload);
    }
    return all;
}
