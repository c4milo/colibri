//! Example: a server answers a gRPC-shaped call through a stream route of `server.Router`, over h2
//! in cleartext.
//!
//! A route of a route table is a function or a struct. A struct route is a stream (decision 163
//! ruling 6). Its `on_request` runs at the request's head, its `on_data` at each event of the
//! request's body, and its `on_finished` once the request is over. `on_request` and `on_data`
//! write the request's one `server.Response`, so the route can answer while the client still sends.
//!
//! The call is a chat of gRPC messages. Each message is a flag octet, the payload's length in four
//! octets, most significant first, and the payload (gRPC's "Length-Prefixed-Message"). Each
//! message of the client carries a name. The route answers each one with a message of its own,
//! which greets the name.
//!
//! The run goes in this order:
//! 1. The client sends the POST's head and the first piece of its body: the first message and the
//!    first octets of the second.
//! 2. `on_request` adds the response's content type. The head goes out with the first reply.
//! 3. `on_data` gets the piece with `next`, reads the first message, and writes and flushes its
//!    reply. So the reply goes out before the request's body ends. `keep` leaves the cut second
//!    message unread.
//! 4. The client hands its next piece only once each reply it waits for came back. The next `next`
//!    gives the kept octets joined with the new ones, and the route answers the second message.
//! 5. The last piece holds the third message and ends the body. Once `ended` is true, the route
//!    ends its response with `grpc-status` in its trailer section.
//! 6. `on_finished` counts the call. The client closes its socket, and the connection ends.
//!
//! The route declares no `next`, the callback that writes what did not fit the response's memory.
//! A TCP connection copies each reply into its own output when it takes it, so the memory is free
//! again at once. Here each reply is small, the client's window takes it whole, and so each reply
//! fits. A route whose replies can wait for room keeps what it owes in its `State`, and writes it
//! in `next`. Over h3, for example, the connection reads a reply in place until the peer
//! acknowledges it.
//!
//! The client is in `server_stream_peer.zig`. The link of `link.zig` stands where a program's
//! socket would be, and `tls_program.zig` holds what any program that links `tls` defines once.
//!
//! The program checks what arrived. The client must get each reply octet for octet, each one only
//! after its message was whole, and `grpc-status` 0 in the trailers. The route must read every
//! message, the response must go whole, and the connection must end. Anything else exits with an
//! error, which is how `zig build examples` and CI know the example still works.
//!
//! Run it with `zig build example-server_stream`, or every example with `zig build examples`.
const std = @import("std");
const colibri = @import("colibri");
const server = colibri.server;
const program = @import("tls_program.zig");
const peer = @import("server_stream_peer.zig");
const link_module = @import("link.zig");

const Link = link_module.Link;

/// Turns of the client and the server before the example gives up.
const turns_max = 256;

/// The longest either side sleeps when nothing waits, in nanoseconds: 100 ms.
const wait_ns_max: u64 = 100_000_000;

/// The octets the server writes before it sends them, at most.
const output_len = 16384;

/// Events the server takes in one turn, and calls to `send_stream` one `send` event takes, at most.
const events_per_turn_max = 64;
const sends_per_event_max = 4;

/// The longest payload the route reads: a name of 64 octets. A message whose prefix names a longer
/// one ends the call with an error.
const payload_len_max = 64;
/// The octets of the longest reply: a prefix, `greeting` and the longest name.
const reply_len_max = peer.prefix_len + peer.greeting.len + payload_len_max;

/// Pieces one `on_data` takes, at most. With no middleware's wrapper, the first `next` gives every
/// octet that has arrived in one piece, and the second returns null.
const pieces_per_event_max = 4;

/// Requests the router answers at once: the one call.
const requests_max = 1;
/// Octets of the entry's response memory: the copies of the header and of the trailer, and the
/// replies that the connection has not taken.
const response_bytes = 256;
/// Octets of the entry's body memory: what `keep` left unread between two body events, joined with
/// the octets of the next event. Octets past it get 413 (RFC 9110 §15.5.14).
const body_bytes = 256;
/// Octets of the entry's copy of a request's header. The one route is a stream route, which reads
/// the header in `on_request` at the head, so the router copies no header.
const header_bytes = 0;

pub const Error = error{
    /// The connection had not ended within `turns_max` turns.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
    /// The connection still owed octets after `sends_per_event_max` calls to `send_stream`.
    SendUnfinished,
};

/// One TCP connection, and no QUIC connection.
const Engine = server.Engine(.{ .tcp_connections = 1, .quic_connections = 0 });

// The link and the engine hold hundreds of kilobytes, so they live outside the stack.
var link: Link align(@alignOf(Link)) = undefined;
var output: [output_len]u8 = undefined;
var engine_config: server.Config align(@alignOf(server.Config)) = undefined;
var engine: Engine align(@alignOf(Engine)) = undefined;
/// The connection of the socket the client connected, until the client closes it.
var accepted: ?server.ConnectionHandle align(@alignOf(server.ConnectionHandle)) = null;
/// Connections that are over.
var ended: u32 = 0;

/// The server's own state, which each callback gets: the messages the route answered, and the
/// calls whose response went whole.
const App = struct {
    messages: u32 = 0,
    sent: u32 = 0,
};
var app: App align(@alignOf(App)) = .{};

/// The route table: one stream route, the gRPC method. The router answers any other request
/// with 404, 405 or 501 itself.
const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .post, peer.path, Greeter },
    },
};

const Router = server.Router(App, routes, .{ .requests = requests_max, .response_bytes = response_bytes, .body_bytes = body_bytes, .header_bytes = header_bytes });
var router: Router align(@alignOf(Router)) = undefined;

/// The trailer section that ends the call: gRPC's status 0 says the call succeeded.
const grpc_ok = [_]server.Header{.{ .name = "grpc-status", .value = "0" }};

/// The stream route of the gRPC method. A struct route has `on_request`, and any of `on_data`,
/// `next` and `on_finished`. Its `State` lives in the request's pool entry.
const Greeter = struct {
    /// What the route holds for one call: the messages it answered, and the octets of the cut
    /// message it left unread with `keep`.
    pub const State = struct {
        messages: u32 = 0,
        kept: usize = 0,
    };

    /// Runs at the request's head, before any octet of its body arrives. The head goes out with
    /// the first bytes of the body.
    pub fn on_request(_: *App, _: *server.RequestContext, _: *State, _: *const server.Request, response: *server.Response) !void {
        try response.header("content-type", peer.content_type);
    }

    /// Runs at each event of the request's body. It answers each message that a piece holds
    /// whole, and keeps the cut message at the end of the piece: the next `next` gives its octets
    /// again, joined with the octets that arrive later. Once the body ended, it ends the response.
    pub fn on_data(_: *App, _: *server.RequestContext, state: *State, body: *server.RequestBodyStream, response: *server.Response) !void {
        // Bounded: each pass takes one piece.
        for (0..pieces_per_event_max) |_| {
            const piece = body.next() orelse break;
            const cut = try answer_whole(state, piece, response);
            state.kept = cut.len;
            body.keep(state.kept);
        }
        if (!body.ended()) return;
        // A body that ends inside a message cuts it short: the last piece held its octets again.
        if (state.kept > 0) return error.MessageCut;
        // RFC 9113 §8.1: a HEADERS frame after the DATA frames carries the trailer section.
        try response.trailers(&grpc_ok);
    }

    /// Runs once the request is over. A `sent` result says the response went whole.
    pub fn on_finished(app_state: *App, _: *server.RequestContext, state: *State, result: server.Result) void {
        app_state.messages += state.messages;
        app_state.sent += @intFromBool(result == .sent);
    }
};

/// Answers each whole message at the start of `piece`, and returns the octets after them: the
/// first octets of a cut message, or none.
fn answer_whole(state: *Greeter.State, piece: []const u8, response: *server.Response) ![]const u8 {
    var rest = piece;
    // Bounded: each pass takes one message, of `prefix_len` octets at least.
    for (0..piece.len / peer.prefix_len + 1) |_| {
        if (rest.len < peer.prefix_len) break;
        const len = std.mem.readInt(u32, rest[1..peer.prefix_len], .big);
        // The route reads no compressed message, and no payload past `payload_len_max`.
        if (rest[0] != 0 or len > payload_len_max) return error.MessageRefused;
        if (rest.len < peer.prefix_len + len) break;
        try reply(rest[peer.prefix_len..][0..len], response);
        state.messages += 1;
        rest = rest[peer.prefix_len + len ..];
    }
    return rest;
}

/// Writes the reply to one message: a message whose payload greets `name`. One `writeAll` of one
/// slice goes into the response's memory whole or not at all, so the reply is built first. The
/// `flush` sends it now, before the request's body ends.
fn reply(name: []const u8, response: *server.Response) !void {
    var message: [reply_len_max]u8 = undefined;
    const payload_len = peer.greeting.len + name.len;
    // The flag octet: the payload is not compressed.
    message[0] = 0;
    std.mem.writeInt(u32, message[1..peer.prefix_len], @intCast(payload_len), .big);
    @memcpy(message[peer.prefix_len..][0..peer.greeting.len], peer.greeting);
    @memcpy(message[peer.prefix_len + peer.greeting.len ..][0..name.len], name);
    const writer = response.body();
    try writer.writeAll(message[0 .. peer.prefix_len + payload_len]);
    try writer.flush();
}

/// Chooses the status after a route's error, before the head went out. After the head, the router
/// cancels the request instead.
fn on_error(_: *App, _: *server.RequestContext, _: *const server.Request, _: anyerror, response: *server.Response) void {
    response.status = .internal_server_error;
}

pub fn main() !void {
    try link.init();
    defer link.deinit();
    const now_ns = link.now_ns(.server);
    // Each value has its default but the CPU features, which the program asks of its CPU once.
    engine_config = .{ .cpu_features = .detect() };
    // Cleartext needs no Unix time: no certificate is judged and no ticket is issued.
    try engine.init(&engine_config, program.random(), .{ .unix_seconds = 0, .monotonic_ns = now_ns });
    router.init();
    // The listener accepts the socket the client connects. The link stands where the socket would
    // be, so it is connected from the start.
    accepted = engine.accept(.{ .tls = false }, now_ns) orelse return error.ExchangeWrong;
    try peer.init(&link);
    for (0..turns_max) |_| {
        try peer.turn();
        try server_turn();
        if (peer.over() and ended == 1) return check();
        // No octet waits for either side. A program sleeps here until the socket has octets or a
        // deadline passes, whichever comes first.
        if (!link.pending()) try link.wait(.server, sleep_ns());
    }
    return error.ExchangeUnfinished;
}

/// One turn of the server: fire its deadlines, pass the engine what the socket read, and act on
/// every event it reports. Then a socket the client closed reads nothing more.
fn server_turn() !void {
    const input = try link.receive(.server);
    const now_ns = link.now_ns(.server);
    engine.on_instant(now_ns);
    var consumed: usize = 0;
    if (accepted) |connection| consumed = try read_stream(connection, input, now_ns);
    link.consume(.server, consumed);
    if (peer.closed() and accepted != null) {
        // The client closed its socket. The program closes its own end and tells the engine, and
        // the connection's `ended` follows.
        engine.transport_closed(accepted.?);
        accepted = null;
    }
    // With no input, `receive` reports what the engine owes.
    for (0..events_per_turn_max) |_| {
        const received = engine.receive(.none, now_ns);
        try serve(received.event orelse return, now_ns);
    }
}

/// Passes the engine the octets the socket read, until it consumes nothing and reports nothing.
/// It returns how many octets the engine consumed.
fn read_stream(connection: server.ConnectionHandle, input: []u8, now_ns: u64) !usize {
    var consumed: usize = 0;
    for (0..events_per_turn_max) |_| {
        const read: server.StreamBytes = .{ .connection = connection, .bytes = input[consumed..] };
        const received = engine.receive(.{ .stream = read }, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try serve(event, now_ns);
    }
    return consumed;
}

/// Acts on one event of the server. The router takes each event of a request, calls the route's
/// callbacks, and hands back the events of the connection.
fn serve(event: server.Event, now_ns: u64) !void {
    switch (router.handle(&app, &engine, event)) {
        .taken => {},
        .event => |other| switch (other) {
            .send => |connection| try flush(connection, now_ns),
            .ended => |over| {
                if (over.failed) return error.ExchangeWrong;
                ended += 1;
            },
            // The client closes its socket first, so the server never says `close`. It reads
            // each request whole, so it never closes in stages (decision 160).
            else => return error.ExchangeWrong,
        },
    }
}

/// Sends what the connection owes its socket, after its `send` event.
fn flush(connection: server.ConnectionHandle, now_ns: u64) !void {
    if (accepted == null or connection != accepted.?) return error.ExchangeWrong;
    for (0..sends_per_event_max) |_| {
        const written = engine.send_stream(connection, &output, now_ns);
        try link.send(.server, output[0..written]);
        if (written < output.len) return;
    }
    return error.SendUnfinished;
}

/// How long both sides may sleep: until the soonest deadline of either, and never longer than
/// `wait_ns_max`.
fn sleep_ns() u64 {
    var wait_ns: u64 = wait_ns_max;
    if (engine.deadline_ns()) |deadline_ns| wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.server));
    if (peer.deadline_ns()) |deadline_ns| wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.client));
    // A wait of 0 would poll, so the shortest sleep is one nanosecond.
    return @max(wait_ns, 1);
}

/// The client got every reply as the route wrote it, the route answered every message, the
/// response went whole, and the connection ended.
fn check() Error!void {
    if (peer.check() and app.messages == peer.names.len and app.sent == 1 and ended == 1) {
        std.debug.print("server_stream: every reply arrived as the route wrote it\n", .{});
        return;
    }
    std.debug.print("server_stream: messages {d}, sent {d}, ended {d}\n", .{ app.messages, app.sent, ended });
    return error.ExchangeWrong;
}
