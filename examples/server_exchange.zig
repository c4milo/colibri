//! Example: a server answers clients over TCP and over QUIC through one `server.Endpoint`.
//!
//! The endpoint holds every connection one thread serves (decision 119): the TCP connections the
//! program accepts, which speak h11 or h2, and the QUIC connections behind one UDP socket, which
//! speak h3. The program calls `accept` for each TCP socket, and the handle it gets names the
//! connection from then on. A QUIC connection starts from a client's first datagram.
//!
//! The server routes each request through a table of `server.router`, which the compiler builds
//! and checks. Its router calls the function of the request's route, and answers 404, 405, 501 and
//! 503 itself.
//!
//! In a turn the server fires the deadlines that passed, then passes the endpoint what each socket
//! read: the octets of a TCP socket under the handle of its connection, and each datagram with the
//! address it came from. Each `receive` reports one event of any connection. The server answers a
//! request by its id, which names the request's connection too, in h11, h2 and h3 alike. It sends
//! what `send_stream` writes for a TCP connection at its `send` event, and every datagram
//! `send_datagram` writes. Then it sleeps until a socket has octets or the endpoint's next
//! deadline passes (decision 110).
//!
//! The server also shows:
//! - `transport_closed`, for a socket whose peer closes it before it sends an octet;
//! - `set_timeouts`, which shortens the idle deadline of the one QUIC connection the endpoint
//!   holds once it has a request, so the server closes it when its client keeps it open;
//! - `h3_alternative`, with which each TLS connection advertises the server's h3 port;
//! - `shutdown`, once both clients are done, and the `closed` event that follows it.
//!
//! Its clients are in `server_peers.zig`: one sends five requests over TCP, and one a GET over
//! QUIC. The links of `link.zig` and `link_datagram.zig` stand where a program's sockets would be,
//! and `tls_program.zig` holds what any program that links `tls` defines once.
//!
//! The program checks what arrived: each client must see 200, the content and its type, octet for
//! octet, for each request that a route names, and 405 with its Allow field or 404 for each other
//! request. The server must see six responses done, one `close`, three connections end, the QUIC
//! one at its idle deadline, and `closed`. Anything else exits with an error, which is how `zig
//! build examples` and CI know the example still works.
//!
//! Run it with `zig build example-server_exchange`, or every example with `zig build examples`.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const tls = @import("tls");
const platform = @import("platform");
const identity = @import("testdata");
const program = @import("tls_program.zig");
const peers = @import("server_peers.zig");
const link_module = @import("link.zig");
const datagram_module = @import("link_datagram.zig");

const Link = link_module.Link;
const DatagramLink = datagram_module.DatagramLink;

/// The octets the server writes for a TCP connection before it sends them, at most.
const output_len = 16384;

/// Turns of the server and its clients before the example gives up.
const turns_max = 256;

/// Events the server takes after one input, and datagrams it reads or writes in one turn, at most.
const events_per_input_max = 64;
const datagrams_per_turn_max = 32;

/// Calls to `send_stream` that one `send` event takes, at most.
const sends_per_event_max = 8;

/// The longest the server sleeps when no octet waits, in nanoseconds: 100 ms.
const wait_ns_max: u64 = 100_000_000;

/// How long the server keeps a connection with no request open, in nanoseconds: 10 s, and 100 ms
/// for a QUIC connection once it has a request.
const idle_ns = 10_000_000_000;
const idle_after_answer_ns = 100_000_000;

/// Requests the server keeps state for, at most.
const requests_max = 7;

const greeting = peers.greeting;
const note = peers.note;
const content_type = peers.content_type;

/// Unix seconds. A program reads them from its clock; colibri reads no clock. The server issues
/// its tickets at this instant.
const now_seconds = identity.now_seconds;

/// The address the QUIC client's datagrams come from, which a program's UDP socket gives.
const loopback = [_]u8{ 127, 0, 0, 1 };
const client_address: server.Address = .of(&loopback, peers.client_port);

pub const Error = error{
    /// The connections had not all ended within `turns_max` turns.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
    /// A connection still owed octets after `sends_per_event_max` calls to `send_stream`.
    SendUnfinished,
};

// The links and the endpoint hold megabytes, so they live outside the stack. The datagram link
// runs on the stream link's loops.
var link: Link align(@alignOf(Link)) = undefined;
var datagram_link: DatagramLink align(@alignOf(DatagramLink)) = undefined;
var output: [output_len]u8 = undefined;
var datagram_output: [datagram_module.datagram_len_max]u8 = undefined;

// The server: its configuration, which holds the TLS identity, and the endpoint that holds its
// connections. colibri's test identity stands in for the certificate and the key a program loads.
/// The TCP and QUIC connections the endpoint holds at once, and the octets each QUIC connection
/// holds unread.
const Endpoint = server.EndpointOf(.{ .tcp_connections = 2, .quic_connections = 1, .receive_pool_len = 64 * 1024 });
const chain = [_][]const u8{ identity.leaf, identity.root };
var cookie_key: [tls.constants.server_key_len]u8 = undefined;
var ticket_key: [tls.constants.server_key_len]u8 = undefined;
var endpoint_config: server.Config align(@alignOf(server.Config)) = undefined;
var endpoint: Endpoint align(@alignOf(Endpoint)) = undefined;
/// The instant the server started at.
var started_ns: u64 = 0;
/// The connection of the socket the TCP client opened, which `accept` named.
var accepted: server.ConnectionHandle align(@alignOf(server.ConnectionHandle)) = undefined;

/// The server's own state, which each route's function gets: here the requests whose head it read,
/// and those whose response is whole.
const App = struct {
    requests: u32 = 0,
    done: u32 = 0,
    /// The responses `Counted` wrapped, and the body bytes the routes wrote through it.
    counted: u32 = 0,
    body_bytes: usize = 0,
};
var app: App align(@alignOf(App)) = .{};

/// The server's table of routes, which the compiler builds and checks. A malformed table, or a
/// table with a conflict, does not compile.
const routes = server.router(App, .{
    .error_handler = on_error,
    .middleware = .{ Brand, Counted },
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .post, "/echo", Echo, .{ .whole_body = true } },
        .{ .get, "/greetings/:name", greet_named },
    },
});

/// The router's pool: an entry for each request at once, with room for its response and for the
/// POST's content. The program places it once and does not move it.
const Router = @TypeOf(routes).Of(.{ .requests = requests_max, .response_bytes = 256, .body_bytes = note.len });
var router: Router align(@alignOf(Router)) = .{};

/// Sockets the endpoint said to close, connections that are over, those that ended at their idle
/// deadline, and whether the shut-down endpoint is over.
var closes: u32 = 0;
var connections_ended: u32 = 0;
var idle_ended: u32 = 0;
var shut: bool = false;
var endpoint_closed: bool = false;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    datagram_link.init(&link.loops);
    // A program probes its CPU once and says what mode its thread runs in, and passes both to every
    // TLS configuration. This one sets no mode, so its sessions run ChaCha20 alone; one whose
    // thread set PSTATE.DIT on arm64 states `.data_independent`.
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    started_ns = link.now_ns(.server);
    try start_server(cpu);
    try peers.init(&link, &datagram_link, cpu);
    try accept_closed();
    for (0..turns_max) |_| {
        try peers.turn();
        try server_turn();
        if (endpoint_closed) return check();
        // No octet and no datagram waits. A program sleeps here until a socket has octets or a
        // deadline passes, whichever comes first.
        if (!link.pending() and !datagram_link.pending()) try link.wait(.server, sleep_ns());
    }
    return error.ExchangeUnfinished;
}

fn start_server(cpu: tls.Cpu) !void {
    // RFC 9846 §4.3.2's cookie key, and the key that seals the tickets of §4.7.1, which a server
    // draws once.
    program.fill(&cookie_key);
    program.fill(&ticket_key);
    endpoint_config = .{
        // The identity names no protocol: the endpoint offers h2 and h11 through ALPN over TCP,
        // as `protocols` allows by default, and names h3 for its QUIC connections.
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
        // Decision 110: timeouts bound how long a peer may hold a connection. The defaults suit a
        // server, and this one ends an idle connection sooner.
        .timeouts = .{ .idle_ns = idle_ns },
        // Each TLS connection advertises h3 on the server's UDP port (RFC 7838).
        .h3_alternative = .{ .port = peers.server_port },
    };
    const now_ns = link.now_ns(.server);
    // One endpoint for every socket the program accepts and for its UDP socket, in storage the
    // program owns. `init` checks that the key signs.
    try endpoint.init(&endpoint_config, program.random(), now_seconds, now_ns);
    // One call for each socket the listener accepts, with whether the socket runs TLS. The handle
    // names the connection in every later call and event. Null says the endpoint starts no
    // connection, and a program then closes the socket.
    accepted = endpoint.accept(.{}, now_ns) orelse return error.ExchangeWrong;
}

/// Accepts a second socket, which its peer closes before it sends an octet, as a port scan does.
/// This example has no link for it: only the calls a program makes for such a socket are here.
fn accept_closed() !void {
    const closed = endpoint.accept(.{}, link.now_ns(.server)) orelse return error.ExchangeWrong;
    // The peer closed the socket first, so the program closes its own end and tells the endpoint.
    // A program calls `transport_closed` then, and when a socket fails. The connection's `ended`
    // follows, with no `close`.
    endpoint.transport_closed(closed);
}

/// One turn of the server: fire the deadlines that passed, pass the endpoint what each socket
/// read, act on every event it reports, and send every datagram it owes.
fn server_turn() !void {
    const input = try link.receive(.server);
    const now_ns = link.now_ns(.server);
    // Decision 110: a deadline bounds how long a peer may hold a connection. `on_instant` ends
    // each connection whose peer is late, at the instant the program woke at, and the `receive`
    // calls below report what that leaves the program to do.
    endpoint.on_instant(now_ns);
    try read_stream(input, now_ns);
    try read_datagrams(now_ns);
    // Both clients are done, so the server stops. `closed` follows once every connection ended.
    if (peers.closed() and !shut) {
        endpoint.shutdown(now_ns);
        shut = true;
    }
    try serve_all(.none, now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = endpoint.send_datagram(&datagram_output, now_ns) orelse break;
        try datagram_link.send(.server, sent.bytes);
    }
}

/// Passes the endpoint the octets the TCP socket read, until it consumes nothing and reports
/// nothing.
fn read_stream(input: []u8, now_ns: u64) !void {
    var consumed: usize = 0;
    for (0..events_per_input_max) |_| {
        // The handle says which connection's socket read the octets.
        const read: server.StreamBytes = .{ .connection = accepted, .bytes = input[consumed..] };
        const received = endpoint.receive(.{ .stream = read }, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try serve(event, now_ns);
    }
    // What an event carried points into the queue, so the queue is consumed only now.
    link.consume(.server, consumed);
}

/// Passes the endpoint each datagram the UDP socket read, with the address it came from. Every
/// call of the turn takes the instant the program woke at, so no call gets an instant earlier than
/// the instant of the call before it.
fn read_datagrams(now_ns: u64) !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try datagram_link.receive(.server) orelse break;
        // The endpoint finds the connection the datagram's connection ID names, or starts one.
        try serve_all(.{ .datagram = .{ .bytes = datagram, .from = client_address } }, now_ns);
        datagram_link.consume(.server);
    }
}

/// Passes `input` to the endpoint, then takes every event it reports until it reports none.
fn serve_all(input: server.Input, now_ns: u64) !void {
    var rest = input;
    for (0..events_per_input_max) |_| {
        const received = endpoint.receive(rest, now_ns);
        rest = .none;
        try serve(received.event orelse return, now_ns);
    }
}

/// Acts on one event of the server. A request is answered by its id, which names the request's
/// connection too, in h11, h2 and h3 alike.
fn serve(event: server.Event, now_ns: u64) !void {
    switch (event) {
        .request => |request| try note_request(request),
        // The request is over. A `sent` result says its response is whole, and colibri reads none
        // of the program's bytes for it again. Over QUIC the client acknowledged every byte of it.
        .finished => |finished| app.done += @intFromBool(finished.result == .sent),
        else => {},
    }
    // The router takes each event of a request: it calls the route's function at the head, passes
    // the body to `Echo`, sends what waits at `writable`, and frees the request's entry at its
    // `finished`. It hands back the events of the connections, which are the program's I/O.
    switch (router.handle(&app, &endpoint, event)) {
        .taken => {},
        .event => |other| switch (other) {
            // A TCP connection owes its socket octets.
            .send => |connection| try flush(connection, now_ns),
            // colibri reads and writes nothing more on this TCP connection. A program closes the
            // socket once the socket has taken the octets `send_stream` returned, and owes the
            // endpoint no call: the connection's `ended` follows by itself.
            .close => closes += 1,
            // The connection is over, and its slot takes a later socket or client.
            .ended => |over| try count_ended(over, now_ns),
            // The shut-down endpoint holds no connection.
            .closed => endpoint_closed = true,
            else => return error.ExchangeWrong,
        },
    }
}

/// Notes a request's head before the router answers it.
fn note_request(request: server.Request) !void {
    std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
    app.requests += 1;
    if (request.version.major == 3) {
        // The endpoint holds one QUIC connection at a time. A client can keep its connection
        // open after the response, so the server shortens its idle deadline, and the slot is
        // free sooner.
        try endpoint.set_timeouts(request.id.connection, .{ .idle_ns = idle_after_answer_ns });
    }
}

/// Answers a GET of `/greeting`. The router passes the request, the path's parameters and the
/// query, here none, and the response's writer. The router ends a response the function leaves
/// open, and `end` adds its Content-Length.
fn greet(_: *App, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", content_type);
    try response.body().writeAll(greeting);
    try response.end();
}

/// Answers a GET of `/greetings/:name` with a greeting to the name, ended with the query's `mark`.
/// The router decodes the name and the query's pairs, and fills each struct by its field names.
fn greet_named(
    _: *App,
    _: *const server.Request,
    path: struct { name: []const u8 },
    query: struct { mark: []const u8 = "" },
    response: *server.ResponseWriter,
) !void {
    try response.header("content-type", content_type);
    try response.body().print("hello, {s}{s}\n", .{ path.name, query.mark });
    try response.end();
}

/// Sends the POST's content back. With `.whole_body`, the router calls `body` once, after the
/// last byte, with a reader over the whole content in the request's entry.
const Echo = struct {
    pub fn on_request(_: *App, _: *void, _: *const server.Request, _: void, _: void, _: *server.ResponseWriter) !void {}

    pub fn on_body(_: *App, _: *void, content: *std.Io.Reader, response: *server.ResponseWriter) !void {
        try response.header("content-type", content_type);
        try response.body().writeAll(content.buffered());
        try response.end();
    }
};

/// A middleware of the route table, which the router calls before each route: it adds a `server`
/// header to each response a route writes. A middleware that answers the request itself, such as
/// with a 401, returns `.answered`, and the router calls no route.
const Brand = struct {
    pub fn on_request(_: *App, _: *const server.Request, response: *server.ResponseWriter) !server.middleware.Next {
        try response.header("server", "colibri");
        return .next;
    }
};

/// A middleware that wraps each response's body writer: it counts the bytes a route writes, and
/// writes them on unchanged. Its `State` lives in the request's pool entry. A middleware that
/// codes a body, such as gzip, wraps the writer the same way, and writes what it owes at the end,
/// such as its last block, in `finish_response`.
const Counted = struct {
    pub const State = struct {
        writer: std.Io.Writer = undefined,
        inner: *std.Io.Writer = undefined,
        bytes: usize = 0,
    };

    pub fn wrap_response(_: *App, state: *State, _: *const server.Request, _: *server.ResponseWriter, inner: *std.Io.Writer) ?*std.Io.Writer {
        state.* = .{ .writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} }, .inner = inner };
        return &state.writer;
    }

    pub fn finish_response(app_state: *App, state: *State) !void {
        app_state.counted += 1;
        app_state.body_bytes += state.bytes;
    }

    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const state: *State = @alignCast(@fieldParentPtr("writer", writer));
        const written = try state.inner.writeSplat(data, splat);
        state.bytes += written;
        return written;
    }
};

/// Chooses the status after a route's error. No route of this server returns one.
fn on_error(_: *App, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = 500;
}

/// Sends what `connection` owes its socket, after its `send` event. A call that fills the buffer
/// leaves more owed, so the program calls again, and a call that leaves room ends the `send`. A
/// program whose socket is full stops here, and calls again when the socket takes more.
fn flush(connection: server.ConnectionHandle, now_ns: u64) !void {
    // This example has one TCP link, so only the connection it carries may owe octets.
    if (connection != accepted) return error.ExchangeWrong;
    for (0..sends_per_event_max) |_| {
        const written = endpoint.send_stream(connection, &output, now_ns);
        try link.send(.server, output[0..written]);
        if (written < output.len) return;
    }
    return error.SendUnfinished;
}

/// Counts a connection that is over. `failed` says colibri closed it because its peer broke a
/// protocol rule or its record layer failed, which does not happen here. `reason` names the
/// deadline or the limit colibri closed it for: here the idle deadline of the QUIC connection
/// alone, which `set_timeouts` shortened, so it passes before `idle_ns` could.
fn count_ended(over: server.Ended, now_ns: u64) !void {
    if (over.failed) return error.ExchangeWrong;
    connections_ended += 1;
    const reason = over.reason orelse return;
    if (now_ns - started_ns >= idle_ns) return error.ExchangeWrong;
    const name = switch (reason) {
        inline else => |value| @tagName(value),
    };
    std.debug.print("server: closed for {s}\n", .{name});
    if (!std.meta.eql(reason, .{ .timeout = .idle })) return error.ExchangeWrong;
    idle_ended += 1;
}

/// How long the server and its clients may sleep: until the soonest deadline of either, and never
/// longer than `wait_ns_max`. `server_turn` then calls `on_instant`.
fn sleep_ns() u64 {
    var wait_ns: u64 = wait_ns_max;
    if (endpoint.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.server));
    }
    if (peers.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.client));
    }
    // A wait of 0 would poll, so the shortest sleep is one nanosecond.
    return @max(wait_ns, 1);
}

/// The sockets the server accepts, the QUIC connection, and the requests the clients send.
const connections_count = 3;
const requests_count = 6;
/// The responses a route wrote, through `Counted`: the greeting over TCP and over QUIC, the note,
/// and the greeting to a name. The router answers the other two itself.
const routed_count = 4;
const routed_bytes = 2 * greeting.len + note.len + peers.named_greeting.len;

/// The clients saw what the server sent. The server saw each response done, one `close`, and
/// every connection end, the QUIC one at its idle deadline.
fn check() Error!void {
    const answered = app.requests == requests_count and app.done == requests_count and
        app.counted == routed_count and app.body_bytes == routed_bytes;
    const over = closes == 1 and connections_ended == connections_count and idle_ended == 1;
    if (peers.check() and answered and over) {
        std.debug.print("server_exchange: every octet arrived as sent\n", .{});
        return;
    }
    std.debug.print("server_exchange: requests {d}, done {d}, counted {d}, bytes {d}, closes {d}, ended {d}, idle {d}\n", .{
        app.requests, app.done, app.counted, app.body_bytes, closes, connections_ended, idle_ended,
    });
    return error.ExchangeWrong;
}
