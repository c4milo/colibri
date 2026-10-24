//! The two clients of `server_exchange.zig`. This file is not an example by itself: it holds what
//! the server example runs against.
//!
//! Each peer is one `client.ConnectionPool`:
//! - the TCP peer holds no receive pool, so its pool opens TCP alone, and ALPN picks h2. It
//!   sends five requests: a GET and a POST that each match a route, a GET whose path holds a
//!   parameter, a POST to a path whose route names GET alone, and a GET of a path that no route
//!   names. It shuts its pool down when all five have finished;
//! - the QUIC peer holds a receive pool and speaks h3 alone, so its pool opens QUIC alone
//!   (decision 120). It sends a GET, and keeps its connection open after the response, as a client
//!   that can ask again does. The server closes the connection when its idle deadline passes, and
//!   the peer then shuts its pool down.
//!
//! The TCP peer runs over the stream link and the QUIC peer over the datagram link, on the client's
//! loop. `docs/usage.md` shows the client's calls with the client example, so the comments here
//! are short.
const std = @import("std");
const client = @import("client");
const tls = @import("tls");
const identity = @import("testdata");
const program = @import("tls_program.zig");
const link_module = @import("link.zig");
const datagram_module = @import("link_datagram.zig");

const Link = link_module.Link;
const DatagramLink = datagram_module.DatagramLink;

pub const greeting = "hello from colibri\n";
pub const note = "a note the client posts, which the server sends back\n";
pub const content_type = "text/plain; charset=utf-8";

/// The name the TCP peer asks the server to greet, and the greeting it must get back.
const name = "colibri";
const named_greeting = "hello, " ++ name ++ "\n";

/// The Allow value of the path "/greeting", whose one route names GET. A HEAD request finds a GET
/// route, so the value lists HEAD after GET.
const greeting_allow = "GET, HEAD";

/// The server's port, for TCP and for UDP: the port of an "https" origin (RFC 9110 §4.2.2). The
/// TCP connections advertise h3 on this UDP port.
pub const server_port = 443;

/// The UDP port the QUIC peer sends from.
pub const client_port = 50_000;

/// The name the server's certificate carries, which each peer asks for and judges it by.
const origin = "localhost";

/// Unix seconds, at which the test identity is valid. A program reads them from its clock.
const now_seconds = identity.now_seconds;

const loopback = [_]u8{ 127, 0, 0, 1 };
const server_addresses = [_]client.Address{.of(&loopback, 0)};
const server_address: client.Address = .of(&loopback, server_port);

/// The octets the TCP peer writes before it sends them, at most.
const output_len = 16384;

/// Events a peer takes after one input, and datagrams it reads or writes in one turn, at most.
const events_per_input_max = 64;
const datagrams_per_turn_max = 32;

/// Requests one peer makes, at most.
const requests_max = 5;

/// One request a peer makes, its response, and the memory the response goes into.
const Asked = struct {
    request: client.Request,
    response: client.Response,
    /// The content type of a 200, and the Allow value of a 405.
    wanted: [2]client.WantedHeader,
    values: [content_type.len + greeting_allow.len]u8,
    body: [note.len]u8,

    /// Fills the request and the response. `content` is the request's content, or empty for none.
    fn place(asked: *Asked, method: []const u8, path: []const u8, content: []const u8) void {
        asked.wanted = .{ .{ .name = "content-type" }, .{ .name = "allow" } };
        asked.request = .{ .method = method, .path = path };
        asked.response = .{ .wanted = &asked.wanted, .values = &asked.values, .body = &asked.body };
        if (content.len == 0) return;
        asked.request.headers = &.{.{ .name = "content-type", .value = content_type }};
        asked.request.body = content;
    }

    /// Whether the exchange ended in a 200 response with `content` and the content type.
    fn arrived(asked: *const Asked, content: []const u8) bool {
        const response = &asked.response;
        if (response.result != .response or response.status != 200) return false;
        if (!std.mem.eql(u8, asked.wanted[0].value orelse "", content_type)) return false;
        return std.mem.eql(u8, response.body_received(), content);
    }

    /// Whether the exchange ended in a response with `status` and no content, whose Allow value
    /// is `allow`, or which has no Allow field when `allow` is null.
    fn refused(asked: *const Asked, status: u16, allow: ?[]const u8) bool {
        const response = &asked.response;
        if (response.result != .response or response.status != status) return false;
        if (response.body_received().len != 0) return false;
        const held = asked.wanted[1].value orelse return allow == null;
        return std.mem.eql(u8, held, allow orelse return false);
    }
};

/// One client: its configuration, its pool, and what it saw.
const Peer = struct {
    config: client.Config,
    pool: client.ConnectionPool,
    pool_memory: [client.ConnectionPool.memory_bytes(.{})]u8 align(client.ConnectionPool.memory_alignment),
    /// The connection the pool's last `open` named (decision 125).
    connection: client.ConnectionHandle,
    asked: [requests_max]Asked,
    asked_count: u32,
    /// Whether the peer keeps its connection open after its exchanges finished.
    keeps: bool,
    finished: u32,
    spoken: ?client.Protocol,
    /// Transports the pool opened, transports it said to close, and tickets it took.
    opens: u32,
    closes: u32,
    tickets: u32,
    /// The shut-down pool is over.
    closed: bool,

    /// Places one request: `content` is its content, or empty for none.
    fn ask(peer: *Peer, method: []const u8, path: []const u8, content: []const u8) !void {
        const asked = &peer.asked[peer.asked_count];
        asked.place(method, path, content);
        peer.asked_count += 1;
        _ = try peer.pool.request(&asked.request, &asked.response);
    }
};

// The links belong to the example, and each peer holds hundreds of kilobytes, so they live outside
// the stack.
var stream_link: *Link = undefined;
var datagram_link: *DatagramLink = undefined;
var tcp_peer: Peer align(@alignOf(Peer)) = undefined;
var quic_peer: Peer align(@alignOf(Peer)) = undefined;
const ReceivePool = client.ReceivePool(64 * 1024);
var receive_pool: ReceivePool align(@alignOf(ReceivePool)) = undefined;
var stream_output: [output_len]u8 = undefined;
var datagram_output: [datagram_module.datagram_len_max]u8 = undefined;
const anchors = [_]tls.Anchor{.{ .subject = identity.root_name, .spki = identity.root_spki }};

/// Starts both peers on the links the example holds, and places their requests.
pub fn init(stream: *Link, datagrams: *DatagramLink, cpu: tls.Cpu) !void {
    stream_link = stream;
    datagram_link = datagrams;
    const known: client.Destination = .{ .addresses = &server_addresses, .port = server_port };
    start(&tcp_peer, cpu, .{}, false);
    // No receive pool: the pool opens TCP alone.
    try tcp_peer.pool.init(&tcp_peer.pool_memory, &tcp_peer.config, known, null);
    try tcp_peer.ask("GET", "/greeting", "");
    try tcp_peer.ask("POST", "/echo", note);
    try tcp_peer.ask("GET", "/greetings/" ++ name, "");
    // The route of "/greeting" names GET alone, so a POST gets 405.
    try tcp_peer.ask("POST", "/greeting", "");
    // A parameter matches one segment, so no route names this path.
    try tcp_peer.ask("GET", "/greetings", "");
    // h3 alone: the pool opens QUIC alone, and needs the receive pool for it.
    start(&quic_peer, cpu, .{ .h11 = false, .h2 = false }, true);
    try quic_peer.pool.init(&quic_peer.pool_memory, &quic_peer.config, known, receive_pool.storage());
    try quic_peer.ask("GET", "/greeting", "");
}

fn start(peer: *Peer, cpu: tls.Cpu, protocols: client.Protocols, keeps: bool) void {
    peer.config = .{
        .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .cpu = cpu },
        .protocols = protocols,
        .authority = origin,
    };
    peer.asked_count = 0;
    peer.keeps = keeps;
    peer.finished = 0;
    peer.spoken = null;
    peer.opens = 0;
    peer.closes = 0;
    peer.tickets = 0;
    peer.closed = false;
    peer.connection = .{ .slot = 0, .generation = 0 };
}

/// One turn of both peers: each reads what arrived, fires its deadlines, and sends what it owes.
pub fn turn() !void {
    try tcp_turn();
    try quic_turn();
}

fn tcp_turn() !void {
    const now_ns = stream_link.now_ns(.client);
    try drain_stream(now_ns);
    try stream_link.send(.client, stream_output[0..tcp_peer.pool.send_stream(tcp_peer.connection, &stream_output, now_ns)]);
    try drain_stream(now_ns);
}

/// Passes the TCP peer's pool the octets the stream link holds, until it consumes nothing and
/// reports nothing. At a `close`, the peer drops the octets it holds.
fn drain_stream(now_ns: u64) !void {
    const input = try stream_link.receive(.client);
    var consumed: usize = 0;
    for (0..events_per_input_max) |_| {
        const held = input[consumed..];
        const read: client.Input = if (held.len > 0) .{ .stream = .{ .connection = tcp_peer.connection, .bytes = held } } else .none;
        const received = tcp_peer.pool.receive(read, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        report(&tcp_peer, event, now_ns);
        if (event == .close) consumed = input.len;
    }
    stream_link.consume(.client, consumed);
}

fn quic_turn() !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try datagram_link.receive(.client) orelse break;
        drain_datagram(.{ .datagram = .{ .bytes = datagram, .from = server_address } }, datagram_link.now_ns(.client));
        datagram_link.consume(.client);
    }
    const now_ns = datagram_link.now_ns(.client);
    quic_peer.pool.on_instant(now_ns);
    drain_datagram(.none, now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = quic_peer.pool.send_datagram(&datagram_output, now_ns) orelse break;
        try datagram_link.send(.client, sent.bytes);
        drain_datagram(.none, now_ns);
    }
}

/// Passes the QUIC peer's pool `input`, then reads it with `.none` until it reports nothing.
fn drain_datagram(input: client.Input, now_ns: u64) void {
    var rest = input;
    for (0..events_per_input_max) |_| {
        const received = quic_peer.pool.receive(rest, now_ns);
        if (received.consumed > 0) rest = .none;
        const event = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        report(&quic_peer, event, now_ns);
    }
}

/// Acts on one event of a peer's pool.
fn report(peer: *Peer, event: client.Event, now_ns: u64) void {
    switch (event) {
        .open => |open| open_transport(peer, open, now_ns),
        // `tcp_turn` writes what the TCP connection owes at each turn.
        .send => {},
        .close => {
            peer.closes += 1;
            // The server closed a connection the peer kept, and every exchange has ended.
            if (peer.finished == peer.asked_count) peer.pool.shutdown();
        },
        .connected => |connected| peer.spoken = connected.protocol,
        .finished => |ended| finish(peer, ended),
        // These peers open no second connection, so each wipes the ticket the server gives it.
        .ticket => |connection| if (peer.pool.take_ticket(connection)) |ticket| {
            var held = ticket;
            held.wipe();
            peer.tickets += 1;
        },
        .closed => peer.closed = true,
    }
}

/// Starts the connection an `open` event named. The link stands where the socket would be, and is
/// connected from the start.
fn open_transport(peer: *Peer, open: client.Open, now_ns: u64) void {
    peer.opens += 1;
    peer.connection = open.connection;
    // A start the TLS stack refuses ends the attempt, which the pool reports.
    switch (open.transport) {
        .tcp => peer.pool.start_tcp(open.connection, program.random(), now_seconds, null) catch {},
        .quic => peer.pool.start_quic(program.random(), now_seconds, now_ns, null) catch {},
    }
}

/// Counts an exchange that ended. A peer that keeps no connection shuts its pool down once
/// every exchange has ended.
fn finish(peer: *Peer, ended: client.Finished) void {
    std.debug.print("client: {s}: {s}, {d}\n", .{
        ended.request.path, @tagName(ended.response.result), ended.response.status,
    });
    peer.finished += 1;
    if (peer.finished == peer.asked_count and !peer.keeps) peer.pool.shutdown();
}

/// The soonest instant either peer's pool wants `on_instant` at, or null.
pub fn deadline_ns() ?u64 {
    const tcp_deadline = tcp_peer.pool.deadline_ns();
    const quic_deadline = quic_peer.pool.deadline_ns() orelse return tcp_deadline;
    return @min(tcp_deadline orelse quic_deadline, quic_deadline);
}

/// Whether both peers' pools are over.
pub fn closed() bool {
    return tcp_peer.closed and quic_peer.closed;
}

/// Whether each peer saw what the server sent: h2 for the TCP peer, with the h3 alternative its
/// connection advertised, a 405 with its Allow value and a 404, and h3 for the QUIC peer. Each
/// peer opened one transport, took a ticket from the server, and closed the transport.
pub fn check() bool {
    const asked = &tcp_peer.asked;
    const routed = asked[0].arrived(greeting) and asked[1].arrived(note) and asked[2].arrived(named_greeting);
    const tcp_arrived = routed and asked[3].refused(405, greeting_allow) and asked[4].refused(404, null);
    const alternative = tcp_peer.pool.alternative();
    const advertised = alternative != null and alternative.?.port == server_port;
    const tcp_right = tcp_peer.spoken == .h2 and tcp_arrived and advertised;
    const quic_right = quic_peer.spoken == .h3 and quic_peer.asked[0].arrived(greeting);
    const opened = tcp_peer.opens == 1 and quic_peer.opens == 1;
    const closed_once = tcp_peer.closes == 1 and quic_peer.closes == 1;
    const ticketed = tcp_peer.tickets > 0 and quic_peer.tickets > 0;
    if (tcp_right and quic_right and opened and closed_once and ticketed) return true;
    std.debug.print("server_peers: tcp {}, alternative {}, quic {}, opens {d} and {d}\n", .{
        tcp_arrived, advertised, quic_right, tcp_peer.opens, quic_peer.opens,
    });
    std.debug.print("server_peers: closes {d} and {d}, tickets {d} and {d}\n", .{
        tcp_peer.closes, quic_peer.closes, tcp_peer.tickets, quic_peer.tickets,
    });
    return false;
}
