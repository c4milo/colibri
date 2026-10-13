//! The two clients of `server_exchange.zig`. This file is not an example by itself: it holds what
//! the server example runs against.
//!
//! Each peer is one `client.Channel`:
//! - the TCP peer holds no receive pool, so its channel opens TCP alone, and ALPN picks h2. It
//!   sends a GET and a POST, and shuts its channel down when both have finished;
//! - the QUIC peer holds a receive pool and speaks h3 alone, so its channel opens QUIC alone
//!   (decision 120). It sends a GET, and keeps its connection open after the response, as a client
//!   that can ask again does. The server closes the connection when its idle deadline passes, and
//!   the peer then shuts its channel down.
//!
//! The TCP peer runs over the stream link and the QUIC peer over the datagram link, on the client's
//! loop. `docs/usage.md` shows the client's calls with the client examples, so the comments here
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
const requests_max = 2;

/// One request a peer makes, and the memory its response goes into.
const Asked = struct {
    exchange: client.HttpExchange,
    wanted: [1]client.Wanted,
    values: [content_type.len]u8,
    body: [note.len]u8,

    /// Fills the exchange. `content` is the request's content, or empty for none.
    fn place(asked: *Asked, method: []const u8, path: []const u8, content: []const u8) void {
        asked.wanted = .{.{ .name = "content-type" }};
        asked.exchange = .{
            .method = method,
            .path = path,
            .wanted = &asked.wanted,
            .values = &asked.values,
            .body = &asked.body,
        };
        if (content.len == 0) return;
        asked.exchange.fields = &.{.{ .name = "content-type", .value = content_type }};
        asked.exchange.content = content;
    }

    /// Whether the exchange ended in a 200 response with `content` and the content type.
    fn arrived(asked: *const Asked, content: []const u8) bool {
        const exchange = &asked.exchange;
        if (exchange.outcome != .response or exchange.status != 200) return false;
        if (!std.mem.eql(u8, asked.wanted[0].value orelse "", content_type)) return false;
        return std.mem.eql(u8, exchange.content_received(), content);
    }
};

/// One client: its configuration, its channel, and what it saw.
const Peer = struct {
    config: client.Config,
    channel: client.Channel,
    asked: [requests_max]Asked,
    asked_count: u32,
    /// Whether the peer keeps its connection open after its exchanges finished.
    keeps: bool,
    finished: u32,
    spoken: ?client.Protocol,
    /// Transports the channel opened, transports it said to close, and tickets it took.
    opens: u32,
    closes: u32,
    tickets: u32,
    /// The shut-down channel is over.
    closed: bool,

    /// Places one request: `content` is its content, or empty for none.
    fn ask(peer: *Peer, method: []const u8, path: []const u8, content: []const u8) !void {
        const asked = &peer.asked[peer.asked_count];
        asked.place(method, path, content);
        peer.asked_count += 1;
        _ = try peer.channel.request(&asked.exchange);
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
    const known: client.Values = .{ .addresses = &server_addresses, .port = server_port };
    start(&tcp_peer, cpu, .{}, false);
    // No receive pool: the channel opens TCP alone.
    try tcp_peer.channel.init(&tcp_peer.config, known, null);
    try tcp_peer.ask("GET", "/greeting", "");
    try tcp_peer.ask("POST", "/echo", note);
    // h3 alone: the channel opens QUIC alone, and needs the receive pool for it.
    start(&quic_peer, cpu, .{ .h11 = false, .h2 = false }, true);
    try quic_peer.channel.init(&quic_peer.config, known, receive_pool.storage());
    try quic_peer.ask("GET", "/greeting", "");
}

fn start(peer: *Peer, cpu: tls.Cpu, versions: client.Versions, keeps: bool) void {
    peer.config = .{
        .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .cpu = cpu },
        .versions = versions,
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
}

/// One turn of both peers: each reads what arrived, fires its deadlines, and sends what it owes.
pub fn turn() !void {
    try tcp_turn();
    try quic_turn();
}

fn tcp_turn() !void {
    const now_ns = stream_link.now_ns(.client);
    try drain_stream(now_ns);
    try stream_link.send(.client, stream_output[0..tcp_peer.channel.send_stream(&stream_output, now_ns)]);
    try drain_stream(now_ns);
}

/// Passes the TCP peer's channel the octets the stream link holds, until it consumes nothing and
/// reports nothing. At a `close`, the peer drops the octets it holds.
fn drain_stream(now_ns: u64) !void {
    const input = try stream_link.receive(.client);
    var consumed: usize = 0;
    for (0..events_per_input_max) |_| {
        const held = input[consumed..];
        const read: client.Input = if (held.len > 0) .{ .stream = held } else .none;
        const received = tcp_peer.channel.receive(read, now_ns);
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
        drain_datagram(.{ .datagram = .{ .octets = datagram, .from = server_address } }, datagram_link.now_ns(.client));
        datagram_link.consume(.client);
    }
    const now_ns = datagram_link.now_ns(.client);
    quic_peer.channel.on_instant(now_ns);
    drain_datagram(.none, now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = quic_peer.channel.send_datagram(&datagram_output, now_ns) orelse break;
        try datagram_link.send(.client, sent.octets);
        drain_datagram(.none, now_ns);
    }
}

/// Passes the QUIC peer's channel `input`, then reads it with `.none` until it reports nothing.
fn drain_datagram(input: client.Input, now_ns: u64) void {
    var rest = input;
    for (0..events_per_input_max) |_| {
        const received = quic_peer.channel.receive(rest, now_ns);
        if (received.consumed > 0) rest = .none;
        const event = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        report(&quic_peer, event, now_ns);
    }
}

/// Acts on one event of a peer's channel.
fn report(peer: *Peer, event: client.Event, now_ns: u64) void {
    switch (event) {
        .open => |open| open_transport(peer, open.transport, now_ns),
        .close => {
            peer.closes += 1;
            // The server closed a connection the peer kept, and every exchange has ended.
            if (peer.finished == peer.asked_count) peer.channel.shutdown();
        },
        .connected => |protocol| peer.spoken = protocol,
        .finished => |ended| finish(peer, ended.exchange),
        // These peers open no second connection, so each wipes the ticket the server gives it.
        .ticket => |transport| if (peer.channel.take_ticket(transport)) |ticket| {
            var held = ticket;
            held.wipe();
            peer.tickets += 1;
        },
        .closed => peer.closed = true,
    }
}

/// Starts the connection of the transport an `open` event named. The link stands where the socket
/// would be, and is connected from the start.
fn open_transport(peer: *Peer, transport: client.Transport, now_ns: u64) void {
    peer.opens += 1;
    // A start the TLS stack refuses ends the attempt, which the channel reports.
    switch (transport) {
        .tcp => peer.channel.start_tcp(program.random(), now_seconds, null) catch {},
        .quic => peer.channel.start_quic(program.random(), now_seconds, now_ns, null) catch {},
    }
}

/// Counts an exchange that ended. A peer that keeps no connection shuts its channel down once
/// every exchange has ended.
fn finish(peer: *Peer, exchange: *const client.HttpExchange) void {
    std.debug.print("client: {s}: {s}, {d}\n", .{
        exchange.path, @tagName(exchange.outcome), exchange.status,
    });
    peer.finished += 1;
    if (peer.finished == peer.asked_count and !peer.keeps) peer.channel.shutdown();
}

/// The soonest instant either peer's channel wants `on_instant` at, or null.
pub fn deadline_ns() ?u64 {
    const tcp_deadline = tcp_peer.channel.deadline_ns();
    const quic_deadline = quic_peer.channel.deadline_ns() orelse return tcp_deadline;
    return @min(tcp_deadline orelse quic_deadline, quic_deadline);
}

/// Whether both peers' channels are over.
pub fn closed() bool {
    return tcp_peer.closed and quic_peer.closed;
}

/// Whether each peer saw what the server sent: h2 for the TCP peer, with the h3 alternative its
/// connection advertised, and h3 for the QUIC peer. Each peer opened one transport, took a ticket
/// from the server, and closed the transport.
pub fn check() bool {
    const tcp_arrived = tcp_peer.asked[0].arrived(greeting) and tcp_peer.asked[1].arrived(note);
    const alternative = tcp_peer.channel.alternative();
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
