//! Example: a client asks for a resource over h3 and a server answers it, through colibri's
//! `client.Channel` and `server.Endpoint`.
//!
//! The server's `Endpoint` holds every QUIC connection behind one UDP socket. The program passes
//! it each datagram with the address it came from. Each `receive` reports one event of any
//! connection, and the program answers a request by its id, which names the request's connection
//! too: `respond` and `write_body`.
//!
//! The client's `Channel` carries exchanges to one origin over QUIC or over TCP, and tells the
//! program which transport to open. Here it opens QUIC first, the handshake completes, and h3
//! carries the exchange. A program that also opens TCP when the channel asks gets h2 or h11 for
//! the same exchange when QUIC fails; this example has no TCP to open.
//!
//! QUIC runs on timers too: each side names its next deadline, and the program sleeps until the
//! sooner one when no datagram waits. Both run over `link_datagram.zig`, which stands where a
//! program's UDP sockets would be, and `tls_program.zig` holds what any program that links `tls`
//! defines once.
//!
//! The program checks what arrived: the client must see 200 and the greeting over h3, octet for
//! octet, the server must have answered one request, and both connections must end.
//! Anything else exits with an error, which is how `zig build examples` and CI know the example
//! still works.
//!
//! Run it with `zig build example-h3_exchange`, or every example with `zig build examples`.
const std = @import("std");
const client = @import("client");
const server = @import("server");
const tls = @import("tls");
const platform = @import("platform");
const identity = @import("testdata");
const program = @import("tls_program.zig");
const link_module = @import("link_datagram.zig");

const Link = link_module.DatagramLink;

/// Turns of both sides before the example gives up.
const turns_max = 256;

/// Datagrams one side reads or writes in one turn, and events it takes after each, at most.
const datagrams_per_turn_max = 32;
const events_per_datagram_max = 64;

/// The longest either side sleeps for a deadline, in nanoseconds: 100 ms.
const wait_ns_max = 100_000_000;

/// How long QUIC's handshake runs before the channel asks for TCP beside it, in nanoseconds:
/// 300 ms.
const fallback_delay_ns = 300_000_000;

/// How long the server keeps a connection with no request open, in nanoseconds: 10 s, and 5 s
/// once the connection has answered the example's request.
const idle_ns = 10_000_000_000;
const idle_after_answer_ns = 5_000_000_000;

const greeting = "hello from colibri over h3\n";
const content_type = "text/plain; charset=utf-8";

/// The name the server's certificate carries, which the client asks for and judges it by.
const origin = "localhost";

/// Unix seconds. A program reads them from its clock; colibri reads no clock. The client judges
/// the server's certificates at this instant, which the test identity is valid at.
const now_seconds = identity.now_seconds;

/// The addresses a program's sockets would give: where the server listens, which the client's
/// DNS lookup returned, and where the client's datagrams come from.
const loopback = [_]u8{ 127, 0, 0, 1 };
const server_port = 443;
const client_port = 50_000;
const server_addresses = [_]client.Address{.of(&loopback, 0)};
const server_address: client.Address = .of(&loopback, server_port);
const client_address: server.Address = .of(&loopback, client_port);

pub const Error = error{
    /// The connections had not both ended within `turns_max` turns.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
};

// The link and both sides hold megabytes, so they live outside the stack.
var link: Link align(@alignOf(Link)) = undefined;
var output: [link_module.datagram_len_max]u8 = undefined;

// The server: the TLS configuration of its QUIC connections, and the endpoint that holds them.
// colibri's test identity stands in for the certificate and the key a program loads.
/// The QUIC connections the endpoint holds at once, and the octets each holds unread.
const Endpoint = server.EndpointOf(.{ .quic_connections = 2, .receive_pool_len = 64 * 1024 });
const chain = [_][]const u8{ identity.leaf, identity.root };
var cookie_key: [tls.constants.server_key_len]u8 = undefined;
var endpoint_config: server.EndpointConfig align(@alignOf(server.EndpointConfig)) = undefined;
var endpoint: Endpoint align(@alignOf(Endpoint)) = undefined;
/// Requests the server answered, and connections that are over.
var answered: u32 = 0;
var ended: u32 = 0;

// The client: a TLS configuration for each transport, the channel, the pool its QUIC connection
// holds the server's unread octets in, and one exchange.
const anchors = [_]tls.Anchor{.{ .subject = identity.root_name, .spki = identity.root_spki }};
const ReceivePool = client.ReceivePool(64 * 1024);
var client_tls: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var client_quic_tls: tls.quic.ClientConfig align(@alignOf(tls.quic.ClientConfig)) = undefined;
var client_tcp: client.Config align(@alignOf(client.Config)) = undefined;
var client_quic: client.QuicConfig align(@alignOf(client.QuicConfig)) = undefined;
var channel_config: client.ChannelConfig align(@alignOf(client.ChannelConfig)) = undefined;
var receive_pool: ReceivePool align(@alignOf(ReceivePool)) = undefined;
var channel: client.Channel align(@alignOf(client.Channel)) = undefined;
var wanted: [1]client.Wanted align(@alignOf(client.Wanted)) = .{.{ .name = "content-type" }};
var wanted_values: [content_type.len]u8 = undefined;
var body: [greeting.len]u8 = undefined;
var get: client.HttpExchange align(@alignOf(client.HttpExchange)) = .{
    .method = "GET",
    .path = "/greeting",
    .wanted = &wanted,
    .values = &wanted_values,
    .body = &body,
};
/// The version that carried the exchange, and whether the channel is closed.
var spoken: ?client.Protocol align(@alignOf(client.Protocol)) = null;
var closed: bool = false;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    // A program probes its CPU once and says what mode its thread runs in, and passes both to every
    // TLS configuration. This one sets no mode, so its sessions run ChaCha20 alone; one whose
    // thread set PSTATE.DIT on arm64 states `.data_independent`.
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    try start_server(cpu);
    try start_client(cpu);
    for (0..turns_max) |_| {
        try client_turn();
        try server_turn();
        if (closed and ended == 1) return check();
        // No datagram waits, so each side sleeps until its next deadline, as a program's loop
        // sleeps in its poll.
        if (!link.pending()) try link.wait(.client, sleep_ns());
    }
    return error.ExchangeUnfinished;
}

fn start_server(cpu: tls.Cpu) !void {
    // RFC 9846 §4.3.2's cookie key, which a server draws once.
    program.fill(&cookie_key);
    endpoint_config = .{
        // The identity names no protocol: the endpoint names h3 for its QUIC connections.
        .tls = .{
            .ecdsa_p256 = .{
                .chain = &chain,
                .public_key = identity.public_key,
                .private_key = identity.private_key,
            },
            .cookie_key = &cookie_key,
            .cpu = cpu,
        },
        // Decision 110: deadlines bound how long a peer may hold a connection. The defaults suit
        // a server, and this one ends an idle connection sooner.
        .deadlines = .{ .idle_ns = idle_ns },
    };
    // One endpoint for the program's UDP socket. It checks that the key signs, and starts a
    // connection from each client's first datagram, in a slot of its own.
    try endpoint.init(&endpoint_config, program.random(), now_seconds, link.now_ns(.server));
}

fn start_client(cpu: tls.Cpu) !void {
    try client_quic_tls.init(.{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } },
        .alpn = &.{"h3"},
        .cpu = cpu,
    });
    try client_tls.init(.{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } },
        .alpn = &.{ "h2", "http/1.1" },
        .cpu = cpu,
    });
    client_tcp = .{ .tls = &client_tls, .authority = origin };
    client_quic = .{ .tls = &client_quic_tls, .authority = origin };
    channel_config = .{
        .tcp = &client_tcp,
        .quic = &client_quic,
        .fallback_delay_ns = fallback_delay_ns,
    };
    // The channel takes what DNS knows as values: the server's addresses and its port.
    const known: client.ChannelValues = .{ .addresses = &server_addresses, .port = server_port };
    channel.init(&channel_config, known, receive_pool.storage());
    // `request` only takes an exchange. The channel sends it over the first connection that
    // completes its handshake.
    _ = try channel.request(&get);
}

/// One turn of the server: pass the endpoint each datagram, answer what its connections report,
/// fire its deadlines, and send every datagram the endpoint owes.
fn server_turn() !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try link.receive(.server) orelse break;
        // The endpoint finds the connection the datagram's connection ID names, or starts one.
        try serve(.{ .datagram = .{ .octets = datagram, .from = client_address } }, link.now_ns(.server));
        link.consume(.server);
    }
    const now_ns = link.now_ns(.server);
    endpoint.on_instant(now_ns);
    try serve(.none, now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = endpoint.send_datagram(&output, now_ns) orelse break;
        try link.send(.server, sent.octets);
    }
}

/// Passes `input` to the endpoint, then takes every event it reports until it reports none, and
/// answers each request by its id.
fn serve(input: server.Input, now_ns: u64) !void {
    var rest = input;
    for (0..events_per_datagram_max) |_| {
        const received = endpoint.receive(rest, now_ns);
        rest = .none;
        switch (received.event orelse return) {
            .request => |request| {
                std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
                try endpoint.respond(request.id, .{
                    .status = 200,
                    .fields = &.{.{ .name = "content-type", .value = content_type }},
                    .end = false,
                });
                // Over QUIC `write_body` copies nothing, because QUIC reads the octets again to
                // send them again. They stay the program's until the request is `done` or
                // `cancelled`.
                _ = try endpoint.write_body(request.id, .{ .octets = greeting, .end = true });
                answered += 1;
                // A program short of connections shortens the deadlines of one it holds. This
                // connection has answered the one request the example sends.
                try endpoint.set_deadlines(request.id.connection, .{ .idle_ns = idle_after_answer_ns });
            },
            // Every request ends once, with `done` or `cancelled`. `done` says the client
            // acknowledged every octet of the response.
            .done => |done| std.debug.print("server: request {d} is acknowledged\n", .{done.id.number}),
            .body, .trailers, .cancelled, .writable => {},
            // A connection that is over comes once, after its requests' endings, and its slot is
            // free for a later client. Its reason names the deadline or the limit that made colibri
            // close it, and is null when its client closed it, as this one does.
            .ended => |over| {
                if (over.reason) |reason| std.debug.print("server: closed for {s}\n", .{@tagName(reason)});
                ended += 1;
            },
            // Only a TCP connection owes octets or a close, and only a shutdown ends in `closed`.
            .send, .close, .closed => unreachable,
        }
    }
}

/// One turn of the client: fire the channel's deadlines, pass it each datagram, and send every
/// datagram it owes.
fn client_turn() !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try link.receive(.client) orelse break;
        const now_ns = link.now_ns(.client);
        // A connection takes a datagram only from the address its server answers from.
        drain(.{ .datagram = .{ .octets = datagram, .from = server_address } }, now_ns);
        link.consume(.client);
    }
    const now_ns = link.now_ns(.client);
    channel.on_instant(now_ns);
    drain(.none, now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = channel.send_datagram(&output, now_ns) orelse break;
        try link.send(.client, sent.octets);
        drain(.none, now_ns);
    }
}

/// Passes `input` to the channel and acts on each event, until the channel consumes nothing and
/// reports nothing. A datagram is consumed whole.
fn drain(input: client.ChannelInput, now_ns: u64) void {
    var rest = input;
    for (0..events_per_datagram_max) |_| {
        const received = channel.receive(rest, now_ns);
        if (received.consumed > 0) rest = .none;
        const event = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        report(event, now_ns);
    }
}

/// Acts on one event of the channel.
fn report(event: client.ChannelEvent, now_ns: u64) void {
    switch (event) {
        // The channel names the transport to open. A program opens a UDP flow or a TCP
        // connection to `open.to`, then starts the connection.
        .open => |open| switch (open.transport) {
            .quic => start_quic(now_ns),
            // This example has no TCP to open, so it tells the channel the transport closed.
            .tcp => channel.transport_closed(.tcp),
        },
        // Nothing to close: one UDP socket serves every QUIC connection, and stays open.
        .close => {},
        .connected => |protocol| {
            std.debug.print("client: connected over {s}\n", .{@tagName(protocol)});
            spoken = protocol;
        },
        .finished => |finished| {
            const exchange = finished.exchange;
            std.debug.print("client: {s}: {s}, {d}\n", .{
                exchange.path, @tagName(exchange.outcome), exchange.status,
            });
            // The one exchange has ended, so the client ends the channel.
            channel.shutdown();
        },
        // This client opens no second connection, so it wipes the ticket a server gives it.
        .ticket => |transport| if (channel.take_ticket(transport)) |ticket| {
            var held = ticket;
            held.wipe();
        },
        .closed => closed = true,
    }
}

/// Starts the QUIC connection the channel asked for. A program draws its connection IDs (RFC
/// 9000 §7.2) and h3's grease value (RFC 9114 §7.2.4.1) at random.
fn start_quic(now_ns: u64) void {
    var start: client.QuicStart = undefined;
    program.fill(&start.source_id);
    program.fill(&start.original_destination_id);
    program.fill(std.mem.asBytes(&start.grease));
    // A start the TLS stack refuses ends the attempt, which the channel reports.
    channel.start_quic(start, program.random(), now_seconds, now_ns, null) catch {};
}

/// How long both sides may sleep: until the sooner of their next deadlines, and never longer
/// than `wait_ns_max`.
fn sleep_ns() u64 {
    var wait_ns: u64 = wait_ns_max;
    if (channel.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.client));
    }
    if (endpoint.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.server));
    }
    // A wait of 0 would poll, so the shortest sleep is one nanosecond.
    return @max(wait_ns, 1);
}

/// The client saw what the server sent, over h3, and the server answered one request.
fn check() Error!void {
    const greeted = get.outcome == .response and get.status == 200 and
        std.mem.eql(u8, get.content_received(), greeting);
    const typed = std.mem.eql(u8, wanted[0].value orelse "", content_type);
    if (spoken == .h3 and greeted and typed and answered == 1) {
        std.debug.print("h3_exchange: every octet arrived as sent\n", .{});
        return;
    }
    std.debug.print("h3_exchange: greeting {}, content type {}, answered {d}\n", .{
        greeted, typed, answered,
    });
    return error.ExchangeWrong;
}
