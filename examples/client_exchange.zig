//! Example: a client sends two requests to one origin through a `client.Pool`, which tries
//! QUIC first and carries the requests over TCP when no QUIC datagram gets through.
//!
//! The pool carries exchanges to one origin over the QUIC and TCP connections it chooses
//! between, and tells the program which transport to open (decision 120). This one has a receive
//! pool and a TLS value, so it offers h3 over QUIC and h2 then h11 over TCP. The program places a
//! request and a response for a GET and for a POST, which the server's routes serve. It places
//! three more, which no route serves: a GET of `/echo`, a GET of `/missing` and a DELETE. The
//! pool sends each request over the first connection whose handshake completes.
//!
//! The network drops every UDP datagram, as some networks do. The run goes in this order:
//! 1. The pool says `open .quic`, and the program starts the QUIC connection. Each datagram it
//!    sends is lost.
//! 2. The fallback delay passes. `deadline_ns` names its end, and the first `receive` at or after
//!    that instant tells the pool. The pool says `open .tcp`, and the program connects a
//!    socket and starts the TCP connection.
//! 3. ALPN picks h2. The pool reports `connected` and sends the five requests, and each
//!    exchange ends in one `finished` event.
//! 4. The program calls `shutdown`. The pool says `close` of the TCP connection once
//!    `send_stream` wrote the GOAWAY and the TLS close_notify.
//! 5. The pool says `close` of the QUIC connection once the abandoned QUIC connection ends, and
//!    then `closed`.
//!
//! Each `open` names the connection it opens, and each later event about it names it too. The
//! program writes what a TCP connection owes when the pool says `send` (decision 125).
//!
//! The QUIC connection ends after its closing period, three PTOs (RFC 9000 §10.2). It has no RTT
//! sample, so each PTO is about 1 s (RFC 9002 §6.2.2). The run thus waits about 3 s of real time.
//!
//! A second pool shows a connect that fails. The program tells the pool with
//! `transport_closed`, and the exchange ends `refused`.
//!
//! The server is in `client_peer.zig`: one endpoint with no UDP socket. The links of `link.zig`
//! and `link_datagram.zig` stand where a program's sockets would be, and `tls_program.zig` holds
//! what any program that links `tls` defines once.
//!
//! The program checks what arrived over h2, octet for octet: 200 twice, the greeting, the note it
//! posted and the content type. It checks 405 with the Allow value "POST", 404 and 501, each with
//! no content. It also checks one open and one close of each transport, at least one lost
//! datagram, a ticket, the `closed` event, and the refused exchange. Anything else exits with an
//! error, which is how `zig build examples` and CI know the example still works.
//!
//! Run it with `zig build example-client_exchange`, or every example with `zig build examples`.
const std = @import("std");
const client = @import("client");
const tls = @import("tls");
const platform = @import("platform");
const identity = @import("testdata");
const program = @import("tls_program.zig");
const peer = @import("client_peer.zig");
const link_module = @import("link.zig");
const datagram_module = @import("link_datagram.zig");

const Link = link_module.Link;
const DatagramLink = datagram_module.DatagramLink;

/// Turns of the client and the server before the example gives up. The run sleeps about 3 s in
/// turns of at most `wait_ns_max`, so it needs about 40 turns.
const turns_max = 256;

/// Calls of `receive` for one read of a socket, at most. Each call takes one octet or more of the
/// link's queue, or reports an event and takes no octet, or ends the loop. At most
/// `Pool.receive_events_without_input_max` calls in a row report an event and take no octet.
const receive_calls_max = (link_module.queue_len_max + 1) * (client.Pool.receive_events_without_input_max(.{}) + 1);

/// Datagrams the client reads or writes in one turn, at most.
const datagrams_per_turn_max = 32;

/// The longest either side sleeps when nothing waits, in nanoseconds: 100 ms.
const wait_ns_max: u64 = 100_000_000;

const greeting = peer.greeting;
const note = peer.note;
const content_type = peer.content_type;

/// The name the server's certificate carries, which the client asks for and judges it by.
const origin = "localhost";

/// The server's address, which the client's DNS lookup returned, and the port of an "https" origin
/// (RFC 9110 §4.2.2). The links stand where the sockets would be, so no socket connects to them.
const loopback = [_]u8{ 127, 0, 0, 1 };
const server_port = 443;
const server_addresses = [_]client.Address{.of(&loopback, 0)};
const server_address: client.Address = .of(&loopback, server_port);

/// Unix seconds. A program reads them from its clock; colibri reads no clock. The client judges
/// the server's certificates at this instant, which the test identity is valid at.
const now_seconds = identity.now_seconds;

comptime {
    // The link's queue holds what the program read of the TCP socket. It holds the octets of each
    // unit that the pool takes whole.
    std.debug.assert(link_module.queue_len_max >= client.constants.stream_input_len_min);
}

pub const Error = error{
    /// The pool was not closed within `turns_max` turns.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
};

// The links and the pools hold megabytes, so they live outside the stack. The datagram link
// runs on the stream link's loops.
var link: Link align(@alignOf(Link)) = undefined;
var datagram_link: DatagramLink align(@alignOf(DatagramLink)) = undefined;
/// What `send_stream` writes, which the link then sends. It holds the largest TLS record, so the
/// TLS stack never refuses it for its length.
var output: [client.constants.stream_output_len_min]u8 = undefined;
var datagram_output: [datagram_module.datagram_len_max]u8 = undefined;

// The client: one configuration for the origin, the receive pool where its QUIC connection holds
// the server's unread octets, one pool, and for each exchange a request and a response. The response
// holds the memory the answer goes into (decision 124).
const anchors = [_]tls.Anchor{.{ .subject = identity.root_name, .spki = identity.root_spki }};
const ReceivePool = client.ReceivePool(64 * 1024);
var client_config: client.Config align(@alignOf(client.Config)) = undefined;
var receive_pool: ReceivePool align(@alignOf(ReceivePool)) = undefined;
var pool: client.Pool align(@alignOf(client.Pool)) = undefined;
// The memory the pool holds its TCP connections and its exchanges in, whose size the counts in
// `client.Options` give (decision 125).
var pool_memory: [client.Pool.memory_bytes(.{})]u8 align(client.Pool.memory_alignment) = undefined;
/// The fields of the response the client reads. colibri keeps no other field.
var wanted: [1]client.Wanted align(@alignOf(client.Wanted)) = .{.{ .name = "content-type" }};
var wanted_values: [content_type.len]u8 = undefined;
var get_body: [greeting.len]u8 = undefined;
var post_body: [note.len]u8 = undefined;
const get: client.Request = .{ .method = "GET", .path = "/greeting" };
var get_response: client.Response align(@alignOf(client.Response)) = .{
    .wanted = &wanted,
    .values = &wanted_values,
    .body = &get_body,
};
const post: client.Request = .{
    .method = "POST",
    .path = "/echo",
    .fields = &.{.{ .name = "content-type", .value = content_type }},
    .content = note,
};
var post_response: client.Response align(@alignOf(client.Response)) = .{ .body = &post_body };

/// The three requests that no route serves. The route of `/echo` names POST alone, so a GET of it
/// gets 405 with an Allow value. No route names `/missing`, so its GET gets 404. No route names
/// DELETE, so its request gets 501 on any path. Each response has no content.
const allow_expected = "POST";
var allow: [1]client.Wanted align(@alignOf(client.Wanted)) = .{.{ .name = "allow" }};
var allow_values: [allow_expected.len]u8 = undefined;
var unanswered_body: [greeting.len]u8 = undefined;
const get_echo: client.Request = .{ .method = "GET", .path = "/echo" };
var get_echo_response: client.Response align(@alignOf(client.Response)) = .{
    .wanted = &allow,
    .values = &allow_values,
    .body = &unanswered_body,
};
const get_missing: client.Request = .{ .method = "GET", .path = "/missing" };
var get_missing_response: client.Response align(@alignOf(client.Response)) = .{ .body = &unanswered_body };
const delete_greeting: client.Request = .{ .method = "DELETE", .path = "/greeting" };
var delete_greeting_response: client.Response align(@alignOf(client.Response)) = .{ .body = &unanswered_body };

/// What the client saw: exchanges that ended, the version ALPN picked, the transports the pool
/// opened and said to close, the tickets it took, and whether the shut-down pool is over.
var finished: u32 = 0;
var spoken: ?client.Protocol align(@alignOf(client.Protocol)) = null;
const Counts = std.EnumArray(client.Transport, u32);
var opens: Counts align(@alignOf(Counts)) = .initFill(0);
var closes: Counts align(@alignOf(Counts)) = .initFill(0);
var tickets: u32 = 0;
var pool_closed: bool = false;
/// The connection each transport's last `open` named, which the program's calls about it name.
const Connections = std.EnumArray(client.Transport, client.ConnectionHandle);
var connections: Connections align(@alignOf(Connections)) = .initFill(.{ .slot = 0, .generation = 0 });

/// The second pool, whose connect fails, and its one exchange.
var refused_pool: client.Pool align(@alignOf(client.Pool)) = undefined;
var refused_memory: [client.Pool.memory_bytes(.{})]u8 align(client.Pool.memory_alignment) = undefined;
var refused_body: [greeting.len]u8 = undefined;
const refused_get: client.Request = .{ .method = "GET", .path = "/greeting" };
var refused_get_response: client.Response align(@alignOf(client.Response)) = .{ .body = &refused_body };

pub fn main() !void {
    try link.init();
    defer link.deinit();
    datagram_link.init(&link.loops);
    // The network drops every datagram.
    datagram_link.blocked = true;
    // A program probes its CPU once and says what mode its thread runs in, and passes both to every
    // TLS configuration. This one sets no mode, so its sessions run ChaCha20 alone; one whose
    // thread set PSTATE.DIT on arm64 states `.data_independent`.
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    try peer.init(&link, cpu);
    try start_client(cpu);
    try connect_refused();
    for (0..turns_max) |_| {
        try client_turn();
        try peer.turn();
        if (pool_closed and peer.over()) return check();
        // No octet waits for either side. A program sleeps here until a socket has octets or a
        // deadline passes, whichever comes first.
        if (!link.pending()) try link.wait(.client, sleep_ns());
    }
    return error.ExchangeUnfinished;
}

fn start_client(cpu: tls.Cpu) !void {
    // One configuration serves both transports. Its TLS value names no protocol: the pool
    // offers h3 over QUIC, and h2 then http/1.1 over TCP, as `versions` allows them.
    client_config = .{
        .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .cpu = cpu },
        .authority = origin,
    };
    // The pool takes what DNS knows as values: the server's addresses and its port.
    const known: client.Values = .{ .addresses = &server_addresses, .port = server_port };
    // `init` builds the TLS configuration of each transport inside the pool, which stays in
    // place from here on. It keeps the pool's TCP connections and its exchanges in `pool_memory`,
    // which `.{}`, the default counts, sizes. The receive pool is what makes the pool offer QUIC.
    try pool.init(&pool_memory, &client_config, known, .{}, receive_pool.storage());
    // `request` only takes a request and its response. The pool asks for a transport, and
    // sends the request over the first connection that completes its handshake, so a program asks
    // at once and never waits.
    _ = try pool.request(&get, &get_response);
    _ = try pool.request(&post, &post_response);
    _ = try pool.request(&get_echo, &get_echo_response);
    _ = try pool.request(&get_missing, &get_missing_response);
    _ = try pool.request(&delete_greeting, &delete_greeting_response);
}

/// One turn of the client: pass the pool what each socket read, fire its deadlines, send what
/// it owes, and read again with the octets the TCP socket still holds.
fn client_turn() !void {
    const now_ns = link.now_ns(.client);
    try read_datagrams(now_ns);
    // `on_instant` fires QUIC's timers that passed. The reads after it count the end of the
    // fallback delay, and report what changed.
    pool.on_instant(now_ns);
    try drain(now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = pool.send_datagram(&datagram_output, now_ns) orelse break;
        try datagram_link.send(.client, sent.octets);
    }
    try drain(now_ns);
}

/// Passes the pool each datagram the UDP socket read, with the address it came from. A
/// datagram is consumed whole. On this network none arrives.
fn read_datagrams(now_ns: u64) !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try datagram_link.receive(.client) orelse break;
        // A connection takes a datagram only from the address its server answers from.
        var rest: client.Input = .{ .datagram = .{ .octets = datagram, .from = server_address } };
        for (0..receive_calls_max) |_| {
            const received = pool.receive(rest, now_ns);
            if (received.consumed > 0) rest = .none;
            const event = received.event orelse {
                if (received.consumed == 0) break;
                continue;
            };
            try report(event, now_ns);
        }
        datagram_link.consume(.client);
    }
}

/// Passes the pool the octets the TCP socket read, until it consumes nothing and reports
/// nothing. Each call passes every octet the program still holds, or `.none` when it holds none:
/// an h11 connection reads a held octet only once the response before it ends.
fn drain(now_ns: u64) !void {
    const input = try link.receive(.client);
    var consumed: usize = 0;
    for (0..receive_calls_max) |_| {
        const held = input[consumed..];
        const tcp = connections.get(.tcp);
        const read: client.Input = if (held.len > 0) .{ .stream = .{ .connection = tcp, .octets = held } } else .none;
        const received = pool.receive(read, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try report(event, now_ns);
        // The octets the closed socket read are its connection's, which is over: they are dropped.
        if (event == .close and transport_of(event.close) == .tcp) consumed = input.len;
    }
    // What an event carried points into the queue, so the queue is consumed only now.
    link.consume(.client, consumed);
}

/// Acts on one event of the pool. Each exchange ends in one `finished` event, whatever happened
/// to it: its `outcome` says whether the response arrived.
fn report(event: client.Event, now_ns: u64) !void {
    switch (event) {
        .open => |open| try open_transport(open, now_ns),
        // The TCP connection owes octets, which the program writes into its socket.
        .send => |connection| try send_owed(connection, now_ns),
        // The connection is over, and the pool reads and writes nothing more on it: the
        // program closes the socket. Over TCP `send_stream` wrote everything first, the TLS
        // close_notify too. The pool has wiped the session's secrets.
        .close => |connection| closes.getPtr(transport_of(connection)).* += 1,
        .connected => |connected| {
            std.debug.print("client: connected over {s}\n", .{@tagName(connected.protocol)});
            spoken = connected.protocol;
        },
        .finished => |ended| {
            // The event names the request and the response, whose memory is the program's again.
            std.debug.print("client: {s}: {s}, {d}\n", .{
                ended.request.path, @tagName(ended.response.outcome), ended.response.status,
            });
            finished += 1;
            // Every exchange has ended, so the client shuts the pool down.
            if (finished == exchanges_count) pool.shutdown();
        },
        .ticket => |connection| take_ticket(connection),
        // The shut-down pool is over: every exchange ended and every transport closed.
        .closed => pool_closed = true,
    }
}

/// Opens the transport an `open` event named, to `open.to`, then starts its connection with the
/// source its TLS session draws from. The pool draws a QUIC connection's IDs (RFC 9000 §7.2)
/// and h3's grease value (RFC 9114 §7.2.4.1) from that source too.
fn open_transport(open: client.Open, now_ns: u64) !void {
    std.debug.print("client: open {s}\n", .{@tagName(open.transport)});
    opens.getPtr(open.transport).* += 1;
    connections.set(open.transport, open.connection);
    // A start the TLS stack refuses ends the attempt, which the pool reports.
    switch (open.transport) {
        // The UDP socket needs no connect.
        .quic => pool.start_quic(program.random(), now_seconds, now_ns, null) catch {},
        .tcp => {
            // The link stands where the socket would be: the server's listener accepts the
            // socket the program connects.
            try peer.accept();
            pool.start_tcp(open.connection, program.random(), now_seconds, null) catch {};
        },
    }
}

/// Writes what the TCP connection owes into the socket, until a call leaves room in `output`:
/// that call wrote all the connection owed (decision 125).
fn send_owed(connection: client.ConnectionHandle, now_ns: u64) !void {
    for (0..sends_per_debt_max) |_| {
        const written = pool.send_stream(connection, &output, now_ns);
        try link.send(.client, output[0..written]);
        if (written < output.len) return;
    }
    return error.ExchangeWrong;
}

/// Calls of `send_stream` for one `send`, at most: the requests of this run fit in a few
/// outputs.
const sends_per_debt_max = 16;

/// The transport whose last `open` named `connection`: a slot holds one transport's connections.
fn transport_of(connection: client.ConnectionHandle) client.Transport {
    return if (connection.slot == connections.get(.quic).slot and opens.get(.quic) > 0) .quic else .tcp;
}

/// Takes the resumption ticket the server issued. This client opens no later connection, so it
/// wipes the ticket. A program keeps it, and offers it in the last argument of the next start.
fn take_ticket(connection: client.ConnectionHandle) void {
    const ticket = pool.take_ticket(connection) orelse return;
    var held = ticket;
    held.wipe();
    tickets += 1;
}

/// The exchanges `start_client` requested.
const exchanges_count = 5;

/// A second pool to the origin, whose connect fails, as when the server's listener is down.
/// The program tells the pool with `transport_closed`, and calls it too for a socket that the
/// peer closed or that failed. The pool then ends the exchange `refused`: no server processed
/// it, so a program may make it again.
fn connect_refused() !void {
    const now_ns = link.now_ns(.client);
    // The pools to one origin share its configuration. With no receive pool this one offers
    // TCP alone.
    const known: client.Values = .{ .addresses = &server_addresses, .port = server_port };
    try refused_pool.init(&refused_memory, &client_config, known, .{}, null);
    _ = try refused_pool.request(&refused_get, &refused_get_response);
    for (0..receive_calls_max) |_| {
        const received = refused_pool.receive(.none, now_ns);
        switch (received.event orelse return error.ExchangeWrong) {
            // The connect failed, so the transport closed before its connection started.
            .open => |open| refused_pool.transport_closed(open.connection),
            .finished => refused_pool.shutdown(),
            .closed => return,
            .send, .close, .connected, .ticket => return error.ExchangeWrong,
        }
    }
    return error.ExchangeWrong;
}

/// How long both sides may sleep: until the sooner of their next deadlines, and never longer
/// than `wait_ns_max`. The pool's deadline is the end of the fallback delay or QUIC's next
/// timer.
fn sleep_ns() u64 {
    var wait_ns: u64 = wait_ns_max;
    if (pool.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.client));
    }
    if (peer.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.server));
    }
    // A wait of 0 would poll, so the shortest sleep is one nanosecond.
    return @max(wait_ns, 1);
}

/// The client saw what the server sent, over h2. It opened and closed each transport once, lost
/// at least one datagram, and took a ticket. The requests that no route serves got 405, 404 and
/// 501. The refused exchange ended `refused`, and the server saw what it expects.
fn check() Error!void {
    const greeted = arrived(&get_response, 200, greeting);
    const typed = std.mem.eql(u8, wanted[0].value orelse "", content_type);
    const echoed = arrived(&post_response, 200, note);
    const unserved = unserved_arrived();
    const opened = opens.get(.quic) == 1 and opens.get(.tcp) == 1;
    const closed = closes.get(.quic) == 1 and closes.get(.tcp) == 1;
    const lost = datagram_link.dropped > 0;
    const refused = refused_get_response.outcome == .refused;
    const right = spoken == .h2 and greeted and typed and echoed and unserved and tickets > 0 and refused;
    if (right and opened and closed and lost and peer.check()) {
        std.debug.print("client_exchange: every octet arrived as sent\n", .{});
        return;
    }
    std.debug.print("client_exchange: greeting {}, content type {}, echo {}, unserved {}, tickets {d}\n", .{
        greeted, typed, echoed, unserved, tickets,
    });
    std.debug.print("client_exchange: opens {d} and {d}, closes {d} and {d}, lost {d}, refused {}\n", .{
        opens.get(.quic), opens.get(.tcp), closes.get(.quic), closes.get(.tcp), datagram_link.dropped, refused,
    });
    return error.ExchangeWrong;
}

/// Whether `response` ended its exchange as a response with `status`, whose content is `content`.
fn arrived(response: *const client.Response, status: u16, content: []const u8) bool {
    if (response.outcome != .response or response.status != status) return false;
    return std.mem.eql(u8, response.content_received(), content);
}

/// Whether the three requests that no route serves got 405 with the Allow value, 404 and 501.
fn unserved_arrived() bool {
    const allowed = std.mem.eql(u8, allow[0].value orelse "", allow_expected);
    return allowed and arrived(&get_echo_response, 405, "") and
        arrived(&get_missing_response, 404, "") and arrived(&delete_greeting_response, 501, "");
}
