# Using colibri

This guide shows how a program drives colibri: how to add it, what the program owns, and the calls
it makes. It starts with the `server` and `client` modules, which most programs use and which
serve every version, and then covers each protocol module by itself. Each module's entry file
documents its calls in full; this guide shows how they fit together.
[`examples/`](../examples/) holds a short whole program for each part, and the test-only endpoints
under [`src/testing/`](../src/testing/) run every protocol over real sockets.

## Adding colibri

Depend on a release tag, or on a commit for a change made since:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#v0.7.0
```

In `build.zig`, import the modules your program uses. Most programs take these three, and a
protocol module is imported the same way:

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true });
exe.root_module.addImport("server", colibri.module("server"));
exe.root_module.addImport("client", colibri.module("client"));
exe.root_module.addImport("tls", colibri.module("tls"));
```

The library is fifteen modules, each exported by name:

| Module | What it holds |
| --- | --- |
| `core` | The bounds-checked reader and writer, and the limits two modules share |
| `wire` | The integer and string codecs of RFC 7541 and RFC 9000 §16, and the Huffman code |
| `http` | What h11, h2 and h3 share: field lines and sections, methods, status codes, URIs, and the message rules of RFC 9110 |
| `tls_provider` | The `tls_provider.Provider` and `tls_provider.QuicProvider` vtables a TLS stack fills |
| `tls` | TLS 1.3 over [chapulin](https://github.com/c4milo/chapulin): the values you set, and the sessions whose provider h11 and h2 take |
| `crypto` | The `crypto.Suite` vtable that protects QUIC packets |
| `qlog` | A qlog log in the caller's buffer, which `quic` and `h3` fill when the caller asks ([decision 102](decisions.md)) |
| `hpack` | HPACK (RFC 7541) |
| `qpack` | QPACK (RFC 9204) |
| `quic` | QUIC versions 1 and 2 (RFC 9000, 9001, 9002, 9369). It imports no HTTP module. |
| `h11` | HTTP/1.1 (RFC 9112) |
| `h2` | HTTP/2 (RFC 9113) |
| `h3` | HTTP/3 (RFC 9114) over `quic` |
| `server` | Responses to h11, h2 and h3 requests behind one set of calls, with each TLS handshake run inside it ([decision 100](decisions.md)). A `Connection` serves h11 or h2 over one TCP connection, and an `Endpoint` holds the QUIC connections that serve h3 behind one UDP socket you own ([decision 103](decisions.md)). |
| `client` | Requests over h11, h2 and h3 behind one set of calls, each ending in one outcome in memory you own, with each TLS handshake run inside it ([decision 100](decisions.md)). A `Channel` carries them to one origin over the QUIC and TCP connections it chooses between, and tells you which transport to open. |

The package also exports stdx's codecs, `codec`, `gzip`, `zlib`, `zstd` and `brotli`, from the stdx
colibri pins ([decision 101](decisions.md)).

A program that uses TLS probes its CPU through stdx's `platform` module
([decision 97](decisions.md)). Depend on stdx at the commit colibri's `build.zig.zon` pins, and
give it the options colibri gives it, so both reach one `platform` module and one `platform.Cpu`:

```zig
const stdx = b.dependency("stdx", .{ .target = target, .release = true });
exe.root_module.addImport("platform", stdx.module("platform"));
```

`.release = true` builds ReleaseSafe. colibri offers Debug and ReleaseSafe only, because its
assertions stay on in production.

## What your program owns

colibri makes no system call, holds no allocator, and reads no clock. Four things follow:

- **Your program owns every struct and buffer.** Declare a connection where you like: in a
  static, in an array of connections, or inside a larger struct. Nothing points at the heap.
  Place large connections outside the stack.
- **Your program does the I/O.** Read octets from the socket, hand them to `receive`, and send
  the octets the `write_*` calls put in your buffer. colibri never waits: when it needs more
  octets, `receive` consumes none and returns no event.
- **Your program passes the time.** A call that needs the current instant takes `now_ns`, in
  nanoseconds from any fixed origin. The same instants and the same octets give the same output,
  which is what lets the simulator replay a connection.
- **Your program configures TLS.** Convert your values once into a configuration:
  `tls.record.ClientConfig` or `ServerConfig` over TCP, `tls.quic.ClientConfig` or `ServerConfig`
  for QUIC. The `server` and `client` modules take the configuration and run each handshake
  themselves. A program that drives a protocol module by itself starts a session of the matching
  kind for each connection: h11 and h2 take a `tls_provider.Provider`, and QUIC takes a
  `tls_provider.QuicProvider` and a `crypto.Suite`, and the `tls` module fills all three from
  chapulin. Over TCP, hand the session's `provider()` to the connection's `attach_tls` once
  `handshake` completes. For QUIC, hand `provider()` and `suite()` to the connection, which starts
  chapulin's session when it sets its transport parameters. A server that sends Retry packets
  checks their tokens with a `tls.quic.Retry` under a key it draws once. A program that links
  `tls` defines chapulin's one hook, `ch_assert_fail`, and passes each connection the source it
  draws from. A program without TLS never links chapulin.

A peer that breaks a protocol rule never crashes colibri. `receive` returns
`error.ConnectionFailed`, the connection names the failure, and the octets colibri owes the peer,
such as h2's GOAWAY or an h11 server's 400, are waiting to be written. A QUIC connection error
from `receive` or `send` leaves the CONNECTION_CLOSE owed, and the next `send` writes it (RFC 9000
§10.2). Over TLS, a record that does not open ends the connection, and `encrypt` called with no
plaintext writes the alert the provider owes (RFC 9846 §5.2).

## The server

The `server` module answers requests behind one set of calls, whichever version the connection
speaks ([decision 100](decisions.md)). A program makes one `server.Config`, and one
`server.Connection` for each TCP connection its listener accepts. Over TLS the connection runs the
handshake itself, and ALPN picks h2 or h11 during it. In cleartext, `Config.cleartext` names the
version.

The code in this section and the next is from
[`examples/tls_exchange.zig`](../examples/tls_exchange.zig), where `link` stands in for a
program's sockets. The server converts its TLS values once into a configuration every connection
borrows. It starts each connection with the source the connection draws from and the instants it
starts at:

```zig
try server_tls.init(.{
    .ecdsa_p256 = .{
        .chain = &chain,
        .public_key = identity.public_key,
        .private_key = identity.private_key,
    },
    .cookie_key = &cookie_key,
    .alpn = &protocols,
    .cpu = cpu,
});
server_config = .{ .tls = &server_tls };
// One call for each connection the listener accepts, in storage the program owns.
try server_connection.init(&server_config, program.random(), now_seconds, link.now_ns(.server));
```

`now_seconds` is Unix time, which the server's tickets are issued at. `now_ns` is the instant on
the clock every later call passes, and the connection's deadlines count from it.

Each turn of the program's loop reads every event that arrived, answers, and sends what the
connection owes:

```zig
const input = try link.receive(.server);
const now_ns = link.now_ns(.server);
var consumed: usize = 0;
for (0..events_per_turn_max) |_| {
    const received = try server_connection.receive(input[consumed..], now_ns);
    consumed += received.consumed;
    const event = received.event orelse {
        if (received.consumed == 0) break;
        continue;
    };
    try serve(event);
}
// What an event carried points into the queue, so the queue is consumed only now.
link.consume(.server, consumed);
try link.send(.server, output[0..server_connection.send(&output, now_ns)]);
// Decision 110: a deadline bounds how long a peer may hold the connection. `on_instant` ends
// a connection whose peer is late, at the instant the program woke at.
server_connection.on_instant(now_ns);
```

`receive` returns at most one event a call. A program loops over it until it consumes nothing and
returns no event, and loops again after each `send`. What an event carries points into the octets
the program passed, so the program keeps them until the next call.

Every event names its request by id, in h11 and h2 alike:

```zig
fn serve(event: server.Event) !void {
    switch (event) {
        .request => |request| {
            std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
            if (is(request, "GET", "/greeting")) return answer(request.id, greeting);
            // The POST's content follows in `body` events, and the answer waits for its end.
            if (is(request, "POST", "/echo")) return;
            try server_connection.respond(request.id, .{ .status = 404, .end = true });
        },
        .body => |body| {
            if (posted_len + body.octets.len > posted.len) return error.ExchangeWrong;
            @memcpy(posted[posted_len..][0..body.octets.len], body.octets);
            posted_len += body.octets.len;
            if (body.end) try answer(body.id, posted[0..posted_len]);
        },
        // The peer has the whole response to this request.
        .done => answered += 1,
        .trailers, .cancelled => {},
    }
}
```

- `request` carries the method, the target and the field lines, which `fields.find` and
  `fields.iterator` read. Its `end` says the head ended the request, so no content follows.
- `body` carries octets of the request's content, and its `end` marks the last of them. A request
  with no content may end this way too, in a `body` event with no octets, as a GET over h3 often
  does. A program that waits for a request's end reads `end` in both events.
- `trailers` carries the request's trailer section, and `cancelled` says the peer gave the request
  up.
- `done` says the peer has the whole response.

The program answers with a head, then content:

```zig
fn answer(id: server.Id, content: []const u8) !void {
    var digits: [8]u8 = undefined;
    const length = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable;
    try server_connection.respond(id, .{
        .status = 200,
        .fields = &.{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "content-length", .value = length },
        },
        .end = false,
    });
    // `write_body` returns the octets it took. It takes fewer than it was given when the room or
    // the peer's window runs out, and a program then calls it again with the rest after `send`.
    const taken = try server_connection.write_body(id, .{ .octets = content, .end = true });
    assert(taken == content.len);
}
```

A response with no content sets `end` in `respond`, and `write_trailers` ends a response with a
trailer section. `cancel` ends one request before its response is whole. `shutdown` ends the
connection once the requests it holds are answered.

A peer may hold a connection only so long ([decision 110](decisions.md)). Deadlines bound the
wait for a first request, the time between requests, a request's head and its content, and how
slowly the peer may take the response. `deadline_ns` names the soonest instant one passes, and
the program waits for octets no longer than that:

```zig
fn server_wait_ns() u64 {
    const deadline_ns = server_connection.deadline_ns() orelse return wait_ns_max;
    return @min(wait_ns_max, deadline_ns -| link.now_ns(.server));
}
```

The program then calls `on_instant` with the instant it woke at, as the turn above does, and a
connection whose peer is late ends. `receive` and `send` fire a deadline that passed too.
`Config.deadlines` sets the limits, `set_deadlines` changes one connection's, and `close_reason`
names the deadline that ended a connection, or the limit its peer passed. A program that wakes
only when octets arrive never ends a silent peer.

Three more things a server sets or watches:

- **The end.** `should_close` says when to close the transport: the connection is over and `send`
  has written everything. The program then calls `transport_closed`, which wipes the TLS
  session's secrets. When `receive` fails with `error.ConnectionFailed`, the octets colibri owes
  the peer wait for `send`, and `should_close` follows.
- **Content codings.** With `Config.codings` and an `EncoderPool` the program places, a response
  marked `codable` goes out in the coding its request accepts, gzip or deflate
  ([decision 101](decisions.md)). The program calls the pool's `reset` once, with
  `server.Features.detect()` or `.target()`, and gives its `encoders()` to the configuration.
- **h3.** `Config.h3_alternative` makes each TLS connection advertise the server's h3 endpoint
  (RFC 7838).

## The client

The `client` module sends requests behind one set of calls too. A program makes one
`client.Config` for an origin, and one `client.Connection` for each TCP connection it opens to it.
For each request it places an `HttpExchange` in its own memory: the request, and where the
response goes.

```zig
var wanted: [1]client.Wanted align(@alignOf(client.Wanted)) = .{.{ .name = "content-type" }};
var wanted_values: [content_type.len]u8 = undefined;
var get_body: [greeting.len]u8 = undefined;
var post_body: [note.len]u8 = undefined;
var get: client.HttpExchange align(@alignOf(client.HttpExchange)) = .{
    .method = "GET",
    .path = "/greeting",
    .wanted = &wanted,
    .values = &wanted_values,
    .body = &get_body,
};
var post: client.HttpExchange align(@alignOf(client.HttpExchange)) = .{
    .method = "POST",
    .path = "/echo",
    .fields = &.{.{ .name = "content-type", .value = content_type }},
    .content = note,
    .body = &post_body,
};
```

`wanted` names the fields of the response the program reads. Their values go into `values` and
the content into `body`; colibri keeps no other field. `content` is the request's own content,
which stays the program's until the exchange ends.

The client converts its TLS values once, starts the connection, and hands it the exchanges:

```zig
try client_tls.init(.{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } },
    .alpn = &protocols,
    .cpu = cpu,
});
client_config = .{ .tls = &client_tls, .authority = origin };
try client_connection.init(&client_config, program.random(), now_seconds, null);
// `request` only takes an exchange. `send` writes it once the handshake has picked the
// version, so a program asks at once and never waits for the connection.
_ = try client_connection.request(&get);
_ = try client_connection.request(&post);
```

Each turn reads every event that arrived and sends what the connection owes:

```zig
const input = try link.receive(.client);
const now_ns = link.now_ns(.client);
var consumed: usize = 0;
for (0..events_per_turn_max) |_| {
    const received = client_connection.receive(input[consumed..], now_ns);
    consumed += received.consumed;
    const event = received.event orelse {
        if (received.consumed == 0) break;
        continue;
    };
    report(event);
}
link.consume(.client, consumed);
try link.send(.client, output[0..client_connection.send(&output, now_ns)]);
```

An exchange ends in exactly one `finished` event, whatever happened to it:

```zig
fn report(event: client.Event) void {
    switch (event) {
        .connected => |protocol| {
            std.debug.print("client: connected over {s}\n", .{@tagName(protocol)});
            spoken = protocol;
        },
        .finished => |ended| {
            const exchange = ended.exchange;
            std.debug.print("client: {s}: {s}, {d}\n", .{
                exchange.path, @tagName(exchange.outcome), exchange.status,
            });
            finished += 1;
            // Every exchange has ended, so the client ends the connection.
            if (finished == exchanges_count) client_connection.shutdown();
        },
        // This client opens no second connection, so it wipes the ticket a server gives it.
        .ticket => if (client_connection.take_ticket()) |ticket| {
            var held = ticket;
            held.wipe();
        },
        .draining, .closed => {},
    }
}
```

The exchange's `outcome` says what happened:

| Outcome | What it means |
| --- | --- |
| `response` | The final response arrived whole: `status`, `content_received()`, and each wanted value. |
| `refused` | The server processed none of the request, so the program may send it on another connection. |
| `reset` | The server reset the stream, and `error_code` names why. |
| `closed` | The connection ended before the response was whole. The server may have processed the request. |
| `malformed` | colibri refused the response, because the protocol's rules make it malformed. |
| `invalid` | The request is one the protocol refuses to send. |
| `too_large` | The content did not fit `body`, or a wanted value did not fit `values`. |

`connected` reports the version ALPN picked. `ticket` says the server issued a resumption ticket:
`take_ticket` hands it over, and a later connection offers it through `init`'s last argument.
`draining` says the server takes no new request on this connection, and `closed` that the
connection is over.

Both sides end the same way:

```zig
// `should_close` says when to close the transport: the connection is over and `send` has
// written everything, the TLS close_notify too. `transport_closed` then wipes the session's
// secrets.
client_connection.transport_closed();
server_connection.transport_closed();
```

A client that decodes content codings names them in `Config.codings`, and places the pool of
decoders each needs ([decision 101](decisions.md)).

## h3: the endpoint and the channel

Over QUIC the same events and the same calls serve h3. What changes is what carries them: a
program moves datagrams with addresses in place of a stream of octets, and it keeps time for the
connection. The code in this section is from
[`examples/h3_exchange.zig`](../examples/h3_exchange.zig), where `link` stands in for a program's
UDP sockets.

### The server's endpoint

A `server.Endpoint` holds every QUIC connection behind one UDP socket
([decision 103](decisions.md)). `server.EndpointOf(connections_max, receive_capacity)` makes one of
another size: the connections it holds at once, and the octets each holds unread. Its TLS
configuration names "h3" in its ALPN list:

```zig
try server_tls.init(.{
    .ecdsa_p256 = .{
        .chain = &chain,
        .public_key = identity.public_key,
        .private_key = identity.private_key,
    },
    .cookie_key = &cookie_key,
    .alpn = &.{"h3"},
    .cpu = cpu,
});
server_quic = .{ .tls = &server_tls };
endpoint_config = .{ .quic = &server_quic };
// One endpoint for the program's UDP socket. It starts a connection from each client's first
// datagram, in a slot of its own.
endpoint.init(&endpoint_config, program.random(), now_seconds, link.now_ns(.server));
```

The program passes the endpoint each datagram with the address it came from. The endpoint finds
the connection the datagram's connection ID names, or starts one from a client's first datagram,
and answers Version Negotiation and Retry itself. It returns the connection that took the
datagram:

```zig
fn server_turn() !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try link.receive(.server) orelse break;
        const now_ns = link.now_ns(.server);
        // The endpoint finds the connection the datagram's connection ID names, or starts one.
        if (endpoint.receive(datagram, .not_ect, client_address, now_ns)) |connection| {
            try serve(connection, now_ns);
        }
        link.consume(.server);
    }
    const now_ns = link.now_ns(.server);
    endpoint.on_instant(now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = endpoint.send(&output, now_ns) orelse break;
        try link.send(.server, sent.octets);
    }
    // A connection that is over comes back once, and its slot is free for a later client.
    if (endpoint.ended()) |_| ended += 1;
}
```

The program drives that connection with the calls of a TCP connection: one event from each
`receive`, and `respond`, `write_body` and `write_trailers` by the request's id.

```zig
fn serve(connection: *server.QuicConnection, now_ns: u64) !void {
    for (0..events_per_datagram_max) |_| {
        const received = try connection.receive(now_ns);
        switch (received.event orelse return) {
            .request => |request| {
                std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
                try connection.respond(request.id, .{
                    .status = 200,
                    .fields = &.{.{ .name = "content-type", .value = content_type }},
                    .end = false,
                });
                // Over QUIC `write_body` copies nothing, because QUIC reads the octets again to
                // send them again. They stay the program's until the request is `done` or
                // `cancelled`, or until `ended` hands its connection back.
                _ = try connection.write_body(request.id, .{ .octets = greeting, .end = true });
                answered += 1;
            },
            // The client acknowledged every octet of the response. A client that closes its
            // connection first, as this one does, ends the connection instead.
            .done => |done| std.debug.print("server: request {d} is acknowledged\n", .{done.id}),
            .body, .trailers, .cancelled => {},
        }
    }
}
```

Three things differ from TCP:

- **Content is not copied.** QUIC reads the program's octets again whenever it sends them again.
  They stay the program's until the request is `done` or `cancelled`, or until `ended` hands its
  connection back. `done` comes once the peer has acknowledged every octet of the response.
- **Time.** `deadline_ns` names the instant the endpoint next needs `on_instant`: for loss
  recovery, acknowledgments and idle timeouts. A program sleeps until then when no datagram
  arrives. The deadlines of [decision 110](decisions.md) bound a TCP connection alone. Over h3,
  `QuicConfig.idle_timeout_ms` ends a silent peer, and nothing yet bounds a slow one.
- **The end.** `ended` hands back each connection that is over, once, and a later client takes
  its slot.

`EndpointConfig.retry` makes every client prove its address before a connection starts (RFC 9000
§8.1.2), and `EndpointConfig.logs` gives each connection a qlog log
([decision 102](decisions.md)).

### The client's channel

A `client.Channel` carries a program's exchanges to one origin over QUIC or over TCP, and tells
the program which transport to open ([decision 105](decisions.md)). The program passes what DNS
knows as values: the server's addresses and its port, and an HTTPS record's `alpn` and `port` when
it has one.

```zig
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
```

The channel takes a configuration for each transport, and the pool its QUIC connection holds the
server's unread octets in: `client.ReceivePool(capacity)`, sized to the longest response the
program expects.

Each turn passes the channel every datagram that arrived, fires its deadlines, and sends every
datagram it owes:

```zig
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
```

After each of those, the program loops over `receive` until the channel consumes nothing and
reports nothing:

```zig
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
```

The channel's events say what the program does next:

```zig
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
```

- `open` names a transport and where it goes. The program opens a UDP flow or a TCP connection
  there, then calls `start_quic` or `start_tcp`. QUIC goes first when the origin is known to speak
  h3, or when `ChannelConfig.quic_first` says to try it. TCP opens when QUIC fails or
  `fallback_delay_ns` passes, and the first connection whose handshake completes takes the
  exchanges.
- `close` names a transport the program closes.
- `connected`, `ticket` and `finished` mean what they mean on a TCP connection, and `closed` says
  the channel was shut down and every transport is closed.

A program that opens TCP passes what its socket read as `.stream` input, and sends what
`send_stream` writes. It starts a QUIC connection with values it draws at random:

```zig
fn start_quic(now_ns: u64) void {
    var start: client.QuicStart = undefined;
    program.fill(&start.source_id);
    program.fill(&start.original_destination_id);
    program.fill(std.mem.asBytes(&start.grease));
    // A start the TLS stack refuses ends the attempt, which the channel reports.
    channel.start_quic(start, program.random(), now_seconds, now_ns, null) catch {};
}
```

Both sides sleep until the sooner of their deadlines when no datagram waits:

```zig
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
```

## The protocol modules

The sections below are for a program that wants one version by itself: h11 or h2 with no TLS or
with a TLS stack of its own, or QUIC without HTTP. The `server` and `client` modules are built on
the same calls.

## h11

One `h11.connection.Connection` is one HTTP/1.1 connection. `receive(input, decoded)` consumes the
octets of at most one event: a head, a run of body data, or the end of a body. Loop over it until
it consumes nothing and returns no event. `decoded` is where the body of a message coded with
`gzip` or `deflate` goes; a program that places no decoders passes it empty.

The code below is from [`examples/h11_exchange.zig`](../examples/h11_exchange.zig), where `link`
stands in for a program's socket. A client writes a request head into a buffer it owns and sends
it. This one sends the body from its own buffer, so `count_body` counts it against the
Content-Length and colibri copies none of it (decision 95); `write_body` would copy it into the
output buffer instead:

```zig
const put_len = try client.write_request(&output, "PUT", "/upload", &.{
    .{ .name = "Host", .value = host },
    .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{upload.len}) },
});
try link.send(.client, output[0..put_len]);
try client.count_body(upload.len);
try link.send(.client, upload);
_ = try client.write_end(&output, &.{});
```

A client pipelines requests and gives each response to the oldest one. It stops pipelining after
a request whose method is not idempotent until that request has its final response (decision 88).

A server hands colibri what arrived and answers each request once it has read it. A request with
no body ends with its head, so no `end` event follows it:

```zig
const step = try server.receive(input, &.{});
if (step.event) |event| switch (event) {
    .request => |request| {
        std.debug.print("server: {s} {s}\n", .{ request.line.method, request.line.target });
        resource = resource_of(request.line.target);
        // A request without a body ends with its head, and no `end` event follows.
        if (ends_with_head(request.body)) {
            try respond(resource);
            answered += 1;
        }
    },
    .data => |data| try store(data),
    .end => {
        try respond(resource);
        answered += 1;
    },
    else => {},
};
// The event's slices point into the queue, so it is consumed only once they are used.
link.consume(.server, step.consumed);
```

Answering is a head, the body, and the end, each written into the output buffer:

```zig
const head_len = try server.write_response(&output, 200, "OK", &.{
    .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{greeting.len}) },
});
const written = head_len + try server.write_body(output[head_len..], greeting);
_ = try server.write_end(output[written..], &.{});
try link.send(.server, output[0..written]);
```

A server reads one request at a time: it reads the next only after the final response to the
current one is written. When `receive` fails, `has_pending` says colibri owes an error response,
`write_pending` writes it, and the connection then closes (decision 92). `should_close` says when
to close the transport, and `transport_closed` reports what a close cut short.

Over TLS, call `attach_tls` once the handshake completes, and pass every record through
`h11.connection_tls`'s `decrypt` and `encrypt`.

### The gzip and deflate transfer codings

A body may arrive coded with `gzip` or `deflate` under `chunked` (RFC 9112 §7.2). stdx decodes it,
and each decoder holds a window of 32,768 octets, so a connection keeps none of its own. Your
program places a pool, `h11.coding.DefaultPool` or `h11.coding.Pool(count)`, calls
`storage().reset(features)` on it once, and gives the storage to each connection in
`Options.decoders`. Connections share the pool, and one takes a decoder only while a message
carries a coding (decision 91). `features` is `h11.coding.Features.detect()` to use the CPU's
fastest paths, or `.target()` for what the build target guarantees; colibri never asks the CPU
itself.

With a pool, `receive` decodes straight into the `decoded` buffer you pass it, and each `data`
event is a slice of that buffer, valid until you pass it again (decision 98). A larger buffer means
fewer calls. A server answers a coded request 501 when it has no pool, 503 when every decoder is
taken, 400 when the body is corrupt, and 501 when it uses a feature stdx refuses. A client with a
pool offers both codings in TE (RFC 9112 §7.4), and one without refuses a response that uses them.

## h2

One `h2.connection.Connection` is one HTTP/2 connection. `receive(input, now_ns)` consumes at most
one whole frame and returns at most one event. When it consumes nothing, `has_pending` says
whether colibri must write first, and `write_pending(output, now_ns)` writes the connection
preface, colibri's SETTINGS, and every frame it owes: acknowledgments, WINDOW_UPDATE, RST_STREAM
and GOAWAY.

Each side of [`examples/h2_exchange.zig`](../examples/h2_exchange.zig) runs this loop once a
round: it reads every frame that arrived, then writes what colibri owes, with what the server's
answer adds in between:

```zig
const input = try link.receive(side);
var consumed: usize = 0;
for (0..frames_per_round_max) |_| {
    const received = try connection.receive(input[consumed..], link.now_ns(side));
    if (received.event) |event| handle(side, event, state);
    consumed += received.consumed;
    if (received.consumed == 0) break;
}
// Every slice an event carried points into the queue, so it is consumed only now.
link.consume(side, consumed);
// What colibri owes goes first: a server's SETTINGS must be the first frame it sends
// (RFC 9113 §3.4). Anything the answer made owed goes out after it.
var written = connection.write_pending(&output, link.now_ns(side));
if (side == .server and state.request_stream != null and !state.answered) {
    written += try answer(output[written..], state.request_stream.?);
    state.answered = true;
}
written += connection.write_pending(output[written..], link.now_ns(side));
try link.send(side, output[0..written]);
```

Events are a request or a response head with its field section (`connection.field_section()`),
trailers, data, a stream the peer reset or colibri refused, the peer's GOAWAY, and the SETTINGS
exchange. `event.ended_stream()` names the stream an event ended, whichever of the request,
response, DATA or trailers ended it. A client opens a stream with `write_request`, a server
answers with `write_response`, and both send content with `write_data`, which writes as much as
the flow-control windows allow. `write_trailers` ends either side's message with a trailer
section, after its final header section (RFC 9113 §8.1). `reset_stream` ends one stream, and the
next `write_pending` writes its RST_STREAM: it needs no room, however many streams the caller
resets between two writes (decision 113). `shutdown` begins a graceful close.

## TLS

The `tls` module runs chapulin's TLS 1.3 sessions behind the vtables h11, h2 and QUIC take. A
program that links it defines chapulin's one hook, `ch_assert_fail`, which a failed chapulin
assertion calls.

```zig
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}
```

Each session draws its randomness from a `std.Random` the program passes to its `start`, and
from nothing else (decision 94 as amended). A program that seeds that source replays the session.
This one reads the operating system's `getentropy`:

```zig
extern "c" fn getentropy(buffer: [*]u8, len: usize) c_int;
const getentropy_len_max = 256;
var entropy_state: u8 = 0;
const entropy: std.Random = .{ .ptr = &entropy_state, .fillFn = fill_entropy };

fn fill_entropy(_: *anyopaque, buffer: []u8) void {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const part = @min(buffer.len - filled, getentropy_len_max);
        if (getentropy(buffer[filled..].ptr, part) != 0) @panic("getentropy failed");
        filled += part;
    }
}
```

The program converts its values once into a configuration, which every session of one chapulin
object borrows. It then starts a session for each connection. Over TCP, `handshake` takes what the
socket read and writes what the session owes the peer. Once the handshake completes, the session's
`provider()` goes to the connection's `attach_tls`. When it fails, `failure_written()` counts the
octets it wrote at the front of the output, the alert that says why last (RFC 9846 §6.2). The
program sends them, then closes the connection. An output of
`tls.record.Client.handshake_output_len_min` octets takes all a client owes in one call. Each
configuration names the most anchors and ALPN protocols it takes, `anchors_max` and
`protocols_max`.

Every configuration also takes `cpu`, which has no default: the `platform.Cpu` that
`platform.probe()` returned. colibri probes nothing. A program probes its CPU once, at start, and
passes the result to each configuration. Only an `aes_clmul` of `yes` lets a session run the AES
instructions. Under `no` or `not_known` a session runs none and holds TLS_CHACHA20_POLY1305_SHA256
alone.

```zig
const cpu = platform.probe();
const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
try tls_config.init(.{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } },
    .alpn = &.{ "h2", "http/1.1" },
    .cpu = cpu,
});
try tls_client.start(&tls_config, entropy, now_seconds, null);
const hello = try tls_client.handshake(&.{}, &output);
```

For QUIC, a `tls.quic.Client` or `tls.quic.Server` hands `provider()` and `suite()` to the
`quic.Connection`, which starts chapulin's session when it sets its transport parameters. A server
that sends Retry packets mints and checks their tokens with a `tls.quic.Retry`.

## QUIC and h3

A `quic.connection.Connection` is one QUIC connection. Your program moves datagrams and time
through four calls:
- `quic.connection_datagram.receive` takes one datagram the peer sent, with its ECN marking and
  its source address.
- `quic.connection_send.send` writes the next datagram colibri owes into your buffer, or returns
  null when it owes nothing.
- `quic.connection_timer.next` names the instant the connection next needs to run, for loss
  detection, acknowledgments and idle timeout.
- `quic.connection_timer.on_instant` runs what that instant is for.

Streams are yours: a `StreamProvider` your program passes to `send` hands colibri the octets of
each stream as the flow-control windows allow.

An `h3.connection.Connection` runs HTTP/3 over one QUIC connection. After each datagram, call its
`receive` until it returns null; each call returns at most one event. `provider` wraps your stream
provider so that h3 serves its control and QPACK streams itself. `write_request`,
`write_response`, `write_trailers` and `write_data_header` write frames into your buffer, and you
send the content behind them on the request stream. Each h3 call that writes or reads a frame
takes the instant, as QUIC's calls do.

To log a connection as qlog ([decision 102](decisions.md)), place a `qlog.Log` over a buffer
with `Log.init(buffer, features)`, write its header with `Log.start`, and pass it as the `qlog`
option of both the QUIC connection and the h3 connection, so one trace holds both. `features` is
`qlog.Features.detect()`, called once, or `qlog.Features.target()`: colibri never asks the CPU
itself, and the records are the same octets either way. colibri appends one record per event; your
program writes `log.bytes()` where it wants, a file under `QLOGDIR` for example, and calls
`log.clear()`. `tools/qlog_to_qvis.py` converts such a file for qvis.

[`src/testing/quic/udp/udp_peer.zig`](../src/testing/quic/udp/udp_peer.zig) is a whole QUIC
endpoint over UDP, and [`src/testing/quic/h3/`](../src/testing/quic/h3/) holds the h3 server and
client built on it.

## Sizes

Every connection is a struct your program places, and its size is fixed at compile time. These are
`@sizeOf` in ReleaseSafe with Zig 0.16.0 on aarch64 macOS, on 2026-09-26:

| Struct | Octets |
| --- | --- |
| `h11.connection.Connection` | 35,040 |
| `h11.coding.DefaultPool` | 691,472, 16 decoders the connections given it share |
| `h2.connection.Connection` | 162,192 |
| `quic.connection.Connection` | 141,232 |
| `h3.connection.Connection` | 145,496, beside the QUIC connection it runs over |

The buffers your program reads into and writes from come on top, and QUIC's calls also take
scratch storage your program places; `udp_peer.zig` shows both.

A client that decodes `zstd` or `br` places a pool of decoders for each. Measured the same way on
2026-09-30, each decoder of a `client.ZstdDecoderPool(count)` is 8,683,024 octets, most of them RFC
9659 §3's 8 MB window, and each of a `client.BrotliDecoderPool(count)` is 19,483,040, most of them
RFC 7932 §9.1's 16 MiB window. An exchange takes a decoder of each coding it offers as its request
goes out, and keeps only the one its response uses once the response's head arrives
([decision 101](decisions.md)).

The named limits in each module's `constants.zig` set these sizes, and
[`docs/decisions.md`](decisions.md) records why each limit has its value.
