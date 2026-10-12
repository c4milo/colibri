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
| `server` | Responses to h11, h2 and h3 requests behind one set of calls, with each TLS handshake run inside it ([decision 100](decisions.md)). An `Endpoint` holds the TCP connections you accept, which serve h11 or h2, and the QUIC connections that serve h3 behind one UDP socket you own ([decision 119](decisions.md)). |
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

- **Your program owns every struct and buffer.** Declare a connection, or a server's endpoint,
  where you like: in a static, in an array, or inside a larger struct. Nothing points at the
  heap. Place large ones outside the stack.
- **Your program does the I/O.** Read octets from the socket, hand them to `receive`, and send
  the octets colibri puts in your buffer: a protocol module's `write_*` calls, and a server
  endpoint's `send_stream` and `send_datagram`. colibri never waits: when it needs more
  octets, `receive` consumes none and returns no event.
- **Your program passes the time.** A call that needs the current instant takes `now_ns`, in
  nanoseconds from any fixed origin. The same instants and the same octets give the same output,
  which is what lets the simulator replay a connection.
- **Your program configures TLS.** The `server` module takes the server's identity in its
  `server.Config`, builds the TLS configuration of each transport from it, and runs each
  handshake itself. Elsewhere, convert your values once into a configuration:
  `tls.record.ClientConfig` or `ServerConfig` over TCP, `tls.quic.ClientConfig` or `ServerConfig`
  for QUIC. The `client` module takes the configuration and runs each handshake itself. A program
  that drives a protocol module by itself starts a session of the matching
  kind for each connection: h11 and h2 take a `tls_provider.Provider`, and QUIC takes a
  `tls_provider.QuicProvider` and a `crypto.Suite`, and the `tls` module fills all three from
  chapulin. Over TCP, hand the session's `provider()` to the connection's `attach_tls` once
  `handshake` completes. For QUIC, hand `provider()` and `suite()` to the connection, which starts
  chapulin's session when it sets its transport parameters. A server that sends Retry packets
  checks their tokens with a `tls.quic.Retry` under a key it draws once. A program that links
  `tls` defines chapulin's one hook, `ch_assert_fail`, and passes the source each session draws
  from: once to `Endpoint.init` for a server, and to each client connection or session it starts.
  A program that imports none of `tls`, `server` and `client` never links chapulin.

A peer that breaks a protocol rule never crashes colibri. A connection's `receive` returns
`error.ConnectionFailed`, the connection names the failure, and the octets colibri owes the peer,
such as h2's GOAWAY or an h11 server's 400, are waiting to be written. A server's endpoint returns
no error. For a TCP connection it reports a `send` for the octets it owes, then `close`, then the
connection's `ended` with `failed` set. For a QUIC connection its `send_datagram` writes the
CONNECTION_CLOSE, and `ended` follows with `failed` set once the closing period ends. A QUIC
connection error
from `receive` or `send` leaves the CONNECTION_CLOSE owed, and the next `send` writes it (RFC 9000
§10.2). Over TLS, a record that does not open ends the connection, and `encrypt` called with no
plaintext writes the alert the provider owes (RFC 9846 §5.2).

## The server

The `server` module answers requests behind one set of calls, whichever version the connection
speaks ([decision 100](decisions.md)). An endpoint is the server side of every connection one
thread serves: RFC 9000 §1.2 and RFC 9113 §2.2 give the word to the client or the server of a
connection, and a server has many connections. A program makes one `server.Config` and one
endpoint for each thread that serves, and calls `accept` for each TCP socket its listener accepts
([decision 119](decisions.md)). The endpoint holds every connection, and a
`server.ConnectionHandle` names one. Over TLS the
connection runs the handshake itself, and ALPN picks h2 or h11 during it. In cleartext, a
connection speaks h2 when its first octets are h2's connection preface and h11 otherwise (RFC 9113
§3.3, [decision 117](decisions.md)). The configuration's `versions` turns either version off, in
cleartext and over TLS: the endpoint builds its ALPN list from `versions`, so the TLS identity
names no protocol.

The code in this section and the next is from
[`examples/tls_exchange.zig`](../examples/tls_exchange.zig), where `link` stands in for a
program's sockets. An endpoint's size is fixed at build time. `server.Endpoint` holds 16 TCP
connections and 16 QUIC connections, and `server.EndpointOf` makes one of another size. This
server has no UDP socket, so its endpoint holds no QUIC connection:

```zig
const Endpoint = server.EndpointOf(.{ .tcp_connections = 2, .quic_connections = 0 });
```

The configuration holds the server's TLS identity. `init` builds the endpoint's TLS configuration
from it and checks that the key signs, so a program learns of a bad identity before it serves. The
program then calls `accept` for each socket, with whether the socket runs TLS:

```zig
endpoint_config = .{
    // The identity names no protocol: the endpoint offers h2 and h11 through ALPN, as
    // `versions` allows by default.
    .tls = .{
        .ecdsa_p256 = .{
            .chain = &chain,
            .public_key = identity.public_key,
            .private_key = identity.private_key,
        },
        .cookie_key = &cookie_key,
        .cpu = cpu,
    },
};
const now_ns = link.now_ns(.server);
// One endpoint for every socket the program accepts, in storage the program owns. `init`
// checks that the key signs.
try endpoint.init(&endpoint_config, program.random(), now_seconds, now_ns);
// One call for each socket the listener accepts, with whether the socket runs TLS. The handle
// names the connection in every later call and event. Null says the endpoint starts no
// connection, and a program then closes the socket.
accepted = endpoint.accept(.tls, now_ns) orelse return error.ExchangeWrong;
```

`now_seconds` is Unix time, which the server's tickets are issued at. `now_ns` is the instant on
the clock every later call passes, and a connection's deadlines count from the instant its
`accept` is given. `accept` returns null when no slot is free, after `shutdown`, when `versions`
allows neither h11 nor h2, or when the TLS stack refuses to start a session. The program closes
the socket then. A program passes `.tls` only when its configuration holds an identity. The
endpoint reads the configuration while it runs and keeps pointers into itself, so the program
keeps both where `init` found them.

Each turn of the program's loop fires the deadlines that passed, passes the endpoint the octets a
socket read, and acts on every event the endpoint reports:

```zig
const input = try link.receive(.server);
const now_ns = link.now_ns(.server);
// Decision 110: a deadline bounds how long a peer may hold a connection. `on_instant` ends
// each connection whose peer is late, at the instant the program woke at, and the `receive`
// calls below report what that leaves the program to do.
endpoint.on_instant(now_ns);
var consumed: usize = 0;
for (0..events_per_turn_max) |_| {
    // The handle says which connection's socket read the octets.
    const read: server.StreamOctets = .{ .connection = accepted, .octets = input[consumed..] };
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
```

`receive` returns at most one event a call, of any connection the endpoint holds. A program loops
over it until it consumes nothing and returns no event. It loops again after every call that
changes a connection: an answer, `cancel`, `send_stream`, `transport_closed`, `shutdown` and
`on_instant`. Each leaves what follows it to the next `receive`, the release of a closed
connection's slot included. The program passes `.stream` with the octets a socket
read and the handle of that socket's connection, and `.none` when no socket read any. A connection
may consume fewer octets than it was given, such as a pipelined h11 request while the one before
it is answered. The program holds the rest, and passes it again with the socket's next read and
after each event that names the connection. The turn above passes what is left after every event.
What an event carries points into the octets the program passed or into the connection, and stays
valid until the next `receive`, `on_instant`, `send_stream`, `send_datagram`, `accept`,
`transport_closed` or `shutdown`.

An event names a request by its id, in h11 and h2 alike, or a connection by its handle. The id
names the request's connection too, so the program answers by the id alone:

```zig
fn serve(event: server.Event, now_ns: u64) !void {
    switch (event) {
        .request => |request| {
            std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
            if (is(request, "GET", "/greeting")) return answer(request.id, greeting);
            // The POST's content follows in `body` events, and the answer waits for its end.
            if (is(request, "POST", "/echo")) return;
            try endpoint.respond(request.id, .{ .status = 404, .end = true });
        },
        .body => |body| {
            if (posted_len + body.octets.len > posted.len) return error.ExchangeWrong;
            @memcpy(posted[posted_len..][0..body.octets.len], body.octets);
            posted_len += body.octets.len;
            if (body.end) try answer(body.id, posted[0..posted_len]);
        },
        // The response to this request is whole: colibri reads none of the program's octets for
        // it again.
        .done => answered += 1,
        // The connection owes its socket octets.
        .send => |connection| try flush(connection, now_ns),
        // colibri reads and writes nothing more on this connection. A program closes the socket
        // once the socket has taken the octets `send_stream` returned, and owes the endpoint no
        // call: the connection's `ended` follows by itself.
        .close => closes += 1,
        // The connection is over, and its slot takes a later socket.
        .ended => |over| try count_ended(over),
        .trailers, .cancelled, .writable => {},
        // Only a shutdown ends in `closed`.
        .closed => unreachable,
    }
}
```

- `request` carries the method, the target and the field lines, which `fields.find` and
  `fields.iterator` read. Its `end` says the head ended the request, so no content follows.
- `body` carries octets of the request's content, and its `end` marks the last of them. A request
  with no content may end this way too, in a `body` event with no octets, as a GET over h3 often
  does. A program that waits for a request's end reads `end` in both events.
- `trailers` carries the request's trailer section.
- `done` says the response is whole, and colibri reads none of the program's octets for it again.
  `cancelled` says the request ended before its response did, and its `reason` says why. Every
  request ends with one of the two.
- `writable` says a response whose last write found no room can take more.
- `send` says a connection owes its socket octets, `close` says the program closes a connection's
  socket, and `ended` says a connection is over. The paragraphs below describe each.

A client that puts `100-continue` in a request's `Expect` field waits for a 100 (Continue) before
it sends the content (RFC 9110 §10.1.1). The connection writes that 100 when the endpoint next
reads the connection or writes its octets, in every version. That may be at the program's next
call. An answer the program gives first takes the place of the 100. A program that refuses such a
request therefore answers it before its next call: a final response, the program's own 100, or `cancel`
takes the place of the 100 the connection owes.

The program answers with a head, then content:

```zig
fn answer(id: server.Id, content: []const u8) !void {
    var digits: [8]u8 = undefined;
    const length = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable;
    try endpoint.respond(id, .{
        .status = 200,
        .fields = &.{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "content-length", .value = length },
        },
        .end = false,
    });
    // `write_body` returns the octets it took. It takes fewer than it was given when the room or
    // the peer's window runs out, and the request's `writable` event then says when to write the
    // rest.
    const taken = try endpoint.write_body(id, .{ .octets = content, .end = true });
    assert(taken == content.len);
}
```

A response with no content sets `end` in `respond`, and `write_trailers` ends a response with a
trailer section. A write can find no room: `write_body` takes fewer octets than it was given, or any
of the three calls returns `error.Blocked` or `error.NoSpaceLeft`. `write_body` most often returns
`error.Blocked`, and `respond` and `write_trailers` `error.NoSpaceLeft`. Either way the endpoint
reports `writable` for the request once the response has room, and the program writes again. `cancel` ends one request before its response is whole, and its `cancelled` follows with
the reason `program`. `shutdown` ends every connection once the requests it holds are answered,
and the `closed` event follows once every connection has ended.

The endpoint reports `send` when a connection owes its socket octets. The program calls
`send_stream` for that connection until a call leaves room in the buffer, and writes what each
call returns to the connection's socket:

```zig
for (0..sends_per_event_max) |_| {
    const written = endpoint.send_stream(connection, &output, now_ns);
    try link.send(.server, output[0..written]);
    if (written < output.len) return;
}
return error.SendUnfinished;
```

A call that fills the buffer leaves more owed. A call that leaves room ends the `send`, and the
endpoint reports another once the connection owes more. A program whose socket is full stops
calling, and calls again when the socket takes more. A program may also call `send_stream` for an
open connection without waiting for a `send`, such as straight after it writes a response.

A peer may hold a connection only so long ([decision 110](decisions.md)). Deadlines bound the
wait for a first request, the time between requests, a request's head and its content, and how
slowly the peer may take the response. The endpoint's `deadline_ns` names the soonest instant one
passes, on any connection it holds, and the program waits for octets no longer than that:

```zig
fn server_wait_ns() u64 {
    const deadline_ns = endpoint.deadline_ns() orelse return wait_ns_max;
    return @min(wait_ns_max, deadline_ns -| link.now_ns(.server));
}
```

The program then calls `on_instant` with the instant it woke at, as the turn above does, and a
connection whose peer is late ends. Over h2, a request whose content is late may end by itself,
with a `cancelled` whose reason names the deadline. `receive` and `send_stream` fire a deadline
that passed too, on the connection they read or write. The configuration's `deadlines` sets the
limits, and `set_deadlines` changes one connection's, by its handle. A program that wakes only
when octets arrive never ends a silent peer.

A connection's socket closes in one of two ways. The endpoint reports `close` once the connection
has finished and `send_stream` has written every octet it owed, the TLS close_notify too, or once
the `linger_ns` deadline passes with octets still owed. The program closes the socket once
the socket has taken the octets `send_stream` returned, and owes the endpoint no call. After a
linger there are none to wait for: colibri dropped what it still owed. Or the peer closes the socket first, or the socket fails, and the
program tells the endpoint with `transport_closed`. The example accepts a second socket to show
that call, a socket its peer closes before it sends an octet:

```zig
const closed = endpoint.accept(.tls, link.now_ns(.server)) orelse return error.ExchangeWrong;
// The peer closed the socket first, so the program closes its own end and tells the endpoint.
// A program calls `transport_closed` then, and when a socket fails. The connection's `ended`
// follows, with no `close`.
endpoint.transport_closed(closed);
```

Either way colibri reads and writes nothing more on the connection, and wipes its TLS session's
secrets. The endpoint then reports the `done` of each response written whole, the `cancelled` of
each other request with the reason `closed`, and last the connection's `ended`, once. A later
socket takes the connection's slot, and the ended connection's handle and every id on it name
nothing from then on. `ended` carries two more fields:

- `reason` names the deadline that passed, or the limit the peer passed, when colibri closed the
  connection for one. It is null otherwise.
- `failed` says colibri closed the connection because its peer broke a protocol rule or its record
  layer failed. The endpoint reports a `send` for what colibri owes that peer, such as h2's
  GOAWAY or an h11 server's 400, before the `close`.

`ended` follows a `close` with no call from the program, so it may come while the program's socket
still writes its last octets or waits for its close to complete. A later connection may then take
the slot while that socket is still open. A program that keeps state for each socket therefore
keeps the connection's whole handle with it, and does not index the state by the handle's `slot`
alone: it maps a slot to the state of the connection the slot holds now.

Three more things a server sets:

- **Content codings.** With the configuration's `codings` and an `EncoderPool` the program places,
  a response marked `codable` goes out in the coding its request accepts, gzip or deflate
  ([decision 101](decisions.md)). The program calls the pool's `reset` once, with
  `server.Features.detect()` or `.target()`, and gives its `encoders()` to the configuration.
- **h3.** The configuration's `h3_alternative` makes each TLS connection advertise the server's h3
  endpoint (RFC 7838).
- **Bounds.** The configuration's `limits` holds the bounds of each connection, named by what they
  bound: `requests_max`, the requests a connection holds at once, and `data_frame_len_min`, the
  shortest DATA frame h2 sends when a window, not the content, decides its length
  ([decision 110](decisions.md)).

## The client

The `client` module sends requests behind one set of calls too. A program makes one
`client.Config` for an origin, and one `client.Connection` for each TCP connection it opens to it.
In cleartext a connection speaks h11, or h2 with prior knowledge when `Config.versions` turns h11
off ([decision 117](decisions.md)). Over TLS, ALPN picks.
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

The client closes its transport once `should_close` says so, and then tells its connection:

```zig
// The client's `should_close` says when to close its transport: the connection is over and
// `send` has written everything, the TLS close_notify too. `transport_closed` then wipes the
// session's secrets.
client_connection.transport_closed();
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

The endpoint of [The server](#the-server) holds QUIC connections too, all of them behind one UDP
socket ([decision 103](decisions.md)), each in a slot of its own. The `server.Capacity` that
`server.EndpointOf` takes names the TCP and the QUIC connections the endpoint holds at once, and
the octets each QUIC connection holds unread. The `server.Config` gives the server's TLS
identity once, with no protocol named: the endpoint names h3 itself for its QUIC connections (RFC
9114 §3.1). `init` builds the TLS configuration of each transport from it and checks that the key
signs, so a program learns of a bad identity before it serves:

```zig
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
```

`versions` and `limits` mean what they mean over TCP. With h3 turned off, or with no identity,
an endpoint that serves no TCP version returns `error.NoVersion` from `init`, and one that also
serves TCP starts no QUIC connection. `limits.requests_max` bounds the request streams a client opens
at once, up to `server.constants.quic_requests_max`.

The program passes the endpoint each datagram with the address it came from, as a
`server.Input`. The endpoint finds the connection the datagram's connection ID names, or starts
one from a client's first datagram, and answers Version Negotiation and Retry itself. After a
datagram and after `on_instant`, the program calls `receive` with `.none` until it reports
nothing:

```zig
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
```

Each `receive` reports one event of any connection. A request's id names its connection, so the
program answers it by that id alone, with `respond`, `write_body` and `write_trailers`:

```zig
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
```

Every request ends with one `done` or `cancelled`, and a connection's `ended` comes after its
requests' endings ([decision 119](decisions.md)). `set_user_data` sets a word that each later event
of a request carries back, so a program finds its own state for the request without a lookup.
`cancel` ends a request the program gives up on, and its `cancelled` follows with the reason
`program`. A connection that stops with requests open ends each with `cancelled` and the reason
`closed`.

A response can find no room. `write_body` takes less than it was given, or returns
`error.Blocked`. `respond` or `write_trailers` returns `error.NoSpaceLeft`, or `write_trailers`
returns `error.Blocked` while a coded response's last octets wait. Over QUIC, room comes back only
as the client acknowledges what was sent (RFC 9000 §3.1). The endpoint then reports `writable` for
the request, once, and the program writes again. A head or a trailer section larger than the room
the response's earlier frames leave waits until the client has acknowledged all of them.

Two things differ from TCP:

- **Content is not copied.** QUIC reads the program's octets again whenever it sends them again.
  They stay the program's until the request is `done` or `cancelled`. `done` comes once the peer
  has acknowledged every octet of the response.
- **Time.** `deadline_ns` names the instant the endpoint next needs `on_instant`: for loss
  recovery, acknowledgments and idle timeouts, and for the deadlines of
  [decision 110](decisions.md), which bound an h3 connection as they bound a TCP one. A program
  sleeps until then when no datagram arrives. `Config.deadlines` sets the limits, and
  `Endpoint.init` refuses limits a connection would refuse, with `error.DeadlineInvalid`.
  `set_deadlines` changes one connection's limits, by its handle. `Config.idle_timeout_ms`
  is QUIC's own idle timeout, which ends a peer that sends nothing at all.

`ended` means what it means over TCP. Its `reason` names the deadline that ended the connection,
or the limit its client passed, and `failed` says colibri closed it because its client broke a rule
of the protocol. A later client then takes its slot, and every id of the ended connection names
nothing. A QUIC connection has no socket of its own, so the endpoint reports no `send` and no
`close` for one.

`Config.retry` makes every client prove its address before a connection starts (RFC 9000
§8.1.2), and `Config.logs` gives each connection a qlog log
([decision 102](decisions.md)).

The same endpoint holds TCP connections, `Capacity.tcp_connections` of them, 16 by default, and
[The server](#the-server) shows the calls a program makes for them. A program that serves QUIC
alone sets `.tcp_connections = 0`.

### The client's channel

A `client.Channel` carries a program's exchanges to one origin over QUIC or over TCP, and tells
the program which transport to open ([decision 105](decisions.md)). The program passes what DNS
knows as values: the server's addresses and its port, and an HTTPS record's `alpn` and `port` when
it has one.

```zig
// One configuration serves both transports. Its TLS value names no protocol: the channel
// offers h3 over QUIC, and h2 then http/1.1 over TCP, as `versions` allows them.
channel_config = .{
    .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .cpu = cpu },
    .authority = origin,
    .fallback_delay_ns = fallback_delay_ns,
};
// The channel takes what DNS knows as values: the server's addresses and its port.
const known: client.ChannelValues = .{ .addresses = &server_addresses, .port = server_port };
// `init` builds the TLS configuration of each transport inside the channel, which stays in
// place from here on. The pool is what makes the channel offer QUIC.
try channel.init(&channel_config, known, receive_pool.storage());
// `request` only takes an exchange. The channel sends it over the first connection that
// completes its handshake.
_ = try channel.request(&get);
```

The channel takes one `client.ChannelConfig` ([decision 120](decisions.md)):

- `tls` is one `tls.Client` value, which says how the client judges the server over TCP and over
  QUIC. Its `alpn` list stays empty. A channel with no `tls` runs in cleartext, over TCP alone.
- `versions` names the HTTP versions the client speaks, each on by default. The channel offers
  them through ALPN: `h2` and then `http/1.1` over TCP, and `h3` over QUIC. It opens TCP only
  while `versions` allows h11 or h2, so a client that speaks h3 alone opens no TCP connection.
  Over TLS, a TCP server that selects no protocol is spoken to in h11 while `versions` allows
  h11. With h11 off, that connection closes, as one whose handshake failed does (RFC 9113 §3.3).
- `authority`, the content codings and their decoder pools are given once, for both transports.
- `fallback_delay_ns` is how long QUIC's handshake runs before TCP opens beside it. Its default
  is `client.constants.fallback_delay_ns_default`, 250 ms.
- `ecn` and `idle_timeout_ms` are for QUIC connections alone.

`init` also takes the pool the channel's QUIC connection holds the server's unread octets in:
`client.ReceivePool(capacity)`, sized to the longest response the program expects. A channel
offers QUIC only when it has a pool, a `tls` value and `versions.h3`. A program that passes
`null` for the pool gets TCP alone.

`init` builds the TLS configuration of each transport the channel offers, inside the channel, so
the program does not move the channel after it. It returns `error.NoVersion` when the
configuration offers neither transport, and `error.TooManyAnchors`, `error.TooManySuites` or
`error.SuitesUnavailable` when the TLS value names more than a TLS configuration holds.

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
`send_stream` writes. After each send, each event and each `on_instant`, it reads the channel
again, with the TCP octets it still holds, or with `.none` when it holds none. The channel may
consume fewer octets than it was given: an h11 connection reads a held octet only once the
response before it ends, and reads half a head again from its first octet.

A program starts a QUIC connection with values it draws at random:

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

One `h11.Connection` is one HTTP/1.1 connection. `receive(input, decoded)` consumes the
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

One `h2.Connection` is one HTTP/2 connection. `receive(input, now_ns)` consumes at most
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
the flow-control windows allow. `sendable_len` says how many octets `write_data` would send now,
so a program sizes a write, or waits for the peer's WINDOW_UPDATE when it says 0. `write_trailers` ends either side's message with a trailer
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

Every configuration also takes `cpu`, which has no default: a `tls.Cpu` holding the
`platform.Cpu` that `platform.probe()` returned and the `tls.Timing` the program's thread runs in.
colibri probes nothing and sets no CPU mode. A program probes its CPU once, at start, and passes
the same value to each configuration. A session runs the AES instructions only where the probe's
`aes_clmul` is `yes` and the timing is `data_independent`; otherwise it runs none and holds
TLS_CHACHA20_POLY1305_SHA256 alone. `data_independent` states that the thread runs Arm's and
Intel's listed instructions in data-independent time: on arm64 a core with FEAT_DIT whose thread
set PSTATE.DIT, and on x86-64 a part on Intel's DOIT list whose operating system set DOITM. Under
`not_stated` a session also runs the portable multiply in place of the native one.

```zig
const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
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

A `quic.Connection` is one QUIC connection. Your program moves datagrams and time
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

An `h3.Connection` runs HTTP/3 over one QUIC connection. After each datagram, call its
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
| `h11.Connection` | 35,040 |
| `h11.coding.DefaultPool` | 691,472, 16 decoders the connections given it share |
| `h2.Connection` | 162,192 |
| `quic.Connection` | 141,232 |
| `h3.Connection` | 145,496, beside the QUIC connection it runs over |

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
