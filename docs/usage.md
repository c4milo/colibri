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
zig fetch --save git+https://github.com/c4milo/colibri#v0.10.0
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
| `client` | Requests over h11, h2 and h3 behind one set of calls, each ending in one outcome in memory you own, with each TLS handshake run inside it ([decision 100](decisions.md)). A `ConnectionPool` carries them to one origin over the QUIC and TCP connections it chooses between, and tells you which transport to open. |

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

- **Your program owns every struct and buffer.** Declare a server's endpoint, a client's pool
  or a protocol module's connection where you like: in a static, in an array, or inside a larger
  struct. Nothing points at the heap. Place large ones outside the stack.
- **Your program does the I/O.** Read octets from the socket, hand them to `receive`, and send
  the octets colibri puts in your buffer: a protocol module's `write_*` calls, and a server
  endpoint's `send_stream` and `send_datagram`. colibri never waits: when it needs more
  octets, `receive` consumes none and returns no event.
- **Your program passes the time.** A call that needs the current instant takes `now_ns`, in
  nanoseconds from any fixed origin. The same instants and the same octets give the same output,
  which is what lets the simulator replay a connection.
- **Your program configures TLS.** The `server` module takes the server's identity in its
  `server.Config`, and the `client` module takes one `tls.Client` value in its `client.Config`.
  Each builds the TLS configuration of each transport from it, and runs each handshake itself. A
  program that drives a protocol module by itself converts its values once into a configuration:
  `tls.record.ClientConfig` or `ServerConfig` over TCP, `tls.quic.ClientConfig` or `ServerConfig`
  for QUIC. It starts a session of the matching kind for each connection: h11 and h2 take a `tls_provider.Provider`, and QUIC takes a
  `tls_provider.QuicProvider` and a `crypto.Suite`, and the `tls` module fills all three from
  chapulin. Over TCP, hand the session's `provider()` to the connection's `attach_tls` once
  `handshake` completes. For QUIC, hand `provider()` and `suite()` to the connection, which starts
  chapulin's session when it sets its transport parameters. A server that sends Retry packets
  checks their tokens with a `tls.quic.Retry` under a key it draws once. A program that links
  `tls` defines chapulin's one hook, `ch_assert_fail`, and passes the source each session draws
  from: to `Endpoint.init`, to `ConnectionPool.start_tcp` and `start_quic`, and to each session it
  starts.
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

## The words of the API

The `server` and `client` modules name each concept once, the same for h11, h2 and h3
([decision 126](decisions.md)). The RFCs name some of them differently for each version, and the
protocol modules keep the RFCs' words. This table says which word means what:

| The API says | RFC 9110 | h11 (RFC 9112) | h2 (RFC 9113) | h3 (RFC 9114) |
| --- | --- | --- | --- | --- |
| a header | a field line | a field line | a field | a field line |
| headers | the header section | "the headers" or the header section | a field block | a HEADERS frame's field section |
| trailers | the trailer section | the trailer section of `chunked` | a field block that ends the stream | the trailing HEADERS frame |
| a body | content | the message body | DATA frames | DATA frames |
| bytes | octets | octets | octets | octets |
| an exchange | a request/response exchange | | | |

## The server

The `server` module answers requests behind one set of calls, whichever version the connection
speaks ([decision 100](decisions.md)). An endpoint is the server side of every connection one
thread serves: RFC 9000 §1.2 and RFC 9113 §2.2 give the word to the client or the server of a
connection, and a server has many connections. A program makes one `server.Config` and one
endpoint for each thread that serves ([decision 119](decisions.md)). The endpoint holds every
connection, and a `server.ConnectionHandle` names one:

- **TCP connections.** The program calls `accept` for each TCP socket its listener accepts. Over
  TLS the connection runs the handshake itself, and ALPN picks h2 or h11 during it. In cleartext,
  a connection speaks h2 when its first octets are h2's connection preface and h11 otherwise (RFC
  9113 §3.3, [decision 117](decisions.md)).
- **QUIC connections.** They serve h3, all of them behind one UDP socket
  ([decision 103](decisions.md)), each in a slot of its own. A client's first datagram starts one.

The configuration's `protocols` turns any protocol off, in cleartext and over TLS: the endpoint
builds its ALPN list from `protocols`, so the TLS identity names no protocol. For its QUIC
connections the endpoint names h3 itself (RFC 9114 §3.1).

The code in this section is from
[`examples/server_exchange.zig`](../examples/server_exchange.zig), where `link` and
`datagram_link` stand in for a program's TCP and UDP sockets. Its clients, in
[`examples/server_peers.zig`](../examples/server_peers.zig), send five requests over h2 and a GET
over h3. An endpoint's size is fixed at build time. `server.Endpoint` holds 16 TCP connections
and 16 QUIC connections, and `server.EndpointOf` makes one of another size. The `server.Capacity`
it takes names the TCP and the QUIC connections the endpoint holds at once, and the octets each
QUIC connection holds unread:

```zig
const Endpoint = server.EndpointOf(.{ .tcp_connections = 2, .quic_connections = 1, .receive_pool_len = 64 * 1024 });
```

A program that serves QUIC alone sets `.tcp_connections = 0`, and a program with no UDP socket
sets `.quic_connections = 0`.

The configuration holds the server's TLS identity, once for both transports. `init` builds the TLS
configuration of each transport from it and checks that the key signs, so a program learns of a
bad identity before it serves. The program then calls `accept` for each socket, with whether the
socket runs TLS:

```zig
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
```

A program turns Nagle's algorithm off on each TCP socket it accepts, with `TCP_NODELAY`. Each
`send_stream` writes what a connection owes in one piece, so a small write that waits for the
peer to acknowledge the one before it only adds latency: over h2 at low rates, colibri's test-only
server waited about 3 ms a request with the option off (design §8 step 13f).

`now_seconds` is Unix time, which the server's tickets are issued at. With a `ticket_key` the
endpoint issues each client a ticket, which a later connection of that client offers to resume
the session. `now_ns` is the instant on
the clock every later call passes, and a connection's deadlines count from the instant its
`accept` is given. `accept` returns null when no slot is free, after `shutdown`, when `protocols`
allows neither h11 nor h2, or when the TLS stack refuses to start a session. The program closes
the socket then. A socket runs TLS unless the program passes `.{ .tls = false }`, and a
configuration with no identity takes cleartext sockets alone. With h3
turned off, or with no identity, an endpoint that serves no TCP version returns `error.NoVersion`
from `init`, and one that also serves TCP starts no QUIC connection. The endpoint reads the
configuration while it runs and keeps pointers into itself, so the program keeps both where `init`
found them.

Each turn of the program's loop fires the deadlines that passed, passes the endpoint what each
socket read, acts on every event the endpoint reports, and sends every datagram the endpoint owes:

```zig
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
```

The program passes `.stream` with the octets a TCP socket read and the handle of that socket's
connection:

```zig
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
```

`receive` returns at most one event a call, of any connection the endpoint holds. A program loops
over it until it consumes nothing and returns no event. It loops again after every call that
changes a connection: an answer, `cancel`, `send_stream`, `transport_closed`, `shutdown` and
`on_instant`. Each leaves what follows it to the next `receive`, the release of a closed
connection's slot included. The program passes `.none` when no socket read any octets. A TCP
connection may consume fewer octets than it was given, such as a pipelined h11 request while the
one before it is answered. The program holds the rest, and passes it again with the socket's next
read and after each event that names the connection. `read_stream` passes what is left after
every event. What an event carries points into the octets the program passed or into the
connection, and stays valid until the next `receive`, `on_instant`, `send_stream`,
`send_datagram`, `accept`, `transport_closed` or `shutdown`.

The program passes each datagram its UDP socket read, with the address it came from, as a
`server.Input`. The endpoint finds the connection the datagram's connection ID names, or starts
one from a client's first datagram, and answers Version Negotiation and Retry itself. After each
datagram the program calls `receive` with `.none` until it reports nothing:

```zig
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
```

An event names a request by its id, in h11, h2 and h3 alike, or a connection by its handle. The id
names the request's connection too. The program passes each event to its router's `handle`, which
answers each request, as [Router](#router) shows. `handle` hands back the events of the
connections, which are the program's I/O:

```zig
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
```

The events, which a program that answers requests itself reads:

- `request` carries the method, the target and the headers, which `headers.find` and
  `headers.iterator` read. Its `end` says the head ended the request, so no body follows. The
  method is its token as it arrived, and `http.method.standard(request.method)` gives one of
  RFC 9110 §9.1's eight methods, or null for another token (decision 122).
- `body` carries bytes of the request's body, and its `end` marks the last of them. A request with
  no body may end this way too, in a `body` event with no bytes, as a GET over h3 often does. A
  program that waits for a request's end reads `end` in both events.
- `trailers` carries the request's trailers, in `headers`.
- `finished` says a request is over, once. Its `result` is `sent` when the response is whole, and
  colibri reads none of the program's bytes for it again. It is `cancelled` with a reason when the
  request ended before its response did. A connection's `ended` comes after its requests' ends.
- `writable` says a response whose last write found no room can take more.
- `send` says a TCP connection owes its socket octets, `close` says the program closes a TCP
  connection's socket, and `ended` says a connection is over. The paragraphs below describe each.
- `closed` comes after `shutdown`, once every connection has ended.

`set_user_data` sets a word that each later event of a request carries back: its `body`,
`trailers`, `writable`, and its one `finished`. A program finds its own state for the request by
the word, with no lookup. The router sets it for each request it answers. Before the router
answers, the example notes each head:

```zig
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
```

A client that puts `100-continue` in a request's `Expect` field waits for a 100 (Continue) before
it sends the content (RFC 9110 §10.1.1). The connection writes that 100 when the endpoint next
reads the connection or writes its octets, in every version. That may be at the program's next
call. An answer the program gives first takes the place of the 100. A program that refuses such a
request therefore answers it before its next call: a final response, the program's own 100, or
`cancel` takes the place of the 100 the connection owes.

A route's function answers through a `server.ResponseWriter` ([decision 127](decisions.md)). It
sets `status`, which is 200 by default, adds headers, and writes the body through the
`std.Io.Writer` that `body()` returns:

```zig
fn greet(_: *App, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", content_type);
    try response.body().writeAll(greeting);
    try response.end();
}
```

`end` sends a head that carries the whole body with its Content-Length. The writer copies each
header and writes the body into the request's entry, which the endpoint may read until the
request's `finished` (decision 103). So the entry's `response_bytes` bound a body that `body()`
writes. `write_kept` sends bytes the program keeps valid until the `finished`, with no copy, such
as a file the program mapped. `trailers` ends the response with a trailer section. When the
endpoint takes less than the writer gives it, the rest waits, and the router sends it at the
request's `writable`.

The writer calls the endpoint's three calls that write a response, which a program that answers
requests itself calls by the request's id: `respond` writes the head, `write_body` the content and
`write_trailers` the trailer section. A response with no content sets `end` in `respond`. A write can find no room: `write_body` takes fewer octets than it was given, or
any of the three calls returns `error.Blocked` or `error.NoSpaceLeft`. `write_body` most often
returns `error.Blocked`, and `respond` and `write_trailers` `error.NoSpaceLeft`. `write_trailers`
returns `error.Blocked` while a coded response's last octets wait. Over QUIC, room comes back only
as the client acknowledges what was sent (RFC 9000 §3.1), and a head or a trailer section larger
than the room the response's earlier frames leave waits until the client has acknowledged all of
them. Either way the endpoint reports `writable` for the request, once, when the response has
room, and the program writes again. `cancel` ends one
request before its response is whole, and its `finished` follows, cancelled with the reason
`program`. A connection that stops with requests open ends each cancelled, with the reason `closed`.
`shutdown` ends every connection once the requests it holds are answered, and the `closed` event
follows once every connection has ended.

The endpoint reports `send` when a TCP connection owes its socket octets. The program calls
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
open connection without waiting for a `send`, such as straight after it writes a response. For
QUIC the turn calls `send_datagram` until it returns null, and sends each datagram to the address
it names.

A peer may hold a connection only so long ([decision 110](decisions.md)). Timeouts bound the
wait for a first request, the time between requests, a request's head and its content, and how
slowly the peer may take the response. They bound an h3 connection as they bound a TCP one. The
endpoint's `deadline_ns` names the soonest instant one passes, on any connection it holds. Over
QUIC it also names the instants of loss recovery, acknowledgments and idle timeouts. The program
waits for octets and datagrams no longer than that:

```zig
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
```

The program then calls `on_instant` with the instant it woke at, as the turn above does, and a
connection whose peer is late ends. Over h2, a request whose content is late may end by itself,
with a `finished` whose result is cancelled, with the timeout as its reason. `receive` and `send_stream` fire a deadline
that passed too, on the connection they read or write. The configuration's `timeouts` sets the
limits, and `Endpoint.init` refuses limits a connection would refuse, with
`error.TimeoutInvalid`. `set_timeouts` changes one connection's limits, by its handle, as
`note_request` does above. A program that wakes only when octets arrive never ends a silent peer.

A TCP connection's socket closes in one of two ways. The endpoint reports `close` once the
connection has finished and `send_stream` has written every octet it owed, the TLS close_notify
too, or once the `linger_ns` deadline passes with octets still owed. The program closes the socket
once the socket has taken the octets `send_stream` returned, and owes the endpoint no call. After a
linger there are none to wait for: colibri dropped what it still owed. Or the peer closes the
socket first, or the socket fails, and the program tells the endpoint with `transport_closed`. The
example accepts a second socket to show that call, a socket its peer closes before it sends an
octet:

```zig
const closed = endpoint.accept(.{}, link.now_ns(.server)) orelse return error.ExchangeWrong;
// The peer closed the socket first, so the program closes its own end and tells the endpoint.
// A program calls `transport_closed` then, and when a socket fails. The connection's `ended`
// follows, with no `close`.
endpoint.transport_closed(closed);
```

Either way colibri reads and writes nothing more on the connection, and wipes its TLS session's
secrets. The endpoint then reports a `finished` for each request: `sent` for each response
written whole, and cancelled with the reason `closed` for the others. Last comes the connection's
`ended`, once. A later
socket or client takes the connection's slot, and the ended connection's handle and every id on it
name nothing from then on. `ended` carries two more fields:

- `reason` names the deadline that passed, or the limit the peer passed, when colibri closed the
  connection for one. It is null otherwise. In the example, the QUIC connection ends at the idle
  deadline `note_request` shortened.
- `failed` says colibri closed the connection because its peer broke a protocol rule or its record
  layer failed. For a TCP connection, the endpoint reports a `send` for what colibri owes that
  peer, such as h2's GOAWAY or an h11 server's 400, before the `close`.

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
  endpoint (RFC 7838), as the example's does. A cleartext connection advertises nothing (RFC 9114
  §3.1.2).
- **Bounds.** The configuration's `limits` holds the bounds of each connection, named by what they
  bound: `requests_max`, the requests a connection holds at once, up to
  `server.constants.limits.quic_requests_max` request streams over QUIC, and `data_frame_len_min`,
  the shortest DATA frame h2 sends when a window, not the content, decides its length
  ([decision 110](decisions.md)). Two more bound resets in one second, 100 each by default:
  `peer_resets_max`, the requests a client may cancel, and `resets_sent_max`, the streams the
  server may reset because the client broke them. One more ends the connection, and its
  `CloseReason` names the limit. Over TLS, the provider bounds a run of KeyUpdates, and `limits`
  does not hold that bound. chapulin reads 16 in a row, and the 17th ends the connection with
  the limit `key_updates`.

### Router

A program declares its routes in a route table at compile time, and the router calls the function of each
request's route ([decisions 122 and 127](decisions.md)). `server.router` builds the route table from the
program's context type and a struct of two fields: `error_handler` and `routes`. Each route holds
a method, a pattern and a function, and options may follow. `Of` gives the type of the pool the
program places:

```zig
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
```

The method of a route is an enum literal, one of RFC 9110 §9.1's eight methods, or the token of
another method, such as `"PATCH"`. CONNECT does not compile, because a CONNECT request has no path
(RFC 9110 §9.3.6, decision 19). Each segment of a pattern is a literal, a parameter such as
`:name`, or the wildcard `*` as the last segment. A pattern holds
`server.constants.limits.path_parameters_max` parameters at most, the wildcard included.

A route's function takes five parameters, in this order: the program's context, the request, the
path's parameters, the query, and the response's writer. The path's parameters are `void`, or a
struct with one `[]const u8` field for each parameter of the pattern, and `rest` for the wildcard.
The query is `void`, `http.QueryParameters`, or a struct whose fields name the query's pairs:

```zig
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
```

A field of the query's struct is `[]const u8`, `?[]const u8`, or a field with a default value. A
query that lacks a `[]const u8` field with no default gets 400, and a query with more pairs than
`http.constants.limits.query_parameters_max` gets 414, with no call. A function runs at the
request's head and reads no body. The router ends a response the function leaves open.

A route can be a struct instead, with `on_request` and any of `on_body`, `on_writable` and
`on_finished`, and a `State` that the request's pool entry holds. `on_request` takes a `*State`
after the context, and else the parameters of a function. `on_body` reads the request body through
a `std.Io.Reader`. A read past the bytes that arrived fails with `error.ReadFailed` while more of
the request body is to come, and an `on_body` that returns that error waits for them: the bytes it
left unread come first in its next call. At the request body's last byte a read fails with
`error.EndOfStream`. With `.whole_body`, the router calls `on_body` once, after the last byte, with
every byte in the pool entry's `body_bytes`:

```zig
const Echo = struct {
    pub fn on_request(_: *App, _: *void, _: *const server.Request, _: void, _: void, _: *server.ResponseWriter) !void {}

    pub fn on_body(_: *App, _: *void, content: *std.Io.Reader, response: *server.ResponseWriter) !void {
        try response.header("content-type", content_type);
        try response.body().writeAll(content.buffered());
        try response.end();
    }
};
```

A request body larger than `body_bytes` gets 413. The router ends the response once `on_body` ran
with the last byte, unless the route has `on_writable`. `on_writable` writes a response over many
calls: the router calls it while the response is open and the endpoint took all it was given, and
the route ends the response itself. `on_finished` runs at the request's `finished` event, with its
result.

The route table must name `error_handler`, which chooses the status after a route's function returns an
error ([decision 127](decisions.md) ruling 4). After the head went out, the router cancels the
request instead, since its body may be cut short:

```zig
fn on_error(_: *App, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = 500;
}
```

The router answers a request with no call of a function in four cases: 404 when no route names
the path, 405 with an Allow field when no route of the path names the method, 501 when no route
of the route table names the method, and 503 when the pool has no free entry. A program that dispatches
a request itself calls `match`, with the request's method and path. Its `found` gives the route's
`Route` tag, named by its method and its pattern, such as `.@"GET /greetings/:name"`.

`match` follows these rules:

- **The method comes first.** When no route of the route table names the method, the result is
  `not_implemented`, on any path, and the router answers 501 (RFC 9110 §9.1, §15.6.2). Then
  `match` reads the path. The query does not change the result.
- **A literal, then a parameter, then the wildcard.** At each segment, `match` tries the literal
  that equals the segment, then the parameter, then the wildcard. When a deeper segment fails, it
  backs up one level and tries the next kind. So the order of the route table does not change the
  result: with `/users/me` beside `/users/:id`, the path `/users/me` matches `/users/me` first.
- **A parameter matches one segment.** The wildcard matches one segment or more, and
  `get("*")` gives the rest of the path, without its first "/". So `/files/*` does not match
  `/files`.
- **Each route names its own parameters.** Two routes may give one position two names, as
  `GET /users/:id` and `PUT /users/:user` do, and each reads its value by its own name
  (decision 129).
- **The first pattern that matches the whole path and names the method decides.** When a
  pattern that matches the path names other methods, `match` backs up and tries the next kind, as
  it does for a segment that fails (decision 128). So with `GET /v1/charges/search` beside
  `POST /v1/charges/:charge`, a POST of `/v1/charges/search` finds `/v1/charges/:charge`. When no
  pattern that matches the path names the method, the result is `method_not_allowed`, and the
  Allow value lists the methods of each of those patterns. The router writes a 405 with an
  "allow" field (RFC 9110 §15.5.6). The field name is in lowercase, because h2 and h3 refuse an
  uppercase field name.
- **HEAD finds GET.** A HEAD request finds the GET route of a pattern that names no HEAD route,
  and the Allow value lists HEAD after GET. The endpoint writes no content in a response to HEAD,
  in h11, h2 and h3 (RFC 9110 §9.3.2). So a program writes one answer for GET and HEAD. It reads
  `request.method` when it must know which one it got.
- **`OPTIONS *` gets one of two results.** A route table with no OPTIONS route gives
  `not_implemented`. A route table with an OPTIONS route gives `not_found`, because "*" is not a path.
  A program that answers `OPTIONS *` reads the request before it passes it to `handle`.
- **Each segment is percent-decoded** (RFC 3986 §2.1, decision 127). `match` splits the path on
  "/" first, then decodes each segment it reads. A literal compares with the decoded segment:
  `/users/%6De` matches `/users/me`. A "%" that two hex digits do not follow stays as written, and
  colibri checks no UTF-8.
- **A segment that encodes "/", "\\" or NUL matches nothing** (RFC 3986 §7.3). So no parameter
  holds a "/" or a "\\", no part of the wildcard's rest is a dot-segment, and no value holds a NUL.
- **A parameter's value is the decoded segment.** A segment with no "%" is a slice of the path,
  valid until the next endpoint call that the comment on `Endpoint.receive` lists. A decoded one
  is a slice of the router's `PathParameters`, valid until the next request. A route that keeps a
  value longer copies it into its `State`.
- **A path that ends in "/" is a resource of its own** (RFC 3986 §6.2.4, decision 122 as
  amended on 2026-10-29). Only a pattern that ends in "/" matches it: `/a/` matches `/a/` and not
  `/a`, and `/a` matches `/a` and not `/a/`. A parameter does not match the empty last segment,
  so `/a/:id` does not match `/a/`. The wildcard does not match a path that ends in "/", so
  `/files/*` does not match `/files/a/`.
- **Paths that match nothing:** a path with an octet outside `pchar` and "%", a path with an empty
  segment that is not its last, such as `/a//b`, a path with a "." or ".." segment, encoded or
  not, such as `/a/%2E%2E`, and a path longer than `server.constants.limits.path_len_max` bytes, its
  query included.

### Middleware

A middleware is a struct that the router calls before a route
([decision 127](decisions.md) ruling 5). The router calls the route table's `middleware` first,
then the route entry's, as `.{ .get, "/admin", admin, .{ .middleware = .{Auth} } }`, in table order.
They run one after the other: no middleware calls the next. A chain is a tuple, so a program names
one, such as `const api = .{ Auth, RateLimit };`, and joins it to another with `++`.

`on_request` runs at the request's head. It returns `.next`, and the router calls the next
middleware, then the route. Or it writes the response and returns `.answered`, and the router calls
nothing more for the request. An error goes to `error_handler`. The server example's middleware
adds a header to each response:

```zig
const Brand = struct {
    pub fn on_request(_: *App, _: *const server.Request, response: *server.ResponseWriter) !server.middleware.Next {
        try response.header("server", "colibri");
        return .next;
    }
};
```

`on_finished` runs when the request ends, with its id and its result, in the reverse order, for
each middleware the chain reached. It holds what a framework whose middleware wraps the next one
runs after `next()` returns, such as an access log.

A middleware can also wrap the bytes of a body (design §8 step 25.6). `wrap_body` gets the reader
of the request body and returns another, which the next middleware wraps and the route's `on_body`
reads. `wrap_response` does the same for the writer that the route's `body()` returns, and may add
a header, such as Content-Encoding. Each runs at the head, after the middleware's `on_request`
returns `.next`, and null keeps the reader or the writer it got. A wrapper writes nothing before
the route starts the body, because the headers are still open. A middleware keeps its wrapper in
its `State`, which the request's pool entry holds, and each field of a `State` has a default
value, which each request starts from.

When the route ends a wrapped response, the router calls each `finish_response` from the route's
side outward, so a wrapper writes what it owes at the end, such as a gzip trailer. It flushes the
writer of a middleware that declares none. Then the router ends the response, so Content-Length
counts the bytes the wrappers wrote. An error of `finish_response` cancels the request.
`write_kept` copies its bytes through the wrapper. The server example counts the bytes of each
response:

```zig
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
```

A middleware declares one or more of `on_request`, `on_finished`, `wrap_body` and
`wrap_response`, and `finish_response` only beside `wrap_response`.

### Query

`request.path` holds the path alone, and `request.query` holds the bytes after the first "?", or
null (decision 127). `http.QueryParameters` reads its `name=value` pairs, as the WHATWG URL
Standard's `application/x-www-form-urlencoded` parser does: it splits on "&" and on the first "=",
skips empty pieces, reads "+" as a space, and percent-decodes. `read` writes the decoded names and
values into a buffer the program gives, and refuses a query of more than
`http.constants.limits.query_parameters_max` pairs, 32, or of more bytes than the buffer holds.
`get` returns the first value of a name. The router reads a route's query this way before it fills
the route's struct, and a route that names `http.QueryParameters` gets the pairs to read by name.

A malformed route table, or a route table with a conflict, does not compile, and the compile error names the
entry and the rule. Two conflicts concern routes that other routes hide:

- **`route_unreachable`:** no request reaches the route. With `GET /a/*`, `GET /a/:x` and
  `GET /a/:x/*`, each path of two segments matches `/a/:x` first, and each longer path matches
  `/a/:x/*` first.
- **`methods_too_many`:** the routes of a route table name more than
  `server.constants.limits.route_methods_max` methods, 10. A 405's Allow value is written at compile
  time for each set of the table's methods, and 10 methods need 1,024 of them.

The check runs at compile time and adds no cost to `match`. The largest route table that the tests build holds 256 routes, each a pattern
of four segments and 64 octets.

### Over QUIC

The same events and the same calls serve h3. A program moves datagrams with addresses in place of
a stream of octets, and it keeps time for each connection. Two things differ from TCP:

- **The body is not copied.** QUIC reads the program's bytes again whenever it sends them again.
  They stay the program's until the request's `finished`. A `sent` result comes once the peer
  has acknowledged every byte of the response.
- **Time.** `deadline_ns` names the instant the endpoint next needs `on_instant`, for loss
  recovery and acknowledgments too, so a program sleeps until then when no datagram arrives.
  `Config.idle_timeout_ms` is QUIC's own idle timeout, which ends a peer that sends nothing at
  all.

`ended` means what it means over TCP. Its `reason` names the deadline that ended the connection,
or the limit its client passed, and `failed` says colibri closed it because its client broke a rule
of the protocol. A later client then takes its slot, and every id of the ended connection names
nothing. A QUIC connection has no socket of its own, so the endpoint reports no `send` and no
`close` for one.

`Config.retry` makes a client prove its address before a connection starts (RFC 9000 §8.1.2).
By default every client must, and `Config.retry_from_percent` limits that to the times when at
least that percent of the QUIC slots hold a connection ([decision 110](decisions.md)). A spoofed
Initial then holds no slot while the server is under load, and an honest client spends no extra
round trip while it is not. `Config.logs` gives each connection a qlog log
([decision 102](decisions.md)).

## The client

The `client` module sends requests behind one set of calls too. An exchange is one request with its
response, from the call of `request` to the request's one `finished` event. RFC 9110 §7.5 calls it a
"request/response exchange". A program makes one `client.Config` for an origin, and a `client.ConnectionPool`
that carries its exchanges there ([decision 120](decisions.md)). The pool carries them over the QUIC
and TCP connections it chooses between, and tells the program which transport to open ([decision
105](decisions.md)). Over QUIC its connection speaks h3. Over TCP with TLS, ALPN picks h2 or h11. In
cleartext its connection speaks h11, or h2 with prior knowledge when `protocols` turns h11 off
([decision 117](decisions.md)).

The code in this section is from [`examples/client_exchange.zig`](../examples/client_exchange.zig),
where `link` and `datagram_link` stand in for a program's TCP and UDP sockets. Its network drops
every UDP datagram. The pool tries QUIC first, and carries its exchanges over TCP once the
fallback delay passes. Its server, in [`examples/client_peer.zig`](../examples/client_peer.zig), is
an endpoint with no UDP socket.

For each exchange the program places two values in its own memory
([decision 124](decisions.md)):

- a `client.Request`, which says what it sends;
- a `client.Response`, which says where the answer goes and holds what arrived.

The client only reads the request, so a program may make it a `const`.

```zig
var wanted: [1]client.WantedHeader align(@alignOf(client.WantedHeader)) = .{.{ .name = "content-type" }};
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
    .headers = &.{.{ .name = "content-type", .value = content_type }},
    .body = note,
};
var post_response: client.Response align(@alignOf(client.Response)) = .{ .body = &post_body };
```

`wanted` names the headers of the response the program reads. Their values go into `values` and
the body into `body`; colibri keeps no other header. The request's `body` is its own body.
The program keeps the request and the response in place, with each slice they name, until the
exchange's `finished` event or until `cancel` returns.

A program places the pool and the memory it holds its TCP connections and its exchanges in
([decision 125](decisions.md)). The pool's `client.Config` counts them: `tcp_connections`, 1 by
default, and `requests`, 16 by default. `ConnectionPool.memory_bytes(.{ .tcp_connections = n,
.requests = m })` gives the bytes those counts need, with the defaults for a count left out.
It is pure, so a program sizes a static array with it, as here, or maps that many octets at run
time:

```zig
var pool: client.ConnectionPool align(@alignOf(client.ConnectionPool)) = undefined;
// The memory the pool holds its TCP connections and its exchanges in, whose size the counts in
// `client.Config` give (decision 125).
var pool_memory: [client.ConnectionPool.memory_bytes(.{})]u8 align(client.ConnectionPool.memory_alignment) = undefined;
```

The client gives one configuration with one TLS value, makes the pool, and hands it each
request and its response. The program passes what DNS knows as values: the server's addresses
and its port, and an HTTPS record's `alpn` and `port` when it has one.

```zig
// One configuration serves both transports. Its TLS value names no protocol: the pool
// offers h3 over QUIC, and h2 then http/1.1 over TCP, as `protocols` allows them.
client_config = .{
    .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .cpu = cpu },
    .authority = origin,
};
// The pool takes what DNS knows as values: the server's addresses and its port.
const known: client.Destination = .{ .addresses = &server_addresses, .port = server_port };
// `init` builds the TLS configuration of each transport inside the pool, which stays in
// place from here on. It keeps the pool's TCP connections and its exchanges in `pool_memory`,
// which `.{}`, the default counts, sizes. The receive pool is what makes the pool offer QUIC.
try pool.init(&pool_memory, &client_config, known, receive_pool.storage());
// `request` only takes a request and its response. The pool asks for a transport, and
// sends the request over the first connection that completes its handshake, so a program asks
// at once and never waits.
_ = try pool.request(&get, &get_response);
_ = try pool.request(&post, &post_response);
```

The pool takes one `client.Config` ([decision 120](decisions.md)):

- `tls` is one `tls.Client` value, which says how the client judges the server over TCP and over
  QUIC. Its `alpn` list stays empty. A pool with no `tls` runs in cleartext, over TCP alone.
- `protocols` names the protocols the client speaks, h11, h2 and h3, each on by default. The pool offers
  them through ALPN: `h2` and then `http/1.1` over TCP, and `h3` over QUIC. It opens TCP only
  while `protocols` allows h11 or h2, so a client that speaks h3 alone opens no TCP connection.
  Over TLS, a TCP server that selects no protocol is spoken to in h11 while `protocols` allows
  h11. With h11 off, that connection closes, as one whose handshake failed does (RFC 9113 §3.3).
- `authority`, the content codings and their decoder pools are given once, for both transports.
- `fallback_delay_ns` is how long QUIC's handshake runs before TCP opens beside it. Its default
  is `client.constants.policy.fallback_delay_ns_default`, 250 ms.
- `ecn` and `idle_timeout_ms` are for QUIC connections alone.

`init` also takes the receive pool, where the pool's QUIC connection holds the server's unread octets:
`client.ReceivePool(capacity)`, sized to the longest response the program expects. A pool
offers QUIC only when it has a pool, a `tls` value and `versions.h3`. A program that passes
`null` for the pool gets TCP alone.

A program that never speaks h3 holds a `client.ConnectionPoolOf(.{ .quic = false })` in place of a
`client.ConnectionPool` ([decision 124](decisions.md)). It holds no QUIC connection and no QUIC TLS
configuration. At the default counts it takes 307,376 octets with its memory, in place of
1,012,288 (docs/performance.md). Its `init` takes `null` for the pool, and it has no
`start_quic`, so a call of it does not compile. The consumer program holds one:

```zig
// The pool speaks h2 over TCP alone, so it holds no QUIC state (decision 124).
const ConnectionPool = client_module.ConnectionPoolOf(.{ .quic = false });
var asked: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
```

`init` builds the TLS configuration of each transport the pool offers, inside the pool, so
the program does not move the pool after it. It returns these errors:

- `error.NoVersion`: the configuration offers neither transport.
- `error.VersionUnavailable`: the configuration allows h3 on a pool with no QUIC.
- `error.TooManyAnchors`, `error.TooManySuites` or `error.SuitesUnavailable`: the TLS value
  names more than a TLS configuration holds.

A program may call `init` again on a pool with no open transport and no exchange, for example
with new addresses. While exchanges run, it calls `set_destination` instead (below).

A program moves datagrams with addresses over QUIC and a stream of octets over TCP, and it keeps
time for the pool. Each turn passes the pool what each socket read, fires its deadlines, sends
the datagrams the QUIC connection owes, and reads again. A TCP connection's octets go out when
the pool says `send`:

```zig
fn client_turn() !void {
    const now_ns = link.now_ns(.client);
    try read_datagrams(now_ns);
    // `on_instant` fires QUIC's timers that passed. The reads after it count the end of the
    // fallback delay, and report what changed.
    pool.on_instant(now_ns);
    try drain(now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = pool.send_datagram(&datagram_output, now_ns) orelse break;
        try datagram_link.send(.client, sent.bytes);
    }
    try drain(now_ns);
}
```

Each datagram goes to `receive` with the address it came from, and the pool consumes it whole:

```zig
fn read_datagrams(now_ns: u64) !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try datagram_link.receive(.client) orelse break;
        // A connection takes a datagram only from the address its server answers from.
        var rest: client.Input = .{ .datagram = .{ .bytes = datagram, .from = server_address } };
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
```

A read of the TCP socket passes every octet the program still holds, or `.none` when it holds
none, until the pool consumes nothing and reports nothing. The pool may consume fewer octets
than it was given: an h11 connection reads a held octet only once the response before it ends,
and reads half a head again from its first octet. After each send, each event and each
`on_instant`, the program reads the pool again.

```zig
fn drain(now_ns: u64) !void {
    const input = try link.receive(.client);
    var consumed: usize = 0;
    for (0..receive_calls_max) |_| {
        const held = input[consumed..];
        const tcp = connections.get(.tcp);
        const read: client.Input = if (held.len > 0) .{ .stream = .{ .connection = tcp, .bytes = held } } else .none;
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
```

A pool holds more than one TCP connection when `client.Config.tcp_connections` says so
([decision 125](decisions.md)). h11 carries one exchange at a time on a connection. So a pool of
h11 connections opens another connection when an exchange waits and no open connection has room
for it. It opens no second h2 connection, as RFC 9113 §9.1 asks. The pool example
([`client_pool.zig`](../examples/client_pool.zig)) holds four:

```zig
const ConnectionPool = client.ConnectionPoolOf(.{ .quic = false });
const tcp_connections: u16 = link_module.streams_max;
var pool: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
var pool_memory: [ConnectionPool.memory_bytes(.{ .tcp_connections = tcp_connections })]u8 align(ConnectionPool.memory_alignment) = undefined;
var client_config: client.Config align(@alignOf(client.Config)) = .{
    .authority = origin,
    .protocols = .{ .h2 = false, .h3 = false },
    .tcp_connections = tcp_connections,
};
```

Each connection is a socket of its own. The handle of each `open` names the connection's slot,
and the program keeps one socket for each slot. Each later event names the connection too:
`send` when it owes octets, and `close` when it is over. The program reads each socket with the
handle of its connection:

```zig
fn client_turn() !void {
    try link.receive(.client);
    const now_ns = link.now_ns(.client);
    for (0..link_module.streams_max) |slot| try drain(@intCast(slot), now_ns);
}

/// Passes the pool the octets the socket of `slot` read, until it consumes nothing and reports
/// nothing. With no socket in the slot it passes `.none`, which reports what the pool owes.
fn drain(slot: u32, now_ns: u64) !void {
    const socket = sockets[slot];
    const input = link.queue(slot, .client);
    var consumed: usize = 0;
    for (0..receive_calls_max) |_| {
        const held = input[consumed..];
        // An event may close this socket, or open another in its slot: its octets then go to no
        // connection.
        const current = socket != null and std.meta.eql(sockets[slot], socket);
        const read: client.Input = if (current and held.len > 0) .{ .stream = .{ .connection = socket.?, .bytes = held } } else .none;
        const received = pool.receive(read, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try report(event, now_ns);
    }
    // A socket closed during the read dropped its octets with it.
    if (socket != null and std.meta.eql(sockets[slot], socket)) link.consume(slot, .client, consumed);
}
```

A program that gets a later DNS answer gives it to the pool with `set_destination`, while exchanges
run. Each connection that opens after the call goes to the new addresses, from the first. Each
open connection keeps its exchanges. The port stays the origin's. The pool keeps the h3
alternative it learned, unless the new values name one.

```zig
        // A later DNS answer names another address. Each connection that opens from now on goes
        // to it, and each open connection keeps its exchanges.
        pool.set_destination(.{ .addresses = &second_addresses, .port = server_port });
```

A program sizes its memory and bounds its loops with two limits of `client.constants` and one
call of the pool, and needs no name from `h11` or `tls_provider` ([decision 124](decisions.md) as
amended by [decision 125](decisions.md)):

- `stream_input_len_min`: what the program holds of the TCP socket's octets, at least, so that
  `receive` takes some while `send_stream` has written what the connection owes. The pool takes
  an h11 head, an h2 frame and a TLS record whole, and this is the largest of them.
- `stream_output_len_min`: the least `output` for `send_stream`, the largest TLS record.
- `ConnectionPool.receive_events_without_input_max(counts)`: the most `receive` calls in a row that
  report an event and take no byte, for a pool of those counts.

The example bounds each read of the socket with them:

```zig
/// Calls of `receive` for one read of a socket, at most. Each call takes one octet or more of the
/// link's queue, or reports an event and takes no octet, or ends the loop. At most
/// `ConnectionPool.receive_events_without_input_max` calls in a row report an event and take no octet.
const receive_calls_max = (link_module.queue_len_max + 1) * (client.ConnectionPool.receive_events_without_input_max(.{}) + 1);
```

The pool's events say what the program does next, and an exchange ends in exactly one
`finished` event, whatever happened to it. The event names the request and the response. Each
event about a connection names its `client.ConnectionHandle`, which the connection's `open` named
first ([decision 125](decisions.md)):

```zig
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
                ended.request.path, @tagName(ended.response.result), ended.response.status,
            });
            finished += 1;
            // Every exchange has ended, so the client shuts the pool down.
            if (finished == requests_count) pool.shutdown();
        },
        .ticket => |connection| take_ticket(connection),
        // The shut-down pool is over: every exchange ended and every transport closed.
        .closed => pool_closed = true,
    }
}
```

A program writes what a TCP connection owes when the pool says `send`, until a call leaves room
in its output:

```zig
fn send_owed(connection: client.ConnectionHandle, now_ns: u64) !void {
    for (0..sends_per_debt_max) |_| {
        const written = pool.send_stream(connection, &output, now_ns);
        try link.send(.client, output[0..written]);
        if (written < output.len) return;
    }
    return error.ExchangeWrong;
}
```

The response's `outcome` says what happened to the exchange:

| Outcome | What it means |
| --- | --- |
| `response` | The final response arrived whole: `status`, `body_received()`, and each wanted value. |
| `refused` | The server processed none of the request, so the program may send it on another connection. |
| `reset` | The server reset the stream, and `error_code` names why. |
| `closed` | The connection ended before the response was whole. The server may have processed the request. When no part of the response arrived, the pool first sent an idempotent request again, once ([decision 124](decisions.md)). |
| `malformed` | colibri refused the response, because the protocol's rules make it malformed. |
| `invalid` | The request is one the protocol refuses to send. |
| `too_large` | The content did not fit `body`, or a wanted value did not fit `values`. A Content-Length larger than `body` ends the exchange at its head, and over h11 the connection with it ([decision 124](decisions.md)). |

The events:

- `open` names a connection, its transport and where it goes. The program opens a UDP flow or
  connects a TCP socket to `open.to`, then calls `start_quic`, or `start_tcp` with the
  connection's handle. A program turns Nagle's algorithm off on each TCP socket it connects, with
  `TCP_NODELAY`, as a server does on each socket it accepts, so a small request leaves at once. Each later call and event about the connection names that handle. QUIC goes first when the origin is
  known to speak h3, or when `Config.quic_first` says to try it. TCP opens when QUIC fails or
  `fallback_delay_ns` passes. The first connection whose handshake completes takes the exchanges.
- `send` names a TCP connection that owes octets. The program calls `send_stream` for it until a
  call leaves room in its output, which ends the debt. The pool says `send` again for the next
  debt, once the connection read octets or the program made another call.
- `connected` names the connection that carries the exchanges, and its version: h3 over QUIC, or
  the version ALPN picked over TCP.
- `ticket` says the server issued a resumption ticket. `ConnectionPool.take_ticket` hands it over, and a
  later connection offers it through the last argument of `start_tcp` or `start_quic`.
- `close` names a connection that is over. Over TCP, `send_stream` wrote everything
  first, the TLS close_notify too. The program closes the socket, and drops the octets it read
  from it and still holds: they are that connection's, and the next connection must not get them.
- After `shutdown`, `closed` says the pool is over: every exchange ended and every transport
  closed.

The example opens no later connection, so its `take_ticket` wipes each ticket the pool hands
over:

```zig
fn take_ticket(connection: client.ConnectionHandle) void {
    const ticket = pool.take_ticket(connection) orelse return;
    var held = ticket;
    held.wipe();
    tickets += 1;
}
```

A program starts each connection with the source its TLS session draws from. The pool draws a
QUIC connection's IDs and h3's grease value from that source too, and the handshake draws the
rest:

```zig
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
```

In the example the TCP connection completes its handshake first, so the pool abandons the QUIC
connection. That connection ends only after its closing period, three PTOs (RFC 9000 §10.2). It
has no RTT sample, so each PTO is about 1 s (RFC 9002 §6.2.2). Its `close` and `closed` thus
come about 3 s after `connected`.

A socket that fails to connect, that the peer closed, or that failed later goes to
`transport_closed`. The example's second pool shows a connect that fails. It offers TCP alone,
so the attempt has no transport left, and the exchange ends `refused`:

```zig
fn connect_refused() !void {
    const now_ns = link.now_ns(.client);
    // The pools to one origin share its configuration. With no receive pool this one offers
    // TCP alone.
    const known: client.Destination = .{ .addresses = &server_addresses, .port = server_port };
    try refused_pool.init(&refused_memory, &client_config, known, null);
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
```

A pool asks for a second TCP socket when an exchange the server refused unprocessed moves to
another connection (RFC 9113 §8.7). It reports the first socket's `close` before it. A program
that opens no second socket calls `transport_closed` with the handle the second `open` named,
and the exchange ends `refused`.

A connection can also close before any of a response arrives. The pool then sends an
idempotent request again on another connection (RFC 9110 §9.2.2): GET, HEAD, OPTIONS, TRACE, PUT
and DELETE. A refusal and a close share one budget, `client.constants.limits.moves_max`, so a
request goes out twice at most. A request with any other method ends `closed`, and the program
decides whether to send it again.

`deadline_ns` names the instant the pool next needs `on_instant`: the end of the fallback
delay, or QUIC's next timer. Both sides sleep until the sooner of their deadlines when nothing
waits:

```zig
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
```

A pool has no deadline of its own for an exchange: QUIC's idle timeout is the one limit it
runs. A server that answers slowly, or never, holds an exchange until the program ends it. So a
program sets its own limit on each exchange and calls `cancel` when the limit passes. The
deadlines of [decision 110](decisions.md) are the server's.

A client that decodes content codings names them in `Config.codings`, and places the pool
of decoders each needs ([decision 101](decisions.md)).

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
so a program sizes a write, or waits for the peer's WINDOW_UPDATE when it says 0. A program that
holds its content in its own buffer calls `write_data_header` instead. It writes the header of the
frame `write_data` would write into `room_len` octets, into nine octets the program passes. The
program sends the frame's `consumed` octets right after the header, before any other octet: after
it in one buffer, or sealed with it by `tls_provider`'s `encrypt_parts` ([decisions 138 and
139](decisions.md)). `write_trailers` ends either side's message with a trailer
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
TLS_CHACHA20_POLY1305_SHA256 alone. On arm64, under the same timing, a session also runs the
SHA-256, SHA-512 and SHA-3 instructions where the probe's `sha256`, `sha512` and `sha3` are `yes`.
`data_independent` states that the thread runs Arm's and Intel's listed instructions in
data-independent time: on arm64 a core with FEAT_DIT whose thread set PSTATE.DIT, and on x86-64 a
part on Intel's DOIT list whose operating system set DOITM. Under `not_stated` a session also runs
the portable multiply in place of the native one.

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

A program that finds an error in what it read, after the handshake, sends the fatal alert that
names it with `fail`, then closes the connection. An example is a record longer than RFC 9846 §5.2
allows, which record_overflow names. `fail` writes at most `tls.record.alert_record_len` octets
into the output and fails the session. It takes the error alerts of RFC 9846 §6.2 alone, on a
connected session: a refused call returns a `tls.record.FailError`, writes nothing and leaves the
session as it was. `tls.record.Server` has the same call. In the excerpt below, the handshake has
not completed, so the call must return `error.NotConnected` and send nothing.

```zig
if (tls_client.fail(.record_overflow, &output)) |_| return error.FailWrong else |failure| {
    if (failure != error.NotConnected) return error.FailWrong;
}
```

What a handshake selected is a `tls_provider.Negotiated`: the version, the cipher suite and the
key-exchange group, each as its codepoint, such as 0x11EC for X25519MLKEM768 ([decision
140](decisions.md)). A record session's provider answers `negotiated_parameters`, and a
`tls.quic.Client` answers `negotiated()`. Each is null until the handshake completed:

```zig
const provider = tls_client.provider();
if (provider.vtable.negotiated_parameters(provider.context)) |chosen| {
    std.debug.print("consumer: group 0x{x:0>4}\n", .{chosen.group});
    return error.NegotiatedWrong;
}
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

Pass `packet_number_skips`, one `u64` your program draws from its source at start, so that the
connection skips a 1-RTT packet number now and then. An ACK of a skipped number then shows a peer
that acknowledges packets it never received (RFC 9000 §21.4, [decision 123](decisions.md)). The
server's and the client's QUIC connections do this for you.

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

Every connection is a struct your program places, and its size is fixed at compile time. The
table of [Memory per connection](performance.md#memory-per-connection) gives the size of each
endpoint, pool, connection and TLS session. `zig build test` fails when that table differs from
what the build compiles.

One more struct, `@sizeOf` in ReleaseSafe with Zig 0.16.0 on aarch64 macOS, on 2026-09-26:

| Struct | Octets |
| --- | --- |
| `h11.coding.DefaultPool` | 691,472, 16 decoders the connections given it share |

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
