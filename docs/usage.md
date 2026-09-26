# Using colibri

This guide shows how a program drives colibri: how to add it, what the program owns, and the calls
each protocol takes. Each module's entry file documents its calls in full; this guide shows how
they fit together. The test-only endpoints under [`src/testing/`](../src/testing/) are complete,
working programs for every protocol, and the best place to read a whole loop.

## Adding colibri

colibri has no release yet, so depend on a commit:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#<commit>
```

In `build.zig`, import the modules your program uses:

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true });
exe.root_module.addImport("h2", colibri.module("h2"));
exe.root_module.addImport("http", colibri.module("http"));
```

The library is eleven modules, each exported by name:

| Module | What it holds |
| --- | --- |
| `core` | The bounds-checked reader and writer, and the limits two modules share |
| `wire` | The integer and string codecs of RFC 7541 and RFC 9000 §16, and the Huffman code |
| `http` | What h11, h2 and h3 share: field lines and sections, methods, status codes, URIs, and the message rules of RFC 9110 |
| `tls` | The `tls.Provider` and `tls.QuicProvider` vtables your TLS stack fills |
| `crypto` | The `crypto.Suite` vtable that protects QUIC packets |
| `hpack` | HPACK (RFC 7541) |
| `qpack` | QPACK (RFC 9204) |
| `quic` | QUIC version 1 (RFC 9000, 9001, 9002). It imports no HTTP module. |
| `h11` | HTTP/1.1 (RFC 9112) |
| `h2` | HTTP/2 (RFC 9113) |
| `h3` | HTTP/3 (RFC 9114) over `quic` |

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
- **Your program chooses the TLS stack.** h11 and h2 take a `tls.Provider`, and QUIC takes a
  `tls.QuicProvider` and a `crypto.Suite`. Design §8 step 16 links
  [chapulin](https://github.com/c4milo/chapulin) into the library to fill all three. Until it
  lands, `src/testing/` holds chapulin adapters you can copy, and a program without TLS runs in
  cleartext.

A peer that breaks a protocol rule never crashes colibri. `receive` returns
`error.ConnectionFailed`, the connection names the failure, and the octets colibri owes the peer,
such as h2's GOAWAY or an h11 server's 400, are waiting to be written.

## h11

One `h11.connection.Connection` is one HTTP/1.1 connection. `receive` consumes the octets of at
most one event: a head, a run of body data, or the end of a body. Loop over it until it consumes
nothing and returns no event.

A client:

```zig
connection.init(.client, .{});
const head_len = try connection.write_request(&output, "PUT", "/object", &.{
    .{ .name = "Host", .value = "store.example" },
    .{ .name = "Content-Length", .value = "5" },
});
const body_len = try connection.write_body(output[head_len..], "hello");
const end_len = try connection.write_end(output[head_len + body_len ..], &.{});
// Send output[0 .. head_len + body_len + end_len], then read and receive the response.
```

A client pipelines requests and gives each response to the oldest one. It stops pipelining after
a request whose method is not idempotent until that request has its final response (decision 88).

A server:

```zig
connection.init(.server, .{});
const received = try connection.receive(input);
if (received.event) |event| switch (event) {
    .request => |request| {
        // The field lines are in connection.section until the next call.
        const head_len = try connection.write_response(&output, 200, "OK", &.{
            .{ .name = "Content-Length", .value = "2" },
        });
        const body_len = try connection.write_body(output[head_len..], "ok");
        _ = try connection.write_end(output[head_len + body_len ..], &.{});
    },
    else => {},
};
```

A server reads one request at a time: it reads the next only after the final response to the
current one is written. When `receive` fails, `has_pending` says colibri owes an error response,
`write_pending` writes it, and the connection then closes (decision 92). `should_close` says when
to close the transport, and `transport_closed` reports what a close cut short.

A body already in a buffer of your own need not be copied. `count_body(len)` counts `len` octets
against the declared Content-Length and writes nothing; your program then sends those octets
itself, next (decision 95).

Over TLS, call `attach_tls` once the handshake completes, and pass every record through
`h11.connection_tls`'s `decrypt` and `encrypt`.

## h2

One `h2.connection.Connection` is one HTTP/2 connection. `receive(input, now_ns)` consumes at most
one whole frame and returns at most one event. When it consumes nothing, `has_pending` says
whether colibri must write first, and `write_pending(output, now_ns)` writes the connection
preface, colibri's SETTINGS, and every frame it owes: acknowledgments, WINDOW_UPDATE, RST_STREAM
and GOAWAY.

```zig
connection.init(.server);
while (true) {
    const received = try connection.receive(input[offset..], now_ns);
    offset += received.consumed;
    if (received.event) |event| handle(event);
    if (received.consumed == 0) {
        if (connection.has_pending()) {
            const written = connection.write_pending(&output, now_ns);
            // Send output[0..written].
            continue;
        }
        break; // Read more octets.
    }
}
```

Events are a request or a response head with its field section (`connection.field_section()`),
trailers, data, a stream the peer reset or colibri refused, the peer's GOAWAY, and the SETTINGS
exchange. A client opens a stream with `write_request`, a server answers with `write_response`,
and both send content with `write_data`, which writes as much as the flow-control windows allow.
`reset_stream` ends one stream, and `shutdown` begins a graceful close.

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
`write_response` and `write_trailers` write frames into your buffer, and you send the content
behind them on the request stream.

[`src/testing/quic/udp/udp_peer.zig`](../src/testing/quic/udp/udp_peer.zig) is a whole QUIC
endpoint over UDP, and [`src/testing/quic/h3/`](../src/testing/quic/h3/) holds the h3 server and
client built on it.

## Sizes

Every connection is a struct your program places, and its size is fixed at compile time. These are
`@sizeOf` in ReleaseSafe with Zig 0.16.0 on aarch64 macOS, on 2026-09-26:

| Struct | Octets |
| --- | --- |
| `h11.connection.Connection` | 35,008 |
| `h2.connection.Connection` | 162,192 |
| `quic.connection.Connection` | 141,232 |
| `h3.connection.Connection` | 145,496, beside the QUIC connection it runs over |

The buffers your program reads into and writes from come on top, and QUIC's calls also take
scratch storage your program places; `udp_peer.zig` shows both.

The named limits in each module's `constants.zig` set these sizes, and
[`docs/decisions.md`](decisions.md) records why each limit has its value.
