# Using colibri

This guide shows how a program drives colibri: how to add it, what the program owns, and the calls
each protocol takes. Each module's entry file documents its calls in full; this guide shows how
they fit together. [`examples/`](../examples/) holds short whole programs for h11 and h2, and the
test-only endpoints under [`src/testing/`](../src/testing/) run every protocol over real sockets.

## Adding colibri

Depend on a release tag, or on a commit for a change made since:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#v0.6.0
```

In `build.zig`, import the modules your program uses:

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true });
exe.root_module.addImport("h11", colibri.module("h11"));
exe.root_module.addImport("http", colibri.module("http"));
exe.root_module.addImport("h2", colibri.module("h2"));
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
| `quic` | QUIC version 1 (RFC 9000, 9001, 9002). It imports no HTTP module. |
| `h11` | HTTP/1.1 (RFC 9112) |
| `h2` | HTTP/2 (RFC 9113) |
| `h3` | HTTP/3 (RFC 9114) over `quic` |
| `server` | Responses to h11 and h2 requests behind one set of calls, with each TLS handshake run inside it ([decision 100](decisions.md)). h3 over QUIC follows (design §8 step 17b). |
| `client` | Requests over h11 and h2 behind one set of calls, each ending in one outcome in memory you own, with each TLS handshake run inside it ([decision 100](decisions.md)). h3 over QUIC and the choice between the transports follow (design §8 step 17d). |

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
- **Your program starts the TLS sessions.** h11 and h2 take a `tls_provider.Provider`, and QUIC
  takes a `tls_provider.QuicProvider` and a `crypto.Suite`. The `tls` module fills all three from
  chapulin. Convert your values once into a configuration: `tls.record.ClientConfig` or
  `ServerConfig` over TCP, `tls.quic.ClientConfig` or `ServerConfig` for QUIC. Start a session of
  the matching kind for each connection. Over TCP, hand its `provider()` to the connection's
  `attach_tls` once `handshake` completes. For QUIC, hand `provider()` and `suite()` to the
  connection, which starts chapulin's session when it sets its transport parameters. A server that
  sends Retry packets checks their tokens with a `tls.quic.Retry` under a key it draws once. A
  program that links `tls` defines chapulin's one hook, `ch_assert_fail`, and passes each session's
  `start` the source it draws from. A program without TLS never links chapulin.

A peer that breaks a protocol rule never crashes colibri. `receive` returns
`error.ConnectionFailed`, the connection names the failure, and the octets colibri owes the peer,
such as h2's GOAWAY or an h11 server's 400, are waiting to be written. A QUIC connection error
from `receive` or `send` leaves the CONNECTION_CLOSE owed, and the next `send` writes it (RFC 9000
§10.2). Over TLS, a record that does not open ends the connection, and `encrypt` called with no
plaintext writes the alert the provider owes (RFC 9846 §5.2).

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
section, after its final header section (RFC 9113 §8.1). `reset_stream` ends one stream, and
`shutdown` begins a graceful close.

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

Every configuration also takes `aes_instructions`, which has no default: whether the CPU the
program runs on has the AES instructions and the carry-less multiply. colibri probes nothing. A
program asks its CPU once, at start, and passes the answer to each configuration. Under `absent` a
session runs no AES instruction and holds TLS_CHACHA20_POLY1305_SHA256 alone. stdx's `platform`
module will answer it (https://github.com/c4milo/stdx/issues/15); until then this program answers
for the target it was built for.

```zig
const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
try tls_config.init(.{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } },
    .alpn = &.{ "h2", "http/1.1" },
    .aes_instructions = aes_instructions(),
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

The named limits in each module's `constants.zig` set these sizes, and
[`docs/decisions.md`](decisions.md) records why each limit has its value.
