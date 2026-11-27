# Using colibri

This guide shows the calls a program makes to serve and fetch over h11, h2 and h3. It starts with
`colibri.Server` and `colibri.Client`, which do the I/O for you, and then covers the `server` and
`client` modules and each protocol module. [`examples/`](../examples/) holds a whole program for
each part, and each module's entry file documents its calls in full.

## Quick start: serve a route and fetch it

```zig
const routes = .{
    .error_handler = on_error,
    .Values = Values,
    .middleware = .{Numbered},
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .get, "/greetings/:name", greet_named, .{ .path = Name } },
    },
};
```

This section is from [`examples/colibri_server.zig`](../examples/colibri_server.zig). The route
table names each method, path and function, and the compiler checks it ([Router](#router)). Each
route's function takes the program's state first:

```zig
fn greet(state: *App, ctx: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    // `Numbered` ran before the route, so the request's values hold its number.
    if (ctx.values(Values).number != state.taken) return error.RequestNotNumbered;
    state.answered += 1;
    try response.header("content-type", "text/plain");
    try response.body().writeAll(greeting);
    try response.end();
}
```

The program places the router, the server and the server's TLS buffer once, outside any stack
frame:

```zig
const Router = server.Router(App, routes, .{ .requests = connections, .response_bytes = 256, .body_bytes = 0, .header_bytes = 0 });
var router: Router align(@alignOf(Router)) = undefined;

/// A server that holds four TCP connections and four QUIC connections, on colibri's own loop. The
/// program places the server once, outside any stack frame, and does not move it.
const connections = 4;
const Server = colibri.Server(.{ .tcp_connections = connections, .quic_connections = connections }, .private);
var http_server: Server align(@alignOf(Server)) = undefined;
/// Room for the TLS session of each TCP connection over TLS the server holds at once (decision
/// 167). A server that serves no TLS over TCP passes no buffer.
var tls_buffer: [server.Config.tls_buffer_len(connections)]u8 = undefined;
```

`main` makes the TLS context, binds the server and runs it on a thread of its own:

```zig
var secure: SecureRandom = .{ .io = init.io };
const cpu_features: platform.CpuFeatures = .detect();
_ = platform.set_data_independent_timing(cpu_features, true);
const crypto = stdx.crypto.init(cpu_features, secure.random());
try http_server.init(&.{
    .host = "127.0.0.1",
    .port = 0,
    .identity = .{ .chain = identity.chain_pem, .key = identity.key_pem },
    .crypto = crypto,
    .unix_seconds = now_seconds,
    .engine = .{ .tls_buffer = &tls_buffer, .cpu_features = cpu_features },
}, &router, &app);
defer http_server.deinit();
const thread = try std.Thread.spawn(.{}, serve, .{cpu_features});
defer thread.join();
defer http_server.shutdown();
```

```zig
fn serve(cpu_features: platform.CpuFeatures) void {
    _ = platform.set_data_independent_timing(cpu_features, true);
    http_server.run() catch |failure| std.debug.panic("run failed: {t}", .{failure});
}
```

A client fetches one response in one call:

```zig
try http_client.init(&.{
    .destination = .{ .addresses = &server_addresses, .port = http_server.port() },
    .pool = .{
        .cpu_features = crypto.features,
        .authority = origin,
        .protocols = .{ .h3 = false },
        .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .crypto = crypto },
    },
    .unix_seconds = now_seconds,
}, null);
```

```zig
const got = try http_client.fetch(&.{ .path = "/greeting", .response_body = &body });
if (got.result != .response or got.status != ok) return error.ResponseWrong;
if (!std.mem.eql(u8, greeting, body[0..got.body_len])) return error.ResponseWrong;
```

Run it with `zig build example-colibri_server`. [colibri.Server](#colibriserver) and
[colibri.Client](#colibriclient) give the rules of each call.

## Adding colibri

```sh
zig fetch --save git+https://github.com/c4milo/colibri#v0.22.0
zig fetch --save=stdx git+https://github.com/c4milo/stdx#v0.4.0
```

Depend on a release tag, or on a commit for a change made since. Depend on stdx at the commit
colibri's `build.zig.zon` pins: tag v0.4.0, commit `fdfbb709`.

From [`tools/consumer/build.zig`](../tools/consumer/build.zig), a program that uses `.private`:

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true, .rotor = true });
exe.root_module.addImport("colibri", colibri.module("colibri"));
```

```zig
const stdx = b.dependency("stdx", .{ .target = target, .release = true, .crypto = true });
exe.root_module.addImport("stdx", stdx.module("stdx"));
```

From [`tools/consumer_hosted/build.zig`](../tools/consumer_hosted/build.zig), a program that uses
the protocol modules or the `.hosted` kind alone, and fetches no Rotor:

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true });
```

- `colibri` is the one module the package exports ([decision 170](decisions.md#decision-170)).
- `.rotor = true` fetches [Rotor](https://github.com/c4milo/rotor), the loop of `.private`. Without
  it, a `.private` object does not compile, and the compiler names the line to add
  ([decision 159](decisions.md#decision-159)).
- `.release = true` builds ReleaseSafe. colibri offers Debug and ReleaseSafe only, because its
  assertions stay on in production.
- Give stdx the options colibri gives it, `.crypto = true` among them. A second stdx module fails
  the build.

The root of `colibri` names each library module. From
[`examples/colibri_server.zig`](../examples/colibri_server.zig):

```zig
const colibri = @import("colibri");
// `colibri` names each library module, so the program imports no other module of colibri
// (decision 170).
const server = colibri.server;
const client = colibri.client;
const tls = colibri.tls;
const stdx = @import("stdx");
const platform = stdx.platform;
```

| Module | What it holds |
| --- | --- |
| `colibri` | `colibri.Server` and `colibri.Client`, which bind sockets and run a loop. The one module that does I/O. |
| `server` | Responses to h11, h2 and h3 behind one set of calls: `server.Engine`, `server.Router` |
| `client` | Requests over h11, h2 and h3 behind one set of calls: `client.ConnectionPool` |
| `h11`, `h2`, `h3` | HTTP/1.1 (RFC 9112), HTTP/2 (RFC 9113) and HTTP/3 (RFC 9114) |
| `quic` | QUIC versions 1 and 2 (RFC 9000, 9001, 9002, 9369). It imports no HTTP module. |
| `hpack`, `qpack` | Field compression for h2 (RFC 7541) and h3 (RFC 9204) |
| `http` | What h11, h2 and h3 share: fields, methods, status codes, URIs (RFC 9110) |
| `tls` | TLS 1.3 values and sessions over `stdx.crypto` |
| `tls_provider`, `crypto` | The vtables a TLS stack fills, and the one that protects QUIC packets |
| `qlog` | A qlog log in your buffer, which `quic` and `h3` fill ([decision 102](decisions.md#decision-102)) |
| `dnssec` | Checks of a DNSSEC signature and a DS digest ([decision 142](decisions.md#decision-142)) |
| `core`, `wire` | The bounds-checked reader and writer, and the integer, string and Huffman codecs |

The package exports nothing of stdx ([decision 170](decisions.md#decision-170)). A program that
codes content itself takes `stdx.compress.gzip`, `zlib`, `zstd` or `brotli` from the same stdx.

## The TLS stack and the CPU

```zig
const SecureRandom = struct {
    io: std.Io,

    fn fill(pointer: *anyopaque, bytes: []u8) void {
        const self: *SecureRandom = @ptrCast(@alignCast(pointer));
        self.io.randomSecure(bytes) catch |err| std.debug.panic("no entropy: {t}", .{err});
    }

    fn random(self: *SecureRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};
```

```zig
var secure: SecureRandom = .{ .io = init.io };
const cpu_features: platform.CpuFeatures = .detect();
_ = platform.set_data_independent_timing(cpu_features, true);
const crypto = stdx.crypto.init(cpu_features, secure.random());
```

From [`examples/colibri_server.zig`](../examples/colibri_server.zig): the program detects its CPU
once and makes one `stdx.crypto.Context` ([decision 175](decisions.md#decision-175)). colibri
reads its TLS stack as `stdx.crypto` ([decision 174](decisions.md#decision-174)).

- Every `cpu_features` field of a configuration takes `crypto.features`, or the same
  `cpu_features` value.
- Every TLS value, the server and the client's pool hold the one `crypto`. Each session draws
  from its source and from no other.
- Call `set_data_independent_timing` on each thread that runs TLS. It sets PSTATE.DIT on arm64
  where the core has FEAT_DIT, and changes nothing elsewhere.
- The program defines no assertion hook. [TLS](#tls) shows the optional `chapulinAssertFail`.
- A program that calls the TLS stack itself reads it from the same stdx, as
  `@import("stdx").crypto.jws`, `.dnssec`, `.scram`, `.hash`, `.tls` or `.quic`.

## colibri.Server

```zig
const BoundServer = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .private);
var bound_server: BoundServer align(@alignOf(BoundServer)) = undefined;
```

From [`tools/consumer/main.zig`](../tools/consumer/main.zig): `colibri.Server(capacity, kind)`
binds one port and runs `server.Engine` ([decision 150](decisions.md#decision-150)). `kind` is
`.private`, on colibri's own Rotor loop, or `.hosted`, on
[your loop](#host-colibri-on-your-own-loop). The
[quick start](#quick-start-serve-a-route-and-fetch-it) shows `init` and `run`.

- Place the server once, outside any stack frame, and do not move it.
- `init` takes a pointer to the configuration, the router, and the program's value, which each
  route takes first. It binds, reads the identity and keeps no pointer to the configuration.
- `port()` returns the port bound, which port 0 leaves to the system.
- `run` serves on the thread that calls it until another thread calls `shutdown`. It then ends
  each connection and returns.
- The thread that calls `run` runs the TLS sessions, so it calls `set_data_independent_timing`
  first, as `serve` does.
- `deinit` closes the sockets and wipes the private key, the cookie key and the ticket keys. Call
  it after `init` returns, and after `run` returns when your program calls `run`.
- `server.Config.tls_buffer_len(n)` gives the bytes of `n` TLS sessions at any alignment. With an
  identity and TCP connections, `engine.tls_buffer` holds one session at least
  ([decision 167](decisions.md#decision-167)).

`colibri.ServerConfig` holds these fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `host` | `"127.0.0.1"` | An IPv4 or IPv6 literal. |
| `port` | 0 | The TCP and UDP port. With 0 the system chooses, and `init` tries up to `colibri.constants.limits.bind_tries_max` (16) ports for a free UDP one. |
| `identity` | null | `.chain` and `.key` as PEM text. `init` keeps no copy, so you may wipe the text after it. Null serves h11 and h2 in cleartext and opens no UDP socket. |
| `unix_seconds` | none | The seconds since 1970 when `run` starts. Session tickets carry it ([decision 161](decisions.md#decision-161)). |
| `crypto` | null | Your `stdx.crypto.Context`. Null makes one of `engine.cpu_features` and the system's entropy. |
| `ticket_key` | null | The key that seals session tickets, which the server copies. Null draws one. Give each server of one port the same key. |
| `ticket_key_previous` | null | An older key that still opens tickets. It differs from `ticket_key`, or `run` returns `error.IdentityRefused`. |
| `engine` | none | The `server.Config` the engine starts from, with `tls_buffer` and `cpu_features`. colibri fills its `tls` and `ecn` ([decision 68](decisions.md#decision-68)). |

With an identity, ALPN picks h2 or h11, and h3 runs on the UDP socket of the same port.

From [`examples/colibri_hosted.zig`](../examples/colibri_hosted.zig), a change of the ticket key:

```zig
var next_ticket_key: [tls.constants.protocol.server_key_len]u8 = undefined;
crypto.random.bytes(&next_ticket_key);
hosted_server.set_ticket_key(&next_ticket_key);
std.crypto.secureZero(u8, &next_ticket_key);
```

- The current key becomes the previous one, so a client keeps its ticket across one change.
- Call `set_ticket_key` on the server's thread: between two calls on `.hosted`, or from a route or
  a middleware on `.private`.
- For more cores, start more servers on one port. Each binds with SO_REUSEPORT
  ([decision 173](decisions.md#decision-173)).
- An h3 client whose address changes can then reach another server, and opens a new connection.

## colibri.Client

```zig
const Client = colibri.Client(.{}, .private);
var http_client: Client align(@alignOf(Client)) = undefined;
```

From [`examples/colibri_server.zig`](../examples/colibri_server.zig): `colibri.Client` owns the
sockets, the loop and a `client.ConnectionPool` ([decision 153](decisions.md#decision-153) ruling
8). The default capacity holds one TCP connection, one QUIC connection and 16 requests.

From [`tools/consumer/main.zig`](../tools/consumer/main.zig), a client with no QUIC:

```zig
const client_capacity: colibri.ClientCapacity = .{ .quic = false, .tcp_connections = 1, .requests = 4 };
const BoundClient = colibri.Client(client_capacity, .private);
var bound_client: BoundClient align(@alignOf(BoundClient)) = undefined;
```

`init` takes the configuration and a pointer to your handler, or null to drop each event:

```zig
try http_client.init(&.{
    .destination = .{ .addresses = &server_addresses, .port = http_server.port() },
    .pool = .{
        .cpu_features = crypto.features,
        .authority = origin,
        .protocols = protocols,
        .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .crypto = crypto },
    },
    .unix_seconds = now_seconds,
}, &fetched);
defer http_client.deinit();
```

The handler declares `on_finished`, and may declare `on_connected`:

```zig
pub fn on_finished(self: *Fetch, _: *Client, _: client.Finished) void {
    self.finished += 1;
}
```

`request` takes a `client.Request` and the `client.Response` it fills. `run` returns once
`shutdown` was called, each exchange finished and each connection closed:

```zig
for (&fetched.requests, &fetched.responses, &fetched.bodies) |*request, *response, *body| {
    response.* = .{ .body = body };
    _ = try http_client.request(request, response);
}
// `run` returns once both exchanges have finished and each connection has closed.
http_client.shutdown();
try http_client.run();
```

- Keep each request and response in place until its exchange's `finished`.
- Call `request` before `run` or from a handler. Each handler runs on the loop's thread, and may
  call `request`, `cancel` and `shutdown`.
- `shutdown` is the one call another thread may make. After it, `request` returns
  `error.ShutDown`.
- Call `run` once for each `init`. `deinit` closes the UDP socket when `run` did not.
- `init` opens the UDP socket when the pool offers QUIC: h3 allowed and a TLS value. A client in
  cleartext needs no `crypto`.
- `set_destination` gives the pool new addresses on the loop's thread. New connections go there,
  and open connections keep their exchanges ([decision 125](decisions.md#decision-125)).
- An open of QUIC to an address family with no UDP socket ends, and the pool opens TCP
  ([decision 156](decisions.md#decision-156) ruling 13).
- With every version allowed, the client opens TCP first. h3 first needs `.prefer = .quic`.

`fetch` runs one exchange on the thread that calls it
([decision 156](decisions.md#decision-156) ruling 12). The
[quick start](#quick-start-serve-a-route-and-fetch-it) shows a call. With no method, a request
body makes the method POST, and no body makes it GET.

- A protocol failure is the `result`, not an error. Read `result` before `status`.
- The handler gets each other exchange that ends while `fetch` runs.
- Call `fetch`, `run` and `deinit` on one thread. `init` may run on another.
- A handler never calls `fetch`. Such a call halts with colibri's message.
- `deinit` stops the loop that the first `fetch` made. Only the pool's `timeouts` bound that wait
  ([decision 159](decisions.md#decision-159) as amended).
- When `fetch` returns an error of the loop, its exchange ended with no result. Call `deinit`.

`cancel` ends an exchange with no `finished`, and the memory of its request and response is yours
again when it returns:

```zig
const id = try http_client.request(&fetched.requests[1], &dropped);
http_client.cancel(id);
```

- An h11 connection then reads and drops the rest of the response for `timeouts.drop_ns`
  ([decision 146](decisions.md#decision-146) ruling 3).
- On `.private`, `cancel(id)` takes the instant of the last turn of colibri's loop. A hosted
  client's call is `cancel(id, now_ns)`, with your loop's instant.

`colibri.ClientConfig` holds three fields, each with no default:

| Field | Meaning |
| --- | --- |
| `destination` | The server's addresses, each with port 0, and the origin's port. The client looks up no name. Keep `addresses` alive until the next `set_destination` or `deinit`. |
| `pool` | The `client.Config` the pool starts from. `init` sets its `tcp_connections`, `requests` and `ecn`. |
| `unix_seconds` | The seconds since 1970 when `run` starts. A web PKI trust judges each chain's dates at it. |

These fields of `client.Config` are the ones a program sets most:

| Field | Default | Meaning |
| --- | --- | --- |
| `authority` | none | `:authority` in h2 and h3, and Host in h11. |
| `cpu_features` | none | Your detected features. |
| `tls` | null | A `tls.Client`, with your `crypto`. Null runs in cleartext. |
| `protocols` | `.{}` | h11, h2 and h3 each true, and `prefer = .tcp`. |
| `codings` | `&.{}` | The content codings to offer, with their decoders ([The client](#the-client)). |
| `quic_unadvertised` | true | Whether QUIC may open before Alt-Svc names h3. |
| `fallback_delay_ns` | 250 ms | How long QUIC's handshake runs before TCP opens beside it, under `prefer = .quic`. |
| `congestion_controller` | `.bbr` | BBRv3, CUBIC or NewReno for QUIC. |
| `idle_timeout_ms` | 30,000 | The QUIC idle timeout the client advertises. |
| `timeouts.connect_ns` | 10 s | The bound on each TCP connect. Null turns it off. |
| `timeouts.drop_ns` | 50 ms | How long an h11 connection drops a cancelled response. |

The client resumes TLS sessions ([decision 161](decisions.md#decision-161)):

- It offers the newest ticket of each transport once, never past its lifetime or seven days.
- `deinit` wipes the tickets, and `pool.tls.takes_tickets = false` keeps none.

## What your program owns

```zig
var router: Router align(@alignOf(Router)) = undefined;
```

Every module except `colibri` makes no system call, holds no allocator and reads no clock:

- **Every struct and buffer.** Place large ones outside the stack, and give each global its
  alignment, as above; `zig build lint` refuses one without it.
- **The I/O.** Hand the bytes you read to `receive`, and send the bytes colibri gives you. When
  colibri needs more bytes, `receive` consumes none and returns no event.
- **The time.** A call that needs the current instant takes `now_ns`, in nanoseconds from any
  fixed origin, which never goes back.
- **TLS.** You make the `stdx.crypto.Context` and the TLS values. [TLS](#tls) shows how.

A peer that breaks a protocol rule never crashes colibri:

- A connection's `receive` returns `error.ConnectionFailed`, and the bytes owed to the peer wait
  to be written.
- A server's engine returns no error. It reports the bytes it owes, then `ended` with `failed`.

## The words of the API

The `server` and `client` modules name each concept once, the same for h11, h2 and h3
([decision 126](decisions.md#decision-126)). The protocol modules keep the RFCs' words:

| The API says | RFC 9110 | h11 (RFC 9112) | h2 (RFC 9113) | h3 (RFC 9114) |
| --- | --- | --- | --- | --- |
| a header | a field line | a field line | a field | a field line |
| headers | the header section | "the headers" or the header section | a field block | a HEADERS frame's field section |
| trailers | the trailer section | the trailer section of `chunked` | a field block that ends the stream | the trailing HEADERS frame |
| a body | content | the message body | DATA frames | DATA frames |
| an exchange | a request/response exchange | | | |

## Host colibri on your own loop

```zig
try hosted_server.init(&.{
    .identity = .{ .chain = identity.chain_pem, .key = identity.key_pem },
    .crypto = crypto,
    .now = .{ .unix_seconds = identity.now_seconds, .monotonic_ns = link.now_ns(.server) },
    .engine = .{ .tls_buffer = &tls_buffer, .cpu_features = cpu_features },
}, &router, &router_context);
```

```zig
const turned = hosted_server.turn(link.now_ns(.server), &operations);
for (operations[0..turned.operations]) |operation| try self.perform(.server, operation);
waits[@intFromEnum(Side.server)] = turned.wait;
```

From [`examples/colibri_hosted.zig`](../examples/colibri_hosted.zig): a `.hosted` object writes the
operations it needs, and your loop gives back one completion for each
([decision 159](decisions.md#decision-159)). It does no I/O, reads no clock and needs no Rotor.

- It has the calls of `.private` except `run`, `fetch`, `port` and the bind.
- [`examples/colibri_shared_rotor.zig`](../examples/colibri_shared_rotor.zig) hosts a server and a
  client on one Rotor loop beside a timer.
- Only `.private` has published numbers ([decision 32](decisions.md#decision-32)).

### What the host does

1. Open the sockets before `init`: a server's TCP listener, and each UDP socket.
   - Name them in the configuration, with `segments` and `ecn` for each UDP socket.
   - A family with no UDP socket turns h3 off, and the client uses TCP.
2. Call `init`, with `now`, a `server.Timestamp`: the Unix seconds and your loop's monotonic
   nanoseconds.
   - A server takes `crypto`, and a client takes it in its pool's TLS value.
   - `now`, a server's `crypto`, and a client's `destination` and `pool` have no default.
3. Call `turn(now_ns, &operations)`. It calls your handler or routes, and writes the operations.
   - Size the slice with the type's `operations_max` and `sockets_max`.
4. Do each operation. Map each `colibri.SocketId` to your socket: `Server.listener`,
   `Server.datagram`, `Client.datagram_ipv4` and `Client.datagram_ipv6`.
5. When an operation ends, call `complete(&completion, now_ns)` with its id and result.
   - A receive of datagrams may complete many times with `more = true`, with a `.datagram`
     result only.
   - You lend the datagram's bytes for the call alone, and colibri may write them (RFC 9001 §5).
6. Call `turn` again at once after a completion, and otherwise at the instant the `Wait` names.
   `.none` waits for the next completion.
7. To stop, call `shutdown`, then `turn` and `complete` until `stopped()` holds, then `deinit`.
   Then close your sockets.

The operations are `connect`, `accept`, `receive`, `send`, `receive_datagram`, `send_datagram`,
`shutdown_send`, `close` and `cancel`:

- A `connect` opens a TCP socket of the address's family, sets TCP_NODELAY and connects it.
- A `shutdown_send` closes the write side, as shutdown(2) with `SHUT_WR` does, and completes with
  `.shut_down`. The receive goes on, and a `close` follows
  ([decision 160](decisions.md#decision-160)).
- A `cancel` gets no completion of its own. Its target gets its final completion, with
  `.canceled`.
- Map your loop's errors onto `colibri.Failure`.

### The rules of the host

colibri halts with its message when a host breaks one of these rules:

1. Each operation gets exactly one final completion, with `more = false`, also when a `cancel` or
   a `close` ends it.
2. colibri frees a socket only after each operation on it had its final completion. Call
   `deinit` only after `stopped()` holds.
3. One thread makes each call into an object.
   - A completion from another thread goes through a queue that your program owns.
   - A `.hosted` object does not check the thread.
4. Never call `turn` or `complete` from inside `turn` or `complete`. Your handler and routes run
   inside `turn`, and inside a `complete` that gives colibri a datagram.
5. After a `complete`, or after `request`, `cancel`, `set_destination` or `shutdown`, call `turn`
   before your loop waits.
6. `now_ns` never goes back: in `turn`, in `complete`, in a hosted client's `cancel`, and from the
   `now` of `init`. A completion with an id that colibri does not hold halts.

### A shared Rotor loop

colibri exports no Rotor adapter, so your program writes one of about 140 lines. From
[`examples/colibri_shared_rotor.zig`](../examples/colibri_shared_rotor.zig), the adapter puts its
own tag in the high 32 bits of each `user_data`, and colibri's `OperationId` in the low 32 bits:

```zig
fn user_data(owner: Owner, kind: Kind, socket: u16, id: colibri.OperationId) u64 {
    const tag: Tag = .{ .socket = socket, .kind = @intFromEnum(kind), .owner = owner };
    return @as(u64, @as(u32, @bitCast(tag))) << 32 | @intFromEnum(id);
}
```

Each event of a tick goes to its owner by that tag:

```zig
switch (tag.owner) {
    .server => server_adapter.complete(tag, id, event),
    .client => client_adapter.complete(tag, id, event),
    .timer => on_timer(),
}
```

### Other loops

On `std.Io` or libxev, each operation becomes a call whose end calls `complete`, and a timer
calls `turn` at the instant of `turned.wait`. The rules above hold on every loop.

## The server

From [`examples/server_exchange.zig`](../examples/server_exchange.zig), where `link` and
`datagram_link` stand in for a program's TCP and UDP sockets:

```zig
const Engine = server.Engine(.{ .tcp_connections = 2, .quic_connections = 1, .receive_pool_len = 64 * 1024 });
```

An engine is the server side of every connection one thread serves, over TCP and over QUIC
([decision 119](decisions.md#decision-119)). `server.Engine(.{})` holds 16 TCP and 16 QUIC
connections. A program places one engine for each thread that serves, and keeps it where `init`
found it.

| `server.Capacity` field | What it sizes |
| --- | --- |
| `tcp_connections` | TCP connections at once, 16 by default; 0 for a program with no TCP socket |
| `quic_connections` | QUIC connections at once, 16 by default; 0 for a program with no UDP socket |
| `receive_pool_len` | Bytes each QUIC connection holds unread |

### Set-up

```zig
engine_config = .{
    // The CPU features the engine's codecs run on: the context's, which the program detected
    // once. colibri never asks the CPU (decision 169).
    .cpu_features = crypto.features,
    // The identity names no protocol: the engine offers h2 and h11 through ALPN over TCP,
    // as `protocols` allows by default, and names h3 for its QUIC connections.
    .tls = .{
        .identities = &identities,
        .cookie_key = &cookie_key,
        .ticket_key = &ticket_key,
        .crypto = crypto,
    },
    .tls_buffer = &tls_buffer,
    // Decision 110: timeouts bound how long a peer may hold a connection. The defaults suit a
    // server, and this one ends an idle connection sooner.
    .timeouts = .{ .idle_ns = idle_ns },
    // Each TLS connection advertises h3 on the server's UDP port (RFC 7838).
    .h3_alternative = .{ .port = peers.server_port },
    // Decision 143: each QUIC connection runs BBRv3, the default, and `.cubic` chooses CUBIC.
    // BBRv3 draws its probe waits from the context's source.
    .congestion_controller = .bbr,
    // Decision 149: RFC 9959's saved sets, which the program keeps (`server_resume.zig`).
    .resumes = resumes.provider(),
};
const now_ns = link.now_ns(.server);
// One engine for every socket the program accepts and for its UDP socket, in storage the
// program owns. `init` checks that the key signs, and every value the engine draws comes from
// the context's source.
try engine.init(&engine_config, .{ .unix_seconds = now_seconds, .monotonic_ns = now_ns });
// One call for each socket the listener accepts, with whether the socket runs TLS. The handle
// names the connection in every later call and event. Null says the engine starts no
// connection, and a program then closes the socket.
accepted = engine.accept(.{}, now_ns) orelse return error.ExchangeWrong;
```

`init` takes a `server.Timestamp`: Unix seconds, at which the engine issues tickets, and the
monotonic instant that every later call passes. The engine copies the `Config` at `init`, so the
program may change or free it after `init` returns ([decision 158](decisions.md#decision-158)).

- `init` returns `error.NoVersion` when no slot can speak a version that `protocols` allows.
- `accept` returns null when no slot is free, after `shutdown`, when `protocols` allows neither
  h11 nor h2, or when the TLS stack refuses a session.
- After a null `accept`, the program closes the socket.
- `accept(.{})` runs TLS, and `accept(.{ .tls = false })` runs cleartext.
- A cleartext connection speaks h2 when its first bytes are h2's preface, and h11 otherwise (RFC
  9113 §3.3, [decision 117](decisions.md#decision-117)).
- A client's first datagram starts a QUIC connection ([decision 103](decisions.md#decision-103)).
- The program sets `TCP_NODELAY` on each TCP socket it accepts, because each send carries a
  whole response.

### `server.Config`

| Field | Default | What it sets |
| --- | --- | --- |
| `cpu_features` | none: the program names it | The features of `CpuFeatures.detect()`, which the codecs run on ([decision 169](decisions.md#decision-169)) |
| `tls` | null | The identity, once for both transports; it names no ALPN protocol |
| `tls_buffer` | empty: TCP serves cleartext alone | Room for TLS sessions: `server.Config.tls_buffer_len(n)` bytes hold `n` ([decision 167](decisions.md#decision-167)) |
| `protocols` | h11, h2 and h3 | The versions the engine serves and offers in ALPN ([decision 117](decisions.md#decision-117)) |
| `limits` | see the next table | Per-connection bounds |
| `timeouts` | see [Deadlines](#deadlines) | How long a peer may hold a connection ([decision 110](decisions.md#decision-110)) |
| `codings`, `encoders` | none | Content codings for a response marked `codable`: gzip or deflate, from an `EncoderPool` ([decision 101](decisions.md#decision-101)) |
| `decoders`, `decoded` | none | TCP alone: h11's gzip and deflate transfer-coding decoders |
| `h3_alternative` | null | TCP over TLS alone: the h3 endpoint each connection advertises (RFC 7838) |
| `ecn` | false | QUIC alone: the program reads and sets each datagram's ECN codepoint |
| `congestion_controller` | `.bbr` | QUIC alone: `.bbr`, `.cubic` or `.newreno` ([decision 143](decisions.md#decision-143)) |
| `idle_timeout_ms` | 30,000 | QUIC alone: the idle timeout the server advertises (RFC 9000 §10.1) |
| `switch_to` | `.v2` | QUIC alone: the version a client that lists it moves to (RFC 9368) |
| `retry` | null: no client proves its address | QUIC alone: the key of Retry tokens (RFC 9000 §8.1.2) |
| `retry_from_percent` | 0: every client with no token | QUIC alone, with `retry`: the share of busy QUIC slots from which a Retry goes out |
| `logs` | null | QUIC alone: each connection's qlog ([decision 102](decisions.md#decision-102)) |
| `resumes` | null | QUIC alone: RFC 9959's saved sets ([Over QUIC](#over-quic)) |
| `resume_bounds` | 4 MiB, 1 hour | QUIC alone: RFC 9959's max_jump and Lifetime |

| `server.Limits` field | Default | What it bounds |
| --- | --- | --- |
| `requests_max` | 100 | Requests a connection holds at once; over QUIC at most `server.constants.limits.quic_requests_max` |
| `data_frame_len_min` | 1,024 | The shortest DATA frame h2 sends when a window decides its length |
| `peer_resets_max` | 100 | Requests a client may cancel in one second |
| `resets_sent_max` | 100 | Streams the server may reset in one second |

One more reset than either bound ends the connection, and the `CloseReason` names the limit. Over
TLS, chapulin reads 16 KeyUpdates in a row, and the 17th ends the connection with `key_updates`.

### The turn

```zig
fn server_turn() !void {
    const input = try link.receive(.server);
    const now_ns = link.now_ns(.server);
    // Decision 110: a deadline bounds how long a peer may hold a connection. `on_instant` ends
    // each connection whose peer is late, at the instant the program woke at, and the `receive`
    // calls below report what that leaves the program to do.
    engine.on_instant(now_ns);
    try read_stream(input, now_ns);
    try read_datagrams(now_ns);
    // Both clients are done, so the server stops. `closed` follows once every connection ended.
    if (peers.closed() and !shut) {
        engine.shutdown(now_ns);
        shut = true;
    }
    try serve_all(.none, now_ns);
    for (0..datagrams_per_turn_max) |_| {
        const sent = engine.send_datagram(&datagram_output, now_ns) orelse break;
        try datagram_link.send(.server, sent.bytes);
    }
}
```

The program passes a TCP socket's bytes as `.stream`, under the handle of its connection:

```zig
fn read_stream(input: []u8, now_ns: u64) !void {
    var consumed: usize = 0;
    for (0..events_per_input_max) |_| {
        // The handle says which connection's socket read the bytes.
        const read: server.StreamBytes = .{ .connection = accepted, .bytes = input[consumed..] };
        engine.receive(.{ .stream = read }, now_ns, &received);
        consumed += received.consumed;
        const event = if (received.event) |*reported| reported else {
            if (received.consumed == 0) break;
            continue;
        };
        try serve(event, now_ns);
    }
    // What an event carried points into the queue, so the queue is consumed only now.
    link.consume(.server, consumed);
}
```

It passes each datagram with the address it came from, then `.none` until `receive` reports
nothing:

```zig
fn read_datagrams(now_ns: u64) !void {
    for (0..datagrams_per_turn_max) |_| {
        const datagram = try datagram_link.receive(.server) orelse break;
        // The engine finds the connection the datagram's connection ID names, or starts one.
        try serve_all(.{ .datagram = .{ .bytes = datagram, .from = client_address } }, now_ns);
        datagram_link.consume(.server);
    }
}

/// Passes `input` to the engine, then takes every event it reports until it reports none.
fn serve_all(input: server.Input, now_ns: u64) !void {
    var rest = input;
    for (0..events_per_input_max) |_| {
        engine.receive(rest, now_ns, &received);
        rest = .none;
        try serve(if (received.event) |*event| event else return, now_ns);
    }
}
```

The rules of `receive`:

- `receive` writes at most one event a call into the `server.ReceiveResult` the program owns
  ([decision 165](decisions.md#decision-165)).
- The program loops over `receive` until a call consumes nothing and writes no event.
- The program loops again after each call that changes a connection: an answer, `cancel`,
  `output_stream`, `sent_stream`, `send_stream`, `transport_closed`, `shutdown` and `on_instant`.
- A TCP connection may consume fewer bytes than it got, such as a pipelined h11 request.
- The program keeps the rest, and passes it again with the next read and after each event of
  that connection.
- What an event carries stays valid until the next `receive`, `on_instant`, `output_stream`,
  `sent_stream`, `send_stream`, `send_datagram`, `accept`, `transport_closed` or `shutdown`.
- The engine answers QUIC's Version Negotiation and Retry itself.

### Events

```zig
fn serve(event: *const server.Event, now_ns: u64) !void {
    switch (event.*) {
        .request => |request| try note_request(request),
        // The request is over. A `sent` result says its response is whole, and colibri reads none
        // of the program's bytes for it again. Over QUIC the client acknowledged every byte of it.
        .finished => |finished| app.done += @intFromBool(finished.result == .sent),
        else => {},
    }
    // The router takes each event of a request. It calls the route's function at the head, or for
    // the POST once its body ended. It sends what waits at `writable`, and frees the request's
    // entry at its `finished`. It hands back the events of the connections, the program's I/O.
    switch (router.handle(&app, &engine, event)) {
        .taken => {},
        .event => |other| switch (other.*) {
            // A TCP connection owes its socket bytes.
            .send => |connection| try flush(connection, now_ns),
            // RFC 9112 §9.6: the program closes only the write side of this TCP connection's
            // socket, and passes on what the socket reads. The `close` follows.
            .half_close => half_closes += 1,
            // colibri reads and writes nothing more on this TCP connection. A program closes the
            // socket once it has sent the bytes it took, and owes the engine no call: the
            // connection's `ended` follows by itself.
            .close => closes += 1,
            // The connection is over, and its slot takes a later socket or client.
            .ended => |over| try count_ended(over, now_ns),
            // The shut-down engine holds no connection.
            .closed => engine_closed = true,
            else => return error.ExchangeWrong,
        },
    }
}
```

An event names a request by its id, which names its connection too, in h11, h2 and h3 alike. The
router's `handle` takes every event of a request, as [Router](#router) shows, and hands back the
rest.

| Event | When | What the program does |
| --- | --- | --- |
| `request` | A head arrived; `end` says no body follows | Answer it, or pass it to the router |
| `body` | Body bytes arrived; `end` marks the last, and may come with no bytes | Read `end` here and in `request` |
| `trailers` | The request's trailer section arrived, in `headers` | Read it |
| `writable` | A response whose last write found no room can take more | Write again |
| `finished` | The request is over, once; `result` is `sent` or `cancelled` with a reason | Free the request's state |
| `send` | A TCP connection owes its socket bytes | Call `output_stream` or `send_stream` |
| `half_close` | h11 closes in stages (RFC 9112 §9.6, [decision 160](decisions.md#decision-160)) | Close the socket's write side; pass on what it reads |
| `close` | colibri is done with a TCP connection | Close the socket after the send ends; call nothing |
| `ended` | The connection is over, after its requests' `finished` | Drop the handle; the slot takes a later connection |
| `closed` | After `shutdown`, every connection ended | Stop |

- `http.method.standard(request.method)` gives one of RFC 9110 §9.1's eight methods, or null.
- `headers.find` and `headers.iterator` read a request's headers.
- `set_user_data` sets a word that each later event of the request carries back.

The example notes each head before the router answers it:

```zig
fn note_request(request: server.Request) !void {
    std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
    app.requests += 1;
    if (request.version.major == 3) {
        // The engine holds one QUIC connection at a time. A client can keep its connection
        // open after the response, so the server shortens its idle deadline, and the slot is
        // free sooner.
        try engine.set_timeouts(request.id.connection, .{ .idle_ns = idle_after_answer_ns });
    }
}
```

A request with `Expect: 100-continue` waits for a 100 (Continue) before its content (RFC 9110
§10.1.1). The connection writes that 100 at the engine's next read or write of the connection.

- A program that refuses such a request answers it before its next call.
- A final response, the program's own 100, or `cancel` takes the place of the owed 100.

### The response

```zig
fn greet(_: *App, _: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    try response.header("content-type", content_type);
    try response.body().writeAll(greeting);
    try response.end();
}
```

A route answers through a `server.Response` ([decision 127](decisions.md#decision-127)). `status`
is `.ok` by default, and takes a code from 100 to 599. `end` sends a head with the Content-Length
of the whole body.

| Call | What it does |
| --- | --- |
| `header(name, value)` | Adds a header before the head goes out |
| `body()` | Returns the `std.Io.Writer` of the body |
| `body().flush()` | Sends what the writer holds as one run |
| `write_kept(bytes)` | Sends bytes the program keeps valid until `finished`, with no copy |
| `end()` | Ends the response |
| `trailers(section)` | Ends the response with a trailer section |

The response writes into the request's `response_bytes`. The engine frees them at once over h11
and h2, and over h3 once the client acknowledges them (RFC 9000 §3.1). So `response_bytes` bounds
the bytes in flight, not the body ([decision 103](decisions.md#decision-103) as amended).

| Call | Errors | What the route does |
| --- | --- | --- |
| `body().writeAll(slice)` | `error.WriteFailed`, and writes nothing | Writes the slice again |
| `body().print(...)`, or a write through a middleware's wrapper | `error.WriteFailed`, after part of the message | Does not write the message again |
| `body().flush()` | `error.WriteFailed`, only when each run slot and the memory are full | Does not write its bytes again |
| `end()`, `trailers(...)`, `write_kept(...)` | `error.Full`: each of `server.constants.limits.response_pieces_max` slots holds a run | Calls again; the response is unchanged |
| `trailers(...)` | `error.NoSpaceLeft`: the memory has no room for the section | Calls again; the response is unchanged |
| `write_kept(...)` through a wrapper | `error.NoSpaceLeft`: the wrapper's write failed | Does not write the bytes again ([#129](https://github.com/c4milo/colibri/issues/129)) |

- A stream route returns from `next` with no error, and calls again in its next `next`.
- A route that returns the error from `next` has its request cancelled once the head went out.
- A trailer section longer than the memory after the headers never fits, and the route is
  cancelled.
- Over h3, a response sends about `response_bytes` a round trip, so a long stream needs a larger
  `response_bytes` ([decision 110](decisions.md#decision-110)'s `send_rate_min`).

[Design §8 step 46](design.md#step-46) holds the run and slot rules in full.

A program that answers requests itself calls the engine by the request's id:

| Call | Writes | When it finds no room |
| --- | --- | --- |
| `respond` | The head; `end` for a response with no content | `error.NoSpaceLeft` |
| `write_body` | The content | Takes fewer bytes, or `error.Blocked` |
| `write_trailers` | The trailer section | `error.NoSpaceLeft`, or `error.Blocked` while a coded response's last bytes wait |
| `cancel` | Nothing; the `finished` follows with the reason `program` | Never |

- After no room, the engine reports `writable` for the request once, and the program writes again.
- `respond` names its h11 body case in `server.ResponseHeader.request_body`: `.keep_reading` or
  `.discard`, the default.
- `shutdown` ends every connection once its requests are answered, and `closed` follows.

### Sends

```zig
const owed = engine.output_stream(connection, now_ns);
link.send(.server, owed) catch |failure| {
    engine.sent_stream(connection, 0, now_ns);
    return failure;
};
engine.sent_stream(connection, owed.len, now_ns);
```

`output_stream` returns the bytes a TCP connection owes, sealed over TLS, where the engine holds
them ([decision 176](decisions.md#decision-176)). The socket sends from there with no copy.

- The program calls `sent_stream` once each send ends, with the bytes it took: 0 for a send that
  failed.
- Until `sent_stream`, the engine keeps the bytes in place and writes new ones after them.
- A call before the send starts returns the same front, with the bytes written since.
- A program whose sends end later calls `output_stream` once a turn for each idle socket.
- A send that took part of the bytes leaves the rest owed, and the engine reports another `send`.
- The engine reports `ended` only after `sent_stream`, so no later connection takes the slot
  while a send reads it.

From [`examples/server_stream.zig`](../examples/server_stream.zig), a program that sends from a
buffer of its own:

```zig
for (0..sends_per_event_max) |_| {
    const written = engine.send_stream(connection, &output, now_ns);
    try link.send(.server, output[0..written]);
    if (written < output.len) return;
}
return error.SendUnfinished;
```

- A call that fills the buffer leaves more owed; a call that leaves room ends the `send`.
- A program whose socket is full stops, and calls again when the socket takes more.
- A program may call `send_stream` for an open connection with no `send`, such as after it writes
  a response.
- For QUIC, the turn calls `send_datagram` until it returns null, and sends each datagram to the
  address it names.

### Deadlines

```zig
fn sleep_ns() u64 {
    var wait_ns: u64 = wait_ns_max;
    if (engine.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.server));
    }
    if (peers.deadline_ns()) |deadline_ns| {
        wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.client));
    }
    // A wait of 0 would poll, so the shortest sleep is one nanosecond.
    return @max(wait_ns, 1);
}
```

`deadline_ns` names the soonest instant the engine needs, on any connection, QUIC's loss recovery
included. The program sleeps no longer, then calls `on_instant` with the instant it woke at. A
program that wakes only for bytes never ends a silent peer.

| `server.Timeouts` field | Default | What it bounds |
| --- | --- | --- |
| `first_request_ns` | 10 s | From the connection's start, TLS included, to its first whole head |
| `idle_ns` | 30 s | The wait between requests |
| `head_ns` | 10 s | The arrival of a request's head |
| `body_ns` | 300 s | The arrival of a request's whole body |
| `body_rate_min` | 1,024 bytes/s | The slowest body, after `rate_grace_ns` (10 s), over `rate_window_ns` (10 s) |
| `send_rate_min` | 1,024 bytes/s | The slowest pace at which a peer may take the response |
| `linger_ns` | 2 s | How long an ended connection waits for its last bytes to go out |
| `drain_ns` | 30 s | How long a connection's requests have after `shutdown` |

- Null turns a deadline off, and `init` refuses 0 or a span past a day with `error.TimeoutInvalid`.
- `set_timeouts` changes one connection's limits by its handle, as `note_request` does.
- `receive` and `send_stream` also fire a passed deadline of the connection they touch.
- Over h2, a request whose content is late may end with a `finished` cancelled for the timeout.
- Set `idle_ns` above your h11 clients' idle time, or a client may send on a connection as it
  closes (RFC 9112 §9.3.1).

### Closes

```zig
const closed = engine.accept(.{}, link.now_ns(.server)) orelse return error.ExchangeWrong;
// The peer closed the socket first, so the program closes its own end and tells the engine.
// A program calls `transport_closed` then, and when a socket fails. The connection's `ended`
// follows, with no `close`.
engine.transport_closed(closed);
```

A TCP socket closes in one of two ways. The engine reports `close` once the socket took every byte,
TLS close_notify too, or once `linger_ns` passes. Or the peer closes the socket or it fails, and
the program calls `transport_closed`.

- Then colibri reads and writes nothing more on the connection, and wipes its TLS secrets.
- A `finished` follows for each request: `sent`, or cancelled with the reason `closed`.
- `ended` comes last, once, and from then on the handle and every id on it name nothing.
- `ended.reason` names the deadline or limit colibri closed the connection for, or is null.
- `ended.failed` says the peer broke a protocol rule or the record layer failed.
- Before a failed TCP connection's `close`, a `send` carries what colibri owes the peer, such as
  GOAWAY or a 400.
- `ended` may come while the socket still sends its last bytes, so a later connection may take the
  slot.
- A program keys its per-socket state by the whole handle, never by `slot` alone.

### Router

From [`examples/server_exchange.zig`](../examples/server_exchange.zig):

```zig
const routes = .{
    .error_handler = on_error,
    .middleware = .{ Brand, Counted },
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .post, "/echo", echo },
        .{ .get, "/greetings/:name", greet_named, .{ .path = Name, .query = Mark } },
    },
};

/// The router's pool: an entry for each request at once. Each entry holds room for its response,
/// for the POST's content and for the copy of the POST's header. The program places it once and
/// does not move it.
const Router = server.Router(App, routes, .{ .requests = requests_max, .response_bytes = 256, .body_bytes = note.len, .header_bytes = header_bytes });
var router: Router align(@alignOf(Router)) = undefined;
```

```zig
// The router starts in place. `.{}` would copy its whole default value, each entry's buffers
// too, from a constant of the program's image (https://github.com/c4milo/colibri/issues/148).
router.init();
```

The compiler builds the route table from the program's context type and this struct ([decisions
122, 127 and 163](decisions.md#decision-122)). The struct names `error_handler` and `routes`, and
may name `middleware` and `Values`. The program calls `router.init()` once, before the first event.

| `server.RouterOptions` field | Default | What it sizes |
| --- | --- | --- |
| `requests` | 32 | Requests the router holds at once; one more gets 503 |
| `response_bytes` | none: the program names it | Each request's response memory: header and trailer copies, and body bytes the engine holds |
| `body_bytes` | none | A function route's whole body, or what a stream route's `on_data` left unread; past it, 413 |
| `header_bytes` | none | Each request's header copy for a function route with a body; past it, 431; 0 copies none |

A program names the last three, 0 included ([decision 163](decisions.md#decision-163) ruling 9).

| Route entry part | Rule |
| --- | --- |
| Method | `.get` or another of RFC 9110 §9.1's methods, or a token such as `"PATCH"`; CONNECT does not compile |
| Pattern | Segments that are literals, parameters such as `:name`, or `*` as the last; at most `server.constants.limits.path_parameters_max` parameters |
| Function or struct | A function route or a stream route |
| `.path` | A struct with one `[]const u8` field for each parameter, and `rest` for `*` |
| `.query` | `http.QueryParameters`, or a struct whose fields name the query's pairs ([Query](#query)) |
| `.middleware` | This route's chain, after the table's ([Middleware](#middleware)) |

#### Function routes

```zig
/// The path and the query of `/greetings/:name`, which the route names as `.path` and `.query`.
const Name = struct { name: []const u8 };
const Mark = struct { mark: []const u8 = "" };

/// Answers a GET of `/greetings/:name` with a greeting to the name, ended with the query's `mark`.
/// The router decodes the name and the query's pairs, and fills each struct by its field names.
/// The request context lends the two structs during this call.
fn greet_named(_: *App, ctx: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    try response.header("content-type", content_type);
    try response.body().print("hello, {s}{s}\n", .{ ctx.path(Name).name, ctx.query(Mark).mark });
    try response.end();
}
```

```zig
/// Sends the POST's content back. The router calls the function once the content ended, and
/// `request.body` reads the whole content, which the request's entry holds. The read never waits.
fn echo(_: *App, _: *server.RequestContext, request: *const server.Request, response: *server.Response) !void {
    try response.header("content-type", content_type);
    _ = try request.body.streamRemaining(response.body());
    try response.end();
}
```

A function takes the program's context, the [request context](#request-context), the request and
the response. It gets the whole request in one call ([decision 163](decisions.md#decision-163)
ruling 4).

- A request with no body gets its call at the head.
- A request with a body gets its call once the body ended, and reads it through `request.body`.
- With `header_bytes` 0, each call comes at the head, and a read of a body still to come fails with
  `error.ReadFailed`.
- The router copies a header with a body into the request's entry, because the engine reuses that
  storage.
- A GET that h2 or h3 ends in a later frame takes a copy too.
- A function sees no trailer section: it ends the body, and the call follows.
- The router ends a response the function leaves open.

```zig
fn on_error(_: *App, _: *server.RequestContext, _: *const server.Request, _: anyerror, response: *server.Response) void {
    response.status = .internal_server_error;
}
```

`error_handler` chooses the status after a route returns an error ([decision
127](decisions.md#decision-127) ruling 4). After the head went out, the router cancels the request
instead.

#### Stream routes

From [`examples/server_stream.zig`](../examples/server_stream.zig), a route that answers gRPC
messages while the body still arrives:

```zig
const Greeter = struct {
    /// What the route holds for one call: the messages it answered, and the bytes of the cut
    /// message it left unread with `keep`.
    pub const State = struct {
        messages: u32 = 0,
        kept: usize = 0,
    };

    /// Runs at the request's head, before any byte of its body arrives. The head goes out with
    /// the first bytes of the body.
    pub fn on_request(_: *App, _: *server.RequestContext, _: *State, _: *const server.Request, response: *server.Response) !void {
        try response.header("content-type", peer.content_type);
    }

    /// Runs at each event of the request's body. It answers each message that a piece holds
    /// whole, and keeps the cut message at the end of the piece: the next `next` gives its bytes
    /// again, joined with the bytes that arrive later. Once the body ended, it ends the response.
    pub fn on_data(_: *App, _: *server.RequestContext, state: *State, body: *server.RequestBodyStream, response: *server.Response) !void {
        // Bounded: each pass takes one piece.
        for (0..pieces_per_event_max) |_| {
            const piece = body.next() orelse break;
            const cut = try answer_whole(state, piece, response);
            state.kept = cut.len;
            body.keep(state.kept);
        }
        if (!body.ended()) return;
        // A body that ends inside a message cuts it short: the last piece held its bytes again.
        if (state.kept > 0) return error.MessageCut;
        // RFC 9113 §8.1: a HEADERS frame after the DATA frames carries the trailer section.
        try response.trailers(&grpc_ok);
    }

    /// Runs once the request is over. A `sent` result says the response went whole.
    pub fn on_finished(app_state: *App, _: *server.RequestContext, state: *State, result: server.Result) void {
        app_state.messages += state.messages;
        app_state.sent += @intFromBool(result == .sent);
    }
};
```

A struct route is a stream ([decision 163](decisions.md#decision-163) ruling 6). Each callback
takes the program's context, the request context and a `*State`, or a `*void` with no `State`.
The request's pool entry holds the `State`.

| Callback | Then takes | Runs |
| --- | --- | --- |
| `on_request` | The request and the response | At the head, before the body |
| `on_data` | A `*server.RequestBodyStream` and the response | At each body event, and once more for an end with no bytes |
| `next` | The response | While the response is open and has room, the body open or not |
| `on_finished` | The request's `server.Result` | At the request's `finished` |

`server.RequestBodyStream` has three calls:

1. `next()` returns the next piece with no copy, or null; the piece is valid until the next `next`
   or the end of `on_data`.
2. `keep(len)` leaves the last `len` bytes of the last piece for the next `next`, joined with later
   bytes.
3. `ended()` returns true once `next` returned null at the body's end.

The rules:

- `on_data` calls `next` until it returns null; the router drops what it leaves at the body's end.
- A route never relies on `ended()` at its last piece: over h11 and h3 the end comes later.
- At the end, a `next` after a `keep` gives the kept bytes once more as the last piece.
- Kept bytes and the next event's bytes share `body_bytes`; past it, 413.
- A wrapper of a middleware with no buffer cannot serve a stream route, and the router asserts so.
- A read of `request.body` in `on_request` fails with `error.ReadFailed`.
- A route ends its own response; with no `next`, the router ends it after the last `on_data`.
- A route that ended its response at the head gets no `on_data`, so it can refuse a request there.
- With `next`, a call that writes nothing while the body is open waits for more bytes or `writable`.
- With `next`, a route that neither ends nor fills the response after the body's end is cancelled.
- After an error of `on_data` or `next`, `error_handler` gets a request with no method, path or
  headers.
- Decision 110's body deadlines apply, so a route that waits on a quiet client sets its own with
  `set_timeouts`.

Over h11 the next request follows the body ([decision 160](decisions.md#decision-160)):

- A route that ended its response at its head reads no more body. The server drops a rest of at
  most 256 KiB, and closes for a longer or chunked one.
- A route whose response ends while the body is open: the server reads up to 256 KiB of the rest,
  then closes.
- A route that ends its response after the body's end keeps the connection.

#### Answers the router writes

| Case | Status |
| --- | --- |
| No route names the path | 404 |
| No route of the path names the method | 405, with an `allow` field (RFC 9110 §15.5.6) |
| No route of the table names the method | 501 (RFC 9110 §15.6.2) |
| The pool has no free entry | 503 |
| A query lacks a required field | 400 |
| A query has more than `http.constants.limits.query_parameters_max` pairs | 414 |
| A header copy passes `header_bytes` | 431 (RFC 6585 §5) |
| A body passes `body_bytes` | 413 (RFC 9110 §15.5.14) |

None of these calls a route. A head with no room waits for `writable`, and the router cancels one
past `requests`.

#### `match`

A program that dispatches a request itself calls `match` with the method and the path. Its `found`
gives the route's `Route` tag, such as `.@"GET /greetings/:name"`. The router applies the same
rules.

| Rule | Example path | Result |
| --- | --- | --- |
| The method comes first; the query changes nothing | `PURGE /a` with no PURGE route | `not_implemented`: 501 |
| A literal, then a parameter, then `*`, with back-up; table order does not count | `/users/me` beside `/users/:id` | `/users/me` |
| A parameter takes one segment; `*` takes one or more | `/files` against `/files/*` | No match |
| Each route names its own parameters ([decision 129](decisions.md#decision-129)) | `GET /users/:id` and `PUT /users/:user` | Each reads its own name |
| The first whole match that names the method decides ([decision 128](decisions.md#decision-128)) | `POST /v1/charges/search` | `POST /v1/charges/:charge` |
| A path that matches with no route of its method | `DELETE /greeting` | `method_not_allowed`: 405 |
| HEAD finds GET; the engine sends no content (RFC 9110 §9.3.2) | `HEAD /greeting` | The GET route |
| `OPTIONS *` | A table with no OPTIONS route | `not_implemented`; else `not_found` |
| Each segment is percent-decoded (RFC 3986 §2.1) | `/users/%6De` | `/users/me` |
| A segment that encodes "/", "\\" or NUL (RFC 3986 §7.3) | `/a/%2F` | No match |
| A trailing "/" names its own resource (RFC 3986 §6.2.4) | `/a/` against `/a` | No match |
| A byte outside `pchar`, an empty inner segment, or a dot-segment | `/a//b`, `/a/%2E%2E` | No match |
| A path longer than `server.constants.limits.path_len_max`, query included | | No match |

- A decoded value lives in the router's `PathParameters` until the next request.
- An undecoded value is a slice of the path, valid until the engine call that `Engine.receive`
  lists.
- A route that keeps a value longer copies it into its `State`.

#### Route tables that do not compile

A malformed route table, or one with a conflict, does not compile, and the error names the entry and
the rule.

| Error | Cause |
| --- | --- |
| `route_unreachable` | No request reaches the route, such as `GET /a/:x` beside `GET /a/*` and `GET /a/:x/*` |
| `methods_too_many` | The table names more than `server.constants.limits.route_methods_max` methods, 10 |

The check runs at compile time and adds no cost to `match`.

### Request context

From [`examples/colibri_server.zig`](../examples/colibri_server.zig):

```zig
const Values = struct {
    /// The number of the request among those the server took, which `Numbered` writes.
    number: u32 = 0,
};

/// A middleware of the route table: it numbers each request in the request's own values. The
/// program's state is one for every request, and the values are one for each.
const Numbered = struct {
    pub fn on_request(state: *App, ctx: *server.RequestContext, _: *const server.Request, _: *server.Response) !server.middleware.Next {
        number(state, ctx);
        return .next;
    }

    /// Gives the request the next number.
    fn number(state: *App, ctx: *server.RequestContext) void {
        state.taken += 1;
        ctx.values(Values).number = state.taken;
    }
};
```

A `server.RequestContext` is the request's own object ([decision
163](decisions.md#decision-163)). Each route, struct callback, middleware hook and `error_handler`
of one request gets the same one, after the program's context. The route table names the values'
type as `.Values = Values`.

| Call | Returns | Valid |
| --- | --- | --- |
| `id()` | The request's `server.RequestId` | Always |
| `values(T)` | A `*T` to the request's values, which start as `.{}` | The whole request |
| `path(P)` | A `*const P` to the route's `.path` | The route's first call alone |
| `query(Q)` | A `*const Q` to the route's `.query` | The route's first call alone |

- Each field of `Values` has a default, or the table does not compile.
- A callback keeps no pointer to the request context after it returns.
- A middleware copies the bytes it keeps into `Values`, and keeps no slice of the request.
- A struct route copies a path or query value it needs later into its `State`.
- A middleware and `error_handler` read no path and no query.
- The program halts with a message on a wrong type for `values`, `path` or `query`.
- The program halts on `path` or `query` outside the route's first call.

A test makes a request context with no router:

```zig
fn check_numbered() !void {
    var state: App = .{};
    var values: Values = .{};
    const id: server.RequestId = .{ .connection = .{ .slot = 0, .generation = 0 }, .number = 1 };
    var ctx: server.RequestContext = .init(id, Values, &values);
    Numbered.number(&state, &ctx);
    if (values.number != 1) return error.RequestNotNumbered;
}
```

A test that builds a `server.Request` gives `body` a reader, such as `.fixed(&.{})`, because `body`
has no default.

### Middleware

From [`examples/server_exchange.zig`](../examples/server_exchange.zig):

```zig
const Brand = struct {
    pub fn on_request(_: *App, _: *server.RequestContext, _: *const server.Request, response: *server.Response) !server.middleware.Next {
        try response.header("server", "colibri");
        return .next;
    }
};
```

```zig
const Counted = struct {
    pub const State = struct {
        writer: std.Io.Writer = undefined,
        inner: *std.Io.Writer = undefined,
        bytes: usize = 0,
    };

    pub fn wrap_response(_: *App, _: *server.RequestContext, state: *State, _: *const server.Request, _: *server.Response, inner: *std.Io.Writer) ?*std.Io.Writer {
        state.* = .{ .writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} }, .inner = inner };
        return &state.writer;
    }

    pub fn finish_response(app_state: *App, _: *server.RequestContext, state: *State) !void {
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

A middleware is a struct the router calls before a route ([decision
127](decisions.md#decision-127) ruling 5). The table's chain runs first, then the route's, as
`.{ .get, "/admin", admin, .{ .middleware = .{Auth} } }`. A chain is a tuple, so `++` joins two.

| Hook | Takes, after the program's context and the request context | Runs |
| --- | --- | --- |
| `on_request` | The request and the response; returns `.next` or `.answered` | At the head, in order |
| `wrap_body` | `*State`, the request and the reader; returns `?*std.Io.Reader` | At the head, after `on_request` |
| `wrap_response` | `*State`, the request, the response and the writer; returns `?*std.Io.Writer` | At the head, after `on_request` |
| `finish_response` | `*State`; returns an error union of `void` | When the route ends a wrapped response, from the route outward |
| `on_finished` | The request's result | At the request's end, in reverse order, for each middleware reached |

- `.answered` means the middleware wrote the response, and the router calls nothing more.
- An error of `on_request` goes to `error_handler`; an error of `finish_response` cancels the
  request.
- No middleware calls the next one.
- A read of `request.body` in `on_request` fails with `error.ReadFailed`.
- A wrap hook that returns null keeps the reader or writer it got.
- A wrapper writes nothing before the route starts the body.
- The router flushes a wrapper with no `finish_response`, then ends the response.
- `write_kept` copies its bytes through the wrapper.
- A middleware declares `finish_response` only beside `wrap_response`.
- Each field of a `State` has a default, from which each request starts.
- A `State` belongs to one middleware, and the [request's values](#request-context) belong to the
  request.

### Query

```zig
const Mark = struct { mark: []const u8 = "" };
```

`request.path` holds the path, and `request.query` the bytes after the first "?", or null
([decision 127](decisions.md#decision-127)). The router fills a route's `.query` struct by field
name before the call, and `ctx.query(Mark)` reads it, as `greet_named` shows.

| `.query` field type | A query with no such pair |
| --- | --- |
| `[]const u8` with no default | 400, with no call |
| `?[]const u8` | null |
| A field with a default | The default |

- A route whose `.query` is `http.QueryParameters` reads pairs by name through
  `ctx.query(http.QueryParameters)`.
- `get` returns the first value of a name.
- The parser follows the WHATWG URL Standard: "&" and the first "=" split, "+" is a space, and each
  part is percent-decoded.
- `http.QueryParameters.read` refuses more than `http.constants.limits.query_parameters_max` pairs,
  32, or a buffer too small.

### Over QUIC

From [`examples/server_resume.zig`](../examples/server_resume.zig):

```zig
fn take(_: *anyopaque, address: server.Address, now_ns: u64) ?server.ResumeState {
    _ = now_ns;
    taken += 1;
    const entry = find_or_add(address) orelse return null;
    entry.open += 1;
    // RFC 9959 §3.2: "Only one connection can use a specific set of saved CC parameters".
    if (entry.open > 1) return null;
    return entry.saved;
}
```

The same events and calls serve h3. A program moves datagrams with addresses, and keeps time for
each connection.

| What differs | Over QUIC |
| --- | --- |
| Body bytes | The connection reads the program's bytes in place until `finished`; `sent` comes once the peer acknowledged every byte |
| Time | `deadline_ns` includes loss recovery and acknowledgments; `idle_timeout_ms` ends a peer that sends nothing |
| Congestion | `congestion_controller`: `.bbr`, `.cubic` or `.newreno` ([decisions 133, 136 and 143](decisions.md#decision-133)); BBRv3 draws from the context in `tls` ([decision 175](decisions.md#decision-175)) |
| Sockets | No `send` and no `close`: a QUIC connection has no socket of its own |
| Address proof | With `retry`, a client proves its address (RFC 9000 §8.1.2) once `retry_from_percent` of the slots are busy ([decision 110](decisions.md#decision-110)) |
| Logs | `logs` gives each connection a qlog log ([decision 102](decisions.md#decision-102)) |

`ended` means what it means over TCP. Its `reason` names the deadline or the limit, and `failed`
says the client broke a protocol rule.

`Config.resumes` lets a client's later connection start near an earlier one's rate, by RFC 9959's
Careful Resume ([decision 149](decisions.md#decision-149)). The program keeps a
`server.ResumeState` for each client address, and gives the engine a `server.ResumeProvider` over
them.

| Provider call | When | What it gets or returns |
| --- | --- | --- |
| `take` | A connection starts | Returns the host's set, or null |
| `put` | The connection ends | What the connection observed, or null to keep the set |
| `drop` | The connection had to retreat, before `put` | The set goes |

- `put` and `drop` name the address `take` got, after a migration too.
- A connection that moved to another host gives null to `put`.
- A provider gives a set to one open connection of a host at a time (RFC 9959 §3.2).
- A `ResumeState` carries its version and size, so a program may store its bytes.

The client takes the same three calls in `client.Config.resumes`, keyed by the server's address.

## The client

A program that drives a `client.ConnectionPool` itself places a request and a response for each
exchange. From [`examples/client_exchange.zig`](../examples/client_exchange.zig):

```zig
var get_headers: [1024]u8 = undefined;
var get_body: [greeting.len]u8 = undefined;
var post_body: [note.len]u8 = undefined;
const get: client.Request = .{ .method = "GET", .path = "/greeting" };
var get_response: client.Response align(@alignOf(client.Response)) = .{
    .headers = .{ .buffer = &get_headers },
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

An exchange is one request with its response, from `request` to its one `finished` event. The
pool carries the exchanges to one origin over QUIC (h3) or TCP (h2 or h11), and tells the program
which transport to open ([decision 120](decisions.md#decision-120)).

- Keep the request, the response and each slice they name in place until `finished`, or until
  `cancel` returns ([decision 124](decisions.md#decision-124)).
- The client only reads the request, so it may be a `const`.
- Each header in `headers.buffer` takes its name, its value and four bytes.
- Read a header with `headers.get(name)`, the first value or null, and each line with
  `headers.iterator()`.
- `trailers` holds the response's trailers the same way, such as `trailers.get("grpc-status")`.
- An empty buffer drops its section; a section that does not fit ends the exchange `too_large`.
- Send request trailers in `Request.trailers` ([decision 152](decisions.md#decision-152)); they
  go after the whole body.
- With a buffer in `Response.trailers`, the client sends `te: trailers`, unless the request names
  TE.
- `request` returns `error.InvalidTrailer` for a forbidden or invalid trailer.
- Over h3, a request whose header and trailer sections do not fit together ends `invalid`.

The pool and the memory for its TCP connections and exchanges are the program's too:

```zig
var pool: client.ConnectionPool(.{}) align(@alignOf(client.ConnectionPool(.{}))) = undefined;
// The memory the pool holds its TCP connections and its exchanges in, whose size the counts in
// `client.Config` give (decision 125).
var pool_memory: [client.ConnectionPool(.{}).memory_bytes(.{})]u8 align(client.ConnectionPool(.{}).memory_alignment) = undefined;
```

`ConnectionPool.memory_bytes(counts)` is pure, so it sizes a static array or a run-time mapping
([decision 125](decisions.md#decision-125)). A program that never speaks h3 holds a pool with no
QUIC state. From [`tools/consumer/main.zig`](../tools/consumer/main.zig):

```zig
// The pool speaks h2 over TCP alone, so it holds no QUIC state (decision 124).
const ConnectionPool = client_module.ConnectionPool(.{ .quic = false });
var asked: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
```

[The memory table](performance.md#memory-per-connection) gives both sizes. That pool has no
`start_quic`, and its `init` takes `null` for the receive pool.

### Start the pool

From [`examples/client_exchange.zig`](../examples/client_exchange.zig):

```zig
// One configuration serves both transports. Its TLS value names no protocol: the pool
// offers h3 over QUIC, and h2 then http/1.1 over TCP, as `protocols` allows them. A pool opens
// TCP first by default, and `.prefer = .quic` makes it open QUIC first.
client_config = .{
    // The CPU features the pool's decoders run on: the context's, which the program detected
    // once. colibri never asks the CPU (decision 169).
    .cpu_features = crypto.features,
    // Every value the pool draws, and every draw of its TLS sessions, comes from the
    // context's source.
    .tls = .{ .trust = .{ .web_pki = .{ .anchors = anchors, .server_name = origin } }, .crypto = crypto },
    .authority = origin,
    .protocols = .{ .prefer = .quic },
};
// The pool takes what DNS knows as values: the server's addresses and its port.
const known: client.Destination = .{ .addresses = &server_addresses, .port = server_port };
// `init` builds the TLS configuration of each transport inside the pool, which stays in
// place from here on. It keeps the pool's TCP connections and its exchanges in `pool_memory`,
// which `.{}`, the default counts, sizes. The receive pool is what makes the pool offer QUIC.
try pool.init(&pool_memory, &client_config, &known, receive_pool.storage());
// `request` only takes a request and its response. The pool asks for a transport, and
// sends the request over the first connection that completes its handshake, so a program asks
// at once and never waits.
_ = try pool.request(&get, &get_response);
_ = try pool.request(&post, &post_response);
```

`init` copies the `client.Config`, so the program may change or free it after `init` returns. The
fields:

| Field | Default | What it sets |
| --- | --- | --- |
| `cpu_features` | none | What `CpuFeatures.detect()` found once; colibri never asks the CPU ([decision 169](decisions.md#decision-169)). |
| `authority` | none | `:authority` in h2 and h3, Host in h11. |
| `tls` | `null` | One `tls.Client` for TCP and QUIC, with an empty `alpn`; `null` runs cleartext over TCP alone. |
| `protocols` | h11, h2, h3 on | The versions offered through ALPN; TCP opens only while h11 or h2 is on ([decision 117](decisions.md#decision-117)). |
| `protocols.prefer` | `.tcp` | The transport that opens first; `.quic` opens QUIC first. |
| `fallback_delay_ns` | 250 ms | Under `.prefer = .quic`, how long QUIC's handshake runs before TCP opens beside it. |
| `quic_unadvertised` | `true` | Whether QUIC may open with no HTTPS record or Alt-Svc that names h3. |
| `tcp_connections` | 1 | TCP connections held, at most 64. |
| `requests` | 16 | Exchanges held at once, at most 1,024. |
| `codings` and the decoder pools | none | Content codings offered and their decoders ([decision 101](decisions.md#decision-101)). |
| `timeouts.connect_ns` | 10 s | How long a TCP connect may take; your loop applies it, as `colibri.Client` does. |
| `timeouts.drop_ns` | 50 ms | How long an h11 connection drops a cancelled response ([decision 146](decisions.md#decision-146)). |
| `idle_timeout_ms` | 30 s | QUIC's idle timeout. |
| `congestion_controller` | `.bbr` | QUIC's controller: `.bbr`, `.cubic` or `.newreno` ([decision 133](decisions.md#decision-133)). |
| `ecn` | `false` | Whether the program reads and sets each datagram's ECN codepoint. |

- QUIC is offered only with a receive pool, a `tls` value and `protocols.h3`.
- Size the receive pool, `client.ReceivePool(.{ .capacity = n })`, to the longest response.
- `init` builds TLS state inside the pool, so do not move the pool after `init`.
- Call `init` again only with no open transport and no exchange.

`init` returns these errors:

- `error.NoVersion`: the configuration offers neither transport.
- `error.VersionUnavailable`: h3 is on, and the pool holds no QUIC.
- `error.TooManyAnchors`, `error.TooManySuites` or `error.SuitesUnavailable`: the TLS value names
  more than a TLS configuration holds.

### Each turn

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

`link` and `datagram_link` stand in for the program's TCP and UDP sockets. Pass each datagram
with the address it came from; the pool consumes it whole:

```zig
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
```

Pass the TCP bytes until the pool consumes nothing and reports nothing:

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
        // The bytes the closed socket read are its connection's, which is over: they are dropped.
        if (event == .close and transport_of(event.close) == .tcp) consumed = input.len;
    }
    // What an event carried points into the queue, so the queue is consumed only now.
    link.consume(.client, consumed);
}
```

- Pass every byte you still hold, or `.none` when you hold none.
- The pool may consume fewer bytes than given; pass the rest again on the next call.
- Read the pool again after each send, each event and each `on_instant`.

The loop bound comes from the pool:

```zig
const receive_calls_max = (link_module.queue_len_max + 1) * (client.ConnectionPool(.{}).receive_events_without_input_max(.{}) + 1);
```

| Name | What it bounds |
| --- | --- |
| `client.constants.limits.stream_input_len_min` | The fewest TCP bytes to hold, so `receive` can take an h11 head, an h2 frame or a TLS record whole. |
| `client.constants.limits.stream_output_len_min` | The smallest `output` for `send_stream`: the largest TLS record. |
| `ConnectionPool.receive_events_without_input_max(counts)` | The most `receive` calls in a row that report an event and take no byte. |

### Events

```zig
fn report(event: client.Event, now_ns: u64) !void {
    switch (event) {
        .open => |open| try open_transport(open, now_ns),
        // The TCP connection owes bytes, which the program writes into its socket.
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
        // No body of the program goes in pieces (decision 153).
        .body_taken, .headers, .body => return error.ExchangeWrong,
        // The shut-down pool is over: every exchange ended and every transport closed.
        .closed => pool_closed = true,
    }
}
```

| Event | What the program does |
| --- | --- |
| `open` | Open a UDP flow or connect a TCP socket to `open.to`, then call `start_quic` or `start_tcp` with `open.connection`. |
| `send` | Call `send_stream` for the connection until a call leaves room in its output. |
| `connected` | Nothing: it names the connection that takes the exchanges and its version. |
| `ticket` | Call `take_ticket`, and offer the ticket in the last argument of a later start. |
| `close` | Close the socket, and drop the bytes it read that you still hold. |
| `finished` | Read the response; its memory and the request's are yours again. |
| `closed` | Nothing: after `shutdown`, every exchange ended and every transport closed. |
| `headers`, `body`, `body_taken` | Only a [streamed exchange](#streamed-bodies) reports them. |

- Each connection event names a `client.ConnectionHandle`, which its `open` named first.
- Keep `open.to`'s `scope_id` in the socket address's `sin6_scope_id` for a link-local IPv6
  address.
- Set `TCP_NODELAY` on each TCP socket, so a small request leaves at once.
- Under `.prefer = .tcp`, QUIC opens once TCP fails; under `.quic`, TCP opens when QUIC fails or
  `fallback_delay_ns` passes.
- The first connection whose handshake completes takes the exchanges.

Start each transport an `open` names. Its TLS session draws from the source of the context in
`tls` ([decision 175](decisions.md#decision-175)):

```zig
fn open_transport(open: client.Open, now_ns: u64) !void {
    std.debug.print("client: open {s}\n", .{@tagName(open.transport)});
    opens.getPtr(open.transport).* += 1;
    connections.set(open.transport, open.connection);
    // A start the TLS stack refuses ends the attempt, which the pool reports.
    switch (open.transport) {
        // The UDP socket needs no connect.
        .quic => pool.start_quic(now_seconds, now_ns, null) catch {},
        .tcp => {
            // The link stands where the socket would be: the server's listener accepts the
            // socket the program connects.
            try peer.accept();
            pool.start_tcp(open.connection, now_seconds, null) catch {};
        },
    }
}
```

Write what a TCP connection owes on `send`:

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

A program that opens no later connection wipes each ticket:

```zig
fn take_ticket(connection: client.ConnectionHandle) void {
    const ticket = pool.take_ticket(connection) orelse return;
    var held = ticket;
    held.wipe();
    tickets += 1;
}
```

### Results

```zig
fn arrived(response: *const client.Response, status: client.Status, content: []const u8) bool {
    if (response.result != .response or response.status != status) return false;
    return std.mem.eql(u8, response.body_received(), content);
}
```

The response's `result`, a `client.Result`, says how the exchange ended:

| Result | What it means |
| --- | --- |
| `response` | The final response arrived whole: `status`, `body_received()`, `headers` and `trailers`. |
| `refused` | The server processed none of the request, so you may send it on another connection. |
| `reset` | The server reset the stream; `error_code` names why. |
| `closed` | The connection ended before the response was whole; the server may have processed the request. |
| `malformed` | colibri refused the response under the protocol's rules, or a content coding was corrupt. |
| `invalid` | The protocol refuses to send the request. |
| `too_large` | The body, the headers or the trailers did not fit their buffer. |

- Read `status`, a `client.Status`, only when `result` is `response` or `too_large`
  ([decision 158](decisions.md#decision-158) ruling 5).
- A code outside 100-599 reads as `.server_error` from `status.class()`; `@intFromEnum(status)`
  gives the raw code.
- A Content-Length larger than `body` ends the exchange at its head, and over h11 the connection
  too.

Call `transport_closed` for a socket that fails to connect, that the peer closed, or that failed
later:

```zig
fn connect_refused() !void {
    const now_ns = link.now_ns(.client);
    // The pools to one origin share its configuration. With no receive pool this one offers
    // TCP alone.
    const known: client.Destination = .{ .addresses = &server_addresses, .port = server_port };
    try refused_pool.init(&refused_memory, &client_config, &known, null);
    _ = try refused_pool.request(&refused_get, &refused_get_response);
    for (0..receive_calls_max) |_| {
        const received = refused_pool.receive(.none, now_ns);
        switch (received.event orelse return error.ExchangeWrong) {
            // The connect failed, so the transport closed before its connection started.
            .open => |open| refused_pool.transport_closed(open.connection),
            .finished => refused_pool.shutdown(),
            .closed => return,
            .send, .close, .connected, .ticket, .body_taken, .headers, .body => return error.ExchangeWrong,
        }
    }
    return error.ExchangeWrong;
}
```

With no transport left, the exchange ends `refused`. The pool moves a refused exchange to another
connection, and sends an idempotent request once more when its connection closed before any
response arrived ([decision 124](decisions.md#decision-124)). A request goes out twice at most
(`client.constants.limits.moves_max`), and any other method ends `closed` for you to decide.

- When a moved exchange asks for a second socket you do not open, call `transport_closed` with
  the handle that `open` named.

### Time and cancel

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

`deadline_ns` names the instant the pool next needs `on_instant`. The pool's limits are
`timeouts.connect_ns`, `timeouts.drop_ns` and QUIC's idle timeout. No deadline bounds a whole
exchange, so set your own limit on each one and call `cancel` when it passes.

- `cancel(id, now_ns)` ends an exchange with no `finished` event; h2 and h3 reset its stream.
- h11 reads and drops the rest of a cancelled response ([decision 146](decisions.md#decision-146)).
- The h11 connection fails instead on a close-delimited response, past
  `client.constants.limits.drop_len_max` (256 KiB), or when `drop_ns` runs out.

### Several TCP connections

From [`examples/client_pool.zig`](../examples/client_pool.zig), a pool of four h11 connections:

```zig
const ConnectionPool = client.ConnectionPool(.{ .quic = false });
const tcp_connections: u16 = link_module.streams_max;
var pool: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
var pool_memory: [ConnectionPool.memory_bytes(.{ .tcp_connections = tcp_connections })]u8 align(ConnectionPool.memory_alignment) = undefined;
var client_config: client.Config align(@alignOf(client.Config)) = undefined;
```

```zig
client_config = .{
    .authority = origin,
    .protocols = .{ .h2 = false, .h3 = false },
    .tcp_connections = tcp_connections,
    // The CPU features the pool's decoders run on. The program asks its CPU once, here, and
    // colibri never asks it (decision 169).
    .cpu_features = .detect(),
};
```

Keep one socket for each slot that `open.connection.slot` names, and read each with its handle:

```zig
fn drain(slot: u32, now_ns: u64) !void {
    const socket = sockets[slot];
    const input = link.queue(slot, .client);
    var consumed: usize = 0;
    for (0..receive_calls_max) |_| {
        const held = input[consumed..];
        // An event may close this socket, or open another in its slot: its bytes then go to no
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
    // A socket closed during the read dropped its bytes with it.
    if (socket != null and std.meta.eql(sockets[slot], socket)) link.consume(slot, .client, consumed);
}
```

An h11 pool opens another connection when an exchange waits and no open connection has room. An
h2 pool opens no second connection (RFC 9113 §9.1). Give a later DNS answer with `set_destination`:

```zig
// A later DNS answer names another address. Each connection that opens from now on goes
// to it, and each open connection keeps its exchanges.
pool.set_destination(&.{ .addresses = &second_addresses, .port = server_port });
```

- Keep `addresses` in place until the next `set_destination` or `init`.
- The port stays the origin's, and the pool keeps the h3 alternative it learned unless the new
  values name one.

### Streamed bodies

From [`examples/client_stream.zig`](../examples/client_stream.zig), a gRPC-shaped call streamed both
ways over h2 in cleartext:

```zig
const call: client.Request = .{
    .method = "POST",
    .path = peer.path,
    .headers = &.{.{ .name = "content-type", .value = peer.content_type }},
    .streamed = .{ .request = true, .response = true },
    .trailers = &.{.{ .name = peer.count_trailer, .value = peer.count_value }},
};
var piece: [piece_len]u8 = undefined;
var header_buffer: [section_len]u8 = undefined;
var trailer_buffer: [section_len]u8 = undefined;
var response: client.Response align(@alignOf(client.Response)) = .{
    .body = &piece,
    .headers = .{ .buffer = &header_buffer },
    .trailers = .{ .buffer = &trailer_buffer },
};
```

The pool copies no piece of either body ([decision 153](decisions.md#decision-153)). A streamed
request has an empty `body`, and the response's `body` holds one piece at a time. `client.Streamed`
has three fields:

- `request`: the request body goes out through `write_body`.
- `response`: the response body comes in through `body` events.
- `request_len`: the body's length when known, sent as Content-Length; without it h11 sends chunks.

Hand each request piece with `write_body`:

```zig
fn hand_next() !void {
    if (handed == payloads.len or taken < handed) return;
    if (received_len < end_of(handed)) return;
    const end: client.PieceEnd = if (handed + 1 == payloads.len) .last else .more;
    // The pool copies none of the message: `chat` stays in place until its `body_taken`.
    try pool.write_body(call_id, chat[end_of(handed)..end_of(handed + 1)], end);
    handed += 1;
}
```

- Keep each piece in place until its `body_taken` event.
- Hand the next piece only after `body_taken`: the pool holds one piece of an exchange.
- Over h3, `body_taken` comes when the server acknowledged the piece.

`write_body` returns a `client.WriteBodyError`:

- `UnknownRequest`: the pool holds no exchange with that id.
- `PieceHeld`: the pool has not taken the last piece.
- `BodyEnded`: an earlier piece ended the body.
- `BodyStopped`: the exchange ended, or an h3 server sent STOP_SENDING; the exchange still
  finishes.

```zig
// The response's status and headers arrived, before any of its body.
.headers => |id| try on_headers(id),
// The connection reads the message no more: its memory is the program's again.
.body_taken => |id| {
    if (id != call_id) return error.ExchangeWrong;
    taken += 1;
    try hand_next();
},
// `body` holds a piece of the response, which `on_piece` copies out and releases.
.body => |held| try on_piece(held),
```

```zig
fn on_piece(held: client.Event.Piece) !void {
    if (held.id != call_id or !heard_headers) return error.ExchangeWrong;
    if (received_len + held.len > received.len) return error.ExchangeWrong;
    @memcpy(received[received_len..][0..held.len], response.body[0..held.len]);
    received_len += held.len;
    pool.release_body(held.id);
    try hand_next();
}
```

Three events carry a streamed response:

- `headers`: the status and headers are in the `Response`, before the first piece.
- `body`: `body[0..len]` holds the next piece; give it back with `release_body(id)`.
- `finished`: comes after you release the last piece, with the trailers in `Response.trailers`.

Release each piece soon; a piece you hold stops its stream
([decision 49](decisions.md#decision-49)). Over h11 and h2 a held piece stops the whole connection.

```zig
fn on_finished(ended: client.Finished) !void {
    if (ended.response.result != .response) return error.ExchangeWrong;
    const status = ended.response.trailers.get("grpc-status") orelse return error.ExchangeWrong;
    if (!std.mem.eql(u8, status, "0")) return error.ExchangeWrong;
    finished = true;
    pool.shutdown();
}
```

- You may call `release_body` while you read the pool's events.
- Over h2 and h3 the request body may go on after the response's head; over h11 a response that
  ends first ends the connection ([decision 124](decisions.md#decision-124) ruling 2).
- The pool moves a streamed exchange only before its first `body_taken` and its `headers`; after
  that a refused exchange ends `closed`.
- `cancel` gives back the request piece and the response piece at once.
- Release each piece and pass the rest of the input before `transport_closed`.
- The client offers no content coding for a streamed response.
- Each `release_body` starts a new run of `receive_events_without_input_max`.

## The protocol modules

Use these modules for one version by itself: h11 or h2 with no TLS or your own TLS, or QUIC with
no HTTP. The `server` and `client` modules are built on the same calls.

## h11

One `h11.Connection` is one HTTP/1.1 connection. From
[`examples/h11_exchange.zig`](../examples/h11_exchange.zig), where `link` stands in for a socket,
a client writes a request head and sends its body from its own buffer:

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

A server passes what arrived to `receive` and answers each request once it has read it:

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

An answer is a head, the body and the end, each written into the output buffer:

```zig
const head_len = try server.write_response(&output, 200, "OK", &.{
    .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{greeting.len}) },
});
const written = head_len + try server.write_body(output[head_len..], greeting);
_ = try server.write_end(output[written..], &.{});
try link.send(.server, output[0..written]);
```

- Call `receive(input, decoded)` until it consumes nothing and returns no event; pass
  `decoded` empty when the connection has no decoders.
- `count_body` sends the body from your buffer, and `write_body` copies it into the output
  ([decision 95](decisions.md#decision-95)).
- A client pipelines, and stops after a request that is not idempotent until its final response
  arrives ([decision 88](decisions.md#decision-88)).
- A server reads the next request only after it writes the final response to the current one
  ([decision 92](decisions.md#decision-92)).
- When `receive` fails and `has_pending` is true, call `write_pending`, send its bytes, then
  close.
- Close the transport when `should_close` says so, and call `transport_closed` when it closes.
- Over TLS, call `attach_tls` once the handshake completes, and pass every record through
  `decrypt` and `encrypt`.

### The gzip and deflate transfer codings

No example places a decoder pool yet. Place one `h11.coding.Pool(.{})`, call `init()` once, and
give its `storage()` to each connection in `Options.decoders`
([decision 91](decisions.md#decision-91)). `receive` then decodes into `decoded`, and each `data`
event is a slice of it, valid until the next call ([decision 98](decisions.md#decision-98)).

| Case | A server answers | A client |
| --- | --- | --- |
| No pool | 501 | refuses a coded response, and offers no coding in TE |
| Every decoder taken | 503 | |
| Corrupt body | 400 | |
| A feature stdx refuses | 501 | |

## h2

One `h2.Connection` is one HTTP/2 connection. Each side of
[`examples/h2_exchange.zig`](../examples/h2_exchange.zig) runs this round: read every frame, then
write what colibri owes, with the server's answer between:

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

The server's answer writes the head, then a DATA frame header, then the content from its own
memory:

```zig
const head_len = try server.write_response(buffer, stream_id, 200, &.{
    .{ .name = "content-length", .value = std.fmt.comptimePrint("{d}", .{greeting.len}) },
}, false);
// The windows and the buffer hold the whole greeting, which `sendable_len` says before it is
// written. A program with more content than they hold writes what it says, and the rest after
// the peer's WINDOW_UPDATE.
std.debug.assert(server.sendable_len(stream_id, buffer.len - head_len, greeting.len) == greeting.len);
const frame = buffer[head_len..];
const data = try server.write_data_header(frame[0..h2.constants.protocol.frame_header_len], frame.len, stream_id, greeting.len, true);
std.debug.assert(data.consumed == greeting.len);
// The frame's data follows its header, before any other byte of the connection.
@memcpy(frame[data.written..][0..data.consumed], greeting[0..data.consumed]);
return head_len + data.written + data.consumed;
```

| Call | What it writes or returns | When |
| --- | --- | --- |
| `receive(input, now_ns)` | consumes at most one frame, returns at most one event | each time bytes arrive |
| `write_pending(output, now_ns)` | the preface, SETTINGS, acknowledgments, WINDOW_UPDATE, RST_STREAM, GOAWAY | when `has_pending` is true |
| `write_request` | a request head on a new stream | a client opens a stream |
| `write_response` | a response head | a server answers a stream |
| `write_data` | DATA, as much as the flow-control windows allow | content in colibri's output |
| `sendable_len` | the bytes `write_data` would send now | before a write; at 0, wait for WINDOW_UPDATE |
| `write_data_header` | the 9-byte header of the frame `write_data` would write | content in your own buffer ([decision 138](decisions.md#decision-138)) |
| `write_trailers` | a trailer section that ends the message | after the final header section (RFC 9113 §8.1) |
| `reset_stream` | nothing; the next `write_pending` writes RST_STREAM | to end one stream ([decision 113](decisions.md#decision-113)) |
| `shutdown` | nothing; begins a graceful close | to close the connection |

- `connection.field_section()` holds the field section of a head or trailers event.
- `event.ended_stream()` names the stream an event ended.
- Send a frame's `consumed` bytes right after the header from `write_data_header`, before any
  other byte.
- Over TLS, the header and the content may go in one record through `encrypt_parts`
  ([decision 139](decisions.md#decision-139)).

## TLS

The `tls` module runs the TLS 1.3 sessions of `stdx.crypto` behind the vtables h11, h2 and QUIC
take ([decision 174](decisions.md#decision-174)). From
[`tools/consumer/main.zig`](../tools/consumer/main.zig), a program makes one `stdx.crypto.Context`
when it starts:

```zig
pub fn main(init: std.process.Init) !void {
    // The random source of every TLS session: the operating system's entropy.
    var secure: SecureRandom = .{ .io = init.io };
    // The CPU features the program detects once, for its codecs (decision 169) and for TLS.
    const cpu_features: platform.CpuFeatures = .detect();
    // PSTATE.DIT on this thread, where the core has FEAT_DIT. Elsewhere the call changes nothing.
    _ = platform.set_data_independent_timing(cpu_features, true);
    // The program's one context, which each TLS value holds (decision 175).
    const crypto = stdx.crypto.init(cpu_features, secure.random());
```

Its random source wraps `io.randomSecure` and halts when a draw fails:

```zig
const SecureRandom = struct {
    io: std.Io,

    fn fill(pointer: *anyopaque, bytes: []u8) void {
        const self: *SecureRandom = @ptrCast(@alignCast(pointer));
        self.io.randomSecure(bytes) catch |err| std.debug.panic("no entropy: {t}", .{err});
    }

    fn random(self: *SecureRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};
```

It converts its values once into a configuration, then starts a session and writes its
ClientHello:

```zig
const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
try tls_config.init(.{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } },
    .alpn = &.{ "h2", "http/1.1" },
    .crypto = crypto,
});
try tls_client.start(&tls_config, now_seconds, null);
const hello = try tls_client.handshake(&.{}, &output);
```

- Each TLS value holds the one context ([decision 175](decisions.md#decision-175)).
- The random source feeds every session secret, QUIC connection ID, token and grease value.
- Call `set_data_independent_timing` on each thread that runs TLS.
- Without the AES and DIT statement, a session offers TLS_CHACHA20_POLY1305_SHA256 alone.
- `handshake` takes the bytes the socket read, and writes what the session owes the peer.
- An output of `tls.record.Client.handshake_output_len_min` bytes takes all a client owes in one
  call.
- When `handshake` fails, send the first `failure_written()` bytes of the output, then close
  (RFC 9846 §6.2).
- Once the handshake completes, pass the session's `provider()` to the connection's `attach_tls`.
- Each configuration takes at most `anchors_max` anchors and `protocols_max` ALPN protocols.
- The TLS stack bounds a run of KeyUpdates; a server's `Ended.reason` names it as the limit
  `key_updates`.

### Alerts and negotiated parameters

A program that finds an error after the handshake sends the alert with `fail`, then closes. Here
the handshake has not completed, so the call returns `error.NotConnected` and writes nothing:

```zig
if (tls_client.fail(.record_overflow, &output)) |_| return error.FailWrong else |failure| {
    if (failure != error.NotConnected) return error.FailWrong;
}
```

- `fail` writes at most `tls.record.alert_record_len` bytes; `tls.record.Server` has it too.
- A refused `fail` returns a `tls.record.FailError` and leaves the session as it was.

What the handshake selected is a `tls_provider.Negotiated`, null until the handshake completes
([decision 140](decisions.md#decision-140)):

```zig
const provider = tls_client.provider();
if (provider.negotiated_parameters()) |chosen| {
    std.debug.print("consumer: group 0x{x:0>4}\n", .{chosen.group});
    return error.NegotiatedWrong;
}
```

- Each field is a codepoint: the version, the cipher suite and the group, such as 0x11EC for
  X25519MLKEM768.
- A `tls.quic.Client` answers `negotiated()` in place of `negotiated_parameters`.

### PEM files

From [`examples/server_exchange.zig`](../examples/server_exchange.zig), a server reads its
chain and key:

```zig
const chain = try tls.pem.chain(identity.chain_pem, &chain_der, &chain_room);
try tls.pem.key(crypto, identity.key_pem, chain[0], &key);
identities[0] = .{ .chain = chain, .key = &key };
```

From [`examples/client_exchange.zig`](../examples/client_exchange.zig), a client reads its CA
bundle:

```zig
const anchors = try tls.pem.anchors(identity.bundle_pem, &anchor_der, &anchor_room);
```

| Call | Returns | At most |
| --- | --- | --- |
| `tls.pem.chain(file, der, room)` | `tls.Identity.chain`, the end-entity first | `tls.constants.limits.certificate_chain_len_max` |
| `tls.pem.key(crypto, file, leaf, &key)` | fills a `tls.Key` and sets `key.scheme` | one key block |
| `tls.pem.anchors(file, der, room)` | `Trust.web_pki.anchors` | `tls.constants.limits.anchors_max` |

| Key block | `key.scheme` |
| --- | --- |
| P-256 under `PRIVATE KEY` (PKCS #8) or `EC PRIVATE KEY` (SEC 1) | `ecdsa_secp256r1_sha256` |
| RSA of two primes and exponent 65537 under `PRIVATE KEY` | `rsa_pss_rsae_sha256` |
| ML-DSA-87 under `PRIVATE KEY` (RFC 9881 §6) | `mldsa87` |

- Each call reads from memory the program filled, and does no I/O
  ([decision 141](decisions.md#decision-141)).
- Keep the DER room and the slice room in place while a session uses them.
- A DER room of three quarters of the file's length holds its DER.
- Each call skips text lines around its blocks (RFC 7468 §2 and §5.2).
- A call returns `error.Invalid` for a block of another label, an encrypted key, or more than the
  rooms hold.
- `pem.key` returns `error.Invalid` for a key that is neither P-256, RSA nor ML-DSA-87, or that the
  leaf does not carry.
- Decoding authenticates nothing: the operator placed the files.
- Call `key.wipe()` once no session uses the key, and wipe your copy of the file.

### Server identities

- `tls.Server.identities` holds at most one identity per scheme
  ([decision 147](decisions.md#decision-147)).
- The server signs with ML-DSA-87 when the client offers it, then ECDSA P-256, then RSA-PSS.
- A `tls.Key` holds 7,488 bytes of key room, the size of an ML-DSA-87 key pair.
- `init` returns `error.IdentityRepeated` for two identities of one scheme.
- `init` returns `error.IdentityUnfilled` for a key with no scheme.
- `init` returns `error.IdentityUnavailable` for ML-DSA-87 on a target other than arm64 or x86-64.

### QUIC and the assertion hook

- A `tls.quic.Client` or `tls.quic.Server` hands `provider()` and `suite()` to the
  `quic.Connection`.
- A server that sends Retry packets mints and checks their tokens with a `tls.quic.Retry`.

The crypto module defines `ch_assert_fail`, which panics by default
([decision 172](decisions.md#decision-172)). A program that reports the failure its own way
declares `chapulinAssertFail` in its root file:

```zig
/// chapulin's module calls this when one of its assertions fails, in place of its own report
/// (decision 172). A program that declares no such function gets chapulin's panic.
pub fn chapulinAssertFail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) noreturn {
    std.debug.panic("this program stops: chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}
```

## DNSSEC

From [`examples/dnssec_check.zig`](../examples/dnssec_check.zig), a resolver asks whether colibri
checks what a record names:

```zig
const algorithm = dnssec.algorithm(13) orelse return error.AlgorithmUnchecked;
const digest_type = dnssec.digest_type(2) orelse return error.DigestUnchecked;
```

It then streams an RRSIG's signed data into a hash and checks the signature:

```zig
fn check(algorithm: dnssec.Algorithm, key: []const u8, signature: []const u8, data: []const u8) dnssec.Error!void {
    var hash = try dnssec.Hash.init(algorithm, key, signature);
    hash.update(data);
    var digest: [dnssec.constants.protocol.digest_len_max]u8 = undefined;
    try dnssec.verify(algorithm, key, hash.final(&digest), signature);
}
```

`dnssec` checks algorithms 8, 10, 13, 14 and 15, and digest types 1, 2 and 4, through
`stdx.crypto` ([decision 142](decisions.md#decision-142)).

- Both lookups return null for any other number, and for every number off arm64 and x86-64.
- Build the signed data yourself (RFC 4034 §3.1.8.1); colibri copies, allocates and reads none.
- Pass `key` as the DNSKEY's Public Key field, in RFC 3110's form for RSA.
- `Hash.init` takes the signature, because Ed25519 hashes it first (RFC 8080).
- `verify` returns `error.SignatureVerificationFailed` for a signature the key does not verify.
- `verify` returns `error.InvalidEncoding` for a key, digest or signature of the wrong form.
- colibri sets no floor on an RSA key's length; the resolver sets it.
- `dnssec.Hash.digest(digest_type)` starts a plain digest for a DS record (RFC 4034 §5.1.4) or one
  NSEC3 round (RFC 5155 §5).

## QUIC and h3

No example drives `quic.Connection` or `h3.Connection` directly yet.
[`src/testing/quic/udp/udp_peer.zig`](../src/testing/quic/udp/udp_peer.zig) is a whole endpoint
over UDP, and [`src/testing/quic/h3/`](../src/testing/quic/h3/) holds an h3 server and client.

| `quic.Connection` call | What it does | Scratch |
| --- | --- | --- |
| `receive` | takes one datagram, with its ECN marking and source address | `quic.Connection.ReceiveScratch` |
| `send` | writes the next datagram colibri owes, or returns null | `SendScratch(options)` with its `SendScratchOptions` |
| `deadline` | names the next instant the connection needs to run | |
| `on_instant` | runs what that instant is for | |

- Pass a `StreamProvider` to `send`; it gives colibri each stream's bytes as the windows allow.
- `SendScratch(.{})` holds the smallest maximum datagram size of RFC 9000 §14.1.
- Pass `packet_number_skips`, one `u64` drawn from your random source at start
  ([decision 123](decisions.md#decision-123)).
- After each datagram, call `h3.Connection.receive` until it returns null.
- Use the h3 connection's `provider` around your stream provider; h3 serves its control and QPACK
  streams.
- `write_request`, `write_response`, `write_trailers` and `write_data_header` write h3 frames, and
  you send the content after them.
- Each h3 call that writes or reads a frame takes the instant.

To log a connection as qlog ([decision 102](decisions.md#decision-102)):

- Place a `qlog.Log` with `Log.init(buffer, cpu_features)`, and write its header with
  `Log.start`.
- Pass it as the `qlog` option of the QUIC connection and of the h3 connection.
- Write `log.bytes()` where you want, then call `log.clear()`.
- Use `quic.Connection.attach_log` for a connection that `init` already made.
- `tools/qlog_to_qvis.py` converts a log for qvis.

## Sizes

Every struct a program places has a size fixed at compile time. The table of
[Memory per connection](performance.md#memory-per-connection) gives each engine, pool,
connection and TLS session, and `zig build test` fails when it differs from the build.

- Your read and write buffers, and QUIC's scratch, come on top of those sizes.
- A client that decodes `zstd` or `br` places a `client.ZstdDecoderPool(count)` or
  `client.BrotliDecoderPool(count)` and calls its `init()` once
  ([decision 101](decisions.md#decision-101)).
- Each module's `constants.zig` names the limits that set the sizes.
