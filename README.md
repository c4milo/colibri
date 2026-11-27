# colibri

[![CI](https://github.com/c4milo/colibri/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/c4milo/colibri/actions/workflows/ci.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg)](https://ziglang.org/download/)
[![release](https://img.shields.io/github/v/release/c4milo/colibri)](https://github.com/c4milo/colibri/releases/latest)
[![line coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fc4milo%2Fcolibri%2Fbadges%2F.github%2Fbadges%2Fcoverage.json)](https://github.com/c4milo/colibri/actions/workflows/ci.yml?query=branch%3Amain)

An HTTP/1.1, HTTP/2 and HTTP/3 library for Zig, client and server, with QUIC underneath HTTP/3.
It is written from the RFCs, and every check it makes on a peer's input cites the section that
requires it.

The protocol code does no I/O:

- It never opens a socket, allocates memory, or reads the clock.
- Your program passes in the bytes it read and the current time, and sends what colibri writes
  into your buffers.
- So the simulator can replay a connection from a seed, byte for byte.

`colibri.Server` and `colibri.Client` run that loop for you on
[Rotor](https://github.com/c4milo/rotor).

The name is Spanish for hummingbird.

## At a glance

| | |
| --- | --- |
| Protocols | h11 ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112), as [RFC 9931](https://www.rfc-editor.org/rfc/rfc9931) updates it), h2 ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) with HPACK ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)), h3 ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)) with QPACK ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)), and QUIC versions 1 and 2 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [9001](https://www.rfc-editor.org/rfc/rfc9001), [9002](https://www.rfc-editor.org/rfc/rfc9002), [9369](https://www.rfc-editor.org/rfc/rfc9369)) |
| Roles | Client and server, for every protocol |
| Memory | No allocator anywhere in `src/`, tests included. Your program owns every struct and buffer. Each size is a comptime constant, or a `memory_bytes` function of the counts your program sets. |
| I/O | None. colibri parses bytes you already read and writes into buffers you own. A call that would block returns what it needs instead. |
| Time | A value you pass. No source file reads a clock. |
| TLS and packet protection | Vtables: `tls_provider.Provider` for h11 and h2, and `tls_provider.QuicProvider` and `crypto.Suite` for QUIC. The `tls` module fills all three from `stdx.crypto`, and a program may fill them itself. |
| Status | Before 1.0: each minor release can change the API. [The releases page](https://github.com/c4milo/colibri/releases) holds each release's notes, its breaking changes first. |
| Language | Zig 0.16.0 |
| License | Apache-2.0 |

## Using colibri

colibri needs Zig 0.16.0. Add colibri, and stdx at the commit colibri pins, to your
`build.zig.zon`:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#v0.22.0
zig fetch --save=stdx git+https://github.com/c4milo/stdx#v0.4.0
```

stdx is colibri's one library dependency. Its `stdx.crypto` holds the TLS stack, and its
`platform` detects your CPU's features. Each colibri release names its stdx commit in its
`build.zig.zon`. Then add both modules to your program in `build.zig`
([decision 170](docs/decisions/0170-the-package-exports-one-module-colibri.md)):

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true, .rotor = true });
exe.root_module.addImport("colibri", colibri.module("colibri"));
```

```zig
const stdx = b.dependency("stdx", .{ .target = target, .release = true, .crypto = true });
exe.root_module.addImport("stdx", stdx.module("stdx"));
```

- `.release = true` builds ReleaseSafe. colibri offers Debug and ReleaseSafe only, because its
  assertions stay on in production.
- `.rotor = true` fetches [Rotor](https://github.com/c4milo/rotor), the loop that
  `colibri.Server` and `colibri.Client` run on. A program that runs them on its own loop, or that
  drives one protocol by itself, leaves the option out
  ([decision 159](docs/decisions/0159-colibriclient-and-colibriserver-take-a-host.md)).
- stdx takes colibri's options, `.crypto = true` among them, so your program links one stdx.

The root of `colibri` names each library module:

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

### A server

`colibri.Server` binds one port and serves a router on it: h11 and h2 over TCP, and h3 over UDP
on the same port. ALPN picks the version. The code in this section and the next is from
[`examples/colibri_server.zig`](examples/colibri_server.zig).

Declare the routes, the router and the server once, outside any stack frame:

```zig
/// The server's table of routes, which the compiler builds and checks.
const routes = .{
    .error_handler = on_error,
    .Values = Values,
    .middleware = .{Numbered},
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .get, "/greetings/:name", greet_named, .{ .path = Name } },
    },
};

/// The router's pool: an entry for each request at once, with room for its response. No route
/// takes a request with a body, so the router keeps no copy of a header (`header_bytes`).
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

In `main`, detect the CPU once, make one `stdx.crypto.Context`, and start the server:

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

- `secure` wraps `io.randomSecure`, the system's entropy. Each TLS session draws from it.
- `identity` is the certificate chain and the key as PEM text, which your program reads from its
  files. `now_seconds` is the Unix time, which your program reads from its clock.
- `set_data_independent_timing` sets PSTATE.DIT on arm64, so the TLS code runs in constant time.
  Call it on each thread that runs TLS.
- Port 0 asks the system for a port, and `http_server.port()` returns it.

`run` serves on the thread that calls it, until another thread calls `shutdown`:

```zig
fn serve(cpu_features: platform.CpuFeatures) void {
    _ = platform.set_data_independent_timing(cpu_features, true);
    http_server.run() catch |failure| std.debug.panic("run failed: {t}", .{failure});
}
```

A route's function takes the program's context, the request context, the request and the
response. The router fills the path's struct by its field names. These lines are from
[`examples/server_exchange.zig`](examples/server_exchange.zig):

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

A table that hides a route, or that is malformed, does not compile.

### A client

`colibri.Client` owns the sockets and runs `client`'s connection pool, behind one set of calls
for h11, h2 and h3. `fetch` runs one exchange on the thread that calls it:

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
// `deinit` stops the loop that `fetch` made: the connection closes.
defer http_client.deinit();
```

```zig
const got = try http_client.fetch(&.{ .path = "/greeting", .response_body = &body });
if (got.result != .response or got.status != ok) return error.ResponseWrong;
if (!std.mem.eql(u8, greeting, body[0..got.body_len])) return error.ResponseWrong;
```

- `server_addresses` holds the server's addresses. colibri looks up no name.
- `anchors` holds the roots the client trusts for `origin`.
- A failed exchange is a `result`, not an error. Read `result` before `status`.
- The pool opens TCP first. With `.protocols = .{ .prefer = .quic }` it tries h3 first.

### Where to go next

| To | Read | Run |
| --- | --- | --- |
| Use the router: middleware, request values, queries and bodies | [Router](docs/usage.md#router) | [`server_exchange.zig`](examples/server_exchange.zig) |
| Read a request body as it arrives, as gRPC and Connect need | [Router](docs/usage.md#router) | [`server_stream.zig`](examples/server_stream.zig) |
| Stream a request body or a response body from a client | [Streamed bodies](docs/usage.md#streamed-bodies) | [`client_stream.zig`](examples/client_stream.zig) |
| Run colibri on your own loop (`.hosted`) | [Host colibri on your own loop](docs/usage.md#host-colibri-on-your-own-loop) | [`colibri_hosted.zig`](examples/colibri_hosted.zig) |
| Drive `server.Engine` or `client.ConnectionPool` yourself | [The server](docs/usage.md#the-server), [The client](docs/usage.md#the-client) | [`server_exchange.zig`](examples/server_exchange.zig), [`client_exchange.zig`](examples/client_exchange.zig) |
| Use one protocol by itself | [h11](docs/usage.md#h11), [h2](docs/usage.md#h2) | [`h11_exchange.zig`](examples/h11_exchange.zig), [`h2_exchange.zig`](examples/h2_exchange.zig) |
| Check a DNSSEC signature | [DNSSEC](docs/usage.md#dnssec) | [`dnssec_check.zig`](examples/dnssec_check.zig) |

`zig build examples` runs every example, and `zig build example-<name>` runs one.

## Conformance

| Protocol | Built | Checked against |
| --- | --- | --- |
| h11 | Client and server, pipelining, `chunked`, and `gzip` and `deflate` bodies decoded | Go's `net/http`, h2o, Caddy and curl, in cleartext and over TLS; the [HTTP Garden](https://github.com/narfindustries/http-garden) against its other origins |
| h2 | Client and server, HPACK with the dynamic table | [h2spec](https://github.com/summerwind/h2spec) 2.6.0: 144 of 146 in cleartext with h2 alone and over TLS, the other 2 test a rule RFC 9113 no longer has ([decision 41](docs/decisions/0041-h2specs-two-self-dependency-cases-are.md)); curl, nghttp, Go, nghttpd and h2o |
| h3 and QUIC | Client and server, QPACK with the dynamic table, Retry, resumption, key update, loss recovery and congestion control | The [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) against quic-go, ngtcp2, neqo and quinn; [h3spec](https://github.com/kazu-yamamoto/h3spec) 0.1.13: 49 examples, 0 failures; `h2load --h3`: 1,000 of 1,000 requests; aioquic in both directions; QPACK against ls-qpack |

[`docs/design.md`](docs/design.md) §8 records each check: what ran, on what machine, and what it
printed. Open work is in the [issues](https://github.com/c4milo/colibri/issues).

## How it is checked

- **RFC citations.** A check that an RFC requires cites the RFC and the section on the line that
  makes it, and a lint refuses a validation without one.
- **Deterministic simulation.** A seeded network delays, drops, reorders and duplicates
  datagrams. Checks drive every protocol through it, and each seed replays byte for byte in Debug
  and in ReleaseSafe.
- **Models.** Twenty-one [TLA+](https://lamport.azurewebsites.net/tla/tla.html) specifications
  in [`spec/tla/`](spec/tla) cover the connections, flow control, QPACK's tables, loss recovery,
  the congestion controllers and the deadlines. Each has configurations that remove one rule,
  which TLC must find violated, and TLC checks the traces of seven simulator runs against them.
- **Proofs.** [`spec/lean/`](spec/lean) holds [Lean 4](https://lean-lang.org/) proofs of the
  integer and Huffman codecs and of the congestion controllers' arithmetic. The Zig tests read
  vectors that the proved definitions produce.
- **Golden corpus.** [`src/golden/`](src/golden) holds exact bytes, each case with its expected
  verdict, the request smuggling shapes of RFC 9112 included.
- **Mutation testing.** Every check is broken on purpose, and a test must fail. Each result is
  recorded as `CAUGHT` or `NOT CAUGHT` in the commit or in [`docs/design.md`](docs/design.md).
- **Fuzzing and line coverage.** Every reader of a peer's bytes has a fuzz property. kcov counts
  the lines of the library that the tests run. The badge above shows the count of the latest run
  of CI on main.
- **Lints.** `zig build lint` refuses a heap allocation, a system call, a clock or random read
  outside the test endpoints, an unbounded loop, a function above cognitive complexity 15, and a
  source file above 500 lines.

CI runs [`tools/ci.sh`](tools/ci.sh) on every push to main and every pull request to main: the lints, every module's tests, the
examples, the simulator, the Lean proofs, line coverage, h2spec, h3spec and the interop scripts.
The TLA+ models run every night, and the HTTP Garden and the QUIC Interop Runner every Monday.

## Performance

The README shows three charts. Each comes from one named run of `bench.yml` on the v0.22.0 tag,
on GitHub's `ubuntu-24.04-arm` runner, an Arm Neoverse-N2. Each server runs on a core of its own.
colibri's numbers come from its test-only servers, which serve through the `server` module on
Rotor's loop.

- Each bar chart draws a dashed line at colibri's value at v0.21.0.
- ▲ or ▼ marks a value of colibri that moved 5% or more since v0.21.0. In the latency chart, the
  value is the highest rate at which colibri's p99 stays under 10 ms.

[`docs/performance.md`](docs/performance.md#the-charts-of-the-readme) names each other server's
version, reads each chart in full, and says how each number is measured and what limits it.

**CPU time a request**
([run 45898056242](https://github.com/c4milo/colibri/actions/runs/45898056242)), against
colibri's:

| Protocol | Other servers |
| --- | --- |
| h2 | hyper 3.2 times |
| h3 | axum on quinn 2.9 times, quic-go 11.4 times |
| h11 | nginx 1.22 times |
| h11 with TLS | fasthttp and hyper tie inside the noise |

![Bars of the CPU time a request of each server on one Neoverse-N2 core, by protocol: colibri takes 6.8 µs over h11, 8.4 µs over h11 with TLS, 1.5 µs over h2, 2.2 µs over h2 with TLS and 3.9 µs over h3; hyper takes 4.9 µs over h2; axum on quinn takes 11.3 µs over h3 and quic-go 44.2 µs](docs/images/cpu.svg)

**Throughput** on one core
([run 45898059688](https://github.com/c4milo/colibri/actions/runs/45898059688)):

| Protocol | colibri, requests a second | Against |
| --- | --- | --- |
| h2 | 1,046,070 | 4.8 times hyper |
| h3 | 277,952 | 2.2 times axum on quinn, 9.6 times quic-go |
| h11 | 148,680 | 1.20 times nginx, past nginx's spread of 10.1% |

![Bars of the requests a second each server serves on one Neoverse-N2 core, by protocol: over h2 colibri serves 1,046,070, hyper 217,040 and h2o 183,070; over h3 colibri serves 277,952, axum on quinn 129,040 and quic-go 29,046; over h11 colibri serves 148,680 and nginx 123,423](docs/images/throughput.svg)

**Latency**: the p99 at fixed rates, over the GitHub API's routes
([run 45898063826](https://github.com/c4milo/colibri/actions/runs/45898063826)):

| Protocol | Rate, requests a second | colibri | axum |
| --- | --- | --- | --- |
| h2 | 80,000 | 7.99 ms | 12.81 ms |
| h3 | 20,000 | 3.07 ms | 4.36 ms |
| h11 | 80,000 | 6.67 ms | 5.51 ms |

![Lines of each server's p99 latency against the rate offered, on log scales, one panel for each of h11, h2, h2 over TLS and h3, with the bound of 10 ms: colibri stays under it up to 80,000 requests a second over h11 and h2, 40,000 over h2 over TLS and 20,000 over h3; axum stays under it up to 80,000 over h11, 40,000 over h2 and h2 over TLS and 20,000 over h3](docs/images/latency.svg)

## Platforms

- CI runs every check on Ubuntu 26.04 on x86-64, and the module tests on Ubuntu 26.04 and
  macOS 26 on arm64.
- Every module but `colibri` makes no system call, so it builds wherever Zig 0.16.0 does. Only
  the platforms above are checked.
- `colibri.Server` and `colibri.Client` run on Rotor, on Linux and macOS.
- Published performance numbers come from Linux alone.

## Documentation

| Document | What it covers |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | Adding colibri, driving each protocol, TLS, and the buffers you own |
| [`examples/`](examples) | Whole programs for `colibri.Server` and `colibri.Client` in both kinds, the `server` and `client` modules, h11 and h2 by themselves, and DNSSEC, which CI runs |
| [`docs/design.md`](docs/design.md) | The module graph, the wire formats, and the numbered build plan with each step's record |
| [`docs/decisions.md`](docs/decisions.md) | Every design decision, with the alternatives it beat |
| [`docs/invariants.md`](docs/invariants.md) | The numbered invariants, each one a runtime assertion |
| [`docs/performance.md`](docs/performance.md) | How colibri measures a change, its baselines, and the memory each object takes |
| [`docs/chapulin.md`](docs/chapulin.md) | The 2026-09 request to chapulin, the TLS stack under `stdx.crypto`, kept as history |
| [`docs/rfcs/`](docs/rfcs) | The RFCs colibri is written from, unmodified, with their checksums |

## Limits

colibri does not build these. The section "What colibri does not build" of
[`docs/decisions.md`](docs/decisions.md) gives the reason for each, and what the refusal still costs
on the wire:
- server push, in h2 and h3;
- priority scheduling, though it parses the priority fields the RFCs still require;
- extended CONNECT;
- 0-RTT;
- connection migration;
- HTTP datagrams and multipath QUIC.

## Contributing and security

[`CONTRIBUTING.md`](CONTRIBUTING.md) states the rules a change must follow and the checks it must
pass. Report a vulnerability as [`SECURITY.md`](SECURITY.md) describes, not in the public tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
