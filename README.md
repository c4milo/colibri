# colibri

[![CI](https://github.com/c4milo/colibri/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/c4milo/colibri/actions/workflows/ci.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg)](https://ziglang.org/download/)
[![release](https://img.shields.io/github/v/release/c4milo/colibri)](https://github.com/c4milo/colibri/releases/latest)
[![line coverage](https://img.shields.io/badge/line_coverage-98.7%25-brightgreen.svg)](https://github.com/c4milo/colibri/actions/runs/43727822114)

An HTTP/1.1, HTTP/2 and HTTP/3 library for Zig, client and server, with QUIC underneath HTTP/3.
It is written from the RFCs, and every check it makes on a peer's input cites the section that
requires it.

The protocol code does no I/O. It never opens a socket, allocates memory, or reads the clock.
Your program reads bytes from the network and passes them in. colibri writes its replies into
buffers you own, and your program sends them. You pass in the current time too. So a connection
depends only on what you give it, and the simulator can replay one from a seed, byte for byte.
If you would rather not run that loop yourself, `colibri.Server` and `colibri.Client` run it for
you on [Rotor](https://github.com/c4milo/rotor).

The name is Spanish for hummingbird.

## At a glance

| | |
| --- | --- |
| Protocols | h11 ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112), as [RFC 9931](https://www.rfc-editor.org/rfc/rfc9931) updates it), h2 ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) with HPACK ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)), h3 ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)) with QPACK ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)), and QUIC versions 1 and 2 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [9001](https://www.rfc-editor.org/rfc/rfc9001), [9002](https://www.rfc-editor.org/rfc/rfc9002), [9369](https://www.rfc-editor.org/rfc/rfc9369)) |
| Roles | Client and server, for every protocol |
| Memory | No allocator anywhere in `src/`, tests included. Your program owns every struct and buffer. Each size is a comptime constant, or a `memory_bytes` function of the counts your program sets. |
| I/O | None. colibri parses octets you already read and writes into buffers you own. A call that would block returns what it needs instead. |
| Time | A value you pass. No source file reads a clock. |
| TLS and packet protection | Vtables: `tls_provider.Provider` for h11 and h2, and `tls_provider.QuicProvider` and `crypto.Suite` for QUIC. The `tls` module fills all three from [chapulin](https://github.com/c4milo/chapulin), the library's TLS stack, and a program may fill them itself. |
| Status | Before 1.0: each minor release can change the API. [The releases page](https://github.com/c4milo/colibri/releases) holds each release's notes, its breaking changes first. |
| Language | Zig 0.16.0 |
| License | Apache-2.0 |

## Performance

Three charts, each from one named run of `bench.yml` on the v0.20.0 tag, on GitHub's
`ubuntu-24.04-arm` runner, an Arm Neoverse-N2. Each server runs on a core of its own. colibri's
numbers come from its test-only servers, which serve through the `server` module on Rotor's loop.
[`docs/performance.md`](docs/performance.md#the-charts-of-the-readme) names each other server's
version, reads each chart in full, and says how each number is measured and what limits it.

**CPU time a request.** Over h2, hyper takes 3.3 times colibri's time. Over h3, axum on quinn
takes 2.9 times, and quic-go 11.4 times. Over h11, nginx takes 1.18 times. Over h11 with TLS,
fasthttp and hyper tie with colibri inside the noise
([run 45630159962](https://github.com/c4milo/colibri/actions/runs/45630159962)).

![Bars of the CPU time a request of each server on one Neoverse-N2 core, by protocol: colibri takes 6.2 µs over h11, 7.9 µs over h11 with TLS, 1.5 µs over h2, 2.2 µs over h2 with TLS and 3.9 µs over h3; hyper takes 4.9 µs over h2; axum on quinn takes 11.3 µs over h3 and quic-go 44.0 µs](docs/images/cpu.svg)

**Throughput.** Over h2, colibri serves 1,062,860 requests a second on one core, 4.8 times
hyper's. Over h3 it serves 2.2 times axum's on quinn, and 9.7 times quic-go's. Over h11, colibri
serves 1.22 times nginx's, past nginx's spread of 16%
([run 45630164036](https://github.com/c4milo/colibri/actions/runs/45630164036)).

![Bars of the requests a second each server serves on one Neoverse-N2 core, by protocol: over h2 colibri serves 1,062,860, hyper 223,280 and h2o 187,710; over h3 colibri serves 290,989, axum on quinn 134,580 and quic-go 30,075; over h11 colibri serves 157,890 and nginx 129,212](docs/images/throughput.svg)

**Latency.** The p99 at fixed rates, over the GitHub API's routes. Over h2 at 80,000 requests a
second, colibri's is 9.05 ms and axum's 146.31 ms. Over h3 at 20,000, colibri's is 3.49 ms and
axum's 4.89 ms. Over h11 at 80,000, colibri's is 5.90 ms and axum's 6.57 ms
([run 45658737912](https://github.com/c4milo/colibri/actions/runs/45658737912)).

![Lines of each server's p99 latency against the rate offered, on log scales, one panel for each of h11, h2, h2 over TLS and h3, with the bound of 10 ms: colibri stays under it up to 80,000 requests a second over h11 and h2, 40,000 over h2 over TLS and 20,000 over h3; axum stays under it up to 80,000 over h11, 40,000 over h2 and h2 over TLS and 20,000 over h3](docs/images/latency.svg)

## Using colibri

Add colibri to your `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#v0.21.0
```

Import `colibri`, the one module the package exports ([decision 170](docs/decisions.md)):

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true, .rotor = true });
exe.root_module.addImport("colibri", colibri.module("colibri"));
```

`.release = true` builds ReleaseSafe. colibri offers Debug and ReleaseSafe only, because its
assertions stay on in production. `.rotor = true` fetches
[Rotor](https://github.com/c4milo/rotor), the loop that `colibri.Server` and `colibri.Client` run
on. A program that runs them on its own loop, or that drives one protocol by itself, leaves the
option out and fetches no Rotor ([decision 159](docs/decisions.md)).

Your program asks its CPU once, through [stdx](https://github.com/c4milo/stdx)'s `platform`
module. Depend on stdx at the commit colibri's `build.zig.zon` pins, with colibri's options:

```zig
const stdx = b.dependency("stdx", .{ .target = target, .release = true });
exe.root_module.addImport("stdx", stdx.module("stdx"));
```

The root of `colibri` names each library module: `colibri.server`, `colibri.client`,
`colibri.tls`, and each protocol, such as `colibri.h2` and `colibri.quic`:

```zig
const colibri = @import("colibri");
// `colibri` names each library module, so the program imports no other module of colibri
// (decision 170).
const server = colibri.server;
const client = colibri.client;
const tls = colibri.tls;
const platform = @import("stdx").platform;
```

colibri links [chapulin](https://github.com/c4milo/chapulin), its TLS stack, and a program
defines nothing for it. A failed chapulin assertion stops the program with a panic. A program that
reports the failure its own way declares this function in its root file:

```zig
/// chapulin's module calls this when one of its assertions fails, in place of its own report
/// (decision 172). A program that declares no such function gets chapulin's panic.
pub fn chapulinAssertFail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) noreturn {
    std.debug.panic("this program stops: chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}
```

### A server

`colibri.Server` binds one port and serves a router on it: h11 and h2 over TCP, and h3 over UDP
on the same port. Each connection runs its own TLS handshake, and ALPN picks the version. These
lines are from [`examples/colibri_server.zig`](examples/colibri_server.zig):

```zig
const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
// The CPU features the codecs run on, which the program also asks once and states in each
// configuration (decision 169).
const cpu_features: platform.CpuFeatures = .detect();
try http_server.init(&.{
    .host = "127.0.0.1",
    .port = 0,
    .identity = .{ .chain = identity.chain_pem, .key = identity.key_pem },
    .cpu = cpu,
    .unix_seconds = now_seconds,
    .engine = .{ .tls_buffer = &tls_buffer, .cpu_features = cpu_features },
}, &router, &app);
defer http_server.deinit();
const thread = try std.Thread.spawn(.{}, serve, .{});
defer thread.join();
defer http_server.shutdown();
```

`cpu` and `cpu_features` are what your program asked its CPU, and neither has a default: colibri
never asks the CPU itself. `tls_buffer` holds the TLS session of each TCP connection. `run` serves
on the thread that calls it until `shutdown`.

A server declares its routes in a table, and `server.Router` builds the table at compile time. A
path can hold parameters, such as `:name`, and a trailing wildcard. A table that hides a route,
or that is malformed, does not compile. These lines are from
[`examples/server_exchange.zig`](examples/server_exchange.zig):

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
```

A route's function takes the program's context, the request context, the request and the
response. The router fills the route's path and query structs by their field names, and the
function writes its response through a `std.Io.Writer`:

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

### A client

`colibri.Client` owns the sockets and runs `client`'s connection pool, behind one set of calls
for h11, h2 and h3. `fetch` runs one exchange on the thread that calls it, and returns how it
ended. This line is from [`examples/colibri_server.zig`](examples/colibri_server.zig):

```zig
const got = try http_client.fetch(&.{ .path = "/greeting", .response_body = &body });
```

The pool opens TCP first by default, and h3 over QUIC only once TCP fails. With
`.prefer = .quic` it tries h3 over QUIC first.

### The rest

[`docs/usage.md`](docs/usage.md) walks through every part, and [`examples/`](examples/) holds a
whole program for each, which `zig build examples` and CI run:

- **The router**: the request context, middleware, queries, request bodies, and the memory a
  router takes.
- **Stream routes**, which read a body as it arrives and can answer before it ends, as gRPC and
  Connect calls need ([`examples/server_stream.zig`](examples/server_stream.zig)).
- **Your own loop.** With the `.hosted` kind, `colibri.Server` and `colibri.Client` do no I/O:
  each `turn` writes the operations it needs, and your program gives back a completion for each
  ([`examples/colibri_hosted.zig`](examples/colibri_hosted.zig)).
- **The engine and the pool by themselves.** `server.Engine` and `client.ConnectionPool` own no
  socket: your program moves the octets and the datagrams
  ([`examples/server_exchange.zig`](examples/server_exchange.zig),
  [`examples/client_exchange.zig`](examples/client_exchange.zig)).
- **One protocol by itself.** `colibri.h11`, `colibri.h2`, `colibri.h3` and `colibri.quic` each
  take octets in, give at most one event out, and write the frames colibri owes into your buffer
  ([`examples/h11_exchange.zig`](examples/h11_exchange.zig)).

## Conformance

| Protocol | Built | Checked against |
| --- | --- | --- |
| h11 | Client and server, pipelining, `chunked`, and `gzip` and `deflate` bodies decoded | Go's `net/http`, h2o and curl, in cleartext and over TLS; the [HTTP Garden](https://github.com/narfindustries/http-garden) against 35 other servers |
| h2 | Client and server, HPACK with the dynamic table | [h2spec](https://github.com/summerwind/h2spec) 2.6.0: 144 of 146 in cleartext with h2 alone and over TLS, the other 2 test an RFC 7540 rule RFC 9113 dropped; curl, nghttp, Go, nghttpd and h2o |
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
  in [`spec/tla/`](spec/tla/) cover the connections, flow control, QPACK's tables, loss recovery,
  the congestion controllers and the deadlines. Each has configurations that remove one rule,
  which TLC must find violated, and TLC checks the traces of seven simulator runs against them.
- **Proofs.** [`spec/lean/`](spec/lean/) holds [Lean 4](https://lean-lang.org/) proofs of the
  integer and Huffman codecs and of the congestion controllers' arithmetic. The Zig tests read
  vectors that the proved definitions produce.
- **Golden corpus.** [`src/golden/`](src/golden/) holds exact bytes, each case with its expected
  verdict, the request smuggling shapes of RFC 9112 included.
- **Mutation testing.** Every check is broken on purpose, and a test must fail. Each result is
  recorded as `CAUGHT` or `NOT CAUGHT` in the commit or in [`docs/design.md`](docs/design.md).
- **Fuzzing and line coverage.** Every reader of a peer's octets has a fuzz property. kcov counts
  the lines of the library that the tests run, and the badge above shows a named CI run's count.
- **Lints.** `zig build lint` refuses a heap allocation, a system call, a clock or random read
  outside the test endpoints, an unbounded loop, a function above cognitive complexity 15, and a
  source file above 500 lines.

CI runs [`tools/ci.sh`](tools/ci.sh) on every push to main: the lints, every module's tests, the
examples, the simulator, the Lean proofs, line coverage, h2spec, h3spec and the interop scripts.
The TLA+ models run every night, and the HTTP Garden and the QUIC Interop Runner every Monday.

## Platforms

CI runs every check on Ubuntu 26.04 on x86-64, and the module tests on Ubuntu 26.04 and macOS 26
on arm64. Every module but `colibri` makes no system call, so it builds wherever Zig 0.16.0 does,
but only these platforms are checked. `colibri.Server` and `colibri.Client` run on Rotor, on
Linux and macOS. Published performance numbers come from Linux alone.

## Documentation

| Document | What it covers |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | Adding colibri, driving each protocol, TLS, and the buffers you own |
| [`examples/`](examples/) | Whole programs for the `server` and `client` modules, and for h11 and h2 by themselves, which CI runs |
| [`docs/design.md`](docs/design.md) | The module graph, the wire formats, and the numbered build plan with each step's record |
| [`docs/decisions.md`](docs/decisions.md) | Every design decision, with the alternatives it beat |
| [`docs/invariants.md`](docs/invariants.md) | The numbered invariants, each one a runtime assertion |
| [`docs/performance.md`](docs/performance.md) | How colibri measures a change, its baselines, and the memory each object takes |
| [`docs/chapulin.md`](docs/chapulin.md) | What colibri needs from chapulin, its TLS stack |
| [`docs/rfcs/`](docs/rfcs/) | The RFCs colibri is written from, unmodified, with their checksums |

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
