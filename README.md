# colibri

[![main](https://github.com/c4milo/colibri/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/c4milo/colibri/actions/workflows/main.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg)](https://ziglang.org/download/)
[![release](https://img.shields.io/github/v/release/c4milo/colibri)](https://github.com/c4milo/colibri/releases/latest)

An HTTP/1.1, HTTP/2 and HTTP/3 library for Zig, client and server, with QUIC underneath HTTP/3.
It is written from the RFCs, and every check it makes on a peer's input cites the section that
requires it.

colibri owns no socket, no allocator and no clock. Your program reads the octets, hands them to
colibri, and gets back events. colibri writes the octets it owes into buffers your program owns,
and your program sends them. Every function that needs the current time takes it as a parameter.
Because of this, one seed of the simulator replays a whole connection byte for byte.

The name is Spanish for hummingbird.

## At a glance

| | |
| --- | --- |
| Protocols | h11 ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)), h2 ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) with HPACK ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)), h3 ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)) with QPACK ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)), and QUIC versions 1 and 2 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [9001](https://www.rfc-editor.org/rfc/rfc9001), [9002](https://www.rfc-editor.org/rfc/rfc9002), [9369](https://www.rfc-editor.org/rfc/rfc9369)) |
| Roles | Client and server, for every protocol |
| Memory | No allocator anywhere in `src/`, tests included. Your program owns every struct and buffer, and each size is a comptime constant. |
| I/O | None. colibri parses octets you already read and writes into buffers you own. A call that would block returns what it needs instead. |
| Time | A value you pass. No source file reads a clock. |
| TLS and packet protection | Vtables: `tls_provider.Provider` for h11 and h2, and `tls_provider.QuicProvider` and `crypto.Suite` for QUIC. The `tls` module fills all three from [chapulin](https://github.com/c4milo/chapulin), the library's TLS stack, and a program may fill them itself. |
| Language | Zig 0.16.0 |
| License | Apache-2.0 |

## Status

colibri is before 1.0. Each minor release can change the API, and its release notes list each
breaking change first. The latest release is
[0.11.0](https://github.com/c4milo/colibri/releases/tag/v0.11.0).

| Release | Date | What it added |
| --- | --- | --- |
| [0.11.0](https://github.com/c4milo/colibri/releases/tag/v0.11.0) | 2026-11-01 | BBRv3 as QUIC's default congestion controller, PEM files, and the `dnssec` module |
| [0.10.0](https://github.com/c4milo/colibri/releases/tag/v0.10.0) | 2026-10-30 | CUBIC with HyStart++, up to 16 STREAM frames in a packet, and 100 open h3 requests |
| [0.9.0](https://github.com/c4milo/colibri/releases/tag/v0.9.0) | 2026-10-29 | Route functions with typed path and query values, middleware, one set of HTTP names, and TLS alerts the program names |
| [0.8.0](https://github.com/c4milo/colibri/releases/tag/v0.8.0) | 2026-10-21 | The server's router, `client.Request` and `client.Response`, deadlines over h3, and zstd and br |
| [0.7.0](https://github.com/c4milo/colibri/releases/tag/v0.7.0) | 2026-09-30 | QUIC version 2, the program's CPU probe, and the server's deadlines and rate limits |
| [0.6.0](https://github.com/c4milo/colibri/releases/tag/v0.6.0) | 2026-09-29 | AES-256-GCM first on CPUs with the AES instructions, and the client's own suite order |
| [0.5.0](https://github.com/c4milo/colibri/releases/tag/v0.5.0) | 2026-09-29 | The server over QUIC, Alt-Svc, and gzip and deflate content codings |
| [0.4.0](https://github.com/c4milo/colibri/releases/tag/v0.4.0) | 2026-09-28 | The `server` and `client` modules, and qlog |
| [0.3.0](https://github.com/c4milo/colibri/releases/tag/v0.3.0) | 2026-09-28 | Connection errors end the connection inside colibri, and h2 trailers |
| [0.2.0](https://github.com/c4milo/colibri/releases/tag/v0.2.0) | 2026-09-27 | A TLS session draws from the source its caller passes |
| [0.1.0](https://github.com/c4milo/colibri/releases/tag/v0.1.0) | 2026-09-27 | h11, h2 and h3, client and server, with TLS through chapulin |

[The releases page](https://github.com/c4milo/colibri/releases) has the notes of each release:
its breaking changes, what is new, its fixes, its speed, and the checks it passed.

### Conformance

| Protocol | Built | Checked against |
| --- | --- | --- |
| h11 | Client and server, pipelining, `chunked`, and `gzip` and `deflate` bodies decoded | Go's `net/http`, h2o and curl, in cleartext and over TLS; the [HTTP Garden](https://github.com/narfindustries/http-garden) against 35 other servers |
| h2 | Client and server, HPACK with the dynamic table | [h2spec](https://github.com/summerwind/h2spec) 2.6.0: 144 of 146 in cleartext with h2 alone and over TLS, the other 2 test an RFC 7540 rule RFC 9113 dropped; curl, nghttp, Go, nghttpd and h2o |
| h3 and QUIC | Client and server, QPACK with the dynamic table, Retry, resumption, key update, loss recovery and congestion control | The [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) against quic-go, ngtcp2, neqo and quinn; [h3spec](https://github.com/kazu-yamamoto/h3spec) 0.1.13: 49 examples, 0 failures; `h2load --h3`: 1,000 of 1,000 requests; aioquic in both directions; QPACK against ls-qpack |

[`docs/design.md`](docs/design.md) §8 records each check: what ran, on what machine, and what it
printed. Open work is in the [issues](https://github.com/c4milo/colibri/issues).

## Using colibri

Add colibri to your `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#v0.11.0
```

Then import the modules you use. Each of the sixteen library modules is exported by name: `core`,
`wire`, `http`, `tls_provider`, `tls`, `dnssec`, `crypto`, `qlog`, `hpack`, `qpack`, `quic`, `h2`,
`h3`, `h11`, `server` and `client`.

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true });
exe.root_module.addImport("server", colibri.module("server"));
exe.root_module.addImport("client", colibri.module("client"));
exe.root_module.addImport("tls", colibri.module("tls"));
```

`.release = true` builds ReleaseSafe. colibri offers Debug and ReleaseSafe only, because its
assertions stay on in production.

Most programs use two modules. `client` sends requests and `server` answers them, behind one
set of calls for h11, h2 and h3. Each connection runs its own TLS handshake, and ALPN picks the
version. For each exchange a client places a request, and a response that holds the memory the
answer goes into. These lines are from
[`examples/client_exchange.zig`](examples/client_exchange.zig):

```zig
const get: client.Request = .{ .method = "GET", .path = "/greeting" };
var get_response: client.Response align(@alignOf(client.Response)) = .{
    .wanted = &wanted,
    .values = &wanted_values,
    .body = &get_body,
};
```

It hands both to a pool. The pool asks for a QUIC or a TCP transport, and sends the
request over the first connection that completes its handshake:

```zig
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

The program moves datagrams and octets between its sockets and the pool's `send_datagram`,
`send_stream` and `receive`, and every exchange ends in one `finished` event, which names the
request and the response:

```zig
.finished => |ended| {
    // The event names the request and the response, whose memory is the program's again.
    std.debug.print("client: {s}: {s}, {d}\n", .{
        ended.request.path, @tagName(ended.response.result), ended.response.status,
    });
    finished += 1;
    // Every exchange has ended, so the client shuts the pool down.
    if (finished == requests_count) pool.shutdown();
},
```

A server holds its TCP and QUIC connections in one endpoint, and calls `accept` for each TCP socket
it accepts. It gets one event from each `receive`, in h11, h2 and h3 alike, and passes it to a
router that it declares at compile time with `server.router`. The router calls the function of each
request's route with the path's parameters and the query as structs, and the function writes its
response through a `std.Io.Writer`. These lines are from
[`examples/server_exchange.zig`](examples/server_exchange.zig):

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

[`docs/usage.md`](docs/usage.md) walks through both modules.

The protocol modules are there for a program that wants one version by itself. An h11 client
writes each request into a buffer it owns, then sends it. These lines are from
[`examples/h11_exchange.zig`](examples/h11_exchange.zig), where `link` stands in for the
program's socket:

```zig
const get_len = try client.write_request(&output, "GET", "/greeting", &.{
    .{ .name = "Host", .value = host },
});
try link.send(.client, output[0..get_len]);
```

It then hands colibri the octets that arrived, and gets at most one event per call:

```zig
const input = try link.receive(.client);
const step = try client.receive(input, &.{});
if (step.event) |event| switch (event) {
    .response => |response| {
        try read_status(response.line.status.code);
        if (ends_with_head(response.body)) ended += 1;
    },
    .data => |data| try read_body(data),
    .end => ended += 1,
    else => {},
};
link.consume(.client, step.consumed);
```

A call that consumes nothing and returns no event means colibri needs more octets. A response
with no body ends with its head, so no `.end` follows it. An event's slices point into the input,
so the example uses them before it lets the link drop the octets `step.consumed` counts. The
response's field lines are in `client.section` until the next call. h2 and h3 follow the same
shape: octets in, at most one event out, and the frames colibri owes written into your buffer.
[`docs/usage.md`](docs/usage.md) walks through each protocol, TLS, and the buffers each one needs.

[`examples/`](examples/) holds whole programs, each a client and a server run over
[Rotor](https://github.com/c4milo/rotor)'s loop: a server that serves TCP and QUIC through one
endpoint, a client whose pool tries QUIC and then TCP, and h11 and h2 by themselves. `zig
build examples` runs them, and CI does too.

## How it is checked

- **RFC citations.** A check that exists because an RFC requires it carries the RFC and the
  section on the line that makes it. A lint refuses a validation without one.
- **Deterministic simulation.** A seeded network delays, drops, reorders and duplicates
  datagrams, and marks them with ECN. Checks drive h11, h2, h3, QUIC, loss recovery and QPACK
  through it, and each seed replays byte for byte in Debug and in ReleaseSafe.
- **Models.** Nineteen [TLA+](https://lamport.azurewebsites.net/tla/tla.html) specifications in
  [`spec/tla/`](spec/tla/) cover the h2 and h3 connections, flow control, QPACK's tables, key
  installation, connection IDs, closing, probe timeouts, CUBIC, HyStart++, BBRv3, the server's
  deadlines and the client's exchanges. Each model also has configurations that remove one rule,
  and TLC must find those violated. Seven simulator runs write their traces as TLA+, and TLC
  checks that each trace is a behavior of its model.
- **Proofs.** [`spec/lean/`](spec/lean/) holds [Lean 4](https://lean-lang.org/) proofs of
  QUIC's variable-length integer, packet number and ACK ranges, HPACK's and QPACK's prefixed
  integer and Huffman code, QPACK's Required Insert Count encoding, and the arithmetic of CUBIC,
  HyStart++, BBRv3 and the server's rate meter. The Zig tests read vectors the proved definitions
  produce.
- **Golden corpus.** [`src/golden/`](src/golden/) holds exact bytes with a manifest that names
  each case's length, checksum and expected verdict, including the request smuggling shapes of
  RFC 9112.
- **Mutation testing.** Every check is broken on purpose, and a test must fail. Each result is
  recorded as `CAUGHT` or `NOT CAUGHT` in the commit or in [`docs/design.md`](docs/design.md).
- **Fuzzing.** Every reader of a peer's octets has a fuzz property, run over its corpus and every
  input of up to two octets. Input checks in the simulator edit what colibri's own writers
  produce, to reach longer inputs.
- **Lints.** `zig build lint` refuses a heap allocation, a system call, a clock or random read
  outside the test endpoints, an unbounded loop, a function above cognitive complexity 15, a
  source file above 500 lines, and a slice indexed by a value a peer chose.

CI runs [`tools/ci.sh`](tools/ci.sh) on every push to main: the lints, every module's tests in
both build modes, the examples, the simulator in both build modes, the TLA+ models and the
traces, the Lean proofs, h2spec and the interop scripts in cleartext and over TLS, h3spec, the TLS
handshakes against Go, and the QUIC checks against colibri and aioquic. Every push also runs the
module tests on arm64, on Linux and on macOS. The HTTP Garden and the QUIC Interop Runner,
against quic-go, ngtcp2, neqo and quinn, run every Monday.

## Platforms

CI runs every check on Ubuntu 24.04 on x86-64, the module tests on Ubuntu 24.04 and macOS 26 on
arm64, and the QUIC Interop Runner on Ubuntu 26.04 on x86-64, because it needs tshark 4.5.0 or
newer.
macOS on arm64 is also the development host, where every check runs, the TLS and QUIC ones
included. colibri makes no system call, so it builds wherever Zig 0.16.0 does, but only these
platforms are checked. Published performance numbers come from Linux alone.

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
