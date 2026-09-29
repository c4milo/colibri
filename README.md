# colibri

[![main](https://github.com/c4milo/colibri/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/c4milo/colibri/actions/workflows/main.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg)](https://ziglang.org/download/)

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
| Protocols | h11 ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)), h2 ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) with HPACK ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)), h3 ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)) with QPACK ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)), and QUIC version 1 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [9001](https://www.rfc-editor.org/rfc/rfc9001), [9002](https://www.rfc-editor.org/rfc/rfc9002)) |
| Roles | Client and server, for every protocol |
| Memory | No allocator anywhere in `src/`, tests included. Your program owns every struct and buffer, and each size is a comptime constant. |
| I/O | None. colibri parses octets you already read and writes into buffers you own. A call that would block returns what it needs instead. |
| Time | A value you pass. No source file reads a clock. |
| TLS and packet protection | Vtables: `tls_provider.Provider` for h11 and h2, and `tls_provider.QuicProvider` and `crypto.Suite` for QUIC. The `tls` module fills all three from [chapulin](https://github.com/c4milo/chapulin), the library's TLS stack, and a program may fill them itself. |
| Language | Zig 0.16.0 |
| License | Apache-2.0 |

## Status

colibri 0.5.0 is the latest release. 0.1.0 was the first, and carried the TLS that design §8 step
16 put in the library. 0.2.0 has each TLS session draw from a source its caller passes. 0.3.0 ends
a connection inside colibri on a TLS or QUIC error, and adds h2's trailers. 0.4.0 adds the `server`
and `client` modules, whose `Channel` chooses h3 over QUIC or TCP for each server, and qlog. 0.5.0
adds the server over QUIC and Alt-Svc advertising, and content codings: the server codes a response
in gzip or deflate, and the client decodes one. The client also retires a QUIC connection near its
idle timeout.

| Protocol | Built | Checked against |
| --- | --- | --- |
| h11 | Client and server, pipelining, `chunked`, and `gzip` and `deflate` bodies decoded | Go's `net/http`, h2o and curl, in cleartext and over TLS; the [HTTP Garden](https://github.com/narfindustries/http-garden) against 35 other servers |
| h2 | Client and server, HPACK with the dynamic table | [h2spec](https://github.com/summerwind/h2spec) 2.6.0: 144 of 146 in cleartext and over TLS, the other 2 test an RFC 7540 rule RFC 9113 dropped; curl, nghttp, Go, nghttpd and h2o |
| h3 and QUIC | Client and server, QPACK with the dynamic table, Retry, resumption, key update, loss recovery and congestion control | The [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) against quic-go, ngtcp2, neqo and quinn; [h3spec](https://github.com/kazu-yamamoto/h3spec) 0.1.13: 49 examples, 0 failures; `h2load --h3`: 1,000 of 1,000 requests; aioquic in both directions; QPACK against ls-qpack |

Still to come:
- published benchmarks from Linux (step 13).

[`docs/design.md`](docs/design.md) §8 records each check: what ran, on what machine, and what it
printed.

## Using colibri

Add colibri to your `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#v0.5.0
```

Then import the modules you use. Each of the fifteen library modules is exported by name: `core`,
`wire`, `http`, `tls_provider`, `tls`, `crypto`, `qlog`, `hpack`, `qpack`, `quic`, `h2`, `h3`,
`h11`, `server` and `client`.

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true });
exe.root_module.addImport("h11", colibri.module("h11"));
exe.root_module.addImport("http", colibri.module("http"));
```

`.release = true` builds ReleaseSafe. colibri offers Debug and ReleaseSafe only, because its
assertions stay on in production.

An h11 client writes each request into a buffer it owns, then sends it. These lines are from
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

[`examples/`](examples/) holds whole programs: an h11 and an h2 client and server, run over
[Rotor](https://github.com/c4milo/rotor)'s loop. `zig build examples` runs them, and CI does too.

## How it is checked

- **RFC citations.** A check that exists because an RFC requires it carries the RFC and the
  section on the line that makes it. A lint refuses a validation without one.
- **Deterministic simulation.** A seeded network delays, drops, reorders and duplicates
  datagrams, and marks them with ECN. Checks drive h11, h2, h3, QUIC, loss recovery and QPACK
  through it, and each seed replays byte for byte in Debug and in ReleaseSafe.
- **Models.** Ten [TLA+](https://lamport.azurewebsites.net/tla/tla.html) specifications in
  [`spec/tla/`](spec/tla/) cover flow control, QPACK's tables, key installation, connection IDs,
  closing, probe timeouts and more. Each model also has configurations that remove one rule, and
  TLC must find those violated. The h3 simulator writes its runs as traces that TLC checks
  against the h3 model.
- **Proofs.** [`spec/lean/`](spec/lean/) holds [Lean 4](https://lean-lang.org/) proofs of
  QUIC's variable-length integer, packet number and ACK ranges, HPACK's and QPACK's prefixed
  integer and Huffman code, and QPACK's Required Insert Count encoding. The Zig tests read vectors the proved definitions
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
both build modes, the examples, the simulator in both build modes, the TLA+ models and the h3
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
| [`examples/`](examples/) | Whole programs for h11 and h2, which CI runs |
| [`docs/design.md`](docs/design.md) | The module graph, the wire formats, and the numbered build plan with each step's record |
| [`docs/decisions.md`](docs/decisions.md) | Every design decision, with the alternatives it beat |
| [`docs/invariants.md`](docs/invariants.md) | The numbered invariants, each one a runtime assertion |
| [`docs/chapulin.md`](docs/chapulin.md) | What colibri needs from chapulin, its TLS stack |
| [`docs/rfcs/`](docs/rfcs/) | The RFCs colibri is written from, unmodified, with their checksums |

## Limits

colibri does not build these, and [`docs/decisions.md`](docs/decisions.md) says why for each:
- server push, in h2 and h3;
- priority scheduling, though it parses the priority fields the RFCs still require;
- extended CONNECT;
- 0-RTT;
- connection migration;
- HTTP datagrams and multipath QUIC;
- QUIC version 2, which is open as
  [#54](https://github.com/c4milo/colibri/issues/54).

## Contributing and security

[`CONTRIBUTING.md`](CONTRIBUTING.md) states the rules a change must follow and the checks it must
pass. Report a vulnerability as [`SECURITY.md`](SECURITY.md) describes, not in the public tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
