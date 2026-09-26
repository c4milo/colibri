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
| TLS and packet protection | Vtables you fill: `tls.Provider` for h11 and h2, and `tls.QuicProvider` and `crypto.Suite` for QUIC. [chapulin](https://github.com/c4milo/chapulin) becomes the library's own TLS stack in design §8 step 16, which is in progress. |
| Language | Zig 0.16.0 |
| License | Apache-2.0 |

## Status

colibri has no release yet. The first one comes after design §8 step 16, so that it carries TLS.
Until then, depend on a commit.

| Protocol | Built | Checked against |
| --- | --- | --- |
| h11 | Client and server, pipelining, `chunked` | Go's `net/http`, h2o and curl, in cleartext and over TLS; the [HTTP Garden](https://github.com/narfindustries/http-garden) against 34 other servers |
| h2 | Client and server, HPACK with the dynamic table | [h2spec](https://github.com/summerwind/h2spec) 2.6.0: 144 of 146 in cleartext and over TLS, the other 2 test an RFC 7540 rule RFC 9113 dropped; curl, nghttp, Go, nghttpd and h2o |
| h3 and QUIC | Client and server, QPACK with the dynamic table, Retry, resumption, key update, loss recovery and congestion control | The [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) against quic-go, ngtcp2, neqo and quinn; [h3spec](https://github.com/kazu-yamamoto/h3spec) 0.1.13: 49 examples, 0 failures; `h2load --h3`: 1,000 of 1,000 requests; aioquic in both directions; QPACK against ls-qpack |

Still to come:
- the `gzip` and `deflate` transfer codings for h11 (design §8 step 15c);
- chapulin linked into the library (step 16);
- published benchmarks from Linux (step 13).

[`docs/design.md`](docs/design.md) §8 records each check: what ran, on what machine, and what it
printed.

## Using colibri

Add colibri to your `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/c4milo/colibri#<commit>
```

Then import the modules you use. Each of the eleven library modules is exported by name: `core`,
`wire`, `http`, `tls`, `crypto`, `hpack`, `qpack`, `quic`, `h2`, `h3` and `h11`.

```zig
const colibri = b.dependency("colibri", .{ .target = target, .release = true });
exe.root_module.addImport("h11", colibri.module("h11"));
exe.root_module.addImport("http", colibri.module("http"));
```

`.release = true` builds ReleaseSafe. colibri offers Debug and ReleaseSafe only, because its
assertions stay on in production.

An h11 client sends a request and reads the response like this. The socket calls are your own:

```zig
const h11 = @import("h11");

var connection: h11.connection.Connection = undefined;
var output: [4096]u8 = undefined;
var input: [16384]u8 = undefined;

connection.init(.client, .{});
const head_len = try connection.write_request(&output, "GET", "/", &.{
    .{ .name = "Host", .value = "example.com" },
});
try send_all(socket, output[0..head_len]);

const input_len = try receive_some(socket, &input);
var offset: usize = 0;
while (true) {
    const received = try connection.receive(input[offset..input_len]);
    offset += received.consumed;
    // No event means colibri needs more octets.
    const event = received.event orelse break;
    switch (event) {
        .response => |response| handle_status(response.line.status.code),
        .data => |data| handle_body(data),
        .end => break,
        else => {},
    }
}
```

The response's field lines are in `connection.section` until the next call, and
`connection.section.find("etag")` looks one up. h2 and h3 follow the same shape: bytes in,
at most one event out, and the frames colibri owes written into your buffer.
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
  QPACK's Required Insert Count encoding. The Zig tests read vectors the proved definitions
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

CI runs [`tools/ci.sh`](tools/ci.sh) on every push to main: the lints, every module's tests, the
simulator in both build modes, the TLA+ models and the h3 traces, h2spec, and the interop
scripts in cleartext. The HTTP Garden runs every Monday. The checks over TLS and QUIC need a
chapulin checkout, and the proofs need a Lean toolchain; a person runs those on the same script
before a step is called done.

## Platforms

CI runs on Linux x86-64 (Ubuntu 24.04). macOS on arm64 is the development host, where every
check also runs, the TLS and QUIC ones included. colibri makes no system call, so it builds
wherever Zig 0.16.0 does, but only these two platforms are checked. Published performance numbers
come from Linux alone.

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
