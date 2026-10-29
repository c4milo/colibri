# Performance work in colibri

The method every performance change follows is pepegrillo's `docs/performance/`, starting at
`performance.md`. `zig build guide` installs it, at the commit `build.zig.zon` pins, to
`zig-out/docs/performance/`; read it first. This appendix is what that method leaves to the project:
colibri's instruments, its admission rule, its baselines and the pitfalls it has paid for. CLAUDE.md's
Performance section states the rules, and design §11 holds the method's numbers for this tree.

## The instruments

- The judge is `bench/run.sh` on the `ubuntu-24.04-arm` runner, a Neoverse N2, which
  `.github/workflows/bench.yml` runs when a person starts it (decision 33 as amended on
  2026-09-30, design §8 step 13a). macOS publishes no number (decision 32). The script builds the
  test-only h2 server in ReleaseSafe, pins it to one core and h2load to two others, and counts the
  server's instructions, cycles, CPU time and system calls with `perf stat`, run as root. It has
  five inputs, four more with `--h11`, and two more with `--h3`:
  - `h2-many` and `h2-tls-many`: many requests on each of a few connections, counted per request,
    in cleartext and over TLS.
  - `h2-one` and `h2-tls-one`: one request on each connection, counted per connection.
  - `h2-routes-many`: h2-many against the server with `--routes github`, whose router answers
    the GitHub API's 131 GET routes, which h2load sends in turn. It is the one input that counts
    `server.router`'s cost, which the owner asked for on 2026-10-28 (design §8 step 13h).
  - `h11-many`, `h11-tls-many`, `h11-one` and `h11-tls-one`: the same four loads over h11, which
    wrk sends, as the baselines below describe (design §8 step 13g).
  - `h3-many` and `h3-one`: the same two loads over h3, against the test-only UDP server in its
    `h3` mode (design §8 step 13d). Each request asks for a file of the same eight octets, which
    the server reads from its directory: the h3 servers design §11.3 names answer from files
    alone, so colibri's does the same work. The h2load that sends them is the one
    `tools/h3load/Dockerfile` builds with HTTP/3, run from its image on the load generator's
    cores.
- Each input runs one warm-up round, which the report discards, and then five rounds. With
  `--base`, the base and the change take turns in each round, and the order alternates. The report
  gives each input's median and spread, and the ratio of the change to the base with the losses
  first. The run fails when an input loses past the noise: the larger of the two spreads and the
  floor.
- The report has one block for each protocol of the run, in the order h11, h2 and h3. The heading
  of a block names its protocol and the client that sends its load: wrk, h2load, or h2load with
  HTTP/3. Each table of a block has rows for the inputs of that protocol alone. A protocol with no
  input in the run has no block.
- For each input counted per connection, the report also gives the connections one core of the
  server completes a second: the reciprocal of the median CPU time per connection. That is design
  §11.2's handshakes per second for a server whose CPU is the limit. It is a time, so it is
  compared within one job and never across jobs.
- The programs the judge and `tools/h3load.sh` time, `http-server` and `quic-udp`, export their own
  `memset` on Linux under Zig 0.16 (`src/testing/memset.zig`), as pepegrillo's guide tells a
  program to: compiler_rt's writes one octet at a time, for Zig's fills and chapulin's C code
  alike. The report names the `memset` each build links.
- The report writes the machine beside the numbers, as decision 33 requires: the CPU, the kernel,
  the core count, the path, the socket buffer sizes, the certificate type, and the cipher suite
  each build ran.
- The workflow runs two jobs, each on a runner of its own, and a change stays only when it wins
  past the noise in both. A number from one job is never compared with a number from another.
- The floor is 0.5% for a judge run's instructions per unit, which the owner set on 2026-09-30,
  and decision 33's 5% for a filter run's CPU time, which moves by more on a laptop. In five jobs
  of a tree against itself on the runner, no ratio of instructions per unit moved from 1 by more
  than 0.13%. Every spread stayed at or under 0.20%, except h2-one's once the programs had their
  own `memset`, which reached 0.80%: a cleartext connection then costs about 305,000 instructions,
  and how the server's loop groups connections from tick to tick moves some of them. That input's
  own spread then sets its noise. The runs are
  [36686649022](https://github.com/c4milo/colibri/actions/runs/36686649022) (its one job that
  passed), [36717711394](https://github.com/c4milo/colibri/actions/runs/36717711394), and, with
  the `memset` override, [36727047216](https://github.com/c4milo/colibri/actions/runs/36727047216).
- A profile shows where the time goes, and is never a measurement. `bench/run.sh --profile`, and
  `bench.yml`'s `profile` input, sample the server at 1,999 Hz with `perf record`, through ten loads of each input after the
  warm-up. They walk each stack by its frame pointers (design §8 step 13h). The report names the functions with the most samples, and the artifact holds the
  folded stacks for a flame graph. A change takes its price from the counts above, never from a
  profile.
- A laptop run is a filter: it orders candidates and never lands in a document.
  `bench/run.sh --filter` needs neither perf nor taskset, and reads the server's CPU time from
  each thread's `/proc` schedstat.
- `tools/h3load.sh [requests] [port]` runs `h2load --h3` from an image built from pinned tags; the
  QUIC Interop Runner (`tools/interop.sh`) and Go's h2 server over TLS are peers for conformance,
  and a load's peer where a number says so.
- The units of work are a frame, a request and a connection; a claim is priced against the four
  orders of magnitude CLAUDE.md names: a cache reference, a main-memory read, a syscall and a
  network round trip. No cost of the four is measured on the judge yet; the first change that
  needs a price measures it and records the run here.

## The admission rule

The shared rule until design §11 states one in numbers: a change stays when it wins past the noise
in `bench/run.sh`'s numbers and no input loses past the noise; the losses come first in the report,
with the request's or frame's size beside every speed.

The owner amended the rule for the h11 inputs on 2026-10-21. wrk's load moves the kernel's
instructions so much that a change of about 1% in colibri's own code hides in the total. So on
those inputs a change wins when its user instructions win past their noise in both jobs. No
input's total instructions may lose past the noise in either job. The report compares both counts
on the h11 inputs, and a loss by either count fails the run.

Three runs show the case:
[39549115441](https://github.com/c4milo/colibri/actions/runs/39549115441),
[39549122678](https://github.com/c4milo/colibri/actions/runs/39549122678) and
[39549129900](https://github.com/c4milo/colibri/actions/runs/39549129900). Each change saved 747
to 957 user instructions a connection on h11-one, with spreads of 0.31% or less. The totals'
spreads on that input were 1.75% to 9.04%, so each total stayed within the noise.

The owner admitted one change that loses by the rule, on 2026-10-26: `TCP_NODELAY` on each socket
the test-only server accepts. The rule counts instructions, and this change trades instructions
for latency, which `bench/run.sh --latency` measures (design §8 step 13f).

- **The cost.** One `setsockopt` for each connection: h2-one lost 1.38% and 1.49% of its
  instructions per connection, past the noise, in the two jobs of
  [40374474584](https://github.com/c4milo/colibri/actions/runs/40374474584). Every other input
  stayed within the noise, and the system calls per connection rose by one.
- **The gain.** Over h2 at 2,000 req/s, colibri's p50 went from 3.40 ms to 0.06 ms and its p99 from
  11.1 ms to 0.10 ms, in [40370739729](https://github.com/c4milo/colibri/actions/runs/40370739729)
  without it and [40374461009](https://github.com/c4milo/colibri/actions/runs/40374461009) with
  it. A small write had waited for the peer to acknowledge the one before it (Nagle's algorithm).

The owner admitted a second batch on 2026-10-28, for the goal of no copy on a request's path,
which the owner set on 2026-10-27 (design §8 step 13h). Its changes:

- the varint encoder writes its octets in place;
- h2 encodes a response's block in its frame;
- the test-only server swaps its receive buffers.

- **The rule's verdict.** In [40749185281](https://github.com/c4milo/colibri/actions/runs/40749185281),
  h2-many lost 0.47% of its instructions per request in both jobs, inside the floor of 0.5%. No
  input lost past the noise in either job.
- **The gain.** h2-many's user instructions fell from 11,485 to 11,421 per request in both jobs,
  with spreads of 0.04% or less.

## The baselines

The servers and clients `bench/` and `tools/` run against are peers and numbers, never designs: a
baseline's binary is sampled by function names to split its time, and its source is not read.

`bench/run.sh --competitors` measures nginx, h2o, hyper and http.zig in turns with colibri's
server, over the same inputs (design §8 steps 13c and 13g), and `bench.yml` does so when its
`competitors` input is set. With `--h11`, and `bench.yml`'s `h11` input, four h11 inputs join the
four h2 ones. Each competitor is set up so that all of them do the same work:

- nginx and h2o come from the runner's Ubuntu 24.04 packages, and the report names the version
  each binary gives and the OpenSSL it was built with. hyper is a program of
  `bench/competitors/hyper/`, built with `cargo build --release --locked`: hyper 1 on tokio's
  single-thread runtime, with rustls over aws-lc-rs for TLS. http.zig is a program of
  `bench/competitors/httpz/`, built in ReleaseFast with Zig 0.17.0, the release its master
  targets. The report names each crate's version, the Rust release and http.zig's commit.
- Each answers every request as colibri's test-only server does, from memory: status 200,
  `text/plain; charset=utf-8` and the eight octets `colibri\n`. nginx answers with `return`, and
  h2o 2.2 through its mruby handler. `bench/competitors/` holds every configuration and program.
- Each runs one worker on the core the judge pins servers to, and presents the same P-256
  identity. h2load offers TLS_AES_256_GCM_SHA384 alone, so that all of them run one cipher.
  http.zig runs one thread that reads connections and one that answers, both on that core.
- http.zig has no TLS, so it serves the two cleartext h11 inputs, and the report compares
  colibri with it on those alone.
- nginx 1.24 speaks no h11 on a cleartext port that has `http2`, so run.sh starts it without
  `http2` for the cleartext h11 inputs. Over TLS it offers both by ALPN.
- wrk sends the h11 inputs for a time and counts the requests it finished, which are the units.
  On the `-one` inputs each request asks for `Connection: close`. wrk counts a close as a socket
  read error when the answer did not announce it, as http.zig's does not, so the report allows
  those errors there, one for each request at most. load.sh writes the wrk command first, and the
  report requires the close on each `-one` input and on no other. wrk sets no ALPN, so each server
  speaks h11 to it over TLS too.
- Each keeps its own TLS ticket behavior, and each issues tickets, which h2load never uses.
- The report gives the change's ratio to each competitor, losses first, and a competitor's numbers
  never fail the run. Decision 31 reports where colibri wins, matches and loses.

With `--h3` as well, `--competitors` measures quic-go's h3 server in turns with colibri's UDP
server over the two h3 inputs (design §8 step 13d), and `bench.yml` does so when both of its
inputs are set:

- quic-go's server comes from the image its project publishes for the QUIC Interop Runner, pinned
  by digest, the one `tools/channel_interop.sh` runs. The report names the quic-go commit the
  image holds.
- It runs in a container on the machine's network, on the core the judge pins servers to, which
  leaves Go one processor. `perf stat` counts the server's process from outside the container.
- The image's own start script turns debug logging on. The judge starts the server without that
  script, so that no server writes a log line for a request.
- Each server reads the same file of eight octets from its directory on each request, and
  presents the same P-256 identity. h2load offers TLS_AES_256_GCM_SHA384 alone.
- Each answers with the fields its own code adds, which h2load counts before QPACK: colibri's
  server sends 25 octets of field lines, `content-length` alone, and quic-go's sends 155.

### Latency at fixed rates

`bench/run.sh --latency` measures servers that route, under oha at fixed rates (design §8 step
13f). Run [40526708637](https://github.com/c4milo/colibri/actions/runs/40526708637) is the
baseline. It measured main at `42445f1c` on the judge, `ubuntu-24.04-arm` with Linux
6.17.0-1022-azure, in two jobs on 2026-10-27.

This table gives each server's highest rate whose median p99 stays under 10 ms. At that rate,
every request got 200, and every round reached 95% of the rate. A cell with two values gives job 1,
then job 2.

| Server | h11 | h2 | h2-tls | h3 |
|---|---|---|---|---|
| colibri | 80,000 | 80,000 | 40,000 | 20,000 |
| axum | 80,000 | 40,000 / 80,000 | 40,000 | 20,000 |
| chi | 40,000 | 20,000 | 10,000 / 20,000 | 10,000 |
| http.zig | 40,000 | — | — | — |
| Fastify | 10,000 | 10,000 | none | — |

The rates step by a factor of two, so the table hides a difference smaller than that. Compare the
p99 at one rate inside one job (§11.4):

- **h2-tls at 40,000 req/s.** colibri loses here: its p99 was 4.68 ms and 3.72 ms, and axum's
  3.49 ms and 2.93 ms. At 20,000 req/s the two match, about 1.2 ms each.
- **h3 at 40,000 req/s.** colibri's p99 was 13.76 ms and 11.98 ms, and axum's 15.79 ms and
  14.28 ms. Neither stays under 10 ms.
- **h3 at 80,000 offered.** colibri reached 64,439 and 66,865 req/s, and axum 58,465 and 61,102.

## Memory per connection

The table gives the size in bytes of each struct a program places, and of the connection in each
slot of an endpoint and in each transport of a client's pool. An endpoint holds a server's connections
(design §8 step 21b.6). Each size comes from the code that the build compiles (design §8 step 13b,
§11.2).

`zig build bench-memory` prints the table for the objects the build targets, and `zig build test`
fails when the table here differs from it. The sizes depend on which object chapulin builds: x86-64
and arm64 build its host objects (decision 97 as amended), so one table serves both. Any other
target builds its device objects, prints another heading, and its test fails until this section
holds its table. An endpoint holds each QUIC connection's receive pool. A QUIC connection listed by
itself holds none: a client's program passes one to `Pool.init`, whose default the table lists.
A client's pool holds its TCP connections and its exchanges in memory that the program supplies:
`Pool.memory_bytes(options)` octets beside the fixed part that `@sizeOf` gives (decision 35 as
amended), and the table lists both at the default counts.
The two endpoints of one slot each hold one connection and the endpoint's fixed part, about 12.7 KB
of TLS and connection configuration, which every endpoint holds once.

With chapulin's host objects:

| Struct | Bytes | What it holds |
| --- | ---: | --- |
| `server.Endpoint` | 40987680 | a server's connections at the default capacity: 16 over TCP, and 16 over QUIC with their receive pools |
| `server.EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 })` | 340480 | an endpoint that holds one TCP connection |
| `server.EndpointOf(.{ .tcp_connections = 0, .quic_connections = 1 })` | 2246000 | an endpoint that holds one QUIC connection, with its receive pool |
| `std.meta.Elem(@FieldType(server.Endpoint, "tcp"))` | 323392 | the connection each TCP slot of an endpoint holds: h11 or h2, in cleartext or over TLS |
| `std.meta.Elem(@FieldType(server.Endpoint, "quic"))` | 724192 | the connection each QUIC slot of an endpoint holds, without its receive pool |
| `std.meta.Elem(@FieldType(client.ConnectionPool, "tcp"))` | 306264 | each TCP connection of a pool: h11 or h2, in cleartext or over TLS |
| `std.meta.Elem(@FieldType(client.ConnectionPool, "tcp_links"))` | 48 | what a pool tracks of each TCP slot's connection |
| `std.meta.Elem(@FieldType(client.ConnectionPool, "entries"))` | 40 | each exchange a pool holds at once |
| `@FieldType(client.ConnectionPool, "quic")` | 706600 | a pool's QUIC connection, without its receive pool |
| `client.ConnectionPool` | 708568 | a pool's fixed part: its QUIC connection and link, and its TLS configurations |
| `client.ConnectionPoolOf(.{ .quic = false })` | 1040 | the fixed part of a pool with no QUIC state |
| `client.ConnectionPool.memory_bytes(.{})` | 306952 | the memory a pool takes at the default counts: one TCP connection, its link and 16 requests |
| `client.DefaultReceivePool` | 1507848 | the receive pool a program passes to a pool, at its default capacity |
| `h11.Connection` | 35040 | the h11 state inside a TCP connection |
| `h2.Connection` | 163520 | the h2 state inside a TCP connection |
| `h3.Connection` | 146312 | the h3 state inside a QUIC connection |
| `quic.Connection` | 141912 | the QUIC state inside an h3 connection |
| `tls.record.Client` | 40968 | a TLS client session over TCP |
| `tls.record.Server` | 40328 | a TLS server session over TCP |
| `tls.quic.Client` | 92472 | a TLS client session inside QUIC |
| `tls.quic.Server` | 91904 | a TLS server session inside QUIC |

## Pitfalls this tree has paid for

- **compiler_rt's `memset`.** Symptom: on the judge, a cleartext h2 connection cost 857,000
  instructions against 46,100 for a request on an open one, about 2.8 for each octet of the server's
  TCP connection. Cause: on Linux every `memset` in a Zig 0.16 program is compiler_rt's, which
  writes one octet at a time, and each connection's structs are filled through it. Rule: the
  programs colibri times export their own (`src/testing/memset.zig`), which brought the connection
  to 305,000 instructions. A program that links colibri should export one too, as pepegrillo's guide
  says.
- **A scratch array as large as its limit.** Symptom: every h2 response cost about 940
  instructions before it wrote an octet, whatever it carried. Cause: ReleaseSafe fills an
  `undefined` local with 0xAA on every call, and `respond` copied the caller's fields into an
  array of `field_count_max` lines, 4,096 octets. Rule: read the caller's data where it is, and
  size a scratch array to its data, as pepegrillo's guide says under "Copies and fills". Design
  §8 step 17 has the judge's numbers.
- **A union constant stored whole.** Symptom: each accepted connection cost 35,700 instructions
  for a zero fill of 163,392 octets. Cause: Zig 0.16 stores a union constant such as `.none` over
  every octet of the union, its largest payload's included. Rule: where a payload is large, store
  the tag with `.{ .none = undefined }`, and read the disassembly for the fill again at each Zig
  upgrade, because the language fixes the tag alone. Design §8 step 17 has the judge's numbers.
- **h2load's exit status.** Symptom: one job of the first `bench.yml` run measured a server that
  had not started, and 0 of 20,000 requests succeeded. Cause: h2load exits 0 even when every
  request fails, so a readiness check on its status passes at once. Rule: read the count h2load
  reports, as `bench/run.sh` does.
- **perf's task-clock unit.** Symptom: CPU time a million times too large. Cause: perf 6.17
  writes task-clock in nanoseconds with no unit, where earlier versions wrote milliseconds as
  `msec`. Rule: read the unit perf writes beside each value.

## Commands

```bash
bench/run.sh [--filter] [--base <tree>] [--competitors] [--h11] [--h3] [--rounds <n>] [report.md]
zig build bench-memory
tools/h3load.sh [requests] [port]
tools/interop.sh [peers] [tests]
```
