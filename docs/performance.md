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
  four inputs:
  - `h2-many` and `h2-tls-many`: many requests on each of a few connections, counted per request,
    in cleartext and over TLS.
  - `h2-one` and `h2-tls-one`: one request on each connection, counted per connection.
- Each input runs one warm-up round, which the report discards, and then five rounds. With
  `--base`, the base and the change take turns in each round, and the order alternates. The report
  gives each input's median and spread, and the ratio of the change to the base with the losses
  first. The run fails when an input loses past the noise: the larger of the two spreads and the
  floor.
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

## The baselines

The servers and clients `bench/` and `tools/` run against are peers and numbers, never designs: a
baseline's binary is sampled by function names to split its time, and its source is not read.

## Memory per connection

Each struct a caller holds for one connection, in bytes, from the code being built (design §8 step
13b, §11.2). `zig build bench-memory` prints the table for the objects the build targets, and
`zig build test` fails when the table here differs from it. The sizes depend on chapulin's `AES`
value: x86-64 and arm64 build `AES=runtime` (decision 97 as amended), so one table serves both. A
target built otherwise prints another heading, and its test fails until this section holds its
table. The QUIC connections hold no receive pool: their caller passes one, whose default the table
lists.

With chapulin's objects built `AES=runtime`:

| Struct | Bytes | What it holds |
| --- | ---: | --- |
| `server.Connection` | 306280 | one TCP connection: h11 or h2, in cleartext or over TLS |
| `server.QuicConnection` | 717520 | one h3 connection, without its receive pool |
| `client.Connection` | 289064 | one TCP connection: h11 or h2, in cleartext or over TLS |
| `client.QuicConnection` | 702912 | one h3 connection, without its receive pool |
| `client.Channel` | 992904 | one server's connections, QUIC first and TCP after, without receive pools |
| `client.DefaultReceivePool` | 1505288 | the receive pool a QUIC connection's caller passes, at its default capacity |
| `h11.connection.Connection` | 35040 | the h11 state inside a TCP connection |
| `h2.Connection` | 163248 | the h2 state inside a TCP connection |
| `h3.Connection` | 145512 | the h3 state inside a QUIC connection |
| `quic.Connection` | 141624 | the QUIC state inside an h3 connection |
| `tls.record.Client` | 40544 | a TLS client session over TCP |
| `tls.record.Server` | 39904 | a TLS server session over TCP |
| `tls.quic.Client` | 90000 | a TLS client session inside QUIC |
| `tls.quic.Server` | 89424 | a TLS server session inside QUIC |

## Pitfalls this tree has paid for

- **compiler_rt's `memset`.** Symptom: on the judge, a cleartext h2 connection cost 857,000
  instructions against 46,100 for a request on an open one, about 2.8 for each octet of
  `server.Connection`. Cause: on Linux every `memset` in a Zig 0.16 program is compiler_rt's,
  which writes one octet at a time, and each connection's structs are filled through it. Rule: the
  programs colibri times export their own (`src/testing/memset.zig`), which brought the
  connection to 305,000 instructions. A program that links colibri should export one too, as
  pepegrillo's guide says.
- **h2load's exit status.** Symptom: one job of the first `bench.yml` run measured a server that
  had not started, and 0 of 20,000 requests succeeded. Cause: h2load exits 0 even when every
  request fails, so a readiness check on its status passes at once. Rule: read the count h2load
  reports, as `bench/run.sh` does.
- **perf's task-clock unit.** Symptom: CPU time a million times too large. Cause: perf 6.17
  writes task-clock in nanoseconds with no unit, where earlier versions wrote milliseconds as
  `msec`. Rule: read the unit perf writes beside each value.

## Commands

```bash
bench/run.sh [--filter] [--base <tree>] [--rounds <n>] [report.md]
zig build bench-memory
tools/h3load.sh [requests] [port]
tools/interop.sh [peers] [tests]
```
