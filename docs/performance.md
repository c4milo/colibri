# Performance work in colibri

The method every performance change follows is pepegrillo's
[docs/performance.md](https://github.com/c4milo/pepegrillo/blob/main/docs/performance.md), at the
commit `build.zig.zon` pins; read it first. This appendix is what that method leaves to the project:
colibri's instruments, its admission rule, its baselines and the pitfalls it has paid for. CLAUDE.md's
Performance section states the rules, and design §11 holds the method's numbers for this tree.

## The instruments

- The judge is `bench/run.sh`, on Linux only, with the machine written down beside the numbers;
  macOS publishes no number (decision 32). `bench/` holds the baselines.
- A laptop run is a filter: it orders candidates and never lands in a document.
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

## Pitfalls this tree has paid for

None recorded yet. The first performance change that pays one adds it here, as symptom, cause and
rule.

## Commands

```bash
bench/run.sh
tools/h3load.sh [requests] [port]
tools/interop.sh [peers] [tests]
```
