# Contributing

colibri holds a high bar because it runs inside other programs' hot paths and reads octets from
strangers. This page is the contributor's summary. [CLAUDE.md](CLAUDE.md) holds the full rules,
and a change follows them whoever writes it.

## Before you start

Read the three documents a change must not contradict:
- [`docs/design.md`](docs/design.md): the module graph, the wire formats, and the numbered build
  plan. Cite its sections by number, for example "§8 step 4".
- [`docs/decisions.md`](docs/decisions.md): every numbered decision, with the alternatives it
  beat. If a change would do something a decision rejected, raise it in an issue first.
- [`docs/invariants.md`](docs/invariants.md): the numbered invariants, each one a runtime
  assertion.

Open work and what comes next are [GitHub issues](https://github.com/c4milo/colibri/issues).

## Setup

colibri needs Zig 0.16.0 and nothing else to build and test. After cloning:

```sh
zig build hooks
zig build test
```

`zig build hooks` points git at `.githooks`, which checks commit messages. `zig build test` runs
the lint first, then every module's tests and the golden corpus. The first build fetches the
tooling colibri pins: pepegrillo, Rotor and the QPACK vectors.

Some checks need more:
- the TLS and QUIC endpoints need a chapulin checkout, built as CLAUDE.md's Commands section
  shows;
- `zig build tla` needs Java, and `zig build lean` needs a Lean toolchain;
- the conformance and interop scripts in `tools/` need the tools each one names.

`tools/ci.sh` runs every check whose tools it finds, and says which it skipped.

## The rules a change keeps

- **No I/O, no heap, no clock.** colibri makes no system call, holds no `Allocator`, and reads no
  clock or random source. The caller owns every buffer and passes every instant. The lint refuses
  each of these.
- **Every limit is named.** A limit lives in its module's `constants.zig`, never inline. Every
  loop is bounded.
- **Every RFC rule is cited.** A check that exists because an RFC requires it carries the RFC and
  the section in a comment on the line that makes it. Cite the RFC that states the rule. Read the
  copies in [`docs/rfcs/`](docs/rfcs/), never a summary or another implementation's source.
- **Peer input fails closed.** A malformed octet, a short buffer or a limit reached returns an
  error value. Assertions are for programmer error, at contract points.
- **Parsing goes through the bounds-checked reader**, and output through the writer. No raw
  buffer arithmetic outside them.
- **Small pieces.** A function scores at most 15 on cognitive complexity, and a source file stays
  at or under 500 lines, tests included. Split rather than raise a limit.
- **Plain names.** Names spell words out; the RFCs' own terms keep the RFCs' spelling. The
  protocols are h11, h2 and h3.

## Tests are proved by mutation

A test must fail when the code it covers is broken. When you add or change a check, break it on
purpose and confirm a test fails. Report each mutation as `CAUGHT` or `NOT CAUGHT` in the commit
body or in the step's entry in `docs/design.md` §8. A `NOT CAUGHT` means a test is missing, so
write it.

A new reader of a peer's octets also gets a fuzz property and, where inputs longer than two
octets matter, cases in the simulator's input checks.

## Commits

Commits are [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): description`.
- The type is one of `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci` or `chore`.
- The scope, when present, is a module: `h2`, `h3`, `quic`, `hpack`, `qpack`, `wire`, `http`,
  `tls`, `crypto`, `core`, `sim`, `golden`, `bench` or `h11`.
- The description is imperative and lowercase, with no period, and the subject line fits in 72
  columns.
- The body says why, in at most 3 paragraphs and 100 words, with lines of at most 100 columns.
  Reasoning that outlives the commit goes in `docs/`.

`zig build lint-commits` checks every commit since `origin/main`. Stage files by path, never with
`git add -A`.

## Asking first

Open an issue before you:
- change a named limit;
- add a dependency, or an edge to the module graph, above all one into `quic`, which must never
  import an HTTP module;
- weaken an assertion or an invariant to make a test pass;
- build something `docs/decisions.md` says colibri does not build.

## Security

Do not report a vulnerability in an issue. [SECURITY.md](SECURITY.md) says where to send it.
