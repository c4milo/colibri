# colibri rules

colibri is an HTTP/2 and HTTP/3 library — client and server — written from the RFCs, named for
the hummingbird: small, fast, and it holds still where it needs to. Home:
github.com/c4milo/colibri.

It is a standalone library. stompy is its first consumer and will vendor it the way it vendors
chapulin. colibri must never depend on stompy, must never name stompy in its source, and must
never take a design decision that only makes sense inside stompy. stompy's workload informs what
colibri measures (docs/design.md §11); it does not inform what colibri's API looks like.

## Read before changing behaviour

- `docs/design.md` — the module graph, the wire formats, and the numbered build plan. Each step
  names the gate that proves it. Cite sections by number in commits and comments ("§8 step 4").
- `docs/decisions.md` — numbered decisions, each with the alternatives it beat.
- `docs/invariants.md` — numbered invariants, each one a runtime assertion.

All three record *decisions with the alternatives they beat*. If you are about to do something a
document rejected, say so and stop — do not quietly re-litigate it in code.

## Non-negotiables

These are not style preferences; the architecture depends on them.

1. **colibri owns no I/O.** No socket, no file descriptor, no `poll`, no thread. Frames and heads
   are written into storage the caller owns and parsed out of bytes the caller has already read.
   Every function that would block instead returns what it wants. If you are reaching for a
   syscall, you are in the wrong repository.
2. **colibri owns no crypto.** Two caller-supplied vtables, `tls.Provider` and `crypto.Suite`,
   with no production implementation in this tree (decisions 8 and 9): `src/sim/` carries null
   implementations, which are test-only and are never packaged. chapulin fills both vtables for the
   gates, linked by `src/testing/` alone (decision 10). The library never links a TLS stack, never
   holds a private key, and never chooses a cipher suite.
3. **Time is a value the caller passes, never a clock read.** Every function that needs the
   current instant takes it as a parameter. RFC 9002's pseudocode reads `now()` at nine sites —
   eight in loss recovery (Appendix A) and one in the congestion controller (Appendix B.6) — and
   all nine become parameters on five entry points (design §8 step 10). No source file may import
   a clock. `tools/lint/determinism.zig` enforces it.
4. **TigerStyle.** Zero heap: no `Allocator` anywhere in `src/`, tests included. The caller owns
   every struct and buffer, and colibri exposes their sizes as comptime constants (decision 35).
   Every loop and queue bounded. Every limit named in
   a `constants.zig` and never written inline. Assertions on in production, roughly two per
   function, covering positive and negative space.
5. **Determinism.** One seed replays byte-identically across hosts and build modes. Nothing on a
   protocol path may read the clock, the PRNG, uninitialised memory, or a pointer value. A
   connection's output is a pure function of (its configuration, the bytes it was fed, the
   instants it was given).
6. **Formats are versioned from the first commit.** Every internal on-disk and cross-process
   structure colibri defines carries a version and a size. The wire formats are the RFCs' and
   cannot be versioned by us — which is exactly why our own structures must be.
7. **The simulator precedes the protocol it tests.** Do not write connection code before the
   deterministic harness that can drive it. For QUIC this is the whole difficulty and design §8
   steps 2 and 8 settle it: the simulator is built against the *seams* — `io` is the caller's,
   time is a parameter, crypto is a vtable — so it exists before there is a protocol to drive.
8. **Invariants are code.** Every numbered invariant in `docs/invariants.md` wants at least one
   runtime assertion. A violated invariant halts with the seed and the byte offset that produced
   it.
9. **Every RFC rule cited by section, in the code.** A check that exists because an RFC demands
   it carries the RFC and the section in a comment on the line that does the checking. A reader
   must be able to go from any validation to the sentence that requires it. Cite the RFC that
   *states* the rule, not the one that inherits it: h2's lowercase-field-name rule is RFC 9113
   §8.2, with its receive-side check in §8.2.1 — not RFC 9110.
10. **Read the RFCs, never a summary and never another implementation's source.** RFC 9113
    obsoletes RFC 7540 — do not read 7540, and do not cite it. The copies to read are in
    `docs/rfcs/`, unmodified from rfc-editor.org, with `docs/rfcs/SHA256SUMS` to show they stay
    that way.

## Tests are proved by mutation

A test no mutation can fail is not a test. When you add a check, break it on purpose and confirm
a test fails. Report the result as `CAUGHT` or `NOT CAUGHT` per mutation, in the commit body or
the step's entry in design §8. A `NOT CAUGHT` is a missing test, not a footnote.

When a mutation shows a rule no test guards, land the mutant: `src/golden/mutations.zig` carries
the corpus mutations, and each one names the verdict it must produce. The framework for this
exists — never propose a second one.

## Conventions

- Zig 0.16. One library, no binary, plus test-only entry points named in design §9.
- Names are settled — use them exactly: **h2** and **h3** for the protocols (never "HTTP2"),
  **field section** and **field line**, the terms RFC 9110 §5.2 uses (never "headers" as a noun
  for the section), **stream** for both h2 streams and QUIC streams with the protocol always
  named when both are in scope, **provider** for a caller-supplied vtable, **endpoint** for one
  side of a connection.
- Names spell words out. `field_section_size`, not `fss`. No vowel-dropping. Domain vocabulary
  the RFCs use stays as the RFCs spell it (`alpn`, `aead`, `hkdf`, `psk`, `dcid`, `scid`,
  `pto`, `rtt`, `ack`). One-letter names only for loop indices. `_len` always counts bytes.
- Functions stay at cognitive complexity 15 or less, scored by `tools/cognitive_complexity.zig`.
  `test` blocks are scored under the same limit. Split the function; never raise the threshold.
- A hand-written source file stays at or under 500 lines, its tests included, enforced by
  `tools/lint/file_length.zig`. Split the file rather than raise the limit, and name every piece
  after the file it came from: `hpack.zig` becomes `hpack_decode.zig`, `hpack_table.zig`, and so
  on, keeping the original name as the entry point.
- Four or more files sharing a prefix move into a subdirectory named for it, the pieces keeping
  their full names: `src/quic/packet/packet_header.zig`.
- All parsing goes through a bounds-checked reader and all output through a bounds-checked
  writer. No raw buffer arithmetic outside them. Never assume host endianness; the wire is
  network byte order in h2 (RFC 9113 §2.2) and in QUIC (RFC 9000 §1.3), and colibri reads and
  writes it byte by byte.
- Operational errors — bad peer input, short buffers, a limit reached — return error values and
  fail closed. Assertions are for programmer error only, seeded at contract points, never in a
  per-byte path where hostile input reaches them.
- Write all prose in active voice with plain words, following Google's Technical Writing One and
  Two: short sentences with one idea each, terms defined before use, lists for list-like content,
  strong verbs, no rhetorical flourishes or metaphors.
- Name what literally happens. The failure mode is a vague spatial metaphor standing in for a
  plain verb: a value "reaches" a buffer instead of being written, a limit becomes a "seam"
  instead of the constant it is. Before an abstract word, ask what literally happens and write
  that.
- One name per thing, and it is the name in the code. Never invent prose shorthand for something
  a field or constant already names.
- Every GitHub issue reference carries its full URL
  (`https://github.com/c4milo/colibri/issues/1`), never the bare hash-and-number form. Markdown
  may keep the short form as the link label; Zig and shell comments spell the URL out.
- Every Markdown file is GitHub-flavored Markdown and must render on GitHub as written: real list
  markers only (no bare `3b.` lines, which GitHub folds into the paragraph above; nest them as
  list items), pipes inside a table cell escaped as `\|`, fenced code blocks with a language, no
  definition lists, no LaTeX.

### Commits

- A commit message is a Conventional Commit: `type(scope)!: description`, with the scope and the
  `!` optional. The type is one of a closed set — `feat`, `fix`, `docs`, `test`, `refactor`,
  `perf`, `build`, `ci`, `chore` — and a scope, when present, holds lowercase letters, digits and
  hyphens. The digits are not decoration: `h2` and `h3` are the two commonest scopes, and a rule
  admitting letters alone would refuse them. Scopes track the module graph: `h2`, `h3`, `quic`,
  `hpack`, `qpack`, `wire`, `http`, `tls`, `crypto`, `core`, `sim`, `golden`, `bench`. A scope
  outside that set is a warning rather than a refusal, because the set grows when the graph does
  and docs/design.md §3 is the authority on it, not the linter.
- The description is imperative, starts with a lowercase letter, and ends without a period: write
  `add the huffman decoder`, never `Adds the Huffman decoder.` The subject line stays at or under
  72 columns.
- Exactly one blank line separates the body from the subject. A body line stays at or under 100
  columns and the body stays at or under 3 paragraphs and 100 words. The diff shows the what, so
  the body says why. Reasoning that outlives the commit belongs in `docs/`: state the why in a
  sentence and name the document.
- Stage by explicit path. Never `git add -A` and never `git add .`
- Mutation results belong in the body when a commit adds or changes a check.

## Layout

- `build.zig` stays short: build options and the module graph. Helpers live in `build/`.
- `src/<module>/` is one Zig module, declared in `build.zig` with its imports listed. A module
  can only `@import` what `build.zig` gives it, so the dependency direction is enforced by the
  build and not by review. The graph is design §3 and is load-bearing — read it before adding a
  module or an edge.
- The one edge that must never exist: **`quic` may not import `http`, `h2`, `h3`, `hpack` or
  `qpack`.** QUIC knows nothing about HTTP (decision 5). The QUIC simulator runs with no HTTP
  module in the graph at all, and that is the gate which proves the boundary.
- Each module owns its `constants.zig`. A limit two modules share lives in
  `src/core/constants.zig`. A comptime assert stays with the constant it pins.
- Tests live in the file they test. Fixtures and corpora live beside the module that reads them.
- `src/testing/` holds the test-only entry points of design §9. It is excluded from the packaged
  library and is the only directory permitted to touch a socket.
- `src/golden/` holds the byte-exact corpus with a manifest naming each file's length, checksum
  and expected verdict.
- `tools/` is developer tooling, run by `zig build lint` and never linked into the library. Its
  engines come from pepegrillo, a lazy Zig package in `build.zig.zon` (decision 36); `tools/`
  holds colibri's configuration of each rule and the rules only colibri has.
- `docs/` is the design set. `bench/` holds benchmarks with their scripts and their committed
  baselines.

## Ask before

- Changing a named limit.
- Adding a dependency. The library is meant to have none: no package, no vendored C, and no
  allocator at all (decision 35). There are two ruled exceptions, and the library imports neither:
  chapulin, which `src/testing/` links (decision 10), and pepegrillo, the tooling `tools/` builds
  on (decision 36).
- Weakening an assertion or an invariant to make a test pass.
- Adding an edge to the module graph, and always before adding one into `quic`.
- Implementing anything docs/decisions.md §"What colibri does not build" says no to.

## Commands

Nothing below exists yet; design §8 step 0 lands it. This section is the contract that step
writes to, and it moves when the step lands, not before.

- Build: `zig build`. `-Drelease` builds ReleaseSafe; ReleaseFast and ReleaseSmall are not
  offered, because assertions stay on in production.
- Lint: `zig build lint` — cognitive complexity over `src`, `tools`, `build/` and `build.zig`,
  then the `tools/lint` rules: heap, io, determinism (no clock, no PRNG), unbounded-loop,
  relative-import, module-graph, magic-numbers, markdown GFM, file length, rfc-citation
  (a validation branch with no RFC section comment) and peer-index (invariant 3). Every rule
  `tools/lint/main.zig` registers gates, and a canary tree in `build/lint.zig` proves it.
- Test: `zig build test` — depends on `lint`, then every module's unit tests and `golden-check`.
  `zig build test-<module>` runs one target's tests with nothing else in the graph, which is what
  a mutation is measured against.
- Golden corpus: `zig build golden-check` checks the embedded corpus against the constructors;
  `zig build golden` regenerates `src/golden/` and refuses a directory carrying a `FROZEN` marker.
- Huffman table: `zig build huffman-table` regenerates `src/wire/huffman_table.zig` from RFC 7541
  Appendix B, and `zig build test` fails when the committed table differs from what the RFC yields.
- Simulator: `zig build sim -- --<gate>-seed <hex>` runs one seed and prints its trace;
  `zig build sim -- --<gate>-gate [seeds]` runs the gate over `[0, seeds)` and prints the census.
  Every gate is also a test inside its module, so `zig build test` runs them, silently.
- Conformance: `tools/h2spec.sh`, `tools/h3spec.sh`, `tools/interop.sh` — each starts the
  test-only endpoint of design §9 and runs the pinned suite version. None is part of
  `zig build test`; run them by hand before calling a step done.
- Bench: `bench/run.sh` on Linux only, with the machine written down beside the numbers. macOS
  produces no published number (decision 32).
- Format: `zig fmt --check build.zig build src tools`.
- Commit messages: `zig build hooks` once after cloning points `core.hooksPath` at `.githooks`;
  `zig build lint-commits` checks `origin/main..HEAD`; `zig build install-commit-lint` installs the
  linter the hook runs. `.githooks/pre-push` is a copy of pepegrillo's `hooks/pre-push`, and
  `zig build test` fails when the two differ.
- Tooling: the first build on a machine fetches pepegrillo (decision 36). After a bump with
  `zig fetch --save=pepegrillo git+https://github.com/c4milo/pepegrillo#<commit>`, confirm
  `.lazy = true` is still set in `build.zig.zon` and copy the new hook. `zig build --fork=<pepegrillo checkout>`
  builds against a local pepegrillo instead of the pinned commit.

There is no CI here. Every gate that a script cannot run inside `zig build test` is run by a
person before a step is called done, and the step's entry in design §8 records what was run, on
what, and what it printed.

## Current task

**Step 0 is done.** Decision 3 was ruled on 2026-09-16: `quic` is a module inside colibri taking
`core`, `wire`, `crypto` and `tls`. `build.zig` wires the §3 graph, the twelve module roots carry
their `constants.zig`, and `zig build test` runs the lint, every module's tests and the graph
gate. Design §8 step 0 records what was run and what it printed.

**Step 1 is done.** `core` holds the bounded reader and writer (invariant 3) and the shared fuzz
harness. `wire` holds the varint, the prefixed integer, the Huffman coder over a table generated
from RFC 7541 Appendix B, and the string literal. `http` holds the field validators, the
connection-specific denylist, and the method and status models. `src/golden/` holds the corpus and
its mutations. Design §8 step 1 records what was run and what it printed, including the one part
not built: invariant 3's lint rule.

**Step 2, the deterministic driver, is next.**

Decision 9 was ruled on 2026-09-16: two vtables, `tls.Provider` for the handshake and
`crypto.Suite` for packet protection, so step 7 has the interface it builds against.

Decision 10 was ruled on 2026-09-16: chapulin provides all of colibri's crypto by filling both
vtables. The library never imports chapulin, and `src/testing/` links it, which answers the
dependency question design §8 step 5 raised. The request is docs/chapulin.md and is the owner's to
send. No decision waits on the owner. Every gate that needs crypto waits on chapulin delivering
the request, and steps 0 to 4, 6, 8 and 11 need none of it.
