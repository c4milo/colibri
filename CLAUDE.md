# colibri rules

colibri is an HTTP/2 and HTTP/3 library — client and server — written from the RFCs, named for
the hummingbird. Home:
github.com/c4milo/colibri.

It is a standalone library. stompy is its first consumer and will vendor it the way it vendors
chapulin. colibri must never depend on stompy, must never name stompy in its source, and must
never take a design decision that only makes sense inside stompy. stompy's workload informs what
colibri measures (docs/design.md §11); it does not inform what colibri's API looks like.

## Read before changing behaviour

- `docs/design.md` — the module graph, the wire formats, and the numbered build plan. Each step
  names the check that proves it. Cite sections by number in commits and comments ("§8 step 4").
- `docs/decisions.md` — numbered decisions, each with the alternatives it beat.
- `docs/invariants.md` — numbered invariants, each one a runtime assertion.

All three record decisions with the alternatives they beat. If you are about to do something a
document rejected, say so and stop — do not reverse it in code.

## Non-negotiables

The architecture depends on every rule in this section.

1. **colibri owns no I/O.** No socket, no file descriptor, no `poll`, no thread. Frames and heads
   are written into storage the caller owns and parsed out of bytes the caller has already read.
   Every function that would block instead returns a value naming the I/O it needs. Do not
   make a syscall in this repository.
2. **colibri owns no crypto.** Two caller-supplied vtables, `tls.Provider` and `crypto.Suite`, with
   no production implementation in this tree (decisions 8, 9 and 48): `src/sim/` will carry the null
   implementations, which are test-only and are never packaged; design §8 step 2 records that the
   null provider lands with step 5 and the null suite with step 7. chapulin fills both vtables for
   the checks, linked by `src/testing/` alone (decision 10). The library never links a TLS stack,
   never holds a private key, a traffic secret or a packet protection key, and never chooses a
   cipher suite.
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
   cannot be versioned by us, so our own structures must carry a version and a size.
7. **The simulator precedes the protocol it tests.** Do not write connection code before the
   deterministic harness that can drive it. For QUIC this is the hardest part, and design §8
   steps 2 and 8 settle it: the simulator is built against what the caller supplies — `io` is
   the caller's, time is a parameter, crypto is a vtable — so it exists before there is a
   protocol to drive.
8. **Invariants are code.** Give every numbered invariant in `docs/invariants.md` at least one
   runtime assertion. A violated invariant halts with the seed and the byte offset that produced
   it.
9. **Every RFC rule cited by section, in the code.** A check that exists because an RFC demands
   it carries the RFC and the section in a comment on the line that does the checking. A reader
   must be able to go from any validation to the sentence that requires it. Cite the RFC that
   *states* the rule, not the one that inherits it: h2's lowercase-field-name rule is RFC 9113
   §8.2, with its receive-side check in §8.2.1 — not RFC 9110.
10. **Read the RFCs, never a summary and never another implementation's source.** RFC 9113
    obsoletes RFC 7540 and RFC 9846 obsoletes RFC 8446 — do not read either older document, and
    do not cite it. An obsoleting revision renumbers, so a section number carried over from the
    older one may name a different rule or none at all; find the section that states the rule and
    cite that. The copies to read are in `docs/rfcs/`, unmodified from rfc-editor.org, with
    `docs/rfcs/SHA256SUMS` to show they stay that way.

## Tests are proved by mutation

A test must fail when the code it covers is broken. When you add a check, break it on purpose and
confirm a test fails. Report the result as `CAUGHT` or `NOT CAUGHT` per mutation, in the commit body
or the step's entry in design §8. A `NOT CAUGHT` means a test is missing; write it.

When a mutation shows a rule no test guards, commit the mutant: `src/golden/mutations.zig` carries
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
  fail closed. Assertions are for programmer error only, placed at contract points, never in a
  per-byte path that parses hostile input.
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
  hyphens. The scope allows digits because `h2` and `h3` are the two commonest scopes, and a rule
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

- `build.zig` stays short: build options and the module graph. Helpers belong in `build/`.
- `src/<module>/` is one Zig module, declared in `build.zig` with its imports listed. A module can
  only `@import` what `build.zig` gives it, so the dependency direction is enforced by the build and
  not by review. The graph is design §3 and the rest of the design depends on it — read it before
  adding a module or an edge.
- The one edge that must never exist: **`quic` may not import `http`, `h2`, `h3`, `hpack` or
  `qpack`.** QUIC knows nothing about HTTP (decision 5). The QUIC simulator runs with no HTTP
  module in the graph at all, and that is the check that proves the boundary.
- Each module owns its `constants.zig`. A limit two modules share belongs in
  `src/core/constants.zig`. A comptime assert stays with the constant it pins.
- Tests belong in the file they test. Fixtures and corpora belong beside the module that reads them.
- `src/testing/` holds the test-only entry points of design §9. It is excluded from the packaged
  library and is the only directory permitted to open a socket. Every endpoint there does its I/O
  without blocking: one `poll` call over a fixed array of connections, or Rotor's one system call
  per tick for the UDP endpoints, and no other call that waits (decisions 46 and 58).
- `src/golden/` holds the byte-exact corpus with a manifest naming each file's length, checksum
  and expected verdict.
- `tools/` is developer tooling, run by `zig build lint` and never linked into the library. Its rule
  implementations come from pepegrillo, a lazy Zig package in `build.zig.zon` (decision 36);
  `tools/` holds colibri's configuration of each rule and the rules only colibri has.
- `docs/` is the design set. `bench/` holds benchmarks with their scripts and their committed
  baselines.
- `spec/` holds the formal specifications: one directory per TLA+ model in `spec/tla/`, and Lean
  proofs, when there are any, in one Lean project in `spec/lean/` (decision 67). Every project
  that uses pepegrillo keeps them this way.

## Performance

colibri runs inside other people's hot paths, so cost is part of the design and not a later pass.
The discipline is [Abseil's performance hints](https://abseil.io/fast/hints.html), applied to this
tree. Design §11 holds the method and the numbers.

- **Measure; do not assume.** A performance claim carries a number, the command that produced it
  and the machine it ran on. `bench/` holds the baselines; macOS publishes no number (decision 32).
- **Know the order of magnitude before optimizing.** A cache reference, a main-memory read, a
  syscall and a network round trip are orders of magnitude apart. Say which of the four a change
  moves, and by how much.
- **Cross the caller's boundary in bulk.** One call reads a whole frame; one call writes every
  reply colibri owes. A per-octet entry point is a per-octet cost.
- **The hot path allocates nothing**, which non-negotiable 4 already requires. What is left to
  judge a change on is syscalls, copies, cache misses and branches.
- **Lay out structs for the cache.** Keep the fields one function touches together, hold hot
  mutable fields apart from read-only ones, use the smallest integer that holds the value, and
  index a fixed array rather than follow a pointer.
- **No two threads write one cache line.** colibri is single-threaded per connection; the
  endpoints of §9 give each core its own state and share nothing.
- **Fast path first, slow path in its own function**, so the common case stays small enough to
  inline and the rare case costs nothing to skip.
- **Precompute what cannot change.** The Huffman and static tables are generated at build time,
  and a value that is the same on every call is computed once, outside the loop.
- **Nothing counts, samples or logs on the per-frame path.** A statistic that costs a branch per
  frame has a price; drop it or sample it outside the loop.
- **A rewrite that only reads better is not a performance change.** Name the cost it removes.

## Ask before

- Changing a named limit.
- Adding a dependency. The library is meant to have none: no package, no vendored C, and no
  allocator at all (decision 35). There are four ruled exceptions, and the library imports none:
  chapulin, which `src/testing/` links (decision 10); pepegrillo, the tooling `tools/` builds on
  (decision 36); Rotor, the loop `src/testing/`'s UDP endpoints run on (decision 58); and TLC, the
  TLA+ model checker `zig build tla` runs through pepegrillo (decision 67).
- Weakening an assertion or an invariant to make a test pass.
- Adding an edge to the module graph, and always before adding one into `quic`.
- Implementing anything docs/decisions.md §"What colibri does not build" says no to.

## Commands

Everything below exists but `tools/h3spec.sh` and `bench/run.sh`, which land with design §8 steps
12 and 13. Change this section when a step adds or renames a command.

- Build: `zig build`. `-Drelease` builds ReleaseSafe; ReleaseFast and ReleaseSmall are not
  offered, because assertions stay on in production.
- Lint: `zig build lint` — cognitive complexity over `src`, `tools`, `build/` and `build.zig`,
  then the `tools/lint` rules: heap, io, determinism (no clock, no PRNG, outside `src/testing`),
  testing-clock (no clock in `src/testing`, decision 63), unbounded-loop,
  relative-import, module-graph, magic-numbers, markdown GFM, file length, rfc-citation
  (a validation branch with no RFC section comment) and peer-index (invariant 3). Every rule
  `tools/lint/main.zig` registers runs, and a canary tree in `build/lint.zig` proves it.
- Test: `zig build test` — depends on `lint`, then every module's unit tests and `golden-check`.
  `zig build test-<module>` runs one target's tests with nothing else in the graph, which is what
  a mutation is measured against.
- Golden corpus: `zig build golden-check` checks the embedded corpus against the constructors;
  `zig build golden` regenerates `src/golden/` and refuses a directory carrying a `FROZEN` marker.
- Generated tables: `zig build huffman-table` regenerates `src/wire/huffman_table.zig` from RFC
  7541 Appendix B, `zig build static-table` regenerates `src/hpack/static_table.zig` from its
  Appendix A, and `zig build qpack-static-table` regenerates `src/qpack/static_table.zig` from
  RFC 9204 Appendix A; `zig build test` fails when a committed table differs from what its RFC
  yields.
- Vectors: `zig build hpack-vectors` decodes every story of the vendored
  `src/hpack/hpack-test-case/` and round-trips `raw-data/` through the encoder (decision 38);
  `zig build test` runs it.
- Simulator: `zig build sim -- --<check>-seed <hex>` runs one seed and prints its trace;
  `zig build sim -- --<check>-check [seeds]` runs the check over `[0, seeds)` and prints the census.
  Every check is also a test inside its module, so `zig build test` runs them, silently. The QUIC
  checks have no command line of their own: `zig build test-sim-run-quic` runs them, in a module
  with no HTTP module in its graph (decision 5), and each one's census is pinned in its test.
- Conformance: `tools/h2spec.sh`, `tools/h3spec.sh`, `tools/interop.sh` — each starts the
  test-only endpoint of design §9 and runs the pinned suite version. `tools/h2_interop.sh [go]
  [nghttpd] [h2o]` runs the test-only h2 client (`zig build h2-client`) against other
  implementations' servers; it needs `go`, `docker` and `python3`. None is part of
  `zig build test`; CI runs them, and so does a person before calling a step done.
- CI: `tools/ci.sh [report.md]` runs every check above that exists and writes the report;
  `.github/workflows/main.yml` runs it on each push to main (decision 47). A new check joins
  `tools/ci.sh`, never the workflow file, so CI and a person run the same thing.
- Bench: `bench/run.sh` on Linux only, with the machine written down beside the numbers. macOS
  produces no published number (decision 32).
- TLS endpoints: `-Dchapulin-client=<checkout>` and `-Dchapulin-server=<checkout>` link chapulin
  into `src/testing/` and nowhere else (decision 10). colibri vendors none of its C: build the
  checkout yourself with `make RAND=drbg TRUST=webpki EXPORTER=on lib && cp bin/chapulin.o
  bin/chapulin-client.o` and `make RAND=drbg ROLE=server TRUST=none EXPORTER=on lib && cp
  bin/chapulin.o bin/chapulin-server.o`, and colibri reads the headers from it in place. The client's
  `TRUST=webpki` is not a preference: chapulin compiles its ALPN fields out for `TRUST=raw` and
  `TRUST=ca`, and without ALPN no client can negotiate h2 (RFC 9113 §3.1), so colibri refuses
  such a build at compile time. Without the options the TLS endpoints compile to nothing, so a
  clone with no chapulin still builds and still runs every other check. Copy each role's object
  out before building the other: `make clean` removes the one already written.
- TLS checks: `tools/tls_handshake.sh <checkout> [port]` runs one handshake with colibri as the
  client against a Go server, and `tools/tls_accept.sh <checkout> [port]` one with colibri as the
  server against a Go client, which also moves a record each way and ends on the client's
  `close_notify`. Both need a Go toolchain and both roles built. `tools/ci.sh` runs them when it
  finds a checkout carrying both objects, at `$CHAPULIN` or `../chapulin`, and says so when it
  does not.
- QUIC check: `-Dchapulin-quic=<checkout>` links chapulin's QUIC object into `src/testing/` and
  nowhere else. Build it with `make RAND=drbg TRUST=webpki TRANSPORT=quic ROLE=both KEYLOG=on lib
  && cp bin/chapulin.o bin/chapulin-quic.o`; `ROLE=both` puts both roles in one object, and
  `KEYLOG=on` hands the check the traffic secrets. `tools/quic_loopback.sh <checkout>` runs a
  colibri client and a colibri server over it in one process, through one handshake and one
  stream, and writes the secrets to `$SSLKEYLOGFILE` when it is set. It needs a Go toolchain.
  `tools/ci.sh` runs it when it finds `bin/chapulin-quic.o`.
- UDP QUIC endpoint: `zig build quic-udp -- server <address> <port> <identity-prefix> <www>
  [once] [retry] [connections=<n>] [seconds=<unix-seconds>]` and `-- client <address> <port>
  <anchor-prefix> <hostname> <unix-seconds> <downloads> [keyupdate] [resumption] <path>...` run
  design §9's hq-interop server and client over Rotor's UDP loop and the same chapulin object,
  which must be chapulin `2262eee` or later for its session tickets. An address is IPv4 or IPv6; a
  server bound to `::` takes both on Linux. `tools/quic_udp.sh <checkout> [port]` runs a client
  against a server on 127.0.0.1, checks each file arrives octet for octet, that a missing one
  resets its stream, and that a second connection resumes the first one's session, and
  `tools/ci.sh` runs it beside the loopback check. `tools/quic_aioquic.sh <checkout> [port]` runs
  the same endpoint against aioquic's, pinned and installed once into a cached virtual
  environment, in both directions; it also needs `python3`, and `tools/ci.sh` runs it too.
- QUIC Interop Runner: `tools/interop.sh <checkout> [peers] [tests]` builds the `colibri-qns` image
  from this working tree and the checkout, with chapulin built `TRUST=raw-ecdsa` because the
  runner's certificates fail the Web PKI profile, and runs it in the runner, pinned by commit, as a
  server and as a client against each peer. It needs Docker with docker compose, `python3` and
  `tshark` from Wireshark 4.5.0 or newer. `-Dchapulin-quic-trust=raw-ecdsa` builds against such an
  object here.
- Models: `zig build tla [-- <configuration>...]` model-checks the TLA+ specifications in
  `spec/tla/` with TLC, through pepegrillo's `tla` tool. `tools/tla.zig` pins TLC by release and
  SHA-256, and the jar is cached on first use; it needs Java. The first line of each
  configuration says whether TLC must find its properties holding or violated, and a file in a
  model's `mutants/` must find them violated. `tools/ci.sh` runs it where Java is installed
  (decision 67).
- Format: `zig fmt --check build.zig build src tools`.
- Commit messages: `zig build hooks` once after cloning points `core.hooksPath` at `.githooks`;
  `zig build lint-commits` checks `origin/main..HEAD`; `zig build install-commit-lint` installs the
  linter the hook runs. `.githooks/pre-push` is a copy of pepegrillo's `hooks/pre-push`, and
  `zig build test` fails when the two differ.
- Tooling: the first build on a machine fetches pepegrillo (decision 36) and Rotor (decision 58).
  A Rotor bump is `zig fetch --save=rotor git+https://github.com/c4milo/rotor#<commit>`, and
  `.lazy = true` must survive it too. After a pepegrillo bump with `zig
  fetch --save=pepegrillo git+https://github.com/c4milo/pepegrillo#<commit>`, confirm `.lazy = true`
  is still set in `build.zig.zon` and copy the new hook. `zig build --fork=<pepegrillo checkout>`
  builds against a local pepegrillo instead of the pinned commit.

CI runs `tools/ci.sh` on each push to main (decision 47). A check CI cannot run — one that needs a
machine a hosted runner is not — is run by a person before a step is called done. Either way the
step's entry in design §8 records what was run, on what, and what it printed.

## Where the work stands

Progress is not tracked here. Open work, what comes next, and what is owed by whom are GitHub
issues at `https://github.com/c4milo/colibri/issues`. A check met is recorded once, in its step's
entry in design §8, with what was run, on what, and what it printed. Rulings are numbered in
docs/decisions.md. This file holds rules only.
