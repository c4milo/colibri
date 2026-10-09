# colibri rules

colibri is an HTTP/1.1, HTTP/2 and HTTP/3 library — client and server — written from the RFCs,
named for the hummingbird. Home: github.com/c4milo/colibri.

It is a standalone library. stompy is its first consumer and will vendor it the way it vendors
chapulin. colibri must never depend on stompy, must never name stompy in its source, and must
never take a design decision that only makes sense inside stompy. stompy's workload informs what
colibri measures (docs/design.md §11); it does not inform what colibri's API looks like.

## Read before changing behaviour

- pepegrillo's performance method, which every performance change follows: `zig build guide`
  installs its folder, at the commit `build.zig.zon` pins, to `zig-out/docs/performance/`, starting
  at `performance.md`; then `docs/performance.md`, colibri's appendix to it: its instruments, its
  admission rule, its baselines and the pitfalls it has paid for.
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
2. **chapulin is colibri's crypto, and colibri holds no key.** The library links chapulin as its
   TLS stack and its packet protection, pinned by commit and hash in `build.zig.zon` and compiled
   by colibri's build (decision 94, which amends decisions 8, 9, 10 and 48; design §8 step 16
   carries the move). The two vtables `tls_provider.Provider` and `crypto.Suite` stay inside colibri, with
   two implementations: chapulin's, and the null ones in `src/sim/`, which are test-only, are never
   packaged, and are what let one seed replay. chapulin holds every private key, traffic secret
   and packet protection key; colibri never holds one and never chooses a cipher suite.
   Randomness is the consumer's: chapulin is built `RAND=session`, each session draws from the
   `std.Random` its caller passes to `start` and from nothing else, and the program that links
   colibri defines `ch_assert_fail` (decision 94 as amended).
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
    `docs/rfcs/SHA256SUMS` to show they stay that way. The one exception to RFCs alone is qlog,
    written from the three Internet-Drafts pinned in `docs/rfcs/qlog/` until they publish
    (decision 102).

## Tests are proved by mutation

A test must fail when the code it covers is broken. When you add a check, break it on purpose and
confirm a test fails. Report the result as `CAUGHT` or `NOT CAUGHT` per mutation, in the commit body
or the step's entry in design §8. A `NOT CAUGHT` means a test is missing; write it.

When a mutation shows a rule no test guards, commit the mutant: `src/golden/mutations.zig` carries
the corpus mutations, and each one names the verdict it must produce. The framework for this
exists — never propose a second one.

## The public API is written first

A module's public API is what a program that depends on colibri calls and names. Nothing else is
reachable from outside the module (decision 115). A function that is public by accident becomes
one a dependent calls, and removing it later breaks that dependent, so decide the API before the
code that serves it.

- **The list comes before the code.** A step that adds a module, or a type a program holds,
  names the type's public functions and the root's exports in its entry in design §8. Its first
  commit holds the tests that list them, with `core.public_names.expect`, beside the type and
  beside the root. The test fails until each name exists, and fails again when one is added.
- **The example comes with the call.** A step that adds a call a program makes shows it in
  `examples/` and in docs/usage.md. The example is where a type with no name, a call a program
  cannot reach and a rule the caller must know show up, so write it before the step is done.
- **The root is the module's API file, and it exports names, never files.** Zig has no
  visibility between file-private and `pub`, so `src/<module>/<module>.zig` is the one place a
  name becomes public. A `pub` in any other file means only that another file of the module may
  call it. A line such as `pub const frames = @import("frames.zig");` exports every `pub` of that
  file, the ones its neighbours call too, so a root holds no such line beside `constants`, and
  `error_code` in `quic`. The `root-exports` lint rule refuses one.
- **No public name repeats itself.** A type named after its file is exported under its own
  name: `h2.Connection` and `http.Field`, never `h2.connection.Connection`. A function or a
  constant keeps the namespace of its file: `http.field.validate_name`.
- **Every root reads in one order.** The modules it re-exports, `constants`, the private `files`
  struct that imports each file, each type under its own name, each function or constant under
  the namespace of its file, the test that lists the names, and last the test block that
  references each file so its tests run.
- **A struct's `pub fn`s are a program's calls.** Zig makes a function `pub` so that another
  file can call it, and a type that passes 500 lines is split over files. A function the type's
  other files call is therefore a free function that takes the type's pointer, in a file the
  root does not export, such as `connection_internal.zig`. Never make a method `pub` to call it
  from another file.
- **A check calls what a program calls.** The simulator, the corpus and `src/testing/` use the
  public API. A check that must read what a program does not reads a field, or the root exports
  that one name with a comment that says which check calls it.
- **A new public name is a design change.** It goes on its list in the commit that adds it, and
  the step's entry in design §8 says which program needs it. Never add one to make a test or
  another file compile.

Every library module follows these rules. A name code outside a module needs and the root lacks
is added to the root and to the list in its test, which prints the name that differs.

## Conventions

- Zig 0.16. One library, no binary, plus test-only entry points named in design §9.
- Names are settled — use them exactly: **h11**, **h2** and **h3** for the protocols (never
  "HTTP2"), **field section** and **field line**, the terms RFC 9110 §5.2 uses (never "headers" as a
  noun for the section), **stream** for both h2 streams and QUIC streams with the protocol always
  named when both are in scope, **provider** for a caller-supplied vtable, **endpoint** for one side
  of a connection.
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

- A commit message is a Conventional Commit: `type(scope)!: description`, with the scope and the `!`
  optional. The type is one of a closed set — `feat`, `fix`, `docs`, `test`, `refactor`, `perf`,
  `build`, `ci`, `chore` — and a scope, when present, holds lowercase letters, digits and hyphens.
  The scope allows digits because `h2` and `h3` are the two commonest scopes, and a rule admitting
  letters alone would refuse them. Scopes track the module graph: `h2`, `h3`, `quic`, `hpack`,
  `qpack`, `wire`, `http`, `tls`, `crypto`, `core`, `sim`, `golden`, `bench`, `h11`, `server`,
  `qlog`, `client`. A scope outside that set is a warning rather than a refusal, because the set
  grows when the graph does and docs/design.md §3 is the authority on it, not the linter.
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
- `src/<module>/` is one Zig module, declared in `build.zig` with its imports listed. The fifteen
  library modules are exported by name, so a dependent reaches them with `dependency.module`
  (decision 86); the simulator, the corpus and `src/testing/` are not. A module can only
  `@import` what `build.zig` gives it, so the dependency direction is enforced by the build and not
  by review. The graph is design §3 and the rest of the design depends on it — read it before
  adding a module or an edge.
- The one edge that must never exist: **`quic` may not import `http`, `h2`, `h3`, `h11`, `hpack` or
  `qpack`.** QUIC knows nothing about HTTP (decision 5). The QUIC simulator runs with no HTTP module
  in the graph at all, and that is the check that proves the boundary.
- Each module owns its `constants.zig`. A limit two modules share belongs in
  `src/core/constants.zig`. A comptime assert stays with the constant it pins.
- Tests belong in the file they test. Fixtures and corpora belong beside the module that reads them.
  The one exception is the TLS test identity, which the tests of several modules and the examples
  over TLS read: it lives once in `src/testing/testdata/`, a test-only module no packaged module
  imports, beside the openssl commands that made it.
- `src/testing/` holds the test-only entry points of design §9. It is excluded from the packaged
  library and is the only directory permitted to open a socket. Every endpoint there does its I/O
  without blocking: Rotor's one system call per tick, and no other call that waits (decisions 46,
  58 and 83).
- `examples/` holds programs a project that depends on colibri would write, importing the library
  modules by name. They run on Rotor's loop over an in-memory link and open no socket, and `zig
  build examples` runs every one (decision 96).
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
- Adding a dependency. The library has two: chapulin, which it links for TLS and packet
  protection (decision 94), and stdx, whose gzip and deflate decoders h11 imports, whose zstd and
  brotli decoders the client imports, and whose JSON module qlog imports (decisions 90, 91, 101
  and 102). stdx's `platform` probes the CPU: a program
  calls `probe()` and depends on stdx itself to do it, and `tls` imports the module for its `Cpu`
  type alone and never probes. The package does not export it (decision 97 as amended).
  It has no allocator at all (decision 35). Five more are ruled for the
  tooling and the tests, and the library imports none of them: pepegrillo, the tooling `tools/`
  builds on (decision 36); Rotor, the loop `src/testing/`'s endpoints and `examples/` run on
  (decisions 58, 83 and 96); TLC, the TLA+ model checker `zig build tla` runs through pepegrillo (decision 67);
  `qpackers/qifs`, the QPACK vectors `tools/qpack_vectors.zig` decodes (decision 75); and the Lean
  toolchain, which `zig build lean` runs through pepegrillo (decision 77).
- Weakening an assertion or an invariant to make a test pass.
- Removing or renaming a name on a public list (decision 115). A dependent builds against it.
- Adding an edge to the module graph, and always before adding one into `quic`.
- Implementing anything docs/decisions.md §"What colibri does not build" says no to.

## Commands

Everything below exists. Change this section when a step adds or renames a command.

- Build: `zig build`. `-Drelease` builds ReleaseSafe; ReleaseFast and ReleaseSmall are not
  offered, because assertions stay on in production.
- Guide: `zig build guide` installs pepegrillo's `docs/performance/`, the performance method,
  from the commit `build.zig.zon` pins to `zig-out/docs/performance/` (`build/guide.zig`).
- Lint: `zig build lint` — cognitive complexity over `src`, `tools`, `bench`, `build/` and
  `build.zig`, then the `tools/lint` rules: heap, io, determinism (no clock, no PRNG, outside
  `src/testing`), testing-clock (no clock in `src/testing`, decision 63), unbounded-loop,
  relative-import, module-graph, magic-numbers, markdown GFM, file length, rfc-citation
  (a validation branch with no RFC section comment), peer-index (invariant 3) and
  static-alignment (a global states `align(@alignOf(T))`, which Zig 0.16's x86_64 backend needs
  to place it right), global-state (no library `var` that every thread shares; a fixture
  several test files share lives in a `*_test_support.zig` file) and root-exports (a library
  module's root exports no file but `constants`, and lists what it exports in a test; decision
  115). Every rule
  `tools/lint/main.zig` registers runs, and a canary tree in `build/lint.zig` proves it. The
  rules read `bench/`, `build/`, `examples/`, `src/`, `tools/` and `docs/`, and the Markdown
  files at the repository root, which `lint_rule_files` in `build.zig` names. A new one joins
  that list.
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
  `src/hpack/hpack-test-case/` and round-trips `raw-data/` through the encoder (decision 38).
  `zig build qpack-vectors` decodes every encoded file of the `qifs` package, fetched on the
  first build (decision 75). `zig build test` runs both.
- Simulator: `zig build sim -- --<check>-seed <hex>` runs one seed and prints its trace;
  `zig build sim -- --<check>-check [seeds]` runs the check over `[0, seeds)` and prints the census.
  Every check is also a test inside its module, so `zig build test` runs them, silently. The QUIC
  checks have no command line of their own: `zig build test-sim-run-quic` runs them, in a module
  with no HTTP module in its graph (decision 5), and each one's census is pinned in its test.
- Conformance: `tools/h2spec.sh [--tls]`, `tools/h3spec.sh`, `tools/interop.sh` —
  each starts the test-only endpoint of design §9 and runs the pinned suite version.
  `tools/h2spec.sh` runs the suite in cleartext twice: against the server with `--h2`, which
  speaks h2 alone, and against the server naming no version (decision 117), which reads the case
  that sends an invalid preface as h11 (RFC 9113 §3.3). With `--tls` it also runs `h2spec -t -k`
  against the h2 server's `--tls` mode, which needs Go to mint the identity. `tools/h3spec.sh` fetches
  h3spec once and checks it against a pinned SHA-256. It needs the `SUITE=aesgcm` object, because
  h3spec offers AES suites alone, and runs the server with `no-ecn`, because h3spec's client does
  not parse an ACK frame that carries ECN counts. `tools/h3load.sh [requests] [port]` runs `h2load --h3`
  from an image `tools/h3load/Dockerfile` builds from pinned tags; it needs Docker.
  `tools/h2_interop.sh [--tls] [go] [nghttpd] [h2o] [caddy]` runs the test-only h2 client
  (`zig build http-client`) against other implementations' servers in cleartext, and with `--tls`
  over TLS too, through the client's `--tls <anchor-prefix> --seconds <unix-seconds>` mode; it
  needs `go`, `docker` and `python3`. `tools/h2_server_interop.sh [--tls] [curl] [nghttp]
  [go]` runs curl, nghttp and Go's client against the test-only h2 server the same way;
  it needs `go` and `docker`. With `--tls` each also runs a handshake colibri refuses, the client
  pinning another root and a Go client offering TLS 1.2 alone to the server, and requires Go to
  read colibri's alert. Both endpoints take `--h11`: in cleartext it makes them speak h11,
  and over TLS it makes them offer `http/1.1` alone instead of `h2` and then `http/1.1`. The
  server takes `--h2` for h2 alone the same way. With neither, the server in cleartext names no
  version and speaks h2 when a connection's first octets are h2's preface and h11 otherwise
  (decision 117), as the h11 and h2 server scripts run it. The
  server takes `--h3-port <port>`, the UDP port each TLS connection advertises h3 on, and nghttp
  must read one ALTSVC frame naming it over TLS and none in cleartext (design §8 step 17b).
  `tools/h11_interop.sh [--tls] [go] [h2o] [caddy]` and `tools/h11_server_interop.sh [--tls] [curl]
  [go]` run the same peers over h11: the client against Go's, h2o's and Caddy's servers, and curl
  and Go's client against the server, where curl also offers no ALPN over TLS and must read an
  Alt-Svc line naming h3 over TLS and none in cleartext. Both endpoints also take `--coded` (decision
  101): the server codes its answers in gzip or deflate, and each server script requires curl
  with `--compressed` and Go's client to read gzip; the client offers br, zstd, gzip and deflate
  and decodes each, and each client script runs it against Go's server with `-gzip`, h2o's
  `compress`, which answers in br, and Caddy's `encode`, which answers in zstd. With `--tls` all
  four also send colibri a record that does not authenticate once the handshake is complete, from
  `tools/h2_interop/forged_record.go` as a client and as a server, and require Go to read
  colibri's `bad_record_mac` (RFC 9846 §5.2). None is part of
  `zig build test`. CI runs each of them on every push, except `tools/interop.sh`, which it runs
  every Monday, and `tools/h3load.sh`, which only a person runs. A person runs each before calling
  a step done.
- CI: `tools/ci.sh [report.md]` runs every check above that exists, except `tools/interop.sh` and
  `tools/h3load.sh`, and writes the report; `.github/workflows/main.yml` runs it on each push to
  main (decision 47). A new check joins `tools/ci.sh`, never the workflow file, so CI and a person
  run the same thing. There are three exceptions (decision 47 as amended). The HTTP Garden and the
  QUIC Interop Runner have jobs the workflow starts by hand and every Monday. The `arm64` job runs
  `zig build test` on each push on Linux and macOS arm64, where a person on either machine runs
  the same command.
- Ports: no check `tools/ci.sh` runs binds a fixed port, so two runs on one machine do not collide
  (https://github.com/c4milo/colibri/issues/94). Each peer a script starts binds port 0 and prints
  `listening on port <port>` once its socket is bound. `tools/listening_port.sh <log> [seconds]`
  waits for that line and prints the port, and `tools/listening_port_check.sh` checks the helper.
  A container peer gets the host port Docker chooses and a name the run alone has; its script
  waits for the peer's own socket inside the container and then for the host port. A new check
  does the same. `tools/h3load.sh` and `bench/run.sh`, which `tools/ci.sh` does not run, keep a
  fixed port.
- HTTP Garden: `tools/http_garden.sh [origin...]` builds the Garden, pinned by commit, patched
  once (decision 88 as amended) and cached, with colibri's server added as an origin in its
  `--echo` mode (`tools/http_garden/`), and feeds every stream of `tools/http_garden/driver.py` to
  colibri and each origin, all of them by default. It reports each stream colibri parses
  differently from another origin, which is then judged against RFC 9112, and fails only when a
  stream went uncompared. It needs Linux, Docker with compose, `python3`, `uv` and tens of GB of
  disk. With `GARDEN_REGISTRY` set it pulls the origins' images from that repository and builds
  only the missing ones, and with `GARDEN_PUSH=1` it pushes what it built; the CI job uses
  `ghcr.io/c4milo/colibri-http-garden` (decision 88 as amended).
- Bench: `bench/run.sh [--filter] [--base <tree>] [--competitors] [--rounds <n>] [report.md]`, on
  Linux only, with the machine written down beside the numbers; macOS produces no published number
  (decision 32). It builds the test-only h2 server in ReleaseSafe and counts the server's
  instructions, cycles and system calls per request and per connection with `perf stat`, run as root
  through `sudo -n`, in cleartext and over TLS (design §8 step 13a). With `--base` it builds a
  second tree, measures the two in turns, and fails when an input loses past the noise.
  `.github/workflows/bench.yml` runs it on the `ubuntu-24.04-arm` runner, the judge, in two jobs
  when a person starts it (decision 33 as amended). `--competitors` measures nginx and h2o in turns
  with it, from `bench/competitors/`, and needs both on the PATH (design §8 step 13c). `--filter`
  needs neither perf nor taskset and reads the server's CPU time from /proc: its numbers order
  candidates on a laptop and are never published. It needs Zig, h2load, python3, and Go to mint the
  TLS identity. `zig build bench-memory` prints the static memory per connection for the objects the
  build targets (design §8 step 13b), and `zig build test` fails when `docs/performance.md`'s table
  for those objects differs from it.
- chapulin: `build.zig.zon` pins it (decision 94), and colibri's build compiles its objects from
  the package, each `RAND=session`. The library's `tls` module links two: the TCP object,
  `TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki EXPORTER=on TX_RECORD=16384`, and the QUIC
  object, `TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki`. On x86-64 and arm64 each is
  chapulin's host object, `SUITE=aesgcm` with no `AES`, `WIDEMUL` or `CHACHA` value: it holds every
  fast path beside the portable code, and each session picks from the `tls.Cpu` its caller passes,
  which has no default: the `platform.Cpu` the program's one probe returned, and the `tls.Timing`
  its thread runs in (decision 97 as amended for chapulin 0.2.0,
  https://github.com/c4milo/colibri/issues/84). A session holds RFC 9846 §9.1's mandatory
  TLS_AES_128_GCM_SHA256 only where the probe's `aes_clmul` is `yes` and the timing is
  `data_independent`, and ChaCha20 alone otherwise. On any other target chapulin builds its device
  object, `SUITE=chacha` over its software AES, because chapulin refuses AES-GCM over software AES
  (chapulin's INV-26). `TRANSPORT=tcp-nonblocking` drives the handshake from octets the caller read, so an
  endpoint runs it inside its loop (decisions 46 and 82), and `TRUST=webpki` is the one client
  trust mode that compiles ALPN in, without which no client negotiates h2 (RFC 9113 §3.1).
  `src/testing/`'s h11 and h2 endpoints and TLS checks reach chapulin through `tls`; its QUIC
  endpoints, and `tls_keylog`'s tests, through `tls_keylog`, whose objects are built `KEYLOG=on`
  so a capture can be decrypted. The package exports each object's module `chapulin`: chapulin's
  Zig API (its `docs/zig.md`), which carries the object, with the public headers translated under
  the object's own defines as its `c`. Because the module carries the object, nothing else may add
  it: a second copy fails the link. A program that links `tls` defines chapulin's one hook,
  `ch_assert_fail`, passes each session's `start` the `std.Random` it draws from, and passes each
  configuration its `tls.Cpu`: the probe it takes once, at start, and its thread's timing. Each
  image of `src/testing/` defines the hook (`src/testing/tls/hooks.zig`), passes `getentropy`'s
  octets (`src/testing/entropy.zig`) and the `tls.Cpu` `src/testing/cpu.zig` builds from stdx's
  probe, taken once: it sets PSTATE.DIT on arm64 and states the timing on x86-64, where no program
  can read DOITM. A QUIC image defines `ch_keylog` too (`src/testing/quic/keylog.zig`). The tests
  describe the build target's probe with the timing stated, and run every description where the
  target has the instructions. `zig build
  test-tls test-tls-keylog -Dcpu=<model>` runs the `tls` tests on a CPU model without the AES
  instructions, so with no `yes` among them: `x86_64` on x86-64 and `generic` on Arm. `tools/ci.sh` runs it. A bump is `zig fetch
  --save=chapulin git+https://github.com/c4milo/chapulin#<commit>`.
- TLS checks: `tools/tls_handshake.sh` runs one handshake with colibri as the client against
  a Go server, and `tools/tls_accept.sh` one with colibri as the server against a Go client,
  which also moves a record each way and ends on the client's `close_notify`. Each then runs a
  handshake colibri refuses, a name the certificate does not carry and a client that offers TLS 1.2
  alone, and requires the Go peer to read colibri's alert (RFC 9846 §6.2). Both need a Go
  toolchain, and `tools/ci.sh` runs them.
- Deadline check: `tools/deadlines.sh` runs the test-only server in h11 and h2 on its
  loop's clock and requires four peers to be cut at decision 110's default deadlines, each within
  a second after its instant: half a head and a silent peer at 10 s, a body too slow at 20 s, and
  an h2 preface alone at 10 s. It needs `python3`, and `tools/ci.sh` runs it.
  `tools/h3_deadlines.sh` runs the test-only h3 server the same way, with aioquic as the slow
  peer, from the cached virtual environment of `tools/quic_aioquic.sh` (design §8 step 20c): a
  peer that sends a PING every second and no request gets a GOAWAY and then H3_NO_ERROR at 10 s,
  half a head a 408 at 10 s, a body too slow a 408 at 20 s, and a peer that acknowledges nothing
  of a response H3_EXCESSIVE_LOAD at 20 s. It needs `python3` and a Go toolchain, and
  `tools/ci.sh` runs it.
- QUIC check: `tools/quic_loopback.sh` runs a colibri client and a colibri server over the QUIC
  object in one process, through one handshake and one stream, and writes the secrets to
  `$SSLKEYLOGFILE` when it is set. It needs a Go toolchain, and `tools/ci.sh` runs it.
- UDP QUIC endpoint: `zig build quic-udp -- server <address> <port> <identity-prefix> <www> [once]
  [retry] [errors] [no-ecn] [h3] [connections=<n>] [seconds=<unix-seconds>] [qlogdir=<directory>]`
  and `-- client <address> <port> <anchor-prefix> <hostname> <unix-seconds> <downloads> [keyupdate]
  [resumption] [h3] [pin] [chacha20] [qlogdir=<directory>] <path>...` run design §9's servers and
  clients over Rotor's UDP loop and `tls.quic`. With `pin` the client trusts the server's key, whose
  SHA-256 `<anchor-prefix>.pin` holds, and judges no chain, date or name. With `chacha20` it offers
  TLS_CHACHA20_POLY1305_SHA256 alone, as the runner's chacha20 case requires, and each client names
  the suite it ran in its report. With `qlogdir` each connection writes its qlog into the directory,
  as `<ODCID>_<vantage point>.sqlog` (decision 102). The server serves h3 or hq-interop, whichever
  its client's ALPN asks for, and a client with `h3` fetches over h3. A server with `h3` serves h3
  alone through the `server` module's `Endpoint` (design §8 step 17b), holds `quic_connections_max`
  connections and writes no qlog; `tools/h3spec.sh`, `tools/h3load.sh` and the runner's `http3` run
  it. An address is IPv4 or IPv6; a server bound to `::` takes both on Linux. `tools/quic_udp.sh`
  runs a client against a server on 127.0.0.1 over both protocols and against the `h3` mode,
  checks each file arrives octet for octet, that a missing one is refused, that a client with
  `chacha20` runs TLS_CHACHA20_POLY1305_SHA256, and that a second connection resumes the first one's
  session. It also checks each connection's qlog files with `tools/qlog_check.py`, which requires
  each record to be a JSON text with the members its event requires. `tools/qlog_to_qvis.py
  <file.sqlog> [output]` rewrites one into the qlog 0.3 form qvis reads (decision 102 as amended).
  `tools/quic_aioquic.sh` runs the same endpoint against aioquic's, pinned and installed once
  into a cached virtual environment, over both protocols in both directions, the `h3` mode serving
  h3. It checks that a handshake colibri's server refuses ends with its CONNECTION_CLOSE, and that
  the `h3` mode writes the 100 (Continue) a request expects before aioquic's client sends its
  content; it also needs `python3`. `tools/ci.sh` runs both.
- Channel check: `zig build http-client -- --channel --tls <anchor-prefix> --seconds <unix-seconds>
  [--fallback-ms <milliseconds>] --get <path>...` hands the plan to one `client.Channel`, which
  opens QUIC first and TCP once QUIC fails or the fallback delay passes (design §8 step 17d).
  `tools/channel_interop.sh` runs it against aioquic's h3 server, against quic-go's from the
  QUIC Interop Runner's image, pinned by digest, and against Go's h2 server over TLS, which has no
  UDP and which the client falls back to. It needs `python3`, `docker` and `go`, and
  `tools/ci.sh` runs it.
- QIF tools: `zig build qif -- encode <input.qif> <output> <capacity> <blocked-streams>
  <acknowledgment>` and `-- decode <input> <output.qif> <capacity> <blocked-streams>` are design
  §9's two QPACK tools, over the "QPACK Offline Interop" format. `tools/qif_interop.sh` runs them
  against ls-qpack, through the pylsqpack of the cached aioquic environment, in both directions
  over the qifs inputs; it needs `python3`, and `tools/ci.sh` runs it.
- QUIC Interop Runner: `tools/interop.sh [peers] [tests]`, whose tests include `http3`, builds the
  `colibri-qns` image from this working tree, its fetched packages included, and runs it in the
  runner, pinned by commit, as a server and as a client against each peer. The clone carries two
  patches: `tools/quic_interop/count_handshakes.patch`, which counts the client's connection
  attempts as handshakes (decision 99), and `tools/quic_interop/rebind_challenges.patch`, which
  passes a rebinding test's new path once the client answers any PATH_CHALLENGE sent on it
  (decision 106). The image's endpoint is
  `zig build interop-endpoint`'s `quic-udp-interop`: the UDP endpoint, whose client runs with
  `pin`, because the runner's certificates fail the Web PKI profile (the owner's ruling of
  2026-09-26). The image passes the runner's `QLOGDIR` to the endpoint, and every qlog file it
  leaves must pass `tools/qlog_check.py`. It needs Docker with docker compose, `python3` and
  `tshark` from Wireshark 4.5.0 or newer. The workflow's `quic-interop-runner` job runs it against
  quic-go, ngtcp2, neqo and quinn on Ubuntu 26.04, which packages tshark 4.6 (decision 47 as
  amended).
- Models: `zig build tla [-- <configuration>...]` model-checks the TLA+ specifications in
  `spec/tla/` with TLC, through pepegrillo's `tla` tool. `tools/tla.zig` pins TLC by release and
  SHA-256, and the jar is cached on first use; it needs Java. The first line of each
  configuration says whether TLC must find its properties holding or violated, and a file in a
  model's `mutants/` must find them violated. `tools/ci.sh` runs it where Java is installed
  (decision 67).
- Traces: `tools/h3_trace.sh` writes 64 seeds of the simulator's h3 trace run as TLA+ with `zig
  build sim -- --h3-trace-write <directory>`, and TLC checks that each is a behavior of
  `spec/tla/h3_connection` (decision 87). `tools/h2_trace.sh` does the same for the h2 trace run,
  with `--h2-trace-write` and `spec/tla/h2_connection` (decision 104), `tools/client_trace.sh`
  for the client trace run, with `--client-trace-write` and `spec/tla/client_exchanges` (decision
  105), `tools/deadline_trace.sh` for the deadline trace run, with `--deadline-trace-write` and
  `spec/tla/server_deadlines`, whose logs also say when three of colibri's clocks run
  (https://github.com/c4milo/colibri/issues/86), and `tools/tcp_trace.sh` for the TCP trace run,
  with `--tcp-trace-write` and `spec/tla/h2_connection`, through `server.Connection` and
  `client.Connection` in cleartext and over TLS (https://github.com/c4milo/colibri/issues/79),
  and `tools/h3_deadline_trace.sh` for the h3 deadline trace run, with
  `--h3-deadline-trace-write` and `spec/tla/h3_deadlines`, whose logs hold only the variables
  that map one to one onto colibri (design §8 step 20d). Each needs Java, and `tools/ci.sh` runs
  all six beside `zig build tla`.
- Proofs: `zig build lean` builds the Lean proofs in `spec/lean/` with lake, through pepegrillo's
  `lean` tool, and checks that the vector files the Zig tests read (such as
  `src/qpack/insert_count_vectors.txt` and the files beside `src/wire/varint.zig`) are what the
  proved definitions give; `zig build lean -- write` rewrites them. `spec/lean/lean-toolchain` pins the Lean release, which elan installs.
  `tools/ci.sh` runs it where lake is installed (decision 77), and the workflow installs that
  release for it (decision 47 as amended).
- Format: `zig fmt --check build.zig bench build examples src tools`.
- Examples: `zig build examples` builds and runs every program in `examples/`, and `zig build
  example-<name>` runs one (decision 96). Each checks what arrived octet for octet.
  `tools/doc_snippets.sh` requires every Zig block in README.md, docs/usage.md and
  examples/README.md to be a verbatim excerpt of an example or of `tools/consumer/`, and
  `tools/consumer_check.sh` builds and runs `tools/consumer/` as a project that depends on colibri
  as a package. `tools/ci.sh` runs all three.
- Commit messages: `zig build hooks` once after cloning points `core.hooksPath` at `.githooks`;
  `zig build lint-commits` checks `origin/main..HEAD`; `zig build install-commit-lint` installs the
  linter the hook runs. `.githooks/pre-push` is a copy of pepegrillo's `hooks/pre-push`, and
  `zig build test` fails when the two differ.
- Tooling: the first build on a machine fetches pepegrillo (decision 36), Rotor (decision 58), the
  `qifs` vectors (decision 75), chapulin (decision 94) and stdx (decision 90). stdx is not lazy,
  because the library imports it; a bump is `zig fetch --save=stdx
  git+https://github.com/c4milo/stdx#<commit>`, to a commit whose CI passed.
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
