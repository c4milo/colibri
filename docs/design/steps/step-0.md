# Design §8 step 0: scaffolding

[Design §8, the build plan](../../design.md#8-build-plan)

`build.zig` with the §3 module graph, `constants.zig` per module, the linters ported from stompy
(cognitive complexity, file length, heap, determinism, unbounded loop, relative-import, magic
numbers, markdown GFM) plus colibri's own three: the `io` import denylist, the module-graph rule,
and the RFC-citation rule, which fails a validation branch carrying no RFC section comment. Commit
hooks.
**Check:** `zig build lint` and `zig build test` pass, and a deliberately added `@import("http")`
inside `src/quic/` fails to build. That last clause proves
[invariant 26](../../invariants.md#inv-26) is enforced by the build
rather than by review. *Small.*

**Check passed, 2026-09-16.** `zig build test` exits 0: the lint scores 396 functions across
`build/`, `src/`, `tools/` and `build.zig` with a highest score of 11 against the limit of 15;
the eight `tools/lint` rules run clean; twelve module test binaries pass; and `zig build
graph-check` prints the control line and five refusals. Zig 0.16.0 on macOS 25.6, arm64.

The check has two halves, and neither half alone proves what it appears to prove.
`tools/graph_check.zig` compiles a fixture as the root of a module carrying `quic`'s import set
and requires the compile to fail — that is a real compiler verdict, not a rule about what the
source says. But the set it compiles against is a list in the tool, so the `module-graph` lint
rule reads `build/modules.zig` and `tools/graph_check.zig` and requires the two to agree. The
compile proves the consequence; the rule proves the premise.

Three properties of the check were checked by mutation rather than assumed, each applied, run,
and reverted:
- `http` added to the tool's import set — **CAUGHT**, the fixture compiled and the check exited 1
  naming INV-26.
- The fixture's `comptime` block removed, making the import lazy — **CAUGHT**, and it fails loud
  rather than silent, which is why the block is there: Zig analyses lazily, so an unreferenced
  `const x = @import("http");` compiles clean and would have made the check vacuous.
- `quic.addImport("http", http)` added to `build/modules.zig` — **CAUGHT** by `module-graph` in
  both directions (the build gained an import the graph forbids; the tool's list no longer
  matched), and `zig build test` exited 1.

The positive control is what stops the whole thing being vacuous: a sixth fixture imports
`core`, which `quic` does have, and must compile. A run where the control fails is reported as a
broken check rather than a pass — and it did fail on the first run, on a real defect (`--dep=x`
instead of `--dep x`). The control caught that defect, which is why it exists.

**Tooling moved to pepegrillo, 2026-09-16.** The lint driver and its generic rules, the
complexity scorer and the commit linter now come from pepegrillo (decision 36). `tools/` keeps
colibri's configuration of each rule with the fixtures that pin it, the `module-graph` rule and
the graph check. Old and new tools printed the same findings for all eight rules, the same scores
at `--max 15` and `--max 0`, and the same commit verdicts, over this tree, stompy's and
pepegrillo's. Each of the 62 configuration lines was mutated once and every mutant was
**CAUGHT**; ten needed a new fixture first.

**The last two rules, 2026-09-16.** `magic-numbers` runs over `src/`, but for each
`constants.zig`, the generated `huffman_table.zig`, and the corpus and mutation tables of
`src/golden/`. The 111 literals it found are now named: a byte's width is `@bitSizeOf(u8)`,
the varint lengths and prefix bounds are `wire` constants, and the RFC 9110 §15 status codes are
`http.status.Code`. `rfc-citation` reads every `return error.Name` under `src/`, but for the
short-buffer errors, the test errors, `src/golden/`, `src/sim/` and `src/testing/`, and requires
an `RFC <number> §<section>` or `RFC <number> Appendix <letter>` comment on the statement or the
comment lines directly above it. It found three citations above a `const` rather than above the
check. `zig build lint` passes no `--rule`, so every rule `tools/lint/main.zig` registers runs,
and the lint must report every rule over a canary tree holding one violation of each. Each rule's
mutations are in its commit, and every one is **CAUGHT**.
