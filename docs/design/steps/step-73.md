# Design §8 step 73: the package exports `colibri` alone, 2026-11-25

[Design §8, the build plan](../../design.md#8-build-plan)

The owner asked that a program import one module ([decision 170](../../decisions/0170-the-package-exports-one-module-colibri.md)).
- **Public names.** The root of `colibri` gains fourteen: `core`, `wire`, `http`,
  `tls_provider`, `tls`, `dnssec`, `crypto`, `qlog`, `hpack`, `qpack`, `quic`, `h2`, `h3` and
  `h11`, beside `server` and `client` of step 44i. Each is the module itself. A program that
  depends on colibri needs them, because the package now exports no other module. The root's
  list test holds the 32 names, and requires each of the sixteen to be its module.
- **The build.** `modules.library` creates each library module with `createModule`, and
  `modules_colibri.add` alone calls `addModule`. `colibri` imports the sixteen others.
  `build/modules_exports.zig`, which exported stdx's codecs, is gone. The module graph of §3
  keeps every other edge, so `zig build test-<module>` and the QUIC simulator's graph with no
  HTTP module are as before.
- **The programs.** Each program of `examples/` imports `colibri` alone and binds its names:
  `const server = colibri.server;`. `h11_exchange` and `h2_exchange` now define
  `ch_assert_fail`: `colibri` links chapulin for `tls`, and neither linked it before.
  `tools/consumer/`, `tools/consumer_hosted/`, `bench/router/` and
  `bench/router/competitors/colibri/` import `colibri` alone too. `tools/consumer/` takes
  stdx's `gzip` from stdx.
- **The check.** `tools/consumer/build.zig` asks the package for a module by name with
  `-Dnamed-module`. `tools/consumer_check.sh` asks for `h2` and for `gzip`, and requires each
  build to stop with Zig's "unable to find module".
- **Mutations: 5, each CAUGHT.** Against `zig build test-colibri`, by the root's list test:
  `h2` naming the module `h3`; `dnssec` not named; and one more public name. Against
  `tools/consumer_check.sh`: each library module exported by name again; and stdx's `gzip`
  exported again.
- **The documents.** docs/usage.md's "Adding colibri" shows the one import. README.md went
  from 558 lines to 297: it keeps one server, one client and the route table, and points to
  docs/usage.md and `examples/` for the rest. The whole reading of its three charts, with each
  server's version, moved to docs/performance.md, "The charts of the README". The note on a
  global's alignment moved to docs/usage.md, "What your program owns".
- **Each dependent changes at its next bump.** cocuyo, stompy and connect-zig ask the package
  for modules by name. Each then asks for `colibri` alone, and its sources name
  `colibri.<module>`. A program of theirs in cleartext defines `ch_assert_fail`.
- **Run on x86-64 Linux, in a container with no IPv6:** `zig build test`, 4,276 of 4,278
  tests, with 1 skipped and 1 failed; `zig build examples`, 10 of 11; `tools/doc_snippets.sh`;
  and `tools/consumer_check.sh`, whose fetch of stdx Zig's cache stood in for, since the
  container reaches no GitHub. The one test and the one example that fail open an IPv6
  socket, as in step 72. The first build of `bench/router/` passed. Its timed rounds need
  `/usr/bin/time`, which the container lacks.
- **Not run:** the checks of `tools/ci.sh` that need Docker or a network peer, which CI runs.
