# Design §8 step 75: colibri asks chapulin once, 2026-11-25

[Design §8, the build plan](../../design.md#8-build-plan)

([decision 172](../../decisions/0172-colibri-asks-chapulin-once-and-chapulins.md)). No public name changes. chapulin is pinned at
`bda41cf6`, whose build takes `TRANSPORT=nonblocking`.
- `build/modules_chapulin.zig` asks the package once for each key log setting, and `tls`,
  `dnssec` and the test-only modules import its module `chapulin`. Each source writes
  `@import("chapulin").tcp` or `@import("chapulin").quic`.
- The test hooks of `tls`, `server`, `client`, `colibri`, `dnssec`, the simulator, `src/testing/`
  and `bench/` are gone, and so is each example's. `tools/consumer/main.zig` declares
  `chapulinAssertFail`, which README.md and docs/usage.md show.
- Zig runs a file's comptime block only when something references the file. So the roots of
  `colibri`, `tls` and `dnssec`, and the two route checks, reference what links chapulin, and
  chapulin's export stays in every program that links its objects.
- `tools/consumer_check.sh` requires `without_assert.zig`, which declares no hook, to link and
  to define `ch_assert_fail`.
- Mutations, each CAUGHT: without `colibri`'s references, `zig build example-h11_exchange`
  fails to link; without `tls`'s, `zig build router-hidden-check` fails; without the route
  check's, the same step fails.
- chapulin's bump makes `tls.quic.Client` and `tls.quic.Server` 1,536 bytes smaller, and
  docs/performance.md's memory table holds the new sizes.
- Run on x86-64 Linux: `zig build test`, 4,277 of 4,279, with 1 skipped and the IPv6 test
  failed; `zig build examples`, the IPv6 example failed; `tools/doc_snippets.sh`; and
  `tools/consumer_check.sh`, with the packages from Zig's cache.
