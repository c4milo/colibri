# Design §8 step 74: colibri takes stdx's one module, 2026-11-25

[Design §8, the build plan](../../design.md#8-build-plan)

([decision 171](../../decisions/0171-colibri-takes-stdxs-one-module-stdx.md)). No public name changes. stdx is pinned at `b643d58`,
whose package exports `stdx` alone.
- `build/modules.zig` and the test roots give each module that read stdx the one import
  `stdx`. Each source writes `@import("stdx").compress.gzip`, `.compress.zlib`,
  `.compress.zstd`, `.compress.brotli`, `.encoding.json`, `.codec` or `.platform`.
- The examples, `tools/consumer/` and `tools/consumer_hosted/` import `stdx` and write
  `@import("stdx").platform`. README.md and docs/usage.md show the same lines.
- No check changes, so no mutation ran: a module that names a retired module does not
  compile.
- Run on x86-64 Linux: `zig build test`, 4,277 of 4,279, with 1 skipped and the IPv6 test
  failed; `zig build examples`, the IPv6 example failed; `tools/doc_snippets.sh`; and
  `tools/consumer_check.sh`, with stdx from Zig's cache.
