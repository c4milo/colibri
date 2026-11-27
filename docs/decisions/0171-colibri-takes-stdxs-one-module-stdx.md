# Decision 171: colibri takes stdx's one module, `stdx`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-25, for v0.20.0. stdx at `b643d58` exports one module, `stdx`, and
retires `codec`, `gzip`, `zlib`, `zstd`, `brotli`, `json` and `platform` as module names (stdx's
decision 6 as amended that day).
- colibri pins stdx at `b643d58`. Each module that read a module of stdx imports `stdx`
  alone, and writes `@import("stdx").compress.gzip`, `.encoding.json`, `.codec` and
  `.platform`.
- A program depends on stdx at colibri's pin, with colibri's options, and imports `stdx`. It
  writes `@import("stdx").platform` to ask its CPU. Decision 97's rule holds: one stdx
  gives one `platform.Cpu`, the type `tls.Cpu` holds.
- No name of colibri changes. A dependent's build that asked stdx for `platform` stops at
  the bump, as stdx's own change says.
- The alternative refused: v0.20.0 on the old stdx, and the move in the next release. The
  owner chose one release for every break of this week.
