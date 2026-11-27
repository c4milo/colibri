# Decision 170: The package exports one module, `colibri`, whose root names each library module

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-25, who asked that a program import one module. It amends decisions
86, 96, 101 and 156 ruling 14.
- `colibri`'s root names the sixteen other library modules: `core`, `wire`, `http`,
  `tls_provider`, `tls`, `dnssec`, `crypto`, `qlog`, `hpack`, `qpack`, `quic`, `h2`, `h3`,
  `h11`, `server` and `client`. A program writes `colibri.h2.Connection`, or binds a name of
  its own: `const h2 = colibri.h2;`. Each name is the module itself, so a type has one
  identity by either path.
- The package exports `colibri` and no other module. A dependent's build that asks for
  `dependency.module("h2")` stops, and `tools/consumer_check.sh` requires that.
- Each library module is still a module of colibri's own build, with the imports design §3
  gives it. `quic` still cannot name an HTTP module (decision 5). The simulator and
  `src/testing/` still import each module by its name, and `zig build test-<module>` still
  runs one module's tests alone.
- `colibri` names nothing of stdx. A program depends on stdx itself for `platform`, at the
  commit colibri pins and with colibri's options. The owner kept decision 97's amendment of
  2026-09-30 on this date. The package no longer exports stdx's `codec`, `gzip`, `zlib`,
  `zstd` and `brotli` either, which decision 101 exported. A program that codes content
  itself takes them from the same stdx.
- `colibri` imports `tls`, which carries chapulin's object files. So every program that
  imports `colibri` links chapulin and defines `ch_assert_fail`, a program in cleartext
  too. Before this decision, a program that imported `h11` or `h2` alone linked no chapulin
  (decision 97). The owner chose `colibri` alone with that cost stated.
- The module adds no code to a program that imported `colibri` before. `colibri` already
  imported `server`, `client` and `tls`, whose imports reach every module but `dnssec`, and
  `dnssec` reads the chapulin object that `tls` links.
- Each program of `examples/` imports `colibri` alone, as a dependent does, and so do
  `tools/consumer/`, `tools/consumer_hosted/` and the router's probes of `bench/router/`.
- The alternatives refused, both by the owner on this date:
  - `colibri.platform`, stdx's module under colibri's name, so that one import serves a
    whole program. It reverses decision 97's amendment of 2026-09-30.
  - The seventeen names kept beside `colibri`. No dependent's build would break, and a
    program in cleartext would still link no chapulin.
