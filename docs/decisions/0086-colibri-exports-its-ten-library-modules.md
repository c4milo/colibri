# Decision 86: colibri exports its ten library modules by name, so a project that depends on it builds against them

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-25, relayed by the cocuyo session.
- `build/modules.zig` creates `core`, `wire`, `http`, `tls`, `crypto`, `hpack`, `qpack`,
  `quic`, `h2` and `h3` with `b.addModule`. Each carries the imports design §3 gives it, and a
  dependent reaches it with `dependency.module("quic")`.
- The simulator, the corpus and the test-only endpoints stay unexported, because they are not
  the library. The tools, pepegrillo, Rotor and the `qifs` vectors are still requested only
  when colibri is the root build.
- A dependent drives its own connections on its own threads, so the library must keep no
  process-wide mutable state. An audit of the ten modules on this date found none in library
  code: every container-level `var` is test-only except `stream_provider.none_context`, a byte
  nothing writes, whose address is the context of the provider that sends nothing.

The alternative refused: a dependent that imports colibri's source files by path. It would
bypass the module graph that keeps `quic` from importing any HTTP module (decision 5).

`h11` joined them on 2026-09-25, when design §8 step 15a created it, so eleven are exported.
`tls` joined them on 2026-09-26, when design §8 step 16b created it, so twelve are.
