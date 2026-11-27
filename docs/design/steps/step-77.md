# Design §8 step 77: colibri takes chapulin through stdx, 2026-11-25

[Design §8, the build plan](../../design.md#8-build-plan)

([decision 174](../../decisions/0174-colibri-takes-chapulin-through-stdx-as.md)). No public name changes. stdx is pinned at `5de7d89f`,
whose `stdx.crypto` is chapulin's one module at `f29c066a`, and colibri's `build.zig.zon` names no
chapulin.
- `build/modules_stdx.zig` asks stdx for `.crypto = true`, and `tls` and `dnssec` read
  `@import("stdx").crypto`. `build/modules_chapulin.zig` is gone.
- `build/modules_keylog.zig` makes `qlog`, `quic`, `h3`, `h11` and `tls` again over a second
  stdx with `crypto_keylog`, for the QUIC endpoints and `tls_keylog`'s tests.
- stdx's root references `stdx.crypto` when its option `crypto` is on, so every program keeps
  chapulin's `ch_assert_fail` beside the objects that stdx links. Before stdx held that line,
  the test binaries of `qlog`, `h11` and `quic` failed to link on an undefined
  `ch_assert_fail`, and colibri's review of `ad15515e` reported it to stdx.
- README.md, docs/usage.md and the consumers pass stdx `.crypto = true`.
- Mutation, CAUGHT: the library's request naming `crypto_keylog = false` gives a dependent a
  second stdx, which `tools/consumer_check.sh` refuses. stdx's readme-check holds its own
  reference to `stdx.crypto`.
- Run on x86-64 Linux: `zig build test`, 4,278 of 4,280, with 1 skipped and the IPv6 test
  failed; `zig build examples`, the IPv6 example failed; `tools/doc_snippets.sh`; and
  `tools/consumer_check.sh`, with the packages from Zig's cache.
