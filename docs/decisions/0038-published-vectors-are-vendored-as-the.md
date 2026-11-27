# Decision 38: Published vectors are vendored as the files their authors published, and a tool reads them

[All decisions](../decisions.md) · Section: [The simulator](../decisions.md#the-simulator)

Ruled by the owner on 2026-09-16 for `http2jp/hpack-test-case`, 478 JSON stories of 66 MB, about 3
MB packed, at `src/hpack/hpack-test-case/` with its commit and license in `COLIBRI.md`. The library
is zero heap (decision 35) and `std.json` allocates, so the module's own tests cannot read the
corpus; `tools/hpack_vectors.zig` reads it, drives the module, and `zig build test` runs the tool.
The check stays in-process, as design §9 says the HPACK vectors are, and nothing is generated from
the corpus.

Two alternatives lost. A fetch-on-demand script keeps the repository small but takes the check
out of `zig build test`, leaving it to be run by hand like h2spec. A converted binary form
adds a colibri format to version, a regenerate-and-check pair, and a copy of the corpus that
is not what its authors published. Cost: a clone carries the corpus.
