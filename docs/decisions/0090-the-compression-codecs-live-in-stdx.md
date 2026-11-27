# Decision 90: The compression codecs live in stdx, a repository of their own, and colibri imports it

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-25. It amends entry 89, which put the decoder in `src/deflate/`, and
entry 35, under which the library imports no package.
- stdx (https://github.com/c4milo/stdx) holds compression codecs, each with an encoder and a
  decoder: deflate with its zlib and gzip wrappers, zstd and brotli. Other projects want them
  without HTTP, which is entry 3's condition for moving code into a repository of its own.
- colibri takes stdx as a Zig package pinned by hash. It is the first package the library
  imports, and h11 imports stdx's gzip and deflate decoders for the transfer codings of entry
  88. The package joins CLAUDE.md's list of ruled dependencies in the commit that adds it.
- stdx keeps colibri's rules: no I/O, no heap, no clock, bounded work per call, a check cited
  to its RFC, and mutations. It never depends on colibri.
- Design §8 step 14 moves to stdx (https://github.com/c4milo/stdx/issues/1), with zlib and
  Wuffs as its oracles and baselines.

The alternatives refused:
- The decoder inside colibri, as entry 89 had it. Another project would have to take an HTTP
  library to get a codec, and encoders and more codecs are coming.
- stdx holding colibri's `core` as well. Every colibri module would change its imports before
  any codec work, and stdx would carry limits that belong to HTTP.
