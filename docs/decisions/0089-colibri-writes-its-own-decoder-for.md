# Decision 89: colibri writes its own decoder for the `gzip` and `deflate` codings, in `src/deflate/`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-25, for https://github.com/c4milo/colibri/issues/60.
- The module holds RFC 1951's inflate, the zlib wrapper of RFC 1950 with its Adler-32 check,
  and the gzip wrapper of RFC 1952 with its CRC-32 check. It imports `core` alone, and `h11`
  imports it. The three RFCs are in `docs/rfcs/compression/`.
- It decodes input that arrives in pieces. Each call takes the bytes the caller has, writes
  what it can into the caller's output, and says whether it needs more input or more room. It
  keeps its state and its window of 32,768 bytes in storage the caller owns, because a
  deflate distance reaches that far back (RFC 1951 §2).
- zlib and Wuffs may serve as test oracles and benchmark baselines in `tools/` and `bench/`.
  Neither is linked into the library.

A survey of the existing decoders is in the issue. Each alternative refused:
- Zig's `std.compress.flate`. It cannot resume when its input runs out mid-stream, and it
  never compares the checksums it reads, so colibri would hold the whole coded body and check
  the checksums itself.
- Wuffs, compiled into the library. It fits the model best and decodes at 1.5 to 1.9 times
  zlib's speed in its own benchmark. But it is C, every consumer would compile it, and the
  release colibri would need is an alpha.
- zlib or zlib-ng, fed from a fixed pool. Both are mature and fuzzed, but they are C, and zlib
  has four CVEs in its decoder or its checksums.
- zlib-rs or miniz_oxide. Both are Rust, so every consumer would need a Rust toolchain, and
  miniz_oxide has no gzip.
- libdeflate, tinf and puff. Each needs the whole coded body at once.

Entry 90 moves this decoder, and the check that proves it, to stdx.
