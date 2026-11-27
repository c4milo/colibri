# Decision 77: Lean 4 proves the pure arithmetic under colibri's codecs, and vector files tie each proved definition to the Zig function it mirrors

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24, on issue [#52](https://github.com/c4milo/colibri/issues/52): the
Lean toolchain is a dependency, pinned in `spec/lean/lean-toolchain`, built with lake through
pepegrillo's `lean` tool, with no Mathlib. Entry 67 placed the project in `spec/lean/`.

TLA+ checks the interleavings of a design; Lean proves that a function is right for every
input. The first proofs are QPACK's:
- RFC 9204 §4.5.1.1's Required Insert Count. The decoder rebuilds the exact count whenever its
  own insert count is at most `MaxEntries` behind it and less than `MaxEntries` ahead. §2.1.1
  is what keeps a decoder in that window: an encoder evicts an entry only after the decoder
  acknowledges it, so it cannot fall further behind.
- §3.2.5, §3.2.6 and §4.5.1.2's index arithmetic: relative and post-Base indices name distinct
  entries on either side of the Base, and every Base the encoder writes comes back.

A proof covers the Lean definition, not the Zig code. So each definition follows its Zig
function line by line, and `spec/lean/Vectors.lean` writes the definition's outputs over every
input in a range to a file beside the Zig function. A Zig unit test reads that file and
requires the Zig function to give the same outputs, so `zig build test` runs it with no Lean
installed. `zig build lean` builds the proofs and checks that the committed files are still what
the proved definitions give, and `zig build lean -- write` rewrites them. `tools/ci.sh` runs
`zig build lean` where lake is installed, as it runs TLC where Java is.

The alternatives refused:
- Proofs with no tie to the code. They would prove a function nothing runs.
- Generating the Zig function from Lean. It would put a second implementation in the build,
  and the Zig code would stop being the one people read and review.
- Proving the Zig code itself. There is no verifier for Zig.
