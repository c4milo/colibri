# Decision 75: The QPACK vectors are a lazy Zig package, fetched once and pinned by hash, and a tool decodes them in `zig build test`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24 for design §8 step 11.

`qpackers/qifs` holds six inputs and 529 files six encoders made of them, 119 MB unpacked.
`build.zig.zon` names its archive at commit `da52cd9` with `.lazy = true`, as it names
pepegrillo and Rotor. The first build on a machine downloads 20 MB and caches it, and a project
that depends on colibri never fetches it. `tools/qpack_vectors.zig` decodes every encoded file
with colibri's decoder and compares the sections with the inputs, and `zig build test` runs it,
as it runs the HPACK corpus of entry 38.

The files follow the QUIC working group's "QPACK Offline Interop" format, which differs from
RFC 9204 in one place: the table starts at its maximum capacity, where RFC 9204 §3.2.2 starts
it at zero, so the tool sets it. The corpus disagrees with itself in one place, and entry 25
makes the RFC the authority: `examples.out.220.100.1` encodes RFC 9204 Appendix B, while the
input beside it lists an earlier draft's examples. The tool skips that file and says so, and
`src/qpack/decoder_test.zig` checks Appendix B.

The alternatives refused:
- Vendoring the corpus compressed, 1.7 MB as `tar.xz`. It works offline, but it puts a binary
  file in the repository and needs the tool to unpack it.
- Vendoring the files as published, as entry 38 does for HPACK. That is 119 MB of files that
  have not changed since 2021.
- A script that fetches the corpus on demand. Entry 38 refused this for HPACK because it takes
  the check out of `zig build test`, and a package keeps it in.
