# Decision 26: The golden corpus is exact bytes with a manifest

[All decisions](../decisions.md) · Section: [Correctness](../decisions.md#correctness)

, in the layout stompy's `src/golden/` uses: one directory per format, one file per case, and a
manifest line per file naming its length, its checksum, its expected verdict and the parameters it
was built from. Valid and invalid cases both, because a parser that accepts everything passes a
valid-only corpus. `zig build golden` regenerates and refuses a directory carrying a `FROZEN`
marker.
