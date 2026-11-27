# Design §8 step 30: constants by who sets them

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 137](../../decisions/0137-each-library-module-groups-its-constants.md) sorts each library module's constants into `protocol`,
`limits`, `policy` and one file for each algorithm's parameters, and keeps units in `constants.zig`.
It comes before step 29b.
- Each module's `constants.zig` exports its files as namespaces, and every name that moves
  takes its namespace: `quic.constants.frame_ack` becomes `quic.constants.protocol.frame_ack`.
- **Check.** Each `constants_limits.zig` holds a test that pins every limit's value. Each
  module's tests, `zig build test` and `tools/ci.sh` pass with no other change, and `zig build
  bench-memory` prints the same table.
- **30, 2026-10-30.** Of the 15 library modules' 544 constants, 536 moved into 35 files: 15 of
  `protocol`, 12 of `limits`, 7 of `policy` and quic's `recovery`, which nests `cubic` and
  `hystart`. Each `constants.zig` keeps its 8 units and one import for each file.
  - The group of the values an RFC fixes is `protocol`, not `wire`, because `wire` is a module
    the others import.
  - Twelve `constants_limits.zig` files pin 143 limits. The `magic-numbers` rule skips the four
    new basenames as it skips `constants.zig`.
  - Earlier decisions and design records keep the names that held when they were written.
    docs/usage.md and the examples use the new names.
  - Mutations: `quic`'s `ack_ranges_max` at 31 and `server`'s `route_methods_max` at 9, each
    CAUGHT by its pinning test.
  - `zig build test`, `zig build examples`, `tools/doc_snippets.sh` and
    `tools/consumer_check.sh` pass.
