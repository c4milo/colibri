# Design §8 step 36: JSON in the server, proposed 2026-11-04

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 151](../../decisions/0151-server-encodes-and-decodes-json-through.md). It depends on a layer stdx's `json` does not have yet,
which maps a Zig value to JSON and back: [stdx#22](https://github.com/c4milo/stdx/issues/22).
colibri builds no such layer of its own.
- **The public names,** each listed beside its root before the code (decision 115):
  `ResponseWriter.json(value)`, a route option `.json_body = T`, which hands the route a `T`,
  and the decoder's limits in `server.constants.limits`.
- **The checks.** Each value type the encoder takes round-trips through stdx's decoder. A body
  that is not JSON, is not `T`, or passes a limit answers 400. An example route shows both.
