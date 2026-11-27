# Design §8 step 41: body readers and writers, proposed 2026-11-05

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 153](../../decisions/0153-a-client-that-runs-on-a.md) ruling 6. It depends on step 39.
- **The rules.** A request body's `std.Io.Writer` and a response body's `std.Io.Reader` over
  the pool. Each fails with `WriteFailed` or `ReadFailed` to mean "not yet" and keeps its state,
  as stdx's codec adapters do (stdx decision 56).
- **The checks.** stdx's gzip writer and JSON value encoder stream a request body through the
  writer, and stdx's decoders read a response body through the reader, over h11, h2 and h3.
  Each retry goes on from the byte it stopped at.
