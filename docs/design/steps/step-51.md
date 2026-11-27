# Design §8 step 51: the constructors take std's name `init`, ruled 2026-11-13

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 158](../../decisions/0158-colibris-public-api-follows-tigerstyle-first.md) as amended on 2026-11-13.
- **Why.** colibri named a value's constructor `of`, and std names it `init`. The owner asked
  whether `of` is how Zig names it, and ruled that v0.17.0, which breaks names already,
  renames each one.
- **The rename.** Each function named `of` that returns its own type is `init`, public and
  private. The names a program reaches change from `of` to `init`:
  - `quic.PeerAddress.init`, which a program names as `client.Address.init` and
    `server.Address.init`.
  - `quic.StreamId.init`.
  - `quic.transport_parameters.ConnectionId.init` and `VersionInformation.init`.
  - `crypto.suite.RetryConnectionIds.init`.
  - `server.Headers.init`.
- **What stays.** A function named `of` that returns another thing: `reason.of`, the lookups
  `Requests.of` and `Tuples.of`, and the casts from `*anyopaque`. No type gains a `deinit`.
- **Checks.** No names test listed `of`, so an `of` added back beside `init` passed. Six types
  gained a names test: `quic.PeerAddress`, `quic.StreamId`, `ConnectionId` and
  `VersionInformation` of `quic.transport_parameters`, `crypto.suite.RetryConnectionIds` and
  `server.Headers`. The compiler finds each call that a dependent did not rename, and
  `tools/consumer_check.sh` builds both dependents.
- **Mutations, 6 of 6 CAUGHT:** `pub const of = init;` beside each of the six constructors.
- **Runs.** The rename landed with sub-step 50e's part 1, so the runs of that part hold for it.
  `tools/consumer_check.sh` built both dependents with the new names.
- **The `owes_` checks, 2026-11-15.** The owner ruled on 2026-11-11 that `owes_` is a poor name
  for a check, and that v0.17.0 renames the seven public ones
  ([#134](https://github.com/c4milo/colibri/issues/134)): `quic.Space.ack_due`,
  `quic.Connection.close_due`, `h2.Connection.window_update_due`,
  `client.Connection.should_send`, `qpack.Decoder.instructions_due`,
  `qpack.decoder_stream.instructions_due`, and the tag `write_instructions_first` of
  `qpack.Decoder.Outcome` and `Abandoned`. The verbs `owe` and the `_owed` suffixes stay.
  - `quic.Space` and the namespace `qpack.decoder_stream` gained a names test, and a test lists
    the tags of `Outcome` and `Abandoned`.
  - **Mutations, 8 of 8 CAUGHT:** each old name added back beside its new one, and the old tag
    added to each enum.
