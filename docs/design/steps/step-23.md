# Design §8 step 23: colibri's own names for HTTP

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 126](../../decisions/0126-the-server-and-client-apis-name.md) has `server` and `client` name each concept once, the same
for h11, h2 and h3, with the word programmers know. The protocol modules keep each RFC's words.
Every rename breaks a dependent's build in 0.9.0.
- **Names of `server`.** New: `Protocols`, `Timeouts`, `Timeout`, `StreamBytes`, `Header`,
  `Headers`, `RequestId`, `RequestBody`, `ResponseBody`, `Finished`, `Result` and
  `ReceiveResult`. They replace `Versions`, `Deadlines`, `Deadline`, `StreamOctets`, `Field`,
  `Fields`, `Id`, `Body`, `Content`, `Done`, `Cancelled` and `Received`, and `Security` leaves.
  The events `done` and `cancelled` become `finished`. `Endpoint.set_deadlines` becomes
  `set_timeouts`, and `accept` takes a `tls` bool.
- **Names of `client`.** New: `ConnectionPool`, `ConnectionPoolOf`, `Protocols`, `Header`,
  `RequestId`, `WantedHeader`, `Result`, `Destination`, `HttpsRecord`, `StreamBytes` and
  `ReceiveResult`. They replace `Pool`, `PoolOf`, `Versions`, `Field`, `Id`, `Wanted`,
  `Outcome`, `Values`, `Https`, `StreamOctets` and `Received`, and `Options` leaves.
  `set_values` becomes `set_destination`, and `memory_bytes` takes the `Config`.
- **Fields.** `fields` becomes `headers`, `octets` becomes `bytes`, `deadlines` becomes
  `timeouts`, `versions` becomes `protocols`, `outcome` becomes `result`, and the client
  request's `content` becomes `body`.
- **Sub-steps.**
  - 23.1: decision 126, the names in CLAUDE.md, and this text.
  - 23.2: headers, bodies, bytes, `RequestId` and `ReceiveResult`, which change names alone.
  - 23.3: `Protocols` and `Timeouts`.
  - 23.4: the client's `ConnectionPool`, `Destination`, `HttpsRecord`, `WantedHeader` and
    `Result`.
  - 23.5: `Options` folds into `Config`.
  - 23.6: `accept` takes a `tls` bool.
  - 23.7: the server's `done` and `cancelled` merge into one `finished` event with a `Result`.
  - 23.8: docs/usage.md, examples/README.md and the notes of 0.9.0.
- **Check.** `tools/ci.sh` on the exact tree. Every census keeps its counts and its wire
  hashes. A trace hash moves only where a label's words changed, and the commit says which.
- **Waits.** `CpuFeatures` (ruling 16) waits for its design, which needs stdx.
- **Two rulings of 2026-10-24.** `memory_bytes` takes the pool's two counts,
  `.{ .tcp_connections = n }`, because a `Config` with TLS values cannot size a static array.
  `accept` runs TLS by default, and a cleartext socket passes `.{ .tls = false }`.
- **The end of a request.** A connection still reports `done` and `cancelled` to its endpoint,
  in the internal `ConnectionEvent`, and the endpoint turns each into `finished`. The tests of
  the connections stand as they were. The endpoint check records a `finished` under its old kind.
- **What ran.** `zig build test` on each sub-step: 183 of 183 steps, 3190 of 3190 tests. Every
  census keeps its counts and its pinned hashes, the endpoint check's event hash included, so the
  renames and the merge change no event and no byte on the wire. The memory table keeps its
  sizes under the new names. Mutations of 23.7: 2 of 2 **CAUGHT**.
- **Owed before the push.** `tools/ci.sh` on the exact tree.
