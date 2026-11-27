# Design §8 step 22: the client's connection pool

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 125](../../decisions/0125-clientpool-holds-several-tcp-connections-to.md) replaces `client.Channel` with `client.Pool`, which holds
up to `tcp_connections` TCP connections and one QUIC connection to one origin
([#108](https://github.com/c4milo/colibri/issues/108)). The program sets the count at run time, in
memory that it supplies (decision 35 as amended). A program that sends 16 requests at once over h11
needs 16 connections, because h11 carries one exchange at a time on a connection.
- **Names.** `client.Pool`, `client.PoolOf`, `client.Options`, `client.ConnectionHandle` and
  `client.StreamOctets`; `client.Channel` and `client.ChannelOf` leave the root.
  `Pool.memory_alignment`, `Pool.memory_bytes`, `Pool.receive_events_without_input_max` and
  `Pool.set_values` are new, and `send` is a new event. `client.constants` gains the maximum of
  each count and `transport_events_max`, and loses `receive_events_without_input_max`.
- **Sub-steps.**
  - 22.1: decision 125, this text, and the amendment of decision 35.
  - 22.2: `Channel` becomes `Pool` and `ChannelOf` becomes `PoolOf`, in the library, the
    examples, the guide and every caller. No behavior changes, and every census stays
    byte-identical.
  - 22.3: the TCP connection, the links and the entries move into the memory that `init` takes,
    with `Options` and `memory_bytes`, and one TCP connection. Every census stays
    byte-identical, and the memory table gains a row for one counted connection.
  - 22.4: events and calls name a `ConnectionHandle`, the `send` event comes in, and
    `Input.stream` carries the handle. Still one TCP connection.
  - 22.5: spec/tla/client_exchanges gains a set of TCP connections, the rule that opens one on
    demand, and the resend to any other connection. The model changes before the code.
  - 22.6: several TCP connections, decision 125 rulings 4 to 7.
  - 22.6b: the pool trace run, whose pool holds two or three TCP connections over h11, and
    `tools/pool_trace.sh`, which has TLC check its logs against the model.
  - 22.7: `set_values`.
  - 22.8: the callers: the simulator's runs, the test-only client, the examples, the consumer
    and docs/usage.md. The test-only client gains `--tcp-connections <n>`, each pool's
    `tcp_connections`, beside `--connections <n>`, which counts its pools.
  - 22.9: the step's entry, the memory table and `tools/ci.sh`.
- **Check:** a test for each rule of decision 125 with a mutation it catches. The pool trace
  run holds 2 and 3 TCP connections, and TLC checks its logs. The client trace run speaks h2,
  which opens one connection (RFC 9113 §9.1), so its seeds keep one. Each configuration
  of the model states its state count, and the TLA+ section of CI's checks job grows by at most
  5 minutes. `tools/h11_interop.sh` runs 8 requests at once over 8 connections against Go's
  server: 8 is the most a plan of the test-only client holds (`requests_max`). `zig build
  examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh` pass.
- **2026-10-20, 22.1 to 22.8, on an Apple M1 Pro.** The commits, in order:
  - **145012aa and fe75587a, 22.1.** Decision 125, this text, the amendment of decision 35, and
    non-negotiable 4 of CLAUDE.md, which the owner approved.
  - **1041761a, 22.2.** The rename. The memory table, the client, TCP and deadline trace logs
    and six census lines stay byte-identical.
  - **011ac431, 22.3.** `Options`, `memory_bytes` and `receive_events_without_input_max(options)`.
    Every census and trace log stays byte-identical. Mutations, 5 of 5 **CAUGHT**.
  - **492eec14, 22.4.** `ConnectionHandle` and the `send` event. Mutations, 13 of 13 **CAUGHT**.
  - **40d2a7cf, 22.5.** The model gains `TcpSlots`, `TcpCapacity` and `TcpDrops`. With
    `TcpDrops`, an h11 connection keeps a cancelled exchange's room until it drops the
    response. Each configuration of one slot keeps its state count. `ClientExchanges_pool`
    holds in 261,547 distinct states and 54 s, and `ClientExchanges_pool_first` in 1,198,311
    and 14 s. The mutants `take_beyond_room` and `retry_within_wait` are violated.
  - **743f014b, 22.6.** Several TCP connections. Mutations, 10 of 10 **CAUGHT** by
    test-client.
  - **9ccc8eb6, 22.6b.** The pool trace run. Its census over 256 seeds: 784 requests, 512
    responses, 29 refused, 118 closed, 125 cancelled, 78 moves, 831 connections, 229 seeds that
    opened more than one slot, and 5,828 states. TLC finds each of 64 seeds' logs a behavior of
    the model, in 147 s. Mutations, 4 **CAUGHT** by the run. 2 are **NOT CAUGHT** by it, and
    test-client catches each.
  - **fa8e57f8, 22.7.** `set_values`. Mutations, 7 of 7 **CAUGHT** by test-client.
  - **b2a3081d and 3451fdf1, 22.8.** The test-only client's `--tcp-connections`, and the
    example `client_pool.zig`. `tools/h11_interop.sh go` sends 8 GETs through one pool of 8 TCP
    connections, in cleartext and over TLS, and the pool opens 8. Mutations, 2 of 2 **CAUGHT**
    by it. Breaks of the example, 9 of 10 **CAUGHT**.
- **What the checks found.**
  - The pool trace run found an exchange that waited beside an idle h11 connection forever.
    The connection had dropped a cancelled exchange's response, which frees room and reports no
    event. `plan` now hands waiting exchanges over (743f014b).
  - The same run found that the model freed a cancelled exchange's room at once. That is true
    of h2 and h3, which reset the stream, and not of h11, which reads the response to its end.
    `TcpDrops` models h11 (40d2a7cf).
  - A test of `set_values` found that a connection to an old address that failed after the
    call moved the index of the new addresses. A flag of each link now stops it (fa8e57f8).
- **The review.** One agent built, read and tried to break the step. It confirmed these
  defects, and the commits after 1ef67695 fix them:
  - bbb175e8: with more exchanges than the 16 slots of a connection, an assertion in
    `on_connected` stopped the program. The hand-over now asks `takes`: room, and a free slot.
  - 889dee28: an exchange that moved to a blocked connection gave it a debt and no `send`.
  - b68081f2: two failures at one address skipped the next address, and an `open` owed across
    `set_values` kept the old address. `Link.replaced` goes.
  - d2fc5e86: `init` took memory longer than its options need, and the docs of the event bound
    and of a second `init` said too little.
  - 777c7e53: the pool trace run's safety check left out a response that a connection drops.
  - Mutations: 9 **CAUGHT**. 2 are **NOT CAUGHT**: a hand-over by room alone, equivalent while
    the origin's connections share one protocol, and the old length check, since no test passes
    longer memory.
  - One finding was no defect: `receive_events_without_input_max` holds for the calls its doc
    names. A `transport_closed` after a start is new I/O, and the doc now says so.
- **The replay and the rename.**
  - The branch moved onto main's 5f4436a2, the chapulin 50d7d17b bump. 3ee2662b gives the new
    sizes, since a TCP connection holds 56 bytes fewer. After a KeyUpdate alone, a connection
    owes no bytes: the provider writes the answer in front of the next record of data.
  - The branch then moved onto d0d4e4b5, which makes the aioquic environment whole again. The
    one conflict was in CLAUDE.md, and `tools/pool_interop.sh` now calls `tools/python_venv.sh`.
  - 5d574f93: counts and limits say requests, at the owner's ruling of 2026-10-20 (decision
    125). The shorter census labels move three trace hashes: deadline 0xf90d85a5, h3-deadline
    0x8742d7c9 and endpoint 0x29a4f339. Every count and every wire hash is unchanged.
- **The memory table.** A pool at the default counts holds 705,952 bytes and its memory
  306,336: 1,012,288, 72 more than `client.Channel`. Each TCP connection more adds 305,696.
- **Owed before the push.** `tools/ci.sh` on the exact tree, whose TLA+ section now runs the
  two pool configurations, the two mutants and `tools/pool_trace.sh`: about 4 minutes more on
  this laptop.

**An IPv6 scope id, 2026-10-31** ([#107](https://github.com/c4milo/colibri/issues/107)).
`quic.PeerAddress`, which `client.Address` names, gains `scope_id`, the interface a link-local
IPv6 address is reached through. The pool keeps it in `Open.to`, and `same_host` compares it,
so the same bytes through two interfaces are two paths (RFC 9000 §9). The test-only UDP
endpoints carry it to and from Rotor's socket address.
- 1 mutation **CAUGHT**: `same_host` without the scope id. A test of the pool's `Open.to` checks
  that the id and the pool's port both arrive.
