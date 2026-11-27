# Design §8 step 58: no copies of the server's events, planned 2026-11-17

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 165](../../decisions/0165-the-servers-receive-writes-its-result.md), for [#133](https://github.com/c4milo/colibri/issues/133).
- **The cost.** `server.Event` holds 160 bytes, and `server.ReceiveResult` 192. A request on
  h11-many takes 8 calls of the engine's `receive`, and 6 of them report nothing. Each layer of
  the engine returns the result by value, and a `server.Router` takes the event by value. The
  laptop profile of 2026-11-14 put about 640 of the 1,710 instructions a request of
  `State.receive` in the lines that build and return the result. Steps 56 and 57 did not
  change that cost.
- **The price, 2026-11-17.** callgrind with `--dump-instr=yes` on `db8817d6` counted each
  instruction of h11-many. The loads and stores of 16 bytes took 537 of 14,402 instructions a
  request. The copies of 8 bytes come on top, so this is a lower bound.
  - `State.receive`, with what LLVM inlined into it: 189 of 1,903.
  - The connection's `receive`: 138 of 594. Each of its 4.9 calls a request copies its whole
    result, about 220 bytes, also when it reports nothing. Decision 121 took `Connection`
    out of the root, so this copy is internal.
  - The test server's handler, which copies each event as a program does: 88.
  - `send_first`: 44, and `engine_state_events.pass`: 16.
  - The native counters of steps 56 and 57 give the same calls a request on io_uring as on
    epoll, so the price a call holds on the judge. The laptop's callgrind decides nothing
    (step 57).
- **58a, internal.** The engine's layers build each event once, in a field that the engine
  holds, and return whether they wrote it. `Engine.receive` copies the event into its result
  once. No public name or signature changes, so it can land before v0.19.0.
- **58a, done 2026-11-17.** The engine builds each event once.
  - `State` holds one `event`. `take_stream` returns how much it consumed and whether it wrote
    the event, and `next_event`, each kind of slot's `poll`, `send_first`, `connection_event`,
    `transport_event`, `engine_state_events.pass` and `writable_of` write `state.event` and
    return a `bool`. `State.receive` copies the event into its result once, or stores null.
  - `pass` and `note_read` take their argument by `*const`, because each is over 16 bytes.
  - The connection's `receive` observes the deadlines in a `defer`, and an `errdefer` keeps a
    failed read from being observed, as before. Its result is written in place, not copied there
    from a local.
  - The same profile as the price above: the loads and stores of 16 bytes fell from 537 to 297
    a request on h11-many, and from 384 to 290 on h2-many.
  - What 58a leaves: the null result stored whole and the copy into the public result in
    `State.receive`, about 51 a request on h11-many, which 58b removes. The connection's
    `receive` keeps about 50, its null result and the request's event copied out of the read,
    because its result is still a value; its tests call it about 60 times.
  - **Mutations, 2 of 3 CAUGHT,** against the tests of `server`, `sim`, `sim-run`, `colibri`
    and `testing`:
    - CAUGHT: a passed request keeps the connection's own handle, and an event that
      `take_stream` wrote is not reported. Under the second, the `colibri` tests wait forever,
      and the run was stopped.
    - NOT CAUGHT: a read that fails is observed too. A failed connection's bytes reach its
      output only in `send`, so the observation starts no clock that a deadline reads. The
      `errdefer` stays, so the connection behaves as before.
  - **Checked, 2026-11-17 and 2026-11-18:**
    - The judge measured `8fac6e7b` against `3d2a738d` in two jobs, with the h11 inputs
      ([run 44204557947](https://github.com/c4milo/colibri/actions/runs/44204557947)). In user
      instructions h11-many won in both jobs, 0.9540 and 0.9585, h11-one 0.9597 and 0.9589, and
      h11-tls-many 0.9771 and 0.9701. h2-many won in both, 0.9849 and 0.9844, h2-routes-many
      0.9870 and 0.9874, h2-routes-post-many 0.9886 and 0.9894, and h2-one 0.9919 and 0.9915.
      No input lost.
    - Replayed onto `d767731f`, which added the input h2-k8s-routes-many, the judge measured
      the same change against `d767731f`
      ([run 44242526127](https://github.com/c4milo/colibri/actions/runs/44242526127)). In user
      instructions h11-many won in both jobs, 0.9518 and 0.9437, and h11-one 0.9607 and 0.9579.
      h2-many won in both, 0.9856 and 0.9854, h2-routes-many 0.9875 and 0.9876,
      h2-k8s-routes-many 0.9882 and 0.9886, h2-routes-post-many 0.9893 and 0.9883, and
      h2-tls-many 0.9907 and 0.9875. No input lost.
    - Each engine grows by 160 bytes, the one `event`, and docs/performance.md's memory table
      says so.
    - The server tests, 757 of 757, passed on x86-64 Debug in an amd64 container.
    - `tools/ci.sh` passed 31 sections on `6b636d09`, with Zig 0.16.0 on an Apple M1 Pro with
      macOS.
- **58b, public, in v0.20.0.** v0.19.0 is released without it (decision 165 as amended on
  2026-11-19). Two signatures change:
  - `server.Engine(capacity).receive` takes `result: *server.ReceiveResult` and returns nothing.
  - A `server.Router`'s `handle` takes `received: *const server.Event`.
  - `colibri.Server`'s loop, each example that calls them, docs/usage.md and `tools/consumer/`
    change with them. No public name is added or removed, so no names list changes.
  - The judge measures 58b against 58a. A change that breaks every program's loop must win
    past the noise.
- **58b, built 2026-11-25** (decision 165 as amended that day). The owner admitted it into
  v0.20.0 for its shape, after the judge found it neutral.
  - The judge measured the change against `dfc50213`, the files of `main` before it, in two
    jobs with the h11 inputs ([run 45605444855](https://github.com/c4milo/colibri/actions/runs/45605444855)).
    No input left the noise in either job. In user instructions h2-many gave 10,401.5 and
    10,397.8 in the first job, and 10,401.2 and 10,396.0 in the second. h11-many gave 1.0006
    and 1.0089 of the base, within noise of 5.32% and 5.83%. The copies 58b removes do not
    show in the judge's counts.
  - `server.Engine(capacity).receive` takes `result: *server.ReceiveResult` and returns nothing.
    `State.receive` writes `consumed` and `event` in place, and writes null when it reports
    nothing.
  - A `server.Router`'s `handle` takes `received: *const server.Event`, and switches on it by
    pointer. `server.Handled.event` is `*const server.Event`: the event `handle` took.
  - Each program keeps one result: `colibri.Server` holds `received` beside its engine, and so
    do the test-only server's session, the h3 endpoint, the examples and `tools/consumer/`.
    Their handlers take `*const server.Event`. The simulator's runs and the tests keep a
    result in each call's scope.
  - No public name is added or removed, so no names list changes. Two signatures change, and
    the type of `Handled`'s payload.
  - Mutations, 4, each CAUGHT against `zig build test-server`: an event `take_stream` reported
    not written into the result; null not written when nothing is reported, which leaves the
    last event; the bytes a reported event consumed not written; and `handle` handing back a
    copy, which the new test of decision 165 catches by its pointer.
  - Run on x86-64 Linux: `zig build test`, 4,277 of 4,279, with 1 skipped and the IPv6 test
    failed; `zig build examples`, 10 of 11, the IPv6 example failed; `tools/doc_snippets.sh`;
    and `tools/consumer_check.sh`, with stdx from Zig's cache.
- **What stays.** The client keeps its own form, because [#133](https://github.com/c4milo/colibri/issues/133) measured the server.
