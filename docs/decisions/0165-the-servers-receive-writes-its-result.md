# Decision 165: The server's `receive` writes its result through a pointer, and a `server.Router` takes `*const server.Event`, from v0.19.0

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-17, for [#133](https://github.com/c4milo/colibri/issues/133).
- `server.Event` holds 160 bytes, and `server.ReceiveResult` 192. Each layer of the engine,
  and the public `receive`, returns the result by value. A `server.Router`'s `handle` takes
  the event by value. The laptop profile of 2026-11-14 put about 640 of the 1,710
  instructions a request of `State.receive` on h11-many in the lines that build and return
  the result.
- From v0.19.0, `server.Engine(capacity).receive` takes a fourth argument,
  `result: *server.ReceiveResult`, writes the bytes it took and the event there, and
  returns nothing. A `server.Router`'s `handle` takes `received: *const server.Event`.
  `colibri.Server`'s loop, the examples, docs/usage.md and `tools/consumer/` change with
  them.
- The work comes in two parts (design §8 step 58). First the engine's own layers stop the
  copies, with no public change. The public change follows in v0.19.0, the next release that
  breaks names. The judge measures each part as a performance change.

The alternatives refused:
- The result by value, as now. Each layer copies the result on each call, and 6 of a
  request's 8 calls on h11-many report nothing.
- `receive` returns a pointer to an event that the engine holds until the next call. The
  owner's ruling puts the result in storage that the program owns, as ruling 1 of decision
  158 does for the `init` of a large struct.
- A smaller `server.Event`. A request event carries the parts of the request that a program
  reads first, and a smaller event moves those reads into later calls.
- Only the engine's own layers stop the copies. The copy across the public `receive`, and
  the copy into `handle`, then stay on each call.

**Amended by the owner on 2026-11-19.** v0.19.0 is released without the public change, so
that connect-zig can pin the memory steps of
[#137](https://github.com/c4milo/colibri/issues/137). The public change, design §8 step 58b,
goes into v0.20.0 if the judge admits it, and programs change their loop then.

**Amended by the owner on 2026-11-25**, who asked for 58b in v0.20.0. `server.Handled` hands
an event back by the pointer `handle` took, as `event: *const server.Event`, so the router
copies no event it does not take. A program switches on `other.*`. The alternative refused:
`Handled.event` by value, which copies 160 bytes back on each `send`, `close` and `ended`.

**Amended again by the owner on 2026-11-25:** 58b ships in v0.20.0 for its shape, and not for
a win of the judge. The judge measured it neutral: every input within the noise in both jobs
([run 45605444855](https://github.com/c4milo/colibri/actions/runs/45605444855)). The owner
admitted it under TigerStyle: the program owns the storage of each result, as decision 158
ruling 1 gives a program the storage of a large struct, and no call copies a 160-byte value
in or out. The rule that a change of every program's loop must win past the noise yields to
that ruling for this change alone.
