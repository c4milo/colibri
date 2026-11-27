# Design §8 step 53: an answer with no entry waits for room, 2026-11-16

[Design §8, the build plan](../../design.md#8-build-plan)

A fault that connect-zig found with connectrpc's conformance suite v1.0.7, for v0.17.3.
- **The fault.** `server.Router` answers 404, 405, 501 and 503 with no entry of its pool. When
  the engine had no room for that head, the router cancelled the request. Over h2 the client
  then read RST_STREAM with CANCEL in place of the status. With 16 calls open on one
  connection, 4 of connect-zig's 19 runs of the suite failed. The fault is as old as the
  pool.
- **The fix.** `server/router/router_pool_answer.zig` keeps a head that found no room in a
  slot of the pool: its request's id, its status, and the Allow value of a 405, which is a
  constant of the route table. The head goes on the request's `writable`, and the request's
  `finished` frees the slot. The request's `user_data` stays 0, as that of each request with
  no entry, and a count of the slots in use lets such a request scan none.
- **The bound.** The pool has one slot for each of its `requests`, so the option that bounds
  the entries bounds the answers that wait too. A slot is 48 bytes, so a router of 32
  requests grows by 1,552 bytes. With an answer in each slot, the router cancels one more
  request, as it cancelled each one before.
- **No public name changes.** `server.RouterOptions.requests` keeps its name and its default.
- **The cost of the first build.** The first build named the slot in the request's
  `user_data`. The judge refused it
  ([run 43950399606](https://github.com/c4milo/colibri/actions/runs/43950399606)):
  h2-routes-many took 126 more user instructions a request, 0.8%, and h2-routes-post-many 160
  more, in both jobs. callgrind on the routed load found where they went:
  - 52 a request in the entry and the exit of the pool's `handle`. Two helper functions made
    it larger, so LLVM no longer inlined it into the loop that calls it.
  - 22 a request in `Engine.set_user_data`. A second call of it, for the slot, ended the
    inline copy in `start`.
  - 7 a request in the copy of `request_body` into h11, which each TCP response ran.
- **What the second build does.** A slot names its request by its id, so `set_user_data`
  keeps its one call. `answer`, `on_writable` and `on_finished` are `noinline`, and the two
  helpers of `handle` are `inline`, so a request that a route serves runs the code that it ran
  before. `write_head` copies `request_body` in its h11 case alone. callgrind then counts 18
  more instructions a request than main on the routed load, of 20,600.
- **Alternatives that lost:**
  - The slot's number in the request's `user_data`, which the first build had. Its cost is
    above.
  - The status in the request's `user_data` alone, with no slot. A 405 needs its Allow value,
    and the route table's type gives the pool no call that finds the value again.
  - An entry of the pool for each answer that waits. An entry holds a route's response
    memory, and a 503 says that no entry is free.
  - A new option for the count of slots. `requests` already says how many requests the
    router holds at once.
- **The tests:** seven in `router_pool_answer_test.zig`, against an engine that refuses a head
  when a test tells it to, and one in `router_pool_answer_engine_test.zig`. That one runs over
  h2 on the engine of the TCP tests: a 404 whose HEADERS frame finds no room is not reset, and
  goes once the output empties.
- **Mutations, 9 of 9 CAUGHT:** a head with no room cancels the request, as before; a
  `writable` writes nothing; the slot loses the Allow value; `finished` frees no slot; another
  error of the engine on a `writable` cancels nothing; a request past the slots is not
  cancelled; a slot answers the `writable` of each request; a kept answer is not counted; and
  a freed slot is not counted down.
- **Checked, 2026-11-16,** on `2c2144db`, with step 47's record: the judge found each input
  within the noise, h2-routes-many at 1.0004 and 1.0005, and every other check of step 47's
  record passed.
