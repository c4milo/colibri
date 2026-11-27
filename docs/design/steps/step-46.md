# Design §8 step 46: long server streams through the router, proposed 2026-11-09

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 103](../../decisions.md) and [decision 127](../../decisions/0127-the-server-reads-a-requests-query.md) as amended on 2026-11-09.
connect-zig reported two limits of a long server stream on `server.Engine` and `server.Router`. The
step ships in v0.15.2, and it is built apart from step 44. It adds no public name and removes none,
and the names tests of each type and root stay as they are.
- **The ring of the body's writer** (decision 103 as amended, decision 127 amendment 1).
  - The runs of an h3 response count the caller's bytes they hold, in `caller_len`. The
    engine's state reads them in `held_len`: none over TCP, none for a coded h3 response, and
    `caller_len` for an uncoded one. `Engine` has no call for it, and the response writer's sink
    reads the state.
  - A request's wait gains `release`. The writer arms it when the engine took every run and holds
    some, and the engine reports `writable` once it holds fewer bytes.
  - The writer counts the bytes the engine took and the runs it released. A write that does not
    fit its region takes back the released runs, and moves to the larger free region: after the
    newest run, or from the start of the body's memory up to the oldest run held. These are the
    slow path, in `response_writer_ring.zig`. A write that fits costs what it costs now.
  - One `writeAll` of one slice goes into the memory whole, or fails and writes nothing. A
    failed `flush` keeps its bytes. The router calls `on_writable` only when the writer has
    room.
  - A `flush` that finds a run in every slot adds its bytes to the newest run (the owner's
    ruling of 2026-11-09, commit 46g).
  - A writer that waits for a release asks the engine again after a push, because a write
    that the engine takes whole ends the wait (commit 46h).
  - Cost: 18 bytes of fields for each router entry and 8 for each h3 request record. No copy
    and no count on the per-frame path.
- **`on_writable` while the request body is open** (decision 127 amendment 2). The router calls
  a struct route's `on_writable` at each `writable` while the body is open, except for a
  `.whole_body` route. A call that writes nothing while the body is open does not count toward
  the cancel of decision 127, and no cancel comes while the body is open.
- **Decision 110 stays** (decision 127 amendment 3). The request body deadlines stay the engine's,
  for each connection, and not for each route.
- **The commits.**
  1. 46a `docs`: the amendments and this entry.
  2. 46b `feat(server)`: the ring.
     - Checks: a writer test where the engine holds runs; a struct route that writes sixteen
       times `response_bytes` over an engine that copies and over one that holds runs until late
       acknowledgments; the same route over h3 through the engine, with each side's datagrams
       lost; and `colibri.Server` with `colibri.Client` over h11, h2 and h3, each byte in order.
     - Mutations: reclaim frees one byte too many; reclaim ignores the bytes h3 holds; drain
       splits a write; the router calls `on_writable` with no room. Each must be CAUGHT.
  3. 46c `feat(server)`: `on_writable` while the request body is open.
     - Checks: a route's `on_writable` runs and writes before the body ends; a call that writes
       nothing while the body is open does not cancel, and the route is cancelled after the body
       ends; a `.whole_body` route's `on_writable` does not run before its `on_body`.
     - Mutations: the old check of the body back; no return on a call that wrote nothing; the
       cancel left out after the body ends too; the `.whole_body` check left out. Each must be
       CAUGHT.
  4. 46d `test(server)`: a struct route that answers each request byte before the body ends,
     on the engine.
     - Checks: over h11 the reply to each byte is longer than the connection's output, over h2
       it is longer than ten windows of the stream, and over h3 it is eight times the route's
       response memory. Each reply arrives before the client sends the next byte, calls that write
       nothing while the body is open cancel nothing, and the response ends after the body. Over
       h2 a `.whole_body` route's `on_writable` does not run before the body ends.
     - Mutations, against `zig build test-server`: the old check of the body back, CAUGHT by the
       h11, h2 and h3 tests; a call that wrote nothing while the body is open goes on to the
       cancel, CAUGHT by the h11, h2 and h3 tests; the cancel while the body is open, CAUGHT by
       the struct test of 46c only; the `.whole_body` check left out, CAUGHT by the h2 test.
  5. 46e `fix(server)`: `trailers` with no room sends the run it cut before it waits. Before,
     no call went to the engine and no wait was armed, so no `writable` came.
     - Checks: a writer test where trailers find no room after a body the engine holds. The run
       goes to the engine, the writer waits for a release, and the trailers go after it.
     - Mutation, against `zig build test-server`: no send before the trailers wait, CAUGHT.
  6. 46f `test(server)`: a `release` wait reports no `writable` until the peer acknowledges
     some of the bytes the engine holds.
     - Mutation, against `zig build test-server`: the wait also ends at an equal count,
       CAUGHT. A review found it NOT CAUGHT before this test.
  7. 46g `fix(server)`: a `flush` that finds a run in every slot adds its bytes to the newest
     run. The owner ruled it on 2026-11-09, after a review. The writer has `response_pieces_max`
     (16) slots and frees one only at a release, and an h3 response holds about 7 runs of the
     caller. So the 17th `flush` of a route that flushed each small message failed with
     `error.WriteFailed`, and the router cancelled the request. No named limit changes.
     - The merge is the slow path of a cut, in `response_writer_ring.zig`:
       - The newest run is the run in the last slot. It takes the bytes when the engine has
         not taken it whole. Over h3 the engine takes a run whole or not at all.
       - The run grows at its end only, over bytes of the writer's own region, which no run
         the engine holds overlaps. A run the engine took whole never changes, because QUIC
         may read it again after a loss (decision 103).
       - The run stays one piece of the memory. The writer's region leaves the newest run only
         when a slot is free. While each slot holds a run, a write that needs the room at the
         start of the memory fails, and the route writes it again. An assertion states that
         the run ends where the writer's bytes start.
       - A run of `write_kept` takes no bytes, because its bytes are the program's.
     - When no run takes the bytes, they stay in the writer, and the `flush` returns no error.
       - Later bytes go after them. The writer waits for the engine, and the next `writable`
         cuts them into a run once a slot is free.
       - This occurs when the engine took every run and holds each, or when the newest run is
         one of `write_kept`. An h3 response holds 8 runs of the caller at most, so only the
         engine of a test does the first.
       - Such a `flush` fails only when the writer's region is full too, and it keeps its
         bytes.
     - `write_kept`, `end` and `trailers` still return `error.Full` when no run takes the
       writer's bytes. A route that writes through `body()` alone gets no such error over h11,
       h2 or h3.
     - Cost: one flag in the writer, which its padding holds, so a router entry keeps its size.
       No copy, and nothing new on the path of a cut that finds a free slot.
     - Checks:
       - Four writer tests, one for each case. A `flush` with a run in every slot adds its
         bytes to the newest run: one the engine took none of, then one it took a byte of.
         A `flush` stays in the writer while the engine holds a run in every slot. It fails
         once the memory is full too, and its bytes go once, after a release. Bytes after a
         `write_kept` run stay in the writer until a slot is free. A write does not go to the
         start of the memory while no slot is free.
       - A struct route flushes 1,000 messages of 7 to 128 bytes, with `response_bytes` 8192.
         It does so over an engine that holds 8 runs until late acknowledgments. It does so
         over h3 through the engine too, with two of the client's datagrams in three lost. No
         `flush` fails, no request is cancelled, and each byte arrives in order. Both tests
         failed before the fix.
       - The same route over an engine that copies, as h11 and h2 do, ends in one call, as it
         did before.
     - Mutations, against `zig build test-server`. Each one was CAUGHT.
       - The merge adds to a run the engine took whole: the writer test of an engine that
         holds every run fails.
       - The merge adds to the oldest run the engine has not taken, so the bytes go out of
         order: the assertion stops 4 tests. With the assertion left out too, the bytes
         differ in 2 writer tests and in both tests of 1,000 messages.
       - A cut with no free slot adds to no run: the writer test of the merge fails, and so do
         both tests of 1,000 messages.
       - The region moves to the start of the memory with no slot free, so a merge leaves a
         gap between its two parts. The writer test of the region fails, and the assertion
         stops both tests of 1,000 messages. With the assertion left out too, their bytes
         differ.
       - A run of `write_kept` takes the bytes: the `write_kept` test stops on an overflow.
       - A run the engine took a byte of takes no bytes: the writer test of the merge fails.
       - A `flush` that keeps its bytes fails while the memory has room, or never fails:
         writer tests fail for each.
       - A cut that keeps its bytes does not mark them, or does not wait for the engine: 2
         writer tests fail for each.
       - The next `writable` does not cut the kept bytes again: 2 writer tests fail.
       - `has_room` returns the error of the cut: the writer test of an engine that holds
         every run fails.
       - A write takes back memory while the writer keeps bytes: that test stops on an
         assertion.
  8. 46h, on 2026-11-10: four commits after an adversarial review of 46g. The review found
     one defect, which came from 46b, and four mutations that no test caught. connect-zig
     reported one case more. Each mutation below ran against `zig build test-server`, which
     runs 624 tests after these commits.
     - `fix(server)`: a writer that waits for a release asks again after a push.
       - The defect, in four steps:
         1. A write finds no room. The engine took every run and holds some, so the writer
            arms the engine's `release` wait.
         2. Before the `writable`, the route writes a smaller message, which fits, and
            flushes it.
         3. The engine takes that run whole. A write that found room ends the one wait that
            the engine keeps for a request (`State.write_body`), so the `release` wait goes.
         4. The writer still says that it waits. The router waits for a `writable` that never
            comes, and the response stops.
       - Over h3 with `response_bytes` 512, the client had 501 of 8,192 bytes after 200
         rounds. No test reached the defect. The test routes returned at the first write that
         failed, and the router's test engine kept its wait through a write.
       - The fix is in the writer. `push_open` sends what waits while the body is open. When
         the writer waits for a release, it then asks the engine again (`ring.wait_again`).
         It reads the bytes that the engine holds again first, because `State.wait_release`
         asserts that the engine holds some. `flush`, a write and `write_kept` send through it.
       - The other fix kept a `release` wait in the engine through a write that found room.
         It was refused, for three reasons:
         - The engine keeps one wait for a request, and each write sets it. A write that
           found no room arms it, and a write that found room ends it. The other fix adds an
           exception to that rule for one kind of wait.
         - A `release` wait holds the count of bytes that the engine held when it began.
           After the write the engine holds more. So the `writable` comes later than the
           first release, unless `write_body` reads the count again.
         - `write_body` is on the path of each h11 and h2 write, and those never arm that
           wait. The writer's fix costs one branch after a push while the body is open, and
           nothing on the path of `end`.
       - Checks:
         - A writer test. The writer asks again after a `flush` that the engine takes whole,
           and after a `write_kept`. It asks for nothing when the engine holds no byte.
         - A struct route that writes the next byte alone after each write that failed, and
           flushes it. Over the router's test engine it ends, with each byte in order.
         - The same route over h3 through the engine, with `response_bytes` 512 and 8,192
           bytes. It ends in 17 rounds, and the test allows 512. It wrote 16 bytes after
           writes that failed. Before the fix it did not end, and the test failed at its
           bound.
         - The router's test engine now ends its wait at a write it takes whole. One test
           pins that, and one test of the engine pins the same rule of `State.write_body`.
       - The writer tests share their engine through `response_writer_test_support.zig`, and
         `response_writer_ring_test.zig` holds the new ones, because of the file length limit.
       - Mutations, each CAUGHT:
         - No second ask after a push: the writer test, the route test over the test engine
           and the h3 test fail. The h3 test stops at its bound of rounds.
         - `write_kept` sends with no second ask: the writer test fails.
         - The second ask does not read the held bytes again: the writer test fails.
         - The test engine keeps its wait through a write, as before: its own test fails.
         - The engine keeps a `release` wait through a write that found room: the engine's
           test fails.
     - `test(server)`: one writer test for each of the review's four mutations.
       - `cut_full` does not clear `cut_owed` after a cut. The test: once the bytes that a
         cut kept went, a `writable` cuts no bytes before a `flush`. CAUGHT.
       - `select` refuses the start of the memory when `piece_count` is 16, though the engine
         released the oldest run. The test: with sixteen runs and the oldest released, a
         write goes to the start. CAUGHT.
       - A `flush` that keeps its bytes fails with one byte of room left. The test: it
         returns no error with one byte left, and fails with none. CAUGHT.
       - `end_now` ignores a cut that keeps its bytes. The test: `end`, `trailers` and
         `write_kept` return `error.Full` and change nothing, and `end` goes after a
         release. CAUGHT: the assertion of `close_body` stops the test.
       - One more, `trailers` ignores such a cut: CAUGHT by the same test, on the assertion
         of `copy_trailers`.
     - `fix(server)`: `write_kept` with no free slot sends the run it cut before it waits.
       - The case that connect-zig found. A struct route flushes 20 messages of 5 bytes,
         one by one, through an engine that takes each run whole and holds it. Then it calls
         `end`, or `trailers`. Each call returns this:
         1. Flushes 1 to 16 return no error. Each makes a run, and the engine takes it.
         2. Flushes 17 to 20 return no error. No slot is free, and the engine took the
            newest run, so their bytes stay in the writer.
         3. `end`, or `trailers`, returns `error.Full`, and changes nothing.
         4. The route returns with no error. The writer waits for a release, so the router
            does not cancel the request.
         5. The engine releases the oldest run. The `writable` cuts the 20 bytes kept into
            one run, in the slot that the release freed.
         6. The route's next call makes the call again. It returns no error, and the
            response ends with each byte in order.
       - A route that returns that `error.Full` from `on_writable` has its request cancelled,
         because the head went out (decision 127 ruling 4).
       - The contract, which docs/usage.md states:
         - A `flush` keeps its bytes.
         - `end`, `trailers` and `write_kept` return `error.Full` while a cut keeps its
           bytes, and change nothing. A second call after a release goes.
         - `end` and `trailers` needed no change for it. The tests are new.
       - `write_kept` had one path with no wait, which the review found:
         - Its cut puts the writer's bytes in the last slot, so its own bytes find no slot.
           It returned `error.Full`, and the run that it cut went to no engine.
         - When the engine had taken and held each of the 15 runs before, no `writable` was
           owed, and the response stopped. Only the engine of a test holds 15 runs.
         - `add_piece` now sends what waits before it waits, as `trailers` does since 46e.
           Then the engine owes a `writable`, or the writer waits for a release.
         - When that push frees a slot, `write_kept` goes on with no error. An engine that
           copies does this once its window opens.
       - Checks: the route above over the router's test engine, with `end` and with
         `trailers`, and the route that returns the error. Two writer tests of `write_kept`,
         one over an engine that holds each run and one over an engine that copies.
       - The writer tests' engine now asserts that it holds bytes when the writer asks for
         a release, as `State.wait_release` does.
       - Mutations, each CAUGHT:
         - `add_piece` does not send before it waits: both writer tests fail.
         - It frees no slot after the push: the test over an engine that copies stops on the
           assertion above.
         - It does not wait after the push: the test over an engine that holds runs fails.
         - A cut that keeps its bytes does not wait for the engine: the route test fails, and
           three writer tests.
         - `end`, or `trailers`, ignores a cut that keeps its bytes: both route tests stop on
           an assertion, and one writer test.
     - `docs`: this entry, the second amendment of decision 127, and docs/usage.md, which
       names the two errors of `end`, `trailers` and `write_kept`.
     - Before each of the three code commits, on macOS on arm64, each of these ended with
       status 0: `zig fmt --check`, `zig build lint`, `zig build test`, `zig build examples`,
       `tools/doc_snippets.sh`, `tools/consumer_check.sh` and `zig build bench-memory`. No
       size of the memory table changed.
