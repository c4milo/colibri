# Design §8 step 57: no poll after a read that changed nothing, refused, 2026-11-17

[Design §8, the build plan](../../design.md#8-build-plan)

[#133](https://github.com/c4milo/colibri/issues/133), a second change of the internal work the owner
ruled. The judge refused it, and two of its tests landed.
- **The cost.** Scratch counters on h11-many after step 56, native, gave 4 polls a request on
  io_uring and on epoll, and 3 of them found nothing. `take_stream` put the slot in the ready
  ring before each read, and two reads a request with no bytes read nothing.
- **The change, `50fd659f`.** `take_stream` put the slot in the ring after a read with no
  bytes that the connection did not read only when `fire` changed what a poll reads: a
  deadline stopped the connection, its linger passed, or the bound of its staged close passed.
  Otherwise it marked only the deadline heap. The counters gave 3 polls a request, and 2 of
  them found nothing, on io_uring and on epoll.
- **The verdict.** The judge found every input within the noise in both jobs
  ([run 44181367630](https://github.com/c4milo/colibri/actions/runs/44181367630)). In user
  instructions h11-many gave 1.0046 and 0.9981, and h2-many 1.0013 and 1.0020. The change did
  not land.
- **The laptop probe.** callgrind, on epoll, counted about 400 instructions less a request on
  h11-many, from two runs of each tree: 14,208 and 14,381 on `db8817d6`, 13,736 and 14,029 on
  `50fd659f`. A run of one tree varies by up to 300. Under valgrind the server falls behind
  wrk, so a poll there costs more than on the judge. The empty poll after a read that found
  nothing costs too little to measure.
- **The tests that landed.** A read with no bytes, with no `on_instant`, at the instant a
  linger passes and at the bound of a staged close, reports `close`. Without the two tests, a
  mutant that ignored the linger or the staged close was NOT CAUGHT. Main passes both, and a
  later change of the ready ring must too.
