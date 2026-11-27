# Design §8 step 59: fewer deadline checks on a TCP connection, planned 2026-11-18

[Design §8, the build plan](../../design.md#8-build-plan)

[#133](https://github.com/c4milo/colibri/issues/133). The owner ruled on 2026-11-18 to plan it. No
public name changes, and the deadlines pass at the same instants (decision 110).
- **The cost.** The judge's profile of main at `3d29359a`
  ([run 44315900856](https://github.com/c4milo/colibri/actions/runs/44315900856)) put about
  10% of the server's user samples on h11-many in deadline work, in both jobs:
  - the heap's flush, which reads each changed slot's deadline again: about 5%, and
    `State.deadline_of` alone 2.1%;
  - `fire_at_new_instant`, which checks every deadline at each new instant: 2.7% to 3.2%;
  - `observe`: 2.2% to 2.5%.

  The same work took 7.9% on h11-tls-many, 6.6% on h11-one, and 3% to 4% on the h2 inputs.
- **59a, a bound for `fire`.** `Clock` holds `quiet_until_ns`, an instant before which `fire`
  changes nothing. A call before it sets `checked_ns` and returns, as a call at the instant of
  the last does now.
  - The bound is the soonest of every deadline and of every running meter's window end. A
    meter's window end counts, not the instant of its verdict (`Meter.check_ns`): a window that
    brought its quota must roll at its end, before more bytes count, or a peer that keeps its
    rate is cut.
  - A full `fire` that finds nothing computes the bound again. Nothing else raises it.
  - Each place that starts a deadline or a window lowers the bound to that instant with one
    `@min`: `init` for the first request; `observe` for the head, the idle wait, the drain, the
    linger and h2's SETTINGS deadline, which starts in the call that writes h2's preface and
    again at the end of each pause; `connection_bodies.observe` for each body's wait and meter
    and for the meter of all bodies; `connection_sends.observe` for each send meter; and
    `connection_close.half_close` for the staged close. `set_timeouts` sets the bound to 0, so
    the next call checks again.
  - A stop moves a deadline later, so it leaves the bound where it is. The next full `fire`
    raises it.
- **59b, the heap's flush, after 59a's verdict.** A slot whose deadline did not change keeps
  the one the heap holds, with no new `deadline_of` and no move in the heap. It needs each
  change of `soonest` in both directions, the protocol's own changes included (`running`), so
  its design waits for 59a's numbers.
- **The checks.** For each place that lowers the bound, a test in which a full `fire` raised
  the bound past the new deadline, then the start, then a call at that deadline's instant, which
  must end the connection there. A mutation removes each `@min`, and each must be CAUGHT. The
  simulator's deadline checks, `tools/deadlines.sh` and the deadline trace run against
  `spec/tla/server_deadlines` must pass as they do now.
- **The verdict.** The judge measures 59a against main. On h11-one, whose user instructions
  vary by 0.5%, the expected gain is about 2%. The QUIC connection keeps its own deadlines.
- **59a, refused, 2026-11-18.** The bound was built as planned, at `7b75a98b`.
  - Laptop callgrind on h11-many counted the deadline functions at 1,240 instructions a
    request, against 1,503 on main, and `fire_at_new_instant` no longer ran. On h2-many the
    server took about 58 instructions a request more: `observe` grew by 48, because its new
    branches keep more values live and its prologue saves more registers. A version that moved
    the lowering into a cold function cost h2-many 18 more again.
  - The judge measured `7b75a98b` against `29ecebca` in two jobs, with the h11 inputs
    ([run 44323413950](https://github.com/c4milo/colibri/actions/runs/44323413950)). In user
    instructions h11-one lost in both jobs, 1.0166 and 1.0150: each of its connections serves
    one request, so it computes the bound once and skips no check. h11-many gave 0.9977 and
    1.0010, and h2-routes-post-many lost in one job, 1.0086. No input won, so 59a did not land.
  - Mutations, of 9 run before the verdict: 7 CAUGHT; NOT CAUGHT, h2's SETTINGS deadline and a
    body's wait lowering nothing. The run stopped at the verdict.
  - **What it shows.** On the judge, a check skipped at a new instant saves about what the
    bookkeeping for the skip costs in `observe`, which runs at every `receive` and `send`. 59b
    would need the same bookkeeping for each change of `soonest`, so it is not planned.
