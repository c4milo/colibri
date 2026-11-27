# Design §8 step 6: the counted-cost check

[Design §8, the build plan](../../design.md#8-build-plan)

Syscalls the caller would have made, copies and bytes per request, counted inside the simulator and
committed as exact numbers. Allocations are not counted: [decision 35](../../decisions/0035-colibri-is-zero-heap.md)
makes them zero, and `tools/lint/heap.zig` holds it. **Check:** the numbers are in the tree and a
diff that changes one fails `zig build test` until the new number is committed on purpose. This is
the cheap half of [decision 34](../../decisions/0034-the-regression-check-has-two-layers.md) and it lands before any QUIC code, so the
h2 half has a regression floor while the larger half is built. *Small.*

**Check passed, 2026-09-18.** `src/sim/cost_check.zig` holds the cost of one request in three
shapes, and `zig build test` fails when any number moves. What it counts is what a caller sees
from outside — calls to `receive` and `write_pending`, the bytes each carried, and the crossings
of the provider vtable — because the library counts nothing itself: §11's rules forbid a
statistic that costs a branch on the per-frame path. Allocations are not counted;
[decision 35](../../decisions/0035-colibri-is-zero-heap.md) makes them zero.

| Scenario | receive | write_pending | bytes in | bytes out | provider calls |
|---|---|---|---|---|---|
| server, cleartext | 4 | 3 | 58 | 58 | 0 |
| client, cleartext | 3 | 3 | 19 | 100 | 0 |
| server, over the null provider | 4 | 3 | 58 | 58 | 2 |

Two of these are worth reading rather than filing. A request and its response cross colibri's
boundary seven times at a server, which is the bulk-crossing rule of §11 holding: one call reads
a frame, one call writes every frame owed. And TLS adds two crossings and no bytes, because the
provider frames what colibri already produced whole.

`tools/lint/magic_numbers.zig` excludes this file, as it excludes the corpus tables of
`src/golden/`. These are measurements, not limits, and naming each one would put the number in
two places.

Four mutations, every one **CAUGHT**: a server advertising one fewer setting, a response carrying
an extra field line, `write_pending` writing the preface in a call of its own, and a request
omitting `:authority`.
