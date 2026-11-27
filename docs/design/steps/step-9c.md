# Design §8 step 9c: streams and flow control

[Design §8, the build plan](../../design.md#8-build-plan)

RFC 9000 §2.1's identifiers, §3.1's sending state machine and §3.2's receiving one, §4.5's final
size, §4.1's stream and connection flow control, and §4.6's stream limits, with the blocked frames
each produces. **Check:** every state and event pair of both machines enumerated; a sender never
exceeds either limit and a receiver refuses a peer that does, with FLOW_CONTROL_ERROR and
STREAM_LIMIT_ERROR where §4.1 and §4.6 name them. *Large.*

**The identifiers and both machines, 2026-09-19.** `src/quic/stream/` holds RFC 9000 §2.1's
identifier, with the two low bits read in one place, and the two state machines, which stay
separate because neither half can observe the other's states: a receiver never sees the
sender's "Ready", and a sender never sees when the application read the data. §4.5's final
size rules are enforced rather than reported, because they are about numbers this code holds:
a size that changes, a size below what already arrived, and data reaching past a known size
are all FINAL_SIZE_ERROR. §4.5 lets an endpoint skip those to spare itself state on closed
streams; colibri holds the state while the stream exists, so it answers.

`src/quic/error_code.zig` names RFC 9000 §20.1's transport error codes once, so no file in
`quic` writes one inline and the same rule closes with the same number everywhere.

Both machines are checked by enumerating every state and event pair, 30 and 36 of them, with
a check that each table holds each pair exactly once and that a terminal state is left by
nothing. Mutations: 26 applied, all **CAUGHT**. Three gaps, and two of them were dead code
rather than missing tests — a term in `is_receivable_by` that could never change the answer,
because the peer may always send on a bidirectional stream, and an offset recorded on reset
that nothing reads once a final size is known. The third was a real gap: data arriving out of
order, where a later frame reaching less far must not lower the mark §4.5's "below what
arrived" check rests on.

**Flow control and the table, 2026-09-19.** `src/quic/flow.zig` holds both levels of §4.1 and
the stream counts of §4.6, because all four counters a connection has are one shape: a limit
the peer advertises, a total spent against it, and §4.1's and §4.6's shared rule that a larger
limit replaces a smaller one while a smaller one is ignored. The receiving half is its own
type, because a peer that passes a limit is an error and not a wait — FLOW_CONTROL_ERROR for
data, STREAM_LIMIT_ERROR for streams — and because credit is measured from what the
application read rather than what arrived, which is what stops a stalled reader advertising
room it does not have.

The receive window grows ([decision 49](../../decisions/0049-colibri-auto-tunes-its-flow-control.md), ruled the same day). A window
that never grew would cap one stream at `window / round trip` whatever the path can carry, so
when credit goes out the receiver asks how long since it last sent some: inside two round
trips means the application drained it faster than the peer could learn of the room, and the
window doubles, to a cap. The instant and the round trip are parameters, because colibri reads
no clock and RFC 9002 computes the round trip in step 10; a caller with no estimate passes 0,
which grows nothing, so this works today and sharpens when step 10 lands. The cap is what
keeps [decision 35](../../decisions/0035-colibri-is-zero-heap.md)'s comptime worst case true. A stream count never
tunes: §4.6's limit counts streams rather than bytes, and the table bounds it instead.

`src/quic/stream/stream_table.zig` holds the streams of a connection against their
identifiers, over the pool of [decision 14](../../decisions/0014-the-stream-table-is-not-shared.md). Its per-class watermark is what
makes §3.2's rule cheap — before a stream is created every lower-numbered stream of its type
must be, so a frame naming the eleventh stream of a type creates the ten below it, and the
watermark says where to start. That rule is also why the advertised limit is capped at the
table: an advertised limit is a promise to hold that many streams at once, and a limit past
the table would be a promise it cannot keep. `core.Pool` gained `watermark_of` for it.

Writing the table found a defect in it. `open_peer` on a stream that already existed walked
past it and filled the table; it now takes an unopened identifier only, and the caller reads
`lookup` first, because a frame for an open stream names that stream and one for a closed
stream is judged by §3.3 against the frame's type — neither being that call's to decide.

Mutations: 31 applied over the flow control, the table and the pool's new accessor, all
**CAUGHT**.

**9c is done.** `zig build test` passes 790 of 790 and the lint is clean.

**The TLA+ model, 2026-09-26** ([#47](https://github.com/c4milo/colibri/issues/47)).
- `3c1fe58`: `spec/tla/quic_stream_flow` models one stream and the connection's flow control
  as colibri keeps them: RFC 9000 §3.1's and §3.2's states, STREAM, RESET_STREAM and
  STOP_SENDING, both limits with their MAX_* and BLOCKED frames, §13.3's rule that a lost frame
  is sent again only when it was the most recent of its kind, and step 9e's BLOCKED repeat
  ([#43](https://github.com/c4milo/colibri/issues/43)). The network loses, reorders and
  duplicates frames and acknowledgments, and the idle timeout of §10.1 closes a connection with
  nothing in flight, nothing owed and no shorter timer armed. The properties: no limit is
  passed, a final size never changes, "Data Recvd" comes only with every byte, a stream done
  at the receiver has given all its connection credit back, no frame goes out that §3.3
  forbids, and a blocked sender is released and the stream finishes.
- It found a defect. A RESET_STREAM's final size counted against the connection's limit, but
  the bytes the application never read were never consumed, so MAX_DATA was measured short of
  them from then on; once reset streams held more than half the window, the other streams stalled
  for good. §4.5 calls the final size "the amount of flow control credit that is consumed by a
  stream", and `a19f0f8` has `take_reset` consume the unread bytes for the connection.
- What `zig build tla` printed, on macOS arm64:
  - holds, as expected: `colibri`, 935365 distinct states; `windows`, 35923;
  - violated, as expected: `no_repeat`, a blocked sender whose peer reads late loses the
    connection to the idle timeout without the BLOCKED repeat; `no_resend`, a lost MAX_DATA or
    MAX_STREAM_DATA that is not sent again leaves the sender blocked, because colibri answers
    a BLOCKED frame with nothing; `reset_leak`, the path the fix closes.
- The fix's mutations, against `zig build test-quic` alone: 3 **CAUGHT**.
