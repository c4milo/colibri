# Decision 49: colibri auto-tunes its flow control receive window

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-19, after the first flow control landed with a fixed window and the
cost was put to him. A fixed window caps one stream at `window / round trip` whatever the path can
carry — a megabyte at a hundred milliseconds is about ten megabytes a second, on any link — because
a sender that fills the window waits a round trip to hear of more credit. Growing the window is how
every implementation that competes on throughput avoids that: Chromium's QUIC, quiche and msquic all
do it, and TCP has done it for two decades as receive buffer auto-tuning.

The rule is the one those implementations share. When a receiver advertises credit, it asks
how long since it last did. Less than a few round trips means the application drained the
window faster than the peer could learn of new room, so the window and not the path is what
is limiting the transfer, and the window doubles, up to a cap. Longer means something else
is the limit and the window stays. The round trip is a parameter, because RFC 9002 computes
it in design §8 step 10 and colibri reads no clock; so is the instant.

RFC 9000 permits this and specifies none of it. §4.1 fixes the mechanism — absolute offsets,
MAX_DATA and MAX_STREAM_DATA — and §4.2 leaves an implementation to decide when to send
them; §4.1 adds only that a smaller limit than one already advertised has no effect, which a
growing window never produces.

This applies to both levels. A connection window that does not grow with its streams becomes
the limit instead, which is the same problem one level up.

Cost: two more numbers per receiver and a growth rule that a test must pin, and a window
that no longer has one size a reader can predict from a transport parameter. Against
[decision 35](0035-colibri-is-zero-heap.md) the cap is what bounds the memory, so it is a named limit
like any other and a connection's worst case is still a comptime number. Gain: throughput
that follows the path rather than the initial parameter, which is the one place §11.1's
workload does not protect colibri — a short connection never reaches the window, but the
interop runner's `transfer` case and any consumer moving a large body do.

The alternative lost was the fixed window this replaces. It is simpler, it is what the first
implementation did, and for design §11.1's stated workload — short connections, small
requests — it is never reached. It was rejected because §11's own measurement plan puts
colibri against msquic and quiche on transfers where it would lose for a reason that is a
policy choice rather than a design one.

Amended by the owner on 2026-11-06, with decision 153 ruling 11. A stream's receive window
grows up to the receive pool's capacity less the stream's reserve, and not up to the whole
pool. The reserve is `stream_window_reserve_windows` of the stream's own starting windows, a
named limit in `quic.constants.limits` that is 1. A stream that the program holds thus keeps
its reserve of the pool free, and one download still uses nearly the whole pool. The rule
applies to the streams of a client and of a server. A pool no larger than one window and its
reserve keeps each stream's window where it starts. The connection's window still grows up
to the whole pool. `quic.Connection` computes the cap from the stream's own starting window,
so `quic` needs no value from the client or the server.

The reserve is a count of starting windows, and not a count of bytes. The reserve that a
stream leaves is by definition its own starting window, so the code reads the count and
multiplies. A program that sets a larger window thus keeps a larger reserve, and needs no
second setting that could disagree with the window.

Amended again by the owner on 2026-11-06: MAX_DATA is also owed on low credit. Before, it
went out only after half the connection's window was consumed since the last one
(`flow_credit_fraction`), so the other streams could get no credit at all while a stream was
held at its cap. Now a connection with a receive pool also owes MAX_DATA when the credit left
to the peer is below its floor, and the application consumed one byte or more since the
last MAX_DATA (RFC 9000 §4.2 leaves the time to the receiver). The floor is the part of the
pool that a stream of its largest starting window leaves free at its cap: one starting
window in a pool of two windows or more. A stream that can fill the pool leaves none, so a
floor there would cost a frame for each byte and keep nothing free. The new limit is still
the bytes consumed plus the window, so it never passes the pool (RFC 9000 §4.1). The
guarantee is this: while a piece is held, the other streams together can keep the floor's
bytes in the pool, and each byte they consume gives one byte of credit back. A connection with no pool caps no window and keeps no reserve, so the rule does
not apply to it. A survey of 19 implementations' published defaults supports the reserve:
HAProxy, which sizes windows from fixed buffers, keeps 10% of the connection from one stream.
Three alternatives lost:
- Growth up to the whole pool, as before. One held stream could then fill the pool and stop
  every other stream of the connection.
- A fixed stream window of 64 KiB, with no growth. It holds one stream at `window / round
  trip`, which is the cost this decision removed.
- MAX_DATA only after half the window is consumed, with the cap alone. The other streams then
  get at most one reserve while a piece is held, less what they consumed since the last
  MAX_DATA, and possibly none.
