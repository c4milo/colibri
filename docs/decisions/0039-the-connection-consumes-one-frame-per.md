# Decision 39: The connection consumes one frame per call and returns what it produced

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Design §4.1 has the caller hand colibri the bytes it read and learn how many were consumed.
`receive` takes a slice and an instant, consumes at most one whole frame, and returns the count
consumed and at most one event: a field section, a data payload, a stream reset, a GOAWAY, an
acknowledged PING or SETTINGS. A count of 0 means the slice holds no whole frame yet, or the queued
replies must be written before more frames are read; `has_pending` tells the two apart. Frames
colibri owes in reply, a SETTINGS or PING acknowledgment, a WINDOW_UPDATE, a RST_STREAM, a GOAWAY,
are queued in fixed slots and written by `write_pending` into the caller's buffer when the caller
asks.

Two alternatives lost. Consuming every whole frame in the slice needs somewhere to hold every
event that produces, and a bounded event queue either drops events or refuses input, both of
which hide a peer's frame from the caller. Callbacks the caller registers give colibri a call
it makes at a time of its choosing, which design §4 forbids. Cost: a caller loops over
`receive` until it returns 0, one frame per iteration. Gain: an event's slices point into the
caller's own input or into one slot the connection owns, valid until the next call, and no
frame is ever processed before the caller has seen the last one's event.

**Amended by the owner on 2026-10-01, for [#85](https://github.com/c4milo/colibri/issues/85).**
The reading stops while the reply queue is full, so two endpoints can stall: each holds a full
queue, and the transport is full both ways, so neither can write the replies it owes or read
on. TLC found the stall in `spec/tla/h2_flow_control`, and the stall check of design §8 step 4
found 4 in 8192 seeds. Each needed both endpoints to write their own frames before what h2
owes, and a transport of 4 KiB or less each way.
- Each connection module writes what h2 owes before its own frames. `client.Connection` does
  so in `send`. `server.Connection` does so before each frame its caller asks for: a
  response's head, DATA, a trailer section and a 100 (Continue). The flow-control model shows
  why: once a reply takes less room than a DATA frame, two endpoints that write what they owe
  first finish over a channel of 2 to 4 units, where a free order stalls, and one endpoint
  alone doing so still stalls over 2 and 3.
- The transport holds at least 16 KiB each way, which every socket's buffers exceed.
- Decision 110's send-rate deadline, on by default, ends a server stalled this way, because
  its output holds bytes the peer does not take.

The alternatives refused:
- Record the transport alone. A server that writes its own frames first could still stall
  against a peer that does the same, over a small transport.
- Coalesce a stream's owed WINDOW_UPDATE frames into one slot. Fewer frames would need a slot,
  but a full queue would still stop the reading.

Cost: one check of the reply queue before each frame the server writes, which finds it empty
in the common case.
