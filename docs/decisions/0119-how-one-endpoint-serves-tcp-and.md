# Decision 119: How one endpoint serves TCP and QUIC

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-10-09 for design §8 step 21b, which decision 117 rules; the owner may overrule any
part of it.
- A request's `Id` is a packed struct: a `ConnectionHandle` and the request's number on
  that connection. A QUIC stream ID takes 62 bits, so a slot does not fit beside it in a
  `u64`. The handle holds the slot and a 32-bit generation that advances when the slot's
  `ended` is reported, so a stale handle or id names nothing.
- `set_user_data(id, word)` is the one way to set a request's word, at its head. Each later
  event of the request carries it.
- Every request ends with exactly one `done` or `cancelled`. The program's own `cancel`
  reports `cancelled` with the reason `program`, and a connection that stops first reports
  `cancelled` with the reason `closed` for each request still open. So "free on `done` or
  `cancelled`" is the whole rule a program follows.
- `send` says a TCP connection owes bytes, so a program calls `send_stream` for that
  connection alone. It is reported once for each debt, and again only after a
  `send_stream` that wrote fewer bytes than its buffer held. QUIC needs none: one socket
  carries every QUIC connection.
- `closed` says, after `shutdown`, that every connection has ended, as `client.Channel`'s
  `closed` says it for a channel.
- `writable` also follows a `respond` that returned `NoSpaceLeft` and a coded
  `write_trailers` that returned `Blocked`. Over h3 nothing else tells a program that a
  response's runs freed.
- h2's `Connection` adds `sendable_len(stream_id, room_len)`, the bytes of DATA a stream
  can send now: both windows, decision 110's floor and the room for a frame header.
  `writable` and `send` read it. h2's send window alone is not exact, because the floor can
  hold a frame while both windows are open.
- What a TCP connection did not consume stays with the program, which passes it again with
  its next read and after a `send_stream` for that connection, as with `client.Channel`.
- `accept(security, now_ns)` takes whether the connection runs TLS, so one endpoint serves
  a cleartext port and a TLS port. It takes no address, which colibri never reads over TCP.
- `Ended.failed` says colibri closed the connection because its peer broke a protocol rule
  or its record layer failed, which `error.ConnectionFailed` said before.
- `constants.tcp_connections_default` is 16, so the default `Endpoint` holds 16 TCP and 16
  QUIC connections. A program sizes its own with `EndpointOf`.

The alternatives refused:
- A `u64` id with the slot in its high bits. A QUIC stream ID does not leave room.
- A table index with a generation as the id. It is a second number beside the protocol's,
  and events would still need a lookup by number.
- `user_data` in a per-connection record. It changes the sizes `docs/performance.md` pins
  and touches one transport only.
- A queue of events. Their slices would go stale.
- Scanning every slot for events, owed bytes or deadlines on each call, as before.
  Decision 117's cost refuses it.
- A timer wheel for the deadlines. It needs a granularity, and the heap is exact.
- Copying every TCP byte into the endpoint. It costs a copy per byte and 33 KB per slot.
- No event for the program's own `cancel`, as `client.Channel.cancel` does. A program would
  then need a second rule for when to free a request's memory.

Amended on 2026-10-09 by design §8 step 21b.4, which met five things the text above left
open:
- `sendable_len` takes the payload's length too: `sendable_len(stream_id, room_len,
  payload_len)`. The floor holds a frame only when the window is shorter than the payload,
  so without it a window under the floor that holds the rest of a response would get no
  `writable` and no `send`, and the stream would wait until `send_rate` cancelled it. A
  request's table entry keeps the bytes its program waits to write for this.
- The transport's close keeps the `done` of each response written whole, and the endpoint
  reports them before the connection's `ended`. `Connection.transport_closed`, which a
  program that drives a TCP connection itself calls, still drops them.
- A TLS client that selects no protocol is served h11 while `versions` allows it (decision
  88). With h11 off its handshake completes and the connection closes with `Ended.failed`,
  with no alert: chapulin has no call that refuses a handshake for its ALPN, and colibri
  works around none (RFC 9113 §3.3).
- `shutdown` takes no instant on a TCP connection, so the endpoint calls its `on_instant`
  after it, and its drain starts at the endpoint's `shutdown`.
- A program that serves QUIC alone sizes its endpoint with `.tcp_connections = 0`, which
  draws and builds nothing for TCP. The examples and checks that serve QUIC alone do so.
- A TCP connection may leave input unconsumed until an event of its own: an h11 connection
  reads a pipelined request only once the response before it ends, which may write no byte
  and so bring no `send`. The program therefore passes held bytes again after each event
  that names the connection, beside its next read and its `send_stream`.

Amended again on 2026-10-09 by design §8 step 21b.5, whose check found two defects of 21b.4:
- An h11 connection in cleartext that had read half a head, or half a chunk-size line,
  reached an assertion when the endpoint polled it with no bytes: h11 needs the bytes it
  left unconsumed at the start of the next call's input. A call with no bytes now reads
  nothing from h11 while any remain, and waits for the program to pass them again.
- The endpoint read a TCP connection between a write and the `send` it owed. Each read
  observes the connection's deadlines, and an h2 stream's send meter waits while the output
  holds bytes (decision 110 as amended). So the meter waited after each write and started
  again with a grace period, and a peer that opened its window a byte at a time was never
  cut. The endpoint now reports the `send` of bytes the output holds before it reads the
  connection again, so `send` comes before the `done` of a response that write ended.

Amended again on 2026-10-11 by design §8 step 21b.6, when every TCP caller moved to the
endpoint. No rule changed. The step met three consequences of the rules above, which the
comments and docs/usage.md now state:
- A slot is free at `ended`, which follows `close` with no call from the program, the
  alternative refused above. So a later connection may take a slot while the program's
  socket for the last one still closes, and a program whose sockets outlive `ended` keeps
  entries of its own and maps a slot to the entry of the connection the slot holds now.
- `transport_closed` is for a socket its peer closed first, or one that failed. After a
  `close` it changes nothing.
- The endpoint reports nothing of a request after its ending, a later `body` included. A
  check that needs a request's end after its response is `done` reads it from h2's stream
  table, as the two trace runs do.

Amended again on 2026-10-11 by design §8 step 21b.7: `server.Config` names the type
`EndpointConfig` named, which `QuicConfig` folded into in 21b.3, and `EndpointConfig` leaves
the root. A TCP connection's own configuration is internal. `Connection` and
`QuicConnection` stay exported until step 21d, and a program is to place neither: the root
exports no name for the configuration either takes.
