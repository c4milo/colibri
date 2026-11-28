# Decision 176: A TCP socket sends from its connection's output, through `output_stream` and `sent_stream`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-26, for [#137](https://github.com/c4milo/colibri/issues/137) (design
§8 step 79).
- A socket of `colibri.Server` held an output of `output_len` bytes, 49,161, beside the
  engine slot's `output` of the same size. In cleartext, `send_stream` copied the slot's
  bytes into it unchanged.
- `server.Engine.output_stream(connection, now_ns)` returns the bytes a TCP connection owes
  its socket, sealed over TLS, where the engine holds them. The program sends them from there.
  It then calls `sent_stream(connection, sent, now_ns)` with the bytes the send took, 0 for
  a send that failed or never went.
- The engine keeps those bytes in place until `sent_stream`, and the connection writes only
  after them. A program calls `output_stream` once a turn, for a socket with no send in
  flight, so the turn's one send carries every byte its writes made (decision 119 as
  amended). A call before the send starts returns the same bytes from the same front, and
  those written since.
- An h2 stream's send meter waits only on bytes no `output_stream` returned. A read that
  finds bytes not lent yet pauses the meter, and the lend at the same instant takes its
  window back (decision 110 as amended a ninth time, on 2026-11-27).
- The engine reports a connection's `ended` only after the `sent_stream` of each
  `output_stream` that returned bytes, whatever ended the connection. So no later
  connection of the slot writes into bytes that a send still reads.
- Over TLS the records need a buffer of their own. Each TLS session holds one of `output_len`
  bytes in `Config.tls_buffer` (decision 167), and the socket holds none.
- `send_stream` stays, for a program that sends from a buffer of its own. A connection may
  use either call between two sends.
- `colibri.Server`, in both kinds, and the test-only server send through the new calls, so
  the judge prices the change. A client's socket keeps its output: `client.ConnectionPool`
  has no such calls.
- The alternatives refused:
  - The program passes the stream buffers in `server.Config`, as it passes `tls_buffer`. The
    contract is the same, and the program sizes a second buffer. It adds a configuration
    name and a `stream_buffer_len` function, and step 62's ruling turned such sizes away.
  - Wait for chapulin to open and seal records in place
    ([c4milo/chapulin#227](https://github.com/c4milo/chapulin/issues/227)), and change both
    directions at once.
  - Keep the copy.

Amended by the owner on 2026-11-28, as "Do the redesign now", after the judge failed design §8
step 79 on one input ([#169](https://github.com/c4milo/colibri/issues/169), design §8 step 80).
The owner approved the rule of the proposal there, and chose the exact heap first:
- **Bytes that `output_stream` returned are out**, as bytes that `send_stream` copied are. The
  ruling above made "out" mean that the socket's send had ended. So each send's end moved
  deadlines, and a connection's `close` came one turn after its last bytes left the engine.
- **`half_close` and `close` come with the lend.** The engine reports them once the connection
  has finished and holds no byte that no call returned. So they may come while a lent send is
  in flight. `ended` still waits for `sent_stream`, so the bytes stay in place for that send.
- **After `close` the engine lends the connection nothing more.** A send that took part of a
  lend leaves the rest with the program's socket. The socket sends it from the same bytes, in
  as many sends as it takes, and the program calls `sent_stream` once they are all out or the
  socket failed. Before a `close`, a count of part of a lend goes back at once, and the engine
  lends the rest again, as before. The proposal did not name this case. It follows from its
  rule that the program lets the send end and then closes.
- **When a program calls `output_stream`.** In cleartext it calls for a socket with no send in
  flight straight after its writes, before its next `receive`. The engine then reports no
  `send` for those bytes, and the program reads a `close` that the lend brought before it
  starts the socket's next receive. Over TLS each call seals a record, so it calls once, after
  the last `receive` of its turn, and the turn's responses leave in one record (decision 119 as
  amended).
- **`sent_stream` of a whole lend, on an open socket,** drops the bytes, counts them for the
  connection's send meter, and stops that meter when the output holds nothing. It starts and
  fires no deadline. INV-31 holds as it was: the call marks the slot's deadline for the next
  `deadline_ns`. The engine polls the connection only when room in the output can bring an
  event.
- **The deadlines** read the same rule: decision 110 as amended a tenth time.
- The alternatives refused:
  - The ruling as it was, with the `close` after `sent_stream`. A socket then arms a receive
    that its close cancels, and h11-one lost 6.9% on the judge.
  - The engine lends the rest of a lend again after its `close`. It would keep a closed
    connection's output and its TLS records as a second state, and a program would wait for a
    `send` after a `close`.
  - Early wake: the heap may hold an instant before a connection's deadline, so `sent_stream`
    marks nothing. It weakens INV-31 from "equal" to "not later". The owner chose to try the
    exact heap first.
