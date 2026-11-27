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
