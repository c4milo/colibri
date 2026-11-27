# Decision 82: The test-only TLS server drives chapulin's record-mode handshake

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24, for design §8 step 5 and
https://github.com/c4milo/colibri/issues/20. Entry 46 stands: this is the handshake it was waiting
for.

chapulin's `ROLE=server TRANSPORT=record` object takes the bytes the caller read through
`ch_srv_record_in`, and hands the server's flight to an `on_record_out` callback. It never
calls `send` or `recv` during the handshake (its INV-28). So the h2 server's `--tls` mode runs
a handshake inside its one `poll` loop:
- `chapulin_server.zig` passes the bytes read, and gets the flight back in the connection's
  output.
- `h2_tls.zig` opens the records into h2's byte stream once `attach_tls` accepts the
  handshake, and seals what the session writes.
- After the handshake, the record adapter gives `ch_read` one whole record at a time. It
  seals only what fits the output, because chapulin fails a session whose `send` cannot take
  a whole record.
- The TLS mode runs one worker. chapulin's generator is one process-wide state with no lock
  (its `drbg.h`).

colibri's checks found two chapulin defects on the way, and chapulin fixed both (`8e556ca`,
`24301d1`). colibri did not work around either.

The client followed on 2026-09-24, under the owner's ruling on
https://github.com/c4milo/colibri/issues/62 to leave no known bug in place. Its
`TRANSPORT=tls` object failed the session on any record that carries no data, a
NewSessionTicket or a KeyUpdate, because its blocking `recv` cannot answer "no record yet".
`chapulin_client.zig` now drives `ch_record_init`, `ch_record_in` and `ch_record_out`, and
every TLS endpoint checks the linked object against the headers with chapulin's
`ch_build_matches` before its first call.

The alternatives refused, both offered in the issue on 2026-09-20:
- A separate serial TLS endpoint, one blocking handshake at a time. It passes h2spec, which
  opens one connection per case, but it is not how a consumer runs colibri.
- A thread for each handshake, joining the poll set when done. It keeps the loop from waiting,
  at the cost of threads and a pool in a file that has neither.
