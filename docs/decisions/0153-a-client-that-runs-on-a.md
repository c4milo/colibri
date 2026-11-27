# Decision 153: A client that runs on a `std.Io`, with streamed bodies under it

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-05 (design §8 step 39), as the client's counterpart of `colibri`
(decision 150). A dependent that implements Connect and gRPC streams request and response bodies,
and runs its client both over sockets and in memory.
1. `colibri.Client` runs a `client.ConnectionPool` through the `std.Io` its program passes, or
   Rotor's when it passes none, as `colibri.Server` runs an endpoint. It opens, reads, writes,
   reads the clock and waits only through that `std.Io`.
2. Each exchange gives a `*std.Io.Writer` for the request body and a `*std.Io.Reader` for the
   response body. Each buffer is the program's own memory. A `std.Io.Writer` or
   `std.Io.Reader` may wait, so only this layer offers them: the pool must not wait
   (non-negotiable 1).
3. Under it, the pool streams bodies in pieces and copies none (decision 139):
   - `Request.streamed` says which body goes in pieces. `ConnectionPool.write_body(id,
     piece, end)` hands a request piece, which the program keeps until a `body_taken` event.
     Over h11 with no Content-Length the request goes chunked (RFC 9112 §7.1).
   - A `headers` event reports the status and headers first. Each `body` event says that
     `Response.body` holds a piece, which the program gives back with `release_body(id)`.
     Until then the pool gives back no flow credit over h2 and h3 (RFC 9113 §5.2, RFC 9000
     §4.1), and over h11 it reads no more of that connection.
   - The pool sends a streamed request again only before its first `body_taken`, because
     after it the pool holds no copy (decision 124 ruling 3).
   - Over h2 and h3 a request body may go on after the response headers arrive (RFC 9113
     §8.1). Over h11, decision 124 ruling 2 stays.
4. `spec/tla/client_exchanges` (decision 105) gains the pieces: no `finished` while a piece is
   held, no piece written over before its release, and no exchange sent again after it gave
   up a piece.
5. The client lives in `colibri`, beside the server, so that one module of the library does
   I/O.

6. Amended by the owner on 2026-11-05, with decision 150 ruling 10: there is no `std.Io`
   client. Rulings 1, 2 and 5 are withdrawn, and `colibri.Client` is not built.
   - Step 39 builds ruling 3's streamed bodies in the pool, with ruling 4's model, at once.
     It depends on no other step, and a program drives the pool on its own loop.
   - Design §8 step 41 then adds a `std.Io.Writer` for a request body and a `std.Io.Reader`
     for a response body over the pool, in the way of stdx's codec adapters (stdx decision
     56). The writer's `drain` takes what the pool takes and fails with `WriteFailed` when the
     stream has no room, and the reader fails with `ReadFailed` until the next `body` event.
     Each keeps its state, so the next call goes on from it. stdx's encoders and decoders
     compose over them unchanged. Code that treats either failure as the end, such as
     `writeAll` with no retry, does not work over them, and the docs say so.

7. Ruled by the owner on 2026-11-05, for design §8 step 39:
   - `client.Streamed` is `struct { request: bool = false, response: bool = false,
     request_len: ?u64 = null }`. A stated length sends Content-Length, and h11 otherwise
     sends the request chunked (RFC 9112 §7.1).
   - A `body` event carries `{ id, len }`, the bytes `Response.body` holds. Trailers land
     in `Response.trailers`, and `finished` comes only after the last piece is released.
   - While a response piece is held, h2 reads nothing more of the connection, and h2 and h3
     hold back that stream's credit alone. The connection's credit flows on (RFC 9113 §6.9,
     RFC 9000 §4.1), so one slow stream does not stop the others over h3.
   - `client.WriteBodyError` names an unknown id, a second piece while one is held, a piece
     after the end, and `BodyStopped`: an h3 STOP_SENDING with H3_NO_ERROR (RFC 9114
     §4.1) ends the request body, and the exchange still finishes as a `response`.
   - `cancel` gives back the request piece and a held response piece at once.
   - `receive_events_without_input_max` grows to count four events for each streamed
     exchange: `headers`, `body`, `body_taken` and `finished`.
8. Amended by the owner on 2026-11-05: `colibri.Client` comes back, on Rotor's own API, as
   the client's counterpart of `colibri.Server` (decision 150 ruling 10). It owns the TCP
   sockets, the UDP socket for h3, the loop, the clock and a `client.ConnectionPool`, and a
   program hands it requests. Step 39's streamed bodies stay in the pool underneath it.
   Design §8 step 42 plans it after step 39 and before step 40. Amended by the owner on
   2026-11-06, so that a program fetches through `colibri.Client` sooner: step 42 lands
   before step 39, with whole bodies. Streamed bodies come to `colibri.Client` with step 39.
9. Ruled by the owner on 2026-11-06, for design §8 step 42:
   - `ClientConfig.unix_seconds` is a `u64` with no default. The program reads its clock and
     passes it, and the client reads no clock (non-negotiable 3). A web PKI trust judges the
     dates of each chain against it (RFC 5280 §4.1.2.5). A trust in pins judges no date.
   - The root exports `colibri.ClientOf` and `colibri.ClientCapacity`, so a program sizes
     its client as it sizes its server. `colibri.Client` stays `ClientOf(.{})`.
     `ClientCapacity` holds `quic`, `tcp_connections` and `requests`: QUIC, one TCP
     connection and `client.constants.limits.requests_max` requests by default.
   - `client.Timeouts.connect_ns` bounds each TCP connect, in nanoseconds as the other fields
     of `Timeouts`. Its default is 10 s, `client.constants.policy.connect_timeout_ns`, and
     null turns it off. The pool opens no socket, so `colibri.Client` passes the limit to
     Rotor's connect. A connect past it ends the attempt as a refused connect does.
10. Amended by decision 156 on 2026-11-06, for rulings 8 and 9: `colibri.Client` owns the
    loop when its type names `.private`. With `.shared` it runs on the program's loop, beside
    other libraries, and the program ticks the loop. Decision 156 also renames `ClientOf` to
    `Client`, a type function, and `ClientCapacity` keeps its three sizes.
11. Ruled by the owner on 2026-11-06, after the review of step 39: over h3 a held piece keeps
    the connection's credit, and that is correct. QUIC gives back MAX_DATA as bytes are
    consumed (RFC 9000 §4.1), and a held piece's bytes still take room in the client's
    receive pool. The gap was the window of a request stream: the client granted each one
    the whole pool, so one held stream could fill the pool and stop the others. The client
    grants each request stream `@min(quic_stream_window, capacity)`, as it grants each
    unidirectional stream (RFC 9000 §18.2). Amended by the owner on 2026-11-06, with
    decision 49: the window grows up to the pool's capacity less its reserve, one starting
    window (`stream_window_reserve_windows`), so a held stream keeps that reserve of the pool
    free. Amended again on 2026-11-06, with decision 49: MAX_DATA is also owed when the
    credit left to the server is below that reserve and the client consumed one byte since
    the last MAX_DATA. The other streams thus keep getting credit while a piece is held.
12. Ruled by the owner on 2026-11-06: over h3 a piece is copied once, as over h11 and h2. The
    `data_available` event carries the count of bytes that arrived and copies none, and
    `h3.Connection.peek_data` copies them from QUIC straight into the caller's memory.
    `client.ConnectionPool` calls it with `Response.body`.
13. Ruled by the owner on 2026-11-06: an h11 response that is not streamed and ends
    `too_large` keeps in `Response.body` the bytes that fit, as it did before step 39. Only
    a held piece goes back to the caller at a drop.

Alternatives that lost:
- `unix_seconds` with a default of 0. A web PKI trust then refuses each chain, and a
  program learns of the field only from the refusal.
- `ClientOf` and its capacity kept inside `client.zig`. A program that needs more TCP
  connections, or no QUIC, could then not have them.
- The system's own connect timeout, about 75 s on macOS and 127 s on Linux. A server that
  answers no connect then holds the run for that long.
- A `std.Io.Writer` and a `std.Io.Reader` on the pool itself. `writeAll` and
  `readSliceAll` call `drain` and `stream` again until they finish, so a pool that cannot
  wait would loop without end.
- `write_body` copies each piece into the pool's output: one copy a piece, and memory for
  each exchange, against decision 139.
- A provider that the pool calls inside `receive` for each piece. The pool reports events and
  does not call the program back inside its loop.
- A module of its own for the client. Two modules would then do I/O.
- For ruling 11: give back the connection's credit when a held piece arrives. The piece's
  bytes still take room in the receive pool, so the server could send more than the pool
  holds.
- For ruling 12: an output for each held stream, given at `write_request`. h3 would then
  write into the caller's memory after the exchange ended, as when a GOAWAY refuses the
  stream (RFC 9114 §5.2) and h3 still reads it.
- For ruling 12: keep two copies, through the h3 connection's 16,384-byte buffer.
