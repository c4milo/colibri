# Decision 125: `client.Pool` holds several TCP connections to one origin, counted at run time

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-17 and 2026-10-19, for design §8 step 22
([#108](https://github.com/c4milo/colibri/issues/108)). A program that sends many requests at once
to one origin over h11 needs one TCP connection for each, because h11 carries one exchange at a time
on a connection. `client.Channel` holds one TCP connection and one QUIC connection.

The rulings:
1. `client.Pool` replaces `client.Channel`, and `client.PoolOf(capacity)` replaces
   `client.ChannelOf`. A channel is a pool of one TCP connection, so one type serves both.
   `client.Capacity` keeps `quic`.
2. The counts are set at run time (decision 35 as amended).
   - `client.Options` holds `tcp_connections` and `requests`. Each has a named maximum in
     `client.constants`.
   - Counts and limits say requests, since a program calls `request`, and a request with its
     response keeps the name exchange, as RFC 9110 §7.5 calls it. The owner ruled it on
     2026-10-20, over a rename everywhere: "request" already names the message, as in
     `client.Request`.
   - `Pool.memory_bytes(options)` returns the bytes that the options need. `init` takes
     that memory, aligned to `Pool.memory_alignment`.
   - `Pool.receive_events_without_input_max(options)` replaces the constant of decision 124
     ruling 5, because the bound counts each exchange and each transport of the pool. The
     owner ruled it on 2026-10-20.
   - Options outside their limits are a programmer error, and so is memory of another
     length or alignment: `memory_bytes` and `init` assert.
3. A `client.ConnectionHandle` names each connection, as `server.ConnectionHandle` does
   (decision 119): a slot and a generation. TCP slots come first, and the QUIC connection has
   the last slot.
   - The events `open`, `close` and `ticket` name it, and `connected` carries it beside the
     protocol.
   - `start_tcp`, `send_stream`, `transport_closed` and `take_ticket` take it. `Input.stream`
     carries it in a `client.StreamOctets`.
   - A new event, `send`, names a TCP connection that owes bytes, as the server's does. A
     program then calls `send_stream` for that connection alone, until a call leaves room in
     its output.
   - The event comes once for each debt, in a call that passes the connection no bytes, so
     the connection has read what the program held for it before a request goes out.
   - The connection says what it may owe without writing it. A request that waits for the
     peer or for room counts, so a `send_stream` may write nothing. That call blocks the
     connection: its next `send` waits until it reads bytes, or until the program makes a
     request or a cancel. A loop of the program therefore never turns on an empty debt.
4. Connections open on demand. The pool opens another TCP connection only when an exchange
   waits, no open connection can take it, and fewer than `tcp_connections` are open or
   opening.
   - In a pool of more than one TCP slot, an h11 connection takes one exchange at a time. A
     pool of one TCP slot pipelines on it, as decision 88 rules.
   - RFC 9113 §9.1: a client "SHOULD NOT open more than one HTTP/2 connection to a given
     host and port pair". So the pool opens another TCP connection only while TCP speaks
     h11. An h2 connection takes every exchange its slots hold, and the server's
     SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §6.5.2) holds the rest back on it.
   - QUIC first and TCP after the fallback delay stay as decision 120 rules. The first TCP
     connection is the fallback.
   - A pool holds one QUIC connection, because h3 carries many exchanges on one.
   - The pool opens no connection while no exchange waits, and none on a timer of its own.
     The fallback delay opens TCP only for exchanges that wait.
5. An attempt that fails ends each waiting exchange `refused` when no open connection is left
   to take it, as the channel does now (spec/tla/client_exchanges's `GiveUp`). The program
   then decides when to send again. While another connection of the pool is open, a waiting
   exchange waits for it.
6. An idle connection stays open for the next exchange, until the server or `shutdown` ends
   it. A limit on the time a client connection stays idle is later work.
7. The resend of decision 124 ruling 3 and a refused move go to any other connection of the
   pool, and share `moves_max`. The reconnect bound of decision 120 ruling 8 counts per pool.
8. `set_values(values)` gives the pool new addresses while exchanges run. Connections that
   open after the call use them, and open connections keep their exchanges.

The alternatives refused:
- A comptime count, as `server.EndpointOf` takes. Decision 35 as amended records why.
- A `Pool` beside `Channel`. Two types would do much the same, and a program would learn
  both.
- A plain slot index in place of the handle. An index names the next connection in its slot
  after a `close`, so a late call acts on the wrong connection.
- No `send` event, so that a program calls `send_stream` for each connection after each
  `receive`. With 16 connections that is 16 calls for each event.
- The count of requests as the comptime `constants.requests_max` alone. A pool of 16 h11
  connections and a pool of one h2 connection then hold the same table.
- Every connection opened at `init`. A program that sends one request then opens 16 sockets
  and runs 16 handshakes.
- An `init` that returns an error for bad options. The options are the program's own
  values, so a bad one is a programmer error.

Cost: a breaking change in 0.9.0 for every program that names `client.Channel`. Each call
and event that names a transport names a connection instead. A program supplies the pool's
memory, and calls `memory_bytes` first.
