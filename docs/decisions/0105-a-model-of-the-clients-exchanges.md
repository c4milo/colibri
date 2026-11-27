# Decision 105: A model of the client's exchanges, and a trace check of the client against it

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-28, for [#70](https://github.com/c4milo/colibri/issues/70), after
design §8 step 17d's tests found two faults in the client over QUIC. A shut-down connection never
closed, because it owed a GOAWAY it never sent. A failed connection left each stream holding its
exchange's bytes, so no `finished` event came. No model covered the client.
- `spec/tla/client_exchanges` models the exchanges the client carries to one origin over QUIC
  and TCP. Each exchange runs from `request` to its one `finished` event, or to its cancel.
  The model holds the connection that carries it, whether a QUIC stream may still read its
  bytes (RFC 9000 §3.1), and whether a server processed it. Each connection runs from its
  handshake to its `closed` event. The choice between them is design §8 step 17d's: QUIC
  first, TCP when QUIC fails or the fallback delay passes, and an exchange the server
  refused unprocessed moves to another connection.
- Its safety property says each exchange is reported once, and never while a stream holds
  its bytes. An exchange is `refused` only when no server processed it, and no request is
  processed by two servers. A connection reports `closed` only once it holds no exchange.
  Its liveness property says every exchange made ends, and every connection opened reports
  its close once the caller shuts the client down.
- Each rule colibri keeps is a constant, and a configuration that turns one off must find a
  violation. The two faults are two of the rules.
- Step 17d's simulator run, which loses, delays and refuses QUIC, logs the model's variables
  after each step, and TLC checks each seed's log is a behavior of the model, as decisions 87
  and 104 have for h3 and h2. A log that stops early is still a behavior, so the run also
  requires every seed to end with each exchange finished and each connection closed.
  `tools/client_trace.sh` runs it, and `tools/ci.sh` runs it where Java is installed.

The alternatives refused:
- Model one connection's exchanges and leave out the choice. It would cover the two faults.
  It would leave the moves between connections to tests, and a move is where a request can
  be processed twice.
- Tests alone. A test checks the sequences its author wrote. TLC checks every sequence the
  model allows within its bounds, and the trace check holds colibri to the model.

Cost: step 17d gains a model and a trace run, and step 17b waits longer.
