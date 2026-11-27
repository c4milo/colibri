# Decision 120: A client's channel builds its TLS configurations, draws what a QUIC connection starts from, and carries every exchange a program makes

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-12 in [#96](https://github.com/c4milo/colibri/issues/96); design §8
step 21c carries it.

Decision 117 made `client.Channel` the one client object. Step 21b did the server's half.
For the client, four things were left:
- a program gave two TLS configurations, each with its own ALPN list, and three
  configuration types: `Config`, `QuicConfig` and `ChannelConfig`;
- `versions` decided nothing over TLS, and a client that spoke h3 alone still opened TCP;
- a program drew each QUIC connection's two connection IDs and h3's grease value, and passed
  them in a `QuicStart`;
- seven callers still placed a `client.Connection`: the endpoint check's peers, the
  test-only client, the content-coding, deadline and TCP trace runs, the TLS example and
  the consumer.

The rulings:
1. `client.Config` holds one `tls.Client` value, whose `alpn` stays empty, and it is the
   channel's configuration. `QuicConfig` and `ChannelConfig` fold into it. Each channel
   builds the TLS configurations it needs in `init`, which returns an error: none in
   cleartext, and none for a transport it does not offer.
2. `versions` names what a channel offers. TCP is offered when it allows h11 or h2, with h2
   first in the ALPN list (RFC 9113 §3.2). QUIC is offered when it allows h3, the
   configuration has a TLS value, and the program gave a receive pool. `init` returns
   `NoVersion` when neither is offered.
3. A client that speaks h3 alone opens no TCP connection. spec/tla/client_exchanges has the
   constant `TcpAllowed` for it, and a configuration that must find TCP opening a
   violation.
4. A handshake that selects no protocol runs h11 only while `versions` allows it (decision
   88). With h11 off the connection closes with no alert, and its exchanges end `refused`,
   as on the server (decision 119 as amended).
5. `start_quic` draws the grease value, then the source connection ID, then the original
   destination connection ID, from the source it is given, as the server's endpoint does.
   `QuicStart` and `QuicStartError` leave the API, and one `StartError` names what `init`
   and both starts return.
6. `client.constants.fallback_delay_ns_default` is 250 ms. No RFC colibri holds gives a
   value.
7. All seven callers move to a channel with TCP alone in step 21c, one commit each. Step
   21d only removes names.
8. An attempt ends when a connection takes the waiting exchanges, and no longer when any
   handshake completes. A connection that fails, or takes no new exchange, in the call that
   completes its handshake reports no `connected`, and its transport stays counted in the
   attempt. Before, a server that completed each handshake and then failed was reconnected
   to without bound. The model states the rule as `TakeAtHandshake`.
9. A channel closes a transport once its connection wrote what it owes: the alert of a
   handshake it refused (RFC 9846 §6.2), its Finished, and in cleartext h2's GOAWAY (RFC
   9113 §6.8).
10. One `Channel` type. A channel with TCP alone still holds a QUIC connection, which it
    never writes. [#99](https://github.com/c4milo/colibri/issues/99) measures a channel
    sized by its transports.
11. `tls.Client.alpn` defaults to empty. `Https.h3` keeps its name: it says what an HTTPS
    record holds (RFC 9460 §7.1.2), a fact about the origin and no choice of the program's.
    INV-5 says colibri draws only from the source its caller passes.
12. A channel does not do what a program could do with a bare `client.Connection`, in
    fourteen ways:
    - hold several TCP connections to one origin: a program makes several channels;
    - send before any receive, or open a connection before its first request;
    - start with no address;
    - hear `draining`, or a connection's `closed` without a shutdown;
    - poll `should_close` and `protocol`;
    - read the raw Alt-Svc advert;
    - see a refused exchange with no retry;
    - get `error.Draining` or `error.ConnectionClosed` from `request`;
    - write its own ALPN list;
    - pay for a TCP connection alone;
    - end one connection gracefully and keep the channel: `shutdown` is final;
    - tell which connection carried an exchange, or why a connection ended.

The alternatives refused:
- A per-origin object that holds the built TLS configurations. It adds a public type to
  save two small structs a channel.
- Building the TLS configurations at each start. A program would read a list too long after
  it opened a socket.
- Refusing an h3-alone client with `NoVersion`. The server serves h3 alone, and `versions`
  is where a program says it.
- `QuicConnection.init` drawing the values. Its tests would lose their fixed IDs.
- A counter and a new limit for the reconnects. `tried` already counts each transport once
  an attempt.
- Moving only the test-only client in 21c. Step 21d's text moves no caller.
- A `ChannelOf` sized by its transports now. It is a second public shape, to measure first.

Cost: a second breaking change to `client`, after decision 115's. A dependent that wrote
`client.ChannelConfig` writes `client.Config`, gives one TLS value, and passes no
`QuicStart`. The client trace census changes once, because each QUIC connection's start
values come from the TLS source. `client.Connection` grows by one field, and
`client.Channel` by two TLS configurations. A program with TCP alone places about 1 MB a
channel where it placed 289,200 bytes a connection.

Amended on 2026-10-12 by design §8 step 21c, for what its sub-steps met that the rulings
left open:
- A channel reports a transport's `close` before the `open` of its next connection. A
  connection that ended while an exchange waited was closed and its transport opened again
  in one pass, and the `open` overwrote the `close` it owed, so the caller kept the old
  socket. It was so from step 17d.
- A caller reads nothing from a socket after the channel's `close`, and still calls
  `receive` for the channel's events. The TCP trace run does so.
- The test-only client counts a connection a success only when its channel closed with
  every exchange answered and every socket it opened ended before the run did.
- A shut-down channel that abandons a connection whose `open` no caller heard of drops the
  `open`, and owes no `close` for it.
- A program drops the bytes it still holds from a socket when the channel says `close`:
  they are that connection's, and the next connection on the transport must not get them.
