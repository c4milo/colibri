# Decision 117: A program names no HTTP version outside `versions`, and one endpoint serves every connection

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-04 in [#96](https://github.com/c4milo/colibri/issues/96); design §8
step 21 carries it.

Decision 100 put h11, h2 and h3 behind one set of calls. A program still named a version in
five places:
- `cleartext`, `.h11` or `.h2`, in the server's and the client's configurations;
- the ALPN lists of its two TLS configurations, one for TCP and one for QUIC;
- `h2_streams_max`, `data_frame_len_min` and `QuicConfig.switch_to`, which bound or choose
  something of one version alone;
- three types named after a transport: `QuicConnection`, `QuicConfig` and `QuicStart`;
- two shapes of server: a `server.Connection` the program places for each TCP connection,
  and a `server.Endpoint` for its UDP socket.

The rulings:
1. One `server.Endpoint` holds the TCP connections a program accepts as well as the QUIC
   connections of its UDP socket. One `receive` takes a TCP connection's bytes or a
   datagram. A request's id names its connection, so `respond`, `write_body`,
   `write_trailers` and `cancel` are calls on the endpoint. One deadline covers every
   connection. `close` and `ended` are events, in place of polling `should_close`,
   `close_reason` and `ended`.
2. Each request carries one word of `user_data`, which the program sets at the request's
   head and each later event of the request brings back. A `writable` event says that a
   response whose last `write_body` took fewer bytes than it was given can take more.
3. `server.Connection`, `server.QuicConnection`, `client.Connection` and
   `client.QuicConnection` leave the public API. `client.Channel` is the one client object.
4. An optional `versions` field says which of h11, h2 and h3 a server or a client speaks,
   each true by default. It is the one place a program names a version. colibri derives the
   ALPN lists from it. A server in cleartext tells h2 from h11 by the connection preface
   (RFC 9113 §3.3). A client in cleartext speaks h11 when `versions` allows it, and h2 with
   prior knowledge when it does not.
5. The bounds that named a version move into a `limits` field, named by what they bound.
   `versions` stays out of it, because a choice of version bounds nothing.
6. A router, `server.router`: a table of methods and paths the program declares at compile
   time, which matches a path and returns its parameters, and does nothing more (design §8
   step 21e). Its first name was `server.routes`, and decision 122 as amended on 2026-10-14
   records the rename. A parameter is the value a pattern's `:name` segment binds, and a program
   reads them from a `server.PathParameters`. The owner named them on 2026-10-10: the first
   draft called them captures, which names what a matcher does and not what a program
   reads.
7. No middleware (decision 118).

`protocol()`, `Request.version` and the close reasons still name a version. They say what
happened, and a program logs them without acting on them.

The alternatives refused:
- A `server.Connection` for each TCP connection beside an endpoint for QUIC, with only the
  configuration changed. It is smaller, but the server would not match the client, and a
  program would keep two loops.
- The per-connection types kept public for a program that drives one TCP connection
  itself. Two ways to serve would each need documenting, testing and keeping compatible.
- `versions` inside `limits`.
- A handler the program registers, which colibri calls for each request. Decision 100 has
  events polled, so the program keeps its loop.
- colibri opening the sockets, which would hide the transport too. Non-negotiable 1
  refuses it.

Cost: a second breaking change to `server`, after decision 115's. Every test-only endpoint,
simulator check, benchmark and example moves to the endpoint and the channel. The endpoint
must find its soonest deadline among all its connections without reading each one on
every call.

Amended by the owner on 2026-11-05: `client.Protocols` gains `prefer`, `.tcp` by default
or `.quic`, which says which transport a pool opens first. The owner set `.tcp` as the
default the same day, so a pool that is not told otherwise opens TCP first, which changes
what a pool did before. h3 gains most on paths that lose
packets, such as mobile networks, and on a datacenter path with no loss QUIC costs more CPU
than TCP and gains nothing.
- `.tcp`, the default: TCP first, and QUIC only once TCP fails.
- `.quic`: QUIC first, and TCP once QUIC fails or the fallback delay passes, as every pool
  did before this ruling.
- h2 stays before h11 in the ALPN list (decision 120). Design §8 step 43 builds it in
  v0.15.0.
The alternatives that lost: an ordered list of protocols, which needs rules for repeats and
for h3 between the TCP versions, and a preference for each destination alone.

Amended by the owner on 2026-11-06, after the review of design §8 step 43:
- Under `.tcp`, QUIC waits for a TCP slot that closes. QUIC opens only once a TCP connect
  failed. A TCP connection that drains after a GOAWAY is not a failure.
- `client.Config.quic_first` becomes `client.Config.quic_unadvertised`, with the same default,
  `true`. The field says whether QUIC may open when no HTTPS record and no Alt-Svc name h3.
  Under `.tcp`, QUIC does not open first, so the old name was wrong. The rename breaks a
  dependent's code at v0.15.0.

Amended by the owner on 2026-11-13, after a pool under `.quic` opened TCP while its QUIC
connection closed:
- Under `.quic`, a QUIC connection that drains and carries no exchange only waits out its
  closing period (RFC 9000 §10.2), about three PTOs. It did not fail. So a waiting exchange
  waits for its slot, and QUIC opens again.
- A QUIC connection that drains after a GOAWAY and still carries exchanges lets TCP open. It
  lasts as long as those exchanges do, so a wait for it has no bound.
- Before this ruling, TCP opened while any QUIC connection still ended. The pool then stayed
  on TCP, because QUIC never opens beside an open TCP connection. The model
  `spec/tla/client_exchanges` had the old rule since its first commit, and no decision named
  it. Design §8 step 43 records the change.
The alternatives that lost: a wait for every QUIC connection that still ends, as under
`.tcp`, and the old rule, written down as it was.
