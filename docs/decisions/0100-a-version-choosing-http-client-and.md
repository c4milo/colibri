# Decision 100: A version-choosing HTTP client and a server of the same shape, above h11, h2 and h3

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-27, for [#70](https://github.com/c4milo/colibri/issues/70), which
cocuyo asked for.
- Two library modules, `client` and `server`, for HTTP in general and not for DoH: cocuyo
  keeps the DNS half. They are the one place that imports `h11`, `h2` and `h3` together,
  which amends design §3's rule that nothing imports them.
- They drive colibri's `tls` themselves over TCP and QUIC. They import `tls`, take its
  configurations and a `tls.Random`, run each handshake, and hand out a resumption ticket
  for each transport. A program that uses them links chapulin. One that wants no TLS uses
  the protocol modules directly.
- The client chooses the version from values the caller passes: the versions to offer,
  what DNS knows (the addresses, and an HTTPS record's `alpn` and `port`, RFC 9460), and a
  fallback delay. It tries h3 first when h3 is offered, and opens TCP when QUIC fails or the
  delay passes, where ALPN chooses h2 or h11. It learns h3 from Alt-Svc (RFC 7838). It never
  resolves a name, and it tells the caller which transport to open, a UDP flow or a TCP
  connection.
- The server serves h11, h2 and h3 behind the same calls. The transport and ALPN choose each
  connection's version, and whether it advertises h3 with Alt-Svc is a value.
- Both keep colibri's rules. Bytes go in and out tagged by transport, time is a value, and
  the caller owns the memory, with bounds known at build time: concurrent requests, the
  longest body, authority and path. Events are polled, a request can be cancelled by its
  id, and the caller names the response fields it reads.

The alternatives refused:
- One module for both roles. A server-only program would carry the client's code in its
  graph.
- No library module, so each consumer races two HTTP stacks itself, as cocuyo does today.
- The caller making each TLS session through a callback, so the modules never import `tls`.
  A cleartext program would link no chapulin, but every caller would write the wiring the
  modules exist to hold.
- One transport at a time, the caller deciding when to fall back. Every caller would write
  the racing cocuyo wants gone.

Cost: design §3 gains two modules and the edges into `h11`, `h2`, `h3`, `quic` and `tls`, and
design §8 step 17 builds them.
