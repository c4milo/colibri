# Examples

Each file here is a complete program of the kind a project that depends on colibri writes. It
imports the library modules by the names a dependent uses, and runs a colibri client and a colibri
server against each other.

| Example | What it shows |
| --- | --- |
| [`server_exchange.zig`](server_exchange.zig) | The `server` module over TCP and QUIC through one `server.Endpoint`. A TCP client gets h2 by ALPN and sends five requests, and a QUIC client sends a GET over h3. The server passes the endpoint each socket's octets and each datagram, and answers each request by its id. It finds the route of each request through a table of `server.router`: a route with a parameter, a 405 with its Allow field, and a 404. It finds its own state for a request through `set_user_data`. It calls `transport_closed` for a socket its peer closed first, shortens the idle deadline of its QUIC connection with `set_deadlines`, advertises h3 with `h3_alternative`, and calls `shutdown` once both clients are done. |
| [`server_peers.zig`](server_peers.zig) | Not an example by itself, but the two clients the server example answers: one `client.Channel` over TCP alone, and one over QUIC alone. |
| [`client_exchange.zig`](client_exchange.zig) | The `client` module through one `client.Channel`, on a network that drops every UDP datagram. The channel offers h3 over QUIC and h2 over TCP. It opens QUIC first, opens TCP once the fallback delay passes, and carries a GET and a POST over h2. Three more requests get 405 with an Allow value, 404 and 501, because no route serves them. The client starts the connection each `open` asks for, closes each transport at its `close`, takes the server's ticket, and calls `shutdown`. The abandoned QUIC connection ends after its closing period, so the run takes about 3 s. A second channel shows a connect that fails: the client calls `transport_closed`, and the exchange ends `refused`. |
| [`client_peer.zig`](client_peer.zig) | Not an example by itself, but the server the client example sends to: one `server.Endpoint` with one TCP slot and no UDP socket. Each of its routes names the function that answers the request, and it answers 405, 404 or 501 to a request that no route serves. |
| [`h11_exchange.zig`](h11_exchange.zig) | The `h11` module by itself. A client pipelines a GET and a PUT, and sends the PUT's body from its own buffer with `count_body`. The server reads one request at a time and answers each. |
| [`h2_exchange.zig`](h2_exchange.zig) | The `h2` module by itself. A client and a server exchange their prefaces and SETTINGS, and the server answers a GET with HEADERS and DATA. Each side runs the loop every h2 program runs: `receive` one frame at a time, then `write_pending`. |
| [`link.zig`](link.zig), [`link_datagram.zig`](link_datagram.zig) | Not examples of colibri, but what the others run over: the stand-ins for a program's sockets, one for a stream of octets and one for datagrams. The datagram link runs on the loops of a stream link, or on loops the program starts, so each side runs one loop. A blocked datagram link drops every datagram, as a network that drops UDP does. |
| [`tls_program.zig`](tls_program.zig) | Not an example by itself, but what a program that links `tls` defines once: chapulin's hook, and the source its connections draw from. |

Run every example, or one:

```sh
zig build examples
zig build example-server_exchange
```

Each example checks what arrived against what was sent, octet for octet, and exits with an error
when anything differs. `tools/ci.sh` runs them on every push, so an example that stops working fails
CI. Fifty-two deliberate breaks each made `zig build examples` fail: 28 of the server example and
24 of the client example. They break the calls each example makes, its peers and the links. One
more break made no example fail: the client keeps the octets of a socket after its `close`. The
socket holds no octets then.

The code in README.md and docs/usage.md is quoted from these programs, and `tools/doc_snippets.sh`
fails when a quote no longer matches them.

## The link

colibri does no I/O, so a program brings its own sockets and its own event loop. These examples
bring [Rotor](https://github.com/c4milo/rotor)'s loop and no socket at all
([decision 96](../docs/decisions.md)):
- the client and the server each run on a Rotor loop of their own, in one process and on one
  thread;
- what one side sends is copied into the other side's queue in memory, and the sending loop posts
  the other a message saying how many octets arrived;
- the instant colibri takes is the one the side's loop read at its last tick, and a side with
  nothing to read waits in its loop until its next deadline.

A real program replaces `link.zig` and `link_datagram.zig` with its own sockets. The colibri calls
stay the same.

## The identity

The examples over TLS present colibri's test identity, a CA and a leaf for `localhost` in
[`src/testing/testdata/`](../src/testing/testdata/), and judge it at an instant it is valid at. A
real program loads its own certificate and key, and passes the Unix time its clock reads.

The test-only endpoints in [`src/testing/`](../src/testing/) run every protocol over real sockets,
and show a whole program with them.
