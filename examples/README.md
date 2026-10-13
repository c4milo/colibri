# Examples

Each file here is a complete program of the kind a project that depends on colibri writes. It
imports the library modules by the names a dependent uses, and runs a colibri client and a colibri
server against each other.

| Example | What it shows |
| --- | --- |
| [`tls_exchange.zig`](tls_exchange.zig) | The `server` and `client` modules over TLS, which most programs use. ALPN picks h2. The client is a `client.Channel` with TCP alone: it places an exchange for a GET and one for a POST, starts the connection the channel's `open` asks for, and closes the socket at its `close`. The server answers each request by its id, and each exchange ends in one outcome. The server holds its connections in a `server.Endpoint`: it calls `accept` for each socket, `send_stream` at each `send` event, and `transport_closed` for a socket its peer closed first, and it reads `close` and `ended`. |
| [`server_exchange.zig`](server_exchange.zig) | The `server` module over TCP and QUIC through one `server.Endpoint`. A TCP client gets h2 by ALPN and sends a GET and a POST, and a QUIC client sends a GET over h3. The server passes the endpoint each socket's octets and each datagram, answers each request by its id, and finds its own state for a request through `set_user_data`. It calls `transport_closed` for a socket its peer closed first, shortens the idle deadline of its QUIC connection with `set_deadlines`, advertises h3 with `h3_alternative`, and calls `shutdown` once both clients are done. |
| [`server_peers.zig`](server_peers.zig) | Not an example by itself, but the two clients the server example answers: one `client.Channel` over TCP alone, and one over QUIC alone. |
| [`h3_exchange.zig`](h3_exchange.zig) | h3 through `server.Endpoint` and `client.Channel`. The endpoint passes each datagram to its connection, the channel opens QUIC and carries the exchange, and both sides sleep until their next deadline. |
| [`h11_exchange.zig`](h11_exchange.zig) | The `h11` module by itself. A client pipelines a GET and a PUT, and sends the PUT's body from its own buffer with `count_body`. The server reads one request at a time and answers each. |
| [`h2_exchange.zig`](h2_exchange.zig) | The `h2` module by itself. A client and a server exchange their prefaces and SETTINGS, and the server answers a GET with HEADERS and DATA. Each side runs the loop every h2 program runs: `receive` one frame at a time, then `write_pending`. |
| [`link.zig`](link.zig), [`link_datagram.zig`](link_datagram.zig) | Not examples of colibri, but what the others run over: the stand-ins for a program's sockets, one for a stream of octets and one for datagrams. The datagram link runs on the loops of a stream link, or on loops the program starts, so each side runs one loop. |
| [`tls_program.zig`](tls_program.zig) | Not an example by itself, but what a program that links `tls` defines once: chapulin's hook, and the source its connections draw from. |

Run every example, or one:

```sh
zig build examples
zig build example-tls_exchange
```

Each example checks what arrived against what was sent, octet for octet, and exits with an error
when anything differs. `tools/ci.sh` runs them on every push, so an example that stops working fails
CI. Twenty-four deliberate breaks each made `zig build examples` fail: in colibri's h11 and h2
writers, in its server, client and endpoint, in the TLS setup, in the links, and in the calls the
TLS example's server makes on its endpoint.

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
