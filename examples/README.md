# Examples

Each example is a program that a project depending on colibri could write. It imports
`colibri` alone, the one module a dependent reaches, and checks what arrived byte for byte. Most
run a colibri client against a colibri server.

Run every example, or one:

```sh
zig build examples
zig build example-server_exchange
```

`tools/ci.sh` runs them on every push, so an example that stops working fails CI.

## The examples

| Example | What it shows |
| --- | --- |
| [`colibri_server.zig`](colibri_server.zig) | `colibri.Server` and `colibri.Client` on colibri's own Rotor loop (`.private`): a route table on 127.0.0.1, GETs over h11, h2 and h3, `fetch`, `cancel`, `shutdown` and `deinit`. |
| [`colibri_hosted.zig`](colibri_hosted.zig) | The `.hosted` kind: the program hosts a server and a client in memory, with `turn` and `complete`, and rotates the ticket key with `set_ticket_key`. |
| [`colibri_shared_rotor.zig`](colibri_shared_rotor.zig) | A program's own adapter of `.hosted` objects on one Rotor loop, beside a timer of its own, and `set_destination` to a new address. |
| [`server_exchange.zig`](server_exchange.zig) | One `server.Engine` over TCP and QUIC, with a `server.Router`: routes, path and query structs, middleware, `output_stream` and `sent_stream`, deadlines, `set_timeouts`, `h3_alternative` and `shutdown`. |
| [`server_stream.zig`](server_stream.zig) | A stream route that answers a gRPC-shaped POST as its body arrives: `on_request`, `on_data`, `on_finished`, and `next`, `keep` and `ended` on the request body. |
| [`client_exchange.zig`](client_exchange.zig) | One `client.ConnectionPool` that opens QUIC first and falls back to TCP: `open`, `send`, `close`, tickets, a refused connect and `transport_closed`. |
| [`client_pool.zig`](client_pool.zig) | A pool of four TCP connections over h11, and `set_destination` after a later DNS answer. |
| [`client_stream.zig`](client_stream.zig) | Streamed bodies: `write_body`, `release_body`, and the request's and the response's trailers. |
| [`h11_exchange.zig`](h11_exchange.zig) | The `h11` module by itself: a pipelined GET and PUT, and `count_body`. |
| [`h2_exchange.zig`](h2_exchange.zig) | The `h2` module by itself: the prefaces, SETTINGS, and the `receive` and `write_pending` loop. |
| [`dnssec_check.zig`](dnssec_check.zig) | The `dnssec` module by itself: an RRSIG check over a streamed `dnssec.Hash`, and a DS digest. |

Each file's `//!` header says what it does, step by step.

## The peers and the links

These files are parts of the examples, not examples by themselves:

| File | What it is |
| --- | --- |
| [`server_peers.zig`](server_peers.zig) | The two clients `server_exchange.zig` answers: one pool over TCP alone, and one over QUIC alone. |
| [`server_resume.zig`](server_resume.zig) | The `server.ResumeProvider` `server_exchange.zig` gives its engine, which keeps RFC 9959's saved sets for each client host ([decision 149](../docs/decisions/0149-colibris-quic-connections-may-resume-congestion.md)). |
| [`server_stream_peer.zig`](server_stream_peer.zig) | The client `server_stream.zig` answers. |
| [`client_peer.zig`](client_peer.zig) | The server `client_exchange.zig` sends to. |
| [`client_pool_peer.zig`](client_pool_peer.zig) | The server `client_pool.zig` sends to. |
| [`client_stream_peer.zig`](client_stream_peer.zig) | The server `client_stream.zig` sends to. |
| [`link.zig`](link.zig), [`link_datagram.zig`](link_datagram.zig), [`link_streams.zig`](link_streams.zig) | The stand-ins for a program's sockets: one stream of bytes, datagrams, and several streams. A blocked datagram link drops every datagram, as a network that drops UDP does. |

## The link

colibri does no I/O, so a program brings its own sockets and its own event loop. Every example
except `colibri_server.zig` and `colibri_shared_rotor.zig` opens no socket. Those two bind
loopback ([decision 96](../docs/decisions/0096-examples-holds-programs-a-dependent-writes.md) as amended). The others run over the
links:

- the client and the server each run on a Rotor loop of their own, in one process;
- what one side sends is copied into the other side's queue in memory, and the sending loop posts
  the other a message saying how many bytes arrived;
- the instant colibri takes is the one the side's loop read at its last tick, and a side with
  nothing to read waits in its loop until its next deadline.

A real program replaces `link.zig`, `link_datagram.zig` and `link_streams.zig` with its own
sockets. The colibri calls stay the same.

## The identity

The examples over TLS present colibri's test identity, a CA and a leaf for `localhost` in
[`src/testing/testdata/`](../src/testing/testdata), and judge it at an instant it is valid at. A
real program loads its own certificate and key, and passes the Unix time its clock reads.

The test-only endpoints in [`src/testing/`](../src/testing) run every protocol over real sockets.

## How the examples are checked

Every Zig block in README.md, docs/usage.md and this page is an excerpt of these programs or of
`tools/consumer*/`, and `tools/doc_snippets.sh` fails when one no longer matches.

Seventy-three deliberate breaks each made `zig build examples` fail: 28 of the server example, 24
of the client example, 9 of the pool example, 4 of the stream example and 8 of the stream route
example. Three more breaks made no example fail:

- The client keeps the bytes of a socket after its `close`. No socket holds bytes then.
- The stream link keeps a stream's bytes after its close, for the same reason.
- The stream example hands a message before the pool took the one before. Over h2 the server
  sends a message back only after the connection wrote it, so the take always comes first.
