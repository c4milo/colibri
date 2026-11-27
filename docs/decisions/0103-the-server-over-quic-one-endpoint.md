# Decision 103: The server over QUIC: one endpoint owns the connections, and the caller keeps each response body until the server reports it done

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-27, for design §8 step 17b and
[#70](https://github.com/c4milo/colibri/issues/70).
- A `server.Endpoint` holds up to a build-time number of QUIC connections. It routes each
  datagram by its first packet's Destination Connection ID (RFC 9000 §5.2), starts a
  connection from a client's Initial (§7.2), and answers Version Negotiation (§6.1) and
  Retry (§8.1.2) itself. It names each request by its connection and its stream. The caller
  passes each datagram with the address it came from, and sends each datagram the endpoint
  writes to the address the endpoint names.
- A response body stays the caller's until the server reports its request done: over h3, once
  the peer has acknowledged every byte (RFC 9000 §3.1) or the stream was reset. `write_body`
  reads the caller's bytes without copying them, and the server keeps only each stream's
  frame headers, as decision 79 has h3's caller do. The same rule holds for h11 and h2,
  which report a request done after the call that writes its last byte, so a caller writes
  one path for every version.

The alternatives refused:
- The server copies each body into send buffers the caller places, and frees them as the
  peer acknowledges. It adds a copy per byte, and the buffers cap the bytes in flight,
  which decision 57 refused for `quic`.
- One object per QUIC connection, with helpers that read a datagram's connection ID. Every
  caller would keep the routing table, the IDs NEW_CONNECTION_ID adds included (RFC 9000
  §5.1.1).

Cost: a caller keeps each response body until its request is done, and the `done` event joins
the server's events for every version.

**Amended by the owner on 2026-11-09, for design §8 step 46 and v0.15.2.** connect-zig
reported that `server.ResponseWriter.body()` stops at `response_bytes` on every version. The
router's response writer now writes again into its body's memory once the engine has released
the bytes there:
- h11 and h2 release them at once, because the connection copies them inside `write_body`.
- A coded h3 response releases them at once, because its encoder copies them into its ring.
- An uncoded h3 response releases them when the peer has acknowledged them (RFC 9000 §3.1).

So the memory that `body()` writes is a ring, and `response_bytes` bounds the bytes in flight,
not the length of the response. The amendment adds no public name. It differs from the first
alternative refused above in two ways:
- That alternative added a copy for each byte and a cap on the bytes in flight to the
  server. `body()` already makes that copy, into the entry's memory, and that memory already
  caps it. A program sets the cap with `response_bytes`.
- The engine's contract does not change. Over h3, `write_body` still reads the bytes it took
  in place, with no copy, and the bytes of `write_kept` stay the program's until the
  request's `finished`.

Cost: over h3, a stream that `body()` writes sends at most about `response_bytes` in each round
trip, so a program that streams sets a larger `response_bytes`.
