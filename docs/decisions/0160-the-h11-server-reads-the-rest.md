# Decision 160: The h11 server reads the rest of a body that its response did not wait for, or closes in stages

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-09, for v0.16.0 (design §8 step 47). connectrpc's conformance case
`unexpected-verb` over h11 sent a POST with content, and the router answered 405 at the head. The
server closed with the body unread, and the client read a reset in place of the 405. RFC 9112 §9.6
names the cause: a reset "might erase the client's unacknowledged input buffers". RFC 9112 §9.3 has
a server read the whole request body or close after its response. This decision amends decisions 92
and 119.
1. A final h11 response that completes before its request's body is read whole starts the
   `discard` phase of `h11.Connection`. The connection reads the rest of the body, reports
   none of it, and then reads the next request. It does so when the rest has a known length
   of at most `server.constants.limits.discard_len_max`, 262,144 bytes (256 KiB), or is
   chunked and ends within that many bytes.
2. Past that bound, for a request with the close option, or when the bound is 0, the
   connection closes in stages (RFC 9112 §9.6):
   - The engine reports `half_close` once the response is out. The program closes only the
     write side of the socket, and passes on what the socket reads. The engine discards it.
   - The engine reports `close` when `server.constants.limits.half_close_ns`, 1 s, has
     passed since the `half_close`. A program whose peer closes first calls
     `transport_closed`, as before.
3. Decision 110's deadlines hold while the body is discarded. The body's bytes count for its
   rate, and its deadlines end with it. A peer that drips the body is cut at the body's
   deadline, with no 408 after the response. The 1 s bound is a deadline that `deadline_ns`
   names, and colibri reads no clock.
4. Two names are new:
   - `h11.Connection.Options.discard_len_max`, 0 by default, which keeps h11's behaviour for
     a program that drives h11 itself. The server passes its limit.
   - `server.Event.half_close`, the one new call that a program makes: it closes the write
     side of a socket. The `colibri` module and `src/testing`'s endpoints submit Rotor's
     `shutdown` operation for it. Item 6 amends this for the `colibri` module.

   The new field breaks a program whose `switch` names every field of `server.Event` and
   has no `else`. The owner ruled on 2026-11-10 that this work ships in v0.16.0 for that
   reason, and not in v0.15.2.
5. A response says that the connection closes when the server knows it. RFC 9110 §10.1.1
   has a server that answers before it reads the whole content say whether it closes. A
   final response that ends at its head carries `Connection: close` (RFC 9112 §9.6) in
   three cases:
   - The request carried the close option.
   - The rest of the body has a known length past the bound.
   - The bound is 0.

   Two responses cannot know, and their heads say nothing:
   - A response whose body is still open when its head goes out. The program can read the
     request body before the response ends, so the end of the response decides.
   - A response to a request whose chunked body is not read whole, with a bound above 0.
     Only the read finds where a chunked body ends.

   After each of the two, the half-close tells the client that the connection closes.

   Amended on 2026-11-16, after connect-zig's report from connectrpc's conformance suite.
   The half-close loses a race: Go's client finished its request, got the response with
   no close option, and sent its next request on the connection, which then gave it
   end-of-file. So the head says the close in both cases, as Go's server does:
   - A final response head that goes out while the request body is open carries
     `Connection: close` when the rest has a known length past the bound, or is chunked.
     It does so whether the response ends at its head or its body is open.
   - The `discard` phase reads only a rest whose known length fits the bound. A chunked
     rest is never discarded, since no head knows where it ends.
   - The cost: a route that answers before the body ended, to a request whose rest is
     past the bound or chunked, loses keep-alive on that connection, even when it later
     reads the whole body.

   Amended again on 2026-11-16, after connect-zig's test of v0.17.2, which holds the
   amendment above. A stream route answers before its request body ends, and still reads
   that body: each Connect, gRPC and gRPC-Web stream over h11 does. Its chunked request
   made each head say the close, so each stream cost its connection. colibri's client
   pool then ended a call that waited behind two such streams as `refused` (decision
   124). RFC 9110 §10.1.1 names two things that a server may say: that it closes, or that
   it continues to read the content. So the program says which, and the owner ruled the
   name:
   - `server.ResponseHeader.request_body` is `.discard` or `.keep_reading`, and
     `.discard` is the default. With `.discard` the head follows the amendment above.
     With `.keep_reading` the head says nothing on account of the request body.
   - `server.Router` sets the field for each route. A response that is open when its
     head goes out gets `.keep_reading`, because its route still gets the body. A
     response that its route ended gets `.discard`.
   - When a response with `.keep_reading` ends before the request body does, the
     `discard` phase reads the rest: a known length that fits the bound, or a chunked
     rest up to the bound. Past the bound the connection closes, and no head said so. No
     head can, because it went out before the program stopped.
   - `h11.Connection` holds the field `request_body` with the same two values. A
     server's program sets it before `write_response`, and each request starts at
     `.discard`.
   - The owner chose the two names on 2026-11-16, in place of `.drop` and `.read`.
6. Amended by decision 159 on 2026-11-10, for item 4 (decision 159's ruling 9 of that day).
   In the `colibri` module, the driver writes the host operation `shutdown_send` for
   `half_close`. On `.hosted` the program's host shuts down the write side. On `.private`
   colibri's Rotor adapter submits Rotor's `shutdown` of the send side. `src/testing`'s
   endpoints submit Rotor's `shutdown` themselves, as item 4 says.

Alternatives that lost:
- Close at once, as before. The client can read a reset in place of the response.
- No close option in a response that ends at its head, which was the first build. The
  server knows that it closes, and RFC 9110 §10.1.1 has it say so.
- The close option in each response that goes out before the body is read. The connection
  then closes after a body that the `discard` phase can read.
- A discard limit that a program names, in place of the close option in the head, which
  connect-zig proposed on 2026-11-16. A chunked body past the limit still closes with no
  word to the client.
- The close option in each head that goes out while a chunked body is open, which v0.17.2
  shipped. Each stream over h11 that answers before its request ends then costs its
  connection.
- A stream library that holds its head until the request body ends, which connect-zig
  offered to build on 2026-11-16. Each library on colibri must then do the same.
- No close option while the response's body is open, which v0.17.1 had. A response that
  its route wrote whole in one call then closed the connection with no word to the
  client.
- Read the whole body, with no bound. A peer with a large Content-Length holds the connection
  for as long as it sends.
- A staged close with no event: the engine waits with the socket open, and then reports
  `close`. Without the half-close the client does not see the end of the response, and RFC
  9112 §9.6 starts with the half-close.
- A bound in `server.Limits` or `server.Timeouts`. The owner ruled two named limits.
