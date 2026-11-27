# Decision 127: The server reads a request's query, and a route table calls the program's functions, with middleware

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-20 and 2026-10-21. Amends decisions 101, 118 and
122. The owner asked how other Zig servers do it. http.zig, zap, jetzig and tokamak each call
a handler that the program registers. Zig's own `std.http.Server` reads a body through a
`std.Io.Reader` and writes one through a `std.Io.Writer`. colibri had matched its pull loop
and its caller memory, and not its bodies.

The rulings:
1. The query.
   - `server.Request.path` holds the path alone, and `server.Request.query` holds the raw
     query, or null. Beat: the path with its query, which every program split itself.
   - `http.QueryParameters` reads the `name=value` pairs of a query by name, with `get`,
     after the WHATWG URL Standard's `application/x-www-form-urlencoded` parser
     (`urlencoded-parsing`). It decodes `+` as a space and percent-decodes (RFC 3986 §2.1)
     into a buffer the program gives.
   - The URL Standard becomes a source beside qlog's drafts, pinned in `docs/rfcs/whatwg/`
     (non-negotiable 10). Beat: RFC 3986 alone, which leaves the pairs to the program.
   - `server.router` percent-decodes a path before it matches it, and no longer refuses a
     `%` (amends decision 122). Path parameters hold the decoded bytes.
2. A route's function. colibri may call a function of the program's, but only inside a call
   the program made, and never from a loop of its own (amends decisions 118 and 122). Beat:
   a table of plain values that the program dispatches, and a framework package that owns
   the sockets.
   - `server.router(Context, table)` builds a router type at compile time. `Router.Of` sizes
     its pool of request entries, which the program places. `router.handle(context,
     endpoint, event)` takes the events of a request and calls the route's functions.
   - A route holds a function, which answers at the head, or a struct with `on_request` and
     any of `on_body`, `on_writable` and `on_finished`, and a `State`. Both forms stay. The
     owner named the four on 2026-10-25, in place of `head`, `body`, `writable` and
     `finished`.
   - The function runs at the head. The body comes in later calls, through a
     `std.Io.Reader`, and bytes the function leaves unread wait for the next call. A route
     may ask for one call with the whole body.
   - The response goes through `server.ResponseWriter`: a status, headers, and a body that
     is a `std.Io.Writer` over the entry's memory. A struct with `on_writable` writes a large
     response over many calls. Beat: answering at the head with no body, and large bodies
     left for later.
   - A request that finds no free entry gets 503.
3. The compiler checks the table. Each function's parameters, the parameter struct against
   the pattern's names (`rest` for a trailing `*`), the query struct's fields, each `State`
   and each middleware are refusals, as decision 122's are, each naming its route.
4. Errors. The table must declare an error function, which the router calls with the request,
   the error and the response writer. Before the head goes out it sets the status, and after
   it ends or cancels the response. The owner: "The user always decides what status to
   return". Beat: an automatic 500.
5. Middleware. A compile-time chain, global and for each route, that sees the head and may
   answer it, and may wrap the body reader and the response writer (decision 118 reversed).
   - colibri ships two. `server.middleware.decode_request` decodes gzip, deflate and zstd,
     and answers 415 with Accept-Encoding to another coding (RFC 9110 §12.5.3).
     `server.middleware.encode_response` codes a response as decision 101 chooses.
   - The endpoint codes no response any more: `codable` and the encoder pools leave
     `server.Config` (amends decision 101). Beat: coding in both places.
   - The `std.Io` adapters of the decoders and encoders belong in stdx, which colibri asks
     for. Beat: wrappers inside colibri.

The API list of each step comes to the owner before its code (decision 115). Every change is
breaking, and 0.9.0's notes list each one.

**Amended by the owner on 2026-11-09, for design §8 step 46 and v0.15.2,** after connect-zig
reported two limits of long server streams through the router. Neither part adds a public
name.
1. Ruling 2's body writer is a ring over the entry's memory (decision 103 as amended on this
   day). The writer writes again into memory whose bytes the engine released.
   - One write through `body()` goes into the memory whole, or fails with
     `error.WriteFailed` and writes nothing.
   - A write that fails while the engine holds the bytes waits. The router calls
     `on_writable` again once the engine has released room, and only when the writer has
     room.
   - Beat: a field `released_len` on the `writable` event, with `Engine.wait_release` and
     `ResponseWriter.released_len`. It added three public names and a count on each write
     over TCP, and each program had to build its own ring over `write_kept`.
2. Ruling 2's `on_writable` also runs while the request body is open.
   - A call that writes nothing while the body is open does not count toward the cancel of a
     route that holds its request. The next body bytes or the next `writable` call the route
     again.
   - Once the body has ended, the cancel applies as before.
   - A `.whole_body` route keeps the old rule: its `on_writable` runs only after its
     `on_body`.
   - Beat: a route option such as `.duplex`. It added a public name and a second path in the
     router.
3. Decision 110's request body deadlines stay as they are: the engine's `Timeouts`, which a
   program may replace for one connection with `set_timeouts`. They do not change for one
   route. A route that waits for a quiet client in a bidirectional exchange needs a program
   that sets them to null for its connection.

**Amended by the owner a second time on 2026-11-09: "merge flushes",** for commit 46g of
design §8 step 46. A review found that a route which flushes each small message had its
request cancelled at its 17th `flush`. The writer has `response_pieces_max` slots for the
runs that the engine has not released, and an h3 response holds about 7 runs of the caller
until the peer acknowledges them. That `flush` found no free slot, and failed.
1. A `flush` that finds a run in each slot adds its bytes to the newest run that the engine
   has not taken whole.
   - A run that the engine took whole takes none, because the engine may read it again in
     place (decision 103).
   - A run of `write_kept` takes none, because its bytes are the program's.
   - When no run takes the bytes, they stay in the writer until a slot is free.
2. No named limit changes. `response_pieces_max` stays 16.
3. On an h3 path with loss, a small `response_bytes` can keep a response under decision
   110's `send_rate_min`. The text of docs/usage.md that says so is enough, and no code
   changes for it.
4. A write through a middleware's wrapper gets no whole-or-nothing promise now. One
   `writeAll` of one slice through `body()` keeps that promise, and
   [#129](https://github.com/c4milo/colibri/issues/129) records the gap.

The alternatives that ruling 1 beat:
- Raise `response_pieces_max` and `quic_response_pieces_max` to 64. Each router entry and
  each QUIC slot then holds more memory, and a route that flushes often still reaches the
  limit.
- Keep the code, and tell a program not to flush more often than the peer acknowledges. A
  program cannot see the acknowledgments, so it cannot follow that rule.
