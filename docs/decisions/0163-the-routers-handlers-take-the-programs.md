# Decision 163: The router's handlers take the program's context, the request's context, a request and a response, and a handler's form says what it gets

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-11 and 2026-11-12, for design §8 step 50 and v0.17.0, as connect-zig's
decisions 35 and 36 split a call. Two things led to it. A middleware had no place for what it learns
about one request but the program's context, which every request of a router shares. And the option
`whole_body` changed when the router calls `on_body`, and with what, so a plain POST route needed a
struct with an empty `on_request`.
 1. Every callback takes `ctx: *server.RequestContext` after the program's context. It is a
    view of the router's entry for the request, and each callback of one request gets the same
    one. Its calls are `id()`, `values(T)`, `path(P)` and `query(Q)`.
 2. The route table takes an optional `.Values = T`, a struct whose fields each have a
    default. Each request starts with `.{}`, and `values(T)` gives it for the whole request.

    Amended on 2026-11-15, after connect-zig's report. The router writes each field's default
    one field at a time, for the values, a route's State and a middleware's state. `.{}`
    copied the whole struct, and connect_colibri's State of about 375 KB cost 95.5% of a unary
    call. Outside Debug a field whose default is `undefined` takes no store, and Debug keeps
    its fill of 0xaa, which shows a read of a field that the program never wrote.
 3. A route's options take `.path = P` and `.query = Q`, in place of the function's path and
    query parameters. The router checks P against the pattern at compile time, and reads Q
    before the call, with 400 or 414 as before. `path(P)` and `query(Q)` answer during the
    route's first call alone. Each call checks its type at run time, and a wrong type halts.
 4. A function route gets the whole request in one call, when the request's body ended,
    unless `header_bytes` is 0 (ruling 5):
    `fn (context, ctx, request: *const server.Request, response: *server.Response) !void`.
    `request.body` is a `*std.Io.Reader` over the whole body, which never waits. A request
    with no body gives an empty reader, and the call comes at the header, as before. The
    option `whole_body` goes. Where a `server.Request` comes before its body, a read of
    `request.body` fails: in the engine's event, in a middleware and in a struct route's
    `on_request`. An empty reader there would read as an empty body.
 5. The router copies a request's header at the request's event, for each request with a
    body on a function route. A request that its header ends costs no copy. The owner ruled this
    on 2026-11-12, in place of a copy only when the body's end comes in a later `receive`
    than the header. The router cannot tell that case: the engine reports one event for
    each `receive`, and h2 and h3 keep one field section for each connection, which the next
    HEADERS frame of any stream writes again. `server.RouterOptions.header_bytes` bounds the
    copy for each entry. It has no default, as ruling 9 says of memory that a program sizes,
    and a header past it gets 431 (RFC 6585 §5). The copy holds a header's live parts
    alone, so `server.Headers` reads its lines through slices, from the engine's section or
    from the copy.

    Amended on 2026-11-13: with `header_bytes` 0 the router copies no header. It calls each
    function route at the header, where a read of a body still to come fails, and it drops
    that body. Over h2 and h3 a GET may end in a later frame, so the router cannot tell at
    the header that no body follows.

    Amended on 2026-11-14, after three judge runs (design §8 step 50e). The copy at the
    request costs a small POST over h2 about 165 instructions, past the noise, and the owner
    accepted that cost. A copy only before the connection writes its section again lost
    more: about 480. h2load runs ten streams on a connection, so another stream's HEADERS
    frame comes before most bodies end, and that path paid its own costs and the copy too.
    The copy gives a part that lies in the copied bytes the same offset there. It finds the
    offset as the difference of two addresses. The owner ruled that such an offset is no
    pointer value in the sense of non-negotiable 5: it follows from the request's bytes,
    at every address. INV-3 and INV-6 say so.
 6. A struct route is a stream. Its `on_request` runs at the header and takes the
    `server.Request`, so it never copies the header. `on_data` takes the stream of the
    request's body, a `server.RequestStream`, and no header: the body is the request's
    payload. The stream gives the body's pieces with `next() ?[]const u8`, because a reader
    cannot say that no piece waits yet. `server.ResponseStream` writes each piece as
    the route gives it, and the router calls `next` when it has room. The callbacks are
    `on_request`, `on_data`, `next` and `on_finished`; `on_body` and `on_writable` go.

    Amended on 2026-11-14 (design §8 step 50f). A stream route writes the one
    `server.Response`, as a function route, each middleware hook and the `error_handler` do.
    `server.ResponseStream` goes. It held the same fields and calls as `server.Response`, so
    it added a name and no behaviour. The stream of the body takes the name
    `server.RequestBodyStream`, because it holds the request's body and no part of the
    response. Its calls are `next`, `keep` and `ended`. `keep(len)` leaves the last `len`
    bytes of a piece unread, and the next `next` gives them joined with the bytes that
    arrive later. So a route reads a message that two events cut, as gRPC and Connect frame
    theirs.

    Amended again on 2026-11-15, after connect-zig moved to step 50 (design §8 step 50i):
    - At the body's end, `next` gives the kept bytes once more as a last piece, with no new
      byte. A `keep` of that last piece keeps nothing, and the call after it returns null and
      makes `ended` true. So a route keeps a body that has no length, as Connect's unary POST,
      until the end, and reads it in place.
    - Through a middleware's wrapper, the router copies kept bytes into the entry's
      `body_bytes` and joins the wrapper's later bytes there. It asks a wrapper for no more
      than one byte past what it gave out. A wrapper's `rebase` may hold less than its buffer,
      as std's flate decompressor does, and the owner ruled that the library prevents that
      mistake. A piece that follows no `keep` stays a slice of the wrapper's buffer.
    - The router's held bytes and the kept bytes share `body_bytes`, with 413 past it, over
      each protocol and with each kind of reader.
 7. `server.ResponseWriter` takes the name `server.Response`, and the engine's header struct
    of that name becomes `server.ResponseHeader`. No other name changes: `server.Request`
    keeps its name and gains `body`.
 8. No measured input may lose. Each sub-step is judged against main on the runner, and the
    judge gets a POST input before the sub-step that copies a header.
 9. `server.RouterOptions.body_bytes` and `response_bytes` have no default, ruled on
    2026-11-12 after connect-zig's report. A program names both, 0 included. With the defaults
    of 0 and 256, a route that reads a whole body answered 413 to a body of 18 bytes, and a
    reply of 1,520 bytes failed, and neither answer named the pool. No value is right to
    assume for memory that a program sizes (decision 158 ruling 16). `requests` keeps its
    default.
10. A test of a program's code makes a context with `server.RequestContext.init(id, T,
    &values)`, which lends those values and no path or query. The owner ruled it on
    2026-11-13, after connect-zig's report. The context's fields stay the router's, and no
    document names them.

 The alternatives refused:
 - A copy that the connection makes only before it writes its field section again, ruled on
   2026-11-14 and refused by the judge the same day (ruling 5 as amended).
 - A function route that never reads a body, and a second field section for each h2 and h3
   connection. The first takes the whole request from the routes that most need it. The
   second costs 17,420 bytes for each connection.
 - A slot that `server.ResponseWriter` gives, with no change of signature. The owner chose
   connect-zig's split.
 - The name `Context` for the request's object. It is the program's type that `server.Router`
   takes.
 - Two calls for a whole body, at the header and at the body's end, which never copy a
   header. The owner chose one call with a copy, and chose it again on 2026-11-12, when the
   copy became one for each request with a body.
 - An event of the engine that tells the router before a lent header changes, so that the
   copy comes only when the body is late. It changes the engine and each protocol's
   connection.
 - A whole `http.FieldSection` for each entry, with no option: 17,420 bytes an entry, where
   the judge's POST header has 171 live bytes.
 - A pool of whole sections with a count of its own, which a program sizes beside
   `requests`.
 - A reader for a stream's body. `std.Io.Reader` reports a body that has no bytes yet as
   `error.ReadFailed`, which is what `on_body` did.
 - A second type for a stream route's response, `server.ResponseStream`, from the same
   definition as `server.Response`. A middleware hook takes a `server.Response`, so a stream
   copied about 1,470 bytes of state to the other type and back, ruled on 2026-11-14.
 - A stream route's body in `server.Request`, whose header the router would copy for each
   stream request too: about 165 instructions on a small POST (ruling 6 as amended).
 - The name `RequestStream`, which suggests a second kind of `server.Request`.
 - Kept bytes that a wrapper's own buffer holds, with a rule in docs/usage.md that a route
   bounds its `keep` through such a wrapper. A long `keep` through std's flate decompressor
   tripped std's assertion (ruling 6 as amended again).
 - The names `RequestHeader` for the engine's request header, and `header_sent` for
   `head_sent`. The owner refused each rename but the response's.
 - Sizes that each route states, from which the router sizes its pool. Most routes would
   write two more options.
 - The defaults of `body_bytes` and `response_bytes`, with what each failure looks like in
   docs/usage.md. A new program would still meet 413 or 500 first.
 - For a test's context, a literal over the context's fields, written in docs/usage.md, or
   no way at all, so that a program tests a route through `server.Router`. The first makes
   the fields part of the API, and the second gives a middleware's own code no test.

 Cost: every route, middleware and error handler of every program changes in v0.17.0, and so
 do connect_colibri's routes. Each router entry grows by a `RequestContext` and by
 `@sizeOf(Values)`. With `header_bytes` above 0 it also grows by `header_bytes`, and by the
 copy's `Slice` and `server.Request`: 176 bytes on a 64-bit target. A request with a body on
 a function route pays one copy of its header, about 165 instructions on a small POST. Each
 connection keeps the `http.FieldSection.Slice` of its event, 32 bytes, so `server.Headers`
 stays at 16 bytes in each copy of an event.
