# Design §8 step 25: a route table that calls the program's functions

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 127](../../decisions/0127-the-server-reads-a-requests-query.md) rulings 2 to 5. The owner approved the names on
2026-10-25.
- **The table.** `server.router(Context, table)` replaces `server.router(Value, table)`. `table`
  is a struct with `error_handler`, `routes` and, optionally, `middleware`. Each route is a
  method, a pattern, a function or a struct, and optionally options such as `.whole_body` and
  `.middleware`.
- **The function form.** A route function has five parameters in this order:
  1. `*Context`.
  2. `*const server.Request`.
  3. The path parameters: a struct with one `[]const u8` field for each `:name` of the pattern,
     and `rest` for a trailing `*`, or `void`.
  4. The query: a struct of `[]const u8` and `?[]const u8` fields, a field with a default value,
     or `http.QueryParameters`, or `void`. A required field that the query lacks gives 400.
  5. `*server.ResponseWriter`.

  It returns `!void`, and its error goes to `error_handler`.
- **The struct form.** A struct with `on_request`, which takes a `*State` after `*Context` and
  else the parameters of the function form, and any of `on_body`, `on_writable` and
  `on_finished`, with a `State` that each pool entry holds. The owner named the four on
  2026-10-25 for the moment each runs, as zap names `on_request`, in place of `head`, `body`,
  `writable` and `finished`, which a reader took for the HEAD method or the endpoint's events.
  `on_body` reads the request body through a `*std.Io.Reader`, and bytes it leaves unread wait
  for the next call. A read past the bytes that arrived fails with `error.ReadFailed` while more
  is to come, and an `on_body` that returns it waits. With `.whole_body`, `on_request` runs at
  the head, and `on_body` runs once, after the last byte,
  with every byte in the entry's `body_bytes`. The owner ruled this on 2026-10-25, since the
  head's slices are gone by the last byte, and a copy of every header would cost each entry a
  whole header section.
- **The router's calls.** `Router.Of(options)` is the type a program places: a pool of
  `options.requests` entries, with `options.response_bytes` of response memory and
  `options.body_bytes` for the request body in each. `memory_bytes` is its size.
  `handle(context, endpoint, event)` takes one event and returns `Handled`: `.taken`, or `.event`
  with the event the program acts on (`send`, `close`, `ended` or `closed`). A request that finds
  no free entry gets 503. A request that matches no route gets 404, 405 with Allow, or 501, and
  the router writes each with no function call. It writes 400 for a query that lacks a required
  pair, 414 for one with too many pairs, and 413 for a body larger than `body_bytes`.
- **`match` stays.** Its `found` gives `Router.Route`, an enum with one tag for each entry, named
  by its method and pattern, such as `.@"GET /users/:id"`, and the path parameters (the owner's
  ruling of 2026-10-25). `bench/router`, `router-check` and the hidden-route checks read it.
- **`server.ResponseWriter`.** The field `status`, which is 200 by default, and `header(name,
  value)`, `body()`, which returns a `*std.Io.Writer` over the entry's response memory, `end()`,
  `trailers(headers)` and `head_sent()`. The first byte of the body sends the head.
  `write_kept(bytes)` sends bytes the program keeps valid until the request's `finished`, with no
  copy, such as a file the program mapped (the owner's ruling of 2026-10-25). Over h3 the bytes
  of `body()` stay in the entry until `finished` (decision 103), so `body()` serves a response of
  `response_bytes` at most, and `write_kept` serves a larger one. Amended on 2026-11-09 by step
  46 (decisions 103 and 127 as amended that day): the writer writes again into memory whose bytes
  the engine released, so `response_bytes` bounds the bytes in flight, not the response.
- **Errors.** The table must name `error_handler`, which the router calls with the context, the
  request, the error and the response writer. Before the head goes out it chooses the status.
  After the head, the router ends or cancels the response itself.
- **Middleware.** A struct with any of `on_request`, `on_finished`, `wrap_body` and
  `wrap_response`, and with `finish_response` beside `wrap_response` (25.6). `on_request` takes
  the context, the request and the response's writer, and returns `server.middleware.Next`:
  `.next` or `.answered`. The chain runs the route table's middleware first, then the route
  entry's, in table order, one after the other: no middleware calls the next. An error of
  `on_request` goes to `error_handler`. `on_finished` takes the context, the request's id and its
  `server.Result`, and runs in the reverse order when the request ends, for each middleware whose
  turn came, as code after `next()` runs in Express or Go (the owner's ruling of 2026-10-25). A
  route table holds its middleware in its `middleware` field, and a route entry in its options, as
  `.{ .middleware = .{Guard} }`. `server.middleware.decode_request` and
  `server.middleware.encode_response` are colibri's two, and `Response.codable` and the encoder
  pools leave `server.Config` (decision 101 as amended).
- **Sub-steps.**
  - 25.1: this text.
  - 25.2: `server.ResponseWriter`, with the test that lists its names.
  - 25.3: `router(Context, table)` with the function and the struct forms, `Route`, `Of`,
    `handle`, `Handled`, `error_handler`, the body reader, `.whole_body`, `writable` and
    `finished`. `bench/router`, `router-check`, the examples and docs/usage.md move to the new
    table. The struct form came forward from 25.5, because the server example's POST reads its
    body.
  - 25.4: the refusals at compile time of a route's function, its struct, and its path and query
    structs, each naming its route.
  - 25.5: middleware with `on_request` and `on_finished`, the route table's and the route
    entry's, and `server.middleware` with `Next`. The struct form's four functions take their
    `on_` names. The refusals of a route table as a whole gain names, as a route entry's have.
  - 25.6: a middleware's `State`, `wrap_body`, `wrap_response` and `finish_response`, which the
    owner approved on 2026-10-26, and the tests of a chain of two wrappers:
    - Each request's entry holds one `State` for each middleware of its chain, and `memory_bytes`
      counts them. Each field of a `State` has a default value, as a struct route's does.
    - `wrap_body(*Context, *State, *const server.Request, *std.Io.Reader) ?*std.Io.Reader`
      runs at the head, after the middleware's `on_request` returns `.next`. The reader it
      returns is what the next middleware wraps and what the route's `on_body` reads. Null keeps
      the reader it got.
    - `wrap_response(*Context, *State, *const server.Request, *server.ResponseWriter,
      *std.Io.Writer) ?*std.Io.Writer` does the same for the writer that `body()` returns. It may
      add a header, such as Content-Encoding. A wrapper writes nothing before the route starts
      the body, because the headers are still open. `write_kept` then copies its bytes through
      the writer, because a wrapper must see each byte.
    - `finish_response(*Context, *State) !void` writes what a wrapper owes at the end, such as a
      gzip trailer, as `std.compress.flate.Compress.finish` does. With a wrapper, the route's
      `end` and `trailers` only record that the response ends. When the route's call returns,
      the router calls each `finish_response` from the route's side outward, or flushes a writer
      whose middleware declares none, and then ends the response. So Content-Length counts the
      coded bytes. An error of `finish_response` cancels the request.
    - The owner ruled the same day that the router runs the chain, and that no middleware calls
      the next one: a function such as Express's `next()` would return at the head, before the
      body. Code that runs at the end goes in `on_finished`.
  - 25.7: `decode_request` and `encode_response`, and the removal
    of `codable` and the encoder pools from `server.Config`. It waits for the `std.Io` adapters of
    stdx's decoders and encoders, which decision 127 places in stdx:
    https://github.com/c4milo/stdx/issues/21. The owner ruled on 2026-10-25 that
    `encode_response` is one middleware, configured with the codings it may use in order of
    preference, such as `.codings = &.{ .br, .gzip }`: it reads Accept-Encoding and picks the
    first coding the client accepts. The same day, the owner added the brotli and zstd encoders'
    adapters to [stdx#21](https://github.com/c4milo/stdx/issues/21), once stdx builds those encoders
    (https://github.com/c4milo/stdx/issues/8, https://github.com/c4milo/stdx/issues/7).
