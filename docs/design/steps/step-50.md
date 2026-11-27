# Design §8 step 50: the router's handlers: a request's context, whole requests and streams, ruled 2026-11-11 and 2026-11-12

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 163](../../decisions/0163-the-routers-handlers-take-the-programs.md), for v0.17.0, as connect-zig's decisions 35 and 36.
- **Why.** A middleware had no place for what it learns about one request. The option
  `whole_body` changed how the router calls `on_body`, and `on_body` waited with
  `error.ReadFailed`. connect-zig built both a slot and a split of its own, and asked for the
  slot in colibri.
- **The public names,** each listed in decision 115's form:
  - `server.RequestContext`, with `id(ctx) server.RequestId`, `values(ctx, comptime T: type)
    *T`, `path(ctx, comptime P: type) *const P` and `query(ctx, comptime Q: type) *const Q`.
    `init(request_id, comptime T: type, request_values: *T) RequestContext` makes one for a
    test of a program's code, with no router: connect-zig asked for it, and the owner ruled it
    on 2026-11-13.
  - `server.Request` gains the field `body: *std.Io.Reader`. In the engine's event a read of
    it fails (decision 163 ruling 4), and the router gives a function route the whole body.
  - `server.Response`, the new name of `server.ResponseWriter`, with the same calls: `Error`,
    `header`, `body`, `write_kept`, `end`, `trailers` and `head_sent`.
  - `server.ResponseHeader`, the new name of the engine's `server.Response`.
  - `server.RequestBodyStream`, the stream of a request's body, with `next(stream) ?[]const
    u8`, `keep(stream, len: usize)` and `ended(stream) bool`. It holds no header. The plan
    named it `server.RequestStream`, and named a `server.ResponseStream` beside it. The owner
    ruled one response type and this name on 2026-11-14 (decision 163 ruling 6 as amended).
  - `server.RouterOptions.header_bytes`, the bytes of each entry's copy of a header. It has
    no default, and a header past it gets 431 (decision 163 ruling 5).
  - `server.Headers` keeps its calls. It holds `lines` and `first`, so that it reads the
    engine's section or the router's copy (sub-step 50e). `lines` points to an
    `http.FieldSection.Slice` that the connection or the router's copy keeps, so
    `server.Headers` stays at 16 bytes in each event that the engine's layers copy.
  - `http.FieldSection.Slice`, a section's live lines as two slices, with `len(slice) u32`,
    `get(slice, index: u32) Field`, `find(slice, name: []const u8) ?Field` and
    `iterator(slice) Iterator`; and `http.FieldSection.slice(section) Slice`. A
    `server.Headers` reads the router's copy of a header through one.
  - The route table's optional `.Values`, and a route's options `.path` and `.query`: literals
    with no public name (decision 156 ruling 2). The option `whole_body` goes.
- **The callbacks.**
  - A function route: `fn (context, ctx, request: *const server.Request, response:
    *server.Response) !void`.
  - A struct route: `on_request(context, ctx, state, request: *const server.Request, response:
    *server.Response)`, `on_data(context, ctx, state, body: *server.RequestBodyStream,
    response: *server.Response)`, `next(context, ctx, state, response: *server.Response)` and
    `on_finished(context, ctx, state, result: server.Result)`.
  - A middleware: `on_request(context, ctx, request: *const server.Request, response:
    *server.Response) !server.middleware.Next`, `on_finished(context, ctx, result)`, and
    `wrap_body`, `wrap_response` and `finish_response` with `ctx` after the context.
  - The route table's `error_handler(context, ctx, request, failure, response)`.
- **The sub-steps.** Each one lands alone, and the judge compares each with main on the runner
  (decision 163 ruling 8). A sub-step that loses an input past the noise does not land.
  1. 50a, `docs`: decision 163 and this entry.
  2. 50b, `bench`: a POST input for the judge, with a body that arrives with its header and one
     that arrives late, so each path of ruling 5 has a number.
  3. 50c, `feat(server)!`: `server.RequestContext`, `.Values`, and the options `.path` and
     `.query`, in every callback of today's routes.
  4. 50d, `refactor(server)!`: the names `server.Response` and `server.ResponseHeader`.
  5. 50e, `feat(server)!`: a function route gets the whole request, with `request.body` and the
     header's copy for each request with a body. The option `whole_body` goes.
  6. 50f, `feat(server)!`: `server.RequestStream`, `server.ResponseStream`, `on_data` and
     `next`. `on_body` and `on_writable` go.
  7. 50g, `feat(server)!`: `RouterOptions.body_bytes` and `response_bytes` lose their
     defaults (decision 163 ruling 9).
  8. 50h, `docs`: every example, docs/usage.md and `tools/consumer/`, then the judge's record.
- **50b, met 2026-11-12.** The test server's `--routes github` route table gives each of its
  29 POST routes a struct route that reads its whole body. The judge gained
  `h2-routes-post-many`, a body of 128 bytes, and `h2-routes-post-late-many`, a body of 8,192
  bytes. [Run 43302515017](https://github.com/c4milo/colibri/actions/runs/43302515017)
  compared `04065452` with main `03d56223` on the `ubuntu-24.04-arm` runner, at 5 rounds, in
  two jobs.
  - The five inputs that main has are within the noise in both jobs: h2-many 1.0002 and
    0.9997, h2-one 0.9966 and 1.0002, h2-tls-many 1.0008 and 1.0008, h2-tls-one 1.0000 and
    1.0006, and h2-routes-many 1.0010 and 1.0008. The last one is 15 instructions a request,
    under the floor of 0.5%, from the test server's larger route table. No library file
    changed.
  - The two new inputs compare different work, so the run reports a failure that this
    sub-step expects: on main a POST route answers at the header and reads no body.
  - The numbers that the later sub-steps start from, in instructions a request: 20,200 and
    20,150 on h2-routes-post-many, and 37,734 and 38,000 on h2-routes-post-late-many, with a
    noise of up to 2.75% on the second.
  - Mutation, 1 of 1 CAUGHT: the POST route without `whole_body`.
- **50c, met 2026-11-12.** Each route's function, each callback of a struct route, each hook of
  a middleware and the route table's `error_handler` take a `*server.RequestContext` after the
  program's context. The route table's `.Values` and a route's `.path` and `.query` are in. The
  root of `server` exports `RequestContext`, which a program names in each callback.
  - **The first judge run.**
    [Run 43343221401](https://github.com/c4milo/colibri/actions/runs/43343221401) compared
    `1ade23f9` with main `7a8d33f2` on the `ubuntu-24.04-arm` runner, at 5 rounds, in two jobs.
    Each of the seven inputs was within the noise. But h2-routes-many gave 1.0016 and 1.0017
    with a spread of 0.02% to 0.06%: 26 instructions a request, from 16,294 to 16,320. The
    judge's route table names no `.Values`, `.path` or `.query`, so that was the fixed cost of
    a context. The router wrote its 88 bytes at each request, and cleared the path and the
    query after each route's first call.
  - **The trim.** The owner ruled on 2026-11-12 that the sub-step lands after a trim. The cost
    was the same in each job, and five sub-steps follow.
    - An entry of the pool starts with a context that lends nothing, so a request writes its
      id alone. A comptime assertion beside the entry pins that start.
    - `call_on_request` writes and takes back only what the route names. It asserts that the
      context held none before.
    - A `Held` keeps the name of its type as one address, so a context is 64 bytes. `values`,
      `path` and `query` compare the two addresses first, and the bytes when they differ.
  - **The second judge run.**
    [Run 43353525738](https://github.com/c4milo/colibri/actions/runs/43353525738) compared
    `b6bec00c` with main `7a8d33f2` the same way. The commit that landed adds the comptime
    assertion to `b6bec00c`, and no instruction.
    - h2-routes-many gave 1.0002 and 1.0002: 3 instructions a request, from 16,291 to 16,294.
    - h2-routes-post-many gave 1.0015 and 0.9982, and h2-routes-post-late-many 0.9987 and
      1.0023.
    - h2-many gave 0.9997 and 0.9999, h2-one 0.9973 and 1.0020, h2-tls-many 1.0007 and
      1.0001, and h2-tls-one 0.9995 and 1.0006.
  - **Checks.** `src/server/router/router_context_test.zig` holds 10 tests over h11, h2 and
    h3. `zig build router-check` gained the refusals `request_context_parameter`,
    `values_type`, `values_not_struct`, `path_not_type` and `query_not_type`. `zig build
    colibri-loop-check` gained four halts: `values`, `path` and `query` asked with a type the
    router did not lend, and `path` asked by a middleware, before the route's first call.
  - **Mutations, 18 of 18 CAUGHT.**
    - Nine of the callbacks: the values not reset; another id; the path and the query kept
      after the call; an empty path; no query read; the context started again at
      `on_finished`, or after the chain; a path, or a query, that names no type.
    - Nine of the trim: the path, or the query, not taken back; the id not written; each name
      equal to each other; names compared by address alone; a name that is not null at the
      start; the type not compared; the halt of a call with none lent; an entry whose context
      starts `undefined`. No test caught the last one at first, because the compiler wrote
      zero there. The comptime assertion now refuses it.
  - **Runs.** `tools/ci.sh` on `77d49d96`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31
    checks passed, and the TLA+ check is the nightly job's. The `server` module's tests in
    Debug for x86-64 Linux, in an amd64 container: 649 of 649.
- **50d, met 2026-11-12.** `server.ResponseWriter` has the name `server.Response`, and the
  engine's header struct has the name `server.ResponseHeader` (decision 163 ruling 7). The
  files of the type are in `src/server/response/`, under the type's name. No call changes.
  - [Run 43357801311](https://github.com/c4milo/colibri/actions/runs/43357801311) compared
    `6d328819` with `77d49d96`, the commit of 50c, on the `ubuntu-24.04-arm` runner, at 5
    rounds, in two jobs. Each input is within the noise. h2-routes-many gave 1.0001 and
    1.0002. Its user instructions a request differ by less than 1: 13,891.0 and 13,891.7 in
    one job, and 13,891.6 and 13,892.4 in the other. The commit that landed changes four
    comments, one test's name and one fixture's alias in `6d328819`, and no instruction.
  - Three reviewers read the commit, each for one thing: the truth of each changed sentence,
    the names that the rename missed, and the rules of a public API. They found those six
    places, and no fault in the code.
  - Mutations, 2 of 2 CAUGHT: the root exports the old name; the root exports no
    `ResponseHeader`.
  - **Runs.** `tools/ci.sh` on `3d44f103`, on the same machine: 31 of 31 checks passed. The
    `server` module's tests in Debug for x86-64 Linux, in an amd64 container: 649 of 649.
- **50e, part 1, met 2026-11-13.** `server.Headers` reads its lines through an
  `http.FieldSection.Slice`, so that part 2 can point it at the router's copy of a header. The
  owner ruled the name `Slice` on 2026-11-13. The part changes no behaviour and copies nothing.
  - **The first judge run.**
    [Run 43370964281](https://github.com/c4milo/colibri/actions/runs/43370964281) compared
    `dec2df9a`, where `server.Headers` held a `Slice` by value, with main `4a813acd`. Each
    input was within the noise, but each counted more user instructions a request:
    h2-routes-many 18, from 13,891 to 13,909, in both jobs; h2-many 19 and 24; and
    h2-routes-post-many 31 and 32.
  - **A trim that lost.** `FieldSection.get` and `find` read a line with no `Slice` built first.
    [Run 43373781578](https://github.com/c4milo/colibri/actions/runs/43373781578) gave 29 on
    h2-routes-many, so it did not land.
  - **The cause.** callgrind counted the instructions of each source line of the test server
    under the judge's routed load, on main and on `dec2df9a`. The reads of a header's lines cost
    less than on main. The files that pass an event along cost about 50 instructions a request
    more: `engine_state_tcp.zig`, `engine_state.zig`, `engine_state_events.zig`, `engine.zig`,
    `connection.zig` and `connection_owed.zig`. Each copies the event by value, and
    `server.Headers` had grown from 16 bytes to 40.
  - **The fix.** `server.Headers` holds a pointer to a `Slice` that the connection keeps beside
    its section, and is 16 bytes again, which a comptime assertion pins. Each TCP and QUIC
    connection grows by the 32 bytes of that `Slice`. `Headers.init` keeps the pointer, so
    the lint rule `kept-options-pointer` excludes `src/server/event.zig`, at the owner's ruling
    of 2026-11-13.
    [Run 43388573905](https://github.com/c4milo/colibri/actions/runs/43388573905) compared
    `fd68d77c` with `4a813acd`: h2-routes-many gave 1.0004 and 1.0003, 3 user instructions a
    request, from 13,892 to 13,895. Each other input is within the noise.
  - **Mutations, 15 of 15 CAUGHT:** `Slice.find` returns the last line, or compares case;
    `slice` drops a line; `Headers` starts at 0, or counts pseudo-header fields; `init` skips
    none; the iterator starts late; the Expect check reads another field; the h11, h2 and h3
    request events, and the h2, h11 and h3 trailers events, read a `Slice` not written again;
    and the lint rule reads `src/server/event.zig`.
  - **Runs.** `tools/ci.sh` on `38a8c66c`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31
    checks passed. In Debug for x86-64 Linux, in an amd64 container: `http` 98 of 98, `server`
    652 of 652, `quic` 957 of 957 and `crypto` 12 of 12. The `client` tests stop at test 209
    of 460 with a segmentation fault there, as main `4a813acd`'s own do, so the emulation and
    not the change fails them. GitHub's `checks` job runs them on x86-64.
- **50e, part 2, met 2026-11-14.** A function route gets the whole request in one call, at
  the body's end (decision 163 ruling 4). `server.Request` gains `body`, a `*std.Io.Reader`.
  `server.RouterOptions.header_bytes` bounds the router's copy of a header, with no default
  and 431 past it. With `header_bytes` 0 the router copies nothing and calls each function
  route at the header (ruling 5 as amended on 2026-11-13). The option `whole_body` goes.
  - **The engine's reader.** A request whose header ended it gets a reader that ends at once,
    and a request whose body is still to come gets one whose every read fails. Each
    connection holds the two, because std's own `ending` is a constant and a read writes it.
  - **The first judge run.**
    [Run 43491731763](https://github.com/c4milo/colibri/actions/runs/43491731763) compared
    `6b81837e` with main `82fb6793`. It lost: a GET cost 108 user instructions a request
    more, and a small POST 472.
  - **The cause, by callgrind.** The function route's call at the header moved into three new
    functions, and the compiler then inlined the pool's `start` into `handle`, whose frame
    grew for every event. The copy made eight bounded writes, and copied each part of an h2
    request although it lies in the copied lines.
  - **The fix.** `start`, `start_ended` and `call` are `inline`, so the call at the header
    stays in `start`, as a struct route's does. The copy makes two copies, of the line records
    and of their bytes, and gives each part that lies in them the same offset in the copy.
    [Run 43606139265](https://github.com/c4milo/colibri/actions/runs/43606139265) compared
    `4b053ee9` with `f4cd4f48`: each GET input within the noise, and h2-routes-post-many
    1.0088 and 1.0072, 163 and 172 user instructions a request more. The owner first refused
    that cost and ruled a copy only before the connection writes its section again.
  - **The copy that waits.**
    [Run 43628275223](https://github.com/c4milo/colibri/actions/runs/43628275223) compared it,
    `21a8b237`, with `c17ca6f4`. It lost more: a GET 94 user instructions a
    request more, a small POST 482, and the late POST 510. callgrind showed why. h2load runs
    ten streams on a connection, so another stream's HEADERS frame comes before most bodies
    end. That path then paid the hold, two calls into the engine, and the copy too. The owner
    accepted the copy at the request on 2026-11-14, at its cost.
  - **The run of what landed.**
    [Run 43635382945](https://github.com/c4milo/colibri/actions/runs/43635382945) compared
    `020553e0`, which differs from `71fb98c3` by one comment, with main `c17ca6f4`.
    h2-routes-post-many gave 1.0044 and 1.0060, 152 and 157 user instructions a request more,
    within the noise in one job and past it in the other. h2-routes-many gave 1.0004 and
    1.0001. Each other input is within the noise.
  - **Runs.** `tools/ci.sh` on `bfb349e7`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31
    checks passed. In Debug for x86-64 Linux, in an amd64 container: `server` 685 of 685 and
    `http` 98 of 98.
  - **Mutations.** 8 of 8 of the first draft, 12 of 12 of its fixes, and 14 of 14 of the copy
    CAUGHT. Among them: the late call reads the engine's request; a bound one byte off; the
    path matched again from another request; a part read from bytes that a later read writes
    again, over h11 in cleartext and over TLS; the copy of a part skipped at the same size.
- **50f, met 2026-11-14.** A struct route is a stream (decision 163 ruling 6 as amended on
  2026-11-14). Its callbacks are `on_request`, `on_data`, `next` and `on_finished`, and each
  one writes the request's one `server.Response`. `on_body` and `on_writable` go.
  - **`server.RequestBodyStream`.** `on_data` takes the stream of the request's body. Its
    `next` gives each piece that has arrived, with no copy, or null when no piece waits.
    `keep(len)` leaves the last `len` bytes of a piece unread, and the next `next` gives them
    joined with later bytes. `ended` turns true once `next` returns null at the body's end.
    Over h11 and h3 that can come in a later `on_data` with no bytes.
  - **The router's rules.** The router copies a kept tail into the entry before the engine's
    event ends, within `body_bytes`, and answers 413 past it. Through a middleware's
    `wrap_body`, a piece holds at most the wrapper's buffer, and kept bytes that fill it get
    413. The router drops the body of a route with no `on_data`, and of a route that ended its
    response. It ends a response that a route with no `next` left open, once the body ended.
  - **Two rulings.** The first build made `server.ResponseStream`, a second type with the same
    fields and calls. It copied about 1,470 bytes between the two around the middleware
    chain, and the owner ruled one type. The owner named the stream `RequestBodyStream`,
    because it holds the request's body alone.
  - **The cost, from the source.** A function route and a request with no body run main's
    code. In a table with no stream route, each entry's `body_stream` is `void`. A stream
    route's body event does a few loads, stores and branches more around `on_data`.
  - **A review.** A second agent read the change and found three faults.
    - A `wrap_body` that returns null keeps the router's reader, but the stream took it for a
      wrapper. A kept tail then got 413, and an end with no bytes left `ended` false. The
      router now tells the two apart at run time.
    - std's flate decompressor rebases fewer bytes than its buffer holds, so a longer `keep`
      trips std's assertion. docs/usage.md bounds `keep` through such a wrapper, and the
      router asserts at the head that a wrapper has a buffer.
    - At the body's end the router drops what `on_data` left unread, and docs/usage.md now
      says so.
  - **Mutations, 18 of 18 CAUGHT:** `next` gives a piece again; `keep` keeps one byte more,
    and one less; a kept tail not joined; a tail past `body_bytes` accepted; kept bytes that
    fill a wrapper accepted; `ended` true before the end; `on_data` after the response ended;
    `next` with no room; a stream route's response left open at the body's end; `wrap_body`
    skipped, with its assertion and without; `keep(0)` ignored; a struct with `on_body` or
    `on_writable` accepted; the parameters of `on_data` and of `next` not checked; and a
    `wrap_body` that keeps the router's reader taken for a wrapper.
  - **The judge.** [Run 43666053443](https://github.com/c4milo/colibri/actions/runs/43666053443)
    compared `3dfa2f89` with main `41fabbff`, at 5 rounds, in two jobs. Each of the seven
    inputs is within the noise in both jobs. h2-routes-many gave 1.0000 and 1.0001, with
    13,901.7 user instructions a request in both trees. h2-routes-post-many gave 1.0005 and
    1.0000. `3dfa2f89` lacks the review's fixes, which change only a stream route's code, and
    no input runs a stream route.
  - **Runs.** `tools/ci.sh` on `08e1b2a3`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31
    checks passed. `78ad4fa3` differs from it by a commit of docs/design.md alone. In Debug for
    x86-64 Linux, in an amd64 container: `server` 711 of 711 on `78ad4fa3`.
- **50g, met 2026-11-14.** `server.RouterOptions.response_bytes` and `body_bytes` have no
  default (decision 163 ruling 9). A program names both, 0 included, as it names
  `header_bytes`. `requests` keeps its default of 32.
  - `server.constants.limits.router_response_bytes_default` goes, with its assertion and its
    pin, because nothing reads it (the owner's ruling of 2026-11-14).
  - Each router of the tests, the examples, `tools/` and `bench/` names both sizes. Each one
    keeps the value it had by default: 256 response bytes and no body bytes. README.md and
    docs/usage.md say that a program names each size.
  - The test of the options checks that `response_bytes`, `body_bytes` and `header_bytes` have
    no default.
  - **Mutations, 2 of 2 CAUGHT:** a default of 256 for `response_bytes`, and a default of 0
    for `body_bytes`.
  - **The judge.** [Run 43679041957](https://github.com/c4milo/colibri/actions/runs/43679041957)
    compared `0d918055` with main `708d45c0`, at 5 rounds, in two jobs. Each of the seven
    inputs is within the noise in both jobs. h2-routes-many gave 0.9999 in both, with
    13,899.5 and 13,899.6 user instructions a request.
  - **Runs.** `tools/ci.sh` on `0d918055`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31
    checks passed. In Debug for x86-64 Linux, in an amd64 container: `server` 711 of 711.
- **50h, met 2026-11-15.** `examples/server_stream.zig` shows a stream route, which no example
  had. One `server.Engine` with a `server.Router` serves a gRPC-shaped POST over h2 in
  cleartext, over the in-memory link. `examples/server_stream_peer.zig` is its client, one
  `client.ConnectionPool(.{ .quic = false })`.
  - The route's `on_data` reads messages of a 5-byte prefix with `next` and `keep`. It writes
    and flushes a reply to each whole message, so each reply goes out before the body ends.
    Once `ended` is true, it ends with `grpc-status` in the trailers.
  - The client hands the body in three pieces, and the first one ends inside the second
    message. It hands each piece once the replies to the whole messages before it came back.
  - The route has no `next` callback. Over TCP the connection copies each reply into its
    output when it takes it, so no write of these small replies fails, and `next` would never
    run. The file's comment says so.
  - docs/usage.md shows the route's `on_data`, and examples/README.md lists both files. Every
    other example, docs/usage.md and `tools/consumer/` took the new calls in the sub-step that
    made each one.
  - **Breaks, 8 of 8 CAUGHT** by `zig build example-server_stream`: `keep` dropped; a reply
    written for a cut message; the trailers left out; `flush` dropped; the test of `ended`
    removed; the trailers written at the first event; `on_finished` that counts nothing; and
    the messages not counted.
  - **Runs.** `tools/ci.sh` on `a2790d1e`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31
    checks passed.
- **50i, met 2026-11-15.** connect-zig moved `connect_colibri` to `2e07fe41`, and reported
  what the API left out. The owner ruled two changes to `server.RequestBodyStream` (decision
  163 ruling 6 as amended again).
  - At the body's end, `next` gives the kept bytes once more as a last piece. A unary Connect
    call, whose body has no length, keeps it whole until the end and reads it in place, with no
    copy into its State.
  - Through a wrapper, the router copies kept bytes into `body_bytes` and joins later bytes
    there, and asks the wrapper for one byte past what it gave out. The 413 for kept bytes
    that fill a wrapper's buffer goes. A test wrapper that keeps a window, as std's flate
    decompressor does, asserts on a larger `rebase`, so the old code fails the new tests.
  - docs/usage.md says that a test that builds a `server.Request` passes its own reader as
    `body`, such as `std.Io.Reader.fixed(&.{})`. A public reader would need a mutable global,
    which the global-state lint refuses.
  - `RequestBodyStream` grows from 32 to 48 bytes, in each entry of a table with a stream route.
  - **A review.** A second agent drove the router with random bodies, cuts, keeps and ends over
    eight routes, 20,000 seeds each, through five window wrappers and a chain of two. It wrote
    junk over each event's bytes and over what each wrapper dropped. It found no fault, and
    one rule that no test guarded, which a test now guards.
  - **Mutations, 15 of 15 CAUGHT:** no last piece at the end; a `keep` of the last piece that
    keeps bytes; no `body_bytes` bound on the last piece; no 413 at the end; `next` that asks
    a wrapper for the kept bytes and one more; a copy with no `keep`; no 413 when kept bytes
    fill the storage, or pass it through a wrapper; no clear-space check before the append, or
    after `on_data`; no 413 mid-body for an overflow; `let_go` that tosses a stored piece, or
    that tosses nothing through a wrapper; storage that overlaps the held bytes; and a bound
    one byte short.
  - **The judge**, of 50i, 50j and step 52 together.
    [Run 43721341820](https://github.com/c4milo/colibri/actions/runs/43721341820) compared
    `f3e9bc09` with main `f76136ab`, at 5 rounds, in two jobs, with the h11 inputs. Each of the
    15 inputs is within the noise in both jobs. h2-routes-many gave 13,900.0 and 13,900.1 user
    instructions a request in job 1, and h2-routes-post-many moved by 1 to 4.
  - **Runs.** `tools/ci.sh` on `f3e9bc09`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31
    checks passed. In Debug for x86-64 Linux, in an amd64 container: `server` 739 of 739.
- **The judge of step 50 as a whole.**
  [Run 43681873844](https://github.com/c4milo/colibri/actions/runs/43681873844) compared main
  `29200af3`, after 50g, with `03d56223`, the main that 50b started from, at 5 rounds, in two
  jobs, with the h11 inputs. Main between the two also holds chapulin v0.7.0 and step 35e.
  - Each input of a GET, over h11 and h2, is within the noise in both jobs. h2-routes-many
    gave 1.0014 and 1.0011: 13,877.5 and 13,899.8 user instructions a request in job 1, 22
    more. h11-one gave 1.0048 and 1.0035 by user instructions, under the noise of 0.50%.
    h2-tls-one won in job 2, 0.9942.
  - The run fails on the two POST inputs, which compare different work. At `03d56223` the
    test server's POST routes answered at the head and read no body (50b).
  - Against 50b's start, h2-routes-post-many went from 20,200 and 20,150 instructions a
    request to 20,379 and 20,356: the copy of 50e, whose cost the owner accepted. The late
    POST went from 37,734 and 38,000 to 37,749 and 37,911, within its noise of 2.75%.
- **50j, met 2026-11-15.** The router resets the request's values, a route's State and each
  middleware's state one field at a time (decision 163 ruling 2 as amended), with
  `router_call.reset_to_defaults`.
  - connect-zig's routed-call benchmark found the cost. `.{}` lowers to a copy of the whole
    struct from a constant, its `undefined` buffers too. connect_colibri's State is about
    375 KB, so a unary call took 76,902 instructions, 95.5% of them that copy.
  - Each field takes its default through the field's default pointer, since an optional cannot
    hold an `undefined` default at comptime. A safe build fills an `undefined` field with 0xaa
    through `memset`, so the reset runs with runtime safety off outside Debug. A `memset` of
    vector stores, as pepegrillo's guide gives a program and Zig after 0.16 has, still writes
    the whole buffer: about 14 µs for 375 KB at the guide's 1.2 µs for 32 KiB on an M1 Pro.
  - Disassembly of a State with a buffer of 64 KiB, on arm64: ReleaseSafe and ReleaseFast each
    store the two defined fields alone. `.{}` called `memcpy` of 65,552 bytes in both, and
    the reset with safety on called `memset` of 65,536 bytes in ReleaseSafe.
  - A test checks that a route's State starts from its defaults at each request on an entry,
    and one checks the reset itself.
  - **Mutations, 4 of 4 CAUGHT:** the reset skips each field after the first; a route's State,
    the request's values, or a middleware's state not reset. Runtime safety left on in
    ReleaseSafe is NOT CAUGHT by a test, since a test may not read an `undefined` field; the
    disassembly above checks it.
- **The release judge of v0.17.0, 2026-11-15.**
  [Run 43734512626](https://github.com/c4milo/colibri/actions/runs/43734512626) compared main
  `ecf7ef5a` with v0.16.3 (`6ff19aa4`), at 5 rounds, in two jobs, with the h11 inputs. Main then
  moved to `9d17c88a`, which changes `tools/ci.sh` alone.
  - h2-many, h2-routes-many, h2-routes-post-many and h2-tls-many win, 1.2% to 2.9%, mostly from
    the HPACK encoder's name chains. Each other GET input, over h11 and h2, is within the noise
    but one.
  - h11-one loses by user instructions: 1.0074 and 1.0058, against the floor of 0.50%. It took
    20,443.7 and 20,389.9 user instructions a connection, where v0.16.3 took 20,293.7 and
    20,273.0. The cost grew in steps that each stayed under the floor: about 96 from step 50,
    whose own judge gave 1.0048, and about 30 from 50i and 50j. h11-many is within the noise.
    The owner accepted the loss on 2026-11-15 and ruled the tag.
  - **After the tag, the cause.** The owner asked for it on 2026-11-15. 50e moved `find`, `get`
    and the iterator of `http.FieldSection` behind `http.FieldSection.Slice`, in calls that the
    compiler did not inline, and the iterator copied a `Slice`. Each h11 request pays them in
    its host, Content-Length and transfer-coding reads: about 146 instructions under callgrind.
    `8817617f` marks seven of them `inline`.
    [Run 43747704561](https://github.com/c4milo/colibri/actions/runs/43747704561) compared it
    with `cc86684c`: h11-one 0.9904 and 0.9907, 20,236 and 20,210 user instructions a
    connection, under v0.16.3's. h2-many, h2-routes-many, h2-routes-post-many and h2-tls-many
    win 1.3% to 2.1% too, and each other input is within the noise or wins. `tools/ci.sh`
    passed 31 of 31 on `8817617f`.
  - h2-routes-post-late-many gives 1.0465 and 1.0438, because the two trees do different work:
    at v0.16.3 the test server's POST routes answered at the head and read no body (50b).
- **Checks.** Tests over h11, h2 and h3 for each sub-step, with its mutations. `zig build
  router-check` gets each new refusal. `zig build colibri-loop-check` gets the halts of
  `values`, `path` and `query` with a wrong type. connect-zig moves `connect_colibri` to the
  commit of 50h before the tag, and reports what the API leaves out.
