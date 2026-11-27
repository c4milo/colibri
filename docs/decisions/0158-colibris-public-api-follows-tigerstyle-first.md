# Decision 158: colibri's public API follows TigerStyle first, and Zig 0.16's std where TigerStyle says nothing

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-07 (design §8 step 45), for v0.15.0. An audit compared each public
name of colibri with the idioms of Zig 0.16's std. It found 12 patterns. A second pass checked 14
more findings: 7 were real, and they join patterns 5, 6, 9 and 10, or make a new pattern 13. The
owner ruled that patterns 1 to 13 go into v0.15.0, with the audit's recommendations, as TigerStyle
adjusts them. For pattern 1, TigerStyle keeps the `*const Config` (ruling 2). This decision amends
decisions 35, 60, 61, 93, 98, 101, 115, 117, 119, 120, 122, 124, 125, 126, 127, 150, 153 (ruling 7)
and 156 (ruling 1).

The rulings:
1. TigerStyle (CLAUDE.md non-negotiable 4) comes first. Where TigerStyle says nothing, a
   public name follows Zig 0.16's std. So these stay as they are:
   - Each function name stays in snake_case, as TigerStyle names it. The audit's question
     13, camelCase as std names functions, loses.
   - `init` of a large struct stays in place, through an out-pointer: `init(self: *T, ...)`.
     The ReleaseSafe fill of a returned value costs a copy (docs/performance.md).
   - An argument over 16 bytes stays `*const T`.
   - `http.QueryParameters` keeps its out-pointer `read`, because the struct is about 1 KiB.
     The audit's `parse`, which returns the value, loses.
2. A type whose `init` takes a `*const Config` copies the fields that it keeps. It keeps no
   pointer to the caller's `Config` (pattern 1).
   - `server.Engine(capacity).init` and `client.ConnectionPool(capacity).init` keep
     `config: *const Config`, and copy into the object each field they read after `init`.
   - A pointer that `Config` holds, such as a pool, an identity or a provider, still names
     the caller's storage. That storage lives as long as the object, as before.
   - A program no longer keeps its `Config` alive after `init`. It needs no global with
     `align(@alignOf(server.Config))`, and `colibri.Server` keeps no copy of `Config` only
     for a stable pointer.
   - `Engine.init` takes one `server.Instant`, with the fields `ns` and `unix_seconds`, in
     place of the two adjacent `u64` values `now_seconds` and `now_ns`. The compiler then
     refuses two instants in the wrong order.
   - Ruling 19 amends this ruling: `server.Timestamp` replaces `server.Instant`, with the
     fields `unix_seconds` and `monotonic_ns`.
3. A type function takes the name of the thing (pattern 2). Ruling 1 of decision 156 now
   applies to each `*Of` name and each `Default*` alias.
   - `server.Engine(capacity)` replaces `server.EndpointOf(capacity)` and
     `server.Endpoint`, the type of the default capacity. A program writes
     `server.Engine(.{})`. Ruling 15 gives the name.
   - `client.ConnectionPool(capacity)` replaces `client.ConnectionPoolOf(capacity)` and
     `client.ConnectionPool`.
   - A pool with defaults takes one struct of comptime values, and the `Default*` alias
     goes. `server.EncoderPool(.{})` replaces `server.DefaultEncoderPool`, and the same
     holds for `server.DecoderPool`, `client.DecoderPool`, `client.ReceivePool` and
     `quic.Connection.SendScratch`.
   - Each such struct has a public name: `server.EncoderPoolOptions`,
     `server.DecoderPoolOptions`, `client.DecoderPoolOptions`, `client.ReceivePoolOptions`,
     `quic.ReceivePoolOptions` and `quic.Connection.SendScratchOptions`. `Capacity` stays
     the name of the sizes of a type that holds connections, as decision 156 names it.
   - `client.ZstdDecoderPool(count)` and `client.BrotliDecoderPool(count)` have no default
     and no alias, so they keep their one count.
4. The router is a type function (pattern 3). `server.Router(Context, table, options)`
   replaces `server.router(Context, table)` and `@TypeOf(routes).Of(options)`.
   - The program places one `Router` and passes it to `colibri.Server.init`, as it placed
     the pool of `Of` before.
   - `Router.match`, `Router.Route` and `Router.Match` are declarations of the type.
     `match` takes no value, because the table holds no state.
   - `server.RouterOptions` names `requests` and `response_bytes`, which `Of` took.
   - Each compile error of a table starts with "server.Router:".

   Amended on 2026-11-23 (design §8 step 70). `Router.init(router: *Router)` starts the
   router in place, as ruling 1 asks of a large struct. `.{}` still compiles, but it copies the
   router's whole default value from the program's image, with each entry's buffers
   ([#148](https://github.com/c4milo/colibri/issues/148)).
5. `http.Status` is one non-exhaustive `enum(u16)` with `_` (pattern 4), as
   `std.http.Status` is. RFC 9110 §15 allows any status code of three digits, and `_` holds
   each code that the enum does not name.
   - The enum holds the names of `http.status.Code`, and the namespace `http.status` goes.
   - `Status.Class`, `Status.Error`, `class`, `from_code`, `from_digits`, `write_digits` and
     `is_recognized` are declarations of the enum. `from_code` and `from_digits` refuse a
     value outside 100 to 599 (RFC 9110 §15).
   - `server.Response.status`, `server.ResponseWriter.status` and `client.Response.status`
     take `http.Status`. `server` and `client` re-export it as `Status`.
   - `client.Response.status` has no default of 0. A program reads `result` to know whether
     a final status arrived.
   - Ruling 17 amends this ruling: `from_digits` accepts a code outside 100 to 599.
6. Each type in a public signature has a public name, as a declaration of the type whose
   calls take or return it (pattern 5). Design §8 step 45 lists each name.
   - The types of one exported type's calls move from the file's lowercase namespace into
     the type: `h2.connection.SendError` becomes `h2.Connection.SendError`, and
     `core.writer.Error` becomes `core.Writer.Error`.
   - A file's namespace stays when it holds names that belong to no one type, such as
     `http.field.validate_name`.
   - `tls.record` exports `Error`, `Progress` and `ConfigError`, which its sessions return.
   - `quic.Connection.Options` and `quic.Connection.IdentityOptions` name what
     `quic.Connection.init` takes. Today they are file declarations that no path names.
   - `colibri.Client.InitError` and `Client.RunError` come from decision 156 and step 44.
     The run error of a client holds no error of the server.
7. Each type and each call has one public path (pattern 6).
   - `http.FieldSection.clear` goes, because it only calls `init`.
   - `h2.connection.Event` goes, and `h2.Event` stays.
   - `h2.connection_tls.attach` goes, and `h2.Connection.attach_tls` stays.
   - `h2.connection.Request_` becomes `h2.Connection.RequestHead`, the request that
     `write_request` writes.
   - The top-level name stays for each type that the root exports twice. The namespace copy
     goes: `crypto.suite.Level`, `crypto.suite.Direction`, `crypto.suite.Role`,
     `tls_provider.provider.Content`, `tls_provider.quic_provider.VTable` and
     `hpack.encoder.Indexing`. Decision 115's root order puts each type under its own name.
   - `tls_provider.Provider.is_complete` goes, and the method `handshake_complete` of
     ruling 14 stays. The two change in one commit, so no caller writes a raw vtable call.
8. A public path follows the concept, not the file (pattern 7). This amends decision 115.
   - A type may hold a declaration alias of a function in another file of its module:
     `pub const send = @import("connection_send.zig").send;`. A program then calls
     `connection.send(...)`, and each file still stays under 500 lines.
   - Such an alias is a call that a program makes. It is not a method made public so that
     another file can call it. A call that only the module's own files make stays a free
     function, as decision 115 rules. The root does not export its file.
   - No public name repeats itself. `quic.Stream`, `quic.StreamId`,
     `quic.StreamProvider` and `quic.Frame` replace `quic.stream.Stream`,
     `quic.stream.StreamId`, `quic.stream.StreamProvider` and `quic.frame.Frame`.
     `quic.Stream` is the stream that a connection holds. `quic.frame.Stream` stays the
     STREAM frame (RFC 9000 §19.8).
   - `quic.ConnectionClose` is the one path of the CONNECTION_CLOSE frame (RFC 9000
     §19.19), with `ConnectionClose.transport` as its declaration.
     `quic.frame.frame_control.ConnectionClose` goes, and `frame` holds no copy of it
     (ruling 7).
   - The 41 calls that a program makes on a `quic.Connection` become declarations of
     `quic.Connection`. A name that two files share takes its concept: `idle_deadline_ns`,
     `open_stream` and `owe_close`. `quic.connection_send.Ecn` becomes `quic.Ecn`.
   - The names that only the simulator, the corpus and the test endpoints call stay in
     their file namespaces, under the comment that says so. A program never sees them on
     `quic.Connection`.
   - `http.uri_percent` and `http.uri_query` fold into `http.uri` and
     `http.QueryParameters`. `h11.connection_tls`, `h2.connection_tls` and the
     `connection` namespaces of h11, h2 and h3 fold into each `Connection`. The free
     functions of `h11.coding` become declarations of `h11.coding.Decoding`.
     `http.content_coding.read_accept` becomes `Acceptance.read`, and
     `h3.frame_write.write_header` becomes `h3.frame.write_header`.
   - The owner's ruling reverses an alternative that decision 115 refused: "methods on
     `quic.Connection`", at about 600 call sites. A program reads the calls of one type in
     one place, as in `server` and `client`.
9. A bare bool in a call or a result becomes a named value (pattern 8).
   - `client.ConnectionPool.write_body(id, piece, end)` takes `end: client.PieceEnd`, an
     `enum { more, last }`. This amends decision 153 ruling 7.
   - `h3.Connection.write_request` takes an `h3.Connection.RequestHead`, which holds
     `section`, `indexing` and `hold_data`, as h2's `RequestHead` holds its choices.
   - `http.message_request.check` returns an `http.message_request.Kind`,
     `enum { connect, other }`, in place of a bool that is true for CONNECT.
   - `client.Request.never_indexed.headers` holds the never-indexed headers as a
     `[]const Header`, after `Request.headers`, as std's `privileged_headers` does. It no
     longer holds one bool for each header, whose count had to match at run time. The pool
     still marks each such field never indexed in h2 and h3 (RFC 7541 §7.1.3, RFC 9204
     §7.1.3). `never_indexed.path` stays a bool, because it names one value.
10. The three HTTP connections have one `init` shape, `init(*Connection, options)`, with the
    role in the options (pattern 9).
    - `h11.Connection.init(role, options)` and `h2.Connection.init(role)` take
      `h11.Connection.Options` and `h2.Connection.Options`. h3's form does not change.
    - A pool that a program places has `init(pool: *Pool, features)`, as std initializes
      large state in place. This amends decision 98.
    - `reset` leaves the program's calls of the storage types `h11.coding.Storage`
      (`server.Decoders` and `client.Decoders`), `client.ZstdDecoders` and
      `client.BrotliDecoders`. Their pools gain `init`, and `storage()` stays.
    - `server.EncoderPool.reset` becomes `server.EncoderPool.init`, and `encoders()` stays.
    - The QUIC `ReceiveStorage.reset` stays. `quic.Connection.init` calls it, and it resets
      the pool at the start of each connection, as `std.heap.FixedBufferAllocator.reset`
      does.
11. A value has the type that std gives it (pattern 10).
    - `h11.Connection.failure` is a `?h11.Connection.Failure`, a named error set, not
      `?anyerror`. `fail` takes a `Failure`.
    - `dnssec.Error` spells each failure out: `SignatureVerificationFailed` replaces `Auth`,
      and `InvalidEncoding` replaces `Invalid`, as `std.crypto.errors` names them.
    - `tls.record.Client.alert` and `Server.alert` return `?tls_provider.Alert`, not `?u8`.
    - `client.RequestId` is an `enum(u64) { _ }`, an opaque id, not a `u64`.
    - `h2.frame.Header.type` is an `h2.frame.Type`, which the root now exports. The `_`
      member holds each frame type that RFC 9113 §4.1 and §5.5 tell a receiver to ignore.
      `flags` stays a `u8`, because the meaning of each flag bit changes with the type.
12. A name says what the call does (pattern 11).
    - `quic.connection_timer.next` becomes `quic.Connection.deadline`. It returns the same
      value on each call, so it is not an iterator's `next`.
    - `quic.connection_qlog.init` becomes `quic.Connection.attach_log`. It runs on a
      connection that `init` already made.
    - `send` takes `comptime options: SendScratchOptions` and
      `scratch: *SendScratch(options)`, in place of `scratch: anytype`.
13. `core.Reader` and `core.Writer` name each read that consumes `take_*`, and each integer
    codec names its byte order (pattern 12).
    - `take_byte` replaces `read_byte`. `take_int_big` and `write_int_big` replace
      `read_int` and `write_int`. The wire is network byte order (RFC 9113 §2.2, RFC 9000
      §1.3), and the name now says so.
    - The types stay. Invariant 3 needs a read and a write that are all or nothing.
14. An interface has one method for each member of its vtable (pattern 13).
    `tls_provider.Provider` gains 13 methods, one for each member of `Provider.VTable`, as
    `tls_provider.QuicProvider` and `std.mem.Allocator` have. A program calls
    `provider.negotiated_parameters()`, not `provider.vtable.negotiated_parameters(
    provider.context)`. Only an implementer writes the vtable.
15. `server.Endpoint` becomes `server.Engine`, a type function: a program writes
    `server.Engine(.{})`. The owner ruled the name on 2026-11-07, after this decision was
    written. He chose it over `server.Connections` and over `server.Endpoint`.
    - The directory `src/server/endpoint/` becomes `src/server/engine/`, and each file
      `endpoint_*.zig` becomes `engine_*.zig`.
    - Prose, the decisions that comments cite, docs/usage.md and the examples say
      "engine".
    - The owner ruled two more names on the same day. The CONNECTION_CLOSE frame's one
      public path is `quic.ConnectionClose`, not `quic.Close` (ruling 8). The connection ID
      options are `quic.Connection.IdentityOptions`, as ruling 6 names them.
16. Amended by the owner on 2026-11-07, for four findings that the review of step 45 left
    open (design §8 step 45):
    - `client.Response.status` keeps the default `undefined`. A program then writes
      `client.Response = .{}` and names no status. Ruling 5 still refuses a default of 0,
      which is not a status. A program reads `result` to know whether a final status
      arrived.
    - Each field of an options struct has a default. `role` in `h11.Connection.Options`,
      `h2.Connection.Options` and `h3.Connection.Options` is `.server` by default.
      `server.RouterOptions.requests` is 32 by default, one for each connection of
      `server.Engine(.{})`. `response_bytes` is 256 by default, as each example passes.
      Decision 163 ruling 9 took that default away on 2026-11-12, and design §8 step 50g
      removes it and `router_response_bytes_default` (the owner's ruling of 2026-11-14).
    - The two router values size the router's memory, so they are in
      `server.constants.limits`, as ruling 1 of decision 137 says. The owner ruled this on
      2026-11-08. An earlier text put them in `policy`. That was an error in the question
      that the session asked, and not the owner's ruling.
    - `role` in `quic.Connection.Options` is `.server` by default too, as in h11, h2 and
      h3. The owner ruled this on 2026-11-08.
    - The rule has one exception. `local_parameters`, `now_ns` and `identity` in
      `quic.Connection.Options`, and `local_initial_source` and `original_destination` in
      `quic.Connection.IdentityOptions`, keep no default. An instant, the transport
      parameters and the connection IDs come from the caller, and no value is right to
      assume.
    - Five types in a public signature get a public name, as ruling 6 rules:
      `qpack.Encoder.Settings`, `h11.Connection.AttachError`, `h11.Connection.Received`,
      `h11.Connection.Closed` and `h2.Connection.Sent`.
    - `colibri.ServerConfig.endpoint` becomes `colibri.ServerConfig.engine`, as ruling 15
      names the engine. Step 44 rebuilds `colibri.Server`, so the field changes there, in
      44d.
17. Amended by the owner on 2026-11-09, for ruling 5. The client accepts any status code of
    three digits, 000 to 999, over h11, h2 and h3, and gives it to the program as
    `http.Status`. connectrpc's conformance suite sends a status of 800, through connect-zig
    on `client.ConnectionPool`, and `from_digits` refused it.
    - RFC 9110 §15 says: "A client that receives a response with an invalid status code
      SHOULD process the response as if it had a 5xx (Server Error) status code." colibri
      follows the SHOULD.
    - `from_digits` reads what a peer sends, and accepts any three DIGIT bytes. Text that is
      not three digits stays `error.StatusNotThreeDigits`, and the response stays malformed.
    - `class` returns `.server_error` for a code outside 100 to 599. Such a code is a final
      response, never an interim one.
    - `write_digits` writes any code of three digits, so a client can write the code it
      received.
    - The send path does not change. `from_code` refuses a code outside 100 to 599 with
      `error.StatusOutOfRange`, so a server cannot send one. `h3.Connection.write_response`
      checks its `:status` with `from_code` too, since `from_digits` no longer refuses it.
    - No public name changes. The release is v0.15.1.
    - The alternative that lost: a refusal of the response as malformed. RFC 9110 §15 asks
      for a 5xx, and a program then cannot read the response that the server sent.
18. Amended by decision 159 on 2026-11-08, for ruling 6:
    - `colibri.Client.InitError`, `Client.RunError` and `Client.FetchError` apply to
      `.private` alone. They spell colibri's own members, and the Rotor adapter maps Rotor's
      errors onto them. A change of a name in Rotor then breaks no dependent.
    - `init` of a `.hosted` object returns `server.StartError` or `client.StartError` alone.
      `.hosted` has no `RunError`.
    - `error.BufferGroupsFull` leaves `RunError`, and `error.PollersFull` leaves `InitError`.
19. Amended by the owner on 2026-11-10, for ruling 2
    ([#131](https://github.com/c4milo/colibri/issues/131)). colibri and cocuyo name their pair
    of clock readings the same way:
    - `server.Instant` becomes `server.Timestamp`, with the fields `unix_seconds` and
      `monotonic_ns`, in this order and with no default. `ns` becomes `monotonic_ns`.
    - In Zig 0.16, `std.Io.Timestamp` is one reading of a clock, and `std.Io.Clock` says which
      clock. The value has no function and reads no clock, so it is not a clock. Its doc
      comment says that it holds two readings of one instant, where `std.Io.Timestamp` holds
      one.
    - `server.Engine(capacity).init` takes a `server.Timestamp`. cocuyo names its own pair
      `cocuyo.Timestamp`, with the same two fields.
    - The rename breaks each caller, so it ships in v0.16.0. The separate fields of the
      client, such as `colibri.ClientConfig.unix_seconds`, are outside this amendment.
20. Amended by decision 159 on 2026-11-10, for amendment 18 (decision 159's ruling 7 of that
    day). Each name of the error sets is on both kinds:
    - `colibri.Server.InitError` joins the `Server` list. On `.hosted` it is
      `identity.LoadError || server.StartError`, because a hosted server reads its identity.
    - A hosted `Client.InitError` is `client.StartError`. Its `RunError` and `FetchError` are
      `error{}`, because a hosted client has no `run` and no `fetch`.
    - This replaces "apply to `.private` alone", "`server.StartError` or
      `client.StartError` alone" and "`.hosted` has no `RunError`" in amendment 18.

What the amended decisions now say:
- Decisions 35 and 125: the comptime count of a server is `server.Engine(capacity)`, not
  `server.EndpointOf(capacity)`.
- Decision 60: a program calls `quic.Connection.receive`, and
  `quic.Connection.receive_error_code` names the code of its error.
- Decision 61: the program places a `quic.ReceivePool(options)`, not a
  `stream_incoming.Pool(capacity)`.
- Decisions 93 and 115: h2's outgoing request is `h2.Connection.RequestHead`. Ruling 8 holds
  the amendment of decision 115.
- Decisions 98 and 101: a program calls `pool.init(features)` once, then `pool.storage()`,
  or `pool.encoders()` for a `server.EncoderPool`. `DecoderPool` takes a
  `DecoderPoolOptions`.
- Decisions 117 (ruling 6), 122, 127 and 150: the router is `server.Router`, and
  `colibri.Server` takes a router that `server.Router` made.
- Decision 150: the engine's configuration in `colibri.ServerConfig` is the field `engine`,
  not `endpoint`, from step 44 (ruling 16).
- Decisions 119 and 120: the engine and the pool copy what they keep of `Config`, and do
  not read the caller's `Config` while they run.
- Decisions 124 and 126 (ruling 8): `server.Engine(capacity)` and
  `client.ConnectionPool(capacity)` are the type functions, and the `Of` names go.
- Decision 153 (ruling 7): `write_body` takes a `client.PieceEnd`.
- Decision 156 (ruling 1): its reason, that the suffix `Of` says nothing to a program, now
  applies to each `*Of` name and each `Default*` alias.

The findings that stay as they are:
- `client.Address` re-exports `quic.PeerAddress`, which decision 72 keeps free of `std.Io`
  types. `server.Address` stays for the same reason.
- `crypto.Suite`: a program only implements its vtable, and `seal` and `open` are already
  methods.
- `tls.Client` and `tls.Server` are values that two session types read, so they cannot be
  a session's `Options` (decision 120 ruling 1). The sessions keep `start` and `close`.
- The constructor `of`, as in `quic.PeerAddress.of` and `quic.StreamId.of`. A rename at one
  site breaks the convention.
- `hpack.Indexing` and `qpack.Encoder.Indexing` differ, because RFC 7541 §6.2 and RFC 9204
  §4.5.4 differ.
- An error member named after an RFC error code, such as `DecoderStreamError` for
  QPACK_DECODER_STREAM_ERROR (RFC 9204 §6).
- Time as an integer, which the caller passes (non-negotiable 3).
- `client.Request.method` as a byte slice. RFC 9110 §9.1 allows extension methods, which
  an exhaustive enum cannot hold.
- The audit's other rejected findings: the names `Config` and `Capacity`, the sans-I/O
  `receive`, `core.Writer` beside `std.Io.Writer`, the in-place `init` of core, hpack and
  qpack, and the order of the arguments of the wire codecs.

The alternatives that lost:
- camelCase for each function, as std names them. TigerStyle names functions in snake_case,
  and a change touches about 1,800 definitions and each program's hooks.
- `Config` by value in `init`. The struct passes 16 bytes, so TigerStyle passes it by
  `*const`. The copy of the fields that the object keeps does the same work once.
- The engine and the pool keep their pointer to `Config`. Each program then keeps its
  `Config` alive and aligned, and a change to it after `init` changes a running engine.
- The two instants as separate arguments, with a comment. The compiler cannot catch a swap.
- `Default*` aliases beside the type functions. A program learns two names for one thing.
- A struct parameter with no public name for each pool. Ruling 6 gives each type in a
  public signature a name.
- The router as a zero-size value with a type behind `Of`. A program writes `@TypeOf` to
  get the type that it places.
- `http.Status` as a struct around a `u16` beside the enum `http.status.Code`. A program
  learns two types, and `.status = 404` compares with neither.
- `take_int(T, .big)` with the byte order as an argument, as std writes it. colibri reads
  and writes network byte order alone, so the `.little` arm would be code that no caller
  runs.
- The top-level copies removed in place of the namespace copies, at about 20 lines in
  place of about 45. It breaks decision 115's root order.
- A separate call that ends a streamed body, as std's `BodyWriter.end`. The pool holds one
  piece of each exchange at a time, so the last piece and the end are one call.
- Methods on `quic.Connection` for the names that only checks call. A program would see
  them beside its own calls.
- One `init` per protocol as it is. A program learns three shapes for one concept.
- `reset` as the name of a pool's initializer. Std keeps `reset` for a value that `init`
  already made.
- Raw vtable calls through `Provider`. A program writes the context twice in each call.
- `server.Connections` as the name of the engine. The owner chose `server.Engine`.
- `server.Endpoint` kept as the name of the type function. The owner chose `server.Engine`.
- `quic.Close` as the path of the CONNECTION_CLOSE frame. The name does not say which close
  it is, and RFC 9000 §19.19 names the frame CONNECTION_CLOSE.

**Amended on 2026-11-13, at the owner's ruling (design §8 step 51).** The constructor
`of` no longer stays. std names the function that makes a value `init`, and a Zig
programmer looks for that name. So in v0.17.0 each function that colibri named `of` and
that returns its own type is named `init`, public and private, to keep one convention. A
type that holds nothing to release has no `deinit`, as std's `FixedBufferAllocator` has
none. A function named `of` that returns something else keeps its name: `reason.of`, a
phrase; two lookups; and the casts from `*anyopaque`. The owner chose this over two others:
- `of` kept, as the finding above ruled. A Zig programmer finds the name strange.
- `init` for `server.RequestContext` alone. colibri's constructors then use two names.
