# Design §8 step 21: one HTTP API

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 117](../../decisions/0117-a-program-names-no-http-version.md) has a program that uses `server` and `client` name no HTTP
version outside `versions`, and serve every connection through one endpoint
([#96](https://github.com/c4milo/colibri/issues/96)). Six parts. Each starts with the tests that
list its public names, beside each type it changes and beside each root (CLAUDE.md, "The public API
is written first").
- **21a, the configuration.** `versions` and `limits`, and cleartext detected.
  - `server.Versions` and `client.Versions`: `h11`, `h2` and `h3`, each true by default.
    `server.Config.versions` and `client.Config.versions` replace `cleartext`.
  - A server connection in cleartext reads its first bytes before it chooses a version: the
    24 bytes of the connection preface (RFC 9113 §3.3) choose h2, and any other bytes h11,
    among the versions `versions` allows. It consumes nothing until it has chosen. A client in
    cleartext speaks h11 when `versions.h11` is set, and h2 with prior knowledge when it is not.
  - `server.Limits` holds `requests_max`, the requests a connection holds at once, which was
    `h2_streams_max`, and `data_frame_len_min`, which leaves the configuration's top level.
    `server.Config.limits` holds them. From 21b, `requests_max` bounds an h3 connection's
    requests too, up to the `quic_requests_max` its table holds.
  - [#96](https://github.com/c4milo/colibri/issues/96) put one TLS value in this part. It comes with 21b, because the endpoint builds both TLS
    configurations and holds a TCP connection only from 21b on. Until then the program's ALPN
    lists choose over TLS, and `versions` governs cleartext alone.
  - Public names: the server's root adds `Versions` and `Limits`, and the client's root adds
    `Versions`. `Config.whole_units`, which only the connection called, leaves `server.Config`
    for a function its files share, and `server.constants.h2_streams_max` becomes
    `requests_max`.
  - **Check:** the h11 and h2 server interop scripts pass in cleartext with the test-only server
    naming no version. h2spec runs twice in cleartext: with the server's `--h2`, which speaks
    h2 alone, every case passes but the two RFC 7540 cases named before; with no version named,
    the case that sends an invalid preface fails too, because RFC 9113 §3.3 has a server that
    speaks both read bytes that are not the preface as h11. Tests show the preface choosing
    h2, other first bytes choosing h11, a partial preface waiting for more, and each version
    `versions` turns off refused. Each rule has a mutation a test catches.
- **21b, one endpoint.** `server.Endpoint` takes TCP connections too, and a program answers
  every request through it (decision 119 records the choices this part made).
  - Types the root adds: `ConnectionHandle` (a slot and its generation, so a handle or an id
    of an ended connection names nothing), `Capacity` (the TCP slots, the QUIC slots and each
    QUIC connection's receive pool, fixed at build time; either count may be 0), `Security`
    (`cleartext` or `tls`, which `accept` takes), `Input` (`none`, `stream` or `datagram`),
    `StreamOctets`, `Datagram`, `Writable` and `Ended`. `Id` becomes a packed struct: the
    connection's handle and the request's number there, which is the h2 or QUIC stream ID, or
    for h11 its place on the connection. `QuicConfig` and `EndpointConfig` fold into `Config`.
  - Events: `Body`, `Trailers`, `Cancelled` and `Done` carry the request's `user_data`, and
    `Event` gains `writable`, `send` (a TCP connection owes bytes), `close` (close its
    socket), `ended` (with the close reason and whether colibri closed it for a protocol
    failure) and `closed` (after `shutdown`, every connection has ended). `CancelReason` gains
    `closed` (the connection stopped first) and `program` (the program's own `cancel`).
  - The endpoint's functions: `init`, `accept`, `receive`, `set_user_data`, `respond`,
    `write_body`, `write_trailers`, `cancel`, `shutdown`, `send_stream`, `send_datagram`,
    `deadline_ns`, `on_instant`, `set_deadlines`, `transport_closed` and `server_name`. h2's
    `Connection` adds `sendable_len`, which `writable` and `send` read.
  - Every request ends with exactly one `done` or `cancelled`, and a connection's `ended`
    comes after them (INV-30). The endpoint keeps a ready ring of the slots that changed, so
    no call scans every slot, and a heap of the slots' deadlines, recomputed lazily for the
    slots a call changed (INV-31). One TLS value: `Config.tls` is a `tls.Server`, whose `alpn`
    stays empty, and the endpoint builds and checks the TCP and the QUIC TLS configurations,
    with the ALPN lists `versions` gives. A TLS client that selects no protocol is served h11
    only while `versions` allows it. `limits.requests_max` bounds h3 too, up to
    `quic_requests_max`.
  - It keeps what step 20 added for h3: a shutdown, or the idle deadline, resets each request
    stream whose head is unread with H3_REQUEST_REJECTED (RFC 9114 §4.1.1).
  - Seven sub-steps, each leaving every check passing:
    - 21b.1: a first Initial whose Destination Connection ID is shorter than RFC 9000 §7.2's
      8 bytes starts no connection. Today a 0-byte one reaches an assertion (INV-24).
    - 21b.2: the id and event types, with each per-connection type's events filled in at the
      endpoint later.
    - 21b.3: the endpoint answers QUIC requests by id: the ready ring, the deadline heap,
      `user_data`, the endings, `writable` over h3, and the QUIC callers moved.
    - 21b.4: TCP slots: `accept`, the `stream` input, `send_stream` and `send`, `close`, and
      `writable` over h11 and h2.
    - 21b.5: `zig build sim -- --endpoint-check`, which runs TCP and QUIC peers through one
      endpoint with fewer slots than connections, and checks each request's one ending, its
      `user_data`, stale ids refused, the heap's deadline against every slot's, and that no
      `send` or `writable` repeats without progress.
    - 21b.6: the TCP callers move, one commit each: the test-only server, the content-coding
      and deadline runs, the two trace runs, the TLS example and the consumer.
    - 21b.7: `Config` names the folded configuration.
  - **Check:** 21b.5's check over seeds. h2spec, h3spec, the h11 and h2 server interop
    scripts, `tools/quic_udp.sh`, `tools/quic_aioquic.sh`, `tools/h3_deadlines.sh` and
    `tools/deadlines.sh` pass on the rebuilt endpoints. The TCP and deadline trace checks pass
    through the endpoint, and the content-coding and deadline CRCs stay as pinned.
- **21c, the client.** `client.Channel` carries every exchange a program makes, builds its
  TLS configurations from one value, and draws what a QUIC connection starts from (decision
  120 records the rulings).
  - `client.Config` is the channel's configuration: `tls` (a `tls.Client`, whose `alpn` stays
    empty), `versions`, `authority`, `codings`, `decoders`, `zstd_decoders`, `br_decoders`,
    `quic_first`, `fallback_delay_ns`, `ecn` and `idle_timeout_ms`. `QuicConfig` and
    `ChannelConfig` fold into it.
  - Public names: the client's root loses `QuicConfig`, `QuicStart`, `QuicStartError` and
    `ChannelConfig`, and exports 44 names where it exported 48. `Config` names the channel's
    configuration, and `StartError` names `TlsRefused`, `NoVersion`, `TooManyAnchors`,
    `TooManySuites` and `SuitesUnavailable`. No name arrives. `client.constants` gains
    `fallback_delay_ns_default`.
  - The channel's functions keep their 15 names: `init`, `request`, `cancel`, `shutdown`,
    `receive`, `send_datagram`, `send_stream`, `deadline_ns`, `on_instant`, `start_quic`,
    `start_tcp`, `transport_closed`, `take_ticket`, `alternative` and `phase`. `init` returns
    `StartError`, and `start_quic` takes no start values: it draws the grease value, the
    source connection ID and the original destination connection ID from its source.
  - `versions` names what a channel offers over TLS as in cleartext, and a client that speaks
    h3 alone opens no TCP connection. A handshake that selects no protocol runs h11 only
    while `versions` allows it.
  - An attempt ends when a connection takes the waiting exchanges, so an exchange no
    connection carried opens each transport once. A channel closes a transport once its
    connection wrote what it owes.
  - Every caller of `client.Connection` moves to a channel with TCP alone.
  - Eleven sub-steps, each leaving every check passing:
    - 21c.1: decision 120, this text, and INV-5 restated.
    - 21c.2: a CRC-32 of the client's bytes pinned in the deadline, content-coding and TCP
      trace runs, before any caller moves.
    - 21c.3: an h11 connection in cleartext reads nothing on a call with no bytes while it
      left some unconsumed.
    - 21c.4: the channel closes a transport after its connection wrote its alert, its
      Finished, or h2's GOAWAY in cleartext.
    - 21c.5: a connection that carried nothing stays counted in its attempt, and the model's
      `TakeAtHandshake` states it.
    - 21c.6: one TLS value, the ALPN lists from `versions`, TCP only when `versions` allows
      it, with the model's `TcpAllowed`, and h11 on no selection only while allowed.
    - 21c.7: the client trace run draws a QUIC connection's start values from its TLS source,
      which changes its census once, and then `start_quic` draws them.
    - 21c.8: the endpoint check's TCP peers run through channels.
    - 21c.9: the test-only client's plain modes run through channels.
    - 21c.10: the content-coding run, the deadline run, the TCP trace run, the TLS example
      and the consumer move, one commit each.
    - 21c.11: `Config` names the channel's configuration, and the step's entry is written.
  - **Check:** `tools/channel_interop.sh` and the h11 and h2 client interop scripts pass
    through the channel. The endpoint, content-coding, deadline and TCP trace checks keep
    their pins, or the entry names each seed that differs and why. `zig build tla` finds the
    new configurations as their first lines say, and `tools/client_trace.sh` and
    `tools/tcp_trace.sh` find every trace a behavior of its model. Each rule has a mutation a
    test catches.
- **21d, the roots.** `server.zig` and `client.zig` stop exporting `server.Connection`,
  `server.QuicConnection`, `client.Connection` and `client.QuicConnection`, and the names only
  their calls took or returned (decision 121 records the rulings).
  - The server's root exports 47 names: `constants`, `Config`, `Versions`, `Limits`,
    `Deadline`, `Deadlines`, `CloseReason`, `Limit`, `Endpoint`, `EndpointOf`, `Capacity`,
    `Input`, `Datagram`, `Security`, `StreamOctets`, `LogProvider`, `Sent`, `Address`, `Ecn`,
    `StartError`, `SendError`, `Field`, `Id`, `ConnectionHandle`, `Version`, `Fields`, `Event`,
    `Request`, `Body`, `Trailers`, `Cancelled`, `CancelReason`, `Done`, `Writable`, `Ended`,
    `Response`, `Content`, `Received`, `Alternative`, `Coding`, `EncoderPool`,
    `DefaultEncoderPool`, `Encoders`, `DecoderPool`, `DefaultDecoderPool`, `Decoders` and
    `Features`. `Connection`, `QuicConnection`, `Error` and `Protocol` leave.
  - The client's root exports 38 names: `constants`, `Config`, `Versions`, `StartError`,
    `RequestError`, `Field`, `Id`, `Protocol`, `HttpExchange`, `Wanted`, `Outcome`, `Finished`,
    `Sent`, `Address`, `Ecn`, `Channel`, `Values`, `Https`, `Alternative`, `Input`, `Datagram`,
    `Received`, `Event`, `Open`, `Transport`, `Phase`, `ReceivePool`, `DefaultReceivePool`,
    `ReceiveStorage`, `Coding`, `DecoderPool`, `DefaultDecoderPool`, `Decoders`,
    `ZstdDecoderPool`, `ZstdDecoders`, `BrotliDecoderPool`, `BrotliDecoders` and `Features`.
    `Connection`, `QuicConnection`, `Event`, `Received`, `Advert` and `ChannelEntry` leave, and
    `ChannelValues`, `ChannelInput`, `ChannelReceived`, `ChannelEvent`, `ChannelOpen` and
    `ChannelPhase` become `Values`, `Input`, `Received`, `Event`, `Open` and `Phase`. The
    client trace names the entry through `Channel.entries`.
  - `server.StartError` loses `TlsRefused`, and `client.RequestError` loses `Draining` and
    `ConnectionClosed`: no program gets them.
  - `Endpoint` keeps its 16 functions and `Channel` its 15. The four connection types keep
    their methods, which the other files of their modules call. Each root imports its
    files through a private `files` struct, in CLAUDE.md's order.
  - `examples/server_exchange.zig` serves TCP and QUIC through one endpoint, and
    `examples/client_exchange.zig` falls back from QUIC to TCP in one channel, on a datagram
    link that drops every datagram. Its run waits about 3 s of real time, while the channel
    closes the QUIC connection it abandoned. The two replace `tls_exchange.zig` and
    `h3_exchange.zig`, and the guide's server and client sections quote them. The h11 and h2
    examples stay until 21f.
  - The memory table measures each connection through the field that holds it, and the
    simulator names the h3 deadline trace's connection the same way.
  - Eleven sub-steps. After each one, every check passes:
    - 21d.1: decision 121, this text, and decision 96 amended.
    - 21d.2 and 21d.3: the simulator and the memory table name each connection through a
      field.
    - 21d.4 and 21d.5: each root imports its files through a private `files` struct.
    - 21d.6 and 21d.7: the roots stop exporting the per-connection types and the names only
      their calls took or returned.
    - 21d.8: the channel's types lose their prefix, and `ChannelEntry` leaves the root.
    - 21d.9: the two error sets name what a program gets, each with a test beside its root's
      list.
    - 21d.10: the datagram link runs on the stream link's loops, and the two examples replace
      the two old ones, with the guide.
    - 21d.11: the step's entry.
  - **Check:** `zig build test`, `zig build examples`, `tools/doc_snippets.sh` and
    `tools/consumer_check.sh` pass, and the lists in `src/server/server.zig` and
    `src/client/client.zig` hold no connection type. The roots of `h11`, `h2`, `h3` and `quic`
    keep `Connection` until 21f. The test counts stay through each `files` move. Each rule has
    a mutation a test catches.
- **21e, the router.** `server.router`, a table of methods and paths the program declares at
  compile time, matched through a trie of path segments as
  [#96](https://github.com/c4milo/colibri/issues/96) describes (decision 122 records the
  rulings).
  - The server's root exports 49 names: the 47 of 21d, then `PathParameters` and `router`.
    `http.method` exports `Standard` beside `standard` and `validate`.
  - Each table has a type of its own, whose public declarations are `Match` and `match`.
    `PathParameters` has one public function, `get`. A test lists each.
  - An entry is a tuple of a method, a pattern and a value: `.{ .get, "/users/:id", .user }`.
    A pattern's segment is a literal, a parameter (`:id`) or, as the last segment, the wildcard
    (`*`). A match writes the path's parameters into a `server.PathParameters`.
  - The walk tries a literal, then a parameter, then the wildcard, and backs up a level when a
    deeper one fails (INV-32). The method is looked up at the leaf: `found`,
    `method_not_allowed` with the Allow value, or `not_found`. A method that no route names
    is `not_implemented`, and HEAD finds a GET route.
  - The path is matched as received. A path with an empty segment, a dot segment, a "%", an
    byte outside `pchar` or more than `path_len_max` bytes matches nothing.
  - A malformed table, or a table with a conflict, does not compile. A route that other routes
    hide is a conflict: a request that it matches gets 405 from another pattern, or no request
    reaches it (decision 122 ruling 12). A table whose Allow value is longer than
    `core.constants.field_value_len_max` does not compile either.
  - The endpoint writes no content in a response to HEAD, in h11, h2 and h3 alike.
  - `server.constants.path_parameters_max` is 8, and `server.constants.path_len_max` is the
    endpoint's own bound on a path, 8192 bytes.
  - `examples/server_exchange.zig` routes its requests through a table, answers a 405 with its
    Allow field, and reads a parameter. Its TCP peer also asks for a path that no route
    names. `examples/client_peer.zig` routes through a table of functions. The guide shows
    both.
  - Thirteen sub-steps. After each one, every check passes:
    - 21e.1: decision 122, INV-32 and this text.
    - 21e.2: `http.method.Standard`.
    - 21e.3: literal routes, with every public name and its list.
    - 21e.4: `zig build router-check`.
    - 21e.5: parameters, the checks of a path, and `path_len_max`.
    - 21e.6: the wildcard as the last segment.
    - 21e.7a: the back-up (INV-32).
    - 21e.7b: the refusal of a hidden route, of a route that no request reaches, and of an
      Allow value that is too long.
    - 21e.8a: no content in a response to HEAD, in each version.
    - 21e.8b: HEAD on a GET route.
    - 21e.9: `not_implemented`.
    - 21e.10: the examples and the guide.
    - 21e.11: the step's entry.
  - **Check:** tests for literal segments, parameters, the wildcard as the last segment,
    precedence whatever the table's order, 404, 405 with its Allow list, 501, HEAD, and a path
    that matches nothing because it holds an encoded byte, a dot segment or an empty segment.
    A test of each version shows that a response to HEAD carries no content. `zig build
    router-check` requires each malformed table and each table with a conflict to fail to
    compile, a hidden route too, and a valid one to compile. A test compares the check of
    hidden routes with a brute force on small tables. `zig build examples`,
    `tools/doc_snippets.sh` and `tools/consumer_check.sh` pass. Each rule has a mutation a test
    catches.
- **21f, the package.** Whether `h11`, `h2`, `h3` and `quic` stay exported (decision 86).
  First, what `client` lacks for a program that leaves the protocol modules (decision 124):
  - **Names.** `client.Request` and `client.Response` replace `client.HttpExchange`;
    `client.ChannelOf` and `client.Capacity`; `client.constants.stream_input_len_min`,
    `stream_output_len_min` and `receive_events_without_input_max`.
  - **Sub-steps.**
    - 21f.1: decision 124 and this text.
    - 21f.2: `client.Request` and `client.Response`, with every caller in the tree.
    - 21f.3: an early final response ends the h11 connection (RFC 9112 §9.5).
    - 21f.4: the channel sends an idempotent request again, once, after its connection closed
      before any byte of the response (RFC 9110 §9.2.2, RFC 9112 §9.3.1).
    - 21f.5: the three limits, and the TLS stall of decision 124 ruling 7.
    - 21f.6: `client.ChannelOf`, and a memory row for a channel with no QUIC.
    - 21f.7: the doc lines of decision 124 ruling 6, the examples and the guide.
    - 21f.8: the step's entry.
  - **Check:** a test for each rule with a mutation it catches; a raw-byte peer that answers
    before the content went out; a retry in each version, and none for POST; a test that drives
    `receive` at `stream_input_len_min` and counts the events with no input; the memory table.
    `zig build examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh` pass.
  **Check of 21f:** the owner's ruling, once the dependent that uses `h11` directly can use
  `client`.

*Large.*

**21a, 2026-10-08.** `server.Versions`, `server.Limits` and `client.Versions`, and a server
connection in cleartext that reads h2's preface to choose its version. Run on macOS 26 on an
Apple M1 Pro, on 590d457, whose seven commits of step 20's h3 deadlines are not on main yet.
- `zig build test` and `zig build test -Drelease`: 131 of 131 steps and 2658 of 2658 tests
  passed in each.
- `tools/h2spec.sh --tls`: with `--h2` in cleartext, and over TLS, 144 of 146 cases, the 2 RFC
  7540 cases named before; with no version named in cleartext, 143, and the invalid-preface
  case as the script names it.
- `tools/h11_server_interop.sh --tls` (curl, Go) and `tools/h2_server_interop.sh --tls` (curl,
  nghttp, Go), each in cleartext with the server naming no version, and over TLS;
  `tools/h11_interop.sh --tls` and `tools/h2_interop.sh --tls` for the client;
  `tools/deadlines.sh`, `tools/tls_accept.sh`, `tools/tcp_trace.sh` (64 of 64 traces) and
  `tools/deadline_trace.sh` (32 of 32); `zig build examples`, `tools/doc_snippets.sh` and
  `tools/consumer_check.sh`, whose consumer's server names no version: each passed.
- A review of the change found two defects, each fixed with a test. A `shutdown` before the
  first bytes was lost: the connection now ends at once, as an idle h11 connection does, and
  a shutdown asked for during a TLS handshake, lost the same way before this step, now reaches
  the protocol the handshake opens. A drain that passed before any protocol served a
  connection stopped it without closing it: it now closes.
- 21 mutations, each **CAUGHT**:
  - the whole preface choosing h11; a four-byte prefix choosing h2; a differing byte
    choosing nothing; the bytes that chose not read;
  - both versions speaking h11 at once; h11 spoken when `versions` turns it off; no version
    speaking h11; a connection allowing both never choosing;
  - a choosing connection closing at once; a shutdown while choosing doing nothing; a shutdown
    during the handshake never reaching the protocol; a drain before a protocol serves
    leaving the connection open;
  - units not judged when cleartext may choose h2, judged for a connection that chose h11, or
    not judged while it chooses;
  - `requests_max`, the configured DATA frame floor, or any floor not reaching h2;
  - the client preferring h2 in cleartext, or speaking h11 with no version allowed;
  - the test-only server ignoring `--h2`, which h2spec's run with it catches.

**21b.1 to 21b.3, 2026-10-09.** QUIC through one endpoint that answers by id. Run on macOS 26
on an Apple M1 Pro, on 590d457.
- 21b.3 moved the endpoint's QUIC calls to ids, `Capacity`, `Input` and `Datagram`, with the
  endings of INV-30 and the deadline heap of INV-31. It then folded `QuicConfig` into
  `EndpointConfig`, which takes one `tls.Server` whose `alpn` stays empty, and `requests_max`
  came to bound h3's request streams. Last, `writable` over h3: a response that found no room
  for its head, its content or its trailer section is reported once a datagram moves its
  slot's room counter and its connection can take the write. Only acknowledgments free room
  over QUIC (RFC 9000 §3.1), so a deadline that fires moves no counter.
- `zig build test` and `zig build test -Drelease`: 131 of 131 steps and 2676 of 2676 tests
  passed in each.
- `zig build sim -- --h3-deadline-check`, 256 seeds in Debug and in ReleaseSafe: the event CRC
  moved from 0xd51694dc to 0x9050e8bf, and the datagram CRC stayed 0x942c7916. A peer with many
  slow bodies now shows its first request `cancelled` for its body rate, at the instant of the
  overload: the stop used to drop that ending. The check now requires every request the
  application read to end before the run does.
- `tools/h3spec.sh` (49 cases, none failed), `tools/quic_udp.sh`, `tools/quic_aioquic.sh`
  (aioquic 1.3.0), `tools/h3_deadlines.sh`, `zig build examples`, `tools/doc_snippets.sh` and
  `tools/consumer_check.sh`: each passed. Each passed again with the folded configuration,
  and again with `writable` and the review's fixes, when `zig build test` and `zig build test
  -Drelease` passed 131 of 131 steps and 2688 of 2688 tests in each.
- Two defects, each fixed with a test. A first Initial whose Destination Connection ID was
  shorter than 8 bytes reached an assertion (INV-24). A poll that read an event moved its
  connection's deadline without marking the slot, so `deadline_ns` read before it kept the old
  instant (INV-31).
- A review of 21b.3, three reviewers and a verifier, made fourteen findings. The verifier
  refuted six, and the other eight name six defects, each fixed:
  - a write that found room on a retry kept its wait, so a false `writable` followed;
  - a head or trailer section larger than the kept frames' room got a `writable` on every
    datagram: it now waits for every run acknowledged;
  - `send_datagram` asked every slot on each call: it now asks only the slots a call changed
    since they last sent nothing;
  - three errors in docs: a citation of RFC 9846 §4.4.2 for the server's certificate, a doc
    comment left above `LogProvider`, and `Sent` naming the old `send`. `StartError`'s new
    members and `init`'s doc also gained the docs a refuted finding asked for.
- Mutations, each **CAUGHT**:
  - 21b.1: no length check; an 8-byte ID refused; a 7-byte one taken, which the test first
    missed and now derives from the ID's length;
  - 21b.2: a connection's id naming a generation; an owed cancellation losing its number;
  - 21b.3, the run's datagram CRC and the endpoint's tables: the server's datagrams not
    counted; a released slot keeping its generation; a wrapped generation naming a
    connection; a slot queued twice; a tie going to the higher slot; a removal never sifting
    down; a stale slot never read again; a removed request staying open;
  - 21b.3, the calls by id: a body or a `done` carrying no word; `set_user_data` ignored; a `done` leaving its
    entry; the program's cancel never reported, reported as `closed`, or leaving its id
    usable; no `cancelled` at a stop, which the simulator's check also catches; `stop`
    clearing its owed endings, which a test then had to be written for; `failed` never set,
    or never reported; a slot never released; a poll or a send leaving its slot's deadline as
    it was; a stopped connection's send not polled, which a test then had to be written for;
  - 21b.3, the folded configuration: an endpoint with no identity, or with h3 turned off,
    starting; an identity never checked; `requests_max` not passed, not clamped, or not
    advertised; deadlines not validated; no h3 named in the handshake;
  - 21b.3, `writable`: a datagram moving no room; a blocked or partial write, a head with no
    room, or trailers with no room or no run, waiting for nothing; `writable` before room
    moves, or never cleared; trailers before the encoder finished; a head never taken;
    content that ignores the runs or the ring, and trailers that ignore the runs, three which
    a test then had to be written for, with room that moves and frees nothing;
  - 21b.3, the review's fixes: content that fit on a retry keeping its wait, and a head or
    trailers that fit keeping theirs, two which a test then had to be written for; a large
    head waiting for a run alone; an empty response never awaited; a slot that sent not asked
    again, and an answer that queues no send, two which a test then had to be written for; a
    poll that queues no send; an ended slot left in the send ring.
- One more was equivalent, and the code no longer has it: a `writable` checked while its
  connection stops, which empties its table first.
- A second review, of 21b.1 to 21b.3's tables and of main's trace world moved to the
  endpoint's calls, found one defect, fixed after the push of 0532f7f. A Retry token sealed by
  a build before 21b.1 can name a first Destination Connection ID under 8 bytes. Under a key
  shared across an upgrade, the Initial that returned it reached `start`'s assertion (INV-24).
  `start` now checks the ID's length on every path. Mutations: no check at `start`, and a
  check that refuses an empty ID alone, each **CAUGHT**.
- One mutant was equivalent: `ended` reported with requests still open. A connection always
  stops before it ends, and a stopped one gives each open request its `cancelled` first, so the
  condition became INV-30's assertion.

**21b.4, 2026-10-09.** TCP connections in the endpoint. Run on macOS 26 on an Apple M1 Pro, on
main cfd7e8a.
- `server.Endpoint` holds `Capacity.tcp_connections` TCP slots, 16 by default, beside its QUIC
  slots. `accept`, `receive(.stream)`, `send_stream` and `transport_closed` serve them, with
  the `send`, `close` and `ended` events and `writable` over h11 and h2. The endpoint builds
  the TCP TLS configuration from the one identity, with the ALPN list `versions` gives. Root
  names added: `Security` and `StreamOctets`; constants `tcp_connections_default`,
  `tcp_requests_max` and `tcp_events_per_poll_max`; `h2.Connection.sendable_len`. Decision 119
  records what this part decided.
- The map of the code before the part found a defect: a TLS record that failed to open left
  the queued plaintext behind the alert, and `should_close` stayed false until the linger
  passed. A record failure now drops it.
- `zig build test` and `zig build test -Drelease`: 131 of 131 steps and 2735 of 2735 tests
  passed in each. `zig build examples`, `tools/doc_snippets.sh`, `tools/consumer_check.sh`,
  `tools/h2spec.sh --tls`, `tools/tls_accept.sh` and `tools/deadlines.sh` passed.
- A review, three reviewers and a verifier, confirmed fourteen findings, seven defects. A
  pipelined h11 request the program held got no signal to be passed again when the response
  before it ended with no byte: the program now passes held bytes again after each event
  that names the connection, and a test shows it. `accept` read the TCP configuration before
  it checked that the endpoint serves TCP. Five were errors in docs.
- Mutations, each **CAUGHT**:
  - `sendable_len`: a closed stream, the stream's state, the final head, or the windows not
    asked;
  - a TLS record failure keeping the queued bytes;
  - `owes_octets`: each of the flight's records, the output, the protocol's own bytes, a
    KeyUpdate's reply, a coded ring and the close_notify dropped, the last four after a test
    was written;
  - `send` re-armed by every `send_stream`, or never; the `done` owed dropped at a close; a
    cleartext slot given TLS; no ALPN served h11 whatever `versions` says; the ALPN list not
    from `versions`; the TCP identity never checked; the TCP configurations missing h11's
    decoders and Alt-Svc; units judged for h11 in cleartext;
  - `writable` over h2 ignoring the window; a read, or a `send_stream`, moving no room;
  - TCP slots in the datagram ring; datagrams served with no QUIC; a failed read not noted;
    the program's cancel reported after the input; `accept` after `shutdown`, with no TCP
    served, or asserting before it checks; requests open at a stop never ended; input kept
    after h11 closed, after a test was written.
- Three mutants were equivalent: a 100 (Continue) term in `owes_octets`, now removed, because
  the poll's `receive` writes the 100 into the output first; `close` before `send`, because the
  linger that lets `should_close` hold with bytes owed starts only while a `send` waits; and
  the alert alone after a record failure, kept as a guard, because every other term is false
  then.

**21b.5, 2026-10-09.** The endpoint check. Run on macOS 26 on an Apple M1 Pro, on main a5d35f2.
- `zig build sim -- --endpoint-check [seeds]` and `--endpoint-seed <hex>` run three TCP and
  three QUIC peers through one endpoint with two slots of each kind, so slots are taken again.
  The TCP peers are the deadline check's: colibri's client for the honest ones, in cleartext or
  over TLS, and the hostile scripts in cleartext. The QUIC peers are the h3 deadline check's,
  each with connection IDs of its own. A peer may reset a request or close early. The program
  sets drawn words, writes drawn pieces after a drawn delay, cancels some requests and makes
  stale calls. P1 to P8 are checked while each seed runs twice, and the census, pinned in its
  test and diffed by `tools/ci.sh` in both build modes, is P9.
- The census, the same in Debug and ReleaseSafe: `seeds=128 connections=767 reused=255
  requests=1577 done=509 cancelled_peer_reset=14 cancelled_deadline=902 cancelled_closed=112
  cancelled_program=37 writable=476 sends=1965 closes=373 stale_calls=13318
  waiting_probes=33358 accept_waits=97 shutdowns=17 unserved=1 failed=0 trace_octets=143625
  crc32=0x560d5625 wire_crc32=0x5ec49f44`. 16,384 seeds passed in ReleaseSafe.
- The check found two defects of 21b.4, fixed first, and decision 119 records them: an h11
  head that two reads carried in cleartext reached an assertion, and a peer that opened its
  window a byte at a time was never cut by `send_rate`.
- It found a third, which waits for the owner: decision 110's stream send meter waits while the
  output holds bytes, and colibri's PING acknowledgments are bytes. An h2 peer that keeps a
  stream's window closed and pings every few seconds is never cut, through the endpoint or a
  connection alone; only the drain after `shutdown` ends it. Seeds 0x4b and 0x5d show it, and
  the run lets that peer's connection alone outlast the 600 s horizon. Step 79 closes it
  (decision 110 as amended a ninth time).
- An honest peer is never cut by a deadline but the drain after `shutdown`, nor its connection
  by one but idle and drain. Peers whose drawn pace would miss decision 110's deadlines for a
  reason of the run's own are kept out: TLS runs only for honest peers at full pace and silent
  ones, since a paced client seals a head into a record that arrives late, and a peer resets a
  request only once the endpoint read it.
- Readings of the properties:
  - P5's oracle is `endpoint.state.deadline_of(slot)`, called through the field `state`, as the
    server's fixtures call it.
  - P8 is read once a pass moves nothing, before P6's probes, which fire TCP deadlines
    themselves. A QUIC connection's acknowledgment and pacing deadlines stay due until
    `send_datagram` sends, so P8 is not read straight after `on_instant`.
  - P6 asks the endpoint's rings and does not poll every QUIC slot: a connection that shuts
    down sends its CONNECTION_CLOSE at its own next timer, within `max_ack_delay` of the
    GOAWAY, as step 20d's check pins. A slot left out of the rings never ends, which the
    horizon check refuses.
  - The socket takes every byte at once, so P7 is exact. A slow reader's unread bytes wait in
    the socket, never in the endpoint's output, so its h2 streams' meters never wait, and the
    send rate may cut an honest slow reader over TCP.
- Not covered: hostile TCP peers over TLS, TCP Rapid Reset, a full socket and a KeyUpdate.
- `zig build test-sim-run` took 3 min 31 s in Debug, against 2 min 54 s to 3 min 15 s before
  the check, and the h3 deadline census stayed 0x9050e8bf and 0x942c7916.
- A review, three reviewers and a verifier, confirmed twenty findings. The check now refuses an
  honest peer cut and a connection left at the horizon, reads P8 before the probes, probes
  `accept` after `shutdown`, and names a stale `receive` that a slot's holder read.
- Mutations, each **CAUGHT**, with what caught it:
  - P4: a generation not advanced at release, or not compared; `done` keeping its entry;
    `transport_closed` without the generation; a stale handle's bytes read by the slot's
    holder.
  - P2: a body without its word; `set_user_data` writing nothing. P3: the program's cancel not
    owed.
  - P5: `set_deadlines` without touching the slot; `on_instant` touching no QUIC slot. P6:
    `write_body` without touching the slot; `owes_octets` without the output; `takes` always
    false. P7: `send` with no bytes owed. P8: QUIC's `on_instant` dropped. P1: `accept` after
    `shutdown`.
  - An honest peer failed when every input was consumed, and was cut when a blocked stream
    was never released.
  - Their unit tests: the ledger's word compare skipped, and P5 comparing nothing.
  - The census alone: `on_instant` firing no TCP slot, because the poll its touch brings fires
    the deadline at the same instant.
- The server fixes: the empty-call rule dropped, and its count never kept; the `send` asked
  first dropped from `poll`, or from `take_stream`. Asking `owes_octets` there too was
  equivalent, so the term is gone.

**21b.6, 2026-10-11.** The TCP callers move to the endpoint. Run on macOS 26 on an Apple M1
Pro, on main 5954c39.
- Nothing outside `src/server` places a `server.Connection` now. The content-coding run, the
  deadline run, both trace runs, the test-only server, the TLS example and the consumer each
  hold their connections in a `server.Endpoint`.
- **The content-coding run and the deadline run.** Each holds an endpoint with one TCP slot.
  Each pass still reads, answers and then calls `send_stream` once, so nothing is read between
  a write and its send. Neither census line changed, in Debug or ReleaseSafe: `content-coding:
  seeds=32 exchanges=82 decoded=19 passed_on=4 too_large=8 trace_octets=8470 crc32=0x69460a6e`
  and `deadline: seeds=256 exchanges=142 first_request=37 idle=114 head=17 body_rate=10 body=7
  send_rate=71 settings=0 drain=0 streams_cut=37 streams_refused=60 held=0 trace_octets=104013
  crc32=0x9369abbc`. A checksum of the bytes each seed moved each way, taken before and after
  the move, is the same for every seed of both. One deadline seed wrote 77 bytes fewer into
  its socket: a slow reader whose linger passed in an instant it also read in. The run before
  still wrote them in that instant, the endpoint had closed the connection, and the peer read
  them in neither. Over 65,536 seeds the deadline check prints `crc32=0x4878c63a` before the
  move and after it.
- **The deadline trace run.** After each action it reads `receive(.none)` until the endpoint
  reports nothing, as a program does once it has answered, where it called `on_instant`: the
  endpoint has no call that hands one connection an instant when no deadline is due. That read
  also writes what h2 owes, one action sooner than before, so the logs differ:
  `deadline-trace: seeds=32 states=3837 requests=69 responses=69 bodies_timed=798
  sends_timed=21`, where the run before printed `states=3864` and `bodies_timed=731`.
  `tools/deadline_trace.sh`: 32 of 32 traces are behaviors of the model.
- **The TCP trace run.** Its server moved and its client did not. The 64 modules it writes are
  byte for byte those it wrote before, and `tools/tcp_trace.sh` finds 64 of 64 behaviors of
  the model: `tcp-trace: seeds=64 tls=38 states=563 requests=129 responses=83 refused=3
  shut_down=25`.
- **What the trace runs read from h2.** The endpoint reports nothing of a request after its
  `done` or `cancelled` (INV-30), so the end of a request whose response ended first reaches
  no program. Each trace run reads the end of such a request, and of no other, from the
  server's stream table: its stream closed with END_STREAM both ways (RFC 9113 §5.1). The TCP
  trace run reads a stream the server reset after its `done` as a malformed request the same
  way.
- **Each trace run's test now holds its census.** TLC finds the log of a server that answers
  nothing a behavior of the model, and each test required only that some counts were above
  zero.
- **The test-only server.** `src/testing/server.zig` was at 500 lines, so it was split first,
  into `src/testing/server/`, with the same 26 and 29 tests. Each worker then serves its
  sockets through one endpoint of `connections_per_worker_max` TCP slots. A step for one
  socket passes its input, writes its owed responses, calls `send_stream` once and reads the
  endpoint's events until it reports none, so the responses to one read leave in one send.
  `test-testing` has 44 tests and `test-testing-client` 37. `tools/h2spec.sh --tls` passes
  144, 143 and 144 cases in its three runs, as before, and `tools/h2_server_interop.sh --tls`,
  `tools/h11_server_interop.sh --tls` and `tools/deadlines.sh` pass. In cleartext with `--h2`
  the server's SETTINGS now leaves at the accept, before the client's first bytes, which RFC
  9113 §3.4 allows.
- **A slot is free before the program's socket is.** The endpoint reports a connection's
  `ended` straight after its `close`, with no call from the program (decision 119 refused
  waiting for one), and a later connection may take the slot while the socket still sends its
  last bytes or closes. So the test-only server keeps socket entries of its own and a map
  from a slot to the entry of the connection the slot holds now. docs/usage.md and the comment
  on `ConnectionHandle` say so; they and the header of `endpoint_slots.zig` had said a slot
  indexes a program's own array of sockets.
- **The TLS wipe.** The test-only server's test that a TLS session is wiped when its socket
  closes moved to the server module, where the duty now is: the endpoint wipes the session at
  `close` and at `transport_closed`. `test-server` has 380 tests.
- **The example, the guide and the consumer.** `examples/tls_exchange.zig` serves through an
  endpoint and shows `accept`, `send` with `send_stream`, `close`, `ended`, and
  `transport_closed` for a second socket whose peer closes first. In its own exchange the
  endpoint reports `close` itself, after which `transport_closed` changes nothing; the comment
  on `Endpoint.transport_closed` said otherwise. docs/usage.md's section on a server over TCP
  is written for the endpoint, and `tools/consumer/` answers through one.
- **Memory.** docs/performance.md lists the default endpoint, 40,625,232 bytes with its 16
  QUIC receive pools, an endpoint of one TCP slot, 323,136, and one of one QUIC slot,
  2,240,512. Each holds the endpoint's fixed part, about 12.7 KB.
- **Owed, and left as it was.**
  - `bench/run.sh --base main` on the judge for the test-only server, which a person starts.
    The endpoint hands out the slot freed longest ago and the server before reused the lowest
    free one, so the judge is also where a cost of first touch would show.
  - A peer that stops reading keeps its socket at the test-only server after the endpoint's
    `close`: the server waits for its own output to leave before it closes, as it did before
    the step. `tools/deadlines.sh` has no such peer.
  - The test-only server still runs one worker over TLS. Its header gave chapulin's
    process-wide generator as the reason, which `RAND=session` removed.
- A review, three readers and a verifier, confirmed eighteen findings, none a defect of the
  library. Twelve were comments or sentences of the guide the source contradicts, the three
  above among them, and they are corrected. Two were checks the move had made weaker: a
  failed read in the content-coding run's last round passed, and the TCP trace run no longer
  saw a `cancelled` after a request's `done`. Both read the fact from the endpoint's fields
  now.
- Mutations, each **CAUGHT** unless it says otherwise:
  - Content-coding: the run never calling `send_stream`; an answer naming another generation
    of its connection; bytes consumed with a `send` event passed again; the endpoint handing
    its TCP connections no codings.
  - Deadline: a drain noted after a linger closed the connection; `close` ignored; the reason
    `ended` names dropped; `send_stream` given more than the socket's room, or called only
    after a `send` event; a held stream's send meter running while the output holds bytes;
    the idle clock starting before the output empties.
  - Deadline trace: a request's end not read from h2 after `done`, unfinished at seed 1; and
    four of colibri's clock rules broken, with 17, 1, 13 and 23 of 32 traces left behaviors,
    the counts of 2026-09-30.
  - TCP trace: a request's end not read from h2, 53 of 64; the caller's own cancel read as
    malformed; a TLS connection accepted in cleartext; a cancel's RST_STREAM not written in
    its action, 53; the endpoint passing no body's end, 39; h2 refusing DATA on a stream
    whose response ended.
  - The census pins, where TLC found every trace a behavior: the server answering with an id
    of another generation; its caller writing no interim response; the deadline trace run
    reading nothing after an action.
  - The test-only server: a `send` ignored; `send_stream` not called again after a call that
    filled its room; held input not passed again after `done`; `close` ignored; a peer's close
    not passed to `transport_closed`; events routed by `handle.slot` with no map; the echo
    taken from another socket's entry; an entry taken again keeping its flags; `.cleartext`
    with an identity loaded, by `tools/h2spec.sh --tls`; `on_instant` never called, by
    `tools/deadlines.sh`. Twenty-six more of its own, six of them **NOT CAUGHT** at first:
    five got a test, and the sixth was a rule no test could reach, which is gone.
  - The TLS wipe: `close_transport` leaving the session open; the wipe moved from `close`, or
    from `transport_closed`, to `ended`.
  - The example, by `zig build examples`: a `send` ignored; `.none` passed for `.stream`;
    `transport_closed` not called; `accept` given `.cleartext`; a response to another
    connection's id; one `send_stream` for a `send`, with a 1,024-byte buffer. The consumer,
    by `tools/consumer_check.sh`: a `send` ignored; a response to a stale id.
  - The memory table: one endpoint row's size changed in docs/performance.md.
  - The endpoint, by the server's tests and not by the deadline check, which sends in every
    pass: `close` reported before what the connection owes; `send` asked again after a
    `send_stream` that filled its room; `send` never asked again.
- **NOT CAUGHT**, and why each has no test:
  - The deadline trace run reading nothing after an action, or reading before it offers
    content: TLC finds all 32 traces behaviors either way. The census pin catches the first.
  - 21b.5's `send` asked before a read, removed: the deadline trace run ignores `send`, and
    21b.5's check is what catches it.
  - The example's `ended` accepting a failed connection, or one closed for a reason: its run
    has neither. A second socket given a record that does not authenticate showed the arm
    refuses a failure. The consumer writing the server's bytes into the buffer its input
    arrives in: its one exchange never has both at once.

**21b.7, 2026-10-11.** `Config` names the endpoint's configuration. Run on macOS 26 on an Apple
M1 Pro, on main 66d91e4.
- `server.Config` is the type `server.EndpointConfig` named, and `EndpointConfig` leaves the
  root, which exports 51 names where it exported 52. A TCP connection's own configuration,
  which `Config` named before, is internal to the module: every caller moved to the endpoint in
  21b.6, so none named it. `Connection` and `QuicConnection` stay exported until 21d, and a
  program is to place neither: the root exports no name for the configuration either takes.
  `Connection.init` is still a public function until then.
- A dependent that wrote `server.EndpointConfig` writes `server.Config`. One that wrote
  `server.Config` for a TCP connection has no type to name: the name still compiles, as the
  endpoint's configuration, and `Connection.init` refuses a pointer to it. It serves through
  the endpoint.
- The comments and the guide had described the endpoint as it was before it held TCP
  connections. The headers of `server.zig` and `endpoint.zig` now describe one endpoint over
  TCP and QUIC. The comment on `Endpoint` and docs/usage.md define the word: the server side
  of every connection one thread serves. RFC 9000 §1.2 and RFC 9113 §2.2 give the word to the
  client or the server of a connection, and a server has many. "What your program owns" in
  docs/usage.md covers an endpoint, and INV-31 lists the TCP calls that mark a slot.
- `zig build test` and `zig build test -Drelease`: 131 of 131 steps and 2795 of 2795 tests
  passed in each. `zig build examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh`
  pass.
- A review, two readers and a verifier, confirmed twelve findings, all of comments and of the
  guide, and they are corrected. One waits for 21d: `server.zig` and `client.zig` import their
  files as top-level names and not through a private `files` struct.
- Mutations, each **CAUGHT**: the root still exporting `EndpointConfig`, by the test that lists
  its names, in `zig build test-server`; `Config` naming a TCP connection's configuration, by
  `zig build`, which no caller then passes.

**The endpoint's cost, 2026-10-11.** Step 21b.6 moved the test-only server, which the judge
measures, onto the endpoint, so the judge then counted what the endpoint costs a request.
- **The gap.** Run [38181560376](https://github.com/c4milo/colibri/actions/runs/38181560376),
  66d91e4 against 5954c39, the commit before 21b.6, in both jobs: h2-many 1.1148 (25,699 to
  28,649 instructions per request), h2-tls-many 1.0906, h2-one 1.050, and h2-tls-one within
  the noise. CPU time per request on h2-many rose 17%.
- **Where it went.** A profile of the two servers under h2-many's load, sampled on a laptop
  and so no published number, put 83% of the added time in the endpoint's own functions. The
  search of a slot's open requests came first: the endpoint walked the table eight times for
  each request, for each event and answer and twice in assertions.
- **Two changes,** each judged alone against the commit before it, on main 291138f:
  - A table keeps, for a request's number, the entry it is open at, so a lookup reads one
    entry (`endpoint_requests.zig`). Run
    [38192700910](https://github.com/c4milo/colibri/actions/runs/38192700910): h2-many 0.9729
    and 0.9728 (19,488 to 18,959), h2-tls-many 0.9805 and 0.9811. It adds 144 bytes to a TCP
    slot.
  - A table counts the cancels it owes and its waiting requests, and a poll scans for either
    only while it counts one. Run
    [38192702985](https://github.com/c4milo/colibri/actions/runs/38192702985): h2-many 0.9894
    in both jobs (18,940 to 18,740), h2-tls-many 0.9924 and 0.9929.
  - h2-one and h2-tls-one stayed within the noise in every job.
- **The proof that nothing else moved.** With both changes, the census lines of the
  content-coding, deadline, endpoint and h3 deadline checks, and the 256 modules the deadline
  trace, the TCP trace and the h3 deadline trace write, are byte for byte what main writes.
  The table's tests keep a table that scans as their reference.
- **What is left.** The two changes take back about 730 of the 2,950 instructions. About
  2,200 remain, by subtraction across runs, which no one run measured. The requests that
  main's h2 changes of the same day made cheaper make that a larger share: about a ninth of
  an h2-many request. It is spread over each call of the endpoint, of which a request makes
  about four and a half: the handle resolved, the slot marked in the ready ring and the
  deadline heap, the event passed on under the connection's handle, and a 176-byte result
  returned through three functions. An endpoint does that work and a connection alone did
  not.
- Mutations, each **CAUGHT** by `zig build test-server`:
  - The places: a place kept after its request ended; a placeless request not counted, or
    never counted out; the step ignored; a lookup that reads no number; a lookup that never
    scans.
  - The counts: a cancel or a wait not counted, or counted twice; a request that found room,
    or that ended, still counted; either scan run only while its count is zero.

**21c, 2026-10-12.** A client's channel builds its TLS configurations, draws what a QUIC
connection starts from, and carries every exchange a program makes (decision 120). Run on macOS
26 on an Apple M1 Pro. The sub-steps ran on main 9b621a0, and the branch was then replayed over
25e1c93, whose one commit changes two tests.
- **The API.** `client.Config` is the channel's configuration: one `tls.Client` value, whose
  `alpn` now defaults to empty, and `Channel.init` builds each transport's TLS configuration
  with the ALPN list `versions` gives. `start_quic` draws the grease value and the two
  connection IDs from its source. `QuicConfig`, `ChannelConfig`, `QuicStart` and
  `QuicStartError` leave the root, which exports 44 names where it exported 48.
  `client.constants.fallback_delay_ns_default` is 250 ms.
- **What the move needed fixed,** each in a commit of its own: an h11 connection in cleartext
  reads nothing on a call with no bytes while bytes wait (21c.3); a transport closes once its
  connection wrote its alert, its Finished or h2's GOAWAY (21c.4); a connection that carried
  nothing stays counted in its attempt (21c.5); a handshake that selects no protocol runs h11
  only while `versions` allows it (21c.6c). The endpoint check's move found one more, there
  since step 17d: a connection that ended while an exchange waited was closed and its transport
  opened again in one pass of the channel, and the `open` overwrote the `close` it owed, so the
  caller kept the old socket. The channel now reports the `close` first. That left an `open`
  owed across a call: a program that then cancelled the last exchange and shut the channel down
  reached an assertion, and a shut-down channel now drops an `open` no caller heard of. A
  program also drops the bytes it still holds from a socket when the channel says `close`:
  passed on after the next `start_tcp`, a stale h2 GOAWAY failed the new connection (RFC 9113
  §3.4). The guide and the TLS example say so, and the test-only client already did.
- **The callers.** The endpoint check's peers, the test-only client's plain modes, the
  content-coding, deadline and TCP trace runs, the TLS example with the guide's client section,
  and `tools/consumer/` each hold a `client.Channel` with TCP alone.
- **What stayed.** 21c.2 pinned a CRC-32 of what the client writes in three runs:
  `wire_crc32=0xe6434a84` in the deadline check, `0xc8625587` in the content-coding check and
  `0x553ad660` in the TCP trace run. Each stayed through every move, and so did each run's
  other pins. Over 65,536 seeds in ReleaseSafe the deadline check printed `crc32=0x4878c63a`
  and `wire_crc32=0x7a90b4e4` before its move and after. The endpoint check kept `0x560d5625`
  and `0x5ec49f44`, and each of its 128 traces line for line. The h2 and h11 interop scripts
  print what they printed before, byte for byte.
- **The one census that moved.** In 21c.7a the client trace run draws a QUIC connection's start
  values from its TLS source: 17 values fewer of `random` and 24 more of `tls_random` at each
  open. `states` went from 2570 to 2569, `refused` from 83 to 85, `failed` from 61 to 59,
  `moved` from 3 to 4 and `tcp_connections` from 272 to 274. Four of 256 seeds print another
  trace, each from its second QUIC open. 21c.7b moved the draws into `start_quic`, and the
  census stayed.
- **A closed socket reads nothing.** The TCP trace run's socket reads nothing after the
  channel's `close`, as a program's closed socket does, and the run still calls `receive` for
  the channel's events. Reading on, the channel drops the server's late bytes, and `states`
  becomes 566 where it is 563: the first difference is a `deliver_to_client` of seed 0x16.
- **The test-only client.** A run counts a connection a success only when its channel closed
  with every exchange answered and every socket it opened ended before the run did. Its channel
  mode gives QUIC every decoder pool, which `--coded` needed.
- **Memory.** docs/performance.md lists `client.Connection` at 289,208 bytes, eight more for
  `unread_len`, and `client.Channel` at 995,328, which holds two TLS configurations now.
- **Models.** spec/tla/client_exchanges gains `TakeAtHandshake`, `Bounded`, `TcpAllowed`,
  `TcpWhenAllowed` and `NoTcp`. The configurations `bounded` and the three `h3_alone` hold, and
  `take_at_handshake` and `tcp_when_allowed` find their invariants violated, as their first
  lines say. `tools/client_trace.sh` found 67 of 67 traces behaviors of the model, and
  `tools/tcp_trace.sh` 64 of 64.
- **Checks.** `zig build test` and `zig build test -Drelease` passed on 21c.11a before the
  replay, and so did `zig build examples`, `tools/doc_snippets.sh`, `tools/consumer_check.sh`,
  `tools/h2_interop.sh --tls`, `tools/h11_interop.sh --tls` and `tools/channel_interop.sh`.
  `tools/ci.sh`, which runs `zig build tla` for every model, runs on the pushed tree.
- A review, two readers and a verifier, confirmed five findings, and each is corrected: the
  assertion and the stale bytes above, design §6.5's sentence that h3's grease value derives
  from configuration, the test-only socket's header, and the commits this entry named before
  the replay.
- Mutations, each **CAUGHT** unless it says otherwise:
  - The pins: one more SETTINGS parameter from the client; Accept-Encoding with a space, by
    the new pin alone, and in another order, by an older check; each hash without its last
    byte; the TCP trace's hash over `consumed`, **NOT CAUGHT** at first and caught by a new
    test.
  - h11's empty call: the rule dropped; `unread_len` never set; the rule on a call with
    bytes.
  - The close: the closed-phase term back in `close_over`; `protocol_pending` removed from
    `should_close`; `close_over` ready whatever `should_close` says.
  - The attempt: the guard removed, or reading `failed` alone; `abandon` removed;
    `end_attempt` before the guard; `connected` reported; `finish_link` reading `abandoned`
    alone, or `won` alone, each caught by a new test; the assertion negated; the model
    without `TakeAtHandshake`, which TLC finds violating `Bounded`.
  - One TLS value, 26 of 28: the ALPN list wrong four ways; QUIC offered in cleartext, without
    a pool, or with h3 off; `quic_allowed` ignoring what the channel offers; TCP offered or
    opened with h11 and h2 off, three ways; `NoVersion` not returned; the fallback instant
    reported with TCP off; QUIC's configuration with another authority, or without `ecn`,
    `idle_timeout_ms`, the codings or any of its three pools; `TooManyAnchors` dropped; a TLS
    configuration built for a transport not offered, two ways; the internal TCP configuration
    with no TLS; the model without `TcpWhenAllowed => TcpAllowed`, which TLC finds violating
    `NoTcp`; the trace world speaking no h3. And 21c.6a's: `alpn`'s default naming "h2", or a
    protocol the test server does not select.
  - No ALPN selection: no selection always h11, always h2, or reading h2; `attach` passing
    default versions, or keeping `connected` owed; the test-only client's versions wrong
    four ways, one caught by a new test.
  - The draws: the IDs drawn before the grease value; the two IDs swapped; one draw for both;
    a constant grease value; the draws after the session starts; the Initial keys derived
    from the source ID; the root exporting `QuicStart` again.
  - The order of `close` and `open`: the `open` dropping the `close` owed; `open` reported
    first. An `open` no caller heard of: the old assertion back; a `close` owed for it; the
    link not closed; the `open` left owed.
  - The endpoint check's peers: `start_tcp` never called; `.none` passed for `.stream`; a
    second `open` started; the `close` flag never set; no `receive` after `start_tcp`; both
    protocols offered over TLS, two ways; `closes` true before `close`.
  - The test-only client: `open`, the start or `close` ignored; a socket's end or a failed
    open not passed on; a second `open` ignored; two sockets of one connection at once; held
    bytes dropped after an event; no read after a send; `versions` wrong over TLS or in
    cleartext.
  - The content-coding, deadline and TCP trace runs: `send_stream` never called; `.none`
    passed for `.stream`; `start_tcp` not called; the channel given no codings; the read after
    `start_tcp` removed; a second `open` started, which the deadline run's new test plays; a
    request while draining; a `receive` after a send; the socket read after `close`.
  - The example and the consumer: `send_stream` never called; `.none` passed for `.stream`;
    `close` ignored; `start_tcp` not called; `shutdown` never called.
  - The name: the root still exporting `ChannelConfig`, by its list test; `Config` naming the
    TCP connection's configuration, by `zig build`.
- **NOT CAUGHT**, and why each has no test:
  - h11's rule returning on every empty call: h11's client reports nothing on one.
  - The trace world given a receive pool under the policy `never`, or speaking h11 too: the
    world's plans and servers make both equivalent.
  - The test-only client dropping held bytes after a send: h11 refuses a response that no
    request it sent awaits (RFC 9112 §9.2), so no byte waits for a send to be read.
  - The TLS example keeping a closed socket's bytes: its socket holds none at its `close`,
    and no second connection opens.
  - 21c.4's `protocol_pending` removed, against the deadline check: its honest peer never
    shuts down, so its h2 owes no GOAWAY when it closes. The client's own tests catch it.
  - The TCP trace run cancelling a moved exchange, or ending a delivery at its first quiet
    call: no state changes over 1,024 seeds. A moved exchange waits at the channel, and the
    connection reports `draining` in the call that reads the GOAWAY.

**21d, 2026-10-13.** The roots of `server` and `client` export what an endpoint and a channel
take and return (decision 121). Run on macOS 26 on an Apple M1 Pro, with Zig 0.16.0. The
sub-steps ran on the branch `roots-21d` over main 0228d20, which holds seven performance
commits of another session of the same day. The branch was then replayed over main bc79211,
which holds four more of them, and the review's fixes were made there. Before the push it was
replayed over main 70f77c1, one more commit of that session.
- **The base.** Before 21d.3, on main 0228d20 with 21d.1 and 21d.2: `zig build test` passed
  2878 of 2878 tests, `zig build test-server` 393 and `zig build test-client` 192.
- **The lists.** The server's root exports 47 names, where it exported 51. The client's root
  exports 39 names after 21d.7, where it exported 44, and 38 after 21d.8. Each root imports its
  files through a private `files` struct. `Endpoint` keeps its 16 functions and `Channel` its
  15.
- **The test counts.**
  - After 21d.4 and 21d.5, `zig build test-server` passed 393 tests, `zig build test-client`
    192 and `zig build test` 2878, as on the base. Thus each file's tests still run through
    `files`.
  - 21d.6, 21d.7 and 21d.8 kept the same counts.
  - 21d.9a and 21d.9b each add one test beside the root's list. Then `zig build test-server`
    passed 394 tests, `zig build test-client` 193 and `zig build test` 2880.
  - From 21d.3 on, `zig build test -Drelease` passed the count of `zig build test` after each
    sub-step.
  - After the replay over bc79211, `zig build test` passed 2890 of 2890 tests: the 2888 of
    main and the two of 21d.9.
- **What stayed.**
  - After 21d.2, `zig build sim -- --h3-deadline-trace-check` printed the census line of the
    base: `seeds=32 states=418 opened=61 responses=24 timeouts=2 rejected=26 cancelled=0
    drained=21 drain_passed=11`. Before the branch moved onto 0228d20,
    `tools/h3_deadline_trace.sh` found 32 of 32 traces behaviors of `spec/tla/h3_deadlines`.
  - After 21d.3, `zig build bench-memory` printed the sizes of the base under the new names:
    306,448 bytes for the server's TCP connection, 721,416 for its QUIC connection, 289,208
    for the channel's TCP connection and 703,712 for its QUIC connection. `zig build
    test-bench` passed.
  - No census, CRC or memory row changed in any sub-step.
- **The examples.** After 21d.10c, `zig build examples` prints "every octet arrived as sent"
  for `h11_exchange`, `h2_exchange`, `server_exchange` and `client_exchange`, and for no other
  example. The client example alone took 3.34 s and 38 of its 256 turns, while the abandoned
  QUIC connection waited for its closing period. `git grep` finds `tls_exchange` and
  `h3_exchange` only in docs/design.md and docs/decisions.md, which are history.
  - `DatagramLink` holds a pointer to the loops of a `Link` and gains `blocked` and `dropped`.
    While `blocked` is set, the link counts each datagram in `dropped` and queues none.
  - `zig build lint` holds `examples/` to a cognitive complexity of 15 too. One function of
    `server_peers.zig` became two to stay under it.
  - After each sub-step, `tools/doc_snippets.sh`, `tools/consumer_check.sh` and `zig fmt
    --check` passed.
- **The guide.** In docs/usage.md, "The server" now holds the endpoint over TCP and over QUIC,
  and "The client" holds the channel. The sections "The server's endpoint", "The client's
  channel" and "h3: the endpoint and the channel" are gone. "Sizes" points to the memory table
  of docs/performance.md. It keeps the row of `h11.coding.DefaultPool`, 691,472 bytes. Four
  rows of the protocol modules differed from the pinned table, and they are gone.
- **CLAUDE.md.** The commit "docs: limit the pub-method rule to the types a root exports"
  limits the rule on `pub` methods to the types that a root exports. The owner approved the
  sentence on 2026-10-13. The commit "docs: write prose in ASD-STE100 beside Google's guides"
  adds the rule on ASD-STE100 prose, which the owner asked for on the same day.
- **The review.** Two readers and a verifier confirmed six findings. Each is text that the
  source does not support, and each is corrected:
  - The four connection lists and two internal headers said that the endpoint or the channel
    makes each call. No file of either calls `protocol`. The text now names the module's other
    files, and the client QUIC connection's `protocol` is private.
  - The client example said that `on_instant` tells the channel the fallback delay ended. The
    next `receive` does.
  - The datagram link's header said that one clock keeps the instants in order. That is true
    only when a program reads the clock once in each turn.
  - The guide quoted a call to the example's `take_ticket` helper, but not the helper. It now
    quotes the helper.
  - This entry named commits from before the replay. It now names them by subject.
- **Owed.** `tools/ci.sh`, on the exact tree before the push. It runs `zig build tla`, the six
  trace scripts and the interop scripts. 21d.8 changed the names that the client trace run
  uses, so `tools/client_trace.sh` runs there too.
- Mutations, each **CAUGHT** unless it says otherwise:
  - 21d.3, by `zig build test-bench`: the server's TCP row read from `"quic"`; the client's
    QUIC row read from `"tcp"`.
  - 21d.6, by the root's list test in `zig build test-server`: `Connection` exported again;
    `Protocol` exported again.
  - 21d.7, by the root's list test in `zig build test-client`: `QuicConnection` exported
    again; `Advert` exported again.
  - 21d.8, by the same test: `ChannelEvent` exported beside `Event`; `ChannelEntry` exported
    again; `Phase` exported as `ChannelPhase`.
  - 21d.9a, by the new test in `zig build test-server`, whose `switch` then does not compile:
    `TlsRefused` back in `StartError`; `Endpoint.init` declared to return the connection's
    `InitError`; the root's `StartError` that names `InitError`.
  - 21d.9b, by the new test in `zig build test-client`: `Draining` back in the channel's
    `RequestError`; `Channel.request` declared to return the set of the connections; the
    root's `RequestError` that names that set.
  - The review's fix, by the list test in `zig build test-client`: the client QUIC
    connection's `protocol` public again.
  - The server example, 28 breaks, by `zig build example-server_exchange`:
    - Step 17f's breaks: the server reports no `done`; it answers 201; the clients keep no
      wanted field; a client's body has no room for its last byte; the stream link drops the
      last byte of each send; the clients ask for another server name; the TCP client never
      shuts its channel down; the `ended` events not counted; the datagram link changes an
      byte of each datagram; the TCP client offers h11 alone.
    - 21b.6's breaks: `send` ignored; `.none` passed for `.stream`; `transport_closed` not
      called; `accept` given `.cleartext`; a response to the id of another connection; one
      `send_stream` for each `send`, with a buffer of 1,024 bytes.
    - 21c's breaks, on the peers: the TCP client never calls `send_stream`; it passes `.none`
      for `.stream`; `close` ignored; `start_tcp` not called.
    - New: datagrams passed as `.none`; `send_datagram` never called; the TCP bytes passed
      under the handle of the closed socket; `set_user_data`, `shutdown`, `h3_alternative`,
      `set_deadlines` or `take_ticket` not called.
  - The client example, 24 of 25 breaks, by `zig build example-client_exchange`:
    - Step 17f's breaks: the client keeps no wanted field; its body has no room for the last
      byte; the stream link drops the last byte of each send; the client asks for another
      server name; the client never shuts its channel down; the client offers h11 alone over
      TCP; the server reports no `done`; the server answers another status.
    - 21b.6's breaks, on the server: `send` ignored; `.none` passed for `.stream`; `accept`
      given `.cleartext`.
    - 21c's breaks: `send_stream` never called; `.none` passed for `.stream`; `close` ignored;
      `start_tcp` not called.
    - New: `on_instant` never called; `start_quic` not called; the datagram link not blocked;
      `close .quic` not counted; `send_datagram` never called; the server's listener never
      accepts; `transport_closed` not called; `take_ticket` not called; the refused channel
      never shut down.
    - Two breaks did not compile at first, for a parameter the break left unused: the server
      that ignores `send`, and `start_quic` not called. Each ran again in a form that
      compiles.
- **NOT CAUGHT**, or no mutation, and why:
  - 21d.6: the test block without its line for `connection/connection.zig`. It is equivalent:
    the endpoint imports the file, so `zig build test-server` still ran 393 tests.
  - The client example that keeps the bytes of a socket after its `close`: **NOT CAUGHT**.
    The socket holds no byte at `close .tcp`, and no later TCP connection opens. No check of
    an example can see it, as in 21c.
  - 21d.10a: no check reads which link starts and stops the loops.
  - 21d.1, 21d.2, 21d.4 and 21d.5 change no check. The test counts are the check of 21d.4 and
    21d.5.

**21e, 2026-10-14.** `server.routes`, a table of methods and paths that a program declares at
compile time (decision 122). Run on macOS 26 on an Apple M1 Pro, with Zig 0.16.0. The commits
are on the branch `router-21e` over main c6eeb9c, from 2026-10-13 to 2026-10-14. 21e.7 became
21e.7a and 21e.7b, and 21e.8 became 21e.8a and 21e.8b.
- **The rulings.**
  - 2026-10-13: the owner ruled "Go with the recommendations" on the choices of the plan.
    Decision 122 records the thirteen rulings. The same day, the owner read ruling 12 as two
    cases, `route_hidden` and `route_unreachable`, after eight examples. The owner also
    approved the two CLAUDE.md sentences of f20e74d.
  - 2026-10-14, after 21e.10: the cross-check of `routes_hidden_test.zig` leaves `zig build
    test-server` for a build step of its own, which `zig build test` runs. Also, 21e fixes the
    compile time of large tables. The owner accepted that the fix changes the run-time code of
    `match`, and that CLAUDE.md's rule on performance then asks for a measurement.
- **The base.** On main c6eeb9c, `zig build test` passed 131 of 131 steps and 2892 of 2892
  tests, `zig build test-server` 395 tests and `zig build test-http` 78.
- **The commits.** After each one, `zig build test` passed these steps and tests, and `zig
  build test-server` these tests:
  - 21e.1, e97e694: decision 122, INV-32 and the text of this step. 131 steps, 2892, 395.
  - 21e.2, d2b73ab: `http.method.Standard`. 131 steps, 2893, 395. `zig build test-http`
    passed 79 tests from this commit on.
  - 21e.3, 98c89fe: literal routes, every public name and its list. 131 steps, 2923, 425.
  - 21e.4, 0222d42: `zig build routes-check`. 160 steps, 2923, 425.
  - 21e.5, a9d1b95: parameters, the checks of a path, and `path_len_max`. 170 steps, 2935, 437.
  - 21e.6, d3c20fb: the wildcard as the last segment. `routes_trie_layout.zig` holds the
    layout, because `routes_trie.zig` was at 486 lines. 172 steps, 2938, 440.
  - f20e74d: CLAUDE.md names `server.routes` and `zig build routes-check`. No check changes.
  - 800ebda: the router's tests move to four files, because `routes_test.zig` was at 483
    lines. 172 steps, 2938, 440, as before.
  - 21e.7a, 6b6c0a3: the back-up (INV-32). 172 steps, 2943, 445.
  - 21e.8a, 52206df: no content in a response to HEAD, in h11, h2 and h3. 172 steps, 2949, 451.
    The six new tests failed on the code before the fix: 445 of 451 passed.
  - 21e.8b, 104d9d5: HEAD on a GET route. 172 steps, 2951, 453.
  - 21e.9, 2b82b3d: `not_implemented`. 172 steps, 2954, 456.
  - 21e.7b, 6ed56b1: the refusals `route_hidden`, `route_unreachable` and `allow_too_long`. It
    came after 21e.9, because it waited until the owner read ruling 12. 178 steps,
    2962, 464.
  - 6eef776: the review's fixes of 21e.7b. 178 steps, 2966, 468.
  - 21e.10, 75d08e9: the examples and the guide. 178 steps, 2966, 468.
  - e6a5c77: the cross-check in `zig build routes-hidden-check`. 181 steps, 2969, 464.
    `zig build routes-hidden-check` passed 7 tests.
  - 546d6b1: the binary search and the walk of the trie. 181 steps, 2971, 465. `zig build
    routes-hidden-check` passed 8 tests.
  - fc90377: the client example sends a request to each arm of its server's route switch.
    181 steps, 2971, 465.
  - 31c52ee: a test builds each route table that docs/usage.md shows. 181 steps, 2972, 466.
  - 174c242: one verb for each sense in the router's text. 181 steps, 2972, 466.
  - 315e3c1: CLAUDE.md names `zig build routes-hidden-check`, and the rule that `zig build
    test` runs each step whose name ends in `-check`. No check changes.
  - 73fbf50: the build of a large table in a few seconds. 181 steps, 2972, 466. `zig build
    routes-hidden-check` passed 8 tests.
  - 8a0dc3f: the quota of the check of hidden routes counts the reads of each pass. 181
    steps, 2973, 467. `zig build routes-hidden-check` passed 8 tests.
  - c05ce20: the text that the second review found wrong. 181 steps, 2973, 467.
  - 1c3a4f2: `bench/routes/`, the probes of the router's cost. 181 steps, 2973, 467.
  - The record of the second review, after 1c3a4f2, changes no check.
  - After 310eff2, on 2026-10-14: the owner ruled the name `server.router` in place of
    `server.routes` (decision 122 as amended). The files, the directory and the two build
    steps were renamed with it, as `zig build router-check` and `zig build
    router-hidden-check`. 181 steps, 2973, 467. `zig build router-check` passed 65 steps,
    and `zig build router-hidden-check` 8 tests.
  - After 5cefb6c, on 2026-10-14: the owner ruled that a table of 257 routes with one segment
    of 8150 bytes runs in a second test binary of `zig build router-hidden-check`,
    `router-quota`. The table is in `router_quota_test.zig`, and the step compiles it in
    parallel with the cross-check. 183 steps, 2979, 467. `zig build router-hidden-check`
    passed 14 tests in two binaries.
    - The step's wall time on the M1 Pro, with a test file changed to force its compile: 66 s
      before, at a load average of 6. After, 81 s twice with both compiles, at load averages
      of 4 and 7, and 67 s with the compile of the cross-check alone.
    - At a load average of 12 to 50, from other builds, the step took 152 s to 255 s, and
      `zig build test` took 664 s.
  - From 21e.2 on, `zig build test -Drelease` passed the count of `zig build test` after each
    commit.
- **What stayed.**
  - From 21e.3 on, `zig build bench-memory` printed the table of the base after each
    sub-step. No census, CRC, golden check or memory row changed.
  - After each sub-step, `zig build lint` passed inside `zig build test`, and
    `tools/doc_snippets.sh` and `zig build lint-commits` passed. From 21e.2 on, `zig fmt
    --check` and `tools/consumer_check.sh` passed too. At 73fbf50, `zig build lint` printed
    "cognitive-complexity: 9233 functions scored, highest 15 (max 15)". At 1c3a4f2, it
    printed 9248 functions, highest 15.
- **The examples.** At 73fbf50, `zig build examples` prints "every octet arrived as sent" for
  `h2_exchange`, `h11_exchange`, `server_exchange` and `client_exchange`. Each program prints
  its statuses in the order that the responses end. The clients of `server_exchange` get 200,
  200, 405, 404, 200 and 200. The client example gets 200, 405, 404, 501 and 200.
- **routes-check.** It compiles `accepted` and 22 refused tables, in 65 steps. 21e.4 added 14
  cases, 21e.5 five, 21e.6 one and 21e.7b three.
  - At 21e.4, the first run took 9.07 s and a run on a warm cache 2.28 s. A refused compile
    is not cached. Two runs of `zig build test` took 220 s and 232 s.
  - At 174c242, two runs on a warm cache took 2.61 s and 2.68 s, timed with `/usr/bin/time -p
    zig build routes-check`.
- **The cross-check.** `routes_hidden_test.zig` compares the check of hidden routes with a
  brute force on 2,838 tables. Each census gives the tables, then those with `route_hidden`,
  with `route_unreachable`, and those that compile:
  - The ordered pairs of two routes over 17 patterns, with GET and PUT: 1122, 240, 0 and 882.
  - The pairs over GET, HEAD and PUT that hold a HEAD route: 1428, 360, 0 and 1068.
  - Example 8's triples in its own order: 48, 36, 6 and 6.
  - Example 8's triples in the five other orders: 240, 180, 30 and 30.
  - 6ed56b1 pinned the first and the third census. 6eef776 added the second and the fourth.
- **The cost of the cross-check.**
  - At 6ed56b1, `zig build test-server --summary all` gave its compile as 51 s and 53 s,
    against 26 s and 25 s before.
  - At 6eef776, a warm run of `zig build test-server` took about 90 s, against about 40 s.
  - e6a5c77 obeys the first ruling of 2026-10-14. `zig build routes-hidden-check` compiles the
    cross-check in a test binary of its own, from `src/server/routes_hidden_check.zig`. After
    a change to a source file, timed with `date +%s`, `zig build test-server` took 86 s and
    86 s before, at a load average of 14 to 5. It took 27 s and 27 s after, at a load
    average of 6 to 4. `zig build routes-hidden-check` alone took 60 s and 61 s, at a load
    average of 7 to 6. Inside `zig build test`, its compile took 57 s.
  - No check caught the new step left out of `zig build test`. So `build/check_steps.zig`
    makes `zig build test` fail for each step whose name ends in `-check` that it does not
    run.
- **Large tables.** 546d6b1 is the first part of the second ruling of 2026-10-14. `match`
  finds a literal edge by a binary search over the edges of a node, which the build sorts by
  length and then by bytes. The check of hidden routes finds the leaves on the paths of a
  route by a walk of the trie.
  - Compile time, in seconds, before and after. Each table compiled twice in a probe project
    outside the tree, as `zig build ct-<name>`, a Debug test binary. The project depended on
    this checkout as a path package, and `bench/routes/` holds it since 1c3a4f2. The load
    average was 4 to 6.
    - One route: 2.0, then 2.0.
    - 256 literals beside `/:x`: 13.6, then 7.0.
    - 512 literals beside `/:x`: 68.2 and 68.5, then 23.3 and 23.4.
    - 512 literals beside `/zzz`: 26.7 and 26.8, then 19.9.
    - The table of 256 routes in `routes_test.zig`: 17.2, then 15.5.
    - 50 routes, of 10 resources each with five routes: 2.1, then 2.1.
  - Run time, in instructions for each match: callgrind's count for 100,000 matches less its
    count for none, divided by 100,000. The probe is a ReleaseSafe build for aarch64 Linux,
    run in Docker under OrbStack on the same M1 Pro. `bench/routes/run_time.sh` runs it since
    1c3a4f2. It is a number from a laptop, and
    docs/performance.md publishes only the numbers of the judge (decision 33). The root has k
    literal edges of four bytes. Each line gives the first edge, the middle edge, the last
    edge and a miss:
    - k = 1: 525, 525, 525 and 429, then 503, 503, 503 and 391.
    - k = 2: 536, 605, 605 and 498, then 568, 518, 518 and 397.
    - k = 4: 536, 674, 743 and 636, then 617, 518, 567 and 433.
    - k = 8: 536, 812, 1019 and 912, then 666, 518, 616 and 470.
    - k = 16: 466, 1002, 1471 and 1382, then 651, 450, 594 and 460.
    - k = 64: 535, 2743, 4882 and 4775, then 826, 526, 768 and 608.
    - k = 256: 557, 9133, 17642 and 17543, then 937, 559, 874 and 726.
  - The search costs more than the old scan only for the first edge, from k = 2 on. On the
    mean of the four segments it costs less at each k measured. So there is no threshold and
    no named limit. `search_passes_max` bounds the loop beside the code.
  - After 546d6b1, 512 literals beside `/zzz` still took 19.9 s, against 2.0 s for one route.
    That table does no walk in the check of hidden routes, so the rest of the cost was in the
    build of the trie and of the layout.
- **Large tables, the build.** 73fbf50 completes the second ruling of 2026-10-14. It changes
  no run-time code of `match`: in `routes_match.zig` only a test block changes.
  - Two causes, from small probes on Zig 0.16. First, the compiler keeps no result of a
    comptime call, so three equal calls cost three times one call. The merge of the trie ran
    four times for each table. Second, a comptime call that gets a large constant, or a
    pointer to one, costs time in proportion to the size of the constant. A pointer to a
    comptime `var` costs a few steps.
  - The parts of the cost, from a copy of the tree with one part removed each time. Each line
    gives the seconds of that part for the table of 512 literals beside `/:x` (23.0 s), and
    for the table of 256 routes in `routes_test.zig` (15.4 s):
    - The insertion sort of the edges: 9.3 and 5.2.
    - The scans of siblings in the merge: 3.3 and 1.7.
    - The scans of the routes of a node: 1.6 and 1.7.
    - The check of hidden routes: 6.1 and 3.0.
    - The pairwise check of parameter names took 1.2 s of 8.5 s for 256 routes `/rNNN/:id`.
  - So `server.routes` merges the trie once and passes it to the build and to each check.
    The loops pass pointers to `var` copies. A hash finds the child of a node, a merge sort
    orders the edges, and an index lists the routes of each node. The merge records the
    first route that gives a parameter node a second name, in place of the pairwise check.
    The check of hidden routes reads the layout through `routes_hidden_canonical.View`.
  - Compile time, in seconds, two runs before and two after, in the probe project of
    546d6b1's runs. Before is 315e3c1, at a load average of about 4. After is a build that differs
    from 73fbf50 only in the names of locals, in comments and in tests, at a load average of
    about 9:
    - One route: 2.1 and 2.1, then 2.2 and 2.1.
    - 256 literals beside `/:x`: 7.1 and 6.9, then 2.9 and 2.9.
    - 512 literals beside `/:x`: 22.8 and 23.1, then 4.0 and 4.7.
    - 512 literals beside `/zzz`: 19.6 and 19.9, then 3.6 and 3.4.
    - The table of 256 routes in `routes_test.zig`: 15.5 and 15.3, then 5.0 and 4.9.
    - 50 routes, of 10 resources each with five routes: 2.0 and 2.0, then 2.1 and 2.1.
    - 338 routes of mixed forms: 3.7 and 3.7, then 2.9 and 3.0.
    - 256 routes `/rNNN/:id`: 8.6 and 8.4, then 2.8 and 2.9.
  - Each table now compiles within 3 s of one route, and no table is slower than before. A run of
    315e3c1 and 73fbf50 in turns, at a load average of 25 to 67, agrees in direction: 512 literals
    beside `/:x` took 71.4 and 78.1 s before, and 19.7 and 15.7 s after.
  - The build gives the same layout as before. A scratch `@compileLog` wrote a hash of each
    array of each layout: 97 layouts in `zig build test-server`, 2843 in `zig build
    routes-hidden-check`, 2 in the examples and 8 in the probe. Some layouts occur in more
    than one set, so 2944 layouts differ. Each set was the same before and after.
- **The review.** Two readers read 21e.7b, and 6eef776 fixes what they found:
  - The check counted a literal each time it repeats when it chose "other". It refused a
    route that a request reaches at `path_len_max`, and it passed a hidden one.
  - The cross-check gained the pairs with HEAD and the five other orders of example 8.
  - One predicate decides `allow_too_long`.
  - The cost of the check grows with the square of the literal siblings of a parameter. The
    second ruling of 2026-10-14 answers it, in 546d6b1 and 73fbf50.
  - After 21e.10, fc90377, 31c52ee and 174c242 fix the client example, the guide's tables and
    the words of the router's text.
- **The citation.** Decision 122 ruling 1 cited RFC 9114 §4.1 for a response to HEAD with no
  content. RFC 9114 §4.1.2 states the rule, so the decision now cites §4.1.2. 21e.8a's code
  and tests cited §4.1.2 already.
- **Large tables, a second run.** At 1c3a4f2, on the same M1 Pro, with the probes of
  `bench/routes/`. `--tree` names an export of an older commit, made with `git archive`.
  - `bench/routes/run_time.sh`, and the same with `--tree` on e6a5c77, gave each count of
    546d6b1's runs within 3 instructions. For k = 256, the last edge took 17,642 at e6a5c77
    and 874 at 1c3a4f2.
  - `bench/routes/compile_time.sh`, in turns with `--tree` on 315e3c1, one table at a time,
    at a load average of 5 to 8. Each line gives two runs at 315e3c1, then two at 1c3a4f2:
    - One route: 2.03 and 2.07, then 2.06 and 2.07.
    - 256 literals beside `/:x`: 6.99 and 7.01, then 2.83 and 3.01.
    - 512 literals beside `/:x`: 23.61 and 23.79, then 4.11 and 3.93.
    - 512 literals beside `/zzz`: 20.12 and 20.14, then 3.51 and 3.46.
    - The table of 256 routes in `routes_test.zig`: 15.67 and 15.60, then 4.88 and 5.01.
    - 50 routes, of 10 resources each with five routes: 2.11 and 2.25, then 2.11 and 2.21.
    - 338 routes of mixed forms: 3.87 and 3.91, then 2.90 and 2.83.
    - 256 routes `/rNNN/:id`: 8.89 and 8.89, then 2.85 and 3.00.
  - With `--tree` on e6a5c77, at a load average of about 6, 512 literals beside `/:x` took
    68.98 s and 69.33 s. The table of 256 routes in `routes_test.zig` took 17.48 s and
    17.60 s.
  - After a change to `routes_hidden_test.zig`, `/usr/bin/time -p zig build
    routes-hidden-check` took 66.07 s and 66.30 s, at a load average of about 6. e6a5c77
    recorded 60 s and 61 s.
  - These runs give the two items that the first record owed for after the push.
- **The second review.** Two reviewers read the whole of step 21e at 6d080ea. One of them
  built and ran the checks below:
  - x86_64 Debug: `zig build test-server -Dtarget=x86_64-linux-gnu --summary all` compiled
    the test binary. In a `linux/amd64` container of `ubuntu:24.04`, it printed "All 466
    tests passed." The binary of `zig build routes-hidden-check` printed "All 8 tests
    passed." x86_64 ReleaseSafe and aarch64 Linux Debug passed the same counts.
  - Seven hostile tests of `match` in a scratch file passed on aarch64 macOS and in the
    x86_64 container, 473 of 473. They covered the binary search over 202 literal edges, paths
    of `path_len_max` bytes, and empty and dot segments. They also covered a query at each
    position, each of the 256 bytes, the methods, and 8 parameters.
  - `zig build examples` and `zig build lint-commits` passed.
  - After the fixes, at 1c3a4f2, the same container ran the x86_64 Debug binaries again.
    `zig build test-server` printed "All 467 tests passed.", and `zig build
    routes-hidden-check` printed "All 8 tests passed."
- **The findings of the second review.** Ten findings, and what each one became:
  - Decision 122's amendment claimed more than the records showed. It said that 21e removes
    the quadratic work. It named counts of edges that were not measured, and it gave a time
    of another build. The amendment now names what 21e removes, a table where the check stays
    quadratic, the counts measured, and the runs of 1c3a4f2.
  - The compile times and callgrind counts came from a probe outside the tree. 1c3a4f2 adds
    it as `bench/routes/`, and the second run above uses it.
  - Two comments cited "the plan's rule 13", a document outside the tree. c05ce20 cites the
    table of the cost of decision 122 ruling 12.
  - Two checks of colibri's own cited issue 96 in place of decision 122. c05ce20 cites
    decision 122 first.
  - The comment of the quota said that a walk reads each byte of its path once. Each pass
    reads the segment of its frame, and the search reads it again. 8a0dc3f states the true
    bound and adds it to the quota.
  - `quota_of` used the factor for each pair of routes as a factor for each route. 8a0dc3f
    names `quota_branches_per_route`, and a new test of 1,024 routes needs it.
  - INV-32 named step 21e.7, which the record split. c05ce20 names 21e.7a.
  - The guide did not say that CONNECT does not compile. c05ce20 says it, in the guide and
    in the doc comment of `routes`.
  - The router's text used -ing forms. c05ce20 changes them, and the heading "Routing"
    becomes "Routes".
  - The body of 73fbf50 counts 2950 layouts and lists 14 of its 15 mutations. The record of
    73fbf50 above holds the true count and list, so no commit changes.
- **Owed.** `tools/ci.sh` on the exact tree, before the push. 21e.8a changes what h11, h2 and
  h3 write in a response to HEAD, so the interop scripts run too. The session that started
  this step runs it.
- Mutations, each **CAUGHT** unless it says otherwise:
  - 21e.2, by `zig build test-http`: `Standard` left out of the namespace; `Standard`
    exported under a second name beside it.
  - 21e.3, 34 breaks, by `zig build test-server`:
    - The match: a literal compared by prefix; a literal compared without case; the query
      read; the first "/" not required; the root read as one empty segment, in `match` and
      in the build; the method compared without case; 404 for a wrong method; 405 for an
      unknown path, at no node and at a node with no leaf; the count not reset to 0; `get`
      that compares by prefix.
    - The Allow value: in the table's order; its tokens before the standard methods; joined
      by ","; without the last method of a leaf. The edges not sorted by length, which a new
      test catches.
    - The refusals: refusals 1 to 5, 11 to 16 and 18 each removed; refusal 3 widened to each
      segment that starts with "."; refusal 17 widened to an entry of four parts;
      `path_octets` widened to each byte; `segment_unsupported` removed; a `Standard` value
      refused.
    - Refusal 1 removed stops the build at the comptime assert of `segments_count`, so a
      compile error catches it.
    - Ten breaks ran a second time, in a form that compiles or with a search text that
      matches one place.
  - 21e.4, by `zig build routes-check`: `built` ignores the refusal; the messages of
    `route_repeated`, `segment_dot` and `method_connect` changed; the route index off by one;
    the control's table made invalid; the fixture builds no table; `expect_errors` not set;
    the fixture's path wrong.
  - 21e.5, by `zig build test-server`, and the messages by `zig build routes-check`:
    - The match: a value with its "/"; the name of another node; the parameter tried before
      the literal; rules 6, 7, 8 and 9 each removed; rule 9 widened to a segment that starts
      with "."; the count left at 0 after `found`; the count written for each result; the
      check of `path_len_max` removed, and off by one.
    - The refusals: refusals 6, 7, 8, 9 and 19 each removed; `name_octets` widened to "-";
      refusal 9 one parameter early; `holds_parameter` always false; `names_differ` that
      reads the wrong segment; refusal 19 removed, by `zig build routes-check` too; each of
      the five new messages changed.
    - Refusal 9 removed writes past the array of names at compile time, so a compile error
      catches it. Refusal 8 removed ran a second time, in a form that compiles.
  - 21e.6, by `zig build test-server`, and the message by `zig build routes-check`: the rest
    with its "/"; the rest that ends at the next "/", in a form that compiles; a wildcard of
    no segment; the wildcard tried before the parameter; the wildcard not counted in
    `path_parameters_max`; refusal 10 removed, by `zig build routes-check` too; the wildcard
    widened to each segment that starts with "*"; the message of `wildcard_not_last` changed.
    The wildcard widened to each segment that holds "*" stops the build at the assert of
    `add_wildcard`, so a compile error catches it.
  - 21e.7a, by `zig build test-server`: no back-up; a back-up that tries the literal again; a
    back-up of two levels; the wildcard not tried after a back-up from the parameter; no
    parameter or wildcard after a back-up; a node with no leaf after the last segment that
    gives `not_found`; `walk_steps_max` of one pass for each node.
  - 21e.8a, by `zig build test-server`:
    - h11: the drop removed, so h11's error comes back; the error restored in place of the
      drop; the drop before the final response.
    - h2: the drop removed; the entry of a response to HEAD released at its head; no entry
      for HEAD when the connection codes nothing; the content written at the end; the entry
      kept after the end; the end not written.
    - h3: the drop removed; the method not kept when the connection codes nothing; the
      stream not ended at the end.
  - 21e.8b, by `zig build test-server`: no fallback; the fallback taken over a HEAD route;
    HEAD not in the Allow value; GET that falls back to HEAD; HEAD twice in the Allow value
    when the table names GET and HEAD.
  - 21e.9, by `zig build test-server`: the method checked after the walk; `not_implemented`
    for a method that another leaf names; HEAD counted as not implemented when the table
    names GET; only the first token of the set compared; the set compared without case.
  - 21e.7b, by `zig build test-server`, and the first two and `allow_too_long` by `zig build
    routes-check` too: case 1 removed; case 2 removed; x(T, L, n) without the literals of L;
    the wildcard tried only at n = k; the HEAD fallback ignored when the check decides if a
    leaf serves a method; L only from the leaves after T; 405 replaced by `not_found`;
    `allow_too_long` removed; the walk skipped for each leaf; "other" chosen without the
    literals; an Allow value of exactly `field_value_len_max` refused.
  - 6eef776, by `zig build test-server`: each repeat of a literal counted again; a length
    whose segments are all taken that gives its first segment; a back-up for a method, a copy
    of the walk in `match` that goes on to the next leaf that matches and serves the method;
    405 replaced by `not_found`; the HEAD fallback ignored; an Allow value of exactly the
    limit refused; `allow_too_long` removed.
  - 21e.10, by `zig build examples`: in `server_exchange`, the 405 without its Allow field,
    the parameter not in the answer, the greeting and echo arms swapped, the 404 and 501 arms
    swapped, the 404 arm that answers 200, the 405 arm that answers 404, and the named route
    that greets the path and not the parameter; in `client_peer`, the two handlers swapped.
  - e6a5c77, by `zig build test`: the new step left out of `zig build test`; `zig build
    routes-check` left out of it; a step that counts as run only when `zig build test`
    depends on it directly.
  - 546d6b1:
    - By `zig build test-server`, and by the test of the first difference against the old
      scan: the low bound one high at the start; the high bound one low at the start; the
      high bound one too far; the low bound one too far; the bytes compared before the
      length.
    - By `zig build test-server` and `zig build routes-hidden-check`: the walk with no
      literal edges at a parameter, with no wildcard child, and with no parameter child;
      `precedes` called on a leaf with no common length.
    - By `zig build routes-hidden-check` alone: the walk with no literal edges past the
      literals of a wildcard leaf.
    - The leaves in the walk's order and not sorted: **NOT CAUGHT** at first. A new line in
      the test of refusal 20 pins the order, and it passed on the old check. Then **CAUGHT**
      by `zig build test-server`.
  - fc90377, by `zig build example-client_exchange`: in `client_peer`, the 405 without its
    Allow field; the 404 arm that answers 200; the 501 arm that answers 404; the 405 arm that
    answers 404; the two handlers swapped.
  - 31c52ee, by `zig build test-server`: the guide's table without `PUT /users/me`; a leaf
    that gives `found` at compile time for a method that it does not name.
  - 73fbf50, 15 breaks, by `zig build test-server`:
    - The merge: the child of another parent with the same segment; a child of the parent
      with another segment; no child found, so each segment added again.
    - The names: the last second name recorded, not the first; no second name found.
    - The routes of a node: the last left out; the first left out; the order reversed.
    - The repeated check: a route compared with itself; only the first route of a node read.
    - The merge sort: the right item taken when the left is less; runs that grow by one item
      a pass; one pass only; a last run with no partner left out of the pass.
    - HEAD that reads no route of the node.
  - 8a0dc3f, by `zig build test-server`: the factor for each route of `quota_of` set to 0,
    and set to 1. Before 8a0dc3f no test held a table that needs the factor.
  - After 5cefb6c, by `zig build router-hidden-check`, in the binary `router-quota` alone:
    the longest segment of the layout not read from its edges (`segment_len_max =
    other.len` in `view_refusal`). The compile fails with "evaluation exceeded 1043726368
    backwards branches". The binary `router-hidden` passed under the mutation.
- **NOT CAUGHT**, or no mutation, and why:
  - 21e.10: in `client_peer`, the 405 without its Allow field, and the 404 arm that answers
    200. No request of the client example reached the two arms. fc90377 adds the requests,
    and then each one is **CAUGHT**.
  - e6a5c77: a step with no dependencies that counts as run. It is equivalent, because each
    `-check` step has a dependency. The line is gone, and the doc comment states the rule.
  - The body of 6ed56b1 names a break "a back-up for a method". That break was "405 replaced
    by `not_found`". 6eef776 ran the real back-up for a method, and it is **CAUGHT**.
  - No check catches the line `_ = @import("routes/routes_hidden_test.zig");` removed from
    `src/server/routes_hidden_check.zig`: the binary then passes with 3 tests. Each test
    block of a module root has the same gap. It did not run as a mutation.
  - 73fbf50: the last second name recorded, not the first, and the repeated check that reads
    only the first route of a node. No test held a table with these shapes. Two new lines in
    `routes_refusal_test.zig` hold them: three names at `/a` and two at `/b` refuse route 2,
    and `GET /a`, `PUT /a`, `PUT /a` is `route_repeated`. Then each one is **CAUGHT**.
  - 73fbf50: the first form of the lone run that the merge sort leaves out copied the run. That
    form is correct, so it is equivalent. A form that leaves the run out is **CAUGHT**.
  - 8a0dc3f, by `zig build test-server` and `zig build routes-hidden-check`: the reads of
    each pass left out of `walk_octets`; the longest segment of the layout not read from its
    edges; the bound of the longest segment not read from the patterns. Each is **NOT
    CAUGHT**. The part for each pair of leaves gives each table that a test builds more
    branches than these reads use. A walk reads a long segment past the other parts only in
    more than 32 frames, and such a table has more than 32 leaves. No such table was found
    where the part for each pair is too small.
  - After 5cefb6c, by `zig build router-hidden-check` with `router-quota`: the reads of each
    pass left out of `walk_octets`, and the bound of the longest segment not read from the
    patterns. Each is **NOT CAUGHT**, and no table that the limits allow catches it:
    - Without the reads of each pass, the other parts of the quota still cover the reads of
      each walk. A table large enough to need them has a quota above `maxInt(u32)`, so the
      quota is `maxInt(u32)` with the mutation and without it.
    - The bound of `quota_bound_of` is `maxInt(u32)` for each table that could exceed it, so
      the mutation changes no result. For the table of `router_quota_test.zig`, the bound before
      the clamp is 8.9e15 without the mutation and 3.0e12 with it, and both become
      4,294,967,295.
  - 21e.1, f20e74d, 800ebda, 174c242, 315e3c1, c05ce20, 1c3a4f2 and the record of the second
    review change no check. The test counts are the
    check of 800ebda.

**After 21e, 2026-10-17.** Three issues that step 21e found or that a dependent asked for, on
the owner's rulings of 2026-10-17. Run on macOS 26 on an Apple M1 Pro, with Zig 0.16.0, on the
branch `paths-tls-102-104` over main 3952bcc.
- **e02fb20, [#103](https://github.com/c4milo/colibri/issues/103).** `server.router` reads a
  query alone, such as the "?x" of `GET http://a?x`, as the root (RFC 9110 §4.2.3; decision 122
  as amended on 2026-10-17). The router's sweep reads a query alone as the root too.
  `zig build test-server`: 468 tests, 467 before. Mutations, each **CAUGHT** by test-server: the
  new rule removed; a query alone refused; the "" of a CONNECT request read as the root too.
- **3998aba, [#102](https://github.com/c4milo/colibri/issues/102).** h2 and h3 hold `:path` to
  the absolute-path and query of RFC 3986 §3.3 and §3.4 (RFC 9113 §8.3.1, RFC 9114 §4.3.1), as
  h11 holds an origin-form target. `zig build test-h2`: 385 tests, 384 before; one more case in
  an h3 test. Mutations, each **CAUGHT**: the first byte alone checked (test-h2 and test-h3);
  the grammar check skipped; the query not checked (test-h2). The simulator's censuses did not
  move.
- **bad1757, [#104](https://github.com/c4milo/colibri/issues/104).** The chapulin pin moves
  from v0.2.0 (26fa782) to 6f3bf952, and `tls.values.Client` gains `takes_tickets` (decision 94
  as amended on 2026-10-17). `tls.constants.anchors_max` is 12. A new test,
  `src/tls/record/record_ticket_test.zig`, shows that a client that takes no tickets keeps none
  and still resumes with a ticket it offers. The memory table moves by 8 to 144 bytes a row,
  for example `client.Channel` from 995,328 to 995,352. Mutations, each **CAUGHT**:
  `takes_tickets` not passed, or passed as true (test-tls); `anchors_max` 11 or 13
  (test-bench, through the memory table).
- **The chapulin pin moves from 6f3bf952 to e6e3c1e7** (decision 94 as amended a second time
  on 2026-10-17). chapulin's clock is now a function that its `init` calls once, so each `tls`
  session keeps the instant `start` was given, and `config.clock_at` answers it. The rows of
  the memory table move by 8 bytes down to 48 up, for example `client.Channel` from 995,392
  to 995,400. Mutations, each **CAUGHT** by test-tls: the instant written as 0 in the record
  client, the record server, the QUIC client and the QUIC server.
- `zig build test`: 183 steps and 2,983 tests, against 2,979 at 3952bcc.
- **Owed before the push.** `tools/ci.sh` on the exact tree, which runs the interop and TLS
  checks against the new chapulin.

**21f, the client's gaps, 2026-10-17.** What `client` lacked for a program that leaves the
protocol modules (decision 124). Run on macOS 26 on an Apple M1 Pro, with Zig 0.16.0.
- **Where.** The commits were written on the branch `client-gaps-21f` over main fa0842d. They were
  replayed by cherry-pick over main aea97ae, then over 28649a3, then over 3d240941, which replayed
  with no conflict. Each memory table was rebuilt from its own commit's tree, and each endpoint
  census pin from its own merged tree. 28649a3 holds decision 123, QUIC's skipped packet numbers,
  so this step's decision became 124 in its text, its code and its commit messages. 21f's own
  ruling, whether `h11`, `h2`, `h3` and `quic` stay exported, waits for the dependent to leave
  `h11`.
- **The rulings, 2026-10-17.**
  - The owner went with the recommendations for the dependent's gaps.
  - The owner then ruled `client.Request` and `client.Response` in place of
    `client.HttpExchange`.
  - The dependent's owner withdrew `Response.response_began`, `ended_by_close` and
    `Channel.negotiated` ("No leaky abstractions"). The owner ruled the resend of ruling 3 in
    their place.
  - The owner ruled the TLS stall fix of ruling 7, and the endpoint census that it moves.
- **The root.** `client` lists 41 names: `HttpExchange` left, and `Request`, `Response`,
  `ChannelOf` and `Capacity` came. `client.StartError` gains `VersionUnavailable`. `Request`
  has no call, and `Response` has `content_received` alone.
- **a2bef06, 21f.1.** Decision 124 and this step's text.
- **f044aac, 21f.2.** The split, with every caller in the tree. `Finished` names the request and
  the response. The simulator's censuses and the client, TCP and deadline trace logs stayed
  byte-identical. Mutations, each **CAUGHT** by test-client or test-sim-run:
  - the channel's assertion on the request pointer, inverted;
  - the same on the response pointer;
  - the client trace world's new assertion, inverted.
- **9ec604a and be0a7f2, 21f.3.** An early final response, and a response dropped while the
  content goes out, end the h11 connection. Raw-byte peers show both, and show that a response
  after all the content keeps the connection. Mutations, each **CAUGHT** by test-client:
  - the rule removed;
  - the connection ended after every final response, or whenever no exchange awaits;
  - the connection left open to write;
  - a response to an earlier exchange that ends the connection;
  - the drop rule removed, and the drop rule applied after the content is done;
  - the head path and the data path that read on after the end.
- **202625c, 21f.4.** The channel sends an idempotent request again, once, after a close before
  any byte of its response. 23 tests in h11, h2 and h3. Mutations, 13, each **CAUGHT** by
  test-client:
  - no resend;
  - a POST, or a token, sent again;
  - a resend after part of the response;
  - h11 that does not mark the start of a response on entry, or on leftover bytes;
  - h2, and h3, that does not mark it;
  - a resend twice;
  - a budget apart from refusals;
  - a cancelled exchange sent again;
  - the refused-to-closed change removed;
  - the `resent` flag not set.
- **The client trace census of 202625c.** It moved for 9 seeds (38, 75, 95, 110, 114, 155, 181,
  185, 210), each a GET sent again once. With the resend turned off, the old census came back
  exactly.
  - states 2569 to 2589, responses 342 to 348, failed 59 to 52, cancelled 48 to 49;
  - moved 4 to 12, and resent 9, a new field;
  - quic 120 to 119, tcp 274 to 279, goaways 49 to 50, learned 60 to 61.
- **The model of 202625c.** `spec/tla/client_exchanges` gained the resend and two mutants in
  `mutants/`. At 7de35d3, `zig build tla` gave each of the model's 21 configurations its
  expected verdict: 9 hold and 12 violated, the largest, `reconnect`, at 16,044,834 distinct
  states. `tools/client_trace.sh` found 67 of 67 traces to be behaviors of the model.
- **ee272b0, 21f.5.** `stream_input_len_min` (32,768), `stream_output_len_min` (16,645) and
  `receive_events_without_input_max` (25), each with comptime asserts and a test at its edges.
  Of 18 mutations, 16 are **CAUGHT**. 2 are **NOT CAUGHT**, each a constant one less with its
  assert removed:
  - the output one byte less: chapulin's largest record is 16,406 bytes, so no run sees it;
  - the events one less: no test makes more than 19 of the 25 events.
- **4fe67f2, 21f.5's fix.** `plaintext_in_len` grows from 33,033 to 49,407 in the client and the
  server (decision 124 ruling 7). A test in each failed before the fix: a 30,000-byte head in
  12,000-byte records. The endpoint census moved for seeds 0x25, 0x3a and 0x49, each with a TLS
  peer whose connection now opens records in fewer calls: crc32 0x560d5625 to 0xf16f98da, wire
  0x5ec49f44 to 0x1e3dec81, over aea97ae. It was the same in Debug and ReleaseSafe, P1 to P8
  held, and failed stayed 0. Over 28649a3, whose QUIC connections draw at start, the pin is
  crc32 0x33a73ac7 and wire 0xf0a61cbb. Mutations, on each side:
  - **CAUGHT**, each with and without its assert: the old value; the h11 term left out; the
    record term left out.
  - **NOT CAUGHT**: the h2 term left out, which the h11 term covers; the byte short of the
    limit; and, as expected, the old value with records of 16,384 bytes, which fit it.
- **0240ce7, 21f.6.** `client.ChannelOf(.{ .quic = false })` holds 307,360 bytes, against
  `client.Channel`'s 1,012,152, and has no `start_quic`. The TCP tests run on both types. It
  closes [#99](https://github.com/c4milo/colibri/issues/99) by the static size, not the resident
  memory of 64 channels that it first asked for. Its commit body gives sizes from before the
  replay: 703,848, 307,352 and 1,012,104. Mutations, each **CAUGHT**:
  - the QUIC connection kept;
  - `init` that takes h3;
  - the default capacity with no QUIC, at compile time.
- **1a12445, 21f.7.** The four doc lines of decision 124 ruling 6, the guide, and the consumer
  program, which now holds a channel with no QUIC.
- **The review.** One agent built, read and tried to break the step. It found 8 problems, which
  the commits after 19c6d45 fix:
  - F1, 6fb0b73: after a failed h11 connection, the requests sent again went out pipelined at
    once, which RFC 9112 §9.3.2 forbids. Now the first one goes alone until its final response.
  - F2, 16fdaf5: a TLS record failure after response bytes in the same input sent the GET
    again. The connection now reads what earlier records opened before it opens the next one.
  - F3, b8aa45f: over h2 and h3, a HEADERS frame that did not decode led to a resend. The
    header of a HEADERS frame now marks the start of a response.
  - F5, 665ad2b: `Request.content_length` and `Response.clear` were public with no program to
    call them. They are internal now.
  - F4, F6, F7 and F8: the promise of `stream_input_len_min`, a size in decision 124, the
    citations of RFC 9112 §9.5, and prose. The last commit fixes them.
  - Mutations of F1, F2, F3 and F5: 17, each **CAUGHT** by test-client.
- **The pins that the review's fixes moved,** both from F2:
  - TCP trace states 563 to 525: each of the 38 TLS seeds logs one state fewer, with the same
    first and last state. Its wire crc32 0x553ad660 did not change.
  - The endpoint census: crc32 0xf16f98da to 0x5f207af3, wire 0x1e3dec81 to 0x734f205d, over
    aea97ae. Only seed 58 changed, and only its wire CRC: its TLS client peer now reads between
    records. Over 28649a3 the pin is crc32 0x81186212 and wire 0x1853ad5a.
- **x86_64.** The review ran the client and server tests built for x86_64-linux in an amd64
  container: Debug with Zig's own x86_64 backend, 282 and 482 tests, and ReleaseSafe, the same.
  Each exit status was 0.
- `zig build test` after the review's fixes: 183 steps and 3,109 tests over aea97ae, and 3,114
  over 28649a3.
- **Owed before the push.** `tools/ci.sh` on the exact tree, which runs the TLA+ models, the six
  trace checks (`tools/tcp_trace.sh` for the 38 changed logs) and the interop scripts.

**After 21f, 2026-10-18.** The client and the server keep opening TLS records while a KeyUpdate's
reply is owed. A dependent found the hold: after a peer's KeyUpdate that asked for a reply,
colibri opened no record until its next `send`, so a program that writes only when its socket
has room stopped. RFC 9846 §4.7.3 asks only that the reply go out "prior to sending its next
Application Data record", which `send` already does. The owner ruled the fix on 2026-10-17.
- **Why it is safe.** RFC 9846 §4.7.3 says a sender "MUST NOT send another KeyUpdate with
  request_update set to "update_requested"" until it receives the peer's KeyUpdate, so an honest
  peer leaves one reply owed at most. chapulin's provider holds `key_update_replies_max` (2), and
  a read that would owe more fails.
- **Tests.** Over a provider that protects nothing:
  - the client opens a response behind the KeyUpdate in the same `receive`, and its next request
    goes out after the reply;
  - the server opens a request behind the KeyUpdate, and its response goes out after the reply;
  - the server ends a connection whose peer asks again while a reply is owed.
- **Mutations.**
  - **CAUGHT**: the old rule restored, in the client and in the server (each new test fails);
    the plain provider that takes a second request; a read that stops after any record with no
    data (the close_notify tests).
  - **NOT CAUGHT**, in the client: a read that stops after a record with no data that is not a
    close. It is equivalent: the next `receive` opens the record behind it. The server's tests
    catch it.
- `zig build test`: 183 steps and 3,116 tests.

**chapulin 50d7d17b, 2026-10-19.** The chapulin pin moves from e6e3c1e7 to 50d7d17b (decision 94
as amended a third time). chapulin's decision 138 moves the answer to a peer's KeyUpdate from
`read` to `write`. `write` sends one answer in front of its first record of data, for every
request read since this side's last KeyUpdate. `read` sends only the alert of a failure. It reads
16 KeyUpdates in a row, `CH_KEY_UPDATE_RUN_MAX`, and fails the 17th with unexpected_message.
- **The owner's rulings, 2026-10-18 and 2026-10-19.**
  - The pin moves after the three performance changes of 2026-10-18, and the TCP TLS paths
    change with it.
  - The rule of 5368f5b that a second request ends the connection while an answer is owed is
    dropped. One answer serves the run (RFC 9846 §4.7.3), and chapulin's limit of 16 bounds it.
  - `tls_provider.Content` merges `new_session_ticket` and `key_update` into `without_data`.
  - `tls.constants.key_update_replies_max` is removed.
  - A run past chapulin's limit gets its own name, after the pattern of `records_without_data`.
    `tls_provider` names it `OpenError.KeyUpdates`, h2 names it `h2.Limit.key_updates`, and h11
    names it `error.KeyUpdates`. The server maps each by name to `server.Limit.key_updates`.
- **What changed.**
  - The adapter keeps only the alert of a failed read, so `State.owed` holds 24 bytes in place
    of 78. It asserts that nothing is owed before a read, and that a read that succeeds sends
    nothing.
  - h2 and h11 lose `Decrypted.owes_handshake`. `handshake_owed` now means only the alert of a
    failure, and `encrypt` asserts it. `encrypt` writes no owed bytes in front of data, so
    `seal_refused` loses its branch for them.
  - The server's `owes_octets` no longer reports `send` for an answer alone. No chapulin call
    sends the answer without data, and RFC 9846 §4.7.3 permits the wait.
  - Both plain providers model chapulin 50d7d17b in three rules:
    - A run count over both kinds of KeyUpdate. Only a record of one byte of data or more ends
      a run.
    - One answer, which `encrypt_record` writes in front of data.
    - An unexpected_message alert past 16 KeyUpdates in a row, which `take_alert` names.
  - The simulator's null provider reports an empty record of application data as
    `without_data`, as `Content` now says. No pinned census of test-sim, test-sim-run or
    test-sim-run-quic moved, because no check of the simulator writes an empty record.
- **What older records said that no longer holds.**
  - The record of 2026-09-24 ([#62](https://github.com/c4milo/colibri/issues/62)) and step 16b
    say that `handshake_write` writes the answer to a KeyUpdate. They also say that the provider
    holds `key_update_replies_max` answers.
  - The record "After 21f, 2026-10-18" says that an honest peer leaves one answer owed at most.
    When requests cross, a second request can be legal (RFC 9846 §4.7.3).
- **Tests.**
  - test-tls-keylog, over chapulin:
    - The answer is in front of the next record of data, and empty plaintext writes none.
    - Two requests in a row get one answer.
    - The close_notify after a request is the alert alone, under the first keys.
    - The 17th KeyUpdate in a row fails the read. The adapter sends only its alert, under the
      first keys.
  - test-server:
    - The server reads a second KeyUpdate that asks while the answer is owed, and one answer
      serves both.
    - A run past the provider's limit ends the connection over h11 and h2. The server sends only
      the alert, and `take_alert` names it.
    - A record of data ends a run, so the server reads a second run of 16 KeyUpdates. One more
      KeyUpdate ends the connection.
  - test-client: a record of data ends a run, and one KeyUpdate past the second run ends the
    connection. The client sends only the alert, and `take_alert` names it.
  - test-sim: the null provider reports an empty record of application data as `without_data`.
  - test-h2 and test-h11: a record without data leaves nothing owed, and after a failure
    colibri asks the provider once.
- **Mutations.**
  - **CAUGHT**, each one:
    - The alert of a failed read not kept.
    - `owed_len_max` one byte short.
    - `seal` without `writableLen`, and `seal` that asks chapulin to seal empty plaintext.
    - A record without data reported as data, in the adapter and in the null provider.
    - The old `owing` restored, in h2 and in h11.
    - `write_owed` that asks the provider again after the alert, in h2 and in h11.
    - A plain provider that fails a second request, or writes the answer in front of every
      record.
    - A plain provider that never ends a run, in the server and in the client.
    - A plain provider whose `take_alert` stays null past the run, in the server and in the
      client.
    - An adapter that writes the owed answer in front of the close_notify. chapulin's `close`
      sends no answer, so the mutant calls `write` with one byte when `writableLen` shows the
      answer owed. It then copies the answer in front of the alert.
  - **NOT CAUGHT**: the `owes_octets` branch for `handshake_owed` restored. It is equivalent:
    only a failure sets `handshake_owed` now, and the line above it returns first for a failure.
- The memory table: each `tls.record` session falls by 56 bytes, to 40,480 for the client and
  39,840 for the server. Each row that holds a TCP connection falls by 56 bytes, or by 48 for
  an endpoint of one TCP connection, after alignment. `server.Endpoint` falls by 896.
- **x86_64.** The tests of `tls_provider`, h2, h11, the server, the client, the simulator and
  tls-keylog ran in an amd64 container. Each was a Debug build for x86_64-linux, with Zig's own
  x86_64 backend. They passed 8, 385, 126, 492, 303, 79 and 68 tests, and each exit status was 0.
- `zig build test`: 183 steps and 3,128 tests.
- **The name of the run limit, 2026-10-20.** A second commit names a run past the provider's
  limit. The first commit ended such a run as `TlsFailed`, with no close reason.
  - `tls_provider.provider.OpenError` gains `KeyUpdates`. The adapter keeps the alert of the
    failed read, then maps chapulin's `KeyUpdateLimit` to it.
  - h2 ends the record layer and sets `failure_limit` to the new `h2.Limit.key_updates`. It
    queues no GOAWAY, because colibri sends no frame after the alert (RFC 9846 §6). h11 fails
    with `error.KeyUpdates`. Both return `TlsFailed`, so neither `RecordError` changes.
  - `server.Limit.key_updates` is new, and `passed_limit` maps h2's limit and h11's failure to
    it. Both plain providers fail with `KeyUpdates` past 16.
  - Tests:
    - The 17th KeyUpdate fails chapulin's read with `KeyUpdates`.
    - h2 and h11 name the limit and write the alert alone.
    - h2 names no limit after another failure.
    - The server names `key_updates` over h11 and h2. It names it too when one KeyUpdate passes
      the second run, after a record of data ended the first one.
  - Mutations, each **CAUGHT**:
    - `KeyUpdateLimit` mapped to `TlsFailed`, and its alert not kept.
    - h2 with no `failure_limit`, h2 through `fail_limit` in place of `end_tls`, and h2 that
      names the limit after another failure.
    - h11 that records `TlsFailed`, or that does not end the record layer.
    - h11's branch in `passed_limit` removed.
    - A plain provider that fails with `TlsFailed`.
    - A plain provider that never ends a run, or whose `take_alert` stays null past the run, in
      the server and in the client.
  - **x86_64.** The tests of `tls_provider`, h2, h11, the server, the client, the simulator and
    tls-keylog ran as above. They passed 8, 386, 127, 492, 303, 79 and 68 tests, and each exit
    status was 0.
  - `zig build test`: 183 steps and 3,130 tests.
- **Owed before the push.** `tools/ci.sh` on the exact tree. Its interop checks show whether Go,
  curl, nghttp, h2o or Caddy send a TLS KeyUpdate, and whether a peer waits for the answer.
