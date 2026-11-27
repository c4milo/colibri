# Design §8 step 45: colibri's public API in Zig's idioms, proposed 2026-11-07

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 158](../../decisions.md). TigerStyle rules first, and Zig 0.16's std rules where TigerStyle says
nothing. The step changes names and signatures, and no behaviour on the wire. It ships in v0.15.0,
and lands before step 44's commits 44b to 44l, which then use its names. The owner ruled the open
names on 2026-11-07: see "The owner's name rulings" below.
- **The public names**, module by module, in decision 115's order. "Adds", "renames" and
  "removes" name a root's list or a type's list of `core.public_names.expect`. Each root's
  list after the step follows.
  - `core` (pattern 12, ruling 6).
    - Renames: `Reader.read_byte` to `take_byte`, `Reader.read_int` to `take_int_big`, and
      `Writer.write_int` to `write_int_big`.
    - Adds: `Reader.Error` and `Writer.Error`. Removes: the namespaces `reader` and `writer`.
    - The root's list: `constants`, `Reader`, `Writer`, `Pool`, `Level`, `levels_count`,
      `fuzz` and `public_names`.
  - `http` (patterns 4 to 8).
    - `Status` becomes a non-exhaustive `enum(u16)`. Its declarations: `Class`, `Error`,
      `class`, `from_code`, `from_digits`, `write_digits` and `is_recognized`.
    - Removes: the namespaces `status` (with `Code`), `field_section`, `uri_percent` and
      `uri_query`, and `FieldSection.clear`.
    - Adds: `FieldSection.AppendError` and `FieldSection.Iterator`, from `field_section`;
      `QueryParameters.ReadError`, from `uri_query`; `uri.decoded_at` and `uri.encoded_len`,
      from `uri_percent`; `message_request.Kind`.
    - Renames: `content_coding.read_accept` to `content_coding.Acceptance.read`.
    - The root's list: `core`, `constants`, `FieldSection`, `Field`, `Status`,
      `QueryParameters`, `field`, `connection_specific`, `method`, `content_length`,
      `message_lines`, `message_request`, `uri` and `content_coding`.
  - `h11` (patterns 5, 7, 9 and 10, and decision 158 ruling 10).
    - Removes: the namespaces `connection` and `connection_tls`.
    - `Connection` adds `Options`, `Error`, `Event`, `Request`, `SendError`, `RecordError`,
      `Failure`, `decrypt`, `encrypt` and `close_notify`. `init` takes `(connection,
      options)`, and `Options` gains `role`.
    - `coding`: `Decoding` adds `start`, `reserve`, `begin`, `decode`, `finish` and `release`,
      and the free functions of the same names leave. `Pool(options)` takes a `PoolOptions`
      and adds `init(pool, features)`. Removes `DefaultPool`, and `Storage.reset` from the
      program's calls.
    - The root's list: `core`, `http`, `constants`, `Connection`, `message`, `chunked` and
      `coding`.
  - `h2` (patterns 5 to 7 and 9 to 10).
    - Removes: the namespaces `connection` and `connection_tls`. `connection.Event` and
      `connection_tls.attach` leave with no new path: `h2.Event` and
      `Connection.attach_tls` stay.
    - `Connection` adds `Options`, `AltSvc`, `Data`, `DataWritten`, `Request`,
      `RequestError`, `RequestIndexing`, `RequestHead` (was `connection.Request_`),
      `Response`, `SendError`, `StreamReset`, `Error`, `Received`, `AttachError`,
      `RecordError`, `close_notify`, `decrypt`, `encrypt`, `encrypt_parts` and
      `writable_len`. `init` takes `(connection, options)`.
    - `frame` adds `Type`, and `frame.Header.type` takes it.
    - The root's list: `core`, `wire`, `http`, `hpack`, `tls_provider`, `constants`, `Role`,
      `FieldBlock`, `Connection`, `Event`, `Limit`, `Window`, `frame` and `stream`.
  - `h3` (patterns 5, 7 and 8).
    - Renames: the namespace `frame_write` to `frame`, which holds `write_header`.
    - Removes: the namespace `connection`. `Connection` adds `Data`, `Ended`, `Error`,
      `Event`, `HeadWait`, `Options`, `Request`, `Response`, `SendError` and `RequestHead`.
      `write_request` takes a `RequestHead`, with `section`, `indexing` and `hold_data`.
    - The root's list: `core`, `wire`, `http`, `qpack`, `quic`, `constants`, `Connection`,
      `frame` and `message`.
  - `hpack` (patterns 5 and 6).
    - Removes: the namespace `encoder`, with its copy of `Indexing`. `decoder` keeps the
      test-only `expect_lines` and `test_decoder`, under their comment.
    - Adds: `Decoder.Error`, `Decoder.Block`, `Encoder.Error` and `Encoder.HuffmanUse`.
    - The root's list: `core`, `wire`, `http`, `constants`, `Field`, `DynamicTable`,
      `Decoder`, `FieldLine`, `Encoder`, `Indexing` and `decoder`.
  - `qpack` (pattern 5).
    - Removes: the namespaces `encoder` and `decoder`.
    - Adds: `Encoder.HuffmanUse`, `Encoder.Indexing`, `Encoder.DecoderStreamError`,
      `Encoder.Coding`, `Decoder.Error`, `Decoder.Outcome`, `Decoder.Settings`,
      `Decoder.error_code` and `Decoder.Abandoned`.
    - The root's list: `core`, `wire`, `http`, `constants`, `Encoder`, `Decoder`,
      `decoder_stream` and `instruction`.
  - `quic` (patterns 2, 5, 7 and 11).
    - `Connection` adds one declaration for each call a program makes. The table below maps
      each one. `Connection` also adds `Options` and `IdentityOptions`, the file
      declarations that `init` takes today and that no path names (pattern 5). Its list then
      holds `Options`, `IdentityOptions`, `init`, `addressed_by` and each name in the right
      column.
    - Adds to the root: `Ecn` (was `connection_send.Ecn`), `ConnectionClose`, `Stream`,
      `StreamId`, `StreamProvider`, `Frame`, `ReceivePool`, `ReceivePoolOptions`,
      `ReceiveStorage`, and the namespaces `version` and `retry`.
      - `Stream`, `StreamId` and `StreamProvider` move from `stream`, and `Frame` from
        `frame`. Each old path goes, so each type has one path (ruling 7).
      - `Stream` is the stream that a connection holds, which was `stream.Stream`.
        `frame.Stream` stays the STREAM frame (RFC 9000 §19.8).
      - `ConnectionClose` is the one path of the CONNECTION_CLOSE frame (RFC 9000 §19.19),
        and `ConnectionClose.transport` is its declaration. `frame` holds no copy of it.
    - Renames, with no name that repeats itself: `stream.stream_provider.VTable` to
      `StreamProvider.VTable`; `stream.stream_incoming.block_len` to
      `stream.receive_block_len`; `frame.frame_ack.Range` to `frame.AckRange`;
      `frame.frame_control.NewConnectionId` to `frame.NewConnectionId`;
      `packet.packet_number` to `packet.number`; `transport_parameters_read.read` to
      `transport_parameters.read`.
    - Removes: the 17 namespaces from `connection_datagram` to `connection_qlog`,
      `stream.Stream`, `stream.StreamId`, `stream.StreamProvider`, `frame.Frame`,
      `stream.stream_incoming` with `DefaultPool`, `stream.stream_table`,
      `frame.frame_ack`, `frame.frame_control` with its `ConnectionClose`, and
      `transport_parameters_read`.
    - Stays: the names that only the simulator, the corpus and the test endpoints call, in
      `connection`, `connection_receive`, `connection_recovery`, `connection_frames`,
      `connection_keys`, `connection_stream_frames`, `connection_stream_recovery`,
      `recovery_ack` and `recovery_sent`. Their comment says so.
    - The root's list: `core`, `wire`, `crypto`, `tls_provider`, `qlog`, `constants`,
      `error_code`, `Connection`, `PeerAddress`, `CongestionController`, `ResumeState`,
      `ResumeBounds`, `ResumeProvider`, `Space`, `Recovery`, `Ecn`, `ConnectionClose`, `Stream`,
      `StreamId`, `StreamProvider`, `Frame`, `ReceivePool`, `ReceivePoolOptions`,
      `ReceiveStorage`, `version`, `retry`, `connection`, `connection_receive`,
      `connection_recovery`, `connection_frames`, `connection_keys`,
      `connection_stream_frames`, `connection_stream_recovery`, `recovery_ack`,
      `recovery_sent`, `packet`, `frame`, `transport_parameters` and `stream`.

    | Before | After |
    | --- | --- |
    | `connection_datagram.receive`, `Received`, `Scratch`, `Error`, `connection_error_code` | `Connection.receive`, `Received`, `ReceiveScratch`, `ReceiveError`, `receive_error_code` |
    | `connection_send.send`, `Sent`, `Error`, `DefaultScratch` | `Connection.send`, `Sent`, `SendError`, `SendScratch(options)` with `SendScratchOptions` |
    | `connection_timer.next`, `on_instant` | `Connection.deadline`, `on_instant` |
    | `connection_resume.observe` | `Connection.resume_state` |
    | `connection_idle.deadline_ns`, `timeout_ns`, `probe_timeout_ns`, `owe_keep_alive`, `keep_alive_owed` | `Connection.idle_deadline_ns`, `idle_timeout_ns`, `probe_timeout_ns`, `owe_keep_alive`, `keep_alive_owed` |
    | `connection_close.owe`, `owes`, `transport` | `Connection.owe_close`, `owes_close`, `ConnectionClose.transport` |
    | `connection_stream_send.open`, `supply`, `reset`, `stop_sending`, `set_priority`, `write`, `write_endings`, `Error` | `Connection.open_stream`, `supply`, `reset_stream`, `stop_sending`, `set_stream_priority`, `write_stream_frame`, `write_stream_endings`, `StreamSendError` |
    | `stream.stream_table.OpenError` | `Connection.OpenStreamError` |
    | `connection_stream_read.read`, `peek`, `consume`, `reset_code`, `Read`, `Error` | `Connection.read`, `peek`, `consume`, `reset_code`, `StreamRead`, `StreamReadError` |
    | `connection_stream_acknowledged.acknowledged_end`, `resets_acknowledged` | `Connection.acknowledged_end`, `resets_acknowledged` |
    | `connection_flow.credit_owed`, `count_credit_owed`, `data_credit_owed` | `Connection.credit_owed`, `count_credit_owed`, `data_credit_owed` |
    | `connection_stream_credit.send_credit` | `Connection.send_credit` |
    | `connection_version.chooser`, `speaks`, `supported_versions` | `Connection.version_chooser`, `version.speaks`, `version.supported_versions` |
    | `connection_retry.answer`, `verify_token` | `retry.answer`, `retry.verify_token` |
    | `connection_id_frames.issue` | `Connection.issue_connection_ids` |
    | `connection_migration.challenge`, `ChallengeData` | `Connection.challenge_path`, `ChallengeData` |
    | `connection_key_update.initiate` | `Connection.initiate_key_update` |
    | `connection_qlog.init` | `Connection.attach_log` |

  - `crypto` (pattern 6). Removes `suite.Level`, `suite.Direction` and `suite.Role`. The
    root's list does not change: `core`, `constants`, `Suite`, `Level`, `Direction`, `Role`,
    `suite` and `packet_number`.
  - `tls_provider` (patterns 6 and 13).
    - Removes: `provider.Content`, `quic_provider.VTable` and `Provider.is_complete`.
    - `Provider` adds one method for each member of `VTable`: `handshake_read`,
      `handshake_write`, `encrypt_record`, `writable_len`, `encrypt_parts`, `decrypt_record`,
      `negotiated_alpn`, `handshake_complete`, `negotiated_parameters`, `take_alert`,
      `send_close_notify`, `initiate_key_update` and `export_keying_material`. `speaks_h2`
      stays.
    - The root's list does not change.
  - `tls` (patterns 5 and 10). The `record` list adds `Error`, `Progress` and `ConfigError`.
    `record.Client.alert` and `record.Server.alert` return `?tls_provider.Alert`. The root's
    list does not change.
  - `dnssec` (pattern 10). `Error` holds `SignatureVerificationFailed` and `InvalidEncoding`
    in place of `Auth` and `Invalid`. No list changes.
  - `server` (patterns 1 to 5).
    - `Engine(capacity)` replaces `EndpointOf(capacity)` and `Endpoint`, the type of the
      default capacity. `Engine(capacity)` adds `Accepted`, and `init` takes
      `(engine, config, random, now: Instant)`.
    - The directory `src/server/endpoint/` becomes `src/server/engine/`, and each file
      `endpoint_*.zig` becomes `engine_*.zig`.
    - `Router(Context, table, options)` replaces `router`. Its type's list: `Route`, `Match`,
      `match`, `memory_bytes` and `handle`.
    - `EncoderPool(options)` and `DecoderPool(options)` replace `DefaultEncoderPool` and
      `DefaultDecoderPool`. `EncoderPool.reset` becomes `EncoderPool.init`, and `encoders()`
      stays. `DecoderPool` adds `init(pool, features)`, and `Decoders.reset` leaves the
      program's calls.
    - `ResponseWriter` adds `Error`. `Response.status` and `ResponseWriter.status` take
      `Status`.
    - The root's list: `constants`, `Config`, `Protocols`, `Limits`, `Timeout`, `Timeouts`,
      `CloseReason`, `Limit`, `Engine`, `Capacity`, `Instant`, `Input`, `Datagram`,
      `StreamBytes`, `LogProvider`, `ResumeProvider`, `ResumeState`, `ResumeBounds`, `Sent`,
      `Address`, `Ecn`, `StartError`, `SendError`, `Header`, `RequestId`,
      `ConnectionHandle`, `Version`, `Headers`, `Event`, `Request`, `RequestBody`, `Trailers`,
      `CancelReason`, `Finished`, `Result`, `Writable`, `Ended`, `Response`, `ResponseBody`,
      `ResponseWriter`, `ReceiveResult`, `Alternative`, `Status`, `Coding`, `EncoderPool`,
      `EncoderPoolOptions`, `Encoders`, `DecoderPool`, `DecoderPoolOptions`, `Decoders`,
      `Features`, `PathParameters`, `Handled`, `Router`, `RouterOptions` and `middleware`.
  - `client` (patterns 1 to 5, 8 and 10).
    - `ConnectionPool(capacity)` replaces `ConnectionPoolOf(capacity)` and the type of the
      default capacity. It adds `Counts`. `write_body` takes `end: PieceEnd`.
    - `ReceivePool(options)` and `DecoderPool(options)` replace `DefaultReceivePool` and
      `DefaultDecoderPool`. `ZstdDecoderPool(count)` and `BrotliDecoderPool(count)` keep
      their count. `DecoderPool`, `ZstdDecoderPool` and `BrotliDecoderPool` add
      `init(pool, features)`. `Decoders.reset`, `ZstdDecoders.reset` and
      `BrotliDecoders.reset` leave the program's calls, and `storage()` stays.
    - `Headers` and `Trailers` add `Iterator`. `Event` adds `Piece`.
    - `RequestId` becomes `enum(u64) { _ }`. `Response.status` takes `Status`, with the
      default `undefined` and no default of 0 (decision 158 rulings 5 and 16).
      `Request.never_indexed.headers` holds `[]const Header`.
    - The root's list adds `Status`, `PieceEnd`, `ReceivePoolOptions` and
      `DecoderPoolOptions`, and removes `ConnectionPoolOf`, `DefaultReceivePool` and
      `DefaultDecoderPool`. The other names stay in their order.
  - `colibri`. No root name changes in this step. Step 44 changes the root (decision 156).
    `colibri.Server` keeps no copy of `ServerConfig` for a stable pointer, because the
    engine copies what it keeps.
- **The commits.** Each commit passes `zig build test`, `zig build examples`,
  `tools/doc_snippets.sh` and `tools/consumer_check.sh`. Each commit moves the examples,
  README.md, docs/usage.md and `tools/consumer/` to its names, so the checks pass at each
  commit. For a rename, the mutation is the old name put back in its root: the names test
  must fail. A mutation that only fires an assertion is recorded **NOT CAUGHT**, with the
  reason.
  1. 45a `docs`: decision 158 and this entry.
  2. 45b `refactor(core)!`: pattern 12 and the `Reader.Error` and `Writer.Error` of pattern
     5. About 690 calls in about 230 files change, and no example does.
     - Mutations: `take_int_big` reads little-endian (the wire vectors catch it);
       `read_int` put back (the names test).
  3. 45c `refactor!`: pattern 6, in http, h2, crypto, tls_provider and hpack.
     `Provider.is_complete` stays until 45m, which adds `handshake_complete` in its place.
     - Mutations: each removed name put back, nine times: the six namespace copies,
       `h2.connection.Event`, `h2.connection_tls.attach` and the old name `Request_` (the
       names test of the root or of the type); `FieldSection.clear` put back (the type's
       names test).
  4. 45d `refactor!`: the types of pattern 5 as declarations, in hpack, qpack, tls,
     server and client, and the `client.Event.Piece`, `ConnectionPool.Counts` and
     `Headers.Iterator` that a program could not name.
     - Test: `examples/client_stream.zig` names `client.Event.Piece` and
       `client.Headers.Iterator`.
     - Mutation: each new name left out of its list.
  5. 45e `refactor!`: pattern 7 outside quic. The `connection` and `connection_tls`
     namespaces of h11, h2 and h3 fold into each `Connection`. `http.uri` and
     `QueryParameters` take the names of `uri_percent` and `uri_query`. `h11.coding`'s
     functions become declarations of `Decoding`. CLAUDE.md "The public API is written first"
     gains decision 158's rule on a declaration alias.
     - Mutation: a declaration alias left out of a `Connection` (the type's names test).
  6. 45f `refactor(quic)!`: pattern 7 and pattern 11 in quic, by the table above, and
     `Connection.Options` and `Connection.IdentityOptions` of pattern 5. h3, `server`,
     `client`, the simulator, the corpus and `src/testing/` move to the new names.
     - Tests: `deadline` returns the same value on two calls with no input between;
       `attach_log` on a connection that `init` made writes the first qlog event.
     - Mutations: a stutter name put back (the names test); a `deadline` that changes the
       timer it reads (the test of two calls fails).
     - Run `zig build test-sim-run-quic`, whose census must not change.
  7. 45g `refactor!`: patterns 2 and 3, and the `init` of each pool (ruling 10).
     `server.Engine(capacity)`, `client.ConnectionPool(capacity)`, the options of each pool,
     and `server.Router`. `src/server/endpoint/` becomes `src/server/engine/`, its files
     `engine_*.zig`, and prose, comments, docs/usage.md and the examples say "engine".
     `tools/fixtures/router_refused.zig` and `build/router_check.zig` expect
     "server.Router:". CLAUDE.md's example of `server.router` becomes `server.Router` in this
     commit, which adds the name.
     - Tests: `zig build router-check` and `zig build router-hidden-check`; an h11 gzip body
       decodes through a pool after its `init`.
     - Mutations: `init` that does not set the features (an h11 gzip body decodes wrong);
       a default in an options struct that differs from the old alias (`zig build
       bench-memory` prints a different table, which `zig build test` compares).
  8. 45h `refactor!`: pattern 1. The engine and the pool copy what they keep of `Config`.
     `server.Instant` replaces the two instants.
     - Test: a program changes its `Config` after `init`, and the engine and the pool serve
       as the first `Config` said.
     - Mutations: the engine reads `config.timeouts` through the caller's pointer; the
       pool reads `protocols` through it. Each test must fail.
  9. 45i `feat(http)!`: pattern 4, `http.Status` as one enum, and the `status` fields of
     server and client.
     - Tests: `from_code(99)` and `from_code(600)` fail; a code with no name, such as 299,
       round-trips through `_`; a client response with no final head reads no status.
     - Mutations: `from_code` takes 600; `class` of 299 is not `success`.
  10. 45j `refactor!`: pattern 8. `client.PieceEnd`, h3's `RequestHead`,
      `message_request.Kind`, and `never_indexed.headers` as a header slice.
      - Tests: a never-indexed header goes out as a never-indexed literal over h2 (RFC 7541
        §6.2.3) and with its N bit over h3 (RFC 9204 §4.5.4).
      - Mutations: `.last` read as `.more`; a never-indexed header sent with indexing.
  11. 45k `refactor!`: pattern 9. One `init(connection, options)` shape for h11, h2 and h3.
      - Mutation: the role in `Options` ignored (the h11 and h2 tests of each role fail).
  12. 45l `refactor!`: pattern 10. `h11.Connection.Failure`, the dnssec error names,
      `?tls_provider.Alert`, `client.RequestId` as an enum, and `h2.frame.Type`.
      - Tests: `examples/dnssec_check.zig` expects `error.SignatureVerificationFailed`; an
        unknown h2 frame type reads as `_` and is ignored (RFC 9113 §5.5).
      - Mutations: an unknown frame type refused; the alert's byte mapped to the wrong
        member.
  13. 45m `refactor!`: pattern 13 in `tls_provider`. `Provider` calls each member through a
      method, and no file outside `tls_provider` writes `.vtable.`. `handshake_complete`
      replaces `Provider.is_complete` (decision 158 ruling 7).
      - Test: the type's names test lists the 13 methods, and not `is_complete`.
      - Mutation: a method that calls the wrong member (the h11 and h2 TLS tests fail).
- **What programs change.** Each commit above changes these where its names appear:
  - `examples/`: `server_exchange.zig`, `client_peer.zig`, `client_pool_peer.zig` and
    `client_stream_peer.zig` (`Engine(.{})`, `Instant`); `client_exchange.zig`,
    `client_pool.zig`, `client_stream.zig` and `server_peers.zig` (`ConnectionPool(.{})`);
    `colibri_server.zig` and `client_peer.zig` (`server.Router`); the files that compare a
    status; `client_stream.zig` and `client_stream_peer.zig` (`write_body`, `RequestId`);
    `dnssec_check.zig`; and `examples/README.md`.
  - docs/usage.md: "colibri.Server", "The server" with "Router" and "Query", "The client"
    with "Streamed bodies", "h11" with "The gzip and deflate transfer codings", "h2", "TLS"
    (the `Provider` calls), "DNSSEC", and "QUIC and h3".
  - README.md, `tools/consumer/main.zig` and `tools/fixtures/router_refused.zig`.
- **Step 44 after step 45.** Step 44's commits from 44b use the names of step 45.
  - `FetchResult.status` is an `http.Status`, and `FetchOptions.never_indexed` holds a
    header slice (decision 158 rulings 5 and 9).
  - `colibri.Server` places an `Engine(capacity)`, and its `init` takes a router that
    `server.Router` made.
  - The poller calls `engine.init` with one `server.Instant`.
  - `Client.InitError` and `Client.RunError` are the named sets of decision 158 ruling 6.
- **The owner's name rulings of 2026-11-07** (decision 158 ruling 15). They close the open
  question on the name of `server.Endpoint`, and came after this entry was written.
  1. `server.Endpoint` becomes `server.Engine`, a type function: `server.Engine(.{})`. 45g
     makes the change, with the directory `src/server/engine/` and its files `engine_*.zig`.
  2. The CONNECTION_CLOSE frame's one public path is `quic.ConnectionClose`, not
     `quic.Close`. 45f adds it.
  3. The connection ID options are `quic.Connection.IdentityOptions`, as planned. 45f adds
     them.
- **The checks.** `zig build test`, `zig build examples`, `tools/doc_snippets.sh`,
  `tools/consumer_check.sh`, `zig build router-check` and `zig build router-hidden-check` at
  each commit, and `tools/ci.sh` once before the branch goes to main. The branch goes to main
  once, after 45m.
- **The run, 2026-11-07.** One MacBook Pro, Apple M1 Pro, 32 GB, macOS 26.6.2, Zig 0.16.0.
  The branch `step-45` holds the commits 45a to 45m. `zig build test` runs `zig build
  router-check`, `zig build router-hidden-check` and the QUIC checks of `zig build
  test-sim-run-quic`, whose census each test pins. `tools/ci.sh` runs once, before the branch
  goes to main.
  - Each commit from 45b to 45j records its mutations in its body:
    - 45b: `take_int_big` reads little-endian, CAUGHT; `read_int` put back, CAUGHT.
    - 45c: each of the nine names put back, and `FieldSection.clear`, CAUGHT.
    - 45d: each new name made private or left out of its type, CAUGHT, 21 of 21.
    - 45e: a declaration alias left out of a `Connection`, CAUGHT in h11, h2 and h3.
    - 45f: a stutter name put back, CAUGHT; a `deadline` that moves its timer, CAUGHT.
    - 45g: `init` with the features unset, CAUGHT; a default that differs, CAUGHT by `zig
      build bench-memory`; each old name put back, CAUGHT.
    - 45h: the engine reads `timeouts` and the pool reads `protocols` through the caller's
      pointer, CAUGHT each.
    - 45i: `from_code` takes 600, CAUGHT; `class` of 299 is not `success`, CAUGHT.
    - 45j: `.last` read as `.more`, CAUGHT; a never-indexed header sent with indexing over h2
      and with no N bit over h3, CAUGHT each.
  - Before 45k, 45l and 45m, the six checks printed `rc=0` each: `zig fmt --check build.zig
    bench build examples src tools`, `zig build lint`, `zig build test`, `zig build examples`,
    `tools/doc_snippets.sh` and `tools/consumer_check.sh`. `zig build lint-commits` printed
    `rc=0` after each commit.
  - 45k: `init` that ignores `options.role` and sets `.server`, CAUGHT in h11 (1 test fails
    and 19 stop on an assertion) and in h2 (35 fail). With `.client`, CAUGHT in h11 (27 fail)
    and in h2 (96 fail).
  - 45l: an unknown frame type refused, CAUGHT (7 h2 tests). The alert's byte mapped to the
    next member, CAUGHT in `Client.alert` and in `Server.alert` (2 tests each). The two dnssec
    errors swapped, CAUGHT by `examples/dnssec_check.zig` and 5 dnssec tests. `Failure` and
    `frame.Type` left out of their lists, CAUGHT each.
  - 45m: `handshake_complete` calls `negotiated_alpn`, CAUGHT (an h11 and an h2 TLS test).
    `negotiated_alpn` calls `negotiated_parameters`, CAUGHT (12 h11 and 1 h2 TLS tests).
    `is_complete` put back, CAUGHT (the names test of `Provider`).
  - What the run found that the plan did not say:
    - The role of `h11.Connection.Options` and `h2.Connection.Options` has no default, as
      in h3's `Options`, because each role reads and writes other messages. Decision 158
      ruling 16 later gave each `role` the default `.server`.
    - `h11.Connection.Failure` holds `RequestTimeout` and `SendTimeout`, which the server's
      deadlines pass to `fail`.
    - `h2.frame` gained a names test, so that a name left out of the namespace fails a test.
    - The tests in `src/tls/quic/` still call `QuicProvider`'s vtable. Step 45 changes the
      calls of `Provider` alone.
  - The review of the branch, 2026-11-07, added four commits and left seven findings open.
    - A test guards each read of `never_indexed.headers`: the h11 send, the check of the
      reserved names, and the scans for Accept-Encoding and TE. Each mutation was CAUGHT.
    - `h2.Connection.write_request` takes `*const RequestHead`, as ruling 1 rules for an
      argument over 16 bytes. `h11.Connection.fail` takes an `?http.Status` (pattern 4).
    - The root of h3 lists the names of `frame` and of `message`.
    - The comments and the private names of `src/testing/` say "engine" for the engine. The
      simulator keeps "endpoint", because its `endpoint` check names the command and its
      worlds.
  - What the review left open:
    - `colibri.Server` keeps `config` and `engine_config`. It fills `engine_config` from the
      identity, and after the bind, and the engine's `init` runs in `run`. Step 44 moves it.
    - The tests in `src/tls/quic/` call `QuicProvider`'s vtable, as the run found.
  - The owner ruled four of the review's findings on 2026-11-07 (decision 158 ruling 16):
    1. `client.Response.status` keeps the default `undefined`, so a program writes
       `client.Response = .{}` and names no status. Ruling 5 still refuses a default of 0. This
       changes no code.
    2. Each field of an options struct has a default. 45o gives them:
       - `role` is `.server` in `h11.Connection.Options`, `h2.Connection.Options` and
         `h3.Connection.Options`.
       - `server.RouterOptions.requests` is `router_requests_default`, 32: one request for
         each of the 16 TCP and 16 QUIC connections of `server.Engine(.{})`.
       - `server.RouterOptions.response_bytes` is `router_response_bytes_default`, 256, the
         value that each example passes.
       - The two values size the router's memory, so they are in
         `src/server/constants_limits.zig`, as decision 137 ruling 1 says. The owner ruled this
         on 2026-11-08. A test pins each default, and the test of the limits pins each value.
       - `role` is `.server` in `quic.Connection.Options` too, as the owner ruled on
         2026-11-08. `local_parameters`, `now_ns`, `identity`, and the
         `local_initial_source` and `original_destination` of `quic.Connection.IdentityOptions`
         keep no default. Decision 158 ruling 16 names them as the exception.
    3. Five types in a public signature get a public name (ruling 6). 45p adds each one to its
       type and to the type's names list: `qpack.Encoder.Settings`, which
       `Encoder.on_settings` takes; `h11.Connection.AttachError`, `Received` and `Closed`; and
       `h2.Connection.Sent`, which `write_request` returns.
    4. `colibri.ServerConfig.endpoint` becomes `engine`. Step 44 rebuilds `colibri.Server`, so
       44d changes the field (step 44's entry, "The configuration").
  - The commits of the rulings:
    1. 45n `docs`: decision 158 ruling 16 and this entry.
    2. 45o `refactor!`: the defaults of ruling 2.
       - Mutations: each default changed, `role` to `.client` and each count by one. The test
         of the default must fail.
    3. 45p `feat!`: the five names of ruling 3.
       - Mutation: each name removed from its type. The type's names test must fail.
    4. 45q `refactor(server)!`: the two router values move to `constants_limits.zig`.
       - Mutations: `router_requests_default` 33, CAUGHT; `router_response_bytes_default` 257,
         CAUGHT. The router's test and the test of the limits fail.
    5. 45r `refactor(quic)!`: `role` is `.server` in `quic.Connection.Options`. The call sites
       keep their `role`, as the h11, h2 and h3 sites do.
       - Mutation: `role` `.client` by default, CAUGHT. The test of the default fails.
