# Design §8 step 17: the version-choosing client and server

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 100](../../decisions/0100-a-version-choosing-http-client-and.md) has two library modules above h11, h2 and h3, for
[#70](https://github.com/c4milo/colibri/issues/70). Nine parts. The owner ruled on 2026-09-27 that
17c and 17d go before 17b, because cocuyo waits for the client and 17c does not depend on step 17b,
and on 2026-09-28 that 17g goes after 17b. 17h came on 2026-09-30, after 17e, and 17i on 2026-10-04,
after 17f. The order is 17a, 17c, 17d, 17b, 17g, 17e, 17h, 17f, 17i:
- **17a**, the server over TCP. It takes bytes tagged by connection, runs the handshake
  through `tls.record.Server`, and serves h11 or h2 as ALPN chose. One set of calls covers
  both: a request is an event with an id, and a response is written by that id, its status,
  fields, body and trailers.
  **Check:** the h11 and h2 endpoints of §9 run on `server`, and the h11 and h2 server interop
  scripts and h2spec pass over it, in cleartext and over TLS.
- **17b**, the server over QUIC. h3 runs through `tls.quic.Server` over datagrams tagged by
  flow, and a TCP response advertises h3 with Alt-Svc when the caller asks.
  **Check:** the UDP endpoint of §9 serves h3 through `server`, and h3spec, aioquic and the
  QUIC Interop Runner's `http3` pass against it.
- **17c**, the client over TCP. `request(authority, path, fields)` returns an id or a refusal,
  each request ends in one outcome (a status, the fields the caller named and the body in the
  caller's memory, or a failure), `cancel(id)` ends one, and connection events report the
  version, a ticket, draining and the close.
  **Check:** the h2 and h11 client interop scripts pass through `client` against Go, nghttpd
  and h2o.
- **17d**, the client over QUIC, and the choice. QUIC goes first when h3 is offered, and TCP
  opens when QUIC fails or the fallback delay passes. The addresses and an HTTPS record's
  `alpn` and `port` come in as values, and Alt-Svc is learned. Each transport has its own
  resumption ticket.
  **Check:** the simulator runs the choice over seeds that lose, delay and refuse QUIC, and
  every seed ends with one completed request per request made. TLC finds each seed's log a
  behavior of `spec/tla/client_exchanges`, and each configuration that turns off one of the
  model's rules finds a violation ([decision 105](../../decisions/0105-a-model-of-the-clients-exchanges.md)). The client fetches over h3
  from quic-go and aioquic, and falls back to h2 against a server with no UDP.
- **17e**, content codings ([decision 101](../../decisions/0101-the-client-and-server-code-content.md)). The server codes a response in
  `gzip` or `deflate` when the request accepts it and the caller marks the response, and the
  client offers both and decodes them. `zstd` decoding follows a stdx bump. colibri's package
  exports stdx's `codec`, `gzip`, `zlib`, `zstd` and `brotli`.
  **Check:** the simulator sends coded and uncoded responses through both modules over seeds,
  and every body arrives byte for byte. curl with `--compressed` and Go's client decode the
  server's coded responses, and the client decodes coded responses from Go's server and h2o.
  Each rule of decision 101 has a mutation that a test catches.
- **17f**, what a dependent reads: an example of each module, docs/usage.md, and a release.
  **Check:** `zig build examples` and `tools/doc_snippets.sh` pass.
- **17g**, the client and QUIC's idle timeout (RFC 9114 §5.1), which cocuyo asked for. A QUIC
  connection that has sat idle for its effective idle timeout (RFC 9000 §10.1) less a margin
  takes no new exchange and closes, and the channel's next exchange opens another QUIC
  connection, which the caller may resume with the first one's ticket. RFC 9114 §5.1 says a
  client SHOULD open a new connection "if approaching the idle timeout". A connection that
  holds an exchange instead sends a PING at that instant, as RFC 9000 §10.1.2 describes,
  because RFC 9114 §5.1 expects a client to keep a connection open while responses are
  outstanding. The margin is one PTO
  (RFC 9002 §6.2.1) and at least 1 s, as the owner ruled on 2026-09-28, since RFC 9000 §10.1.2
  warns that a packet sent close to the timeout can arrive after the peer's timer ran out.
  **Check:** `spec/tla/client_exchanges` gains both rules, and a configuration that turns off
  either finds a violation. The client trace run's plans leave QUIC idle past the margin and
  answer past the idle timeout, and every seed ends with each exchange finished. TLC finds each
  seed's log a behavior of the model.
- **17h**, the client decodes `zstd` and `br` ([decision 101](../../decisions/0101-the-client-and-server-code-content.md) as amended on
  2026-09-30, [#80](https://github.com/c4milo/colibri/issues/80)). The caller places a pool for
  each coding. The client offers a coding only when its pool has a free decoder, takes one from
  each pool it offers as it writes the request, and gives back the others at the response's
  head. A `br` window holds 16 MiB, RFC 7932 §9.1's largest, and a `zstd` one 8 MB (RFC 9659
  §3).
  **Check:** client tests decode fixtures that the `zstd` and `brotli` programs wrote, in pieces
  as they arrive; a stream whose window passes the limit fails its response; a pool with no
  free decoder drops its coding from the offer; the client decodes `br` from h2o and `zstd`
  from Caddy, in cleartext and over TLS; and mutations.
- **17i**, the server over QUIC owes the 100 (Continue) ([decision 116](../../decisions/0116-over-h3-the-server-owes-a.md)). A
  request over h3 that expects one gets it at the connection's next `receive` or `send`,
  unless the caller answered it first, as a request over TCP does (RFC 9110 §10.1.1). A
  request whose stream ended gets none.
  **Check:** server tests that read one event at a time: the 100 at the next `receive` and
  before the next datagram; none after a final response, the caller's own 100, a cancel or
  the stream's end; a 100 that waits for a run of its response; and mutations. aioquic's
  client reads the 100 from §9's UDP server before it sends its content.

**17a, 2026-09-27.** `src/server/` is the `server` module, exported by name. It imports `core`,
`http`, `h11`, `h2`, `tls` and `tls_provider`.
- A `Connection` serves one TCP connection. `receive(input, now_ns)` takes the bytes the
  transport read and returns at most one event: a request's head, bytes of its content, its
  trailer section, or its cancellation. `send(output, now_ns)` writes what the connection owes,
  sealed over TLS. The caller answers a request by its id with `respond`, `write_body` and
  `write_trailers`, ends one with `cancel`, and asks the connection to end with `shutdown`.
  `should_close` says when to close the transport, and `transport_closed`, which is idempotent,
  ends the connection and wipes the TLS session.
- Over TLS the connection runs the handshake through `tls.record.Server`, and ALPN chooses h2 or
  h11 (decision 88). In cleartext, `Config.cleartext` names the protocol.
- The server frames h11 content itself. A response that ends with its head carries
  `Content-Length: 0`, and one whose content follows is chunked for an HTTP/1.1 request and runs
  until the close for an HTTP/1.0 one (RFC 9112 §6.3, §7.1). Field names are lowercase, as h2
  sends them (RFC 9113 §8.2).
- It owes a 100 (Continue) to an HTTP/1.1 or later request that expects one and has content,
  and writes it at the next `receive` or `send` unless the caller answered first (RFC 9110
  §10.1.1).
- A connection is 284,360 bytes: h2's connection, the TLS session, 33,033 bytes of opened
  plaintext and 49,161 of output.
- The first interop run over TLS stalled nghttp's upload of 300,000 bytes. The opened plaintext
  held a frame and one record's plaintext, but a provider opens a record only into room for all
  that follows its header, which RFC 9846 §5.2 bounds by `record_ciphertext_len_max`. When a DATA
  frame began a record, the record held all of the frame but its last 9 bytes, and the next
  record did not fit. The buffer now holds a frame and `record_ciphertext_len_max`, and a test
  that starts DATA frames on a record catches the old size.
- 70 tests, handshakes against colibri's own client among them, and 83 mutations, each CAUGHT.
  The tests found that h2's `write_data` sent a server's DATA before any response head, which
  RFC 9113 §8.1 forbids; `write_data` now refuses it.
- §9's h11 and h2 server runs each connection on `server` (`src/testing/server/server_session.zig`),
  in place of its own record half and protocol sessions.

**17a check,** run on macOS 26.6.2 arm64 on 2026-09-27, the peers in Docker where the scripts
put them:
- `tools/h2spec.sh 18443 --tls`: h2spec 2.6.0 passed 144 of 146 cases in cleartext and 144 of
  146 over TLS. The two it fails are the cases the script names as skipped: RFC 7540 §5.3.1's
  self-dependency, which RFC 9113 §5.3.2 dropped.
- `tools/h2_server_interop.sh --tls`: curl 7.88.1, nghttp2 1.52.0 and Go 1.27.1 each sent 64
  GETs on one connection and a POST of 300,000 bytes, and each request ended with 200, in
  cleartext and over TLS. A Go client offering TLS 1.2 alone read the server's
  protocol_version alert.
- `tools/h11_server_interop.sh --tls`: curl 7.88.1 and Go 1.27.1 did the same over h11, in
  cleartext and over TLS, and curl also over TLS with no ALPN.
- `zig build test` passed. The HTTP Garden, which feeds the `--echo` mode, needs Linux and is
  left to its CI job; the echo's own tests pass over `server`.

**17c, 2026-09-28.** `src/client/` is the `client` module, exported by name. It imports `core`,
`http`, `h11`, `h2`, `tls` and `tls_provider`, as `server` does.
- A `Connection` carries exchanges over one TCP connection to one origin, whose authority
  `Config` names. For each request the caller places an `HttpExchange` in its own memory: the
  method, the path, its field lines and its content, and where the response goes, a body buffer
  and the names of the response fields it reads. `request(exchange)` returns an id, `send` writes
  the request when the protocol, the room and the server allow, and `cancel(id)` ends one. The
  plan named `request(authority, path, fields)`. The authority is the connection's instead,
  because one TCP connection carries one origin.
- Each exchange ends in one outcome, which its `finished` event reports. `response` carries the
  status, the count of interim responses, the content and each named field's value in the
  caller's memory. The others are `refused`, `reset`, `closed`, `malformed`, `invalid` and
  `too_large`. `refused` means the server processed none of the request, so it may go on another
  connection (RFC 9113 §6.8, §8.7). The connection's own events report the version, a
  resumption ticket, draining and the close.
- `receive` returns events and no error. A connection that fails ends each exchange it holds
  and reports `closed`.
- h2 opens the streams in the order `request` took the exchanges and waits at the server's stream
  limit. A stream whose response ended before its content went out is reset with CANCEL (RFC 9113
  §8.1). h11 pipelines as decision 88 rules, and reads and drops a response that did not fit or
  that the caller cancelled. A cancel while the content is going out ends the connection.
- The client adds Host in h11 and Content-Length, and refuses a request that names either, or a
  connection-specific field (RFC 9113 §8.2.2), so a request means the same in every version.
- A connection is 285,768 bytes, and an exchange 152.
- Building it found an h2 defect. `write_request` opened its stream, and each writer declared its
  HPACK block, before the output was known to hold the frames (`3f6e609`).
- 47 tests and 47 mutations, each CAUGHT. A 48th named the handshake's room check, which no call
  sequence can reach. It is now an assertion, with a comptime bound on the flights.
- §9's client runs each connection on `client` (`src/testing/client/client_session.zig`), in
  place of its own h2 and h11 sessions and its record half. Its report names each exchange's
  protocol and outcome.

**17c check,** run on macOS 26.6.2 arm64 on 2026-09-28, the peers in Docker where the scripts
put them:
- `tools/h2_interop.sh --tls`: against Go 1.27.1, nghttpd 1.52.0 and h2o 2.2.5, every exchange
  ended as planned, in cleartext and over TLS, on one connection and on 64. The plan is a GET, a
  GET of 1 MiB, a POST of 300,000 bytes that Go echoes, an interim response, trailers and a 404.
  The client that pins another root sent the alert Go read as `unknown certificate authority`.
- `tools/h11_interop.sh --tls`: against Go 1.27.1 and h2o 2.2.5, the same over h11, in
  cleartext and over TLS: Go's ALPN chose h11, and the client offered only h11 to h2o.
- `zig build test` passed.

**17c, a request's content with no copy, 2026-10-30**
([#105](https://github.com/c4milo/colibri/issues/105)). Over h11, `send` writes a request's
content from the program's memory into its `output`, and over TLS it seals the content from
there. Before, each byte went through the connection's own output first.
- Over TLS, the bytes that fill the head's record are still copied, so a small content goes out
  in the record of its head.
- h11 counts the bytes with `count_body` (decision 95), and the body ends after its last byte.
- h2 in cleartext does the same through `h2.Connection.write_data_header` (decision 138), a
  new public name the client needs: h2 writes each DATA frame's header, and the data follows it
  from the program's memory. h3 needs no change: QUIC reads the content from the program's
  memory into each packet (decision 57).
- The TCP trace run took a cleartext send's plaintext from what the client staged in its
  output. It now takes the bytes the send handed out, which hold the content too.
- The change removes a copy of each content byte in cleartext. Over TLS it also removes the
  move of the output's rest after each record that `send` sealed. A probe sent a 4 MiB PUT under
  callgrind and counted fewer instructions both ways. Its numbers are a laptop's and are not
  published (decision 32).
- For h11, three new tests and six mutations, each CAUGHT. For h2, six new tests and nine
  mutations. One was NOT CAUGHT until a test of a DATA header before the final response was
  added, and then all nine were CAUGHT.

**17c, h2's content over TLS with no copy, 2026-10-31**
([#105](https://github.com/c4milo/colibri/issues/105)). colibri pins chapulin a9167b5b, whose
`writeParts` seals several slices as one run (https://github.com/c4milo/chapulin/issues/212).
Decision 139 adds `writable_len` and `encrypt_parts` to `tls_provider.VTable`, and the client's
h2 seals each DATA frame's header and its data from the program's memory.
- Each frame over TLS takes at most one record's plaintext, its header included. A frame of
  16,384 bytes of data would pass a record by 9 bytes, and cost a record of 9 bytes.
- The DATA frame that fills the record of the request's head is still copied, as h11 copies.
- The client trace's census moved: 347 responses to 345, 52 failed to 53 and 49 cancelled to
  50. A send now fills the caller's segment, not only what the connection's output holds, so
  the bytes reach the server at other instants. In seeds 0x9d and 0xab a connection breaks
  before a response arrives. `tools/client_trace.sh` found each of the 68 traces a behavior of
  the model.
- Six new tests and ten mutations. A record fill that counts the handshake's records was NOT
  CAUGHT until a test sent a content queued before the handshake, and then all ten were
  CAUGHT. The first mutant of a seal failure that does not end the connection did not compile,
  and the one that compiled was CAUGHT.

**17c, a response too large at its head, 2026-10-31**
([#106](https://github.com/c4milo/colibri/issues/106)). A final response whose Content-Length
is larger than the room left in `body` ends `too_large` at its head, in h11, h2 and h3
(decision 124 as amended). Before, the client read and dropped all of its content, and an h11
connection stayed held until then.
- h11 ends the connection, h2 resets the stream with CANCEL, and h3 with H3_REQUEST_CANCELLED.
- The response to HEAD, a 304, and content the client decodes are not judged at the head.
- Two h11 tests of a dropped response now send it chunked, which gives no length at its head.
- Six new tests and nine mutations. Content judged at the head while it is decoded was NOT
  CAUGHT until a gzip test was added, and then all nine were CAUGHT.

**17d, the client over QUIC and the choice, 2026-09-28.**
- `QuicConnection` (`35dfbde`) carries exchanges over h3 on QUIC with the TCP connection's calls
  and events. An exchange's `finished` event waits until its stream reads nothing more of the
  exchange (RFC 9000 §3.1), so the caller may reuse its memory once the event arrives.
- `Channel` (`289bd69`) carries a caller's exchanges to one origin over a QUIC and a TCP
  connection it chooses between. It opens QUIC first when a fresh Alt-Svc alternative names h3,
  when an HTTPS record does, or, with no record, when `Config.quic_first` says to try it (RFC 9114
  §3.1, RFC 9460 §7.1.2). It opens TCP when QUIC is not allowed, when QUIC's attempt failed, or
  when the fallback delay passes during QUIC's handshake. The first handshake to complete takes
  the exchanges, and the other is abandoned. The caller passes the addresses, the port and an
  HTTPS record's `alpn` and `port`, and the origin names the transport, address and port to open
  in an `open` event. It never resolves a name.
- An exchange that a connection taking no new exchange refused unprocessed moves once to another
  connection, as though never sent (RFC 9114 §4.1.1). One that an open connection refuses reaches
  the caller as `refused`.
- A TCP response's Alt-Svc over TLS teaches the origin h3 on its host (RFC 7838 §3) for its next
  connection, and `alternative()` hands it to the caller to keep. RFC 7838 and RFC 9460 joined
  `docs/rfcs/` (`31091af`).
- A `Channel` is 987,216 bytes: a QUIC connection of 700,472 and a TCP one of 285,928. The
  caller places the QUIC connections' receive pool beside it (decision 61), sized with
  `ReceivePool`: 1,505,288 bytes for the default 1 MiB of capacity, and 377,504 for 66,560.
  Every window the client advertises follows the pool's capacity (RFC 9000 §4.1).
- Decision 105's model, `spec/tla/client_exchanges` (`10352d2`), holds in 4 scopes, 3.2 million
  states in all, and each of its 6 rules turned off finds a violation.
- The client trace run, `src/sim/client_trace_*.zig`, has a `Channel` carry each seed's exchanges
  to a QUIC server over the simulator's network and to an h2 server over TLS on an ordered link,
  both built from colibri's modules over chapulin. Its plans block, refuse, slow and lose QUIC,
  and its rough seeds reject and reset requests and break connections. Each seed must end with
  the origin closed within 10 s of its last exchange, each exchange reported once or cancelled,
  and, in a clean seed, each one ended in a response. `zig build test` runs 256 seeds and pins
  their census, and `tools/client_trace.sh` has TLC check that 64 seeds' logs are behaviors of
  the model.
- Building the run found three defects. A cancel of an exchange whose response had ended left
  its stream sending (`89c930d`). A closing QUIC connection kept its acknowledgment deadline,
  which came due at every instant (`b459adf`). A shut-down origin let a handshake it had nothing
  for run to its idle timeout (`a3af76f`). Working out why a mutant went uncaught found a fourth:
  a QUIC handshake the origin abandoned could still complete from datagrams in flight, and was
  reported `connected` (`215782c`).
- Mutations, each CAUGHT by a unit test: 110 in the client (`289bd69`), 3 in its shut-down
  (`a3af76f`), 2 in its abandoned handshake (`215782c`), and 2 in QUIC's timer (`b459adf`).
- The run itself, measured by breaking the client in 14 places: 12 CAUGHT by the run or by TLC,
  and TLC alone caught a fallback flag kept after its attempt ended. The run reaches neither of
  the other two, an abandoned handshake reported as connected and a move past `moves_max`, and
  unit tests catch both (`215782c`).
- `http-client --channel` (§9) hands its plan to one `Channel` on one Rotor loop, which holds the
  UDP socket every QUIC connection shares and one TCP socket at a time.
  `tools/channel_interop.sh` runs it three times on an Apple M1 Pro, macOS 26.6.2:
  - Against aioquic 1.3.0 and quic-go `9d085cc`, the QUIC Interop Runner's image pinned by
    digest: each fetched 1,000, 100,000 and 1,000,000 bytes with matching CRC-32s, sent a POST
    of 300,000 bytes whole, and read a 404. Every exchange ran over h3, and TCP never opened.
  - Against Go 1.27.1's server over TLS, which listens on TCP alone: QUIC opened, TCP opened once
    the 250 ms fallback delay passed, and h2 carried a GET, a GET of 1 MiB and a POST of 300,000
    bytes that Go echoed.
  - The whole script took 7.7 s. The fallback run waits about 3 s for the abandoned QUIC
    connection's closing state, which lasts three PTOs (RFC 9000 §10.2).
- Mutations of the channel mode, each CAUGHT: the script catches offering no h3, reporting every
  exchange as h2, a fallback delay of 0 and TCP input that never advances; unit tests catch
  `--channel` without `--tls`, `--fallback-ms` ignored, and the TCP socket's first operation read
  as a UDP send's.
- The owner renamed `Origin` to `Channel` and `Exchange` to `HttpExchange` on 2026-09-28, before
  the v0.4.0 tag:
  - `Origin` reads as RFC 9110 §3.6's origin server, and no other HTTP client names this object
    so. `Channel` is gRPC's name for what sends requests to one target over connections it
    chooses.
  - `HttpExchange` names the struct's two halves, the request and where its response goes: RFC
    9113 §8.1 calls the pair an "HTTP request/response exchange".

**17b, the server over QUIC, 2026-09-28.**
- The server reports a request `done` once its response's memory is the caller's again
  (decision 103, `0fb5878`). h11 and h2 copy the bytes, so a request is done after the call
  that writes its last one, and `receive` reports it before it reads more.
- `QuicConnection` (`c533709`) serves h3 over one QUIC connection with the TCP connection's calls
  and events, in the shape the owner chose on 2026-09-28. `write_body` sends the caller's bytes
  from where they are and keeps only each DATA frame's header. A request is `done` once the peer
  acknowledged every byte of its response (RFC 9000 §3.1), and `cancelled` once either side
  reset its stream. A request no record can hold is refused with H3_REQUEST_REJECTED.
- `Endpoint` (`ba34897`) holds up to a build-time number of connections behind the caller's UDP
  socket. It routes each datagram by its first packet's Destination Connection ID (RFC 9000
  §5.2), starts a connection from a client's first Initial of at least 1,200 bytes, and answers
  Version Negotiation and Retry itself. `send` writes what the endpoint owes, and `ended` hands
  back each connection that is over. A connection issues spare connection IDs once its handshake
  is confirmed, and validates a client's new path.
- A `QuicConnection` is 716,128 bytes. An `Endpoint` of the default 16 connections, each with a
  receive pool of 1 MiB, is 35,553,376.
- §9's UDP endpoint takes `h3`, which serves h3 alone through `server.Endpoint`, over an instance
  of `server` built on `tls_keylog` (§3). It answers a GET of a file in its directory with the
  file mapped in place until the request is done, `/` with a short body, and any other path with
  404. It writes no qlog, because `server` takes no log yet.
- Its first run found a defect: the server reported a client's close as a failure (`87fff2f`).
- Mutations, each CAUGHT by a unit test: 12 in `done`, 24 in the QUIC connection, 13 in the
  endpoint and 2 in the close.
- A TCP connection advertises h3 when `Config.h3_alternative` names a UDP port (decision 100),
  over TLS alone, because h3 cannot reach an "http" origin (RFC 9114 §3.1.2). h11 puts an
  Alt-Svc line on each final response (RFC 7838 §3). h2 sends one ALTSVC frame per connection
  instead, on the stream of its first final response, as RFC 7838 §3 asks of an h2 server; the
  owner ruled on 2026-09-28 to follow the RFC there. h2 gained the frame, its one extension
  (RFC 7838 §4), and the client learns h3 from it as from the field. §9's `http-server` takes
  `--h3-port`.

**17b check,** run on macOS 26.6.2 arm64 on 2026-09-28, the peers in Docker where the scripts
put them:
- `tools/h3spec.sh`: h3spec 0.1.13 passed 49 of 49 against the `h3` mode.
- `tools/interop.sh quic-go,ngtcp2,neqo,quinn http3`: the `h3` mode passed `http3` against the
  clients of colibri, quic-go, ngtcp2, neqo and quinn, and colibri's client passed it against
  the four servers.
- `tools/quic_aioquic.sh`: aioquic 1.3.0's h3 client fetched files of 1,000, 100,000 and
  3,000,000 bytes from the `h3` mode, each byte for byte. Two handshakes that offered another
  ALPN each ended with the server's CONNECTION_CLOSE carrying 0x178.
- `tools/quic_udp.sh`: colibri's h3 client fetched the same three files from the `h3` mode, and
  a missing one was answered 404. The mode refused a client that offered hq-interop alone, and
  the refused connection ended its run with a failure.
- `tools/h3load.sh`: h2load from nghttp2 1.70.0 sent 1,000 GETs over 10 connections to the `h3`
  mode, and each ended with a 2xx.
- Mutations of the `h3` mode, each CAUGHT by `tools/quic_udp.sh`: a missing path answered 200, a
  file left uncounted, a run with `once` that never ends, content one byte short, and a failed
  connection that does not end the run.
- `tools/h2_server_interop.sh --tls nghttp`: nghttp 1.52.0 read one ALTSVC frame naming h3 on
  port 8443 over TLS, and none in cleartext. `tools/h11_server_interop.sh --tls curl`: curl
  7.88.1 read the Alt-Svc line over TLS, and none in cleartext.
- Mutations of the advertisement, each CAUGHT by a unit test: 13 in h2's frame and connection,
  8 in the server and 8 in the client.
- `zig build test` passed: 2226 of 2226 tests.

**17g, the client and QUIC's idle timeout, 2026-09-28.**
- `quic.connection_idle` gives a caller the idle deadline and the effective idle timeout (RFC
  9000 §10.1), and `owe_keep_alive`, which has the next packet at the application level elicit
  an acknowledgment, with a PING when nothing else in it does (RFC 9000 §10.1.2). The packet
  waits for the congestion window as any other.
- The client's `QuicConnection` acts once at each idle deadline less the margin. Holding an
  exchange, it owes a keep-alive. Holding none, it retires: it takes no new exchange, closes with
  H3_NO_ERROR, and reports `draining` and `closed` (RFC 9114 §5.1). A channel's next exchange
  then opens another QUIC connection once the closing period ends. One that comes during the
  closing period opens TCP, as the model's CanOpenTcp has for any QUIC connection still ending.
- The margin is also at most half the effective timeout, which the owner's ruling left open.
  With a timeout under 2 s, a margin of 1 s would act again at once after each keep-alive's
  acknowledgment.
- `spec/tla/client_exchanges` gains the variables `stale` and `quiet`, the actions Age, Silence
  and TimeOut, and the rules RetireStale and KeepAlive. It holds in 4 scopes, 4.2 million states
  in all, and each rule turned off finds Completes violated.
- The client trace run: one seed in two makes its last exchange 25 to 40 s after the others,
  and one in three has its servers answer 30 to 45 s late. Over 256 seeds, 1 QUIC connection
  retired and 4 keep-alives went out: QUIC carries few seeds' exchanges, since TCP often wins
  the race. So `--client-trace-write` writes the first 64 seeds and each later one that reaches
  an idle rule.
- Mutations, each CAUGHT: 4 in quic's keep-alive and 10 in the client, one of them after a new
  test. With RetireStale off in the trace configurations, TLC finds the retiring seed no
  behavior of the model.

**17g check,** run on macOS 26.6.2 arm64 on 2026-09-28:
- `zig build tla -- spec/tla/client_exchanges/*.cfg`: the 4 scopes hold, and the 8
  configurations that turn a rule off are each violated.
- `tools/client_trace.sh`: 67 of 67 traces are behaviors of the model.
- `zig build test` passed: 2253 of 2253 tests.

**17e part 1, the server's content codings, 2026-09-28.**
- `http.content_coding` reads Accept-Encoding (RFC 9110 §12.5.3): each coding's weight in
  thousandths (§12.4.2), `*` for a coding the field does not list, and the first weight each
  gets. `x-gzip` is `gzip` (§8.4.1.3). `choose` takes the highest nonzero weight, and the
  server's order breaks a tie. A value the grammar refuses leaves the response uncoded.
- `server.Config` and `server.QuicConfig` gain `codings` and `encoders`, and `Response` gains
  `codable`, false unless the caller sets it. `EncoderPool(count, level)` holds the encoders,
  each with a ring of `encoder_ring_len` coded bytes, 64 KiB (the owner's ruling of
  2026-09-28). `DefaultEncoderPool` has 4 at level 6. A response takes a slot when its head goes
  out coded, and gives it back when its end is written (h11, h2) or acknowledged (h3), when it
  is cancelled, or when its connection ends.
- Decision 101's rules, with one reading of RFC 9110 §8.8.3.3: its example sends
  `Vary: accept-encoding` on the uncoded response too, so each marked final response that
  Accept-Encoding could choose carries it, coded or not. A response that ends with its head has
  no content to code, and an interim one goes out as it is.
- h11 and h2 copy the ring into the output as they frame content. `send` moves what the ring
  holds after the caller's last call, and ends the content once the encoder has finished. h3
  frames each run the encoder writes as DATA, which QUIC reads in place, and `receive` frees
  what the peer acknowledged and lets the encoder finish. A full ring makes `write_body` return
  `Blocked`, and a trailer section waits, with `Blocked`, until the coded bytes before it are
  out.
- Mutations: 62, each CAUGHT. On the first run 8 were NOT CAUGHT:
  - Three got a test each: an element with no coding, a second `*`, and a parameter other than
    `q`.
  - h3's limit on a response's runs got a test whose interim heads fill them.
  - A fourth decimal's check went, because the comma rule already refuses one.
  - The end written with no bytes was dead code, since gzip and zlib end with a trailer. It
    became an assertion, which uncovered the release it had masked.
  - A second give-back at a stream's close masked the one at `done`. It went, and a test keeps
    a request open past its response.

  Before the run, h3's check for room to keep a DATA frame's header became an assertion, with a
  comptime proof over the limits that it holds.
- `zig build test` passed: 2293 of 2293 tests.

**17e part 2, the client's content codings, 2026-09-29.**
- `client.Config` and `client.QuicConfig` gain `codings` and `decoders`. The client's
  `DecoderPool` is h11's pool of stdx's decoders (decision 91), and `h11.coding.reserve` now
  takes a decoder before a message's coding is known.
- The client offers its codings in each request's Accept-Encoding, each after the first a tenth
  lighter (`gzip, deflate;q=0.9`), and takes a decoder as it writes the request. It offers
  nothing when the caller's request names the field, or when every decoder is taken.
- It decodes a final response whose Content-Encoding names one coding it offered, `x-gzip`
  included, into the exchange's body, and reports the coding in `HttpExchange.coding`. Content
  coded twice, in a coding it did not offer, or in a 206 (RFC 9110 §14.1.2) goes on as it
  arrived. A response with no content, such as one to HEAD, decodes nothing.
- Decoded content past `body` ends the exchange `too_large`. Content that breaks its format, or
  ends before its checksum, ends it `malformed`. The decoder goes back when the head names no
  coding the client decodes, when the exchange ends, or when it is cancelled.
- Mutations: 31, each CAUGHT. On the first run 4 were NOT CAUGHT, and each got a test: a gzip
  trailer that arrives once the body is full, and the decoder given back at an exchange's end,
  at a drop and at a release, each of which the others had masked.
- `zig build test` passed: 2321 of 2321 tests.

**17e part 3, the package and the simulator, 2026-09-29.**
- colibri's package exports stdx's `codec`, `gzip`, `zlib`, `zstd` and `brotli`
  (`build/modules_exports.zig`), and `tools/consumer/` codes and decodes through the exported
  `gzip`.
- `zig build sim -- --content-coding-check [seeds]` runs each seed's plan between colibri's
  client and server over h11 or h2. `sim_run` imports `server` for it, as the owner ruled on
  2026-09-29. The plan draws each side's codings, and for each exchange its method, its caller's
  own Accept-Encoding, the server's mark, the status, the content and the body memory. Each seed
  runs twice in the same pieces and once whole, and each exchange must end as decision 101 says,
  with its body byte for byte.
- Over its 32 seeds: 82 exchanges, 19 decoded, 4 passed on coded, and 8 too large. The census
  CRC-32, 0x69460a6e, is the same in Debug and ReleaseSafe.
- `zig build test` passed: 2323 of 2323 tests.

**17e part 4, interop, 2026-09-29.** The test-only server and client take `--coded`. The server
codes its fixed answer in gzip or deflate, and echoes stay as they arrived, so the HTTP Garden
sees the same bytes. The client offers both codings and decodes, and names the coding it
removed in its report. Go's test server takes `-gzip`, and h2o's configuration turns on
`compress` over a 64 KiB text file.

**17e check,** run on macOS 26.6.2 arm64 on 2026-09-29, the peers in Docker where the scripts
run them:
- `zig build sim -- --content-coding-check`: seeds=32 exchanges=82 decoded=19 passed_on=4
  too_large=8 crc32=0x69460a6e.
- `tools/h2_server_interop.sh --tls` and `tools/h11_server_interop.sh --tls`: curl 7.88.1 with
  `--compressed` got gzip and decoded it to the body, and every one of Go 1.27.1's 65 requests
  came back coded in gzip, in cleartext and over TLS.
- `tools/h2_interop.sh --tls` and `tools/h11_interop.sh --tls`: the client decoded Go's gzip
  answers, `/` and the 1 MiB `/large`, and h2o 2.2.5's gzip `/text.txt`, byte for byte, on one
  connection and on 64, in cleartext and over TLS.
- Mutations: 93, each CAUGHT: 62 of the server's rules and 31 of the client's.

**17h, the client decodes `zstd` and `br`, 2026-09-30.**
- `http.content_coding.Coding` gains `zstd` and `br`, and `from_name` reads both in any case.
  The server encodes `gzip` and `deflate` alone, and each server configuration asserts that it
  names no other coding.
- `client.ZstdDecoderPool(count)` and `client.BrotliDecoderPool(count)` hold stdx's decoders.
  The caller places each pool, resets it with the CPU features its decoders run on, and gives a
  configuration its `storage()` as `zstd_decoders` or `br_decoders`. A `zstd` decoder is
  8,683,024 bytes and a `br` one 19,483,040. A configuration names each coding once at most,
  each with its pool, and gives no pool for a coding it does not name.
- Each request offers, in the configuration's order, each coding whose pool has a decoder free,
  and takes that decoder. A head that waits, for room or for the server's stream limit, offers
  again with the decoders it took. The response's head keeps the decoder of the coding it names
  and gives back the others. The slot records the codings its offer named, and the client
  decodes a response only in one of them.
- A `zstd` decoder starts again after each frame (RFC 8878 §3.1), and a frame whose window
  passes 8 MB fails its response (RFC 9659 §3). A `br` stream ends with its last meta-block (RFC
  7932 §9.2), so a byte after it fails the response. Content that ends inside a frame or a
  stream fails it too.
- The client module imports stdx's `zstd` and `brotli`, and no longer `gzip` and `zlib`, which
  only its tests import.
- Each exchange's slot grows by 88 bytes, for the handles of its `zstd` and `br` decoders and
  the codings its offer named: 1,408 per connection, which `docs/performance.md`'s table shows.
- The tests decode the fixtures in `src/client/coding_fixtures/`, which zstd 1.5.7 and brotli
  1.2.0 wrote, in pieces of 1 byte, of 7 and whole, over h11, h2 and h3.
- Before the mutations ran, four tests went in for rules that others masked. An exchange's end
  gives every decoder back, which would cover a head that kept them, so one test counts each
  pool between the head and the content. The others: a head that waits for the server's stream
  limit offers again, a `br` stream cut short ends malformed, and `coding.codings_valid` refuses
  a configuration that names a coding twice or gives a pool for a coding it does not name.
- Mutations: 37, and 36 CAUGHT. Two first failed to compile, since each removed the only use of
  a name, and ran again with the name kept. The one NOT CAUGHT removes the head's shortcut for a
  slot that holds no decoder, and is equivalent: such a slot offered no coding, so its head
  finds none to decode.
- `zig build test` passed: 2528 of 2528 tests.

**17h check,** run on macOS 26.6.2 arm64 on 2026-09-30, the peers in Docker where the scripts
run them:
- `tools/h2_interop.sh --tls` and `tools/h11_interop.sh --tls`, with the test client's `--coded`
  offering `br, zstd;q=0.9, gzip;q=0.8, deflate;q=0.7`: the client decoded h2o 2.2.5's `br` and
  Caddy 2.6.2's `zstd` of the 65,536-byte `/text.txt` byte for byte, in cleartext and over
  TLS, and Go 1.27.1's `gzip` answers as before. A run of 64 connections, which share two
  decoders of each coding, ended every exchange with a response read whole.
- h2o 2.2.5 codes nothing for a token that carries a weight: `br;q=0.9` gets an uncoded answer,
  and `br` a coded one. So the test client offers `br` first, with no weight.

**17f, what a dependent reads, 2026-10-04.** The owner asked whether the client and the server
are easy to use, and then why so much of them was public. The release is the owner's to cut.
- `examples/tls_exchange.zig` runs `server.Connection` and `client.Connection` over TLS: ALPN
  picks h2, the client places a GET and a POST, and the server answers each by its id. The
  server sleeps no longer than `deadline_ns` and calls `on_instant` each turn (decision 110).
- `examples/h3_exchange.zig` runs `server.Endpoint` and `client.Channel` over
  `examples/link_datagram.zig`, which moves datagrams between the two Rotor loops of
  `examples/link.zig`. `examples/tls_program.zig` holds what a program that links `tls` defines
  once. Both examples present the test identity ([decision 96](../../decisions/0096-examples-holds-programs-a-dependent-writes.md) as amended).
- docs/usage.md and README.md lead with the two modules. The guide's sections on the server,
  the client, the endpoint and the channel are excerpts of the two examples, and
  `tools/consumer/` builds `server`, `client` and `tls` as a dependent and runs an h2 exchange.
- [Decision 115](../../decisions/0115-a-types-public-functions-are-the.md): a type's public functions are the calls a program makes. The
  calls a type's other files make moved to free functions in files the roots do not export,
  and each root exports `constants` and an alias for each type a program names. A program now
  writes `client.ChannelValues`, `client.ChannelInput`, `client.ChannelEvent`, `client.Address`
  and `server.Sent` where it wrote `client.channel.Values` and the like. This breaks a
  dependent that named a file of either module. `write_owed` moved with the rest, since the
  TCP trace calls `send` with no room in its place (step 4's record of 2026-10-04).
- `core.public_names`, test-only as `core.fuzz` is, compares a type's public declarations with
  the names its test lists, and prints each name one list has and the other lacks. A test
  beside each listed type and beside each root uses it, but qlog's root, which cannot import
  `core` and compares its names itself.
- `quic` followed the same day, when the owner asked for it. `quic.zig` exports the 121 names
  code outside the module uses, each under the namespace of its file, so no caller changed.
  The root went from 58 names to 40, and exports no file but `constants` and `error_code`.
  `quic.Connection` keeps `init` and `addressed_by`: its six other methods became functions
  of `connection.zig`, which rewrote 144 call sites inside the module. The corpus and h3's
  test call two of them, through `quic.connection`.
- The twelve other roots followed too, when the owner asked for one convention in every module
  and for no name that repeats its file's ([decision 115](../../decisions/0115-a-types-public-functions-are-the.md) as amended a third
  time). A script lists the names code outside a module uses, and each root is that list, so
  72 whole files are no longer exported. A type named after its file is exported under its own
  name: `http.Field`, `h2.Connection` and `quic.PeerAddress` replace `http.field.Field` and its
  like, which rewrote 147 call sites. `tools/lint/root_exports.zig` refuses a root that
  exports a file or lists nothing. h11's connection keeps 13 methods of 16, h2's 20 of 22 and
  h3's 15 of 16; a build with each candidate made private showed that the server calls `fail`
  on all three.
- `server.Endpoint.init` returns `error.DeadlineInvalid` for limits a connection would refuse,
  as the owner ruled on 2026-10-04 ([decision 110](../../decisions/0110-the-servers-defences-against-denial-of.md) as amended), so its callers
  gained `try`. Before, each connection's start failed and the endpoint answered no client.
- Writing the examples found four things a program must know, and the guide or the example it
  quotes now says each. A connection's deadlines count from the instant `init` is given. A
  client takes a QUIC datagram only from the address it sends to. Over QUIC a client that
  closes as its exchange ends acknowledges nothing more, so the server reports no `done`, and
  `ended` hands the connection back. Over h3 a request with no content may end in an empty
  `body` event.
- Deliberate breaks of the examples: 13, each CAUGHT by `zig build examples`. For
  `tls_exchange`: the server never reports `done`, the server answers another status, the client
  keeps no wanted field, the client drops the last byte of content, the link drops a byte,
  the client asks for another server name, and the client never shuts the connection down,
  after which both sides sleep until the server's deadline and the example gives up. For
  `h3_exchange`: the server answers another status, the endpoint never hands back an ended
  connection, the client keeps no wanted field, the client drops the last byte, the link
  changes a byte of each datagram, and the client offers another ALPN token.
- Mutations of decision 115's tests: 10, each CAUGHT. A call made public again on each of the
  six types, a file exported again from each root, and an alias dropped from each root. Each
  test names the declaration, as in `public and not listed: write_owed`.
- Mutations of `quic`'s lists: 4, each CAUGHT. A file exported again, a namespace dropped, a
  method added to `quic.Connection`, and a name no file declares.
- Mutations of `core.public_names`: 6, each CAUGHT. The comparison ignoring the names, ignoring
  the lengths, and a private declaration made public; and for `reference`, a root exporting a
  name no file declares, visiting no name, and looking into no namespace.
- Mutations of the twelve roots: one each, a file exported whole again, 12 CAUGHT by the
  lists. Of the lists of the connections of h11, h2 and h3: one each, a function made a
  method again, 3 CAUGHT. Of `Endpoint.init`: 2, each CAUGHT, a limit of 0 taken and a body
  rate under the unit bound taken.
- Mutations of the `root-exports` rule: 7, each CAUGHT. A real root exporting a file, the rule
  passing a file exported through `files` and through a private name, letting any root export
  `error_code`, letting `constants` name another file, asking for no list, and reading every
  file.
- Mutations of the consumer check: 3, each CAUGHT. The package exports no `client` module, the
  consumer's server answers 200, and colibri's server writes another status.
- `zig build test` passed: 2628 of 2628 tests.

**17f check,** run on macOS 26.6.2 arm64 on 2026-10-04:
- `zig build examples`: the four programs each printed that every byte arrived as sent.
- `tools/doc_snippets.sh`: every Zig block of README.md, docs/usage.md and examples/README.md
  is an excerpt of code that runs.
- `tools/consumer_check.sh`: the dependent project built and ran `server` and `client`.

**17i, the 100 (Continue) over QUIC, 2026-10-04.** The server over TCP owed the 100 from 17a.
The server over QUIC wrote none, so a client that sent `expect: 100-continue` waited until the
caller answered or its own timer ran out.
- The code is in `src/server/quic/quic_continue.zig`. When the connection reports a request's
  head, it sets `continue_owed` on the request's record and on itself if `expects_continue`
  says so, the test the TCP server applies. `settle` then writes the 100 through `respond`, the
  call a program makes, as an interim response on the request's stream (RFC 9114 §4.1).
  `receive` settles first, and `send` settles when the connection's `continue_owed` is set.
- `respond` refuses a 100 for a request the caller answered with a final response or cancelled,
  and `settle` then clears the record's `continue_owed`. A 100 the caller writes itself clears
  it too.
- [Decision 116](../../decisions/0116-over-h3-the-server-owes-a.md): the server owes the 100 on the head alone, and a request whose
  stream h3 has read to its end gets none, whether the stream ended with the head or after it.
  Content that arrived with the head leaves the 100 owed, as over h2.
- A 100 that finds no free run among its response's runs stays owed until the peer acknowledges
  one, and delays no other request.
- `server.QuicConnection` gains no call and the root no name, so the lists of step 17f are
  unchanged. A `QuicConnection` is 721,384 bytes, 256 more: each of its 32 request records
  holds `continue_owed`.
- docs/usage.md says when the server writes the 100, in every version, and how a program
  answers first.
- Not done: a body's wait over h3 (step 20c,
  [#95](https://github.com/c4milo/colibri/issues/95)) still starts at its request's head, also
  when the request is owed a 100. Over TCP it starts once the 100 is written, and over h3 it
  is to start when the record's `continue_owed` clears.
- 12 tests in `quic_continue_test.zig`. `pump` reads every event the server has, so each test
  moves the datagrams while the connection reads nothing, and then calls `receive` itself.
- `tools/quic_aioquic.sh` gains a check against another implementation.
  `tools/quic_interop/expect_continue.py` has aioquic's client send a request's head with
  `expect: 100-continue` and no content to the `h3` mode of §9's UDP server, and requires the
  first response head it reads to carry 100. The check ends there: aioquic 1.3.0 validates a
  second HEADERS frame of a response as a trailer section, so it reads no final response after
  an interim one.
- Mutations: 30, each **CAUGHT** by `zig build test-server`.
  - The head: owing nothing, owing every request, setting `continue_owed` on the record alone
    or on the connection alone, and `on_request` noting nothing.
  - The write: `settle` or `send` calling no write, and `send` never settling; `send`
    settling with nothing owed, or keeping the last call's instant; a status of 103; and a 100
    for every request.
  - The caller's answer: `respond` clearing nothing, or told of no status; any interim status,
    or any status, clearing `continue_owed`; and a refused 100 left owed.
  - The stream's end: never read; read as its opposite; a known final size alone; "Data Read"
    alone; an unknown final size; and bytes still to read taken for the end.
  - Room: a 100 with no room dropped, or left off the connection's `continue_owed`; and the
    test for no room inverted.
  - `continue_owed` itself: the connection's never cleared, or cleared after the pass; `start`
    leaving it as it was; and a new record that starts with it set.
- Two of them, `settle` writing no 100 and a status of 103, are each **CAUGHT** by
  `tools/quic_aioquic.sh` too. The script cannot tell which call wrote the 100: the `h3` mode
  calls `receive` until it reports nothing, so `send` writing none passes the script, and the
  unit test catches it.

**17i check,** run on macOS 26.6.2 arm64 on 2026-10-04, with the commit replayed on step 20c's
first three parts:
- `zig build test`: 131 of 131 steps and 2604 of 2604 tests passed.
- `tools/quic_aioquic.sh`: aioquic 1.3.0's client read a response head with status 100, 0.002 s
  after it sent the request's head and with no content sent. The files of both directions
  arrived byte for byte, as before.
- `tools/quic_udp.sh`: colibri's client fetched the three files from the `h3` mode, and each
  connection's qlog files passed `tools/qlog_check.py`.
- `tools/h3spec.sh`: h3spec 0.1.13 passed 49 of 49 against the `h3` mode.
- `zig build examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh` passed.

**h2 reads the caller's fields where they are, 2026-10-12.** The h2 half of `server.Connection`
copied the fields a caller passes to `respond` and `write_trailers` into an array of
`h2.hpack.Field`, a second type with the same two slices as `http.Field`. The array holds
`field_count_max` lines, 4,096 bytes, and ReleaseSafe fills an `undefined` local with 0xAA on
every call, so each response paid for the whole fill whatever it carried. `hpack.Field` is now
`http.Field`. The module graph already gave `hpack` the `http` module, the name stays on
hpack's list, and a struct literal that built one still builds it. The h2 half checks the count
of lines against `field_count_max`, as the copy did, and gives h2 the caller's slice, which h2
does not keep past the call. The client's h2 half adds lines of its own to a request and still
builds its array. `qpack.Field`, which no other module names, is unchanged.

What each check printed:
- The copy stays in `connection_h2_fields_test.zig` as the reference. `respond` and
  `write_trailers` must return what h2 returns for the copy and send the same bytes, at every
  count of lines from none to one past `field_count_max`. Two more tests hold the order of the
  checks: an id that names no stream is refused before its lines are counted, and a section
  refused for its count leaves the reply h2 owes unwritten.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change.
- 9 mutations, each **CAUGHT**: the limit one line low, or one line high; the count left out of
  `respond`, or of `write_trailers`; a response without its last line, or a trailer section
  without its first; the count taken before the id is judged, in each call; and what h2 owes
  written before the count.

The judge, [run 38201623243](https://github.com/c4milo/colibri/actions/runs/38201623243),
measured it against `13558c2`, in instructions per request, or per connection for the two
`one` inputs. The base and the change are the first job's medians. The judge measured the
commit before its review, which differs from this one in tests and comments alone.

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 18,747 | 17,798 | 0.9494 | 0.9493 | wins in both |
| h2-tls-many | 26,585 | 25,658 | 0.9651 | 0.9648 | wins in both |
| h2-one | 222,772 | 222,005 | 0.9966 | 0.9974 | within the noise |
| h2-tls-one | 7,330,245 | 7,328,750 | 0.9998 | 1.0000 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 943 in both
jobs, where the disassembly gave about 940: the test server's `memset` runs 7 instructions for
each 32 bytes. A program that links compiler_rt's `memset` paid a store for each byte of the
same fill (docs/performance.md, "Pitfalls this tree has paid for").

**A connection's start stores the session's tag alone, 2026-10-12.** `Connection.init` wrote
`connection.session = .none`, and Zig 0.16 stores a union constant over every byte of the
union: a zero fill of 163,392 bytes, the size of `h2.Connection` and the tag, for each
connection accepted. `.{ .none = undefined }` stores the tag's byte. `.none` has no payload,
every read of the session goes through its tag, and `open_session` writes the payload it
switches to, so no read finds a byte the fill used to write. The bytes under the union now
hold what the slot's last connection left until `open_session` writes over them, where each
accept zeroed them before. Nothing copies, compares or logs a whole connection.

What each check printed:
- The disassembly of the server `bench/run.sh` builds no longer calls `memset` over 163,392
  bytes where a connection starts.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change.
- 2 mutations, each **CAUGHT**: `init` leaving the session of the connection's last use, and
  `init` opening h11 before a protocol is chosen.

The judge, [run 38201628405](https://github.com/c4milo/colibri/actions/runs/38201628405),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians. The judge measured the
commit before its review, which differs from this one in a comment alone.

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-one | 222,294 | 192,968 | 0.8681 | 0.8639 | wins in both |
| h2-tls-one | 7,323,135 | 7,288,921 | 0.9953 | 0.9951 | within the noise |
| h2-many | 16,886 | 16,857 | 0.9983 | 0.9983 | within the noise |
| h2-tls-many | 24,736 | 24,731 | 0.9998 | 1.0005 | within the noise |

No input loses. On h2-one the server's user instructions per connection fell by 35,740 in the
first job and by 35,773 in the second, where the disassembly gave 35,767. A connection over
TLS saves the same count, which is 0.47% of what it costs and under the floor. `open_session`
still fills the payload it switches to with 0xAA, 163,384 bytes for h2: that is ReleaseSafe's
fill of `undefined`, and this change leaves it.

**A request's regular lines are counted from its pseudo-headers, 2026-10-13.** The h2 half
found a request's regular field lines with `event.Fields.of`, which reads lines until one does
not start with a colon. h2 reports a request only with each pseudo-header field at most once,
before every regular line, none but the four RFC 9113 §8.3.1 defines (decision 19 refuses
`:protocol`), and `:method` always (RFC 9113 §8.3). So the count of the pseudo-headers the
request carries is the index of its first regular line, and one assertion reads that line to
check it. A trailer section holds none (RFC 9113 §8.1). `Fields.of` stays for h3.

What each check printed:
- `connection_h2_fields_test.zig` holds the count to `Fields.of`: for each set of
  pseudo-headers h2 admits, in two orders, with none to three regular lines; and for a trailer
  section of two lines and of none.
- The four traces wrote the same bytes before and after the change.
- 6 mutations, each **CAUGHT**: the count leaving out `:method`, `:authority` or `:path`, or
  taking `:scheme` for `:authority`; a trailer section skipping its first line; and the
  assertion reading the first line of an empty trailer section.

The judge, [run 38342561888](https://github.com/c4milo/colibri/actions/runs/38342561888),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 15,448 | 15,237 | 0.9864 | 0.9874 | wins in both |
| h2-tls-many | 23,401 | 23,193 | 0.9911 | 0.9911 | wins in both |
| h2-one | 181,364 | 181,303 | 0.9997 | 0.9996 | within the noise |
| h2-tls-one | 7,277,899 | 7,278,332 | 1.0001 | 0.9999 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 211 in both jobs,
where the disassembly gave about 225.

**The server skips the replies h2 owes when it owes none, 2026-10-13.** `respond` and
`write_body` write what h2 owes ahead of their own frames (decision 39 as amended), and most
calls find nothing pending: `write_replies` still walked its five queues. When `has_pending` is
false, `write_replies` writes nothing and `take_owed` changes nothing, so `write_owed_first` now
returns first.

What each check printed:
- An h2 test requires a connection with nothing pending to write no reply, after each kind of
  reply goes out: a PING's and a SETTINGS frame's acknowledgments, WINDOW_UPDATEs, a lone
  RST_STREAM, and a GOAWAY.
- The four traces wrote the same bytes before and after the change.
- 2 mutations, each **CAUGHT**: the replies skipped when something is pending, and always
  skipped. 1 mutation **NOT CAUGHT**: nothing skipped, which is the old code.

The judge, [run 38427732415](https://github.com/c4milo/colibri/actions/runs/38427732415),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 14,644 | 14,529 | 0.9921 | 0.9917 | wins in both |
| h2-tls-many | 22,606 | 22,499 | 0.9953 | 0.9950 | within the noise in job 1, wins in job 2 |
| h2-one | 179,922 | 179,862 | 0.9997 | 0.9989 | within the noise |
| h2-tls-one | 7,272,536 | 7,272,524 | 1.0000 | 1.0001 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 132 in both jobs,
where the disassembly gave about 140.

**The h2 session is made without filling its payload, 2026-10-13.** `open_session` wrote the
session as `.{ .h2 = undefined }`, and ReleaseSafe fills a payload written as `undefined` with
0xAA: 163,384 bytes on every h2 connection, the largest cost of one that remained. The owner
ruled on 2026-10-13 for `@setRuntimeSafety(false)` on that one assignment: `make_h2_session`
holds it alone, so it stores the tag and nothing else. No assertion is turned off; the function
has none. `h2.Connection.init` then writes every field a read reaches. h11's payload, 35,040
bytes, was still filled until the record below.

What each check printed:
- A new test in h2's `connection_test.zig` inits a connection of each role over storage of
  zeros and over storage of ones, and requires every field at every depth to match but eleven
  regions read only after they are written: the HPACK tables' bytes and entries, the
  decoder's two scratch buffers, the stream pool's entries (invariant 5), the field block's
  buffer and section, and `send_block`.
- A new test in `connection_internal_test.zig` runs one h2 exchange (a body, a trailer section,
  a PING, a SETTINGS frame, a stream the peer resets, and a shutdown) over a connection whose
  storage is filled four ways, and requires the same bytes and events from each.
- With each TCP endpoint's storage filled with 0x00, and again with 0xFF, before it starts,
  `zig build sim -Drelease -- --deadline-check 65536`, `--tcp-trace-check`,
  `--content-coding-check`, `--deadline-trace-check` and `--connection-check` printed what the
  tree printed with no fill, and `--tcp-trace-write` and `--deadline-trace-write` wrote the same
  bytes. The fill was a patch for those runs alone.
- The disassembly of the server `bench/run.sh` builds no longer fills 163,384 bytes where a
  session is made.
- 12 mutations, each **CAUGHT**: `init` leaving each of ten fields, its reply queues or its send
  window as the storage held them, and a scratch region left off the test's list. 1 mutation
  **NOT CAUGHT**: the payload filled as before, which is the old code.

The judge, [run 38445649577](https://github.com/c4milo/colibri/actions/runs/38445649577),
measured it against `bc79211`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-one | 179,622 | 145,555 | 0.8103 | 0.8091 | wins in both |
| h2-tls-one | 7,275,284 | 7,238,002 | 0.9949 | 0.9948 | wins in both |
| h2-many | 14,445 | 14,347 | 0.9932 | 0.9926 | wins in both |
| h2-tls-many | 22,387 | 22,304 | 0.9963 | 0.9956 | within the noise |

No input loses. On h2-one the server's user instructions per connection fell by 34,910 in the
first job and by 34,982 in the second, where the disassembly gave about 35,760.

**`open_session` leaves the h11 session's payload unfilled, 2026-10-18.** The judge of step
13g found h11-one at 1.09 to 1.55 times the instructions of each competitor. The owner said to
profile h11 and then fix it. A laptop profile of h11-one, one request on each connection, put
`memset` first among the server's functions. Most of its samples came from `open_session`.

`open_session` wrote the session as `.{ .h11 = undefined }`. So ReleaseSafe filled all 35,040
bytes of `h11.Connection` with 0xAA on every h11 connection. This fix is the one the owner
ruled for h2 on 2026-10-13. `make_h11_session` stores the tag alone, under
`@setRuntimeSafety(false)`. `h11.Connection.init` then writes every field that code reads.

What each check printed:
- A new test in h11's `connection_init_test.zig` inits a connection of each role over storage
  of zeros, and again over storage of ones. Every field at every depth must match, except five
  regions that code reads only after it writes them. These are the ring of outstanding
  requests, and the bytes and lines of the two field sections.
- A new test in `connection_internal_test.zig` fills a connection's storage four ways, and
  runs one h11 exchange over each fill. The exchange holds a body, a chunked body with a trailer
  section, two pipelined requests, and a request that asks for the close. The test requires the
  same bytes and events from each fill. The h2 test there now shares its loop.
- A patch for these runs alone filled each TCP endpoint's storage with 0x00, and again with
  0xFF, before it started. Then five simulator checks printed what the tree printed with no
  fill: `zig build sim -Drelease -- --deadline-check 4096`, `--content-coding-check`,
  `--endpoint-check`, `--tcp-trace-check` and `--deadline-trace-check`. `--tcp-trace-write` and
  `--deadline-trace-write` wrote the same bytes too.
- 4 mutations, each **CAUGHT** by h11's tests: an `init` that leaves `answered`,
  `outstanding_len`, `decoding` or `scanner` as the storage held it. The server's tests catch
  three of the four and miss `answered`. Each of their exchanges over filled storage starts
  with a head that parses, and that head writes `answered` before code reads it.

The judge, [run 39157844257](https://github.com/c4milo/colibri/actions/runs/39157844257),
measured `782340c` against `611c7d3`, in instructions per request, or per connection for the
`one` inputs. `782340c` is this commit before its review. The review changed comments, documents
and the names of a test's parameters, and no code that the judge ran. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h11-one | 111,192 | 102,449 | 0.9214 | 0.9152 | wins in both |
| h11-tls-one | 1,821,266 | 1,814,289 | 0.9962 | 0.9963 | within the noise |
| h11-many | 37,565 | 37,585 | 1.0005 | 1.0197 | within the noise |
| h11-tls-many | 52,223 | 52,109 | 0.9978 | 1.0155 | within the noise |

No input loses, and each h2 input is within the noise. On h11-one the server's user
instructions per connection fell by 7,713 in the first job and by 7,682 in the second. The h2
record's rate, 35,760 instructions for 163,384 bytes, gives about 7,670 for 35,040 bytes.

**The deadline tables write no entry when a connection starts, 2026-10-18.** The same profile
put `Connection.init` second among the callers of `memset`. It wrote all 128 entries of the
body table and of the send table on every connection: 6,144 and 5,120 bytes. A connection
seldom holds more than a few bodies or held streams. Each table now keeps `written`, the count
of entries written since `init`, and `init` writes no entry. A body or a held stream takes a
freed entry first, or else it writes the next entry whole, and every scan stops at `written`.

`written` adds 8 bytes to each TCP connection, because `Bodies` had no padding to hold it.
The table in `docs/performance.md` holds the new sizes. At the h2 record's rate, 11,264 bytes
is about 2,470 instructions a connection: 2.4% of h11-one and 1.7% of h2-one. Each table alone
is under h11-one's noise, so the owner ruled to judge the two as one change.

What each check printed:
- Two new tests for each table. The first runs a connection with more bodies, or held streams,
  than the table holds. Each one ends before the next begins, so the connection writes one
  entry. In the second, a connection follows one that wrote two entries. It starts with none
  written, and the entry past `written` moves no deadline.
- `expect_counts`, which the deadline tests call after each read and send, counts each table's
  entries up to `written`. The simulator's deadline trace reads them up to `written` too.
- The patch of the record above filled each TCP endpoint's storage with 0x00, and again with
  0xFF. Its five simulator checks and two trace writes then printed and wrote what the tree did
  with no fill. They also printed what the tree of the h11 record printed.
- 14 mutations, each **CAUGHT**:
  - in each table, a lookup, `soonest` or `fire` that reads every entry;
  - in each table, a freed entry never taken again, a `written` that never moves, and an `init`
    that keeps `written`;
  - in the body table, `start_waits` that reads every entry;
  - in the send table, a new entry not written.
- 2 mutations **NOT CAUGHT**: `observe` that reads every entry, in each table. The mutant also
  starts or stops the meters past `written`. A body or a held stream writes each of those
  entries whole before code reads it. So the mutant does what the code does.

The judge, [run 39160745977](https://github.com/c4milo/colibri/actions/runs/39160745977),
measured `0eb1a65` against `5faf212`, in instructions per connection. These are this commit and
the commit above, before their review. The review renamed `reached` to `written`, and changed
comments, a simulator scan and documents. It changed no code that the judge ran. The base and
the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-one | 146,126 | 143,935 | 0.9850 | 0.9846 | wins in both |
| h11-one | 102,822 | 95,957 | 0.9332 | 0.9674 | wins in job 1 |
| h2-tls-one | 1,946,495 | 1,943,887 | 0.9987 | 0.9990 | within the noise |
| h11-tls-one | 1,812,238 | 1,810,960 | 0.9993 | 0.9991 | within the noise |

No input loses, and each `many` input is within the noise. h11-one's noise in job 2 was 3.47%.
The server's user instructions per connection fell by 2,449 and 2,452 on h2-one. On h11-one
they fell by 2,474 and 2,494. The estimate was about 2,470.

**`respond` leaves an h11 response's lines unfilled, 2026-10-18.** Callgrind counted the
server's instructions per function under h11-many's load. The server ran on epoll in a Linux
container on the laptop, so the counts only put the costs in order. The fill of `lines` came
first. `respond` declared `lines`, an array of `field_count_max` fields, 4,096 bytes, before
it knew whether `complete` adds a line. So ReleaseSafe filled the array with 0xAA on every
response.

The owner ruled on 2026-10-18 for the method of `make_h2_session` and `make_h11_session`.
`unfilled_lines` returns `undefined` under `@setRuntimeSafety(false)`, and holds nothing else. The array is the
result of the call, so `respond` keeps every other safety check. A probe compiled in
ReleaseSafe for aarch64 shows a `memset` of 0xAA for the plain declaration and none for the
call. `complete` writes each line it returns, and `write_response` reads no other. At the h2
record's rate, 4,096 bytes is about 900 instructions a response: 2.4% of h11-many.

What each check printed:
- A new test in `connection_h11_test.zig` fills an array four ways and gives it to `complete`.
  It does so for a response that ends with its head, and for one whose content follows. It
  requires the same section each time: the caller's line, then the framing line the server adds.
- 4 mutations, each **CAUGHT**:
  - `complete` returns one line past those it wrote;
  - `complete` returns a section that starts one line late;
  - `complete` does not copy the caller's lines;
  - `complete` does not copy the lines it adds.
- 1 mutation **NOT CAUGHT**: the array filled as before, which is the old code.

The judge, [run 39163706783](https://github.com/c4milo/colibri/actions/runs/39163706783),
measured `f337a45` against `edbc234`, in instructions per request, or per connection for the
`one` inputs. These are this commit and the commit above, before their review. Their review
changed no code that the judge ran. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h11-many | 37,549 | 36,633 | 0.9756 | 0.9685 | wins in both |
| h11-tls-many | 52,161 | 51,317 | 0.9838 | 0.9785 | wins in job 2 |
| h11-one | 99,252 | 97,809 | 0.9855 | 0.9841 | within the noise |
| h11-tls-one | 1,810,493 | 1,810,090 | 0.9998 | 0.9992 | within the noise |

No input loses, and each h2 input is within the noise. h11-one sends one response on each
connection. There the server's user instructions fell by 930 in the first job and by 951 in the
second. On h11-many they fell by 930 and by 1,175 a request, with spreads of 3.9 to 5.2%.

**`write_final_head` leaves `with_close` unfilled, 2026-10-20.** h11 adds `close_field` to the
last final response on a connection when the caller's fields do not carry the close option (RFC
9112 §9.6). `write_final_head` copied the fields into `with_close`, an array of
`field_count_max` fields, 4,096 bytes. ReleaseSafe filled the array with 0xAA before the copy.
wrk sends `Connection: close` in each request of h11-one and h11-tls-one. So each connection of
those inputs paid for the fill once.

The owner ruled on 2026-10-20 for the method of the record above. h11's `unfilled_lines`
returns `undefined` under `@setRuntimeSafety(false)`, and holds nothing else. The array is the
result of the call, so `write_final_head` keeps every other safety check. A new function,
`write_head_with_close`, copies the fields and `close_field` into the array. It gives the head
writer those lines and no other.

The estimate comes from a probe compiled with `zig build-obj -O ReleaseSafe -target
aarch64-linux-gnu -mcpu=neoverse_n2 -femit-asm`. The plain declaration calls `memset` with 0xAA
and 4,096 bytes. The call to `unfilled_lines` has no `memset` and no copy of the array. In the
probe, the loop of `src/testing/memset.zig` has 8 instructions for each 32 bytes. That gives
about 1,040 for the fill. The judge measured about 7 for each 32 bytes in the h2 records, which
gives about 900.

So h11-one saves 900 to 1,040 instructions a connection. That is 0.9% to 1.1% of the 97,809 the
judge measured in the record above. h11-tls-one saves the same count, about 0.05% of what it
costs. No other input adds the close option. The record above removed a fill of the same size
on h11-one, and the judge found that change within the noise there.

What each check printed:
- A new test in h11's `connection_server_test.zig` fills an array four ways: zeros, ones, 0xAA
  and another pattern. It gives each array to `write_head_with_close` with two fields. It
  requires the same head each time: the two lines of the caller, then `Connection: close`.
- A second new test gives `write_head_with_close` `field_count_max` lines, which leave no room
  for `close_field`, and requires `TooManyFields` (RFC 9110 §5.4). With one line fewer, that
  limit does not refuse the head.
- The h11 tests, built for x86_64 in Debug, passed 129 of 129 in an amd64 container.
- 5 mutations, each **CAUGHT** by the new tests or by tests that already existed:
  - `write_head_with_close` does not copy `close_field`;
  - it gives the head writer one line past those it wrote;
  - it does not copy the lines of the caller;
  - its limit lets `field_count_max` lines through;
  - its limit refuses a head one line early.
- 1 mutation **NOT CAUGHT**: the array filled as before, which is the old code.

The judge, [run 39549115441](https://github.com/c4milo/colibri/actions/runs/39549115441),
measured `cf8604e` against `d0d4e4b` with `--h11`. The rule docs/performance.md states for the
h11 inputs decides it. The change wins on h11-one: its user instructions a connection fell by
904 and by 957, ratios 0.9634 and 0.9614, past a noise of 0.50% in each job. No input's total
instructions lose past the noise in either job. On the total, each h11 input is within the noise,
and h11-one's spreads were 9.04% and 4.20%. This commit is `cf8604e` replayed over the change
that reads the field lines once, so `write_head_with_close` also takes the pass over the fields.

**`Scanner.scan` keeps its fields in locals, 2026-10-20.** Callgrind counted the server's
instructions per source line under h11-many's load, in a Linux container on the laptop. The
counts only put the costs in order. Of the costs of `read_request`, the scan of the head came
first. `scan` read and wrote each field of the scanner through its pointer. The compiler cannot
prove that the scanner and the input do not overlap. So each byte loaded the fields again and
stored them again.

The owner ruled on 2026-10-20 for one parser with its state in locals, not for a scan of eight
bytes at a time. `scan` now copies the fields into a local at its start. A `defer` stores the
copy once on each return: a span, a null or an error. The loop reads the bytes of the slice
that `reader.peek_rest()` gives. `step` returns early for a byte of a field line, after its
CR and LF checks. Each check, limit and citation stays as it was, and each error comes at the
same byte.

The estimate comes from a probe compiled with `zig build-obj -O ReleaseSafe -target
aarch64-linux-gnu -mcpu=neoverse_n2 -femit-asm`. The probe compiles `message_scan.zig` with the
`core` and `http` modules, and calls `scan` for each role. A check of the probe used the server:
`zig build install -Drelease -Dtarget=aarch64-linux-gnu -Dcpu=neoverse_n2`, on this commit and
on its parent. The server's `read_head` holds `scan`, so its last row also holds the slice that
`read_head` returns. LLVM inlines `step` into `scan` in each build. The table gives the
instructions of the loop for a request, from each disassembly:

| Byte or call | Probe, before | Probe, after | Server, before | Server, after |
| --- | ---: | ---: | ---: | ---: |
| A byte of the method | 36 | 25 | 41 | 25 |
| The SP that ends the method | 37 | 25 | 39 | 25 |
| Another byte of the start line | 32 | 22 | 34 | 21 |
| A byte of a field line | 28 | 16 | 30 | 16 |
| A CR | 19 | 11 | 21 | 10 |
| The LF of a line that is not empty | 30 | 18 | 32 | 19 |
| The entry of a call with new bytes | 24 | 29 | 26 | 30 |
| A call with no new byte | 37 | 36 | 42 | 38 |
| The LF of the empty line, and the return of the head | 37 | 36 | 53 | 37 |

wrk sends a head of 41 bytes on h11-many and h11-tls-many: 3 bytes of the method, the SP, 10
more bytes of the start line, 21 bytes of a field line, 3 CRs and 3 LFs. In the probe its scan
costs 1,231 instructions before the change and 790 after, 441 fewer. In the server it costs
1,338 before and 781 after, 557 fewer. So the estimate is 440 to 560 fewer a request on those
two inputs. On h11-one and h11-tls-one, a `Connection: close` line adds 19 bytes, so the head
has 60 bytes and the estimate is 670 to 820 fewer a connection.

That is 1.2% to 1.5% of the 36,633 a request that the judge measured for h11-many in the record
above. It is 0.9% to 1.1% of h11-tls-many's 51,317, and 0.68% to 0.84% of h11-one's 97,809 a
connection. The records above give spreads of 3.9 to 5.2% on h11-many and of 3.47% on h11-one.
So the judge can find the change within the noise. A longer head saves more: 12 to 14
instructions for each byte of a field line, and 10 to 13 for each other byte of the start
line.

What each check printed:
- A new file, `message_scan_test.zig`, holds the old `scan` as a reference that only the tests
  compile. Its tests require `scan` to return what the reference returns, and to leave the same
  six fields. Each test reads each input in both roles, at each split into two calls:
  - each word of up to six bytes over CR, LF, SP, 'G', '/' and NUL;
  - each word of up to three of those bytes after each prefix of a request head, before each
    of three ends;
  - inputs at `start_line_len_max` and at `head_len_max`, split within two bytes of each limit;
  - each input of up to two bytes, as a fuzz property that `core.fuzz.sweep` runs.
- The first two tests also require their inputs to give a span, a null, and each error that
  those inputs can cause. The third requires a span and the two limit errors.
- `zig build test-h11` passed 132 of 132 tests. The h11 tests, built for x86_64 in Debug, passed
  132 of 132 in an amd64 container.
- `zig build test` passed. It runs the h11 split check of the simulator, whose census keeps its
  CRC-32, 0x793d2f38.
- 19 mutations, each **CAUGHT** by the new tests and by tests that already existed:
  - each of the six fields not stored, one at a time, and the copy stored only when `scan`
    returns an error;
  - the copy not loaded from `scanner`;
  - the limit of the start line checked one byte late, and at one byte less;
  - the limit of the head applied one byte late, and the reader not cut at `head_len_max`;
  - the method check skipped;
  - the early return of `step` taken for each byte but NUL, taken one line late, and taken
    only for NUL;
  - the loop started one byte early;
  - `scanned` counted after `step`;
  - the span read from `scanner`, not from the copy.

The judge, [run 39549122678](https://github.com/c4milo/colibri/actions/runs/39549122678),
measured `d695701` against `25c3d57` with `--h11`. The rule docs/performance.md states for the
h11 inputs decides it. The change wins on h11-one: its user instructions a connection fell by
787 and by 813, ratios 0.9681 and 0.9671, past a noise of 0.50% in each job. In the second job,
h11-many and h11-tls-many also win on the total, at 0.9836 and 0.9899. No input's total
instructions lose past the noise in either job.

**h11 reads the field lines of a head it writes once, 2026-10-21.** Callgrind counted the
server's instructions per source line under h11-many's load, in a Linux container on the
laptop. The counts only put the costs in order. Each response of the test server has two field
lines, and they went through 13 loops. One loop validated them and one wrote them. The other 11
compared their names with a name that a rule reads: Content-Length, Transfer-Encoding or
Connection.

The owner ruled on 2026-10-20 that h11 reads the names of a response's field lines in one pass.
Each check keeps its result, its RFC citation and the order of its errors. `Checked.add`, in
`message_write_fields.zig`, is the pass. It validates each line, and compares the line's name
with Host, Connection, Content-Length or Transfer-Encoding. The length of the name selects the
one name it compares. The record keeps these values:
- the error of the first line that is not valid;
- the first value of each of the four names, and whether a second line has the name;
- whether a Connection line carries the close option;
- the first Content-Length value as a u64, when `parseUnsigned` reads it.

These rules now read the record, and none of them scans the lines:
- each rule of `write_response_head` and `write_request_head`, through
  `write_response_head_checked` and `write_request_head_checked`;
- in the server's `write_response`, the rule for a 2xx to CONNECT, `declared`, the close option
  and `write_final_head`;
- in the client's `write_request`, `declared` and the close option.

The order of the checks does not change. A connection applies its rule for a 2xx to CONNECT,
and `declared` refuses a Content-Length it cannot count, before the head writer validates the
lines. So the pass reads the names of the lines after one that is not valid too. The lines that
`write_final_head` and the client add are valid, and they change no value of the record but the
close option. So `write_final_head` copies the record and sets its close option, and the client
uses the record as it is. A test pins each of the added lines.

No public name changes (decision 115). The server's own scan, `names_framing` in the `server`
module's `connection_h11.zig`, stays. h11 exports no name that could give the server the record.

The caller holds the record, and `add` writes into it. A first version returned the record, and
the copy of its fields cost 79 more instructions in the pass.

The estimate comes from a static count of the server's disassembly. `zig build install -Drelease
-Dtarget=aarch64-linux-gnu -Dcpu=neoverse_n2` built `http-server` before and after the change.
The count follows the path of the test server's response to a GET: status 200, reason `OK`,
and the lines `content-type` and `content-length: 8`. It starts after the check for an interim
status in `write_response`, and it ends when the head is written. It leaves out the two calls
of `validate_value`, which are the same before and after.

| Part of the path | Before | After |
| --- | ---: | ---: |
| `write_response`, inlined into `connection_coding.write_head` | 91 | 66 |
| `line_asks_close`, called for each line | 52 | 0 |
| `Checked.add` | 0 | 359 |
| `response_body` | 193 | 47 |
| `write_final_head` | 49 | 43 |
| The head writer, with the bytes it writes | 1,116 | 352 |
| All | 1,501 | 867 |

The change removes about 630 instructions a response. The code before this path differs by some
register moves, so the count can be wrong by a few instructions. That is 1.7% of the 36,633 a
request that the judge measured for h11-many in the record above, and 1.2% of h11-tls-many's
51,317. On h11-one it is 0.65% of 97,809 a connection, and more: each response there gets a
`Connection: close` line, which each old scan read too. The count does not cover that path.
The records above give spreads of 3.9 to 5.2% on h11-many, so the judge can find the change
within the noise.

What each check printed:
- Two new test files keep the old code as a reference that only the tests compile. The tests
  require the same bytes or the same error from the new code and the reference:
  - `message_write_test.zig` holds the old head writers. Its tests write each list of up to
    three lines from 25 lines. A response head takes seven statuses and three reasons, and a
    request head takes three methods and two targets. The 25 lines hold each fault, each name
    that a rule reads, and names one byte away from those names.
  - `connection_fields_test.zig` holds the old `write_response` and `write_request`. Its
    tests also require the same state of the connection. They write each list of up to two of
    the 25 lines, and of three lines from eight of them. Each list answers five requests, with
    six statuses and two reasons. The tests also write the longest section that
    `write_final_head` takes, and one line more.
- Seven new tests pin orders of errors that no test read before. Among them, a line that is not
  valid comes before each framing rule of the head writer. The rule for a 2xx to CONNECT comes
  before the lines. A Content-Length that `declared` cannot count comes first too, unless the
  request, the status or a Transfer-Encoding decides the body.
- 40 mutations: 39 **CAUGHT** and 1 **NOT CAUGHT**.
  - 16 wrong classifications, each **CAUGHT**:
    - each of the four names never recorded, or recorded by its length alone;
    - the close option set by each Connection line, or compared with case;
    - the last value kept, or a second line not counted;
    - the last error kept, or no name read after a line that is not valid;
    - a name or a value not validated;
    - a Content-Length that `parseUnsigned` refuses, read as 0.
  - 15 checks given the wrong field, each **CAUGHT**:
    - each of the six framing rules of the head writer;
    - the two Host rules, and the rule for the content of a CONNECT request;
    - two in h11's `Checked.names_framing` and two in `declared`;
    - the close option in `write_response` and in `write_final_head`.
  - 8 orders of errors swapped, each **CAUGHT**:
    - the framing rules, the reason and the rule for a 1xx or 204, each against the lines;
    - the Host rules against the framing rules, and the rule for CONNECT content against the
      lines;
    - `declared` before the rule for a 2xx to CONNECT, and `declared` after the head;
    - Content-Length before Transfer-Encoding in `declared`.
  - **NOT CAUGHT**: the record of `with_close` without the close option. The head writer reads
    no close option from the record, so the mutant does what the code does.
- x86_64 Debug: `zig build test-h11 -Dtarget=x86_64-linux-gnu` built the tests, and an
  `ubuntu:24.04` container for `linux/amd64` ran them. All 150 passed.

The judge, [run 39549129900](https://github.com/c4milo/colibri/actions/runs/39549129900),
measured `4da3535` against `574bf60`, the fix above, with `--h11`. The rule docs/performance.md
states for the h11 inputs decides it. The change wins on h11-one: its user instructions a
connection fell by 747 and by 750, ratios 0.9697 and 0.9696, past a noise of 0.50% in each job.
On the total, h11-many wins in the first job at 0.9591, and h11-tls-many in the second at 0.9725.
No input's total instructions lose past the noise in either job.
