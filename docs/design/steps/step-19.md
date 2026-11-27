# Design §8 step 19: QUIC version 2

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 108](../../decisions/0108-quic-version-2-beside-version-1.md) adds RFC 9369's version 2 beside version 1, with RFC
9368's compatible version negotiation, for [#54](https://github.com/c4milo/colibri/issues/54).
chapulin derives both versions' keys (its decision 79), and colibri reads and writes the wire. Five
parts, in order:
- **19a**, the suite learns the version. A chapulin pin with version 2; `Sealing` and `Opening`
  naming each packet's version; the Retry tag members taking the original version; and the
  null suite of §10 keeping keys per version. Every connection still runs version 1.
  **Check:** `zig build test`, the simulator's pinned censuses and `tools/quic_udp.sh`, all
  unchanged.
- **19b**, version 2's packets. The Version field `0x6b3343cf` and version 2's long header type
  codes (RFC 9369 §3.1 and §3.2) in the packet reader and writer, with invariant 22's
  version-independent parse unchanged.
  **Check:** RFC 9369 Appendix A's sample packets, read and written byte for byte through the
  suite.
- **19c**, version_information. The transport parameter of RFC 9368 §3, sent by both endpoints
  and parsed and validated as §4 requires, with VERSION_NEGOTIATION_ERROR (§10.2) for a Chosen
  Version the connection does not use.
  **Check:** a test for each rule of RFC 9368 §4, each proved by a mutation.
- **19d**, the client's switch, and a server that starts in version 2. The client starts in
  version 1 with version 2 available (RFC 9368 §2.5), switches once at the first long header in
  another version, and drops Handshake and 1-RTT packets in any version but the negotiated one
  (RFC 9369 §4.1). A server accepts a first flight in either version, and version 2 joins the
  versions a Version Negotiation packet lists. Tickets and tokens belong to the version that
  issued them (RFC 9369 §5). qlog's `version_information` event names both versions, which the
  lists first carry here.
  **Check:** a simulator check over both versions, and the QUIC Interop Runner's `v2` case with
  colibri as the client.
- **19e**, the server's switch. A server answers a version 1 first flight in version 2 whenever
  the client lists version 2 (decision 111), through the callback chapulin's decision 79 names,
  which chapulin `3f775fa`, the pinned commit, carries, unless its configuration's `switch_to` is
  null. A client offered a ticket starts in the ticket's version.
  **Check:** a simulator check of the client's switch against that server, and the QUIC Interop
  Runner's `v2` case in both roles, beside the version 1 matrix.

**19a, 2026-09-29.** Each packet call names its version, and every connection still runs
version 1 (decision 108).
- `crypto.suite.Version` names versions 1 and 2 by their Version fields, and `quic`'s
  `version_1` is its value. `Sealing` and `Opening` carry the packet's version, and the two
  Retry tag members take the original one.
- chapulin's calls already took a version, so `tls.quic`'s suite passes each packet's on. A Retry
  tag chapulin refuses to write is `Unsupported`, where it was `unreachable`. The pin stays at
  `10a5bc8`, which derives version 1's keys alone.
- The null suite folds a version other than 1 into every key's name and into the Retry tag's, so
  version 1's bytes are unchanged and a version 2 packet opens under version 2's keys alone.
- `quic` passes version 1 where it seals, opens, and checks or writes a Retry tag. Its test
  suites refuse any other version, so a caller that names the wrong one fails a test.

What each check printed, on macOS arm64:
- `zig build test`: 2338 of 2338 tests, with the simulator's pinned censuses unchanged.
  `tools/quic_udp.sh` and `tools/quic_loopback.sh`: ok.
- 9 mutations, each **CAUGHT**: a key's name without its version, `seal` or `open` ignoring its
  version, the Retry tag's name without its version, `tls.quic`'s suite naming version 1 always,
  a Retry tag checked or written in version 2, and packets sealed or opened in version 2.

**19b, the wire, 2026-09-29.** The packet reader and writer carry version 2's Version field and
type codes, and every connection still runs version 1.
- `header.read` reads a long header of either version and says which on `Long` and `Retry`. RFC
  9369 §3.2's type codes are version 1's plus one, modulo four, which `type_bits` and `type_of`
  compute. A version neither names is handed over as before, and invariant 22's reader is
  unchanged.
- `header_write.Long` and `header_write.Retry` take a version, so every caller names one.
- Until 19d a version 2 packet goes where a packet of an unknown version went. A connection ends
  its walk on one (RFC 9000 §5.2), a client takes no Retry in it (RFC 9369 §4.1), and the server
  answers one with Version Negotiation rather than route it to a connection (RFC 9000 §5.2.2).
- Listing version 2 in a Version Negotiation packet moved to 19d, where a server first accepts
  it; a server that lists a version it refuses would send the client a version that fails.

What each check printed, on macOS arm64:
- `zig build test`: 2342 of 2342 tests. RFC 9369 Appendix A's headers of both Initials and of
  the Retry, byte for byte, and the Retry read back into its fields.
- 9 mutations, each **CAUGHT**: version 2's type bits written or read as version 1's, byte 0
  carrying version 1's bits, the reader handing version 2 over as another version, either
  header writing version 1's Version field, and each of the three places a version 2 packet is
  refused letting it through.

**19b, the keys, 2026-09-29.** chapulin `3f775fa` derives version 2's keys, lets a client
switch once and a server choose the negotiated version, and binds tickets and Retry tokens to
their version (its decision 79). colibri pins it.
- RFC 9369 Appendix A's client Initial, server Initial and Retry seal, open and check byte for
  byte through `tls.quic`'s suite, from a session that starts in version 2. A client starts in
  the version its configuration names, version 1 unless it names another (RFC 9368 §2.5).
- The Retry token members take the original version, as the tag members do (RFC 9369 §4.1),
  and the null suite folds a version other than 1 into its token.
- `values.Ticket` records the QUIC version that issued it, 0 for TCP. RFC 9369 §5 and chapulin's
  decision 79 keep a ticket to its transport and version, so a client refuses to start with
  any other (`error.Refused`), and nothing is sent. Step 16c's ticket that resumed a connection
  of either object resumes only one of its own transport now.

What each check printed, on macOS arm64:
- `zig build test`: 2348 of 2348 tests. `tools/quic_udp.sh`, whose second connection resumed the
  first one's session over a ticket that names version 1, `tools/quic_loopback.sh`,
  `tools/quic_aioquic.sh`, `tools/tls_accept.sh`, `tools/tls_handshake.sh`, and the h2 interop
  scripts with `--tls go`: ok.
- 11 mutations, each **CAUGHT**: a client starting in version 1 whatever its configuration
  names; a ticket that records no version, or is offered without one; every ticket fitting
  every connection; a TCP client offering a QUIC ticket, and a QUIC client one of another
  version; chapulin's token minted or checked in version 1 always; the null suite's token
  ignoring the version; and `quic` writing or checking a token in version 2.

**19c, 2026-09-29.** Both endpoints send RFC 9368's version_information and check the one they
receive, and every connection still runs version 1.
- `transport_parameters` writes and reads the parameter, 0x11 (§10.1). The reader refuses what §4
  calls a parsing failure with TRANSPORT_PARAMETER_ERROR, as version 1 requires: a value shorter
  than four bytes or not a multiple of four, a version of zero, and a client's Chosen Version
  missing from its Available Versions. A repeat is refused, as for any known parameter.
- A peer's list is bounded only by the parameter's length, so the reader checks every entry and
  keeps the first `version_information_versions_max`, 16. A Chosen Version listed past them
  takes the last place kept.
- A connection states version 1 as its Chosen Version and its one Available Version, which keeps
  a server from switching a client (§2.3). A peer whose Chosen Version is not the version its
  packets carried closes the connection with VERSION_NEGOTIATION_ERROR (§10.2), and so does a
  server that chose a version the client never listed. A peer that sent none passes (§4).
- qlog's `version_information` event moved to 19d. It names version 1 alone today, and names
  both once the lists do.
- Every handshake carries ten more bytes, so the simulator's census digests moved and its
  datagram, packet and loss counts did not. Both build modes gave the new digests.

What each check printed, on macOS arm64:
- `zig build test`: 2355 of 2355 tests. `tools/quic_udp.sh`, `tools/quic_loopback.sh`,
  `tools/quic_aioquic.sh`, `tools/h3spec.sh` and `tools/channel_interop.sh`: ok.
- 24 mutations, each **CAUGHT**: the reader admitting a value too short, a length not divisible
  by four, or a Chosen or Available Version of zero; a client's Chosen Version left out of its
  list, or that rule binding the server instead; a Chosen Version listed past the kept entries
  dropped, or looked for only among them; a full list taking more; a repeat admitted; the
  parameter read past, left unwritten, or written with a short length; no endpoint holding the
  Chosen Version to the version in use, a client skipping that rule, a client accepting a
  version it never listed, and a server checking its own list instead; a missing parameter
  refused; the connection skipping the check, or closing with TRANSPORT_PARAMETER_ERROR;
  VERSION_NEGOTIATION_ERROR numbered 0x10; a connection sending no parameter, or listing
  version 2; and every list naming every version.

**19d, the switch member, 2026-09-29.** `crypto.Suite` gains `switch_version`, decision 108's
thirteenth member, and invariant 23's list moves with it. No connection calls it yet.
- `tls.quic`'s client suite calls chapulin's `switchVersion`. It refuses a session chapulin has
  not started, and a server's suite refuses every call (RFC 9369 §4.1).
- The null suite keeps the original and the negotiated version (`null_suite_version.zig`). A
  client switches once, before it holds the Handshake keys. From then on the Initial level
  admits both versions, and the Handshake and application levels the negotiated one alone,
  which is what chapulin's packet calls admit. A call in any other version counts as a call
  without keys, which the QUIC simulator treats as a violation (invariant 21). A version has no
  zero value, so the two checks whose storage starts zeroed zero it around their suites.
- chapulin `3f775fa`, which colibri pins, also carries the server's `choose_version` callback
  that 19e needs.

What each check printed, on macOS arm64:
- `zig build test`: 2376 of 2376 tests.
- 14 mutations, each **CAUGHT**: a server's switch succeeding; a session not started
  switching; the suite switching nothing, or swallowing chapulin's refusal; the null suite
  letting a server switch, a client switch twice, after the server's CRYPTO bytes, or to the
  negotiated version; its switch not remembered or blind to the Handshake keys; the Initial
  level forgetting the original version, or every level admitting it; and seal or open ignoring
  the version.

**19d, the client's switch, 2026-09-29.** A connection keeps its original and its negotiated
version (`connection_version.Versions`), and a client switches once.
- `Options.version` names the original version, version 1 unless the caller names another.
  Every packet is sealed in the negotiated version, and a long header names it (RFC 9369 §4.1).
- A client lists version 2, then version 1, in its version_information, starting in the oldest
  and advertising the newer (RFC 9368 §2.5). A server lists the versions it accepts, version 1
  alone until the next part.
- A client switches at the first long header in another version it listed, before that packet
  opens, until it switched or read a CRYPTO byte from the server. A server is settled from the
  start. A Handshake or 1-RTT packet in any version but the negotiated one is dropped, and so is
  an Initial in neither version, as `other_version`, which qlog names `unsupported`. The walk
  goes on past it, since both versions share the long header's layout.
- A client takes a Retry in its original version alone, and checks its tag in that version. A
  Version Negotiation packet that lists the original version is discarded (RFC 9000 §6.2).
- A client holds the server's Chosen Version to the Negotiated Version, and a server holds the
  client's to the version of the client's first flight (RFC 9368 §4). qlog's
  `version_information` event lists the versions the endpoint sends.
- The runner's endpoint takes the `v2` case as a client, and `tools/interop.sh` runs it.
- The census digests moved with the client's longer version_information; the counts did not,
  and both build modes gave the new values.

What each check printed, on macOS arm64:
- `zig build test`: 2382 of 2382 tests. `tools/quic_udp.sh`, `tools/quic_loopback.sh`,
  `tools/quic_aioquic.sh`, `tools/h3spec.sh` and `tools/channel_interop.sh`: ok.
- `tools/interop.sh quic-go,ngtcp2,neqo,quinn v2`: with colibri as the client, `v2` passed
  against ngtcp2 and neqo, whose servers switched it to version 2. quic-go's and quinn's servers
  do not offer the case, and colibri's server does not until 19e.
- 24 mutations, each **CAUGHT**: the negotiated version not admitted first; an Initial of the
  original version dropped after a switch, or every level admitting it; a settled client
  switching, a server not settled from the start, a client switching to a version it did not
  list, and a refused switch still opening its packet; the switch leaving the negotiated
  version or unsettled; settling, or a CRYPTO frame's call to it, doing nothing; a dropped
  version ending the walk; a long header or a 1-RTT packet opened in version 1; a packet sealed
  in version 1, or naming it; a client listing what a server lists; a client checking the
  original version, or a server the negotiated one; a Retry taken, or its tag checked, in
  version 1 alone; Version Negotiation looking for version 1; and qlog listing one version, or
  naming another trigger for a version dropped.

**19d, a server in version 2, 2026-09-29.** A server accepts a first flight in either version and
runs the version it carried (RFC 9368 §2).
- Version 2 joins `supported_versions`, so a Version Negotiation packet lists both, a datagram in
  version 2 starts a connection rather than drawing one, and a server's version_information
  lists both.
- The `server` module's endpoint and the UDP endpoint hand the first flight's version to the
  connection and to its TLS session: `tls.quic.Server.start` takes it. A Retry, its tag and its
  token are in that version, and the token is checked in the version of the Initial that
  returns it (RFC 9369 §4.1).
- The QUIC connection check runs every other seed in version 2 at both endpoints, and counts
  the seeds that did: 128 of 256 in each of its five runs. The client's switch comes to the
  simulator with 19e, whose server switches.
- The UDP client's `v2` starts in version 2, and its report names the version it ran.
  `tools/quic_udp.sh` runs it against both servers, which serve it in version 2, and checks that
  the other clients ran version 1.
- The census digests moved with the server's longer version_information and the version 2
  seeds; the counts did not, and both build modes gave the new values.

What each check printed, on macOS arm64:
- `zig build test`: 2383 of 2383 tests. `tools/quic_udp.sh`, `tools/quic_loopback.sh`,
  `tools/quic_aioquic.sh`, `tools/h3spec.sh` and `tools/channel_interop.sh`: ok.
- `tools/interop.sh ngtcp2,neqo handshake,transfer,retry,resumption,http3`, run on the client's
  switch: every case passed both ways, so a client listing version 2 is not switched where the
  case does not ask for it.
- 18 mutations, each **CAUGHT**: the server speaking version 1 alone; a Retry's token, header or
  tag, or a token's check, in version 1; both servers answering version 2 with Version
  Negotiation, or listing version 1 alone in it; the endpoint starting its connections, checking
  tokens or writing Retry packets in version 1; the connection, its session or chapulin's server
  session starting in version 1 whatever the first flight carried; and the simulator running
  version 1 alone, in its connections or in its suites.
- 3 mutations of the UDP endpoint, each **CAUGHT** by `tools/quic_udp.sh`: its server's
  connection or session starting in version 1, and the client ignoring `v2`.

**19e, 2026-09-29.** A server switches a client that lists version 2 to it, and a client resumes
in its ticket's version (decision 111).
- chapulin asks a server for the negotiated version through `choose_version` once the client's
  transport parameters have arrived and before anything is sent. `tls.quic.Server` takes a
  `tls_provider.VersionChooser` and answers with it. chapulin's hook context is now the
  provider's state, which keeps a `KEYLOG=on` object's context beside the chooser.
- `quic.connection_version.choose` reads the client's version_information. When the client lists
  the connection's `switch_to`, the negotiated version becomes it, and the server's own
  parameters are written again, at the same length, with it as the Chosen Version (RFC 9368 §3).
  A client that does not list it, sends no version_information, or sends parameters that do not
  read keeps its original version.
- `switch_to` is version 2 unless the caller names another, in `quic.connection.Options` and in
  `server.QuicConfig`, and null keeps every client in its original version. The UDP endpoint's
  `no-switch` sets it to null, and the runner's endpoint passes it in every case but `v2`.
- A client offered a ticket starts in the ticket's version unless its configuration names
  another (RFC 9369 §5), and its connection starts in the version its session chose.
- The simulator's null provider asks the chooser once it reads the ClientHello. In the QUIC
  connection check every seed runs version 2, the 128 that start in version 1 because the server
  switched them. The loopback check requires version 2 at both endpoints.
- The census digests moved with the switch; the counts did not, and both build modes gave the
  new values.

What each check printed, on macOS arm64:
- `zig build test`: 2397 of 2397 tests. `tools/quic_udp.sh`, `tools/quic_loopback.sh`,
  `tools/quic_aioquic.sh`, `tools/h3spec.sh` and `tools/channel_interop.sh`: ok.
- `tools/interop.sh quic-go,ngtcp2,neqo,quinn`, over `handshake`, `transfer`, `chacha20`,
  `retry`, `resumption`, `http3` and `v2`:
  - With colibri as the server, every case passed against colibri's, ngtcp2's and neqo's clients,
    `v2` included, and every case but `v2` against quic-go's, which does not offer it.
  - quinn's client passed every case but `v2`. Its ClientHello carries no version_information,
    so the server keeps it in version 1 (RFC 9368 §2.3), where the runner expects version 2.
    `tools/interop.sh` now reports that case without failing the run (decision 112).
  - With colibri as the client, every case passed. quic-go's and quinn's servers do not offer
    `v2`.
- 23 mutations, each **CAUGHT**: a server with no version to switch to switching; a client that
  does not list version 2, sends no version_information or sends parameters that do not read being
  switched; the switch leaving the negotiated version, the Chosen Version or the server's
  parameters as they were; `Options.switch_to` ignored; chapulin's callback or the chooser never
  set; the chooser given no client parameters, or none of the server's, or the provider keeping no
  length for them; the hook context left the keylog's; the ticket's version ignored, preferred to
  the configuration's, or taken unchecked; the client's connection starting in version 1; the
  `server` module ignoring `switch_to` or installing no chooser; and the simulator's provider
  never asking, its server given no chooser, or its suite sealing the original version.
- 6 mutations of the test endpoints, each **CAUGHT** by `tools/quic_udp.sh` or
  `tools/quic_loopback.sh`: either server mode ignoring `no-switch`, the word read as a switch,
  the UDP server or the loopback server installing no chooser, and the UDP connection starting in
  version 1.

**`tls.quic.version` leaves the API, 2026-10-04.** The owner ruled that the constant becomes
private to `src/tls/quic/quic.zig`, as `original_version_default`.
- Its one reader is `tls.quic.Client.start`. It is the version a client's session starts in
  when neither its configuration nor the ticket it offers names one: version 1.
- The public name read as the one QUIC version. Its type is chapulin's `Version`, which no
  colibri call takes: a connection's `Options.version` is a `crypto.suite.Version`. A caller
  that converted it would seal version 1 packets for a session that a version 2 ticket started
  in version 2, and the suite asserts that the two agree. `Client.original_version()` gives the
  version the session chose, in colibri's type, and `client.QuicConnection` passes it to its
  connection.
- Nothing else read it: no file in `src`, `examples`, `tools`, `bench` or `build`.
- The alternatives refused: keeping the name public, and renaming it while keeping it public.

What each check printed, on macOS arm64:
- `zig build test`: 2539 of 2539 tests.
- 1 mutation, **CAUGHT** by `zig build test-tls`: the default naming version 2. 5 tests failed,
  and 3 more ended on the suite's assertion.
