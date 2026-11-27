# Design §8 step 5: the TLS provider vtable and h2 over TLS

[Design §8, the build plan](../../design.md#8-build-plan)

The record-mode vtable, ALPN, the handshake-complete signal, `close_notify` as end of data. Still no
implementation in the packaged library. **Check:** `h2spec -t -k` against the TLS entry point;
interop against nghttp2, curl, Go's `net/http2` and h2o, **both directions**, with the exact
versions recorded.

**This step waits on chapulin, and so does every later check that needs TLS.** The check needs a
TLS 1.3 *server*, certificate signing included, and colibri's library supplies none:
[decision 8](../../decisions/0008-the-tls-provider-is-a-caller.md) keeps production implementations out of the
tree. [Decision 10](../../decisions/0010-chapulin-provides-all-of-colibris-crypto.md) answers the "Ask before" this paragraph
used to raise: chapulin fills both vtables, and `src/testing/` links it while the packaged library
never does. Steps 9, 10, 12 and 13 need the same server for the interop endpoint, h3spec and
`secnetperf`, and step 7 needs chapulin's `crypto.Suite` for RFC 9001 Appendix A's vectors.
chapulin has neither a server role nor ALPN today, so this step waits for the h2 items of
[the request](../../chapulin.md). *Medium, once chapulin delivers them.*

**colibri's side, 2026-09-18.** The half of this step that needs no crypto is built, and the
step is not passed: its check is `h2spec -t -k` and interop in both directions, and both need a
TLS 1.3 server that signs a certificate.

`src/tls/` declares the record-mode vtable of [decision 8](../../decisions/0008-the-tls-provider-is-a-caller.md)
with [decision 43](../../decisions/0043-the-record-mode-vtable-carries-negotiatedparameters.md)'s eleventh member, `negotiated_parameters`, which reports the
version and suite RFC 9113 §9.2 places rules on. `h2.Connection` gains an optional provider
([decision 44](../../decisions/0044-the-provider-is-an-optional-field.md)): with none it is the cleartext prior-knowledge endpoint step 4
built, unchanged. `attach_tls` refuses a handshake that has not completed, that selected anything
but "h2" (§3.1, §3.3), or whose version and suite colibri does not admit — TLS 1.3 and three
suites, by [decision 45](../../decisions/0045-colibri-admits-tls-13-alone-and.md). `decrypt` applies §9.2.3: a post-handshake
CertificateRequest is a connection error of PROTOCOL_ERROR, a NewSessionTicket and a KeyUpdate
reach h2 as nothing, a peer `close_notify` is the end of data (RFC 9846 §6.1) and every other
alert ends the transport. Both buffers stay the caller's, so a connection carries no record
storage.

`src/sim/null_provider.zig` fills the vtable with no cryptography, framing records at the sizes
RFC 9846 §5.1 and §5.2 give them. `src/sim/tls_check.zig` drives one connection over it three
ways per seed: one record holding the whole stream, records cut where the seed says, and those
records delivered in the pieces a socket read leaves behind. The events must be identical, which
is what says a frame spanning records and a record holding several frames change nothing.
`zig build sim -- --tls-check` prints `tls: seeds=256 events=512 crc32=0x795236bd`, the same in
Debug and `-Drelease`. It has no `--tls-seed` form, because it writes no trace: what it compares
is three runs of one seed, and the check names the seed that differed.

`zig build test` passes 619 tests, the lint is clean and `zig build sim -- --connection-check`
still prints `crc32=0xe8f7c0b4`, which says the cleartext path did not move.

Mutations. Over the checks of `connection_tls.zig`: eight applied, all **CAUGHT**, the last one
added after a mutation showed the fake provider hiding whether colibri or the provider kept a
non-application record out of h2. Over the simulator check: four applied, one **CAUGHT**, one
caught by the cleartext check instead, and two equivalent, because the null provider frames its
own records and a symmetric change to its tag length is invisible.

**The client direction, cleartext, 2026-09-19.** `src/testing/h2/h2_client_session.zig` is one
client connection with no socket in it: it opens a stream for every exchange of a plan before it
reads a response, sends request content as the windows allow, records what each frame meant, and
queues a GOAWAY once every exchange has settled. `h2_client.zig` is the socket around it, and
[decision 46](../../decisions/0046-every-endpoint-in-srctesting-does-its.md) shapes it: every socket is O_NONBLOCK from before it connects, one
thread holds up to 64 connections in one `poll` set, and no other call waits. It speaks cleartext
h2 with prior knowledge (RFC 9113 §3.3), because chapulin's TLS client reads its socket through
a callback that cannot say "nothing yet" (decision 46). `zig build h2-client` runs it and
`tools/h2_interop.sh` judges it.

The script ran on macOS 25.6 arm64 against three peers, on one connection and then on 64 at
once, and every exchange ended as planned:

| Peer | Version | What the plan covers |
|---|---|---|
| Go `net/http` | go1.27.1 | a 1 MiB response, a 300,000-byte echo read while it is sent, a 103 before a 200, a trailer section, a 404 |
| nghttpd | nghttp2 1.52.0, Debian bookworm | a 1 MiB response, a POST of 300,000 bytes, a 404 |
| h2o | 2.2.5, Debian bookworm | a 1 MiB response, a POST of 300,000 bytes answered 405, a 404 |

Both sizes are several times the 65,535-byte window a stream starts with (RFC 9113 §6.9.2), so
each finishes only if WINDOW_UPDATE frames flow the right way, and each is checked by CRC-32
against a pattern whose period no frame size divides. The 103 is the case the client send path
of step 4 fixed, now met on the wire.

Writing the client found a defect in the library. A client read DATA that arrived before any
response, or after an interim response alone, as the content of a message that had not begun.
RFC 9113 §8.1 starts a message with its HEADERS frame, so `connection_data.zig` now refuses such
a frame with a stream error of PROTOCOL_ERROR (§8.1.1), after both windows have counted it
(§6.9). h2spec still prints 144 passed and the simulator's checksums did not move.

Mutations. Over the library check: three applied, all **CAUGHT**. Over the client session:
seventeen applied. Thirteen were **CAUGHT** at once and four were **NOT CAUGHT**. Three of the
four got a test each: the GOAWAY was checked as a flag and not as a frame, a connection that
failed after every exchange ended still counted as a success, and so did a response that
arrived before the content was sent whole. The fourth, a success with no final status, was
what the library defect above allowed; with the defect fixed no frame sequence produces it, and
the check became an assertion. A second run of all sixteen that remain: all **CAUGHT**.

**Both directions of the handshake, live, 2026-09-20.** chapulin's TLS 1.3 client and its
server each fill `tls.Provider`, from `src/testing/` alone ([decision 10](../../decisions/0010-chapulin-provides-all-of-colibris-crypto.md)); the
packaged library still links no TLS stack and holds no key.

The adapter has two phases, which is what lets a socket-owning TLS stack fill a vtable that owns
no I/O. During the handshake chapulin's `send` and `recv` callbacks drive the socket; afterwards
they serve the buffers colibri passes to `encrypt_record` and `decrypt_record`, and no
descriptor is touched again. `chapulin_record.zig` is that second phase, written once for both
roles because `ch_read`, `ch_write` and `ch_close` name no side: each role holds a `Held` whose
address is the provider's context, and `chapulin_client.zig` and `chapulin_server.zig` are the
two handshakes above it.

Two runs on macOS 25.6 arm64 against Go 1.27.1, with chapulin built `RAND=drbg TRUST=webpki` and
`RAND=drbg ROLE=server`:

- `tools/tls_handshake.sh ../chapulin` printed `tls-handshake: complete alpn=h2 version=0x0304
  suite=0x1303 buf_len=20480`.
- `tools/tls_accept.sh ../chapulin` printed `tls-accept: complete alpn=h2 version=0x0304
  suite=0x1303` and `tls-accept: records ok, peer closed cleanly`. Go's client reported the same
  three values, that the server echoed the record it sent, and that its `close_notify` was
  accepted.

The server check moves a record each way rather than stopping at the handshake, so it is the
first run of the record phase over a real session. The server also reports the suite rather than
deriving it: chapulin declares `session.suite` under `CH_ROLE_SERVER` alone, so the client still
reports the one suite its build offers.

Writing the server found a defect in the client. `decrypt_record` classified a peer's clean close
as an alert and `take_alert` then answered none, which `connection_tls.on_alert` documents as a
provider breaking its contract and turns into `error.TlsFailed`. Every orderly `close_notify`
would have read as a failure, which an h2 server meets on every connection it serves. The record
phase now records the report and `take_alert` hands it over once. Mutations: two applied, both
**CAUGHT** — dropping the recorded report, and reporting the record as application data.

`zig build test` passes 972 of 972 with both roles linked, and 954 with 18 skipped when no
checkout is given.

**`user_canceled`, and the bound that makes it safe, 2026-09-20.** RFC 9846 §6.1 tightened what
RFC 8446 left unclear: the alert "MUST be followed by a `close_notify`" and a receiver "SHOULD
continue to read data" after it. colibri answered `error.TlsFailed`, so it closed a connection
the RFC says to keep reading. `tls.alert.verdict` now answers three ways — `keep_reading`,
`end_of_data`, `fatal` — because the alert is neither an ending nor an error.

Continuing to read is, on its own, an invitation: a peer that sends nothing but `user_canceled`
gets a reader that never returns. The chapulin session raised it, having hit the same thing and
bounded it with a cap of 32 on records carrying no application data. colibri had no such bound
and three dataless outcomes already — a NewSessionTicket, a KeyUpdate and a partial record — so
the exposure predated this alert. `connection_tls.zig` now counts records in a row that carry
none, resets the count on any record that carries some, and fails past
`records_without_data_max`, which the owner set at 32 on 2026-09-20 to match
`continuation_count_max`. One past it is ENHANCE_YOUR_CALM (RFC 9113 §10.5).

Mutations: five applied, all **CAUGHT** — `user_canceled` fatal again, `user_canceled` as the
end of data, the bound removed, the reset removed, and the bound off by one.
`zig build test` passes 976 of 976, `h2spec` still prints 144 passed, and both simulator
checksums are where they were.

**Still owed for the step.** `h2spec -t -k`; the same interop over TLS; and the server
direction against curl, nghttp and Go's client, which cleartext could run today and nobody has
yet. The provider itself is no longer owed: both roles are filled and both are proved live
above. What stands between here and `h2spec -t -k` is [decision 46](../../decisions/0046-every-endpoint-in-srctesting-does-its.md) — chapulin's
handshake blocks, and the h2 server's rule is that `poll` is the only call that waits.

**Ruled by the owner on 2026-09-20: wait for chapulin.** A serial TLS endpoint and a thread for
each handshake were both offered and both lost; decision 46 stands unamended. What colibri waits
on is named: a server handshake whose `send` and `recv` callbacks can report "nothing yet"
instead of failing, so `h2_server.zig` can drive it from inside its one `poll` call.
<https://github.com/c4milo/colibri/issues/20> tracks it, and chapulin has the request. RFC 9113 Appendix A's prohibited suites are
not checked and will not be: decision 45 records why.

**`h2spec -t -k` passes, 2026-09-24.** chapulin now has a record-mode server driver.
- `fcc6292`: the server object is built `TRANSPORT=record`, and `h2-server --tls` runs each
  handshake inside its one `poll` call ([decision 82](../../decisions/0082-the-test-only-tls-server-drives.md)).
- colibri's checks found two chapulin defects: a ChangeCipherSpec sent through the blocking
  `send`, and records taken past the client's Finished. chapulin fixed both (`8e556ca`,
  `24301d1`), and colibri did not work around either.
- 25 mutations, all CAUGHT.

What each check printed on macOS arm64, with chapulin `24301d1`:
- `tools/h2spec.sh 18443 <checkout>` ran h2spec 2.6.0 over TLS and printed `146 tests, 144
  passed, 0 skipped, 2 failed`, the same as cleartext. The two failures are the RFC 7540 §5.3.1
  cases decision 41 skips.
- `tools/tls_accept.sh`, the record-mode server against Go's `crypto/tls`, printed `complete
  alpn=h2 version=0x0304 suite=0x1303`, the same exporter value on both ends, and `records ok,
  peer closed cleanly`.

A third chapulin defect is being fixed. On the peer's `close_notify`, chapulin closes its own
write side, which RFC 9846 §6.1 no longer asks for, and in record mode its own `close_notify` is
lost.

**The h2 endpoints on Rotor, 2026-09-24.** `2315384` moves `h2-server`, cleartext and TLS, and
`h2-client` from their `poll` loops to Rotor ([decision 83](../../decisions/0083-the-h2-endpoints-run-on-rotor.md),
[#61](https://github.com/c4milo/colibri/issues/61)). 11 mutations, all CAUGHT.
- On macOS arm64 (kqueue), h2spec printed 144 passed in both modes, and `tools/h2_interop.sh`
  printed `every exchange ended as planned against: go nghttpd h2o`.
- Throughput did not move measurably. In an OrbStack Linux VM on the same Mac, with io_uring
  allowed, both servers ran at once and h2load alternated between them, ten runs each. The
  medians were `poll` 427,476 and Rotor 403,606 req/s at one h2load thread, and 881,525 and
  861,608 at four. Every pair of ranges overlaps.
- CI's hosted runners agree. The `poll` server's medians were 293,178, 294,412, 301,501 and
  561,046 req/s over four runs, and Rotor's first was 503,620: runner variance is larger than
  any difference. `tools/ci.sh` now prints which Rotor backend ran.
- Nothing here is a published number: the VM shares its cores with h2load, and entry 33's
  rules are not met.

**A peer's KeyUpdate is answered, 2026-09-24** ([#62](https://github.com/c4milo/colibri/issues/62)).
RFC 9846 §4.7.3 has a KeyUpdate that asks for one get a reply, protected under the keys it
replaces. chapulin sends that reply from inside `ch_read`. Before this fix, the adapter gave it
nowhere to go, so the session failed, and h2 never called the provider's `handshake_write`,
which its contract says it calls for the life of the connection.
- The adapter keeps what chapulin sends during a read, and reports that record as `.key_update`.
- `connection_tls.encrypt` writes what the provider owes before any record it seals. It asks
  only after a KeyUpdate, so the common record still crosses the vtable once, and the cost check
  did not move.
- The endpoint seals on every step, and opens no record while a reply is owed.
- A zero-key test sends a KeyUpdate through chapulin and reads the reply, under the old keys,
  ahead of anything else. The same work found that the client's `TRANSPORT=tls` object cannot
  survive a record carrying no data: the read runs dry and chapulin fails the session. The
  adapter now reports that as the failure it is.
- 11 mutations, all CAUGHT.

**The client drives chapulin's record-mode handshake, 2026-09-24.** The client object is now
built `TRANSPORT=record`, like the server's ([decision 82](../../decisions/0082-the-test-only-tls-server-drives.md)). That fixes the
failure above: a record that carries no data now leaves the session live.
- `chapulin_client.zig` stages the ClientHello with `ch_record_init`, passes what the caller
  read to `ch_record_in`, and collects what it owes from `ch_record_out`. No call touches a
  descriptor.
- A `TRANSPORT=tls` object does not link. Every TLS endpoint calls chapulin's
  `ch_build_matches` at start, so an object built with other defines than colibri reads the
  headers under is refused before it runs.
- `tools/tls_handshake.sh` now opens the records Go's server sends after the handshake. It
  requires one that carries no data, the NewSessionTicket, before the SETTINGS.
- 14 mutations, all CAUGHT.

What each check printed on macOS arm64, with chapulin `6a4c5eb`:
- `tools/tls_handshake.sh`: `complete alpn=h2 version=0x0304 suite=0x1303`, the same exporter
  on both ends, and `records ok, 1 carried no data, then 45 octets of data`.
- `tools/tls_accept.sh`: `records ok, peer closed cleanly`.
- `tools/h2spec.sh 18443 <checkout>`: `146 tests, 144 passed, 0 skipped, 2 failed`, in both
  modes.

**The client direction over TLS, 2026-09-24.** `h2-client --tls <anchor-prefix> --seconds
<unix-seconds>` runs each connection's handshake through chapulin's record-mode client, inside
the same Rotor loop, and then speaks h2 over the records.
- `h2_tls_records.zig` holds the record half, which the server's `h2_tls.zig` and the client's
  `h2_client_tls.zig` now share. Each keeps only its own handshake.
- `tools/h2_interop.sh --tls <checkout>` runs every peer's plan in cleartext, then over TLS 1.3.
  Each peer serves the identity `tls_identity.go` mints, whose root the client pins.
- 13 mutations, all CAUGHT. Two survived at first and now have tests: a TLS run whose requests
  named `:scheme` "http", which Go's server ignores, and a `close_notify` sealed while plaintext
  still waited. chapulin's adapter fills its output, so the second shows only with a test
  provider that seals one small record a call, as the vtable permits.

What `tools/h2_interop.sh --tls <checkout>` printed on macOS arm64, with chapulin `6a4c5eb`:
- Go 1.27.1 and h2o 2.2.5: `connections=1 succeeded=1` and `connections=64 succeeded=64` in both
  modes, and `every exchange ended as planned, in cleartext and TLS, against: go h2o`.
- nghttpd 1.52.0 passed in cleartext and failed over TLS: it answered the ClientHello with a
  fatal handshake_failure. nghttpd accepts secp256r1 key exchange alone, and chapulin's webpki
  client offers X25519MLKEM768 and x25519. RFC 9846 §9.1 says a client "MUST support key
  exchange with secp256r1". chapulin has the report, and colibri adds no workaround.

**The server direction, 2026-09-24.** `tools/h2_server_interop.sh [--tls <checkout>]` runs
curl, nghttp and Go's client against `h2-server`, in cleartext and then over TLS 1.3. Each sends
64 GETs and a 300,000-byte POST. The run requires 200 and the server's body for each.
- curl 7.88.1 cannot reuse a prior-knowledge connection. Its second request on one fails with
  "Error in the HTTP2 framing layer", against Go's server as against colibri's. So in cleartext
  each curl GET gets its own connection, 64 at once. Over TLS they share one.
- 9 mutations, all CAUGHT: every client catches a status of 201 and a body one byte shorter,
  and a body with one byte changed. nghttp at first checked only the size, so the script now
  counts its bodies too.

What `tools/h2_server_interop.sh --tls <checkout>` printed on macOS arm64, with chapulin
`6a4c5eb`, Docker Desktop reaching the server through `host.docker.internal`:
- curl 7.88.1 (OpenSSL 3.0.22, nghttp2 1.52.0): `64 GETs and a 300000-octet POST ended with
  200`, in cleartext and over TLS.
- nghttp 1.52.0: the same, in both modes.
- Go 1.27.1: `requests=65 failed=0`, in both modes.

**nghttpd over TLS, 2026-09-25** ([#7](https://github.com/c4milo/colibri/issues/7)).
- chapulin `ca80351` renames its transports for what TLS runs over and who does the I/O:
  `TRANSPORT=tls` is now `tcp-blocking`, `record` is `tcp-nonblocking`, and `quic` is
  `quic-nonblocking`. The defines and the build records follow, so colibri reads
  `ch_build_info_tcp_nonblocking` and `ch_build_info_quic_nonblocking`. `build/modules.zig`, the
  endpoints, the interop image and CLAUDE.md's make lines take the new names. 2 mutations, 2
  CAUGHT: the client's and the QUIC object's headers read under the old define no longer
  compile.
- chapulin `b32ad68` adds secp256r1 key exchange to its webpki client and its server, which RFC
  9846 §9.1 makes a MUST. The client lists the group last, and sends a P-256 share only when a
  HelloRetryRequest asks for one. nghttpd accepts no other group.

What each check printed on macOS arm64, with chapulin `b32ad68` built as CLAUDE.md gives it:
- `tools/h2_interop.sh --tls <checkout>`: `every exchange ended as planned, in cleartext and TLS,
  against: go nghttpd h2o`, with Go 1.27.1, nghttpd 1.52.0 and h2o 2.2.5. Each ran one
  connection and then 64 at once.
- `tools/h2_server_interop.sh --tls <checkout>`: `every request ended with 200, in cleartext
  and TLS, from: curl nghttp go`, with curl 7.88.1 (OpenSSL 3.0.22), nghttp 1.52.0 and Go
  1.27.1.
- `tools/h2spec.sh 18443 <checkout>`: 144 passed in cleartext and over TLS, and 2 skipped by
  name, the RFC 7540 §5.3.1 cases that RFC 9113 §5.3.2 dropped.
- `tools/tls_handshake.sh` and `tools/tls_accept.sh`: `tls_handshake: ok` and `tls_accept: ok`.
- `zig build test` with all three objects linked: 1760 of 1760 tests passed.
- The QUIC object under its new name: `tools/quic_loopback.sh`, `tools/quic_udp.sh` and
  `tools/quic_aioquic.sh` passed, `tools/h3spec.sh` printed `49 examples, 0 failures`, and
  `tools/interop.sh <checkout> quic-go,ngtcp2 handshake,transfer,retry,resumption,keyupdate,http3`
  passed every case in both roles against both peers.

Every check step 5 names has passed, and the step owes nothing more.

**The KeyUpdate cap, 2026-09-26** ([#19](https://github.com/c4milo/colibri/issues/19)). RFC 9846
§4.7.3 forbids a sender more than 2^48-1 key updates, which `tls_provider.constants` names
`key_updates_max`. A provider that lets its caller start a key update now has an answer for the
cap: `KeyUpdateError.EpochExhausted`. It means nothing was written and the keys did not change,
so the connection goes on; `TlsFailed` would end the connection and `Unsupported` would be false.
colibri itself never starts a key update, and at the cap a provider ignores a peer's
`update_requested` and owes no reply, which `handshake_write` already reports by writing nothing.
chapulin does that at `handshake_post.c` and has no call that starts one, so its adapter answers
`Unsupported` as before. The null provider now counts its key updates and refuses at the cap.
Mutations of that count, each **CAUGHT** by a §4.7.3 test in `null_provider.zig`: a cap never
reached, the cap reported as `TlsFailed`, an update not counted, and an update counted before it
fits its output.
