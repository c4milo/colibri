# Design §8 step 12: h3

[Design §8, the build plan](../../design.md#8-build-plan)

Stream types, the frame layer, the one setting, the control stream rules, request and response
mapping, GOAWAY, greasing. **Check:** `h3spec` against the h3 entry point, with every case accounted
for; the interop runner's `http3` case; `h2load --h3`; and the h2 suite's semantics tests re-run
against h3, which proves the `http` module is shared rather than duplicated. *Medium.*

**The message rules h3 will need are in `http` already, 2026-09-20.** `http/message_lines.zig`
and `http/message_request.zig` hold every rule RFC 9113 §8 and RFC 9114 §4 both state, and
return a reason rather than a verdict; h2's two files in `src/h2/message/` are now the mappers
that name h2's errors for those reasons. h3's side of step 12 writes the second mapper and the
five rules [decision 51](../../decisions/0051-h2-and-h3-share-their-message.md) keeps per protocol, and writes no rule twice. The move
changed nothing that runs: h2's tests moved with their files and pass unaltered, `h2spec` still
prints 144 passed, and `connection-check` still prints `crc32=0xe8f7c0b4`. Five mutations over
the shared rules, each broken in `src/http/`: all **CAUGHT** by h2's own tests, which is what
says the shared code is the code that runs.

**The message rules are done, 2026-09-20.** `src/h3/message/message.zig` is the second mapper
decision 51 asked for: it names h3's errors for the reasons `http` returns and holds almost no
rule of its own. Every malformed message is one stream error, H3_MESSAGE_ERROR (§4.1.2), which
`verdict` answers.

Three rules part from h2 here, and each is a place the split had to be right rather than
convenient. `message_authority.zig` holds RFC 9114 §4.3.1's rules binding `:authority` to
`Host`, which are four MUSTs where RFC 9113 §8.3.1 has one SHOULD; three are checked and the
fourth needs a registry of which schemes have a mandatory authority component, which colibri
has only for http and https. A repeated pseudo-header is refused whichever it is: §4.3.1 names
`:method`, `:scheme` and `:path`, and §4.1.2 makes an invalid value for any pseudo-header
malformed, so colibri takes the strict side. And a value starting or ending with SP or HTAB is
refused under RFC 9110 §5.5, because RFC 9114 states no rule of its own — which is exactly why
`http` reports that reason apart from the character rules.

Two of h2's rules are absent, for the reasons decision 51 gives: an informational response with
END_STREAM, which needs a flag h3 has no equivalent of, and `:protocol`.

Mutations: seven applied over h3's own rules, all **CAUGHT** — the missing authority, an empty
`:authority`, an empty `Host`, a case-insensitive comparison, the scheme test skipped, and the
two divergent reasons mapped to the wrong error. `zig build test` passes 986 of 986 and
`connection-check` still prints `crc32=0xe8f7c0b4`.

**The framing and stream layers are done, 2026-09-20.** `src/h3/frame.zig` and
`frame_write.zig` are §7's frames, §7's Table 1 saying which stream carries which, §7.2.4's
settings, and §6.2.3 and §7.2.8's reserved types. `src/h3/stream.zig` is §6.2's unidirectional
stream headers and the rules about which of them may exist.

Two shapes are worth naming. The frame header and its payload are read apart, because a DATA
frame's payload is as long as the content and arrives over many packets: a reader wanting the
whole frame in one buffer would put the body's size in colibri's memory bound, which
[decision 35](../../decisions/0035-colibri-is-zero-heap.md) forbids. And a short read is not a protocol error —
`Truncated` means the bytes have not all arrived, while every other error names the §8.1 code
the connection closes with. Telling those two apart is why the header is read on its own.

**Check so far:** 32 mutations over the three files, all caught. **Still owed:** the request
and response mapping of §4.1 to §4.3, which §12 question 6 must settle first; the connection
itself, which needs QUIC streams and so waits on 9e; and h3spec, the interop runner's `http3`
case and `h2load --h3`, which all need a connection.

**Fuzzing, 2026-09-26.** `frame_fuzz.zig` reads a header and, when colibri reads the payload
whole, the payload ([#53](https://github.com/c4milo/colibri/issues/53)). A short header must consume nothing. A whole payload must never
be `Truncated`, which would have the caller wait for bytes that are not coming. An accepted
payload must be the type its header named and keep §7.2's rules, which the property reads
again. Written again, it must read back the same. 10 mutations, 10 **CAUGHT** by the fuzz test
alone, two of them only after the corpus gained a SETTINGS payload cut inside a pair and one
holding a single setting.

**The connection and its simulator check, 2026-09-24.** The owner ruled h3's send path first
(decisions 78 and 79), and decision 80 followed:
- `61443b6`: `quic` reports how far a stream is acknowledged from its start (decision 78), which
  h3's three streams need because they never end. 7 mutations, 7 CAUGHT.
- `3e1ed79`: `quic` copies a stream's received bytes without taking them (decision 80), so a
  field section blocked on QPACK stays in the receive pool. 7 mutations, 7 CAUGHT.
- `1b5d763`: `quic` keeps the error code of a peer's RESET_STREAM for the application. 2
  mutations, 2 CAUGHT.
- `929a760`: `src/h3/connection/`. It opens the control and QPACK streams and reads the peer's.
  It maps requests and responses (§4.1), with interim responses, trailers and content-length
  (§4.1.2). It covers GOAWAY (§5.2), refusals and resets (§4.1.1), and greasing (§7.2.4.1,
  §8.1). Every RFC 9114 rule it checks has a test that breaks it. 65 mutations, 65 CAUGHT. Three
  first survived and gained tests.
- `1db9175`: `src/sim/h3_check.zig`. A colibri client and server exchange a seed's requests
  over step 8's network. Every field section and content byte must arrive as planned. The
  connection must then settle: no slot, blocked section or owed instruction left, and every
  insert acknowledged. The long mode's connections outgrow h3's own buffers, so decision 78's
  drop runs under loss.

`zig build sim -- --h3-check` and `-- --h3-long-check` printed, in Debug and in ReleaseSafe on
macOS arm64:
`h3: seeds=256 exchanges=7524 content=20308595 inserts=14526 acknowledged_dropped=0
datagrams=88945 dropped=4498 crc32=0xbd4c7fc8` and `h3-long: seeds=64 exchanges=14733
content=3386507 inserts=10721 acknowledged_dropped=71805 datagrams=133432 dropped=6238
crc32=0xc1c60f94`. 4 mutations, 4 CAUGHT. Three first survived: no buffer had filled, and
nothing required every insert to be acknowledged. One of them, an acknowledged end that ignores
the lost table, is caught only from 64 long seeds, which is why the long check runs 64.

**Still owed:** design §9's h3 server and client on the UDP endpoint, and with them h3spec, the
interop runner's `http3` case and `h2load --h3`. The h2 suite's semantics tests re-run against
h3 are the message tests of `src/h3/message/`, recorded above. The TLA+ model of the connection,
checked against the simulator's traces, is
[#58](https://github.com/c4milo/colibri/issues/58).

**The endpoint and three of the four checks, 2026-09-24.**
- `f6344f8`: design §9's h3 server and client on the UDP endpoint. The server offers h3 and
  hq-interop by ALPN and serves whichever the client picks. Both sides advertise a QPACK table
  of 4,096 bytes and 16 blocked streams, so each peer's encoder uses one.
- `8accf3c`: h3's control and QPACK streams go out ahead of request streams. Without it,
  `h2load --h3` lost 6 of 1,000 requests in about one run in ten: a response left ahead of the
  insert it referenced, and h2load ended the blocked stream unread. The simulator's censuses
  moved with the new order and were pinned again, in Debug and ReleaseSafe alike:
  `h3: ... inserts=15432 acknowledged_dropped=0 datagrams=96643 dropped=4895 crc32=0xdacf68d7`
  over 256 seeds, and `h3-long: seeds=128 ... acknowledged_dropped=176393 datagrams=313830
  dropped=15189 crc32=0xb2ba117a`. The long check now runs 128 seeds, the fewest that catch an
  acknowledged end that ignores the lost table.
- `1e1b480`: `tools/h3load.sh` and `tools/h3spec.sh`, and the server's `errors` option, which
  keeps it serving past a connection error.

What each check printed on macOS arm64, with chapulin `989e3da`:
- The QUIC Interop Runner's `http3` case passed in both roles against quic-go, ngtcp2, neqo and
  quinn, and against colibri itself.
- `tools/quic_udp.sh` and `tools/quic_aioquic.sh` fetched three files over h3 in both
  directions, byte for byte. aioquic's h3 uses ls-qpack with a dynamic table.
- `tools/h3load.sh` printed `requests: 1000 total, 1000 started, 1000 done, 1000 succeeded,
  0 failed` with ALPN h3, three runs out of three. It saved 84% of the header bytes, which
  shows the peer's decoder reading colibri's dynamic table.
- `tools/h3spec.sh` ran h3spec v0.1.13 and no case passed, because no handshake completed.
  h3spec's client offers TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256 and
  TLS_AES_128_CCM_SHA256 alone, and chapulin's QUIC mode protects packets with
  ChaCha20-Poly1305 alone; its Makefile refuses `SUITE=aesgcm` with `TRANSPORT=quic`. The
  request for AES-GCM in QUIC mode is with chapulin.

Two faults outside h3 surfaced. chapulin `274b1f5` fails every handshake with ngtcp2's client,
because that client reorders its extensions after a HelloRetryRequest. The bytes are with
chapulin, and colibri stays on `989e3da`. After any TLS alert, colibri cannot send its
CONNECTION_CLOSE, because chapulin no longer seals once its session fails:
[#59](https://github.com/c4milo/colibri/issues/59).

**The TLA+ model, 2026-09-24.**
- `b084ef2`: `spec/tla/h3_connection` models a colibri client and a colibri server. It covers
  request streams, cancels, GOAWAY and the control stream, and QPACK's encoder and decoder
  streams against the server's flow-control windows. `zig build tla` printed `holds, as
  expected` for both scopes: `37428 distinct states` for shutdown, and `25007` for flow.
- Each of the seven mutant configurations printed `violated, as expected`:
  - a stream at or above the GOAWAY is taken;
  - the GOAWAY names the last stream taken;
  - a GOAWAY rises;
  - the control stream ends;
  - a stream reports after its cancel;
  - the encoder stream sends after request streams;
  - an insert is made without credit.
- All nine ran in 26 seconds on macOS arm64.
- `beb782f`: the last mutant was colibri's rule. h3 gave the QPACK encoder the encoder
  stream's buffer room, not its flow-control credit. Sections referencing an insert that had no
  credit then blocked at the peer, and they held its whole connection window. h3 now cuts the
  encoder's writer to quic's new `connection_stream_credit.send_credit`
  ([decision 81](../../decisions/0081-h3-lets-the-qpack-encoder-insert.md)). 8 mutations, 8 CAUGHT.
- The encoder-stream order is the rule `8accf3c` added after `h2load --h3` lost requests. The
  model shows that without it, blocked sections can hold the connection window.

**The close after a failed handshake, 2026-09-24.** colibri's UDP server now sends the
CONNECTION_CLOSE RFC 9001 §4.8 owes when its TLS stack refuses a handshake, and serves the next
connection ([#59](https://github.com/c4milo/colibri/issues/59), [decision 84](../../decisions/0084-after-the-tls-provider-fails-the.md)).
- After the provider fails, colibri asks the suite which levels can still seal. chapulin
  (`0e6fd15`, `6a4c5eb`) seals one close per level through `ch_quic_seal_close`.
- Against chapulin `6a4c5eb`, an aioquic client offering an ALPN colibri does not serve read
  `close carried 0x178 after 0.61s` twice in a row: CRYPTO_ERROR for no_application_protocol.
  Before, it waited out its 20-second idle timeout, and colibri's server exited.
- `tools/quic_aioquic.sh` now checks this, and `tools/quic_loopback.sh`, `tools/quic_udp.sh` and
  the rest of `tools/quic_aioquic.sh` still pass.
- 7 mutations, all CAUGHT.

**The runner against ngtcp2 on chapulin `6a4c5eb`, 2026-09-24.** chapulin fixed the
HelloRetryRequest fault above, and colibri leaves `989e3da`. On macOS arm64,
`tools/interop.sh <checkout> ngtcp2` passed all 17 cases in both roles: H, DC, C20, M, L1, L2,
S, U, A, 6, E, LR, B, BP, BA, R and 3.

**h3spec, 2026-09-25.** chapulin `1558099` adds the AES-GCM suites to its QUIC mode, so h3spec's
handshakes now complete ([decision 85](../../decisions/0085-the-quic-object-is-built-suiteaesgcm.md)).
- The QUIC object is built `SUITE=aesgcm AES=hw`. Every chapulin endpoint checks it against the
  headers with `ch_build_matches` before it starts.
- h3spec 0.1.13 found two colibri defects, both fixed:
  - `5c25f1b`: a STOP_SENDING, STREAM, MAX_STREAM_DATA or RESET_STREAM frame naming a stream the
    server initiated but had not opened reached an assertion, so any peer could crash the
    server. It is now STREAM_STATE_ERROR (RFC 9000 §19.5, §19.8, §19.10), and
    STREAM_DATA_BLOCKED now follows §19.13 through the same lookup. 3 mutations, 3 CAUGHT.
  - `d6c686d`: the receive walk never called the reserved-bit check, so packets with those bits
    set were processed. It now closes with PROTOCOL_VIOLATION (RFC 9000 §17.2, §17.3.1). 3
    mutations, 3 CAUGHT.
- h3spec's client does not parse an ACK frame of type 0x03, and colibri's server sends one
  whenever it reads ECN codepoints. `tools/h3spec.sh` runs the server with the new `no-ecn`
  word. quic-go, ngtcp2 and aioquic read those frames.

- On `1558099`, the last case failed. chapulin's server dropped a KeyUpdate that followed the
  client Finished in one Handshake-level delivery, where RFC 9001 §6 requires error 0x010a.
  chapulin fixed it in `37bebc5`, and colibri added no workaround.

What each check printed on macOS arm64, with chapulin `37bebc5`:
- `tools/h3spec.sh <checkout>`: `49 examples, 0 failures` and `ok, every case passed`.
- `tools/quic_loopback.sh`, `tools/quic_udp.sh` and `tools/quic_aioquic.sh` passed. Against
  aioquic's server, colibri's client ran TLS_AES_256_GCM_SHA384, so its key log held 48-byte
  secrets.
- `tools/interop.sh <checkout> quic-go,ngtcp2`, whose image built chapulin `1558099` with the
  new make line: every case passed in both roles against both peers. quic-go reports its own
  side of the ECN case as unsupported.
- 3 mutations of the switch, all CAUGHT: a define the object lacks, which `check_build`
  refuses; the resumption PSK's length ignored; and `no-ecn` ignored.

**Trace validation, 2026-09-25**
([#58](https://github.com/c4milo/colibri/issues/58), [decision 87](../../decisions/0087-the-simulators-h3-trace-run-logs.md)).
- `src/sim/h3_trace_check.zig`: a colibri client and server act out a seed's plan over step
  8's network. The plan draws requests of whole frames, cancels, GOAWAYs and QPACK inserts.
  After each step, `h3_trace_state.zig` computes the 28 variables of
  `spec/tla/h3_connection` from both endpoints, and the run keeps each state that differs from
  the one before.
- `zig build sim -- --h3-trace-write <directory>` writes 64 seeds' states as TLA+ modules and
  TLC configurations. `tools/h3_trace.sh` runs TLC over them with `H3ConnectionTrace.tla`.
  Between two logged states the model takes up to 24 steps. A seed passes when TLC reaches its
  last logged state.
- The run found two places where the model refused what colibri does and the RFCs allow. The
  model changed in both:
  - A decoder with no dynamic table sends no Stream Cancellation, which RFC 9204 §2.2.2.2
    allows. The new constant `DecoderTable` says whether the server's decoder allows a table.
  - The client's quic resets a refused stream when the server's STOP_SENDING arrives (RFC 9000
    §3.5). That can happen before or after the client reads the refusal, and never when every
    byte is already acknowledged. It is now its own action, `StopSending`, and no longer part
    of `ReadAnswer`.
- TLC stops a path once a variable that only grows has passed the next logged state
  (`Toward`). Without that, one seed took 5.7 million states and 49 seconds. With it, the seed
  took 32 states and one second.

What each check printed on macOS arm64:
- `zig build sim -- --h3-trace-check`, in Debug and in ReleaseSafe: `h3-trace: seeds=256
  requests=428 responses=155 rejections=162 cancels=111 goaways=235 inserts=59`.
- `tools/h3_trace.sh`: `64 of 64 traces are behaviors of the model`, in 54 seconds. The 64
  logs hold 507 states. Of the logs, 33 hold an answered request, 31 a rejected one, 24 a
  cancelled one, 40 a GOAWAY, 25 a Stream Cancellation, 8 an Insert Count Increment, 4 a
  Section Acknowledgment and 3 a blocked field section. 15 seeds' servers allow no table.
- `zig build tla`: both scopes hold, shutdown in 90005 distinct states and flow in 25007, and
  all seven mutant configurations are violated, as before.
- A log edited by hand to hold a state the model cannot reach left `Unfinished` holding, and
  the script failed.
- 4 mutations of colibri, 4 CAUGHT:
  - the GOAWAY names the last stream taken: 54 of 64 traces pass;
  - the server takes a stream at or above its GOAWAY: 37 of 64 pass;
  - a decoder with a table owes no Stream Cancellation: 60 of 64 pass;
  - a later GOAWAY names a higher ID. colibri's own client catches this before TLC runs, and
    closes the connection with H3_ID_ERROR (RFC 9114 §5.2).

Every check step 12 names has passed, and the step owes nothing more.
