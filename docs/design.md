# colibri — h11, h2 and h3 Design Document

Owner: Camilo. Scope: the library, its three HTTP versions and QUIC, both roles. §8 records each
step of the build and what its check printed. Sibling to [decisions.md](decisions.md) and
[invariants.md](invariants.md); decisions there are taken as given and cited, not relitigated.

Every section is cited by number in commits and comments ("§8 step 4").

---

## 1. Thesis and scope

colibri is an HTTP/1.1, HTTP/2 and HTTP/3 library, client and server, written from the RFCs. It owns
no I/O and no clock: bytes and time arrive from the caller. Its crypto is `stdx.crypto`, which
holds every key ([decisions 94 and 174](decisions/0094-colibri-links-chapulin-as-its-tls.md)). The `.private` kind of
`colibri.Server` and `colibri.Client` is the one part that does I/O
([decision 150](decisions/0150-colibri-binds-reads-its-files-and.md)). What it owns is the
part that is hard to get right and easy to get wrong — framing, field compression, stream state,
flow control, loss recovery — and it owns it with no heap, bounded loops and assertions that stay on
in production.

A library that owns no sockets can be driven by a deterministic
simulator, replayed from a seed, and embedded in a runtime whose I/O model it never heard of.
stompy is the first consumer and will vendor colibri the way it vendors chapulin; colibri never
depends on stompy and never names it in source.

**Deliberately excluded:** caching, server push, priority scheduling, extended CONNECT, 0-RTT,
active connection migration, QUIC datagrams and multipath. [Decisions 16 to 23](decisions.md)
give each one a reason and state what saying no still costs on the wire. HTTP/1.1 was excluded
too, until [decision 88](decisions/0088-colibri-builds-http11-as-h11-client.md) amended decision 2 to build it as h11.

## 2. What the two protocols actually are

It is worth stating the shape plainly before the module graph, because the module graph follows
from it.

**h2** is one TCP connection carrying 9-byte-framed messages, with its own stream multiplexing,
its own credit-based flow control, and HPACK for field compression. Everything above the socket is
colibri's.

**h3** is three layers, and only the top one is HTTP. QUIC (RFC 9000, 9001, 9002) supplies
streams, flow control, loss recovery and packet protection. QPACK (RFC 9204) supplies field
compression over two extra unidirectional streams. RFC 9114 is the thin part: a frame layout, a
handful of stream types, one setting, and the mapping of HTTP messages onto QUIC streams. RFC
9114 Appendix A makes the point from the other side — h3 removes `RST_STREAM`, `PING`,
`WINDOW_UPDATE` and `CONTINUATION` because QUIC already has each of them (Appendix A.2.5), drops
the Flags field for the same reason (Appendix A.2), and leaves stream concurrency to QUIC
(Appendix A.1).

So the work is not split evenly. QUIC is the larger half of colibri by a wide margin, and
[decision 3](decisions/0003-quic-is-a-module-inside-colibri.md) puts it in a module that knows nothing about HTTP.

## 3. Module graph

A module can import only what `build.zig` gives it, so the direction below is enforced by the
build and not by review. An arrow reads "imports".

```text
core   <- wire   <- hpack <- h2
                 <- qpack <- h3
core   <- http   <- h2, h3, h11
core   <- tls_provider <- h2, h11, quic, tls
stdx   <- h11, qlog, tls, dnssec, client, server, colibri, sim_run
stdx (crypto_keylog) <- tls_keylog, testing_quic, testing_udp
core   <- crypto <- quic, tls
core   <- dnssec
qlog   <- quic, h3
core   <- wire   <- quic  <- h3
core, tls_provider, crypto <- sim
core, wire, sim, h2, qpack, h3, quic, client, server, tls <- sim_run
core, sim, quic  <- sim_run_quic
core, wire, hpack, quic <- golden
core, h2, tls, server, rotor <- testing, testing_client
core, h2, tls    <- testing_tls, testing_tls_server
h2, h3, tls, rotor <- testing_udp
h2, quic, tls    <- testing_quic
core, qpack      <- testing_qif
core, http, h11, h2, h3, quic, tls <- client, server
each of the sixteen other library modules, rotor (lazy, decision 159) <- colibri
testdata <- tls_keylog, sim_run, and the roots the tests of tls, server and client compile from
```

| Module | Holds | Imports | RFCs |
|---|---|---|---|
| `core` | limits, assertions, the bounded reader and writer, the slot pool | nothing | — |
| `wire` | varint, prefixed integer, Huffman, string literal | `core` | 9000 §16, 7541 §5.1, §5.2, App. B |
| `http` | the version-independent semantics core | `core` | 9110 |
| `tls_provider` | the TLS provider vtable, which `tls` and the simulator fill ([decision 97](decisions/0097-the-librarys-tls-module-is-tls.md)) | `core` | 9846, 7301, 9001 §4 |
| `crypto` | the packet-protection vtable, no production implementation | `core` | 9001 §5 |
| `hpack` | HPACK | `core`, `wire`, `http` | 7541 |
| `qpack` | QPACK | `core`, `wire`, `http` | 9204 |
| `qlog` | a log in the caller's buffer as JSON Text Sequences, and the QUIC and HTTP/3 event records `quic` and `h3` fill ([decision 102](decisions/0102-colibri-writes-qlog-when-its-caller.md)) | stdx, of which it reads `json` and `platform` ([decision 102](decisions/0102-colibri-writes-qlog-when-its-caller.md) as amended and [171](decisions.md)) | 7464, 8259, and the qlog drafts of `docs/rfcs/qlog/` |
| `quic` | the transport: packets, frames, streams, recovery | `core`, `wire`, `crypto`, `tls_provider`, `qlog` | 8999, 9000, 9001, 9002 |
| `h2` | HTTP/2 | `core`, `wire`, `http`, `hpack`, `tls_provider` | 9113 |
| `h3` | HTTP/3 | `core`, `wire`, `http`, `qpack`, `quic`, `qlog` | 9114 |
| `h11` | HTTP/1.1 ([decision 88](decisions/0088-colibri-builds-http11-as-h11-client.md)) | `core`, `http`, `tls_provider`, and stdx's decoders of the `gzip` and `deflate` codings ([decision 90](decisions/0090-the-compression-codecs-live-in-stdx.md)) | 9112 |
| `tls` | TLS 1.3 over `stdx.crypto`, which is chapulin: colibri's values, converted once per chapulin object; record-mode sessions behind `tls_provider.Provider`; and QUIC sessions behind `tls_provider.QuicProvider` and `crypto.Suite` ([decisions 94, 97 and 174](decisions/0094-colibri-links-chapulin-as-its-tls.md)) | `tls_provider`, `crypto`, and stdx, whose `crypto` carries chapulin's TCP and QUIC objects, built `KEYLOG=off` | 9846, 7301, 9001 |
| `dnssec` | DNSSEC's signature checks and DS digests over `stdx.crypto`'s TCP object, the one `tls` links ([decisions 142 and 174](decisions/0142-dnssecs-signature-checks-are-a-module.md)) | `core` for its tests' lists, and stdx, whose TCP object is built `DNSSEC=on` on arm64 and x86-64 | 4034, 3110, 4509, 5155, 5702, 6605, 8080 |
| `client` | HTTP requests over whichever of h3, h2 and h11 the connection negotiates: it drives the TLS handshake over TCP or QUIC and chooses the transport from the values its caller passes ([decision 100](decisions/0100-a-version-choosing-http-client-and.md)) | `core`, `http`, `h11`, `h2`, `h3`, `quic`, `tls`, and stdx's decoders of the content codings ([decision 101](decisions/0101-the-client-and-server-code-content.md)) | 9110, 9112, 9113, 9114, 7838, 9460 |
| `server` | HTTP responses behind the same calls for h11, h2 and h3, the version chosen by transport and ALPN ([decision 100](decisions/0100-a-version-choosing-http-client-and.md)) | `core`, `http`, `h11`, `h2`, `h3`, `quic`, `tls`, and stdx's encoders of the content codings ([decision 101](decisions/0101-the-client-and-server-code-content.md)) | 9110, 9112, 9113, 9114, 7838 |
| `colibri` | `colibri.Server` and `colibri.Client`, which run `server` and `client` behind a host contract of colibri's own ([decision 159](decisions/0159-colibriclient-and-colibriserver-take-a-host.md)). On `.private`, colibri's Rotor adapter binds the sockets and runs the loop: the one library code that does I/O ([decisions 150 and 153](decisions/0150-colibri-binds-reads-its-files-and.md)). On `.hosted` the program is the host, and colibri does no I/O | Each of the sixteen other library modules, which its root names: it is the one module the package exports ([decision 170](decisions/0170-the-package-exports-one-module-colibri.md)). stdx, for the `stdx.crypto.Context` a server's configuration takes ([decision 175](decisions/0175-colibri-takes-the-programs-stdxcryptocontext-once.md)). And Rotor, a lazy dependency that a build fetches only with the build option `rotor` ([decision 159](decisions/0159-colibriclient-and-colibriserver-take-a-host.md), which amends [decision 150](decisions/0150-colibri-binds-reads-its-files-and.md) rulings 3 and 6) | — |
| `tls_keylog` | `tls` again over objects built `KEYLOG=on`: for the tests that seal a peer's records under the secrets chapulin logs, and for the QUIC endpoints of §9, which write them to SSLKEYLOGFILE; test-only | `tls_provider`, `crypto`, a second stdx built with `crypto_keylog`, whose chapulin objects are built `KEYLOG=on` ([decision 174](decisions/0174-colibri-takes-chapulin-through-stdx-as.md)), and `testdata` for its tests | — |
| `testdata` | the test identity the handshake tests of `tls`, `tls_keylog`, `server` and `client` and the client trace run read: a CA, a leaf for `localhost` and the leaf's key pair, valid from 2026-01-01 to 2126-01-01 and made once with openssl (`src/testing/testdata/README.md`). One copy serves them all, because `@embedFile` reads only inside the directory of the module that calls it. Test-only: the tests of `tls`, `server` and `client` compile from roots of their own that import it (`build/modules_test_roots.zig`). No packaged module imports it, and only colibri's own build makes it, so a project that depends on colibri never reaches its private key (the owner's ruling of 2026-09-28) | nothing | — |
| `sim` | deterministic clock, byte pipe, datagram network, null providers | `core`, `tls_provider`, `crypto` | — |
| `sim_run` | the checks of §8 run over `sim`, and the `zig build sim` command line | `core`, `wire`, `sim`, then each module a check drives: `h2` at step 4, `qpack` at step 11, `h3` and `quic` at step 12, `h11` at step 15a, stdx's `gzip` and `zlib` encoders at step 15c, which code the bodies the h11 coding check sends (the owner's ruling of 2026-09-26), and `client` and `tls` at step 17d, whose client trace run drives the client's connections over chapulin (decision 105, the owner's ruling of 2026-09-28), with `testdata` for the identity its servers present, and `server` at step 17e, whose content-coding check runs the client against it (the owner's ruling of 2026-09-29) | — |
| `sim_run_quic` | the QUIC checks of §8 run over `sim`, from step 7 on | `core`, `sim`, `quic`, and no HTTP module | — |
| `golden` | the byte-exact corpus and its manifest | what it checks | — |
| `testing` | the test-only endpoints of §9, and the only socket in the tree | `core`, then each module an endpoint serves, `tls` for its TLS mode, `server`, which its h11 and h2 server runs on from step 17a, and `rotor` ([decision 83](decisions/0083-the-h2-endpoints-run-on-rotor.md)) | — |
| `testing_client` | the same directory under a second root, because an executable has one `main`: the h2 client of §9 | what `testing` imports | — |
| `testing_tls`, `testing_tls_server` | the two one-connection TLS checks of §8 step 5, a root each for its `main` | `core`, `h2` for the shared constants, `tls_provider` and `tls` | — |
| `testing_qif` | the two QPACK command-line tools of §9, `.qif` to encoded and back | `core`, `qpack` | — |
| `testing_quic` | the QUIC loopback check of §8 step 9e: a colibri client and server over `tls.quic` in one process | `h2` for the shared constants, `quic`, `tls_keylog` as `tls`, and its QUIC object's module for `ch_keylog` | — |
| `testing_udp` | §9's UDP QUIC endpoint, the hq-interop and h3 servers and clients, on Rotor's loop ([decision 58](decisions/0058-rotor-is-the-loop-of-srctesting.md)) | `h2` for the shared constants, `h3` from step 12, `quic`, `rotor`, `tls_keylog` as `tls` with its QUIC object's module, and from step 17b `server`, an instance over `tls_keylog` that nothing packaged sees, which its h3 server runs on (the owner's ruling of 2026-09-28) | — |

The architecture depends on four of these edges and forbids one.

- **`quic` does not import `http`, `h2`, `h3`, `h11`, `hpack` or `qpack`.** This is
  [invariant 26](invariants.md#inv-26) and
  [decision 5](decisions/0005-quic-knows-nothing-about-http.md). The check that proves it is that the QUIC simulator
  builds and runs with no HTTP module in the graph at all — not a lint rule, a link.
- **`sim` imports `core`, `tls_provider` and `crypto`, and no protocol module.** It implements the same two
  vtables a real caller does, so the build hands its null providers to the protocol modules in
  place of the caller's and nothing is conditionally compiled. It cannot import a protocol module,
  which is what keeps the harness from knowing anything the caller would not. A check drives a
  protocol module through the harness, so the one module that imports both is `sim_run`, rooted at
  `src/sim/run.zig`, and `sim` never imports it back ([decision 37](decisions/0037-the-checks-and-the-zig-build.md)).
  The QUIC checks have a root of their own, `sim_run_quic` at `src/sim/run_quic.zig`, because
  `sim_run` imports `h2`: a QUIC check placed there would run with an HTTP module in its graph,
  and the first edge of this list is proved by a build that has none.
- **`wire` is shared by both families and holds two different integer codecs.**
  [decision 11](decisions/0011-the-huffman-coder-and-the-prefixed.md) explains why the split is *field
  compression against framing* and not h2 against h3.
- **No protocol module imports `tls`.** h11, h2 and quic take a provider, and a program makes a
  session with `tls` and hands its provider over ([decision 97](decisions/0097-the-librarys-tls-module-is-tls.md)). `colibri` imports
  `tls`, so every program that imports `colibri` links chapulin through `stdx.crypto`, a program
  in cleartext too ([decisions 170 and 174](decisions/0170-the-package-exports-one-module-colibri.md)).
- **Nothing imports `h2`, `h3` or `h11` but `client` and `server`.** The protocol modules are the
  roots a consumer picks from, and `client` and `server` are consumers above all three, which
  choose the version for their caller ([decision 100](decisions/0100-a-version-choosing-http-client-and.md)). No library module but
  `colibri` imports `client` or `server` in turn, and no library module imports `colibri`
  ([decision 150](decisions/0150-colibri-binds-reads-its-files-and.md) ruling 1). `testing` is a consumer like any other: the library it drives cannot use the
  socket it opens, because the edge runs one way and nothing imports `testing` back.

## 4. What the caller supplies

Five things cross the boundary out of colibri. Each is a value or a vtable, never a callback
colibri invokes at a time of its choosing.

### 4.1 Bytes

The caller reads from its socket and hands colibri a slice. colibri parses what it can, tells the
caller how many bytes it consumed, and leaves the remainder for the next call. For output the
caller hands colibri a slice to fill and colibri returns how many bytes it wrote. There is no
buffering of unconsumed input inside colibri beyond what a partial frame requires, and that is a
fixed, named size (§7).

### 4.2 Time

Every function needing an instant takes `now_ns: u64`. RFC 9002's pseudocode reads `now()` at
nine sites, reachable from five entry points: `OnPacketSent`, `OnDatagramReceived`,
`OnAckReceived`, `SetLossDetectionTimer` and `OnLossDetectionTimeout`. The ninth site is inside
the congestion controller's `OnCongestionEvent`, so the instant is passed to it too rather than
stopping at the loss detector. colibri passes one instant through a whole call, which RFC 9002
permits and determinism requires.

colibri never sets a timer. It returns the instant at which it next wants to be called, and the
caller arranges that. An idle timeout, a PTO and a `SETTINGS_TIMEOUT` are all the same shape: a
deadline colibri computes and the caller honours.

### 4.3 The TLS provider

Two modes, because RFC 9001 §3 says QUIC "takes over the responsibilities of the TLS record
layer". The full list is [decision 8](decisions/0008-the-tls-provider-is-a-caller.md); the shape is:

| Operation | Record mode (h2) | QUIC mode (h3) |
|---|---|---|
| handshake bytes | record-framed, over TCP | unframed messages, per encryption level |
| application protection | `encrypt_record` / `decrypt_record`, and `writable_len` / `encrypt_parts` for a frame's header and its data ([decision 139](decisions/0139-a-provider-seals-a-frames-header.md)) | absent — colibri protects packets itself |
| secrets | never exposed | never exposed to colibri: the provider hands them to the suite ([decision 48](decisions/0048-the-suite-holds-every-key-and.md)) |
| key derivation | provider-internal | provider-internal |
| transport parameters | absent | `set_transport_params` / `peer_transport_params` |
| ALPN | `negotiated_alpn` | `negotiated_alpn` |
| alerts | `take_alert` | `take_alert`, mapped to `0x0100 + AlertDescription` |
| key update | `initiate_key_update` | forbidden — QUIC's Key Phase instead |
| a peer's KeyUpdate | answered in front of the records of the next `encrypt_record` | a connection error of 0x010a (RFC 9001 §6) |
| exporter | `export_keying_material` | `export_keying_material` |

Two facts constrain the ALPN half and are easy to get wrong. In TLS 1.3 the selected protocol
is sent in EncryptedExtensions, not ServerHello, so it is only readable after the provider has
decrypted EE — colibri must not assume it knows the ALPN earlier. And `"h2"` is the two bytes
`0x68 0x32` (RFC 9113 §3.1) while `"h3"` is `0x68 0x33` (RFC 9114 §11.1); no overlap is a fatal
`no_application_protocol` alert, value 120 (RFC 9846 §6, RFC 7301 §3.2), which RFC 9001 §8.1
extends by requiring QUIC *clients* to use it too.

One state colibri owns and no provider will supply: **handshake confirmed**. RFC 9846 has no such
concept; it is defined only in RFC 9001 §4.1.2 — at the server when the handshake completes, at
the client when `HANDSHAKE_DONE` arrives.

### 4.4 The crypto suite

QUIC only; h2 needs none of it, because the provider does the record layer. The suite holds every
key of a connection and colibri holds none ([decision 48](decisions/0048-the-suite-holds-every-key-and.md)),
so its members are whole-packet operations at an encryption level (RFC 9001 §4.1.4):

| Member | What it does | RFC 9001 |
|---|---|---|
| `install_initial_keys(role, dcid)` | derives the Initial keys from the client's first Destination Connection ID, and again after a Retry | §5.2 |
| `keys_available(level, direction)` | whether colibri may seal or open at the level | §4.1.4 |
| `seal(level, packet_number, header, payload)` | protects the payload, then masks byte 0 and the packet number | §5.3, §5.4 |
| `open(level, packet, packet_number_offset, largest)` | removes both protections and recovers the packet number, in one call | §5.3, §5.4, §9.5 |
| `retry_tag_valid`, `retry_tag_write` | the Retry Integrity Tag, checked by a client and written by a server | §5.8 |
| `update_keys`, `key_phase`, `discard_previous_keys` | the key update, which colibri times and the suite performs | §6 |
| `discard_keys(level)` | forgets a level's keys when colibri says the level is over | §4.9 |

colibri frames the packet and the suite protects it. For `seal` colibri writes the header with the
packet number encoded (RFC 9000 §17.1), the Key Phase bit from `key_phase`, and enough payload for
the sample of §5.4.2. After `open` colibri reads byte 0 for the Reserved Bits and the packet number
length (RFC 9000 §17.2). `open` reports which keys opened a 1-RTT packet, the previous, the
current or the next, and that is how colibri learns the peer has updated (§6.2).

RFC 9001 fixes three things to AES whatever suite TLS negotiates: Initial packet protection (§5,
§5.2), the header protection used before a suite is selected (§5.4.1, §5.4.3), and the Retry
integrity tag (§5.8). A suite must carry those and whatever TLS goes on to negotiate (§5.3,
§5.4.1). colibri cannot see what a suite carries, so a suite that refuses `install_initial_keys`
is a configuration error
([invariant 25](invariants.md#inv-25)),
never a peer's fault. [Decision 9](decisions/0009-packet-protection-is-a-second-caller.md) is why this is a second
vtable, and decision 48 is why its members are these.

### 4.5 The stream provider

QUIC only. colibri retransmits stream data itself (RFC 9000 §13.3), so it must be able to read a
stream's bytes again until the peer acknowledges them, and it holds no copy. The caller keeps
the bytes and supplies a vtable with one member, `read(stream_id, offset, output)`, which writes
the stream's bytes from `offset` into `output` and returns how many it wrote. colibri calls it
inside `send` alone, for new bytes and for lost ones, and the caller may drop a stream's bytes
once colibri reports the stream in Data Recvd (RFC 9000 §3.1) or reset. The provider answers the same
bytes for an offset every time, which RFC 9000 §2.2 requires and colibri cannot check.
[Decision 57](decisions/0057-the-caller-keeps-a-streams-unacknowledged.md) is the ruling and the alternatives it beat.

## 5. What is shared, and what only looks shared

[decisions 11 to 16](decisions/0011-the-huffman-coder-and-the-prefixed.md) argue each of these from the
RFC text. The summary, because it is the question the module graph answers:

| Candidate | Verdict | Module or file |
|---|---|---|
| Huffman code, RFC 7541 App. B | **shared**, verbatim — RFC 9204 §4.1.2 | `wire/huffman.zig` |
| Prefixed integers, RFC 7541 §5.1 | **shared**, unmodified — RFC 9204 §4.1.1 | `wire/prefixed_integer.zig` |
| String literals, RFC 7541 §5.2 | **shared**, with QPACK's mid-byte prefix added | `wire/string_literal.zig` |
| Dynamic-table size formula | **shared** arithmetic — 7541 §4.1, 9204 §3.2.1 | `wire/table_size.zig` |
| RFC 9110 semantics core | **shared**; the *verdicts* are not | `http/` |
| Bounded slot pool with a watermark | **shared** structure; the rules are not | `core/slots.zig` |
| Corpus, fuzz and simulator harnesses | **shared** | `sim/`, `golden/` |
| Static tables | **not shared** — 61 from 1 vs 99 from 0 | `hpack/`, `qpack/` |
| Index address space | **not shared** — fused vs separate, 9204 §3 | `hpack/`, `qpack/` |
| Representations | **not shared** — different patterns, two with no analogue | `hpack/`, `qpack/` |
| Encoder/decoder streams and blocking | **not shared** — 9204 §2.2, no HPACK equivalent | `qpack/` |
| Framing | **not shared** | `h2/`, `h3/`, `quic/` |
| **Flow control** | **not shared** — credits vs offsets | `h2/`, `quic/` |
| **Stream table rules** | **not shared** — 31-bit parity vs 62-bit type bits | `h2/`, `quic/` |
| QUIC varints | h3 and QUIC only | `wire/varint.zig` |

The last three rows correct candidates that looked shared. Flow control differs most: h2 is a
credit counter with a *signed* send window and a retroactive sweep of every stream on a settings
change (RFC 9113 §6.9.2); QUIC is a non-decreasing offset limit with a final-size rule and no
sweep. Forcing them through one interface buys nothing and risks an accounting bug in both.

## 6. Wire formats colibri reads and writes

Every table below was read from the RFC text. Values are hexadecimal where the RFC writes them
that way. `(i)` marks a QUIC variable-length integer.

### 6.1 HTTP/2 framing (RFC 9113 §4.1)

The frame header is 9 bytes and is not counted in `Length`:

| Bits | Field | Notes |
|---:|---|---|
| 24 | Length | payload bytes; > 2^14 only if the peer raised `SETTINGS_MAX_FRAME_SIZE` |
| 8 | Type | unknown types are ignored and discarded, but must still be consumed; a client reads ALTSVC |
| 8 | Flags | unused flags ignored on receipt, unset on send |
| 1 | Reserved | ignored on receipt, unset on send — mask it, never reject it |
| 31 | Stream Identifier | 0x00 means the connection as a whole |

Frame types, RFC 9113 §6: `DATA` 0x00, `HEADERS` 0x01, `PRIORITY` 0x02, `RST_STREAM` 0x03,
`SETTINGS` 0x04, `PUSH_PROMISE` 0x05, `PING` 0x06, `GOAWAY` 0x07, `WINDOW_UPDATE` 0x08,
`CONTINUATION` 0x09. One extension (RFC 9113 §5.5), from step 17b: `ALTSVC` 0x0a (RFC 7838 §4),
which a server writes to advertise h3 and a client reads.

Settings, RFC 9113 §6.5.2:

| Name | Id | Initial value | colibri |
|---|---|---|---|
| `SETTINGS_HEADER_TABLE_SIZE` | 0x01 | 4096 | advertised small (§7) |
| `SETTINGS_ENABLE_PUSH` | 0x02 | 1 | sent as 0 by the client; omitted by the server |
| `SETTINGS_MAX_CONCURRENT_STREAMS` | 0x03 | unlimited | **must** be advertised, or nothing is bounded |
| `SETTINGS_INITIAL_WINDOW_SIZE` | 0x04 | 65,535 | §7 |
| `SETTINGS_MAX_FRAME_SIZE` | 0x05 | 16,384 | left at the default; the range is 2^14 to 2^24−1 |
| `SETTINGS_MAX_HEADER_LIST_SIZE` | 0x06 | unlimited | **must** be advertised |

Two of the six initial values are unlimited. An implementation that does not advertise
a concrete `SETTINGS_MAX_CONCURRENT_STREAMS` and `SETTINGS_MAX_HEADER_LIST_SIZE` in its own
preface has bounded nothing, whatever its constants file says.

Error codes, RFC 9113 §7: `NO_ERROR` 0x00, `PROTOCOL_ERROR` 0x01, `INTERNAL_ERROR` 0x02,
`FLOW_CONTROL_ERROR` 0x03, `SETTINGS_TIMEOUT` 0x04, `STREAM_CLOSED` 0x05, `FRAME_SIZE_ERROR` 0x06,
`REFUSED_STREAM` 0x07, `CANCEL` 0x08, `COMPRESSION_ERROR` 0x09, `CONNECT_ERROR` 0x0a,
`ENHANCE_YOUR_CALM` 0x0b, `INADEQUATE_SECURITY` 0x0c, `HTTP_1_1_REQUIRED` 0x0d.

The client connection preface is the 24 bytes
`50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30 0d 0a 0d 0a 53 4d 0d 0a 0d 0a` — the ASCII of
`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` — followed by a SETTINGS frame that may be empty (RFC 9113
§3.4). The server's preface is a SETTINGS frame that must be its first frame. An invalid preface
is a connection error of `PROTOCOL_ERROR` and the GOAWAY may be omitted, which lets colibri fail
closed on a peer that is not speaking h2 without writing a byte.

### 6.2 HPACK (RFC 7541)

| Representation | Pattern | Prefix | Section |
|---|---|---:|---|
| Indexed field | `1` | 7 | §6.1 |
| Literal, incremental indexing | `01` | 6 | §6.2.1 |
| Literal, without indexing | `0000` | 4 | §6.2.2 |
| Literal, never indexed | `0001` | 4 | §6.2.3 |
| Dynamic table size update | `001` | 5 | §6.3 |

Static table: 61 entries, numbered from 1 (Appendix A). Entry size is
`name_len + value_len + 32`, measured unencoded (§4.1). Index 0 in an *indexed* representation is
fatal; index 0 in a *literal* is the normal new-name discriminator; an insert larger than the
capacity is not an error, it empties the table (§4.4). Those three are the common interop breaks
and each gets a named error and a corpus case.

### 6.3 QPACK (RFC 9204)

Static table: 99 entries, numbered from 0 (Appendix A). Encoder stream is unidirectional type
0x02, decoder stream type 0x03 (§4.2). Settings:
`SETTINGS_QPACK_MAX_TABLE_CAPACITY` 0x01, default 0; `SETTINGS_QPACK_BLOCKED_STREAMS` 0x07,
default 0 (§5). Errors: `QPACK_DECOMPRESSION_FAILED` 0x0200, `QPACK_ENCODER_STREAM_ERROR` 0x0201,
`QPACK_DECODER_STREAM_ERROR` 0x0202 (§6).

Both defaults being zero matters: a colibri that advertises nothing gets a static-table-only
encoder from its peer, which is a legal and perfectly serviceable starting point. Step 11 ships
exactly that before it ships a dynamic table.

### 6.4 QUIC (RFC 8999, RFC 9000)

Variable-length integers, RFC 9000 §16 — the two most significant bits of the first byte give
the length:

| 2 MSB | Bytes | Usable bits | Range |
|---|---:|---:|---|
| `00` | 1 | 6 | 0 – 63 |
| `01` | 2 | 14 | 0 – 16,383 |
| `10` | 4 | 30 | 0 – 1,073,741,823 |
| `11` | 8 | 62 | 0 – 4,611,686,018,427,387,903 |

Minimal encoding is *not* required except for the Frame Type field (§16, pointing at §12.4). A
decoder that rejects a non-minimal varint is wrong; a frame-type reader that accepts one is also
wrong.

The version-independent layer (RFC 8999 §5) reads only: bit 0x80 of byte 0; and for a long
header, the 32-bit Version at offset 1, a DCID length byte, up to 255 DCID bytes, an SCID length
byte, up to 255 SCID bytes. RFC 8999 §5 scopes the invariants to the **first** packet in a
datagram, and the Length field that makes coalescing parseable is a version-1 field, so the
invariant layer parses one packet and stops. It must not apply RFC 9000's 20-byte connection-ID
maximum, because RFC 9000 §17.2.1 says version-specific rules must not influence whether a Version
Negotiation packet is sent. [Invariant
22](invariants.md#inv-22--a-version-independent-parse-reads-only-rfc-8999-fields)
is this rule.

Long packet types, RFC 9000 §17.2: Initial 0, 0-RTT 1, Handshake 2, Retry 3, in the two bits
masked by 0x30. Version 1 is 0x00000001 and 0x00000000 means Version Negotiation (§15, and
§17.2.1 for the Version Negotiation packet itself).

Three packet number spaces — Initial, Handshake, Application data — each with its own next number,
largest processed number, ACK ranges and ECN counters (§12.3).

### 6.5 HTTP/3 (RFC 9114)

Frames are `Type (i)`, `Length (i)`, payload — no flags field. Types, §7.2: `DATA` 0x00,
`HEADERS` 0x01, `CANCEL_PUSH` 0x03, `SETTINGS` 0x04, `PUSH_PROMISE` 0x05, `GOAWAY` 0x07,
`MAX_PUSH_ID` 0x0d.

Unidirectional stream types: control 0x00 (§6.2.1), push 0x01 (§6.2.2), plus QPACK's 0x02 and
0x03 (RFC 9204 §4.2).

One setting is defined: `SETTINGS_MAX_FIELD_SECTION_SIZE` 0x06, default **unlimited** (§7.2.4.1).
Settings are sent once and can never change — there is no ACK, no settings state machine and no
`SETTINGS_TIMEOUT`.

Error codes are the `H3_*` space from 0x0100 to 0x0110 (§8.1), of which the ones colibri produces
most are `H3_FRAME_UNEXPECTED` 0x0105, `H3_MESSAGE_ERROR` 0x010e, `H3_ID_ERROR` 0x0108 and
`H3_MISSING_SETTINGS` 0x010a.

Greasing is prescriptive rather than optional: RFC 9114 §7.2.4.1 says endpoints SHOULD send a
reserved setting, and §8.1 says they SHOULD sometimes send a reserved error code in place of
`H3_NO_ERROR`. colibri does both. It holds no generator of its own
([invariant 5](invariants.md#inv-5)):
the server's endpoint and the client's channel draw the reserved value from the source the caller
passes when a connection starts, so a seed still replays.

### 6.6 colibri's own formats

Two, and both are versioned from the first commit ([CLAUDE.md](../CLAUDE.md) non-negotiable 6),
because the wire formats are the RFCs' and cannot be versioned by us:

- **The golden manifest line**, one per corpus file, naming the file's length, checksum, expected
  verdict and the parameters it was built from. stompy's `src/golden/*/manifest.txt` is the shape.
- **The simulator trace record**, one per abstract transition, which is what the replay check
  compares byte for byte.

A trace is text, one record per line, so a failing seed prints a trace a person can read. Version
1 has this shape:

```text
colibri-sim-trace version=1 check=<check> seed=0x<16 hex digits>
<record> <key>=<value> <key>=<value> ...
end records=<count> outcome=<outcome>
```

- The first line names the version, the check and the seed. A change to what any line holds is a
  new version, never a silent edit.
- Each record between the first line and the last is a name, then fields separated by one space.
  A key is lowercase letters, digits and underscores. A value holds no space: an unsigned decimal
  integer, bytes as lowercase hexadecimal with no prefix, or a word such as an error name.
- The last line gives the count of records between the first line and itself, and how the run ended.
  A trace with no `end` line was cut short.
- The seed is the only value written in hexadecimal with a `0x` prefix, because it is the value a
  person copies into `zig build sim -- --<check>-seed <hex>`.

The records design §8 step 2 writes are the byte pipe's:

| Record | Fields | Written when |
|---|---|---|
| `feed` | `at_ns`, `len`, `held` | a chunk of the stream is fed to the caller; `held` counts the bytes the caller holds after it |
| `accept` | `offset`, `len`, then the subject's fields | the subject consumed a whole value; `offset` is its first byte in the stream |
| `reject` | `offset`, `error` | the subject refused the bytes at `offset` |

No record but `feed` carries an instant. The chunk schedule decides when a value completes, so
removing every `feed` record, and the record count from the `end` line, leaves the lines that do
not depend on the chunking. The step 2 check compares exactly those lines between a chunked run and
a run fed in one piece.

## 7. Named limits

Every one is declared in a `constants.zig` and never inline. The RFCs leave most of these to the
implementation and say so, so they are named here rather than chosen at a call
site. A limit that sizes storage sizes storage the caller owns: colibri allocates nothing
([decision 35](decisions/0035-colibri-is-zero-heap.md)), exposes each struct's size as a comptime constant, and
leaves the caller to place the struct. A count the caller sets at run time, such as a pool's TCP
connections, sizes memory through `memory_bytes(options)` (decision 35 as amended).

**Shared** (`core`): `field_name_len_max` · `field_value_len_max` · `field_count_max` ·
`field_section_size_max` · `connections_max` · `streams_per_connection_max`.

**h2** (`h2`): `frame_size_max` (16,384, the RFC 9113 §4.2 floor, and colibri does not raise it) ·
`continuation_count_max` · `concurrent_streams_max` · `window_initial` · `window_max` (2^31 − 1) ·
`settings_pending_max` · `ping_pending_max` · `rst_stream_rate_max` · `peer_reset_rate_max` ·
`settings_timeout_ns` ·
`representation_len_max` (31,721 encoded bytes: the longest field line within
`field_name_len_max`, `field_value_len_max` and `integer_len_max`, Huffman-coded at 30 bits an
byte, so it refuses no line those limits admit) · `field_block_buffer_len` (one cut representation
plus one frame, decision 40) · `send_block_len_max` (two frames' worth of field block colibri
sends, cut into a HEADERS frame and the CONTINUATION frames it needs) · `settings_ack_pending_max`
· `ping_ack_pending_max` · `stream_replies_max` (the reply queues of decision 39: a full queue
stops the reading, and no reply is ever dropped; a RST_STREAM the caller asks for takes no slot,
because the stream's record owes it, decision 113).

**wire** (`wire`): `varint_value_max` (2^62 − 1, RFC 9000 §16) · `integer_value_max` (2^62 − 1, the
62 bits RFC 9204 §4.1.1 requires) · `integer_len_max` (10 bytes, the length those 62 bits need
past a 1-bit prefix) · `huffman_padding_bits_max` (7, RFC 7541 §5.2).

**HPACK / QPACK** (`hpack`, `qpack`): `dynamic_table_capacity_max` (4,096, ruled 2026-11-18; 16,384
from 2026-09-16) · `dynamic_table_entries_max` (the capacity over the 32-byte overhead) ·
`size_updates_per_block_max` (2, RFC 7541 §4.2) · `blocked_streams_max` ·
`encoder_instruction_len_max` · `decoder_instructions_owed_max` (the last three decision 74's).
Huffman data expands by up to 1.6x, since the shortest code is 5 bits, and
`wire.huffman.decoded_len_max` is that bound; a literal's decoded length is capped by `core`'s
field-length limits (RFC 7541 §7.4).

**QUIC** (`quic`): `datagram_size_max` · `datagram_size_min` (1200) · `ack_ranges_max` ·
`crypto_buffer_bytes_max` · `connection_ids_active_max` (at least 2; the default is 2) ·
`connection_ids_retire_pending_max` · `sent_packets_max` (per packet number space, three tables) ·
`paths_probing_max` · `token_len_max` · `reason_phrase_len_max` · `idle_timeout_ns` ·
`pto_backoff_max`.

**h3** (`h3`): `uni_streams_max` · `push_ids_max` (0 — colibri never sends `MAX_PUSH_ID`) ·
`frame_length_max`.

Four of these exist only because an RFC declines to bound something and leaves it to the
implementation: `ack_ranges_max` (RFC 9000 §13.2.3, "limits the number ... to avoid resource
exhaustion", no maximum given), `crypto_buffer_bytes_max` (§7.5 — CRYPTO data is not flow
controlled and a peer could force unbounded buffering; the defence is this constant plus
`CRYPTO_BUFFER_EXCEEDED` 0x0d), `continuation_count_max` (RFC 9113 §6.10 sets no cap), and
`field_section_size_max` (RFC 9110 §5.4 says no predefined limits exist, and RFC 9113 §10.5.1 says
there is no hard limit on field block size). Each is a named limit because the RFC does
not name one.

## 8. Build plan

Each step names the check that proves it. **A step with no check is not a step.** Reading the RFC is
not evidence. Every step that adds a check reports its mutations as `CAUGHT` or `NOT CAUGHT`, and
a `NOT CAUGHT` blocks the step.

Sizes are the owner's estimate of effort, given for planning and not as a commitment.

| Step | Title |
| --- | --- |
| <a id="step-0"></a>[0](design/steps/step-0.md) | Step 0 — scaffolding. |
| <a id="step-1"></a>[1](design/steps/step-1.md) | Step 1 — `wire` and `http`. |
| <a id="step-2"></a>[2](design/steps/step-2.md) | Step 2 — the deterministic driver. |
| <a id="step-3"></a>[3](design/steps/step-3.md) | Step 3 — HPACK. |
| <a id="step-4"></a>[4](design/steps/step-4.md) | Step 4 — h2 connection and streams, cleartext, prior knowledge. |
| <a id="step-5"></a>[5](design/steps/step-5.md) | Step 5 — the TLS provider vtable and h2 over TLS. |
| <a id="step-6"></a>[6](design/steps/step-6.md) | Step 6 — the counted-cost check. |
| <a id="step-7"></a>[7](design/steps/step-7.md) | Step 7 — QUIC packet formats and the crypto vtable. |
| <a id="step-8"></a>[8](design/steps/step-8.md) | Step 8 — the QUIC simulator. |
| <a id="step-9"></a>[9](design/steps/step-9.md) | Step 9 — QUIC transport, cut into five. |
| <a id="step-9a"></a>[9a](design/steps/step-9a.md) | Step 9a — the frame layer. |
| <a id="step-9b"></a>[9b](design/steps/step-9b.md) | Step 9b — packet number spaces, acknowledgments, and how a connection ends. |
| <a id="step-9c"></a>[9c](design/steps/step-9c.md) | Step 9c — streams and flow control. |
| <a id="step-9d"></a>[9d](design/steps/step-9d.md) | Step 9d — connection IDs, path validation and anti-amplification. |
| <a id="step-9e"></a>[9e](design/steps/step-9e.md) | Step 9e — the handshake over CRYPTO frames, and the interop runner. |
| <a id="step-10"></a>[10](design/steps/step-10.md) | Step 10 — loss recovery and congestion control. |
| <a id="step-11"></a>[11](design/steps/step-11.md) | Step 11 — QPACK. |
| <a id="step-12"></a>[12](design/steps/step-12.md) | Step 12 — h3. |
| <a id="step-13"></a>[13](design/steps/step-13.md) | Step 13 — `bench/`. |
| <a id="step-14"></a>[14](design/steps/step-14.md) | Step 14 — stdx's decoders, taken as a package. |
| <a id="step-15"></a>[15](design/steps/step-15.md) | Step 15 — h11. |
| <a id="step-15a"></a>[15a](design/steps/step-15a.md) | Step 15a — the message parsers and writers. |
| <a id="step-15b"></a>[15b](design/steps/step-15b.md) | Step 15b — the connection. |
| <a id="step-15c"></a>[15c](design/steps/step-15c.md) | Step 15c — the `gzip` and `deflate` codings. |
| <a id="step-15d"></a>[15d](design/steps/step-15d.md) | Step 15d — the endpoints and conformance. |
| <a id="step-16"></a>[16](design/steps/step-16.md) | Step 16 — chapulin in the library. |
| <a id="step-17"></a>[17](design/steps/step-17.md) | Step 17 — the version-choosing client and server. |
| <a id="step-18"></a>[18](design/steps/step-18.md) | Step 18 — qlog. |
| <a id="step-19"></a>[19](design/steps/step-19.md) | Step 19 — QUIC version 2. |
| <a id="step-20"></a>[20](design/steps/step-20.md) | Step 20 — denial of service at the server. |
| <a id="step-21"></a>[21](design/steps/step-21.md) | Step 21 — one HTTP API. |
| <a id="step-22"></a>[22](design/steps/step-22.md) | Step 22 — the client's connection pool. |
| <a id="step-23"></a>[23](design/steps/step-23.md) | Step 23 — colibri's own names for HTTP. |
| <a id="step-24"></a>[24](design/steps/step-24.md) | Step 24 — a request's query. |
| <a id="step-25"></a>[25](design/steps/step-25.md) | Step 25 — a route table that calls the program's functions. |
| <a id="step-26"></a>[26](design/steps/step-26.md) | Step 26 — several STREAM frames in a packet. |
| <a id="step-27"></a>[27](design/steps/step-27.md) | Step 27 — CUBIC. |
| <a id="step-28"></a>[28](design/steps/step-28.md) | Step 28 — HyStart++. |
| <a id="step-29"></a>[29](design/steps/step-29.md) | Step 29 — BBRv3. |
| <a id="step-30"></a>[30](design/steps/step-30.md) | Step 30 — constants by who sets them. |

Steps 0 to 6 are h2 and deliver a shippable library. Steps 7 to 12 are h3, and step 13 benchmarks
both. Steps 14 and 15 are h11: the decoder package first, because h11 imports it. Step 6 exists
where it does on purpose: the cheap regression check is in place before the larger half begins.
Step 16 moves chapulin, which the checks from step 5 on linked in `src/testing/`, into the
library.

| Step | Title |
| --- | --- |
| <a id="step-31"></a>[31](design/steps/step-31.md) | Step 31 — DNSSEC's signature checks, the `dnssec` module. |
| <a id="step-32"></a>[32](design/steps/step-32.md) | Step 32 — the h11 client's bounded drop. |
| <a id="step-33"></a>[33](design/steps/step-33.md) | Step 33 — CNSA 2.0 on the server. |
| <a id="step-34"></a>[34](design/steps/step-34.md) | Step 34 — NewReno beside CUBIC and BBRv3. |
| <a id="step-35"></a>[35](design/steps/step-35.md) | Step 35 — Careful Resume (RFC 9959), proposed 2026-11-04. |
| <a id="step-36"></a>[36](design/steps/step-36.md) | Step 36 — JSON in the server, proposed 2026-11-04. |
| <a id="step-37"></a>[37](design/steps/step-37.md) | Step 37 — the `colibri` module, proposed 2026-11-04. |
| <a id="step-38"></a>[38](design/steps/step-38.md) | Step 38 — response headers and trailers in the client, proposed 2026-11-05. |
| <a id="step-39"></a>[39](design/steps/step-39.md) | Step 39 — streamed bodies in the pool, proposed 2026-11-05. |
| <a id="step-40"></a>[40](design/steps/step-40.md) | Step 40 — DPLPMTUD, proposed 2026-11-05. |
| <a id="step-41"></a>[41](design/steps/step-41.md) | Step 41 — body readers and writers, proposed 2026-11-05. |
| <a id="step-42"></a>[42](design/steps/step-42.md) | Step 42 — `colibri.Client`, proposed 2026-11-05. |
| <a id="step-43"></a>[43](design/steps/step-43.md) | Step 43 — a protocol preference in the client, proposed 2026-11-05. |
| <a id="step-44"></a>[44](design/steps/step-44.md) | Step 44 — colibri on a loop that the program hosts, proposed 2026-11-06, planned again 2026-11-08. |
| <a id="step-45"></a>[45](design/steps/step-45.md) | Step 45 — colibri's public API in Zig's idioms, proposed 2026-11-07. |
| <a id="step-46"></a>[46](design/steps/step-46.md) | Step 46 — long server streams through the router, proposed 2026-11-09. |
| <a id="step-47"></a>[47](design/steps/step-47.md) | Step 47 — the h11 server reads the rest of a body, or closes in stages, ruled 2026-11-09. |
| <a id="step-48"></a>[48](design/steps/step-48.md) | Step 48 — session tickets in colibri's servers and client, ruled 2026-11-10 and 2026-11-11. |
| <a id="step-49"></a>[49](design/steps/step-49.md) | Step 49 — chapulin v0.6.0, and a server that changes its ticket key, ruled 2026-11-11. |
| <a id="step-50"></a>[50](design/steps/step-50.md) | Step 50 — the router's handlers: a request's context, whole requests and streams, ruled 2026-11-11 and 2026-11-12. |
| <a id="step-51"></a>[51](design/steps/step-51.md) | Step 51 — the constructors take std's name `init`, ruled 2026-11-13. |
| <a id="step-52"></a>[52](design/steps/step-52.md) | Step 52 — line coverage, ruled 2026-11-15. |
| <a id="step-53"></a>[53](design/steps/step-53.md) | Step 53 — an answer with no entry waits for room, 2026-11-16. |
| <a id="step-54"></a>[54](design/steps/step-54.md) | Step 54 — the router's branch quota on a table of many routes, 2026-11-17. |
| <a id="step-55"></a>[55](design/steps/step-55.md) | Step 55 — no byte-loop copy in the library, 2026-11-17. |
| <a id="step-56"></a>[56](design/steps/step-56.md) | Step 56 — the engine's empty polls on h11, 2026-11-17. |
| <a id="step-57"></a>[57](design/steps/step-57.md) | Step 57 — no poll after a read that changed nothing, refused, 2026-11-17. |
| <a id="step-58"></a>[58](design/steps/step-58.md) | Step 58 — no copies of the server's events, planned 2026-11-17. |
| <a id="step-59"></a>[59](design/steps/step-59.md) | Step 59 — fewer deadline checks on a TCP connection, planned 2026-11-18. |
| <a id="step-60"></a>[60](design/steps/step-60.md) | Step 60 — one input and one output buffer in each TCP socket, 2026-11-18. |
| <a id="step-61"></a>[61](design/steps/step-61.md) | Step 61 — h2's field blocks where they lie, 2026-11-18. |
| <a id="step-62"></a>[62](design/steps/step-62.md) | Step 62 — colibri sizes a TCP connection to what it uses, 2026-11-18. |
| <a id="step-63"></a>[63](design/steps/step-63.md) | Step 63 — a TLS server session holds no trust anchors, 2026-11-18. |
| <a id="step-64"></a>[64](design/steps/step-64.md) | Step 64 — a TCP connection holds a TLS session only over TLS, 2026-11-19. |
| <a id="step-65"></a>[65](design/steps/step-65.md) | Step 65 — an output of one HEADERS and one DATA frame, refused, 2026-11-19. |
| <a id="step-66"></a>[66](design/steps/step-66.md) | Step 66 — MAX_STREAMS rides in a packet that goes anyway, 2026-11-19. |
| <a id="step-67"></a>[67](design/steps/step-67.md) | Step 67 — an encoder starts in place, with no fill, 2026-11-19. |
| <a id="step-68"></a>[68](design/steps/step-68.md) | Step 68 — stdx v0.2.0, 2026-11-19. |
| <a id="step-69"></a>[69](design/steps/step-69.md) | Step 69 — an h11 decoder starts in place, with no fill, 2026-11-19. |
| <a id="step-70"></a>[70](design/steps/step-70.md) | Step 70 — a router starts in place, 2026-11-23. |
| <a id="step-71"></a>[71](design/steps/step-71.md) | Step 71 — a server keeps 1-RTT packets that arrive early, 2026-11-23. |
| <a id="step-72"></a>[72](design/steps/step-72.md) | Step 72 — a configuration states the CPU features, and a pool none, 2026-11-24. |
| <a id="step-73"></a>[73](design/steps/step-73.md) | Step 73 — the package exports `colibri` alone, 2026-11-25. |
| <a id="step-74"></a>[74](design/steps/step-74.md) | Step 74 — colibri takes stdx's one module, 2026-11-25 |
| <a id="step-75"></a>[75](design/steps/step-75.md) | Step 75 — colibri asks chapulin once, 2026-11-25 |
| <a id="step-76"></a>[76](design/steps/step-76.md) | Step 76 — a server's UDP socket shares its port, 2026-11-25 |
| <a id="step-77"></a>[77](design/steps/step-77.md) | Step 77 — colibri takes chapulin through stdx, 2026-11-25 |
| <a id="step-78"></a>[78](design/steps/step-78.md) | Step 78 — colibri takes the program's `stdx.crypto.Context` once, 2026-11-26 |
| <a id="step-79"></a>[79](design/steps/step-79.md) | Step 79 — a TCP socket sends from its connection's output, 2026-11-26 |

## 9. Test-only entry points

Four, and they are not interchangeable. Each lives in `src/testing/`, is excluded from the
packaged library, does its I/O without blocking ([decisions 46 and 58](decisions/0046-every-endpoint-in-srctesting-does-its.md)), and is the
only place in the tree permitted to touch a socket
([invariant 2](invariants.md#inv-2) is scoped to `src/` outside it).

1. **A server**, `http-server`, answering `GET /` and `POST /` with 200 and a non-empty body,
   of the bytes `--body` names when it is given (design §8 step 13n),
   and CONNECT with 501, since it opens no tunnel (decision 109), in both cleartext and TLS
   modes, and **a client**, `http-client`, that runs a plan of
   exchanges against another implementation's server and reports how each ended. For h2spec,
   h2load and `tools/h2_interop.sh`. They landed as `h2-server` and `h2-client` with step 4
   (cleartext) and step 5 (TLS), and the owner renamed them on 2026-09-25, when step 15d gave
   them h11 as well. Each connection of a client's run is a TCP connection of a `client.ConnectionPool`,
   which asks for its socket and for another when an exchange moves (steps 21c and 22). In cleartext the client
   speaks h2 with prior knowledge, or h11 with `--h11`. The server in cleartext names no version
   and speaks h2 when a connection's first bytes are h2's preface and h11 otherwise (decision
   117, step 21a), or one alone with `--h11` or `--h2`. Over TLS, both offer `h2` and then
   `http/1.1` through ALPN, or one alone with `--h11` and, for the server, `--h2`, and each
   connection speaks what the handshake selected: h2 for `h2`, and h11 for `http/1.1` or for no
   selection (decision 88). With `--pool` and `--tls` the client hands its plan to one
   `client.ConnectionPool` that adds QUIC, which tries h3 over QUIC first and falls back to TCP
   (steps 17d and 22), and `tools/pool_interop.sh` runs it.
2. **A QUIC and h3 server** with ALPN `h3` and a self-signed certificate. For h3spec and
   `h2load --h3`. Lands with step 12. From step 17b it runs on `server`: the UDP endpoint's `h3`
   mode serves h3 alone through `server.Engine`, and h3spec, `h2load --h3` and the interop
   endpoint's `http3` server run it. With `qlogdir` it writes each connection's qlog through the
   engine's log provider.
3. **An interop endpoint**, both roles: a server on port 443 serving `/www` with `/certs`, and a
   client that parses `REQUESTS` and writes to `/downloads`, reading `ROLE` and `TESTCASE`,
   emitting a keylog and qlog, and **exiting 127 for any case it does not support**. It must speak
   HTTP/0.9 over ALPN `hq-interop` as well as h3, because most of the matrix's transfers use it.
   Lands with step 9.
4. **Two QPACK command-line tools**, `.qif` to encoded and back, to take part in the QIF interop.
   Lands with step 11.

The HPACK and frame vectors need none of these; they are in-process unit tests.

Each server among them takes the port its caller names. With port 0 it takes the one the kernel
chooses, and it prints `listening on port <port>` once its socket is bound. The check scripts
start every peer that way and read the port from that line, so no check binds a fixed port, and
two runs on one machine do not collide ([decision 114](decisions/0114-no-check-toolscish-runs-binds-a.md),
[#94](https://github.com/c4milo/colibri/issues/94)).

**Checked on macOS 26.6.2 arm64 on 2026-10-03:**
- The fourteen network checks ran at once in two worktrees: the port helper's check, h2spec, the
  four interop scripts, the deadline check, the two TLS checks, the QUIC loopback, h3spec, the
  two UDP scripts and the channel check. Every check passed in both worktrees, in each of two
  rounds.
- The first run of that kind failed one check in one worktree: the port helper read a log its
  peer's shell had not created yet, and exited with no message. It now waits for the log, and
  `tools/listening_port_check.sh` checks it.
- Docker Desktop's host port refused the first connection in 17 of 30 container starts, for up
  to 0.15 s. So a container's script waits for the host port after the peer's own socket.
- Mutations: 12, each CAUGHT:
  - every worker of the test server binding port 0, with its assertion and without;
  - a peer printing a port it did not bind: the test server, `tls-accept`, the three Go peers
    and the two Python peers;
  - the helper reading no port, and reading a log that does not exist yet;
  - no wait for the host port, in 3 runs of 3.
- `zig build test` passed: 2539 of 2539 tests.

## 10. Determinism and the simulator

The simulator replaces the caller — the bytes, the instants, the TLS provider and the crypto suite
— with deterministic implementations driven by one seed. A run is a schedule of chunk boundaries,
delays, drops, reorderings and, for QUIC, duplications and ECN markings. The same seed replays
exactly, so a failure found on seed `0xC0FFEE` is a failure that can be debugged.

Assertions run inside the simulated connection continuously, not at the end. A violated assertion
halts the run with the seed and the byte offset that produced it.

Two things make this possible, and both are decisions rather than conveniences. colibri owns no
I/O and no clock, so there is nothing to stub — the simulator is the caller, using the same API a
real caller uses, with nothing conditionally compiled. And crypto is a vtable, so the QUIC
simulator can exist before the QUIC handshake does.

Be exact about what the null crypto suite buys, because the obvious claim is wrong. It is **not**
what makes a seed replay: AES-GCM and ChaCha20-Poly1305 are pure functions of key, nonce and
plaintext, so a real suite replays just as deterministically. What it buys is a harness with no
crypto dependency and no cipher time. It must therefore be **size-faithful rather than an identity
function** — appending a 16-byte tag, and masking byte 0 and the packet number from a 16-byte
sample, exactly as a real suite would — because RFC 9001 §5.3's expansion feeds §5.4.2's sample
offset, the packet's Length varint, RFC
9000 §14.1's 1200-byte minimum and the anti-amplification count of
[invariant 18](invariants.md#inv-18). A suite that shortened
packets would simulate a protocol QUIC does not have.

The simulator is written before the protocol it drives. For QUIC that ordering is the whole
difficulty, and steps 2 and 8 are where it is paid for.

## 11. Performance

### 11.1 The workload

Many short connections, small requests, high connection churn — one connection per agent process,
a little work, then gone. Handshake cost and per-connection memory dominate; single-stream bulk
throughput does not. [Decision 31](decisions/0031-the-workload-colibri-intends-to-win.md) states where colibri expects to win,
where it expects only to match, and where it expects to lose, and all three get reported.

### 11.2 Metrics

Requests per second at fixed concurrency; p50, p99 and p99.9 latency; handshakes per second;
single-stream and many-stream throughput; instructions and cycles per request and per connection
from `perf stat`, with instructions per connection as the **primary** metric because it is the
most reproducible counter across machines and frequencies; syscalls per request; bytes on the wire,
which is the field-compression ratio; and static memory per connection, which is a comptime number
measured the way chapulin's `bench/sram.sh` measures its SRAM rows and never estimated.

### 11.3 Competitors, on the same machine in the same run

h2load from nghttp2 for h2, and for h3 when built against ngtcp2 and nghttp3 — which stock
packages are not, so the build is part of the bench. `secnetperf` from msquic for QUIC throughput.
quiche and quic-go for h3. h2o and nginx as the h2 server bar, and for h11 too. hyper, the Rust
server most Rust programs build on, for h11 and h2, and http.zig, a Zig server, for h11 in
cleartext (step 13g). wrk sends the h11 inputs, since h2load counts no answer whose reason phrase
is empty, as http.zig's is. aioquic is a correctness reference and not a performance target.

### 11.4 Method

[Decision 33](decisions/0033-the-method-is-fixed-before-the.md) fixes it before the first measurement so the numbers
cannot be shaped afterwards: Linux for every real number, warmup discarded, at least five runs
reported as median with spread and never a best-of, the A/B in the same session on the same
kernel, and the machine written down beside the numbers. As amended on 2026-09-30, the judge is
GitHub's `ubuntu-24.04-arm` runner, a Neoverse N2, under pepegrillo's method: instructions per
unit from `perf stat` are the primary metric, the base and the change are measured in turns in one
job with cores pinned, and a change stays only when it wins past the noise in at least two such
jobs. The runner fixes no governor, so a time is never compared across jobs. Anything under about
5% is noise until the judge's own floor, measured and recorded in `docs/performance.md`, says
otherwise.

### 11.5 What must hold

Two layers. The cheap layer is step 6's counted costs in the simulator — exact numbers a diff must
change on purpose — and it runs in `zig build test`. The expensive layer is `bench/run.sh`, which
`.github/workflows/bench.yml` runs on the judge when a person asks, with a base to compare against:
the job fails when an input loses past the floor, and a person runs it before a step is called done.
[Decision 47](decisions/0047-every-check-runs-on-each-push.md) runs the cheap layer on each push to main and prints an h2load figure
beside it, which is indicative and carries no threshold: the push job's x86-64 runner counts no
instructions and draws a different CPU from run to run.

## 12. Ruled questions

The owner ruled each question below in September 2026, and each ruling is a decision. Open
questions are [GitHub issues](https://github.com/c4milo/colibri/issues).

1. **QUIC as a module or its own repository** ([decision 3](decisions/0003-quic-is-a-module-inside-colibri.md)).
   Ruled 2026-09-16: a module with a mechanically enforced boundary, which step 0 built and proved.
2. **The packet-protection vtable** ([decision 9](decisions/0009-packet-protection-is-a-second-caller.md)). Ruled
   2026-09-16: two vtables, `tls.Provider` and `crypto.Suite`. Ruled again 2026-09-19
   ([decision 48](decisions/0048-the-suite-holds-every-key-and.md)): the two vtables stay, the suite holds
   every key, and its members seal and open whole packets. Step 7 builds against that.
3. **The ask to chapulin** ([decision 10](decisions/0010-chapulin-provides-all-of-colibris-crypto.md)). Ruled 2026-09-16:
   chapulin provides all of colibri's crypto by filling both vtables, and `src/testing/` links it.
   The request is [docs/chapulin.md](chapulin.md), and sending it is the owner's.
4. **RFC 9002's one internal disagreement**, which step 10 must settle in writing and pin with a
   test. Its §5.3 updates `smoothed_rtt` first and then computes `rttvar` against the new value,
   while its Appendix A.7 computes `rttvar` first against the old value. These produce different
   numbers on every sample. It is not a bug in the RFC; it is a place where an implementation must
   choose, and interop will show which choice the field made.

   **Ruled 2026-09-20: Appendix A.7** ([decision 50](decisions/0050-where-rfc-9002-disagrees-with-itself.md)). §5.3's new
   term is always exactly seven eighths of Appendix A.7's, so §5.3's variation settles an eighth
   lower and its Probe Timeout with it. The appendix is the executable text and the more
   conservative of the two; `src/quic/rtt.zig` implements it and its tests compute both orderings
   and pin the factor.

   The PTO composition looked like a second disagreement and is not one, which is worth recording
   so nobody re-opens it: §6.2.1 sets `max_ack_delay` to 0 for the Initial and Handshake spaces,
   and Appendix A.8 adds `max_ack_delay * (2 ^ pto_count)` only in the Application Data arm. The
   two texts agree.
5. **Whether step 9 stays one step.** It is estimated very large and almost certainly wants
   splitting once its shape is real. Splitting it before writing any of it would be guessing.

   **Ruled 2026-09-19: cut into five.** The frame layer landed at about 1,070 lines with its
   tests and needed no key, no handshake and no connection state, which showed where the
   dependencies already cut. §8 now carries **9a** the frame layer, **9b** the packet number
   spaces with acknowledgments and the states a connection ends in, **9c** streams and flow
   control, **9d** connection IDs, path validation and anti-amplification, and **9e** the
   handshake over CRYPTO frames with the interop runner. Only 9e waits on chapulin, so four
   fifths of the largest step can be built without it.

6. **Whether h2 and h3 share their message validation, and how.** Step 12's check says the h2
   suite's semantics tests are re-run against h3, "which proves the `http` module is shared
   rather than duplicated". Writing h3's framing made the shape of that question concrete and it
   needs the owner before any h3 message code is written.

   **Ruled 2026-09-20: share through `http`** ([decision 51](decisions/0051-h2-and-h3-share-their-message.md)). The shared checks
   move into `http` and return a reason; each protocol maps it to its own error. A shared check
   cites both RFCs, because both state the rule. Four rules stay per protocol, because they
   differ in what they accept: `:authority` against `Host`, a repeated pseudo-header name, an
   informational response with END_STREAM, and `:protocol` from RFC 8441.

   RFC 9114 §4.1 to §4.3 restates most of RFC 9113 §8: the pseudo-header rules, the field name
   and value rules, the connection-specific field ban, the CONNECT rules. What differs is which
   RFC section states each rule and which error code a violation carries — PROTOCOL_ERROR for h2
   (§8.1.1), H3_MESSAGE_ERROR for h3 (§4.1.2). h2's implementation is 1,224 lines across
   `src/h2/message/`, heavily tested and fuzzed.

   Three ways to go, and the third is the recommendation:

   - **Duplicate it in `src/h3/message/`.** Fastest, and exactly the duplication step 12's check
     exists to refuse. The two copies would drift the first time an erratum moved one.
   - **Have h3 call h2's.** Cheapest in lines and wrong in the graph: it would add an `h3` to
     `h2` edge, which design §3 does not have and which would make h3 depend on h2's error names.
   - **Lift the shared rules into `http`, leaving each protocol to name its own errors.** That is
     what [decision 15](decisions/0015-the-semantics-core-is-shared-the.md) already says the split is — "`http` returns reasons and
     this file names h2's errors" — so this is finishing that split rather than changing it. The
     cost is a refactor of working, fuzzed h2 code, and the risk is that a rule that looked
     shared turns out to differ in a way the reasons cannot carry.

   It is the owner's because it moves tested h2 code for h3's benefit, which is the one direction
   CLAUDE.md's rule about taking a decision for another module's sake is meant to catch.

## 13. Risks

- **Risk: the size of step 9.** QUIC transport is the largest single body of work and every later
  step depends on it. The mitigation is that steps 0 to 6 deliver a complete, shippable h2 library
  first, so a QUIC schedule overrun costs h3 and nothing else. It was cut into 9a to 9e on
  2026-09-19 (§12 question 5), which makes the overrun visible part by part rather than at the
  end. Step 9 is built.
- **The conformance suites are older than the RFCs they test.** h2spec is written against RFC 7540
  and 7541 and last released in 2020. A disagreement is checked against RFC 9113 before it is
  treated as colibri's bug, and the version is pinned so the answer does not move.
- **The QPACK vectors are stale.** `qpackers/qifs` targets draft-05 and has not moved since 2021.
  RFC 9204 Appendix B is the authority where they disagree.
- **CI runs what a hosted runner can.** [Decision 47](decisions/0047-every-check-runs-on-each-push.md) runs the checks on each push
  to main and leaves a report, runs the module tests on Linux and macOS arm64 too, and runs the
  HTTP Garden and the QUIC Interop Runner every Monday.
  What needs a machine it does not have — the published numbers of §11 — is still run by a
  person, and the step's entry in §8 records what was run, on what, and what it printed.
- **colibri's crypto moves with stdx.** colibri reads chapulin as `stdx.crypto`
  ([decision 174](decisions/0174-colibri-takes-chapulin-through-stdx-as.md)), so a fix in chapulin reaches colibri only through a
  stdx commit that pins it, and a colibri commit that pins that stdx. The mitigation is that stdx's
  CI runs before colibri takes a bump, and colibri's TLS checks run against Go, OpenSSL, curl and
  aioquic on every push.
- **The development machine is not the measurement machine.** Every real number needs Linux.
  A macOS-only development loop can hide a regression that only a kernel mechanism would show.
