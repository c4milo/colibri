# colibri — HTTP/2 and HTTP/3 Design Document

Status: v1 (design, pre-implementation). Owner: Camilo. Scope: the library, both protocols, both
roles. Sibling to [decisions.md](decisions.md) and [invariants.md](invariants.md); decisions there
are taken as given and cited, not relitigated.

Every section is cited by number in commits and comments ("§8 step 4").

---

## 1. Thesis and scope

colibri is an HTTP/1.1, HTTP/2 and HTTP/3 library, client and server, written from the RFCs. It owns
no I/O, no crypto and no clock: bytes, keys and time all arrive from the caller. What it owns is the
part that is hard to get right and easy to get wrong — framing, field compression, stream state,
flow control, loss recovery — and it owns it with no heap, bounded loops and assertions that stay on
in production.

The narrowness is the point. A library that owns no sockets can be driven by a deterministic
simulator, replayed from a seed, and embedded in a runtime whose I/O model it never heard of.
stompy is the first consumer and will vendor colibri the way it vendors chapulin; colibri never
depends on stompy and never names it in source.

**Deliberately excluded:** caching, server push, priority scheduling, extended CONNECT, 0-RTT,
active connection migration, QUIC datagrams and multipath. [Decisions 16 to 23](decisions.md)
give each one a reason and state what saying no still costs on the wire. HTTP/1.1 was excluded
too, until [decision 88](decisions.md) amended decision 2 to build it as h11.

## 2. What the two protocols actually are

It is worth stating the shape plainly before the module graph, because the module graph follows
from it.

**h2** is one TCP connection carrying 9-octet-framed messages, with its own stream multiplexing,
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
[decision 3](decisions.md#scope-and-shape) puts it in a module that knows nothing about HTTP.

## 3. Module graph

A module can import only what `build.zig` gives it, so the direction below is enforced by the
build and not by review. An arrow reads "imports".

```text
core   <- wire   <- hpack <- h2
                 <- qpack <- h3
core   <- http   <- h2, h3, h11
core   <- tls_provider <- h2, h11, quic, tls
chapulin <- tls, tls_keylog, testing_quic, testing_udp
stdx   <- h11, sim_run, client, server
core   <- crypto <- quic, tls
stdx   <- qlog   <- quic, h3
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
testdata <- tls_keylog, sim_run, and the roots the tests of tls, server and client compile from
```

| Module | Holds | Imports | RFCs |
|---|---|---|---|
| `core` | limits, assertions, the bounded reader and writer, the slot pool | nothing | — |
| `wire` | varint, prefixed integer, Huffman, string literal | `core` | 9000 §16, 7541 §5.1, §5.2, App. B |
| `http` | the version-independent semantics core | `core` | 9110 |
| `tls_provider` | the TLS provider vtable, which `tls` and the simulator fill ([decision 97](decisions.md)) | `core` | 9846, 7301, 9001 §4 |
| `crypto` | the packet-protection vtable, no production implementation | `core` | 9001 §5 |
| `hpack` | HPACK | `core`, `wire`, `http` | 7541 |
| `qpack` | QPACK | `core`, `wire`, `http` | 9204 |
| `qlog` | a log in the caller's buffer as JSON Text Sequences, and the QUIC and HTTP/3 event records `quic` and `h3` fill ([decision 102](decisions.md)) | stdx's `json` and `codec` ([decision 102](decisions.md) as amended) | 7464, 8259, and the qlog drafts of `docs/rfcs/qlog/` |
| `quic` | the transport: packets, frames, streams, recovery | `core`, `wire`, `crypto`, `tls_provider`, `qlog` | 8999, 9000, 9001, 9002 |
| `h2` | HTTP/2 | `core`, `wire`, `http`, `hpack`, `tls_provider` | 9113 |
| `h3` | HTTP/3 | `core`, `wire`, `http`, `qpack`, `quic`, `qlog` | 9114 |
| `h11` | HTTP/1.1 ([decision 88](decisions.md)) | `core`, `http`, `tls_provider`, and stdx's decoders of the `gzip` and `deflate` codings ([decision 90](decisions.md)) | 9112 |
| `tls` | TLS 1.3 over chapulin: colibri's values, converted once per chapulin object; record-mode sessions behind `tls_provider.Provider`; and QUIC sessions behind `tls_provider.QuicProvider` and `crypto.Suite` ([decisions 94 and 97](decisions.md)) | `tls_provider`, `crypto`, and chapulin's TCP and QUIC objects, built `KEYLOG=off` | 9846, 7301, 9001 |
| `client` | HTTP requests over whichever of h3, h2 and h11 the connection negotiates: it drives the TLS handshake over TCP or QUIC and chooses the transport from the values its caller passes ([decision 100](decisions.md)) | `core`, `http`, `h11`, `h2`, `h3`, `quic`, `tls`, and stdx's decoders of the content codings ([decision 101](decisions.md)) | 9110, 9112, 9113, 9114, 7838, 9460 |
| `server` | HTTP responses behind the same calls for h11, h2 and h3, the version chosen by transport and ALPN ([decision 100](decisions.md)) | `core`, `http`, `h11`, `h2`, `h3`, `quic`, `tls`, and stdx's encoders of the content codings ([decision 101](decisions.md)) | 9110, 9112, 9113, 9114, 7838 |
| `tls_keylog` | `tls` again over objects built `KEYLOG=on`: for the tests that seal a peer's records under the secrets chapulin logs, and for the QUIC endpoints of §9, which write them to SSLKEYLOGFILE; test-only | `tls_provider`, `crypto`, chapulin's TCP and QUIC objects built `KEYLOG=on`, and `testdata` for its tests | — |
| `testdata` | the test identity the handshake tests of `tls`, `tls_keylog`, `server` and `client` and the client trace run read: a CA, a leaf for `localhost` and the leaf's key pair, valid from 2026-01-01 to 2126-01-01 and made once with openssl (`src/testing/testdata/README.md`). One copy serves them all, because `@embedFile` reads only inside the directory of the module that calls it. Test-only: the tests of `tls`, `server` and `client` compile from roots of their own that import it (`build/modules_test_roots.zig`). No packaged module imports it, and only colibri's own build makes it, so a project that depends on colibri never reaches its private key (the owner's ruling of 2026-09-28) | nothing | — |
| `sim` | deterministic clock, byte pipe, datagram network, null providers | `core`, `tls_provider`, `crypto` | — |
| `sim_run` | the checks of §8 run over `sim`, and the `zig build sim` command line | `core`, `wire`, `sim`, then each module a check drives: `h2` at step 4, `qpack` at step 11, `h3` and `quic` at step 12, `h11` at step 15a, stdx's `gzip` and `zlib` encoders at step 15c, which code the bodies the h11 coding check sends (the owner's ruling of 2026-09-26), and `client` and `tls` at step 17d, whose client trace run drives the client's connections over chapulin (decision 105, the owner's ruling of 2026-09-28), with `testdata` for the identity its servers present, and `server` at step 17e, whose content-coding check runs the client against it (the owner's ruling of 2026-09-29) | — |
| `sim_run_quic` | the QUIC checks of §8 run over `sim`, from step 7 on | `core`, `sim`, `quic`, and no HTTP module | — |
| `golden` | the byte-exact corpus and its manifest | what it checks | — |
| `testing` | the test-only endpoints of §9, and the only socket in the tree | `core`, then each module an endpoint serves, `tls` for its TLS mode, `server`, which its h11 and h2 server runs on from step 17a, and `rotor` ([decision 83](decisions.md)) | — |
| `testing_client` | the same directory under a second root, because an executable has one `main`: the h2 client of §9 | what `testing` imports | — |
| `testing_tls`, `testing_tls_server` | the two one-connection TLS checks of §8 step 5, a root each for its `main` | `core`, `h2` for the shared constants, `tls_provider` and `tls` | — |
| `testing_qif` | the two QPACK command-line tools of §9, `.qif` to encoded and back | `core`, `qpack` | — |
| `testing_quic` | the QUIC loopback check of §8 step 9e: a colibri client and server over `tls.quic` in one process | `h2` for the shared constants, `quic`, `tls_keylog` as `tls`, and its QUIC object's module for `ch_keylog` | — |
| `testing_udp` | §9's UDP QUIC endpoint, the hq-interop and h3 servers and clients, on Rotor's loop ([decision 58](decisions.md#the-h2-connection)) | `h2` for the shared constants, `h3` from step 12, `quic`, `rotor`, `tls_keylog` as `tls` with its QUIC object's module, and from step 17b `server`, an instance over `tls_keylog` that nothing packaged sees, which its h3 server runs on (the owner's ruling of 2026-09-28) | — |

The architecture depends on four of these edges and forbids one.

- **`quic` does not import `http`, `h2`, `h3`, `h11`, `hpack` or `qpack`.** This is
  [invariant 26](invariants.md#inv-26--quic-imports-no-http-module) and
  [decision 5](decisions.md#scope-and-shape). The check that proves it is that the QUIC simulator
  builds and runs with no HTTP module in the graph at all — not a lint rule, a link.
- **`sim` imports `core`, `tls_provider` and `crypto`, and no protocol module.** It implements the same two
  vtables a real caller does, so the build hands its null providers to the protocol modules in
  place of the caller's and nothing is conditionally compiled. It cannot import a protocol module,
  which is what keeps the harness from knowing anything the caller would not. A check drives a
  protocol module through the harness, so the one module that imports both is `sim_run`, rooted at
  `src/sim/run.zig`, and `sim` never imports it back ([decision 37](decisions.md#the-simulator)).
  The QUIC checks have a root of their own, `sim_run_quic` at `src/sim/run_quic.zig`, because
  `sim_run` imports `h2`: a QUIC check placed there would run with an HTTP module in its graph,
  and the first edge of this list is proved by a build that has none.
- **`wire` is shared by both families and holds two different integer codecs.**
  [decision 11](decisions.md#what-is-shared-between-h2-and-h3) explains why the split is *field
  compression against framing* and not h2 against h3.
- **No protocol module imports `tls`.** h11, h2 and quic take a provider, and a program makes a
  session with `tls` and hands its provider over, so a cleartext program never links chapulin
  ([decision 97](decisions.md)).
- **Nothing imports `h2`, `h3` or `h11` but `client` and `server`.** The protocol modules are the
  roots a consumer picks from, and `client` and `server` are consumers above all three, which
  choose the version for their caller ([decision 100](decisions.md)). No library module imports
  `client` or `server` in turn. `testing` is a consumer like any other: the library it drives cannot use the
  socket it opens, because the edge runs one way and nothing imports `testing` back.

## 4. What the caller supplies

Five things cross the boundary out of colibri. Each is a value or a vtable, never a callback
colibri invokes at a time of its choosing.

### 4.1 Bytes

The caller reads from its socket and hands colibri a slice. colibri parses what it can, tells the
caller how many octets it consumed, and leaves the remainder for the next call. For output the
caller hands colibri a slice to fill and colibri returns how many octets it wrote. There is no
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
layer". The full list is [decision 8](decisions.md#what-the-caller-supplies); the shape is:

| Operation | Record mode (h2) | QUIC mode (h3) |
|---|---|---|
| handshake bytes | record-framed, over TCP | unframed messages, per encryption level |
| application protection | `encrypt_record` / `decrypt_record` | absent — colibri protects packets itself |
| secrets | never exposed | never exposed to colibri: the provider hands them to the suite ([decision 48](decisions.md#what-the-caller-supplies)) |
| key derivation | provider-internal | provider-internal |
| transport parameters | absent | `set_transport_params` / `peer_transport_params` |
| ALPN | `negotiated_alpn` | `negotiated_alpn` |
| alerts | `take_alert` | `take_alert`, mapped to `0x0100 + AlertDescription` |
| key update | `initiate_key_update` | forbidden — QUIC's Key Phase instead |
| exporter | `export_keying_material` | `export_keying_material` |

Two facts constrain the ALPN half and are easy to get wrong. In TLS 1.3 the selected protocol
is sent in EncryptedExtensions, not ServerHello, so it is only readable after the provider has
decrypted EE — colibri must not assume it knows the ALPN earlier. And `"h2"` is the two octets
`0x68 0x32` (RFC 9113 §3.1) while `"h3"` is `0x68 0x33` (RFC 9114 §11.1); no overlap is a fatal
`no_application_protocol` alert, value 120 (RFC 9846 §6, RFC 7301 §3.2), which RFC 9001 §8.1
extends by requiring QUIC *clients* to use it too.

One state colibri owns and no provider will supply: **handshake confirmed**. RFC 9846 has no such
concept; it is defined only in RFC 9001 §4.1.2 — at the server when the handshake completes, at
the client when `HANDSHAKE_DONE` arrives.

### 4.4 The crypto suite

QUIC only; h2 needs none of it, because the provider does the record layer. The suite holds every
key of a connection and colibri holds none ([decision 48](decisions.md#what-the-caller-supplies)),
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
([invariant 25](invariants.md#inv-25--a-suite-that-cannot-protect-initial-packets-is-a-configuration-error)),
never a peer's fault. [Decision 9](decisions.md#what-the-caller-supplies) is why this is a second
vtable, and decision 48 is why its members are these.

### 4.5 The stream provider

QUIC only. colibri retransmits stream data itself (RFC 9000 §13.3), so it must be able to read a
stream's octets again until the peer acknowledges them, and it holds no copy. The caller keeps
the octets and supplies a vtable with one member, `read(stream_id, offset, output)`, which writes
the stream's octets from `offset` into `output` and returns how many it wrote. colibri calls it
inside `send` alone, for new octets and for lost ones, and the caller may drop a stream's octets
once colibri reports the stream in Data Recvd (§3.1) or reset. The provider answers the same
octets for an offset every time, which RFC 9000 §2.2 requires and colibri cannot check.
[Decision 57](decisions.md#the-h2-connection) is the ruling and the alternatives it beat.

## 5. What is shared, and what only looks shared

[decisions 11 to 16](decisions.md#what-is-shared-between-h2-and-h3) argue each of these from the
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

The frame header is 9 octets and is not counted in `Length`:

| Bits | Field | Notes |
|---:|---|---|
| 24 | Length | payload octets; > 2^14 only if the peer raised `SETTINGS_MAX_FRAME_SIZE` |
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

The client connection preface is the 24 octets
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

Variable-length integers, RFC 9000 §16 — the two most significant bits of the first octet give
the length:

| 2 MSB | Octets | Usable bits | Range |
|---|---:|---:|---|
| `00` | 1 | 6 | 0 – 63 |
| `01` | 2 | 14 | 0 – 16,383 |
| `10` | 4 | 30 | 0 – 1,073,741,823 |
| `11` | 8 | 62 | 0 – 4,611,686,018,427,387,903 |

Minimal encoding is *not* required except for the Frame Type field (§16, pointing at §12.4). A
decoder that rejects a non-minimal varint is wrong; a frame-type reader that accepts one is also
wrong.

The version-independent layer (RFC 8999 §5) reads only: bit 0x80 of octet 0; and for a long
header, the 32-bit Version at offset 1, a DCID length octet, up to 255 DCID octets, an SCID length
octet, up to 255 SCID octets. RFC 8999 §5 scopes the invariants to the **first** packet in a
datagram, and the Length field that makes coalescing parseable is a version-1 field, so the
invariant layer parses one packet and stops. It must not apply RFC 9000's 20-octet connection-ID
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
`H3_NO_ERROR`. colibri does both, and because it owns no randomness
([invariant 5](invariants.md#inv-5--no-source-reads-randomness-or-uninitialised-memory)) the
reserved value it picks is derived from configuration the caller supplied, so a seed still
replays.

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
  integer, octets as lowercase hexadecimal with no prefix, or a word such as an error name.
- The last line gives the count of records between the first line and itself, and how the run ended.
  A trace with no `end` line was cut short.
- The seed is the only value written in hexadecimal with a `0x` prefix, because it is the value a
  person copies into `zig build sim -- --<check>-seed <hex>`.

The records design §8 step 2 writes are the byte pipe's:

| Record | Fields | Written when |
|---|---|---|
| `feed` | `at_ns`, `len`, `held` | a chunk of the stream is fed to the caller; `held` counts the octets the caller holds after it |
| `accept` | `offset`, `len`, then the subject's fields | the subject consumed a whole value; `offset` is its first octet in the stream |
| `reject` | `offset`, `error` | the subject refused the octets at `offset` |

No record but `feed` carries an instant. The chunk schedule decides when a value completes, so
removing every `feed` record, and the record count from the `end` line, leaves the lines that do
not depend on the chunking. The step 2 check compares exactly those lines between a chunked run and
a run fed in one piece.

## 7. Named limits

Every one is declared in a `constants.zig` and never inline. The RFCs leave most of these to the
implementation and say so, so they are named here rather than chosen at a call
site. A limit that sizes storage sizes storage the caller owns: colibri allocates nothing
([decision 35](decisions.md#memory)), exposes each struct's size as a comptime constant, and
leaves the caller to place the struct.

**Shared** (`core`): `field_name_len_max` · `field_value_len_max` · `field_count_max` ·
`field_section_size_max` · `connections_max` · `streams_per_connection_max`.

**h2** (`h2`): `frame_size_max` (16,384, the RFC 9113 §4.2 floor, and colibri does not raise it) ·
`continuation_count_max` · `concurrent_streams_max` · `window_initial` · `window_max` (2^31 − 1) ·
`settings_pending_max` · `ping_pending_max` · `rst_stream_rate_max` · `peer_reset_rate_max` ·
`settings_timeout_ns` ·
`representation_len_max` (31,721 encoded octets: the longest field line within
`field_name_len_max`, `field_value_len_max` and `integer_len_max`, Huffman-coded at 30 bits an
octet, so it refuses no line those limits admit) · `field_block_buffer_len` (one cut representation
plus one frame, decision 40) · `send_block_len_max` (two frames' worth of field block colibri
sends, cut into a HEADERS frame and the CONTINUATION frames it needs) · `settings_ack_pending_max`
· `ping_ack_pending_max` · `stream_replies_max` (the reply queues of decision 39: a full queue
stops the reading, and no reply is ever dropped; a RST_STREAM the caller asks for takes no slot,
because the stream's record owes it, decision 113).

**wire** (`wire`): `varint_value_max` (2^62 − 1, RFC 9000 §16) · `integer_value_max` (2^62 − 1, the
62 bits RFC 9204 §4.1.1 requires) · `integer_len_max` (10 octets, the length those 62 bits need
past a 1-bit prefix) · `huffman_padding_bits_max` (7, RFC 7541 §5.2).

**HPACK / QPACK** (`hpack`, `qpack`): `dynamic_table_capacity_max` (16,384, ruled 2026-09-16) ·
`dynamic_table_entries_max` (the capacity over the 32-octet overhead) · `size_updates_per_block_max`
(2, RFC 7541 §4.2) · `blocked_streams_max` · `encoder_instruction_len_max` ·
`decoder_instructions_owed_max` (the last three decision 74's). Huffman data expands by up
to 1.6x, since the shortest code is 5 bits, and `wire.huffman.decoded_len_max` is that bound; a
literal's decoded length is capped by `core`'s field-length limits (RFC 7541 §7.4).

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

- **Step 0 — scaffolding.** `build.zig` with the §3 module graph, `constants.zig` per module, the
  linters ported from stompy (cognitive complexity, file length, heap, determinism, unbounded
  loop, relative-import, magic numbers, markdown GFM) plus colibri's own three: the `io` import
  denylist, the module-graph rule, and the RFC-citation rule, which fails a validation branch
  carrying no RFC section comment. Commit hooks.
  **Check:** `zig build lint` and `zig build test` pass, and a deliberately added `@import("http")`
  inside `src/quic/` fails to build. That last clause proves
  [invariant 26](invariants.md#inv-26--quic-imports-no-http-module) is enforced by the build
  rather than by review. *Small.*

  **Check passed, 2026-09-16.** `zig build test` exits 0: the lint scores 396 functions across
  `build/`, `src/`, `tools/` and `build.zig` with a highest score of 11 against the limit of 15;
  the eight `tools/lint` rules run clean; twelve module test binaries pass; and `zig build
  graph-check` prints the control line and five refusals. Zig 0.16.0 on macOS 25.6, arm64.

  The check has two halves, and neither half alone proves what it appears to prove.
  `tools/graph_check.zig` compiles a fixture as the root of a module carrying `quic`'s import set
  and requires the compile to fail — that is a real compiler verdict, not a rule about what the
  source says. But the set it compiles against is a list in the tool, so the `module-graph` lint
  rule reads `build/modules.zig` and `tools/graph_check.zig` and requires the two to agree. The
  compile proves the consequence; the rule proves the premise.

  Three properties of the check were checked by mutation rather than assumed, each applied, run,
  and reverted:
  - `http` added to the tool's import set — **CAUGHT**, the fixture compiled and the check exited 1
    naming INV-26.
  - The fixture's `comptime` block removed, making the import lazy — **CAUGHT**, and it fails loud
    rather than silent, which is why the block is there: Zig analyses lazily, so an unreferenced
    `const x = @import("http");` compiles clean and would have made the check vacuous.
  - `quic.addImport("http", http)` added to `build/modules.zig` — **CAUGHT** by `module-graph` in
    both directions (the build gained an import the graph forbids; the tool's list no longer
    matched), and `zig build test` exited 1.

  The positive control is what stops the whole thing being vacuous: a sixth fixture imports
  `core`, which `quic` does have, and must compile. A run where the control fails is reported as a
  broken check rather than a pass — and it did fail on the first run, on a real defect (`--dep=x`
  instead of `--dep x`), which is the control earning its place.

  **Tooling moved to pepegrillo, 2026-09-16.** The lint driver and its generic rules, the
  complexity scorer and the commit linter now come from pepegrillo (decision 36). `tools/` keeps
  colibri's configuration of each rule with the fixtures that pin it, the `module-graph` rule and
  the graph check. Old and new tools printed the same findings for all eight rules, the same scores
  at `--max 15` and `--max 0`, and the same commit verdicts, over this tree, stompy's and
  pepegrillo's. Each of the 62 configuration lines was mutated once and every mutant was
  **CAUGHT**; ten needed a new fixture first.

  **The last two rules, 2026-09-16.** `magic-numbers` runs over `src/`, but for each
  `constants.zig`, the generated `huffman_table.zig`, and the corpus and mutation tables of
  `src/golden/`. The 111 literals it found are now named: an octet's width is `@bitSizeOf(u8)`,
  the varint lengths and prefix bounds are `wire` constants, and the RFC 9110 §15 status codes are
  `http.status.Code`. `rfc-citation` reads every `return error.Name` under `src/`, but for the
  short-buffer errors, the test errors, `src/golden/`, `src/sim/` and `src/testing/`, and requires
  an `RFC <number> §<section>` or `RFC <number> Appendix <letter>` comment on the statement or the
  comment lines directly above it. It found three citations above a `const` rather than above the
  check. `zig build lint` passes no `--rule`, so every rule `tools/lint/main.zig` registers runs,
  and the lint must report every rule over a canary tree holding one violation of each. Each rule's
  mutations are in its commit, and every one is **CAUGHT**.

- **Step 1 — `wire` and `http`.** The varint (RFC 9000 §16), the prefixed integer generic over N
  in 1..8 and sized for 62 bits, the Huffman coder over RFC 7541 Appendix B, the string literal
  including QPACK's mid-byte prefix form, the `tchar` and field-value validators, the
  connection-option denylist, the status and method models. **Check:** a golden corpus with a
  manifest, valid and invalid, including one case per Huffman decode error (padding over 7 bits,
  padding that is not EOS's high bits, EOS inside the data) and one per varint length; RFC 9000
  Appendix A's sample varint decodings; fuzzing of every decoder; and a mutation per check
  reported `CAUGHT`. *Small to medium.*

  **Check passed, 2026-09-16.** `zig build test` exits 0 on Zig 0.16.0, macOS 25.6, arm64:
  262 tests pass, the lint scores 583 functions with a highest score of 12 against the limit of
  15, the eight `tools/lint` rules run clean, and `huffman_table --check` confirms that
  `src/wire/huffman_table.zig` is what RFC 7541 Appendix B yields.

  - **Reader and writer.** `core.Reader` and `core.Writer` work over caller-owned slices and hold
    no memory ([decision 35](decisions.md#memory)). A read or write that does not fit returns an
    error and moves no cursor, and each entry point asserts that the cursor is inside the slice
    ([invariant 3](invariants.md#inv-3--every-write-is-inside-the-callers-buffer)). Every decoder
    built on them consumes a whole structure or nothing.
  - **Huffman table.** `tools/huffman_table.zig` generates the table from the RFC text. It reads
    both code columns of every row and refuses a row where they disagree. Comptime asserts in
    `src/wire/huffman.zig` pin Kraft equality, EOS as thirty set bits, and the canonical order the
    decoder depends on. The octets 204 and 22 encode to `ff ff fb ff ff ff ff 7f`, whose run of
    thirty-four ones decodes with no EOS
    ([decision 11](decisions.md#what-is-shared-between-h2-and-h3)).
  - **Corpus.** `src/golden/` holds 32 cases in four formats, 14 of them invalid, each format with
    a version 1 manifest: 10 varint, 9 prefixed integer, 7 Huffman and 6 string literal. They cover
    one valid case and one truncation per varint length, RFC 9000 Appendix A.1's five sample
    decodings, RFC 7541 Appendix C.1's three integers, the Appendix C strings, one case per Huffman
    decode error, and QPACK's mid-octet string literal at 4-bit and 2-bit prefixes.
    `zig build golden-check` compares every committed file and manifest with the case table, and
    runs the 15 corpus mutations of `src/golden/mutations.zig`, each of which produces the verdict
    it names.
  - **Fuzzing.** Every decoder and validator has a `std.testing.fuzz` property function.
    `zig build test` runs each one over its corpus and over every input of up to two octets, at
    every prefix size where the decoder takes one (`core.fuzz.sweep`). The fuzzer itself does not
    run: with Zig 0.16.0, `zig build test-wire --fuzz` fails to compile the fuzz-mode test runner,
    because `lib/compiler/test_runner.zig:566` passes a `builtin.StackTrace` where
    `std.debug.writeStackTrace` takes a `debug.StackTrace`. The property functions are ready for a
    toolchain that fixes it. A corpus entry is not raw octets: outside `--fuzz`, `Smith` reads a
    4-octet length before each slice, which `core.fuzz.input` writes.
  - **Built after the step passed.** Invariant 3's lint rule, no slicing with a peer-derived
    index outside the reader and writer, was not written when the step passed; its assertions
    and fuzzing were. `tools/lint/peer_index.zig` added it on 2026-09-16, and the tree was clean
    under it.

  Seventy-two source mutations were applied, run against the narrowest test step that can catch
  them, and reverted. The first run found one `NOT CAUGHT`: an encoder that ended the prefixed
  integer one value early wrote `ff 00` for a remainder of 127, which decodes to the same value, so
  no test saw it. The test "continuation octets follow only while the remainder is 128 or more" now
  pins RFC 7541 §5.1's loop condition. Five mutations failed only to compile, because they left a
  local unused, which proves nothing about the rule. Each was replaced with a mutation that
  compiles. Every row below is the final result.

  | Mutation | Result | Caught by |
  |---|---|---|
  | reader: take accepts one octet past the end | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | reader: peek_byte skips the empty check | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | reader: read_byte does not advance | **CAUGHT** | test `reader`: "a read inside the slice returns the octets and moves the cursor" |
  | reader: read_int shifts seven bits | **CAUGHT** | test `reader`: "integers read in network byte order" |
  | writer: write_bytes accepts one octet past the end | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | writer: write_byte skips the full check | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | writer: write_int writes little-endian | **CAUGHT** | test `writer`: "a write inside the buffer lands and moves the cursor" |
  | writer: print advances at most one octet | **CAUGHT** | test `writer`: "formatted text lands whole or not at all" |
  | varint: length read from the top bit alone | **CAUGHT** | test `varint`: "a non-minimal encoding decodes and re-encodes at its own length" |
  | varint: length bits left in the value | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | varint: encoder writes the length bits one place low | **CAUGHT** | test `varint`: "a non-minimal encoding decodes and re-encodes at its own length" |
  | varint: one-octet range includes 64 | **CAUGHT** | test `varint`: "each length's largest value round-trips and one more needs the next length" |
  | prefixed integer: a full prefix read as the value | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
  | prefixed integer: continuation flag read from bit 6 | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
  | prefixed integer: value limit one past 62 bits | **CAUGHT** | test `prefixed_integer`: "a value one past the ceiling is IntegerTooLarge" |
  | prefixed integer: octet limit one longer | **CAUGHT** | test `prefixed_integer`: "an eleventh octet is IntegerTooLong even when every group is zero" |
  | prefixed integer: groups shifted by eight | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
  | prefixed integer: caller high bits kept in the prefix | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
  | prefixed integer: encoder ends one value early | **CAUGHT** | test `prefixed_integer`: "continuation octets follow only while the remainder is 128 or more" |
  | prefixed integer: failed decode still consumes | **CAUGHT** | test `prefixed_integer`: "a value one past the ceiling is IntegerTooLarge" |
  | wire constants: integer_len_max nine | **CAUGHT** | comptime assert |
  | huffman: EOS compared with symbol 255 | **CAUGHT** | test `huffman`: "every octet round-trips, and the empty string is empty" |
  | huffman: EOS found by scanning for thirty ones (invariant 12) | **CAUGHT** | test `huffman`: "octets 204 and 22 decode through a run of thirty-four ones with no EOS" |
  | huffman: padding of eight bits allowed | **CAUGHT** | test `huffman`: "padding longer than seven bits is HuffmanPaddingTooLong" |
  | huffman: padding not checked against EOS | **CAUGHT** | test `huffman`: "padding that is not a prefix of EOS is HuffmanPaddingNotEos" |
  | huffman: canonical range admits one code too many | **CAUGHT** | test `huffman`: "octets 204 and 22 decode through a run of thirty-four ones with no EOS" |
  | huffman: encoder pads with zeros | **CAUGHT** | test `huffman`: "octets 204 and 22 decode through a run of thirty-four ones with no EOS" |
  | huffman: failed decode commits partial output | **CAUGHT** | test `huffman`: "a complete EOS inside the data is HuffmanEosInData, even before a valid symbol" |
  | huffman table: one code changed | **CAUGHT** | comptime assert |
  | huffman table: one length changed | **CAUGHT** | comptime assert |
  | huffman table: generated comment edited by hand | **CAUGHT** | `huffman_table --check` in `zig build test` |
  | string literal: H flag one bit low | **CAUGHT** | test `string_literal`: "a Huffman error inside the data fails the literal and consumes nothing" |
  | string literal: length read at N bits | **CAUGHT** | test `string_literal`: "a Huffman error inside the data fails the literal and consumes nothing" |
  | string literal: declared length clamped to the data present | **CAUGHT** | test `string_literal`: "a length longer than the data present is Truncated and consumes nothing" |
  | string literal: Huffman data copied raw | **CAUGHT** | test `string_literal`: "a Huffman error inside the data fails the literal and consumes nothing" |
  | string literal: decode never commits the reader | **CAUGHT** | test `string_literal`: "fuzz: a literal consumes its whole length or nothing" |
  | field: bar dropped from tchar | **CAUGHT** | test `field`: "every tchar RFC 9110 §5.6.2 lists is a tchar, and nothing else is" |
  | field: empty name accepted | **CAUGHT** | test `field`: "a field name is a non-empty token within the limit" |
  | field: name limit refuses the limit itself | **CAUGHT** | test `field`: "a field name is a non-empty token within the limit" |
  | field: name octets above 0x7f accepted | **CAUGHT** | test `field`: "a field name is a non-empty token within the limit" |
  | field: CR not refused as CR | **CAUGHT** | test `field`: "a field value is refused in check order" |
  | field: HTAB reported as control | **CAUGHT** | test `field`: "a field value admits VCHAR, obs-text and inner whitespace" |
  | field: DEL not a control | **CAUGHT** | test `field`: "a field value is refused in check order" |
  | field: control octets accepted | **CAUGHT** | test `field`: "a field value is refused in check order" |
  | field: leading whitespace accepted | **CAUGHT** | test `field`: "a field value is refused in check order" |
  | field: trailing whitespace read from the first octet | **CAUGHT** | test `field`: "a field value is refused in check order" |
  | field: value limit refuses the limit itself | **CAUGHT** | test `field`: "a field value admits VCHAR, obs-text and inner whitespace" |
  | field: names compared case-sensitively | **CAUGHT** | test `field`: "field names compare case-insensitively" |
  | connection-specific: Connection dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | connection-specific: Proxy-Connection dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | connection-specific: Keep-Alive dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | connection-specific: TE dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | connection-specific: Transfer-Encoding dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | connection-specific: Upgrade dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
  | connection-specific: TE trailers matched by prefix | **CAUGHT** | test `connection_specific`: "TE is trailers only when it says exactly that" |
  | method: empty method accepted | **CAUGHT** | test `method`: "a method that is not a token is refused" |
  | method: space accepted in a method | **CAUGHT** | test `method`: "a method that is not a token is refused" |
  | method: standard methods matched case-insensitively | **CAUGHT** | test `method`: "a method is case-sensitive, and an unknown token is still a method" |
  | status: 99 in range | **CAUGHT** | test `status`: "the range ends are 100 and 599" |
  | status: 600 in range | **CAUGHT** | test `status`: "the range ends are 100 and 599" |
  | status: four digits accepted | **CAUGHT** | test `status`: "three digits parse, and anything else is refused in check order" |
  | status: digits not checked | **CAUGHT** | test `status`: "three digits parse, and anything else is refused in check order" |
  | status: recognised codes not kept | **CAUGHT** | test `status`: "an unrecognised code is understood as the x00 of its class" |
  | status: 426 dropped from the recognised codes | **CAUGHT** | test `status`: "the recognised codes are exactly those RFC 9110 §15.2 to §15.6 define" |
  | golden: constructor value changed | **CAUGHT** | test `golden`: "golden-check: every committed case file is what its constructor builds" |
  | golden: rejection named wrongly | **CAUGHT** | test `golden`: "golden-check: every committed manifest is what the table renders" |
  | golden: manifest checksum edited | **CAUGHT** | test `golden`: "golden-check: every committed manifest is what the table renders" |
  | golden: corpus mutation names the wrong verdict | **CAUGHT** | test `golden`: "golden-check: every corpus mutation produces the verdict it names" |
  | golden tool: frozen marker ignored | **CAUGHT** | test `golden`: "a frozen directory is refused and a writable one is written in full" |
  | golden tool: stale cases kept | **CAUGHT** | test `golden`: "a frozen directory is refused and a writable one is written in full" |
  | huffman tool: only a larger hex column refused | **CAUGHT** | test `huffman_table`: "a row whose bits and hex disagree is refused" |
  | huffman tool: symbol order not checked | **CAUGHT** | test `huffman_table`: "a missing, reordered or short appendix is refused" |

  **The varint proved, 2026-09-26.** `spec/lean/Colibri/Wire/Varint.lean` states RFC 9000 §16's
  codec over natural numbers, as `varint.zig` computes it, and proves four things
  ([#52](https://github.com/c4milo/colibri/issues/52)):
  - `decode_encode`: an encoding decodes to its value and its length, whatever octets follow it;
  - `encode_octets`: in the four lengths, every octet of an encoding is below 256;
  - `decode_bound`: whatever octets are decoded, the value fits the length the first octet names;
  - `minimal_fits` and `minimal_shortest`: the minimal length carries the value, and no shorter
    one does.

  The proof of the first used no bound on the length. The four lengths are what keep the first
  octet a byte, which `u8` enforces in `varint.zig` and the model had left unstated, so that
  fact became `encode_octets`. `spec/lean/Vectors.lean` writes `src/wire/varint_vectors.txt`:
  60 encodings, among them RFC 9000 Appendix A.1's, 484 decodings of every one-octet input and
  every cut encoding, and 23 minimal lengths. A test in `varint.zig` requires the Zig codec to
  give each. Mutations: 3 in `varint.zig`, each **CAUGHT** by that test; 2 in the Lean
  definitions, each stopping the proofs; and 1 edit to the vector file, which `zig build lean`
  refuses.

  **The prefixed integer proved, 2026-09-26.** `spec/lean/Colibri/Wire/PrefixedInteger.lean`
  states RFC 7541 §5.1's integer as `prefixed_integer.zig` computes it, at every prefix size 1 to 8,
  and proves:
  - `decode_encode`: an encoding decodes to its value and its length, whatever high bits the
    caller set above the prefix and whatever octets follow;
  - `encode_octets`: every octet is below 256;
  - `encode_length`: every value up to 2^62 - 1 takes at most `integer_len_max` octets at every
    prefix size;
  - `decodeLimited_encode`: with colibri's octet and value limits, every such encoding still reads
    back, so the limits refuse nothing RFC 9204 §4.1.1 requires.

  `src/wire/prefixed_integer_vectors.txt` holds 191 encodings, RFC 7541 Appendix C.1's three
  among them, and 355 decodings: every cut encoding, and the inputs only colibri's limits refuse.
  A test in `prefixed_integer.zig` requires the Zig codec to give each. Mutations: 5 in
  `prefixed_integer.zig`, each **CAUGHT** by that test. One, reading a tenth continuation octet,
  was caught only after the vectors gained an input whose tenth octet ends the integer. 1 in the
  Lean definitions stops the proofs, and 1 edit to the vector file is refused by `zig build lean`.

  **The Huffman code proved, 2026-09-26.** `spec/lean/Colibri/Wire/Huffman.lean` states RFC 7541
  Appendix B's code and §5.2's padding as `huffman.zig` encodes them. Its decoder reads one bit at
  a time and looks the bits read so far up in the table. It proves:
  - `prefix_free`: no symbol's code is a prefix of another's. The kernel checks this over the
    codes as numbers in 9 seconds, where a check over the codes as bits took 100, and a lemma
    carries it to the bits;
  - `eos_ones`: EOS is thirty ones;
  - `decode_encode`: every string of octets decodes back from its encoding, padding included;
  - `decode_octets`: whatever a decoding accepts is octets below 256, so EOS never reaches the
    output.

  `spec/lean/Colibri/Wire/HuffmanTable.lean` copies the 257 rows of `huffman_table.zig`.
  `src/wire/huffman_vectors.txt` names each row, and holds 271 encodings and 1,288 decodings, 796
  of them refused. The encodings cover every octet, RFC 7541 Appendix C.4's and C.6's strings, and
  all 256 octets in one string. A test in `huffman.zig` requires the Zig table and coder to give
  each line. `huffman.zig` decodes through the table's canonical ranges, so these vectors are what
  tie it to the decoder the proofs are about.

  Mutations:
  - 8 in `huffman.zig` and `huffman_table.zig`, each **CAUGHT** by that test. Two first failed to
    compile and were rewritten to compile: zero padding, which left a constant unused, and a table
    row, which the comptime Kraft check refused and which became two 5-bit codes swapped.
  - 4 in the Lean definitions. Three make a theorem false: EOS reaching the output, zero padding,
    and two rows sharing a code. The fourth, eight bits of padding accepted, first broke only a
    proof script that named the constant 7. That script now uses `split`, so the mutant builds,
    and `zig build lean` refuses it for the vectors it changes.
  - 1 edit to the vector file, which `zig build lean` refuses.

- **Step 2 — the deterministic driver.** A seeded harness that feeds bytes in arbitrary chunks,
  supplies instants, and substitutes null TLS and crypto providers. This is the simulator for the h2
  half, and it exists before there is a connection to drive, which is possible only because §4 put
  I/O, time and crypto in the caller's hands. **Check:** the step 1 decoders driven through the
  harness at seeded chunk boundaries over a seed range, with the §6.6 trace records compared byte
  for byte across macOS and Linux and across Debug and ReleaseSafe. What this does and does not
  prove: at step 2 nothing but the harness can differ, so it shows the harness is self-consistent.
  The same check re-run over a connection at step 4 is the first point at which it can fail for any
  other reason. *Small.*

  **Check passed on macOS, 2026-09-16.** `zig build test` exits 0 on Zig 0.16.0, macOS 25.6,
  arm64, in Debug and with `-Drelease`, and the lint scores 460 functions with a highest score
  of 12. `zig build sim -- --chunk-check` prints the same census in both modes:
  `seeds=256 passed=193 rejected=63 chunks=2551 trace_octets=278839 crc32=0x11c9c07a`. That digest
  is `chunk_check.census_crc32_expected` and the check's test requires it.

  **Check passed on Linux, 2026-09-18, on two architectures**
  ([issue 1](https://github.com/c4milo/colibri/issues/1)). Debian bookworm with glibc, Zig 0.16.0,
  under OrbStack on the development Mac, once on aarch64 and once on x86-64. `zig build test`
  passes 622 tests on x86-64, and all three checks print what macOS prints, in Debug and with
  `-Drelease`:

  | Check | Census |
  |---|---|
  | chunk | `seeds=256 passed=193 rejected=63 chunks=2551 trace_octets=278839 crc32=0x11c9c07a` |
  | connection | `seeds=256 passed=195 rejected=61 frames=4670 chunks=9636 trace_octets=588870 crc32=0xe8f7c0b4` |
  | tls | `seeds=256 events=512 crc32=0x795236bd` |

  Two qualifications, so the claim is read for what it is. The x86-64 run is Zig's own x86-64 code
  generation, which is the part determinism depends on, executed under Rosetta rather than on
  x86-64 hardware. And every run so far is little-endian; a big-endian host would test the
  byte-order rules of §2.2 harder than any of these do.

  - **Harness.** `src/sim/` holds `Random`, SplitMix64 written out so a Zig upgrade cannot change
    what a seed replays; `Clock`, which moves only when the pipe advances it; `Trace`, the §6.6
    format over a `core.Writer`; and `pipe.run`, which feeds a stream to any subject with `step`
    and `describe` in chunks of 1 to `chunk_len_max` octets after delays of up to
    `chunk_delay_ns_max`, writing a `feed` record per chunk and an `accept` or `reject` per value.
  - **Check.** `src/sim/chunk_check.zig`, in the `sim_run` module. Each seed draws 1 to 16 values
    across the varint, the prefixed integer at every prefix size, and the string literal at every
    prefix size in both codings, and one seed in four appends an encoding a decoder refuses. The
    seed runs chunked twice and in one piece once: the two chunked traces must match byte for
    byte with the same draw count, the chunked run's accept and reject records must be the
    one-piece run's, the outcome must be what the plan says, and the run in one piece must feed
    exactly once, without which the comparison is vacuous.
  - **Driver.** `zig build sim -- --chunk-seed <hex>` prints one seed's chunked trace and its
    outcome; `--chunk-check [seeds]` prints the census or the seed that failed.
    `src/sim/run_main.zig` is the one file under `src/sim/` the `io` rule exempts, by path.
  - **Not built.** The null TLS provider and the null crypto suite. `tls.Provider` and
    `crypto.Suite` do not exist yet, and no step 2 subject calls a provider, so each null
    implementation lands with the step that shapes its vtable: the provider with step 5
    ([issue 3](https://github.com/c4milo/colibri/issues/3)), the suite with step 7
    ([issue 4](https://github.com/c4milo/colibri/issues/4); design §10 fixes its sizes: a
    16-octet tag and a 5-octet mask).

  Twenty-nine mutations over the generator, the clock, the trace, the pipe, the stream, the check
  and the command line were applied, run against `zig build test-sim` or `test-sim-run`, and
  reverted, plus three over the `wire` decoders, which the check must see: every one **CAUGHT**,
  eight after a new test. The three that mattered most: a chunked run replaced by a run in one
  piece, the reverse, and a replay restarted from the seed rather than from the generator as it
  stood after the stream was drawn.

- **Step 3 — HPACK.** Static table, dynamic table with the shared size arithmetic, all five
  representations, the size-update instruction. **Check:** `http2jp/hpack-test-case` decoded across
  **every** encoder directory, not only nghttp2's — the naive, static and linear strategies crossed
  with Huffman and plain are what exercise the dynamic table; round-trip of `raw-data`; the three
  interop breaks of §6.2 each with a named error and a corpus case; fuzzing; mutations. *Medium.*

  **Check passed, 2026-09-16.** `zig build test` exits 0 on Zig 0.16.0, macOS 25.6, arm64: 256 tests
  pass, the lint scores 556 functions with a highest score of 15 against the limit of 15, the
  eleven `tools/lint` rules run clean, `static_table --check` confirms `src/hpack/static_table.zig`
  is what RFC 7541 Appendix A yields, and `hpack-vectors` prints
  `directories=15 stories=478 cases=47142 fields=548382 round_trips=10152` in 2.9 s.

  - **Module.** `hpack.Decoder` reads a block one representation at a time and returns each field
    line to the caller, which is §3.1's minimal transitory memory; `hpack.Encoder` writes a block
    with the strategy Appendix C's examples follow, and the tests hold both to C.3 through C.6
    byte for byte. `DynamicTable` is shared by the two, with the size formula in
    `wire/table_size.zig` (decision 11) and invariant 11's sum recomputed after every insert and
    eviction. The size-update rules of §4.2 and §6.3, and RFC 9113 §4.3.1's rule that a block
    after a lowered limit opens with a conformant update, are decoder errors with their sections
    on the checks. The static table is generated from Appendix A by `tools/static_table.zig`,
    as the Huffman table is from Appendix B.
  - **Vectors.** Every directory of `http2jp/hpack-test-case` decodes, `nghttp2-change-table-size`
    and `nghttp2-16384-4096` included, and `raw-data` round-trips through the encoder in each of
    its three Huffman settings (decision 38 on how the corpus is held).
  - **Corpus.** `src/golden/hpack/` holds the three interop breaks of §6.2 beside their legal
    twins, six cases with five mutations, and `golden` now imports `hpack` to check them.
  - **Not built.** Nothing of the step. `Decoder` and `Encoder` are 30 KiB and 22 KiB, sized by
    `dynamic_table_capacity_max`; the h2 connection of step 4 places one of each.

  Forty-three source mutations were applied over the table, the decoder, the encoder, the
  constants, the golden decode and the vectors tool, run against the narrowest step that can
  catch them, and reverted: 42 **CAUGHT**, eight of them only after a test was added (an exact-fit
  insert, a duplicate entry in `find`, the `never_indexed` flag, a name referenced from the entry
  its own insert evicts and then compacts over, a size update held to a case's
  `header_table_size`), and one equivalent: preferring the dynamic table's exact match over the
  static table's cannot be observed, because a line the static table holds is indexed and never
  inserted, so the mirror never holds one. The code now says so and prefers the static index.

- **Step 4 — h2 connection and streams, cleartext, prior knowledge.** Frame reader and writer,
  the two prefaces, settings with the ACK discipline, the stream state machine, the signed send
  window and the retroactive settings sweep, GOAWAY, `RST_STREAM`, the field-block reassembly
  slot, request and response validation. Push refused per [decision 17](decisions.md), priority
  parsed but never scheduled per [decision 18](decisions.md). **Check:** `h2spec` green at the
  pinned version against the test-only prior-knowledge cleartext h2 server of §9 — h2spec connects
  in cleartext unless `-t` is given — with every skipped case named and justified;
  `http2jp/http2-frame-test-case`; the step 2 driver checking
  [invariants 13 to 16](invariants.md#http2) after every step of every seed; fuzzing; mutations.
  **This is the largest single step and the first shippable thing.** *Large.*

  **Check passed, 2026-09-17.** `zig build test` exits 0 on Zig 0.16.0, macOS 26.6, arm64: 587 tests
  pass, the lint scores 1,324 functions with a highest score of 13 against the limit of 15, and
  the eleven `tools/lint` rules run clean. `tools/h2spec.sh` prints `146 tests, 144 passed,
  0 skipped, 2 failed` against h2spec 2.6.0, and the script names the two: both test RFC 7540
  §5.3.1's rule that a stream cannot depend on itself, which RFC 9113 §5.3.2 dropped with the rest
  of the priority scheme, leaving §6.3 two rules that colibri does enforce
  ([decision 41](decisions.md#the-h2-connection)). `h2-frames` prints
  `cases=34 normal=12 errors=22 round_trips=12`. The simulator check prints
  `connection: seeds=256 passed=195 rejected=61 frames=4670 chunks=9636 trace_octets=588870
  crc32=0xe8f7c0b4`, the same number in Debug and `-Drelease`.

  - **Connection.** `receive` consumes one frame and returns at most one event, and the frames
    colibri owes are queued in fixed slots that a short buffer never truncates (decision 39). The
    send path writes a response, its DATA under both windows, a RST_STREAM and a graceful GOAWAY
    into the caller's buffer. A connection error queues the GOAWAY and stops the reading; a stream
    error queues a RST_STREAM and the connection goes on (invariant 27).
  - **Streams.** The table keeps every closed record until an open needs its slot, which is what
    tells a stream the peer opened and closed from an identifier it never opened: h2spec
    `http2/5.1/12` wants `STREAM_CLOSED` for the first and `http2/5.1.1/2` `PROTOCOL_ERROR` for
    the second, and §5.1 permits both only if the two are distinguished.
  - **Field blocks.** Every fragment is passed to the decoder whatever colibri thinks of its stream,
    or the dynamic table would stop matching the peer's (invariant 10, decision 40).
    `representation_len_max` is the longest line the decoder's own limits admit, so it refuses none
    of them.
  - **Simulator.** `src/sim/connection_check.zig` drives one connection through the step 2 pipe and
    reads invariants 13 to 16 after every frame it accepts. A seed replays byte for byte and
    chunking changes no verdict, which at this step can fail for the connection's own reasons and
    not only the harness's.
  - **Endpoint.** `src/testing/` holds the cleartext server of §9, in two halves: a session with no
    socket in it, which the unit tests drive, and the socket around it. Nothing imports the module
    back, so the library cannot reach that socket.
  - **Not built.** TLS, which is step 5, and with it h2spec's `-t` mode. Push stays refused
    (decision 17) and priority parsed and never scheduled (decision 18).

  Two hundred and nineteen source mutations were applied over the field-block slot, the message
  validators, the stream table, the connection's two paths, the Huffman bound and the simulator
  check, each run against the narrowest step that can catch it, and reverted: 215 **CAUGHT** and
  four equivalent. The four: two in the stream table that change no answer it gives, one weakening
  the check's replay comparison, which two runs of a seed cannot tell apart, and one that makes the
  highest identifier the peer opened lag without ever decreasing, which invariant 13 does not
  forbid and `zig build test-h2` catches on h2spec's `http2/5.1.1/2` case.

  **The client send path, 2026-09-18.** Step 4's check proved the server. The stream table was
  written for both roles at the time, but `open_local` was never called from connection code, so a
  client could parse a response and had no way to ask for one. `connection/connection_request.zig`
  adds `write_request`: it refuses a request §8.3.1 or §8.5 would make malformed before anything
  changes, then opens the stream, encodes the section with the pseudo-header fields before the
  regular field lines (§8.3), and cuts it into HEADERS and CONTINUATION. The order is the point:
  §5.1.1 forbids reusing an identifier, so a request refused for its own contents costs no stream.

  Two receive-side rules came with it, both on the client path that nothing could reach before. A
  client now reads any number of interim responses before the final one (§8.1), which the
  `sections_received` marker on the stream record decides; until now the second field section on a
  stream was always a trailer section, so a response after a 1xx was refused as malformed. And an
  interim response no longer sets the content-length §8.1.1 compares the DATA octets against.

  `zig build test` passes 598 tests on Zig 0.16.0, macOS 26.6, arm64, the lint scores 1,354
  functions with a highest score of 13 against the limit of 15, and the simulator check prints the
  census the step recorded, unchanged: `crc32=0xe8f7c0b4`. What this does not have is a conformance
  suite: h2spec connects to a server, so no suite drives a colibri client, and §9 lists no client
  endpoint. Interop in the client direction is step 5's check, which waits on a TLS server.

  Thirteen mutations were applied over the new checks, each run against `zig build test-h2` and
  reverted. Every one was **CAUGHT**.

  | Mutation | Caught by |
  |---|---|
  | an interim response is marked final | test: "an interim response is not a trailer section, and the final response follows it" |
  | any second field section is trailers | same test |
  | an interim response sets the content-length | test: "an interim response does not set the content-length the DATA is compared with" |
  | the request is validated after the stream opens | test: "each request opens the next odd identifier, and a refused one opens none" |
  | a CONNECT request may carry `:path` | test: "a CONNECT request carries :authority alone" |
  | an uppercase field name is sent | test: "an uppercase name and a connection-specific line are refused" |
  | TE carries any value | same test |
  | an empty `:path` is sent | test: "a request without :scheme or :path, or with an empty one, is refused" |
  | `:authority` is left out of the block | test: "the block carries the pseudo-header fields, then the regular field lines" |
  | `:path` is written before `:method` | same test |
  | the regular field lines are left out | same test |
  | CONNECT writes a `:scheme` anyway | test: "a CONNECT block carries :method and :authority alone" |
  | no stream opens after a GOAWAY the peer sent | test: "no stream opens after a GOAWAY the peer sent" |

  **Still not built.** Neither role sends a trailer section. A server may send an interim response
  by calling `write_response` twice, and nothing stops it setting END_STREAM on one, which §8.1
  forbids.

  **The TLA+ model, 2026-09-26** ([#48](https://github.com/c4milo/colibri/issues/48)).
  - `347f8e7`: `spec/tla/h2_flow_control` models a colibri client and a colibri server over one
    connection: RFC 9113 §5.1's stream states, §6.9's connection and stream windows, colibri's
    WINDOW_UPDATE threshold and its queue of owed replies, and a peer that changes its
    SETTINGS_INITIAL_WINDOW_SIZE, which may drive a send window negative (§6.9.2). The
    properties: no frame goes out that its stream's state forbids, no window passes its maximum,
    no sender sends on a window that is not positive, and every exchange finishes.
  - It found a defect. colibri queued a stream's WINDOW_UPDATE when DATA arrived and wrote it
    later, so it could follow the frame that closed the stream, which §5.1 forbids ("An endpoint
    MUST NOT send frames other than PRIORITY on a closed stream"). `3653d52` drops a stream's owed
    credit once the peer ends its side or either side resets it, since no more DATA comes.
  - What `zig build tla` printed, on macOS arm64:
    - holds, as expected: `colibri`, 6463 distinct states; `two_streams`, 572165; `settings`,
      432411;
    - violated, as expected: `update_after_end`, the path the fix closes; `settings_negative`, a
      send window does go negative, so the rule is exercised; `ignore_negative`, a sender that
      sends on a window that is not positive; `threshold_above_window`, a WINDOW_UPDATE threshold
      above the window, which stalls the exchange and is why `window.Receiver` requires the
      window to be at least the threshold.
  - The fix's mutations, against `zig build test-h2` alone: 7 **CAUGHT**. h2spec still prints 144
    of 146 in cleartext and over TLS, and the server interop against Go passes.

  **The input check, 2026-09-26.** `src/sim/h2_input_check.zig` gives the frame reader inputs
  longer than two octets, as the QPACK and QUIC input checks do
  ([#53](https://github.com/c4milo/colibri/issues/53)).
  - Each input is a stream of frames of all ten types and one of an unknown type, written by
    `h2.frame`'s writers, with values drawn at their bounds or a few inside them half the time.
    What the writers produced must be read whole before it takes up to eight edits.
  - The edited stream is read as the connection reads it: the header, the Length against
    SETTINGS_MAX_FRAME_SIZE, then `parse`.
  - A refusal must get a verdict of PROTOCOL_ERROR or FRAME_SIZE_ERROR, and a stream error only on
    a stream other than 0 (§5.4.2). An accepted frame must keep every rule its writer asserts.
    Written again, it must keep its type, its stream and its defined flags, and read back the
    same.

  `zig build test-sim-run` runs 256 seeds of 128 inputs and pins the census, which Debug and
  ReleaseSafe agree on. `zig build sim -- --h2-input-check` prints `seeds=256 taken=6698
  incomplete=16496 refused=9574 frames=157943 crc32=0x0d547a5d`. 200,000 seeds, 25.6 million
  inputs, ran in ReleaseSafe with no input halted. 20 mutations of the reader, its writers and
  `verdict`, all **CAUGHT** by the check alone.

  **The connection model and its trace check, 2026-09-27**
  ([#75](https://github.com/c4milo/colibri/issues/75), [decision 104](decisions.md)).
  - `spec/tla/h2_connection` models a colibri client and server over one connection. It holds each
    stream's state at both endpoints (RFC 9113 §5.1), each message's order in each direction
    (§8.1), RST_STREAM crossing frames in flight (§6.4) and GOAWAY (§6.8). Each rule colibri keeps
    is a constant: `SendInState`, `DataAfterHead`, `OneFinalHead`, `DiscardAfterReset`,
    `IgnoreAboveGoaway` and `NoStreamAfterGoaway`. A configuration that turns one off must find a
    violation.
  - `src/sim/h2_trace_check.zig`: a colibri client and server act out a seed's plan over one queue
    of octets in each direction. The plan draws write calls colibri must refuse as well as ones it
    takes: DATA before a response's head, a head after the final one, a frame after END_STREAM or a
    reset, and a stream after a GOAWAY. After each action, `h2_trace_state.zig` computes the
    model's variables from both endpoints, and the run keeps each state that differs from the one
    before. The run fails a seed on a connection error, a stream error or a stream opened after a
    GOAWAY, so it finds those without TLC.
  - `zig build sim -- --h2-trace-write <directory>` writes 64 seeds' states as TLA+ modules and
    TLC configurations. `tools/h2_trace.sh` runs TLC over them with `H2ConnectionTrace.tla`.
    Between two logged states the model takes up to 40 steps, `steps_between_max`. A seed passes
    when TLC reaches its last logged state.
  - `c32cabe` fixed the defect that led to the model: `write_data` sent DATA before the response's
    head. The run then found two more:
    - `3fa6e78`: `write_response` set END_STREAM on an interim response. The note "Still not
      built" above names this, and it no longer holds.
    - `9acb1dc`: after a GOAWAY colibri sent, DATA, RST_STREAM or WINDOW_UPDATE on a stream the
      peer initiated above its last stream identifier failed the connection. §6.8 lets the
      GOAWAY's sender ignore those frames, and colibri now does.

  What each check printed on macOS arm64:
  - `zig build sim -- --h2-trace-check`, in Debug and in ReleaseSafe: `h2-trace: seeds=256
    opened=405 responses=123 resets=169 goaways=196 refused=5422`.
  - `tools/h2_trace.sh`: `64 of 64 traces are behaviors of the model`, in 59 seconds. The 64 logs
    hold 570 states. Of the logs, 22 hold an answered request, 4 an interim response, 24 a reset
    and 38 a GOAWAY, 8 of them two. 26 seeds open three streams.
  - `zig build tla -- spec/tla/h2_connection/*.cfg`: the three scopes hold, `messages` in 626993
    distinct states, `resets` in 3264 and `goaway` in 1633432. The six configurations that turn a
    rule off are violated.
  - 4 mutations of colibri, 4 **CAUGHT**. For each, the run's own checks fail a seed. With those
    checks removed, TLC finds traces that are not behaviors of the model:
    - DATA before the final head: 47 of 64 traces pass;
    - an interim response that ends the stream: 61 of 64 pass;
    - frames above a GOAWAY colibri sent not ignored: 60 of 64 pass;
    - the client opens a stream after a GOAWAY it read: 52 of 64 pass.

  **The caller's resets, 2026-09-30** ([decision 113](decisions.md)).
  - `reset_stream` pushed its RST_STREAM into the reply queue with no room check, and the push
    asserted a free slot among `stream_replies_max`. Before the fix, six tests stopped on that
    assertion. At a server: 128 resets between two writes, 128 before an open, and 127 before an
    open that must drop the one record it may. Then one reset after the peer's DATA filled the
    queue with WINDOW_UPDATE frames, 128 resets at a client, and 33 cancels through
    `server.Connection.cancel`.
  - The reading could not overflow the queue. A DATA frame that owes a WINDOW_UPDATE and then
    breaks its content-length drops that frame before its RST_STREAM is queued, so it takes one
    slot. A test pins the case with one slot left, and `receive` now asserts after each frame that
    it owes at most one reply about one stream. No other frame pushes two.
  - `spec/tla/h2_flow_control` models the resets of one endpoint's caller, `Resetter`, and the
    reading's stop for a full queue, `QueueMax`. `resets` checks safety with a one-slot queue,
    `QueueBounded` among it, and `resets_finish` checks that every exchange finishes. With one slot
    and two frames in flight each way, both endpoints can stop reading while both channels are
    full, with resets or without ([#85](https://github.com/c4milo/colibri/issues/85)), so `resets`
    checks no liveness. Three configurations turn a rule off: `reset_in_queue` queues the resets
    with no room checked, `reset_keeps_update` keeps the credit owed on a reset stream, and
    `reset_uncharged` leaves DATA after a reset out of the connection window.
  - 18 mutations of colibri, 17 **CAUGHT** and 1 **NOT CAUGHT**:
    - **CAUGHT**: the reset owes nothing; an open drops a record that owes a reset; a HEADERS
      frame never waits for a slot; every frame waits, or a client's HEADERS waits too; an open
      waits with no reset owed, with a free slot, at the peer limit, or while a closed record
      owes nothing; a written reset keeps its mark, or its count; `owe_reset` counts nothing; the
      owed resets go before the queued replies; `has_pending` leaves them out; either reset keeps
      the stream's credit; a reset the reading decides queues its RST_STREAM before it drops the
      credit.
    - **NOT CAUGHT**: the write walks the records when none owes a reset. The walk then writes
      nothing, so no test can tell.

  What each check printed on macOS arm64:
  - `zig build test`: `128/128 steps succeeded; 2492/2492 tests passed`.
  - `tools/h2spec.sh 28443 --tls`: 144 passed and the 2 cases decision 41 names, in cleartext and
    over TLS.
  - `tools/h2_trace.sh`: `64 of 64 traces are behaviors of the model`. `tools/client_trace.sh`:
    `67 of 67 traces are behaviors of the model`. `zig build sim -- --h2-trace-check`: the census
    above, unchanged.
  - `zig build tla -- spec/tla/h2_flow_control/*.cfg`: `colibri` holds in 6463 distinct states,
    `settings` in 432411 and `two_streams` in 572165, as before, `resets` in 1384220 and
    `resets_finish` in 176219. The seven configurations expected to be violated are.

  **The stall check, 2026-09-30** ([#85](https://github.com/c4milo/colibri/issues/85)).
  - `src/sim/h2_stall_check.zig` runs a colibri client and a colibri server over a transport that
    holds 1 to 256 KiB each way. Each endpoint is driven as a caller drives h2 (decision 39): it
    reads while `receive` takes frames, writes what it owes when `receive` takes none, and reads on
    only if that fits. It writes what its connection owes before its own frames, as
    `client.Connection` does, or after them, as `server.Connection`'s `respond` and `write_body`
    do. A round in which nothing moves ends a run, and one whose messages did not all arrive is a
    stall.
  - Random seeds send bodies of up to 128 KiB on up to 48 streams, and seldom fill a reply queue.
    While an endpoint cannot write, its peer can send it at most the connection window, 65,535
    octets, which gathers two thresholds' worth of stream credit. Only streams whose credit already
    sits just below the threshold owe more. Aligned seeds make that happen: 40 to 48 streams each
    send one octet short of the threshold first, so the next octet on each owes a WINDOW_UPDATE.
  - What `zig build sim -Drelease -- --h2-stall-check 8192` printed, on macOS arm64 in 538
    seconds: 30.9 GB of bodies and 4 stalls. All four are aligned seeds over a transport of 1 KiB
    (two) or 4 KiB (two), with both endpoints writing their own frames first and both reply
    queues full. None of the 6074 runs in which an endpoint writes what it owes first stalled.
    Random seeds filled a queue three times, and each of those runs finished.
  - The test runs seeds `[0, 16)`, which finish, and pins seed `0x12c`, which stalls. A stall in
    a run whose endpoints both write what they owe first is a violation, `StalledOwedFirst`.
  - 4 mutations of h2, 4 **CAUGHT**. With no stream WINDOW_UPDATE written, no connection
    WINDOW_UPDATE written, or a reading that does not stop for a full queue, both tests fail. A
    queue of 64 fails the check's build, because its aligned seeds open more streams than the
    queue holds.

  **The server writes what h2 owes first, 2026-10-01**
  ([#85](https://github.com/c4milo/colibri/issues/85)). The owner ruled on the stall above in
  decision 39 as amended: the transport holds at least 16 KiB each way, and `server.Connection`
  writes what h2 owes before its own frames, as `client.Connection` already did.
  - h2's `write_replies` writes the queued replies once the preface is out, and `write_pending`
    writes the preface and then calls it, so no reply goes ahead of the preface (RFC 9113 §3.4).
  - `server.Connection` calls it before a response's head, DATA, a trailer section and a 100
    (Continue). A WINDOW_UPDATE written there holds a body's rate deadline, as one written in
    `send` does (decision 110 as amended).
  - Three tests have the server read a PING and a request in one call, which returns the request
    while the PING's acknowledgment is owed. The acknowledgment must go out before each frame. A
    fourth, in h2, has a connection fail before its preface is out: `write_replies` writes
    nothing, and `write_pending` writes the SETTINGS before the GOAWAY.
  - `zig build test`: 131 of 131 steps and 2536 of 2536 tests passed.
  - 6 mutations, each **CAUGHT**. Each of the four calls removed fails its test. `write_replies`
    without its preface check fails h2's test. `take_owed` without its note of a WINDOW_UPDATE
    fails decision 110's test of the send deadline.

  **The write order in the flow-control model, 2026-10-01**
  ([#85](https://github.com/c4milo/colibri/issues/85)). The stall check found no stall when an
  endpoint writes what it owes first. `spec/tla/h2_flow_control` now checks that order.
  - `OwedFirst` names the endpoints that write what they owe before a frame of their own: their
    HEADERS and DATA wait while they owe anything. Every earlier configuration leaves it empty,
    which keeps the order free, and explores the states it did before.
  - With every frame one of `ChannelMax` slots, the order changes nothing. Over channels of 2 to
    6 frames and queues of 1 or 2, both orders stall or both finish. A reply then takes as much
    room as a DATA frame, and with both endpoints writing what they owe first, their replies fill
    a channel of two frames (`queue_stall_owed_first_slots`, violated).
  - `Weighted` makes the channel count DATA units. A reply takes one unit, a DATA frame its units
    and one for its header, and a DATA frame is cut to the room left, as `sendable` cuts it. Over
    2, 3 and 4 units the free order stalls (`queue_stall_weighted`, violated), and both endpoints
    writing what they owe first finish (`queue_stall_owed_first`, 68,777 states). With the client
    alone doing so, as colibri did before the server's change above, it stalls over 2 and 3 units
    (`queue_stall_client_first`, violated) and finishes over 4. Over 5 units every order
    finishes.
  - `ChannelBounded` says the frames in flight never take more room than the channel has.
  - `zig build tla -- spec/tla/h2_flow_control/*.cfg`: the 23 configurations give their verdicts,
    the earlier ones over the states they explored before.
  - 5 mutations of the model, 4 **CAUGHT** by `queue_stall_owed_first`: no order, an order that
    waits for no stream reply, every frame one unit, and a DATA frame not cut to the room. The
    fifth, an order that waits for no connection increment, is **NOT CAUGHT**, and no
    configuration can catch it: only the queue of stream replies stops the reading, so a
    connection increment written late never stalls.

  **The prefaces in the connection model, 2026-09-30**
  ([#79](https://github.com/c4milo/colibri/issues/79)). `e3126a9` fixed a server that answered a
  request read with the client's preface before writing its own SETTINGS, which RFC 9113 §3.4
  requires to be the first frame a server sends. The model had no prefaces, so it could not see
  that.
  - `spec/tla/h2_connection` now starts each endpoint with its preface: the client's 24 octets and
    its SETTINGS, carried as one frame, and the server's SETTINGS. Each endpoint reads its peer's
    first, and any other frame first is a connection error (§3.4). `PrefaceFirst` is colibri's
    rule: an endpoint writes its preface before any other frame, and before it reads one.
    `NothingBeforePreface` says no frame goes ahead of its sender's preface.
  - Two configurations turn the rule off, and each must be violated. In `preface_first` the
    server's response goes ahead of its SETTINGS, and in `preface_read` the client reads that
    response first, a connection error.
  - The h2 trace run logs a state before either preface, and shows each preface in flight as the
    model's frame.
  - `zig build tla -- spec/tla/h2_connection/*.cfg`: the three scopes hold, `messages` in 821,759
    distinct states, `resets` in 3,970 and `goaway` in 2,193,274. The eight configurations that
    turn a rule off are violated.
  - `tools/h2_trace.sh`: 64 of 64 traces are behaviors of the model. `zig build sim --
    --h2-trace-check`: the census above, unchanged.
  - `zig build test`: 131 of 131 steps and 2513 of 2513 tests passed.
  - 6 mutations, each **CAUGHT**. In the model: the server, or the client, sending before its
    preface; no `NothingBeforePreface`; and no error for a frame read before the peer's preface.
    In the trace run, no preface shown in flight. In h2, the SETTINGS written before the client's
    24 octets. The fourth was **NOT CAUGHT** while the model dropped a frame read before the
    preface. It now reads it as colibri would without the check.
  - A trace through `server.Connection` and `client.Connection`, where e3126a9's defect was, is
    the rest of #79.

  **The TCP trace, 2026-09-30** ([#79](https://github.com/c4milo/colibri/issues/79)). The h2
  trace drives `h2.Connection` directly and writes each preface first, as h2's contract asks, so
  it could not see e3126a9's defect, which was in `server.Connection`.
  - `src/sim/tcp_trace_check.zig` has a `client.Connection` and a `server.Connection` act out a
    seed's plan over h2 in cleartext. Each side writes into its own output until its caller calls
    `send`, and a delivery gives the reader every octet in flight at once, as one read from a
    socket does.
  - The client's first flight carries its preface, its SETTINGS and one to three requests, and
    the server reads it in one delivery. The server's caller answers some requests the moment the
    server reports them, inside that delivery, which is where e3126a9's server wrote a response
    ahead of its SETTINGS.
  - After each action the run computes `spec/tla/h2_connection`'s state from both connections, in
    the h2 trace's `State`, and TLC checks each seed's log as it checks the h2 trace's. A
    connection error, a malformed message, a stream opened after a GOAWAY or a replay that
    differs fails the run without TLC.
  - A cancel or a shutdown decides a RST_STREAM or a GOAWAY that h2 writes at the caller's next
    `send`. The model sends either in the step that decides it, so the run has the connection
    write it at once with `write_owed`.
  - The client sends its own GOAWAY when it closes after the server's (RFC 9113 §6.8). It names
    stream 0, because colibri's server opens no stream (decision 17), so the log leaves it out as
    it leaves out SETTINGS and PING.
  - `zig build sim -- --tcp-trace-check 64`: `seeds=64 states=508 requests=123 responses=76
    refused=5 shut_down=26`. `tools/tcp_trace.sh`: 64 of 64 traces are behaviors of the model.
  - 6 mutations, each **CAUGHT**. Three undo e3126a9 a layer at a time. With the server reading
    before it writes its SETTINGS, h2's assertion that nothing goes out before the preface halts
    the run. With that assertion gone too, the client reads the response first and fails the
    connection: `ConnectionFailed` on seed 0. With the client's §3.4 check gone as well, TLC finds
    22 of the 64 traces to be behaviors of the model. Before the server's caller answered on the
    event, the deadline check alone caught the first two, and nothing caught the third.
  - The other three: the client and h2 opening a stream after a GOAWAY, `OpenedAfterGoaway` on
    seed 0x1b; the client reading a 103 as its final head, the client's assertion in
    `record_head`; and h2 refusing every response head that ends its stream, `Malformed` on seed
    0.
  - TLS, where cocuyo found the defect with the request in the flight of the client's Finished, is
    the rest of #79.

  **The TCP trace over TLS, 2026-09-30** ([#79](https://github.com/c4milo/colibri/issues/79)).
  cocuyo found e3126a9's defect over TLS, where the client's first flight goes out with its
  Finished, and the server reads the request in the call that completes its handshake.
  - One seed in two runs over TLS, with the test identity of `src/testing/testdata/` judged at
    its fixed instant and h2 chosen by ALPN. The handshake runs before the first flight: the
    ClientHello one way, the server's flight the other. The first flight then goes out with the
    client's Finished, and the server reads both in one delivery.
  - A side's records carry the protocol's octets sealed, so the run calls `send` twice. The first
    call has no room, so it writes what the connection owes and seals nothing. The run copies the
    plaintext the connection then holds, and the second call seals it.
    `src/sim/tcp_trace_direction.zig` notes where each send ended, in octets handed out and in
    plaintext. A reader that consumed the records of whole sends has read their plaintext, less
    what it holds unread. A reader stopped inside one send's records fails the run, since the
    run cannot place it.
  - Until a side's handshake completes it has no h2 connection, and the model's state for it is
    the initial one.
  - `zig build sim -- --tcp-trace-check 64`: `seeds=64 tls=38 states=564 requests=129
    responses=83 refused=3 shut_down=25`. `tools/tcp_trace.sh`: 64 of 64 traces are behaviors of
    the model.
  - With every seed over TLS, the three mutations that undo e3126a9 are each **CAUGHT**: by h2's
    assertion, by `ConnectionFailed` on seed 0x4, and by TLC, which finds 25 of the 64 traces to
    be behaviors.
  - The six mutations above, again over the mixed seeds, each **CAUGHT**: h2's assertion;
    `ConnectionFailed` on seed 0x4; TLC with 24 of 64; `OpenedAfterGoaway` on seed 0x18; the
    client's assertion in `record_head`; and `Malformed` on seed 0.

  **The TCP trace without `write_owed`, 2026-10-04.** After a cancel or a shutdown the run called
  each connection's `write_owed`, the one caller that kept those two functions public. It now
  calls `send` with no room, which writes what the connection owes and hands out nothing.
  - The client's `send` also writes the requests that wait, so a cancel's action can write them
    too, and the census has one state fewer: `seeds=64 tls=38 states=563 requests=129
    responses=83 refused=3 shut_down=25`.
  - `tools/tcp_trace.sh`: 64 of 64 traces are behaviors of the model.
  - The six mutations are each still **CAUGHT**, the third by TLC with 25 of 64.

- **Step 5 — the TLS provider vtable and h2 over TLS.** The record-mode vtable, ALPN, the
  handshake-complete signal, `close_notify` as end of data. Still no implementation in the packaged
  library. **Check:** `h2spec -t -k` against the TLS entry point; interop against nghttp2, curl,
  Go's `net/http2` and h2o, **both directions**, with the exact versions recorded.

  **This step waits on chapulin, and so does every later check that needs TLS.** The check needs a
  TLS 1.3 *server*, certificate signing included, and colibri's library supplies none:
  [decision 8](decisions.md#what-the-caller-supplies) keeps production implementations out of the
  tree. [Decision 10](decisions.md#what-the-caller-supplies) answers the "Ask before" this paragraph
  used to raise: chapulin fills both vtables, and `src/testing/` links it while the packaged library
  never does. Steps 9, 10, 12 and 13 need the same server for the interop endpoint, h3spec and
  `secnetperf`, and step 7 needs chapulin's `crypto.Suite` for RFC 9001 Appendix A's vectors.
  chapulin has neither a server role nor ALPN today, so this step waits for the h2 items of
  [the request](chapulin.md). *Medium, once chapulin delivers them.*

  **colibri's side, 2026-09-18.** The half of this step that needs no crypto is built, and the
  step is not passed: its check is `h2spec -t -k` and interop in both directions, and both need a
  TLS 1.3 server that signs a certificate.

  `src/tls/` declares the record-mode vtable of [decision 8](decisions.md#what-the-caller-supplies)
  with [decision 43](decisions.md)'s eleventh member, `negotiated_parameters`, which reports the
  version and suite RFC 9113 §9.2 places rules on. `h2.Connection` gains an optional provider
  ([decision 44](decisions.md)): with none it is the cleartext prior-knowledge endpoint step 4
  built, unchanged. `attach_tls` refuses a handshake that has not completed, that selected anything
  but "h2" (§3.1, §3.3), or whose version and suite colibri does not admit — TLS 1.3 and three
  suites, by [decision 45](decisions.md). `decrypt` applies §9.2.3: a post-handshake
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
  [decision 46](decisions.md) shapes it: every socket is O_NONBLOCK from before it connects, one
  thread holds up to 64 connections in one `poll` set, and no other call waits. It speaks cleartext
  h2 with prior knowledge (RFC 9113 §3.3), because chapulin's TLS client reads its socket through
  a callback that cannot say "nothing yet" (decision 46). `zig build h2-client` runs it and
  `tools/h2_interop.sh` judges it.

  The script ran on macOS 25.6 arm64 against three peers, on one connection and then on 64 at
  once, and every exchange ended as planned:

  | Peer | Version | What the plan covers |
  |---|---|---|
  | Go `net/http` | go1.27.1 | a 1 MiB response, a 300,000-octet echo read while it is sent, a 103 before a 200, a trailer section, a 404 |
  | nghttpd | nghttp2 1.52.0, Debian bookworm | a 1 MiB response, a POST of 300,000 octets, a 404 |
  | h2o | 2.2.5, Debian bookworm | a 1 MiB response, a POST of 300,000 octets answered 405, a 404 |

  Both sizes are several times the 65,535-octet window a stream starts with (RFC 9113 §6.9.2), so
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
  server each fill `tls.Provider`, from `src/testing/` alone ([decision 10](decisions.md)); the
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
  above. What stands between here and `h2spec -t -k` is [decision 46](decisions.md) — chapulin's
  handshake blocks, and the h2 server's rule is that `poll` is the only call that waits.

  **Ruled by the owner on 2026-09-20: wait for chapulin.** A serial TLS endpoint and a thread for
  each handshake were both offered and both lost; decision 46 stands unamended. What colibri waits
  on is named: a server handshake whose `send` and `recv` callbacks can report "nothing yet"
  instead of failing, so `h2_server.zig` can drive it from inside its one `poll` call.
  <https://github.com/c4milo/colibri/issues/20> tracks it, and chapulin has the request. RFC 9113 Appendix A's prohibited suites are
  not checked and will not be: decision 45 records why.

  **`h2spec -t -k` passes, 2026-09-24.** chapulin now has a record-mode server driver.
  - `fcc6292`: the server object is built `TRANSPORT=record`, and `h2-server --tls` runs each
    handshake inside its one `poll` call ([decision 82](decisions.md)).
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
  `h2-client` from their `poll` loops to Rotor ([decision 83](decisions.md),
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
  built `TRANSPORT=record`, like the server's ([decision 82](decisions.md)). That fixes the
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
  64 GETs and a 300,000-octet POST. The run requires 200 and the server's body for each.
  - curl 7.88.1 cannot reuse a prior-knowledge connection. Its second request on one fails with
    "Error in the HTTP2 framing layer", against Go's server as against colibri's. So in cleartext
    each curl GET gets its own connection, 64 at once. Over TLS they share one.
  - 9 mutations, all CAUGHT: every client catches a status of 201 and a body one octet shorter,
    and a body with one octet changed. nghttp at first checked only the size, so the script now
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

- **Step 6 — the counted-cost check.** Syscalls the caller would have made, copies and bytes per
  request, counted inside the simulator and committed as exact numbers. Allocations are not
  counted: [decision 35](decisions.md#memory) makes them zero, and `tools/lint/heap.zig` holds
  it. **Check:** the numbers are in the tree and a diff that changes one fails `zig build test`
  until the new number is committed on purpose. This is the cheap half of
  [decision 34](decisions.md#performance) and it lands before any QUIC code, so the h2 half has a
  regression floor while the larger half is built. *Small.*

  **Check passed, 2026-09-18.** `src/sim/cost_check.zig` holds the cost of one request in three
  shapes, and `zig build test` fails when any number moves. What it counts is what a caller sees
  from outside — calls to `receive` and `write_pending`, the octets each carried, and the crossings
  of the provider vtable — because the library counts nothing itself: §11's rules forbid a
  statistic that costs a branch on the per-frame path. Allocations are not counted;
  [decision 35](decisions.md#memory) makes them zero.

  | Scenario | receive | write_pending | octets in | octets out | provider calls |
  |---|---|---|---|---|---|
  | server, cleartext | 4 | 3 | 58 | 58 | 0 |
  | client, cleartext | 3 | 3 | 19 | 100 | 0 |
  | server, over the null provider | 4 | 3 | 58 | 58 | 2 |

  Two of these are worth reading rather than filing. A request and its response cross colibri's
  boundary seven times at a server, which is the bulk-crossing rule of §11 holding: one call reads
  a frame, one call writes every frame owed. And TLS adds two crossings and no octets, because the
  provider frames what colibri already produced whole.

  `tools/lint/magic_numbers.zig` excludes this file, as it excludes the corpus tables of
  `src/golden/`. These are measurements, not limits, and naming each one would put the number in
  two places.

  Four mutations, every one **CAUGHT**: a server advertising one fewer setting, a response carrying
  an extra field line, `write_pending` writing the preface in a call of its own, and a request
  omitting `:authority`.

- **Step 7 — QUIC packet formats and the crypto vtable.** The RFC 8999 invariant reader as its own
  file with an empty import set, the version-1 reader above it, long and short headers, packet
  number encoding and decoding, the Initial key schedule, packet protection, header protection,
  Retry integrity. **Check:** RFC 9001 Appendix A's sample packet protection, byte for byte, in the
  golden corpus; RFC 9000 Appendix A.2 and A.3's packet number encoding and decoding; corpus cases
  with connection IDs longer than 20 octets under an unknown version, which must **parse** rather
  than fail; a mutation that applies the 20-octet cap in the invariant reader, reported `CAUGHT`;
  fuzzing of the packet reader. *Medium to large.*

  **The formats, 2026-09-19.** The half of this step that touches no key is built, in
  `src/quic/packet/`. `invariant.zig` reads RFC 8999 alone: the Header Form bit, the long header's
  Version and connection IDs of 0 to 255 octets, the short header, and the Version Negotiation
  packet of §6 in both directions. It imports `std` and `core` and nothing else, and a comptime
  block in `packet_header.zig` fails the build if it imports a third module or names version 1's
  connection ID maximum ([invariant 22](invariants.md#inv-22--a-version-independent-parse-reads-only-rfc-8999-fields)).
  `packet_header.zig` is the version 1 reader above it (RFC 9000 §17): the four long types, the
  Initial token, the Length that ends a packet so the next one of the datagram can be read
  (§12.2), Retry with its tag, and the short header. It reads as far as header protection
  allows and reports where the Packet Number field starts; `unprotected_long` and
  `unprotected_short` read byte 0 once protection is removed, and refuse set Reserved Bits.
  `packet_header_write.zig` writes the same headers and the Retry Pseudo-Packet of RFC 9001 §5.8.
  `packet_number.zig` is Appendix A.2 and A.3.

  What was checked, on macOS 25.6 arm64, with `zig build test` at 685 of 685:

  - The writers produce RFC 9001 Appendix A's published headers octet for octet: the client
    Initial of A.2, the server Initial of A.3, the Retry packet of A.4 less its tag, and the short
    header of A.5. The reader takes A.4's Retry packet apart into its fields.
  - Packet numbers: A.2's two sample encodings and A.3's sample decoding, the boundary of every
    field length, and every length encoded and decoded back. Appendix A.3's sample leaves one
    case out: when the largest number processed is 2^62-1 every candidate is a window past the
    largest packet number §12.3 permits. `decode` returns the number one window below, which is
    the closest one that exists.
  - The golden corpus gains two formats, `quic_invariant` with 8 cases and `quic_packet` with 18,
    and seven mutations. Connection IDs of 21 octets parse under an unknown version in both
    readers, and the same octets are dropped once one edited octet makes the version 1.
  - Both readers have a fuzz property, run over a corpus and over every input of up to two
    octets: a header that is read accounts for every octet of its datagram.

  Mutations: 34 applied over the four files, each against `zig build test-quic` and
  `zig build test-golden`. 32 were **CAUGHT**, the one this step names among them: the 20-octet
  maximum applied inside `invariant.zig` fails both. One was **NOT CAUGHT**, a decode that leaves
  the last window upward, and got its test. The last removed the comptime guard of invariant
  22, which no test can see; it was replaced by three mutations that break what it guards — a
  third import, an import of the version 1 constants, and the maximum's name — and each fails
  the build.

  **The crypto vtable, 2026-09-19.** The owner ruled the same day
  ([decision 48](decisions.md#what-the-caller-supplies)): the suite holds every key and protects
  every packet, and colibri holds none. So this step no longer builds the Initial key schedule,
  packet protection, header protection or the Retry tag, which its first sentence still lists as
  it was planned. It builds what calls them. `src/crypto/suite.zig` is the vtable: ten members,
  each about a whole packet at an encryption level, and none that takes or returns a key. A test
  holds the member names to the decision's list
  ([invariant 23](invariants.md#inv-23--colibri-holds-no-secret)). The `Suite` wrapper asserts
  colibri's half of the contract: a packet number inside its range, a Packet Number field of 1 to
  4 octets, and the four octets RFC 9001 §5.4.2 needs before the sample. Recovering a packet
  number (RFC 9000 Appendix A.3) moved to `src/crypto/packet_number.zig`, because §9.5 makes it
  the suite's step; `quic` keeps Appendix A.2, and its tests encode with one module and decode
  with the other.

  `src/sim/null_suite.zig` fills the vtable with no cryptography
  ([issue 4](https://github.com/c4milo/colibri/issues/4)). It is size-faithful, as §10 requires:
  header, payload and a 16-octet tag, with byte 0 and the Packet Number field masked from a
  16-octet sample four octets past the field. It models keys as names, because colibri's
  connection logic will be checked against it. A level has keys, never had them, or had them
  discarded. The Initial keys follow the role and the connection ID. A key update moves both
  directions, keeps the previous read keys until colibri drops them, and changes the tag's name
  while it leaves the mask's alone, which is how a header protection key survives an update
  (RFC 9001 §6.1). Both limits of §6.6 exist at numbers a test sets.

  `src/sim/packet_check.zig` is the check that the two halves fit. Each seed draws connection
  IDs, a number of key updates and up to three packets in RFC 9000 §12.2's order. One endpoint
  writes each header, picks the Packet Number field's length from what the peer acknowledged,
  and seals into one datagram. The other reads the datagram packet by packet, opens each, and
  must get back the number, the header and the payload with nothing left over. Then one bit of
  the datagram is changed and at least one packet must fail to open, judged by the suite alone.
  256 seeds, 512 packets, 128,870 octets, every field length drawn, digest `0xf0818926` in Debug
  and in `-Drelease`, on macOS 25.6 arm64. The check's module imports `sim` and `quic` and no
  HTTP module, so it is also the first build that holds
  [decision 5](decisions.md#scope-and-shape)'s boundary; step 8 inherits that root. It has no
  command line until step 8, and its test pins the digest.

  `zig build test` passes 705 of 705. Mutations: 30 applied over the null suite, its keys, and
  three places where framing and protection must agree (the Length counting the tag, the
  reported offset of the Packet Number field, the field's length). All 30 **CAUGHT**; the three
  cross-module ones are caught by the packet check and by `quic`'s own tests.

  **Still owed for the step.** RFC 9001 Appendix A's sample packet protection, byte for byte.
  Under decision 48 those vectors check a provider through the vtable, so they need chapulin's
  `ch_quic_*` calls, which chapulin implemented on 2026-09-20, and they will run from
  `src/testing/` and not from
  the corpus, whose cases are 64 octets at most. The headers of those samples are already
  checked, octet for octet, above.

  **Check passed, 2026-09-25**, on macOS arm64 with Zig 0.16.0 and chapulin's QUIC object at
  `b32ad68`. `src/testing/quic/protection_vectors.zig` runs RFC 9001 Appendix A through
  `crypto.Suite` as chapulin fills it, with the hex copied from `docs/rfcs/rfc9001.txt` line for
  line. One client session, holding the A.1 connection ID's Initial keys:
  - A.2: seals the client's Initial, which comes out as the published 1200 octets;
  - A.3: opens the server's published Initial, which gives back its header, packet number 1 and
    its 99-octet payload, with the keys of the other direction;
  - A.4: checks the Retry Integrity Tag over the pseudo-packet colibri's
    `write_retry_pseudo_packet` builds, and chapulin writes the published tag over it.

  A.1's keys are what makes A.2 and A.3 match octet for octet. A.5 is chapulin's to check, and
  its `test/quic_packet_tests.h` does: it starts from a 1-RTT secret, and under decision 48 no
  secret crosses the vtable, so colibri has none to give.

  What each check printed: `zig build test-testing-quic -Dchapulin-quic=<checkout>` passes 15 of
  15, and without the option the three vector tests skip. Mutations, against that command: six
  **CAUGHT** — the packet number, the connection ID the keys derive from, the Packet Number
  field's offset, the pseudo-packet's connection ID length, and the adapter's packet number length
  and Retry check.

  **The packet number proved, 2026-09-26.** `spec/lean/Colibri/Quic/PacketNumber.lean` states RFC
  9000 Appendix A.2 as `quic`'s `encode` computes it and Appendix A.3 as `crypto`'s `decode`
  computes it, and proves:
  - `encode_range` and `encode_shortest`: the length `encode` picks represents more than twice
    the unacknowledged range, as §17.1 requires, and no shorter length does;
  - `encode_none`: `encode` refuses exactly when four octets do not;
  - `decode_closest`: `decode` rebuilds every packet number within half a window of the one
    expected;
  - `decode_encode`: a receiver that has processed at least the number the sender saw
    acknowledged, and none at or past the one sent, rebuilds the number `encode` truncated;
  - `decode_bound` and `decode_field`: any field decodes to a packet number (§12.3) that ends in
    the field's octets;
  - `field_read_write`: the field's octets, most significant first, read back to its value.

  `src/quic/packet/packet_number_vectors.txt` holds 112 encodings, Appendix A.2's two among them,
  and `src/crypto/packet_number_vectors.txt` holds 381 decodings, Appendix A.3's among them. A
  test beside each requires the Zig function to give them. Mutations: 11 in the two Zig files.
  9 are **CAUGHT** by those tests. 2 are equivalent, so no test can catch them:
  - `candidate + window < packet_number_max`: the sum equals 2^62 - 1 only when the field is all
    ones, and then the candidate is not half a window below the number expected;
  - `candidate > window`: the candidate equals `window` only when the number expected is at least
    `window`, and then the candidate is not above it.

  A Lean proof that each mutated `decode` equals `decode` on every input confirmed both; it was
  run once and not committed. 3 mutations in the Lean definitions stop the proofs, and 1 edit to
  a vector file is refused by `zig build lean`.

- **Step 8 — the QUIC simulator.** A datagram network with delay, drop, reorder, duplication and ECN
  marking, over the step 2 clock, with a null crypto suite. **Check:** one seed replays
  byte-identically across hosts and build modes — and the harness **builds and runs with no HTTP
  module in the graph**, which is the check for [decision 5](decisions.md#scope-and-shape).
  *Medium.*

  **Check passed, 2026-09-19.** `src/sim/network.zig` carries datagrams between two endpoints over
  the clock of step 2. A `Schedule` fixed before a run gives the rates of three events as counts
  out of a thousand — dropped, duplicated, and marked ECN-CE — and a delay range; every draw for a
  datagram is made when it is sent, so its fate does not depend on when it is collected.

  Reordering is not a draw. Each datagram takes its own delay, so one sent later and delayed less
  overtakes one sent earlier, which is what a network does. Two that arrive at one instant are
  delivered in the order they were sent: without that tie-break the delivery order would follow
  the array's layout, and a run would replay only on the host that laid it out. RFC 9000 §13.4
  puts one rule on the marking, and the network keeps it: a node answers congestion by marking a
  datagram the sender sent ECT, and never one sent Not-ECT. The codepoints carry RFC 9000 §13.4's
  names and no bit values, because the two bits are RFC 3168's, which is not in `docs/rfcs/` and
  which colibri never writes: the field belongs to the IP header its caller owns.

  What the network does not model is recorded with it. There is no bandwidth, no queue length and
  no path MTU, so a datagram is never dropped for being too large or too frequent. RFC 9002's
  congestion control is step 10's, and a network that modelled a bottleneck would decide the
  answers step 10 must compute.

  `src/sim/network_check.zig` is the check, and it is the first run in which both halves meet:
  colibri frames a packet, the null suite seals it, the network carries it, and the peer reads the
  datagram, opens the packet and compares it. Each packet carries the number its header encodes
  inside its sealed payload, so the peer compares what it rebuilt against what was sent and not
  against what is plausible. An endpoint learns what its peer has acknowledged only when a
  datagram comes back, which is the narrowest Packet Number field RFC 9000 Appendix A.2 permits
  and so the strict case for recovery.

  Over 256 seeds on macOS 25.6 arm64: 16,384 packets sent, 16,398 delivered, 809 dropped, 823
  duplicated, 9,294 reordered, 982 marked ECN-CE, and **6,611 packet numbers rebuilt against a
  history that had already moved past them, every one exactly right**. Digest `0x1f31d87e` in
  Debug and in `-Drelease`. A run in which any of those events never happened fails as
  `ScheduleUnexercised`, so the check cannot pass while proving less than it claims.

  The second half of the check is the module graph. `src/sim/run_quic.zig` receives `sim` and
  `quic` and no HTTP module, so this harness builds and runs with `h2`, `h3`, `hpack`, `qpack`
  and `http` absent — held by the build, not by a lint. `zig build test-sim-run-quic` runs it,
  and CI runs it in both modes.

  `zig build test` passes 716 of 716.

  Mutations: 22 applied over the network and the check, 21 **CAUGHT** and one equivalent. The
  first pass caught 14, and the seven it missed were worth more than the fourteen.

  One did not fail the run, it **hung** it. Removing the line that frees a delivered datagram's
  slot left `receive` returning the same datagram for ever, and a test helper looped on it with
  `while (network.receive(...)) |_| {}`. That is an unbounded loop, which non-negotiable 4
  forbids and which `tools/lint/unbounded_loop.zig` does not catch: its own header records the
  blind spot, that a `while` over an optional is outside both of its checks. The helper is now
  bounded by the network's slots, and what found it was a mutation harness that times a step out
  and reports the hang rather than waiting.

  Three were missing tests of the network's bookkeeping, each written: the tie-break between two
  datagrams arriving at one instant, which the old test could not tell from the array's layout
  because its slots happened to be in order; the highest sequence delivered being assigned
  instead of raised; and the two endpoints sharing one record of it.

  Three were a check whose assertions never fire on a healthy run, so deleting one changed no
  output. `Fault` is the answer, in the shape the null suite's refusal flags already use: a test
  turns one on and requires the violation it should produce — a corrupted octet, a packet number
  misreported as an earlier one of the sender's own, a scrambled payload, a run left undrained,
  and a network with nothing to report. Two of those faults were themselves wrong at first, and
  the mutations said so: one returned its violation directly instead of leaving datagrams in
  flight, and one misreported a number out of range, where a neighbouring check caught it first
  and hid the comparison the fault existed to prove.

  The equivalent one is sizing the Packet Number field as if nothing were acknowledged. Every
  number in this run is small enough that both sizings give one octet, so the mutant's output is
  identical — which is also why no field here exceeds one octet. Fields of two, three and four
  octets are drawn by step 7's packet check, which sets the distance directly.

- **Step 9 — QUIC transport, cut into five.** The owner ruled on 2026-09-19 that this step is
  five (§12 question 5), after the first part of it showed where the dependencies already cut.
  Only the last waits on chapulin. **Check:** the step 8 simulator checking
  [invariants 17 to 21](invariants.md#quic) after every step; the QUIC Interop Runner's
  `handshake`, `transfer`, `retry`, `resumption`, `keyupdate`, `multiplexing`, `ipv6`,
  `amplificationlimit`, `rebind-port` and `rebind-addr` cases against the endpoint of §9, with
  **exit 127** for everything not yet supported — `connectionmigration` and `zerortt` are
  permanent 127s by decisions 21 and 20. That check belongs to step 9e, because nothing before
  it completes a connection.

- **Step 9a — the frame layer.** Every frame type of RFC 9000 §19, read and written.
  **Check:** each type round-trips, every rule §19 states as a FRAME_ENCODING_ERROR refuses the
  frame it names, and a frame cut anywhere is a truncation that consumes nothing. *Small.*

  **The frame layer, 2026-09-19.** `src/quic/frame/` reads and writes all twenty frame types of
  RFC 9000 §19. It is the piece of this step that needs no key, no handshake and no connection
  state: a frame is read out of octets and written into them, and what it means is the
  connection's business.

  Three types carry their shape in the type itself, and each is decoded into a field so nothing
  downstream reads a bit out of a number: a STREAM frame's OFF, LEN and FIN bits (§19.8), an ACK
  frame's ECN bit (§19.3.2), and the directionality bit of MAX_STREAMS and STREAMS_BLOCKED
  (§19.11, §19.14). A CONNECTION_CLOSE carries the frame type that caused it only when it speaks
  for the transport (§19.19).

  ACK ranges are walked, not expanded. A frame names the largest packet number acknowledged and
  then descends through alternating gaps and runs, so expanding it into a set would cost storage
  proportional to what a peer claims. `AckRanges` keeps the octets and yields one range at a
  time, and the arithmetic is checked once when the frame is read: §19.3.1 makes a computed
  packet number below zero a connection error, so a later walk cannot fail.

  Every rule §19 states as a FRAME_ENCODING_ERROR is enforced and cited on the line that
  enforces it: a range below zero (§19.3.1), a stream or crypto offset past 2^62-1 (§19.8,
  §19.6), an empty NEW_TOKEN (§19.7), a stream limit above 2^60 (§19.11, §19.14), a connection
  ID outside 1 to 20 octets and a Retire Prior To above its own Sequence Number (§19.15), and a
  frame of unknown type (§12.4), which is refused rather than ignored because §12.4 admits no
  extension frame this version does not define.

  `zig build test` passes 734 of 734 and the lint is clean. Two of its rules caught real defects
  while this landed. `peer-index` found the reader's octets being indexed directly, which
  invariant 3 forbids; `core.Reader` now has `consumed_since(mark)`, so a parser that learns a
  structure's length only by reading it still takes its slice from the reader. `rfc-citation`
  found two refusals whose citation sat a line away from the check.

  Mutations: 27 applied, 26 **CAUGHT** and one equivalent. Two gaps were real and both were in
  the tests: three frame types were missing from the round-trip table, so nothing cut a
  CONNECTION_CLOSE short, and nothing checked that a frame too large for the buffer writes
  nothing at all. The equivalent one replaces the bound on the ACK range walk with a huge
  number. Each turn of that loop reads two variable-length integers and each needs an octet, so
  the reader ends the loop whatever the bound says; the bound is there because non-negotiable 4
  asks for one a reader can see.

  **Fuzzing, 2026-09-26.** `frame_fuzz.zig` reads a payload frame by frame, as a connection
  does ([#53](https://github.com/c4milo/colibri/issues/53)). Three things must hold:
  - A refused frame consumes nothing.
  - A frame that is read keeps every rule the writer asserts, so no peer's frame can halt colibri
    when it is written again.
  - A frame is written with the type it was read from, and reads back as the same frame.

  It runs over 23 corpus inputs, most of them one on each side of a §19 refusal, and over every
  input of up to two octets; the fuzzer does not build with Zig 0.16.0 (step 1). 18 mutations,
  18 **CAUGHT** by the fuzz test alone: ten §19 refusals removed or loosened, a refusal that
  consumes octets, three writer faults, and four type bits misread, which the round trip saw only
  once it compared the types.

  **The input check, 2026-09-26.** `src/sim/quic_input_check.zig` gives the QUIC readers inputs
  longer than two octets, as `qpack_input_check.zig` does for QPACK ([#53](https://github.com/c4milo/colibri/issues/53)). Each input starts
  from what colibri's writer produces and takes up to eight edits from `src/sim/input_edit.zig`,
  which gained a fifth edit: an octet moved up or down by one, which takes a value at a bound
  past it. Values are drawn at their bounds, or a few inside, one time in two. The inputs go to:
  - the frame reader, under the rules of `frame_fuzz.zig`;
  - the packet header reader, datagram by datagram, where every packet must lie inside what is
    left and keep its Fixed Bit;
  - the transport parameter reader, under §18.2's bounds, read again without
    `Parameters.valid`.

  What the writer produced must be read whole first. `zig build test-sim-run-quic` runs 256
  seeds of 128 inputs each and pins the census, which Debug and ReleaseSafe agree on:
  `crc32=0x1cfa0ad6`, 54,437 frames read, with every target reaching both outcomes. No input
  halted. 34 mutations, 31 **CAUGHT** by the check alone. The fuzz tests catch the three it
  misses, and a one-octet edit cannot reach two of them: `max_ack_delay`'s bound needs a longer
  encoding than the writer uses, and `active_connection_id_limit`'s is its default, which the
  writer leaves out. The third, a CRYPTO offset one past 2^62-1, did not come up in 32,768
  inputs.

- **Step 9b — packet number spaces, acknowledgments, and how a connection ends.** The three
  spaces of RFC 9000 §12.3, duplicate suppression, ACK generation and processing (§13.1, §13.2),
  the ECN counts (§13.4.1), the idle timeout (§10.1) and the closing and draining states
  (§10.2). **Check:** an ACK frame written from a space reads back through step 9a as the ranges
  the space holds, and both state machines are checked by enumerating every state and event
  pair. *Medium.*

  **The packet number spaces, 2026-09-19.** `src/quic/space/` holds the three spaces of RFC 9000
  §12.3 — Initial, Handshake and Application data — each with its own numbers, its own record of
  what it received, its own ECN counts and its own acknowledgment state. Sharing nothing is the
  point: §12.3 gives the spaces cryptographic separation, and a number means nothing outside the
  one it was used in.

  One structure does two jobs, because both ask which numbers have been processed. §12.3 has a
  receiver discard a packet unless it is certain it has not processed that number before, and
  §19.3.1's ACK ranges are exactly the runs such a record holds. `Received` keeps them
  descending and merges a number that closes a gap, so the ranges are always the fewest that
  describe what arrived, in any order it arrived in.

  Its storage is fixed, which §13.2.3 asks for, and the cost is stated rather than hidden. Past
  the limit the oldest range is dropped — §13.2.3's own remedy — and below what is left §12.3's
  certainty is gone, so a packet there is discarded. A number one below the floor is refused
  too, though it would merely extend the lowest range: the range that held it could have been
  dropped before its neighbour arrived, and extending downward would then take a number this
  endpoint had already processed. That refuses some packets a larger record would accept; it
  never accepts one twice.

  `Space` writes the ACK frame from that record (§19.3), with the ACK Delay measured from the
  instant the largest number arrived and shifted by the endpoint's `ack_delay_exponent` (§19.3,
  §13.2.5, §18.2), and the three ECN counts when the endpoint reports them (§13.4.1, §19.3.2).
  It owes an ACK after two ack-eliciting packets (§13.2.2), and at once when one arrives out of
  order or marked ECN-CE (§13.2.1). `on_ack` reads what a peer's frame said: §13.1 makes an
  acknowledgment for a packet never sent a connection error of PROTOCOL_VIOLATION, and §13.2
  makes acknowledgments irrevocable, so the largest never moves backward. What it does not do is
  loss recovery — nothing here remembers what was sent, so nothing here can call a packet lost;
  RFC 9002 is step 10's, and the report exists for that step to act on.

  Every ACK frame the tests write is read back through the frame layer, so the writer and the
  reader agree about §19.3.1's arithmetic rather than each agreeing with itself.

  `zig build test` passes 750 of 750 and the lint is clean. Mutations: 32 applied, 31 **CAUGHT**.
  The one that was not removed a guard against a space that owes an acknowledgment while having
  received nothing, which no reachable state produces: both counters move only on a packet the
  space processed. It is now an assertion stating that invariant rather than a branch defending
  against it, so a later change that empties a space without clearing them fails at the
  assertion instead of writing an ACK frame with no ranges. Removing the assertion is not caught
  either, and cannot be: no input violates it, which is what makes it an invariant.

  A test of mine was wrong before the code was. It expected a number just below the remembered
  floor to be accepted, and the reasoning in the paragraph above is why it must not be.

  **How a connection ends, 2026-09-19.** `src/quic/termination.zig` holds RFC 9000 §10's idle
  timeout and its closing and draining states. The effective idle timeout is the smaller of the
  two advertised values, or the sole non-zero one, and never below three Probe Timeouts (§10.1).
  Receiving a packet restarts the timer; sending restarts it only when nothing ack-eliciting has
  gone out since a packet last arrived, which is what stops an endpoint that only talks from
  holding a dead connection open. A timeout closes silently, so nothing goes on the wire.

  The two states differ in what may be sent. A closing endpoint answers an arriving packet with
  a CONNECTION_CLOSE frame and nothing else, each answer waiting for twice as many packets as
  the last, which is the rate limit §10.2.1 asks for. A draining endpoint sends nothing at all
  (§10.2.2), and a closing one that hears a close moves to draining, which ends the endless
  exchange of close frames that section warns about — keeping its own reason and the instant its
  period began, because changing state is not a second close. Both periods last three Probe
  Timeouts, which the caller supplies: §10.1 and §10.2 size themselves on it and RFC 9002
  computes it in step 10.

  **How the state machine is checked, and why by no tool.** The transitions are verified by
  enumerating every one: four states by five events, each pair asserted, with a check that the
  table holds each pair exactly once. For a finite machine that is the whole function rather
  than a sample, so a model in a second language would restate the same twenty facts and add a
  source of truth that can drift. The owner asked on 2026-09-19 whether Lean or TLA+ belonged
  here; the answer recorded then was that neither earns its place at this size, that the same
  enumeration covers step 9's stream machines (§3.1, §3.2), and that the case for TLA+ — not
  Lean, which suits pure functions, as chapulin's use of it shows — arises only for properties
  that quantify over interleavings of two endpoints, which the step 8 network check samples
  rather than covers. Adding one is a new dependency and so the owner's call, to be made against
  a specific property that resists both an enumeration and a simulator invariant.

  Mutations: 22 applied, all **CAUGHT**. Two needed tests first: nothing called the
  instant-passing entry point on an active connection, and the check that a draining endpoint
  stays silent was masked, because the counter it reads stops moving once draining begins.

  **The TLA+ model, 2026-09-26** ([#51](https://github.com/c4milo/colibri/issues/51)).
  - `spec/tla/quic_close` models two endpoints ending a connection as colibri does: the idle
    timeout (§10.1) with its rule for restarting on a send, the immediate close, and the closing
    and draining states (§10.2), over a network that loses packets and delivers some a tick late.
    Time moves in ticks of one PTO, so the idle timeout, the PTO and its doubling, and the three
    PTOs of each period are checked against each other. Either endpoint may close first, both may
    close at once, and any CONNECTION_CLOSE may be lost. The properties: a closing endpoint sends
    CONNECTION_CLOSE alone and a draining or closed one sends nothing; a closing endpoint's
    answers back off, so after n answers it has received at least 2^(n-1) packets; and once
    either endpoint leaves "active", both reach "closed".
  - It found no defect, and one sentence above that no longer holds. `Termination` moves a closing
    endpoint that hears a close to draining, but the connection never asks it to:
    `connection_datagram.receive` takes no frame while closing, as §10.2.1 allows. The rate limit
    is what ends an exchange of closes, and the model checks that it does.
  - What `zig build tla` printed, on macOS arm64:
    - holds, as expected: `colibri`, both endpoints may close and neither sends data, 3996
      distinct states; `talker`, one closes while the other sends a packet every tick, 127762;
    - violated, as expected: `no_idle`, with no idle timeout a peer whose CONNECTION_CLOSE was
      lost and that has nothing to send never ends; `restart_every_send`, restarting the idle
      timer on every ack-eliciting send keeps a peer that talks into a closed connection alive
      for good, which is why §10.1 restarts it only on the first; `no_rate_limit`, two endpoints
      closing at once answer each other without backing off.
    - Run once and not kept, because it takes seven minutes: both endpoints closing while one
      talks, with one loss, holds over 2242541 distinct states.

  **The ACK ranges proved, 2026-09-26.** `spec/lean/Colibri/Quic/AckRanges.lean` states RFC 9000
  §19.3.1's ranges as `frame_ack.zig` reads them and as `write_ack_at` in `space.zig` writes them,
  and proves:
  - `decode_encode`: ranges that descend with an unacknowledged number between each two, as
    `space_received.zig` keeps them, read back from what the writer writes;
  - `encode_decode` and `decode_wellFormed`: whatever the reader accepts is such ranges, and the
    writer writes them back as the same fields;
  - `decode_none_iff`: the reader refuses a frame exactly when a packet number §19.3.1 computes
    over the integers is below zero, which is that section's FRAME_ENCODING_ERROR.

  `src/quic/frame/frame_ack_vectors.txt` holds 205 frames, 32 ranges long at most, and what the
  reader gives each. `src/quic/space/space_ack_vectors.txt` holds the 74 distinct sets of ranges
  the reader accepts, and the fields the writer writes for each. A test beside each requires the
  Zig code to give them. Mutations: 14 over the reader, its iterator, `smallest_acknowledged` and
  the writer, each **CAUGHT** by those tests. One, a writer that counts the next gap down from a
  range's largest, was caught only after the vectors gained ranges of two numbers between two
  others. 3 mutations in the Lean definitions stop the proofs, and 1 edit to a vector file is
  refused by `zig build lean`.

- **Step 9c — streams and flow control.** RFC 9000 §2.1's identifiers, §3.1's sending state
  machine and §3.2's receiving one, §4.5's final size, §4.1's stream and connection flow
  control, and §4.6's stream limits, with the blocked frames each produces. **Check:** every
  state and event pair of both machines enumerated; a sender never exceeds either limit and a
  receiver refuses a peer that does, with FLOW_CONTROL_ERROR and STREAM_LIMIT_ERROR where §4.1
  and §4.6 name them. *Large.*

  **The identifiers and both machines, 2026-09-19.** `src/quic/stream/` holds RFC 9000 §2.1's
  identifier, with the two low bits read in one place, and the two state machines, which stay
  separate because neither half can observe the other's states: a receiver never sees the
  sender's "Ready", and a sender never sees when the application read the data. §4.5's final
  size rules are enforced rather than reported, because they are about numbers this code holds:
  a size that changes, a size below what already arrived, and data reaching past a known size
  are all FINAL_SIZE_ERROR. §4.5 lets an endpoint skip those to spare itself state on closed
  streams; colibri holds the state while the stream exists, so it answers.

  `src/quic/error_code.zig` names RFC 9000 §20.1's transport error codes once, so no file in
  `quic` writes one inline and the same rule closes with the same number everywhere.

  Both machines are checked by enumerating every state and event pair, 30 and 36 of them, with
  a check that each table holds each pair exactly once and that a terminal state is left by
  nothing. Mutations: 26 applied, all **CAUGHT**. Three gaps, and two of them were dead code
  rather than missing tests — a term in `is_receivable_by` that could never change the answer,
  because the peer may always send on a bidirectional stream, and an offset recorded on reset
  that nothing reads once a final size is known. The third was a real gap: data arriving out of
  order, where a later frame reaching less far must not lower the mark §4.5's "below what
  arrived" check rests on.

  **Flow control and the table, 2026-09-19.** `src/quic/flow.zig` holds both levels of §4.1 and
  the stream counts of §4.6, because all four counters a connection has are one shape: a limit
  the peer advertises, a total spent against it, and §4.1's and §4.6's shared rule that a larger
  limit replaces a smaller one while a smaller one is ignored. The receiving half is its own
  type, because a peer that passes a limit is an error and not a wait — FLOW_CONTROL_ERROR for
  data, STREAM_LIMIT_ERROR for streams — and because credit is measured from what the
  application read rather than what arrived, which is what stops a stalled reader advertising
  room it does not have.

  The receive window grows ([decision 49](decisions.md#memory), ruled the same day). A window
  that never grew would cap one stream at `window / round trip` whatever the path can carry, so
  when credit goes out the receiver asks how long since it last sent some: inside two round
  trips means the application drained it faster than the peer could learn of the room, and the
  window doubles, to a cap. The instant and the round trip are parameters, because colibri reads
  no clock and RFC 9002 computes the round trip in step 10; a caller with no estimate passes 0,
  which grows nothing, so this works today and sharpens when step 10 lands. The cap is what
  keeps [decision 35](decisions.md#memory)'s comptime worst case true. A stream count never
  tunes: §4.6's limit counts streams rather than octets, and the table bounds it instead.

  `src/quic/stream/stream_table.zig` holds the streams of a connection against their
  identifiers, over the pool of [decision 14](decisions.md). Its per-class watermark is what
  makes §3.2's rule cheap — before a stream is created every lower-numbered stream of its type
  must be, so a frame naming the eleventh stream of a type creates the ten below it, and the
  watermark says where to start. That rule is also why the advertised limit is capped at the
  table: an advertised limit is a promise to hold that many streams at once, and a limit past
  the table would be a promise it cannot keep. `core.Pool` gained `watermark_of` for it.

  Writing the table found a defect in it. `open_peer` on a stream that already existed walked
  past it and filled the table; it now takes an unopened identifier only, and the caller reads
  `lookup` first, because a frame for an open stream names that stream and one for a closed
  stream is judged by §3.3 against the frame's type — neither being that call's to decide.

  Mutations: 31 applied over the flow control, the table and the pool's new accessor, all
  **CAUGHT**.

  **9c is done.** `zig build test` passes 790 of 790 and the lint is clean.

  **The TLA+ model, 2026-09-26** ([#47](https://github.com/c4milo/colibri/issues/47)).
  - `3c1fe58`: `spec/tla/quic_stream_flow` models one stream and the connection's flow control
    as colibri keeps them: RFC 9000 §3.1's and §3.2's states, STREAM, RESET_STREAM and
    STOP_SENDING, both limits with their MAX_* and BLOCKED frames, §13.3's rule that a lost frame
    is sent again only when it was the most recent of its kind, and step 9e's BLOCKED repeat
    ([#43](https://github.com/c4milo/colibri/issues/43)). The network loses, reorders and
    duplicates frames and acknowledgments, and the idle timeout of §10.1 closes a connection with
    nothing in flight, nothing owed and no shorter timer armed. The properties: no limit is
    passed, a final size never changes, "Data Recvd" comes only with every octet, a stream done
    at the receiver has given all its connection credit back, no frame goes out that §3.3
    forbids, and a blocked sender is released and the stream finishes.
  - It found a defect. A RESET_STREAM's final size counted against the connection's limit, but
    the octets the application never read were never consumed, so MAX_DATA was measured short of
    them from then on; once reset streams held more than half the window, the other streams stalled
    for good. §4.5 calls the final size "the amount of flow control credit that is consumed by a
    stream", and `a19f0f8` has `take_reset` consume the unread octets for the connection.
  - What `zig build tla` printed, on macOS arm64:
    - holds, as expected: `colibri`, 935365 distinct states; `windows`, 35923;
    - violated, as expected: `no_repeat`, a blocked sender whose peer reads late loses the
      connection to the idle timeout without the BLOCKED repeat; `no_resend`, a lost MAX_DATA or
      MAX_STREAM_DATA that is not sent again leaves the sender blocked, because colibri answers
      a BLOCKED frame with nothing; `reset_leak`, the path the fix closes.
  - The fix's mutations, against `zig build test-quic` alone: 3 **CAUGHT**.

- **Step 9d — connection IDs, path validation and anti-amplification.** NEW_CONNECTION_ID and
  RETIRE_CONNECTION_ID (RFC 9000 §5.1), PATH_CHALLENGE and PATH_RESPONSE (§8.2), the
  anti-amplification limit of §8, and the Stateless Reset of §10.3 — its §10.3.1 half here, with
  §10.3's writer landing later, `9d902e1`.
  `disable_active_migration` per [decision 21](decisions.md), which saves less than it sounds
  like. **Check:** [invariants 18 to 20](invariants.md#quic) asserted in the step 8 simulator
  after every step. *Medium.*

  **Done, 2026-09-19.** Three files, one per rule set.

  `src/quic/connection_id.zig` holds the two sets, which are not symmetric: the peer's, which
  this endpoint writes into a Destination Connection ID field, and its own, which it accepts
  there. §5.1.2's ordering is the part that is easy to get wrong and is written out — the
  connection IDs below a frame's Retire Prior To are retired **before** the one it carries is
  added, because the other order can push the count past `active_connection_id_limit` for an
  instant, which §5.1.1 makes a CONNECTION_ID_LIMIT_ERROR. §19.15's tolerance is there too: the
  same frame twice is ordinary, and the same sequence number carrying a different connection ID
  is a PROTOCOL_VIOLATION.

  `src/quic/path.zig` holds §8's anti-amplification limit and §8.2's validation, which are one
  mechanism from two sides: an unvalidated path may take three times what it gave
  ([invariant 18](invariants.md#inv-18--the-anti-amplification-limit-holds)), and validating it
  is what lifts that. Whether a path is validated and whether a probe is outstanding are
  separate fields, and the reported state is derived from both.

  `src/quic/stateless_reset.zig` splits §10.3 where the entropy falls. Detecting a reset is
  colibri's, because §10.3.1 fixes when the comparison happens and against what — the tokens of
  connection IDs this endpoint has used and not retired, never the others — and the comparison
  reads every octet of every token, which §10.3.1 requires so the value cannot leak through
  timing. Sending one is the caller's: §10.3 wants the octets before the token
  indistinguishable from random and colibri draws no random number (invariant 5). What colibri
  gives is the arithmetic, `permitted_len`, which holds both size rules at once — smaller than
  the packet that triggered it (§10.3.3), so a loop dies out, and under three times it (§10.3),
  so the answer cannot amplify.

  Two defects surfaced while writing, both colibri's own. The repeat check for a
  NEW_CONNECTION_ID swallowed §19.15's rule that a connection ID arriving below the current
  Retire Prior To still owes a RETIRE_CONNECTION_ID; those are two questions and are now two
  checks, with a bounded record so "unless it has already done so" survives the queue draining.
  And path validation was modelled as one state, so challenging a path forced it out of
  validated — which §8.2.1 permits at any time and §8.2.3 *requires* when the first datagram
  was too small to test the MTU. A crashing test found it.

  Mutations: 46 applied over the three, all **CAUGHT**. Five needed work first: three tests that
  could not tell the mutant from the code — a retire mark with nothing active at it, a datagram
  exactly at the amplification limit, and a sequence number at the top of what was issued — and
  two more dead assignments, a cleared "already reported" mark and a cleared abandonment that
  nothing reads while a probe is outstanding.

  `zig build test` passes 809 of 809 and the lint is clean. What 9d still owes is its check,
  which is the step 8 simulator asserting invariants 18 to 20 after every step; that needs a
  connection to drive, so it lands with 9e.

  **The TLA+ model, 2026-09-26** ([#50](https://github.com/c4milo/colibri/issues/50)).
  - `spec/tla/quic_connection_ids` models the IDs a peer issues and colibri uses and retires:
    NEW_CONNECTION_ID with Retire Prior To, RETIRE_CONNECTION_ID, the limit of §5.1.1 and the
    order §5.1.2 puts retiring before adding, over a network that loses and reorders frames and
    sends lost ones again (§13.3). The properties: colibri holds no more active IDs than its limit;
    it sends no packet to an ID it retired; no RETIRE_CONNECTION_ID names its own packet's ID
    (§19.16); and every ID below a Retire Prior To the peer sent is retired in the end.
  - It found three defects.
    - The peer's handshake ID, sequence number 0, was never in the set: only NEW_CONNECTION_ID
      filled it. A Retire Prior To above 0 therefore never retired it, and it did not count
      against the limit.
    - Every short header went to that handshake ID, whatever the set held, so colibri kept
      sending to an ID the peer had asked back, which §5.1.2 says the peer "MUST stop using".
    - A retirement past the queue of ones awaiting acknowledgment was dropped, where §5.1.2 says
      "An endpoint MUST NOT forget a connection ID without retiring it". It now closes with
      CONNECTION_ID_LIMIT_ERROR, which the same paragraph allows.

    The fix holds sequence number 0 from the peer's first Source Connection ID, addresses short
    headers to the set's active ID, and closes on a full queue. It also found a field,
    `Remote.highest_offered`, that is written and never read.
  - What `zig build tla` printed, on macOS arm64:
    - holds, as expected: `colibri`, 109398 distinct states; `rotate_early`, a peer that raises
      Retire Prior To before its older IDs are retired, 30712;
    - violated, as expected: `pinned`, colibri before the fix, where sequence number 0 is never
      retired; `no_follow`, a packet sent to a retired ID; `forget`, a retirement dropped from a
      full queue, which the peer then never receives.
  - The fix's mutations, against `zig build test-quic` alone: 9 applied, 8 **CAUGHT**. The header
    length mutant needed a test with a peer ID longer than the handshake's first. The one not
    caught set `highest_offered` for sequence number 0, which nothing reads, and the line is gone.
    `aebc502` then removed the field, its doc comment and its remaining two writes.
    `tools/quic_udp.sh` and `tools/quic_aioquic.sh` pass against the fix.

- **Step 9e — the handshake over CRYPTO frames, and the interop runner.** CRYPTO frame
  reassembly by offset, the handshake driven through `tls.Provider`'s QUIC mode, and the
  transport parameters of §7.4. **This is the only part of step 9 that waits on chapulin**: its
  `ch_quic_*` calls were stubs until 2026-09-20, when chapulin implemented all fifteen; the
  client role is on its `main` and the server role has no driver yet. **Check:** step 9's,
  above. *Large.*

  **This step is about ten pieces, and only the last needs chapulin, 2026-09-20.** Steps 9a to 9d
  built ten leaves and nothing joining them: no `Connection` exists in `src/quic/`, nothing
  declares three `Space`s, and the simulator's QUIC checks drive modules one at a time. What 9e
  owes is the assembly — a receive path, a frame dispatch loop, a datagram send path with §12.2's
  coalescing and §14.1's padding, CRYPTO reassembly per level, the key-schedule timing calls of
  RFC 9001 §4.9 and §6, Retry and version negotiation — plus three things that do not exist at
  all: `tls.Provider`'s QUIC mode, the transport parameters, and a simulator connection check.
  The test-only endpoint and `tools/interop.sh` are the only part that waits on chapulin.

  `src/tls/tls.zig` said QUIC mode "lands with design §8 step 7". It did not: step 7 shipped the
  packet formats and, after [decision 48](decisions.md#what-the-caller-supplies), a
  `crypto.Suite` that protects packets and drives no handshake. The comment is corrected.

  **The transport parameters are done, 2026-09-20.** `src/quic/transport_parameters.zig` holds
  RFC 9000 §18.2's seventeen parameters, their defaults and the writer;
  `transport_parameters_read.zig` holds the reader. Every value is stored inline, so a
  `Parameters` is one struct the caller owns.

  A default is not an absence, and four of §18.2's are not zero: `max_udp_payload_size` is 65527,
  `ack_delay_exponent` is 3, `max_ack_delay` is 25 milliseconds and `active_connection_id_limit`
  is 2. `Parameters.initial()` is what an empty extension means, the reader starts from it, and
  the writer leaves out any value that equals its default — so two endpoints agreeing on
  everything exchange no octets at all, which one test pins.

  Two things are read past rather than kept. `preferred_address` is skipped by the length every
  parameter carries, because [decision 21](decisions.md) refuses migration in both directions and
  §9.6 makes using one a MAY. And a repeat of an identifier colibri does not know goes
  undetected, although §7.4 forbids a repeat of any parameter: detecting it means holding every
  identifier a peer chose to send, which is the trade the ACK range walk of §19.3.1 already
  refuses, and §18.1 gives an unknown parameter no semantics to conflict with.

  **Fuzzing, 2026-09-26.** A fuzz property reads each input as a client's extension and as a
  server's ([#53](https://github.com/c4milo/colibri/issues/53)). An accepted extension must keep §18.2's bounds and each value's shape. It
  must name no §18.2 identifier twice (§7.4), and a client's must name no server-only one.
  Written again, it must read back the same. Its 20 corpus inputs sit on each side of every
  bound. 10 mutations, 10 **CAUGHT** by the fuzz test alone, two of them only after it checked
  each value's shape.

  **The connection exists, 2026-09-20.** `src/quic/connection/connection.zig` is what joins the
  ten pieces steps 9a to 9d built: three packet number spaces paired with three encryption
  levels, the CRYPTO stream of each, the stream table, both levels of flow control, the
  connection IDs each side holds, the path, the termination state and RFC 9002's recovery. Every
  one was tested alone; what is new is that they belong to one connection and agree about it.

  It holds no key, no socket and no provider — a test refuses a field whose name says otherwise,
  because the keys are the caller's `crypto.Suite` (decision 48) and the handshake is the
  caller's `tls.QuicProvider` (decision 8). It reads no clock: `init` takes the instant.

  The shape worth naming is that a connection starts not knowing what its peer will accept. RFC
  9000 §7.4 carries the peer's parameters in the handshake, so what colibri may spend against
  begins at zero and `apply_peer_parameters` raises it. That is not a special case: §18.2 says a
  stream limit that is "absent or zero" means the peer cannot open streams until a MAX_STREAMS
  frame, which is the state a connection begins in. What colibri *grants* is its own parameters
  and is in force from the first packet.

  Mutations: seven applied, all **CAUGHT** — a level paired with the wrong space, colibri
  spending its own grant instead of the peer's, the send window starting at colibri's own limit,
  the peer's parameters not raising it, an idle timeout of zero arming the timer instead of
  disabling it, every level answering one CRYPTO stream, and the idle timeout read as nanoseconds
  rather than milliseconds.

  **The handshake over CRYPTO frames runs, 2026-09-20.** `connection_crypto.zig` is the wiring
  step 9e is named for, and it owns none of the three things it joins: `crypto_stream` turns the
  peer's frames into an in-order run per level, the caller's `tls.QuicProvider` consumes it and
  produces what colibri owes back, and `quic.frame` writes that into CRYPTO frames. No key passes
  through it — decision 48 sends the secrets from the provider to the suite inside the caller's
  code.

  The transport parameters are part of the handshake rather than something beside it: RFC 9001
  §8.2 carries them in a TLS extension, so `take_peer_parameters` reads the peer's out of the
  provider and gives them to the connection, which is what raises every limit colibri may spend
  against. Its absence is only fatal once the handshake completes, because a client has not read
  EncryptedExtensions before then; `require_peer_parameters` is where §8.2's MUST is applied.

  Each failure carries the code RFC 9000 §20.1 gives it, and an alert is not among them: RFC 9001
  §4.8 makes its code the description plus 0x0100, which `alert_error_code` computes.

  Mutations: six applied, all **CAUGHT** — octets handed to the provider twice, every frame
  claiming offset 0, the peer's parameters read under colibri's own role, and three failures
  closing with the wrong code. Writing them found a weak test: the parameters it exchanged held
  nothing server-only, so reading them under the wrong role would have passed. It now carries a
  stateless reset token, which only a server may send.

  **What 9e still owes, 2026-09-20.** Five agents mapped the remaining work against the vendored
  RFCs and a sixth checked every claim they made against the tree. The list is longer than the six
  items this paragraph used to hold, and it is ordered: each piece needs the ones above it. The
  four prerequisites are done and struck through; the entries below say what each one printed.

  1. ~~Connection identity.~~ **Done, `da116dd`.** `connection_identity.zig` holds §7.3's five
     values, apart from the §5.1 set `connection_id.Local` holds. `destination` is derived from
     Figures 7 and 8 read in order, and `describe` writes the three parameters so the extension
     cannot disagree with the headers.
  2. ~~The client's path, and a read-only duplicate query.~~ **Done**, `8f3152e` and `52c71f1`.
     The limit is the server's (§8.1, §21.1.1.1) and a client had been unable to send its first
     Initial; `Space.duplicate_verdict` is the read-only half §12.3 needs.
  3. ~~Key-schedule state.~~ **Done, `b9ae985`.** `connection_keys.zig` holds invariant 21's
     none, available or discarded per level and direction, which `keys_available` cannot answer,
     and `can_open` asks the handshake as well because of §5.7. §4.9's triggers are there; §6's
     key update is piece 7.
  4. ~~A null `tls.QuicVTable`.~~ **Done, `cc93d7a`.** `src/sim/null_quic_provider.zig` carries a
     pair through §4.1.5's Figure 5 to §4.1.1's completion, framing each message as RFC 9846 §4
     frames one. No check drives it through `connection_crypto.zig` yet: `sim` is given only
     `core`, `tls` and `crypto`, so that check belongs in the `sim_run_quic` module with piece 10.
  5. ~~The receive path — one datagram walked into packets and frames.~~ **Done**, and recorded
     below.
  6. **The send path** — §12.2's coalescing and §14.1's padding, into a buffer the caller owns.
  7. ~~Key-update timing.~~ **Done**, `4d0cc65` and `871d034..ac522a2`, and recorded below. All
     of RFC 9001 §6, at the call sites pieces 5 and 6 own.
  8. ~~Version negotiation.~~ **Done, `fc2a6ae`**, and recorded below. `connection_version.zig` holds §6's
     two connection-level decisions, above the packet `packet/invariant.zig` already read and
     wrote.
  9. ~~Retry, with §7.3's validation.~~ **Done**, `bb33948` to `89a4bfa`, and recorded below.
     Both halves of §17.2.5, §8.1.2's token, and the connection IDs §7.3 authenticates.
  10. ~~The simulator connection check for invariants 17 to 21.~~ **Done**, `79d8d29`, and
      recorded below.
  11. **The test-only endpoint and `tools/interop.sh`**, which is the only part that waits on
      chapulin, whose QUIC server has not yet exchanged a packet with any implementation.

  **The receive path is done, 2026-09-20.** A datagram arrives from the caller and comes apart
  into packets, then frames, then acts on the connection. Seven commits: the read-only duplicate
  query (`52c71f1`), §12.4's permitted-frame table (`b64307d`), §12.2's coalescing walk
  (`8befbd5`), the frame dispatch (`391da52`), the frames naming a stream (`3c0a31f`), the
  connection ID and path frames (`37f2450`) and §19.16's in-use refusal (`a4f0881`).

  The shape worth naming is where a rule stops being a discard and starts being a connection
  error. Everything `connection_receive.zig` does is a discard, because until the AEAD tag matches
  nothing in a packet is the peer's word for anything: §12.2 has the walk carry on past a packet
  it could not read and RFC 9001 §5.5 forbids closing on one. Once the tag matches,
  `connection_frames.zig` applies §12.4's refusals and every rule §19 states, each with its own
  code.

  Two rules pull against each other and the split between asking and recording is what settles
  them. §12.3 wants a duplicate suppressed before the packet is processed and §13.1 forbids
  recording it for acknowledgment until every frame has been. One call could not do both, so
  `Space.duplicate_verdict` is the read-only half and `Space.receive` is what the caller records
  with afterwards.

  Two checks colibri makes that the RFC leaves optional, both for the reason design §8 step 9c
  already gave — colibri answers an optional check it has the state for. §19.16's "MUST NOT refer
  to the Destination Connection ID field of the packet in which the frame is contained" is a MAY
  for the receiver, and `connection_id.Local` now keeps octets so it can answer; §5.1.1 makes the
  identity's own Source Connection ID sequence number 0, which is what gives a packet a connection
  ID to name from the first flight. And §4.5's final size rules are answered while a stream
  exists, though not after it closes, because §4.5 says generating them "is not mandatory" exactly
  when an endpoint would have to keep state for closed streams, and colibri keeps none.

  One check was left unmade there and is now made: §8.2.3's path MTU. `take_path_response` passed
  a hard-coded false, so the second validation was owed after every probe. `Path.Challenge`
  remembers instead, and `on_challenge_sent` takes the datagram's length rather than a flag, so
  §8.2.1's 1,200 octets are compared in one place. Recorded below, `4aafd03`.

  **Version negotiation is done, 2026-09-20.** RFC 8999 §6 defines the packet for every version
  of QUIC and `packet/invariant.zig` already read and wrote it. What `connection_version.zig`
  adds is RFC 9000 §6's two decisions: when a server owes one, and what a client does with one.

  The server's half takes no `Connection` and takes a datagram rather than a packet. §6.1 says
  the scheme "allows a server to process packets with unsupported versions without retaining
  state", so there is no connection to take. §17.2.1's "A server MUST NOT send more than one
  Version Negotiation packet in response to a single UDP datagram" is then kept by the shape of
  the call — one datagram in, at most one packet out — rather than by counting what was sent.
  §17.2.1 also forbids a version-specific rule from reaching the decision, which is why the
  datagram is read through `invariant.read_long`: that reader cannot apply one, so a 255-octet
  connection ID is echoed although version 1 stops at 20.

  A client checks that both connection IDs echo what it sent. §17.2.1 states those two echoes as
  rules on the server and their purpose on the client — they give "some assurance that the
  server received the packet and that the Version Negotiation packet was not generated by an
  entity that did not observe the Initial packet" — so the check is step 9c's precedent again,
  colibri answering an optional check it holds the state for. What turns on it is abandoning the
  connection attempt, which an off-path sender must not be able to cause.

  §6.2's "received and successfully processed any other packet" is read off the three spaces,
  because the caller records a packet in one once its frames have been processed, which is what
  the phrase names. Two packets leave no such record and are read separately: an earlier Version
  Negotiation packet acted on, which left the connection no longer active, and a Retry, which
  §17.2.5.2 gives no packet number for a space to hold.

  24 mutations, 24 CAUGHT. Two of them only after a test was written: `answer` guards an empty
  datagram and a header cut short, and nothing passed it either.

  Mutations: 44 applied across the seven commits, 38 CAUGHT first time and one a no-op control
  that correctly was not. Five gaps, every one in the tests rather than the code, and all of one
  shape — a test that checked a length or a wrapper where the distinguishing thing was elsewhere.
  A payload slice taken one octet early kept the right length. Three of §18.2's stream data
  parameters were set to one value, so swapping two was invisible. A retransmission reaching the
  same distance did not separate a high-water mark from a running total. A stream limit was read
  through the error the dispatch flattens it to rather than its own. And no test had a client
  process a Handshake packet, which is the trigger RFC 9001 §4.9.1 gives the other role.

  `zig build test` passes and `zig build lint` and `zig fmt --check` are clean after each commit.

  **Seven more things 9e owes that no piece above claims.** ~~Sending a CONNECTION_CLOSE that
  carries an error code~~ is done, `368344e`, and recorded below. ~~Driving the timers, which is
  one deadline out and one instant in (§4.2)~~ is done, `18e9949`, and recorded below.
  ~~Generating a PATH_CHALLENGE and running §8.2's validation~~ is done, `10aabc5`, and recorded
  below. ~~Validating the ECN counts a peer reports (§13.4.2)~~ is done, `ab178c3`, and recorded
  below. ~~Sending a Stateless Reset (§10.3)~~ is done, `9d902e1`, and recorded below.
  ~~Retransmitting a lost packet's frames under a new number~~ is done for every frame colibri
  sends, `79d5dd9` and `a15af0f`, and recorded below; §13.3's other rules land with the senders
  they belong to. Scheduling the application level's frames. And golden corpus cases for the receive path's
  new refusals, with their entries in `src/golden/mutations.zig`.

  **The CONNECTION_CLOSE writer is done, 2026-09-20**, `368344e`. Reading the peer's frame was
  already `connection_frames.zig`'s; `connection_close.zig` is the other half, and every piece
  above had been naming connection errors that nothing could send.

  RFC 9000 §10.2.3 is the whole of it, and its rule is about keys rather than about closing.
  §10.2.3 states the goal — "the goal is to ensure that the peer will process the frame" — and
  before the handshake is confirmed neither endpoint knows for certain which keys the other
  holds. So the frame goes out at every level that can seal one, §12.2 coalesces those into a
  single datagram, and the peer reads whichever copy it can open. A test pins the reason: a
  client that has not completed its handshake cannot open the 1-RTT copy at all (RFC 9001 §5.7),
  and it is the Initial and Handshake copies that reach it.

  §12.5 confines a type 0x1d frame to the application packet number space, so `frame_for` writes
  §10.2.3's replacement below it: type 0x1c, APPLICATION_ERROR, and the Reason Phrase cleared,
  because §10.2.3 says otherwise "information about the application state might be revealed".
  The Reason Phrase is the caller's octets and colibri copies none of them (decision 35); a
  reason that will not fit the packet is dropped rather than the frame, which §19.19 allows by
  making the field able to be zero length.

  Two rules turned out to be owned already and one was not. §10.2.1's rate limit is
  `Termination.permission`, which answers a closing endpoint on a doubling count of received
  packets. §10.2.1's "limit the cumulative size of packets it sends to an unvalidated address to
  three times the size of packets it receives" is §8's limit, which `Path` already holds — and
  checking it here is what exposed the defect below. §10.2.2's MAY, a single close before
  entering the draining state, is declined: `on_close_received` enters draining at once.

  21 mutations, 21 CAUGHT, three of them only after a test was written.

  **A fourth defect, found while building the close writer**, `64c13a2`. `connection_send`
  asserted RFC 9000 §8.1's anti-amplification limit after sealing instead of bounding the
  datagram by it: `datagram_ceiling` never read `Path.send_allowance`, so a server that had
  received nothing halted rather than answering that it had nothing to send. That is the
  ordinary state of every server at the start of a connection, not colibri's own defect, and
  the file header already said the limit was checked before the datagram was returned. No test
  had ever sent from a server with a zero allowance.

  **Key-update timing is done, 2026-09-21**, `4d0cc65`. `connection_key_update.zig` is RFC 9001
  §6, which is timing and nothing else: colibri holds no key, so every rule in §6 is about when it
  calls `crypto.Suite.update_keys` and when it refuses. Both call sites existed already and
  neither used the answer — `packet_build.zig` wrote the Key Phase bit as a constant 0, and
  nothing read the `key_set` that `crypto.Suite.open` reports.

  §6.1 states its own recipe — "tracking the lowest packet number sent with each key phase and the
  highest acknowledged packet number in the 1-RTT space" — so `Connection` gains
  `phase_lowest_sent` beside the `current_phase_lowest` §6.5 already needed. The first update is
  held to that rule as well as a subsequent one, because §6.1's recipe does not except it and a
  phase nothing was sent in is one no peer can have acknowledged.

  Two refusals are the peer's to trigger and both carry KEY_UPDATE_ERROR (§6.7): §6.2's second
  update, before this endpoint acknowledged the first under the new keys, and §6.4's packet opened
  with old keys above the lowest number the current keys opened. A third failure is not the
  peer's — a suite that opens a packet with its next keys and then refuses to move to them — and
  it closes with INTERNAL_ERROR, which RFC 9000 §11 gives an endpoint with no more specific code.

  Three rules of §6 were left without a call site and each has one now, recorded below. 20
  mutations, 20 CAUGHT, one of them only after a test was written: a 1-RTT space the peer had
  acknowledged nothing in read as acknowledged, because no case had sent a packet without also
  recording an acknowledgment. `zig build test`: 1155 passed, 18 skipped.

  **The handshake's connection IDs are authenticated, 2026-09-21**, `bb33948`. RFC 9000 §7.3
  says "Endpoints MUST validate that received transport parameters match received connection ID
  values", and nothing did: `connection_identity.zig` held §7.3's five values and wrote its own
  into the parameters colibri sends, and the peer's arrived unchecked.

  §7.2's half was missing too, and it is what makes §7.3's possible. `Identity.on_peer_initial`
  had no caller outside a test, so a client never addressed the Source Connection ID the server's
  Initial carried and there was nothing to hold the peer's parameter to. It is now taken off the
  first long-header packet that opened — never off one that did not, because until the AEAD tag
  matches nothing in a packet is the peer's word for anything — and a later long header carrying a
  different Source Connection ID is discarded, which §7.2 requires of both roles.

  `authenticate` runs before the peer's limits are raised, so parameters that fail §7.3 never
  widen what colibri may spend. Every failure carries TRANSPORT_PARAMETER_ERROR: §7.3 mandates it
  for the absent parameters and permits it for the rest, so one code answers the whole section.

  17 mutations, 16 CAUGHT. The survivor compared connection IDs by prefix, which no case
  separated because every pair a test used was the same length; §7.3's "If a zero-length
  connection ID is selected, the corresponding transport parameter is included with a zero-length
  value" is the case that does, and it is now a test.

  **A client acts on a Retry, 2026-09-21**, `20e51c0`. `packet/packet_header.zig` could read a
  Retry packet and nothing decided what to do with one. `connection_retry.zig` is that decision:
  RFC 9000 §17.2.5.2's refusals, the Retry Integrity Tag checked over the pseudo-packet RFC 9001
  §5.8 defines, and what a Retry that survives changes.

  Nothing in a Retry is protected, which §17.2.5 says in as many words, so every rule is a discard
  and none is a connection error. Two of the refusals are §7.2's work from the commit above:
  "After the client has received and processed an Initial or Retry packet from the server, it MUST
  discard any subsequent Retry packets" is `retry_source` and `peer_initial_source` being null.

  colibri installs no key. RFC 9001 §5.2 changes the Initial keys with the Destination Connection
  ID, so `Taken` reports the Retry's Source Connection ID and the caller installs over it, exactly
  as it installed the first set — the shape decision 48 already had. A token longer than decision
  54's `token_len_max` is discarded, because §8.1.2 has the client repeat the token in every later
  Initial and one it cannot hold is one it cannot answer.

  12 mutations, 11 CAUGHT. The survivor sized an Initial's header without its Token field, which
  no case separated because what bounded every payload was what the provider owed rather than the
  room the header left. A packet built into an output the payload fills is the case that does.

  `zig build test`: 1190 passed, 18 skipped.

  **Each CRYPTO stream keeps what it sent, 2026-09-21**, `fd97a12`. RFC 9000 §17.2.5.3: "A
  client MUST use the same cryptographic handshake message it included in this packet." The
  provider gives its octets up once — `write_handshake` is a drain — and `CryptoStream` held
  `sent_len` and no octets, so the Initial that answers a Retry could not be written. The owner
  ruled a per-level send window on 2026-09-21; `crypto_send_buffer_len` is its size, a judgement
  set equal to the window §7.5 fixes for the other direction, and three of them sit in every
  connection.

  The window forgets only octets it has already framed, and only when it has no room left. A
  flight that fits is therefore never forgotten, which is what makes a repeat possible; a longer
  one carries on at the offset it reached rather than stalling, which a window anchored at zero
  would have done. A Retry arriving after a flight was forgotten is discarded, because colibri
  cannot repeat what it no longer holds.

  The same window is what §13.3's retransmission will read, which is why it is per level and not
  a copy of the client's first flight. When the sent-packet table records which frames a packet
  carried, the window can be anchored at what the peer acknowledged instead of at what was framed.

  8 mutations, 8 CAUGHT, two only after a test was written: one framed the provider's octets
  without keeping them, which no case separated because none sent anything twice; and one forgot
  a flight that fits as soon as the next packet asked for room, which no case separated because
  none asked for room between framing and repeating.

  `zig build test`: 1196 passed, 18 skipped.

  **The server writes a Retry, 2026-09-21**, `89a4bfa`. Decision 55's two members land on
  `crypto.Suite`, which makes twelve: RFC 9000 §8.1.4 wants an address validation token
  authenticated and expiring, and non-negotiables 2 and 3 leave colibri neither a key nor a clock.
  Decision 48's list and invariant 23 move with them, which is the procedure invariant 23 exists
  to force.

  `answer` holds nothing, because §8.1.2 says a Retry is how a server "defers the state and
  processing costs of connection establishment". §17.2.5.1's "A server MUST NOT send more than one
  Retry packet in response to a single UDP datagram" is then kept by the shape of the call — one
  request in, at most one packet out — which is the same answer version negotiation gave to the
  same rule. Everything it writes is the caller's: §5.1 wants a connection ID unpredictable and
  invariant 5 forbids colibri a random number, and the client's address is opaque octets because
  colibri owns no socket.

  `verify_token` reads a later Initial's Token field as absent, validated or invalid, which are
  the three things §8.1.2 has a server do next: send a Retry, continue, or close with
  INVALID_TOKEN. The last is a verdict and not an error value, because §8.1.2 says the server "has
  not established any state for the connection at this point and so does not enter the closing
  period", so there is no connection to fail.

  The strongest case is a round trip in one file: the server writes a Retry and the client half of
  §17.2.5.2 reads it back and accepts it, which checks the pseudo-packet both sides build against
  each other rather than against an expected byte string.

  11 mutations, 10 CAUGHT. The survivor wrote a Retry carrying a zero-length token — the one thing
  §17.2.5.2 has a client discard outright — which no suite in a test had produced.

  `zig build test`: 1204 passed, 18 skipped.

  **§8.2.3's path MTU is recorded where it is known, 2026-09-21**, `4aafd03`. The receive path
  had no way to answer RFC 9000 §8.2.3's question — "If an endpoint sends a PATH_CHALLENGE frame
  in a datagram that is not expanded to at least 1200 bytes and if the response to it validates
  the peer address, the path is validated but not the path MTU" — because the fact belongs to the
  datagram that went out and nothing kept it. So `take_path_response` passed false, which was safe
  and always wrong: every probe left a second validation owed.

  `Path.Challenge` keeps it now. `on_challenge_sent` takes the datagram's length rather than a
  flag, so §8.2.1's "at least the smallest allowed maximum datagram size of 1200 bytes" is
  compared once, in `path.zig`, instead of at every call site that might get it wrong;
  `on_response` loses the parameter it could have been lied to through.

  7 mutations, 6 CAUGHT. The survivor let an unexpanded probe unsettle an MTU an earlier probe had
  validated, which no case had sent in that order — §8.2.3 asks for the MTU to be verified once,
  not for every probe to verify it again.

  `zig build test`: 1205 passed, 18 skipped.

  **The timers are driven, 2026-09-21**, `18e9949`. Five deadlines were armed across a
  connection — RFC 9002 Appendix A.8's loss timer, RFC 9000 §10.1's idle timeout, §10.2's closing
  period, §8.2.4's PATH_CHALLENGE and RFC 9001 §6.5's previous read keys — and nothing put them
  together, so a caller had to ask each piece and take the smallest itself.

  `connection_timer.zig` is one question and one answer. colibri still sets no timer, which is
  design §4.2: "It returns the instant at which it next wants to be called, and the caller
  arranges that." `Fired` is a set rather than a choice, because more than one deadline can come
  due at one instant.

  Loss detection is reported and not run. RFC 9002 Appendix A.9's `OnLossDetectionTimeout` needs
  storage for the packets it declares lost, which decision 35 leaves with the caller, so the timer
  is reported and `Recovery.on_timeout` stays the caller's to call. Everything else is state
  colibri already holds, so it acts on it.

  15 mutations, 14 CAUGHT. The survivor guarded a state the key phase cannot reach — read keys
  discarded while the instant that times them is still recorded — so the guard went and an
  assertion says why one field answers.

  `zig build test`: 1214 passed, 18 skipped.

  **A lone ack-eliciting packet is acknowledged, 2026-09-21**, `53205ae`. Found while wiring the
  timers above, and a real defect rather than a missing piece. `Space.owes_ack` answered on
  RFC 9000 §13.2.2's two ack-eliciting packets or on §13.2.1's immediate cases, and nothing knew
  about the deadline under both: one in-order ack-eliciting 1-RTT packet set neither, so colibri
  waited for a second that might never arrive and the peer's Probe Timeout fired instead. §13.2.1
  calls max_ack_delay "an explicit contract".

  The space records the instant the oldest packet it has not acknowledged arrived — the oldest,
  because the promise is about every packet and the oldest is nearest to breaking it — and
  `owes_ack` takes the instant. Only the application space arms a deadline: §13.2.1 has every
  ack-eliciting Initial and Handshake packet acknowledged immediately, which `receive` already
  records as `ack_immediately`, so those two are owed at once and want no timer.

  The recovery check's census moved with it, which is recorded above rather than pinned over.

  11 mutations, 8 CAUGHT first time. One guarded a path that could not be reached — a deadline
  taken across three spaces where only one ever arms one — so the loop went. The other two were
  tests that computed their expectation from the code they check: a deadline read back off the
  connection rather than spelled as §18.2's 25 milliseconds, and no case that built a packet after
  the delay rather than before it.

  `zig build test`: 1219 passed, 18 skipped.

  **The path frames are sent, 2026-09-21**, `10aabc5`. `Path` had run RFC 9000 §8.2's validation
  since step 9c and nothing wrote a frame: `on_challenge_sent` had no caller, and the PATH_RESPONSE
  a peer's challenge earned was reported to the caller in `Report.owed` rather than sent. The
  connection remembers both now — sixteen octets each — and the send path writes them into the
  next 1-RTT packet, which is where §12.5's Table 3 permits them.

  §8.2.1 and §8.2.2 both expand the datagram that carries one to §14.1's 1,200 octets, and both
  except the anti-amplification limit. Neither needs a check for that exception: `datagram_ceiling`
  already bounds every datagram by §8's allowance, so a server that may not send 1,200 octets sends
  fewer and §8.2.3's second validation is exactly what the short datagram leaves owed. The two
  rules meet in one place rather than arguing at two.

  §8.2.4's timer is "three times the larger of the current PTO or the PTO for the new path (using
  kInitialRtt)", which is why `Rtt` gained `new_path_probe_timeout_ns`. It keeps the peer's
  max_ack_delay, because RFC 9002 §5.3 resets the estimator on migration and leaves that alone: it
  is a property of the peer and not of the path.

  What stays the caller's is the unpredictable data §8.2.1 requires, because invariant 5 forbids
  colibri a random number, and the decision to probe at all. `Path.owe_challenge` is the whole of
  the entry point.

  15 mutations, 13 CAUGHT. Both survivors were tests that could not tell two values apart: one
  never read whether the packet elicited an acknowledgment, which Table 3 says it does; and one
  gave the connection a round trip equal to kInitialRtt, so §8.2.4's "larger" chose between two
  equal numbers and choosing wrongly looked the same.

  A follow-up, `605a9c9`, named a literal the magic-numbers rule refuses. It was pushed broken:
  the lint result was read after the commit rather than before it.

  `zig build test`: 1224 passed, 18 skipped.

  **The peer's ECN counts are validated, 2026-09-21**, `ab178c3`. RFC 9000 §13.4.2.1: "An
  endpoint that receives an ACK frame with ECN counts therefore validates the counts before using
  them." colibri used them. A rise in the reported ECN-CE count was a congestion event whatever
  else the frame said, so a peer — or a network element rewriting the field — could halve the
  congestion window by reporting counts for markings nobody applied.

  colibri marks nothing: §13.4.2 has an endpoint set ECT(0) in the IP header, and the IP header is
  the caller's (non-negotiable 1). So the caller says what it set, one `Record` at a time, and
  `recovery_ecn.zig` judges what comes back against it. All four of §13.4.2.1's checks are there —
  counts absent where a marked packet was acknowledged, a total above what was marked, an increase
  smaller than the packets newly acknowledged, and the reordering rule that forbids failing on a
  frame which did not raise the largest acknowledged. §13.4.2.2's answer is one flag, because
  §13.4.2 validates "for each network path" and a connection holds one path here.

  A frame that fails leaves nothing behind: its counts are exactly what stopped being believed, so
  they are not recorded and no congestion event follows from them.

  14 mutations, 10 CAUGHT. All four survivors were in the wiring rather than the checks, and one
  of them was a defect the mutation found: `recovery_ack.take` merges a `Removed` per ACK range,
  and the new per-codepoint counts were assigned rather than summed, so a two-range frame
  under-counted what it had acknowledged. A case with two ranges pins it now.

  `recovery_sent.zig` passed 500 lines with the codepoint on `Record`, so its tests moved to
  `recovery_sent_test.zig`.

  `zig build test`: 1236 passed, 18 skipped, and `zig build test-sim -Drelease` agrees.

  **A Stateless Reset can be written, 2026-09-22**, `9d902e1`. colibri could read one and not
  write one, which made RFC 9000 §10.3's datagram the only wire format in the tree it can take
  apart and not assemble. The owner asked for it on 2026-09-22, for failing fast where a peer
  would otherwise wait out an idle timeout, and ruled the invariant change it needed.

  Every part that needs a secret stays the caller's, and each for a rule of its own: §10.3's
  unpredictable octets because invariant 5 forbids colibri a random number, §10.3.2's token
  because it comes from a static key and non-negotiable 2 keeps keys out of this tree, and the
  decision to send because §10.3 answers a datagram no connection could be found for and
  non-negotiable 1 leaves the socket with the caller. `write` lays out Figure 10 around them,
  which is the division a Retry packet already had.

  **Invariant 20 was what had to move, and it came out stronger.** It had said nothing in
  `src/quic/` may build a Stateless Reset, because RFC 9000 §9 forbids answering a peer's
  migration with one: a third party could then close connections by spoofing traffic. That rule is
  about a connection, and §10.3's answer is to a datagram that belongs to none, so the invariant
  now names the shape rather than the absence: `write` takes no `Connection`, and a function that
  cannot see one cannot be reached from the path that refuses a migration.

  The old check was a test that no declaration of `stateless_reset` is named `write` or `build`.
  Replacing it exposed that the new one was vacuous — no function took a `Connection`, so
  weakening the assertion changed nothing and the test could not fail. It now runs the rule
  against a canary shaped the way §9 forbids, which is what `build/lint.zig` does for the lint
  rules, so the passing line is evidence.

  12 mutations, 12 CAUGHT, two of them the invariant's own check once it had a canary to fail on.

  `zig build test`: 1240 passed, 18 skipped.

  **Lost CRYPTO octets are sent again, 2026-09-22**, `79d5dd9`. RFC 9000 §13.3's first rule:
  "Data sent in CRYPTO frames is retransmitted according to the rules in [QUIC-RECOVERY], until
  all data has been acknowledged." Nothing did, so a lost handshake packet ended the attempt.

  §13.3's shape is worth stating, because it is not the one the name suggests. "QUIC packets that
  are determined to be lost are not retransmitted whole. The same applies to the frames" — the
  *information* is sent again, by whoever holds it. So there is no queue of frames to replay:
  each piece keeps what it owes and writes it afresh. The send window `fd97a12` added for a
  Retry's repeat is the CRYPTO half of exactly that, and what was missing was the record of which
  octets a packet carried.

  A `recovery_sent.Record` carries that range now, and `connection_crypto.on_packets_lost` rewinds
  the level's flow to the lowest lost offset. Nothing is tracked per packet, because §13.3 permits
  sending more than was lost — "a receiver MUST accept packets containing an outdated frame" — so
  the lowest rewind covers every higher one. A new packet number carries the repeat, which
  invariant 17 requires and §17.2.5.3 says of a Retry for the same reason.

  `Record` grew from 24 octets to 32. 256 of them sit in each of three spaces, so a test pins the
  size: the next field added to it is measured rather than assumed. The range is two flat fields
  rather than a struct, because a struct of a `u64` and a `u16` pads to sixteen octets and would
  have cost 40.

  `packet_build.zig` passed 500 lines, so its framing half became `packet_build_frames.zig`; that
  made four files sharing the prefix, which moved them into `packet_build/`.

  10 mutations, 8 CAUGHT. One survivor rewound to the last lost offset rather than the lowest,
  which nothing separated until a case sent a flight across two packets; the other was an anchor
  the split had moved.

  What is left of §13.3 is its other rules: STREAM data, which needs the stream send buffers;
  RESET_STREAM and STOP_SENDING, which are sent until a state is reached; the limit frames, which
  carry the current value rather than the lost one; NEW_CONNECTION_ID, RETIRE_CONNECTION_ID and
  NEW_TOKEN, which carry the same content again; and HANDSHAKE_DONE, which "MUST be retransmitted
  until it is acknowledged".

  `zig build test`: 1245 passed, 18 skipped.

  **§13.3's table is in the frame it belongs to, 2026-09-22**, `a15af0f`. `Frame.repair` answers
  what a lost packet owes for each frame type, one arm per sentence of §13.3, beside
  `permitted_at` and `is_ack_eliciting` because it is the same kind of fact about a frame. The
  switch has no `else`, so a frame type added to the union stops the build until its rule is
  written down.

  That closes the retransmission piece for what colibri can send, which is five frames: CRYPTO,
  ACK, PATH_RESPONSE, PATH_CHALLENGE and CONNECTION_CLOSE. The CRYPTO one sends its octets again;
  the other four need no repair, and §13.3 gives a different reason for each — PING and PADDING
  "contain no information", an ACK is superseded by the next, a connection close is resent by §10
  rather than by loss detection, and a PATH_RESPONSE is "sent just once". Four of those were true
  by colibri having built nothing, which is the state mutation testing exists to find, so a case
  sends all four in one packet and loses it.

  What is left of §13.3 belongs to senders that do not exist: STREAM data, RESET_STREAM,
  STOP_SENDING, the limit and blocked frames, the connection ID frames, NEW_TOKEN and
  HANDSHAKE_DONE. Each lands with the piece that sends it rather than with a queue of its own,
  which is what §13.3 asks for: "the information that might be carried in frames is sent again in
  new frames as needed". The exhaustive switch is what will stop a sender landing without its rule.

  7 mutations, 7 CAUGHT, one per classification the table could have got wrong.

  `zig build test`: 1247 passed, 18 skipped.

  **Every acknowledged record reaches the caller, 2026-09-22**, `272b179`. This is the first
  piece of [decision 57](decisions.md#the-h2-connection). It counts the octets the peer has
  acknowledged on each stream, and only a packet's record says which octets it carried.
  `recovery_sent.Removed` kept the largest record alone, because RFC 9002 needs no more: the
  round trip sample and the congestion event both come from the largest. So `remove_range_into`
  writes each record it takes into a slice the caller places, and `recovery_ack.on_ack_received`
  passes that slice through one ACK range after another, as `recovery_loss.detect` already does
  for lost records. A slice too short is told how many records did not fit.

  The recovery simulator now settles acknowledged packets from those records rather than from
  the ACK ranges it wrote itself. A run that ends with a packet neither acknowledged nor declared
  lost fails as `NotDrained`.

  10 mutations, 10 CAUGHT: four on the table's writes, four on the sums across ranges and the
  outcome, and two through the simulator.

  `zig build test`: 1250 passed, 18 skipped.

  **A sent record holds one range for CRYPTO or STREAM, 2026-09-22**, `d9bde2e`. Decision 57's
  second piece. A packet carries at most one CRYPTO frame or one STREAM frame and never both, so
  the CRYPTO pair on `recovery_sent.Record` becomes `data_offset` and `data_len`, tagged by
  `carries`: none, CRYPTO, STREAM, or STREAM with the FIN. The record names the stream by its
  62-bit identifier, never a table slot, because a slot is reused. It grows from 32 octets to 40,
  where a separate stream range would have made it 56. Nothing frames STREAM yet, so only the
  record carries `stream_id`; the send path gains it with the frames that fill it.

  `connection_crypto.on_packets_lost` now reads `carries` and not a nonzero length, and a test
  loses a record that carried stream octets at an offset the CRYPTO flow also used.

  7 mutations, 7 CAUGHT.

  `zig build test`: 1250 passed, 18 skipped.

  **Each stream counts what it sent, lost and had acknowledged, 2026-09-22**, `9df4675`. Decision
  57's third piece. A stream holds no octets. `stream_outgoing.Outgoing` holds four offsets:
  how far the caller's octets reach, how far colibri has framed them, how many the peer has
  acknowledged, and whether the caller ended the stream there. `Streams.on_range_acknowledged`
  adds an acknowledged range to its stream and moves the sending part to "Data Recvd" once every
  octet and the FIN are acknowledged (RFC 9000 §3.1). `Streams.on_range_lost` keeps a lost range
  in `stream_lost.LostRanges`, the ranges owed again across every stream, oldest first, unless the
  stream has sent RESET_STREAM (§13.3).

  The count is exact because each framed octet is in one place: one packet in flight, the lost
  table, or acknowledged. [Invariant 29](invariants.md) states that, and
  `Outgoing.on_acknowledged` asserts that the count never passes the framed offset.

  The lost table holds `stream_lost_ranges_max` ranges, which is `sent_packets_max`: a lost range
  comes from one lost packet, and new octets wait while any range is owed. A range split to fit
  a smaller packet (§13.3) lies next to its remainder, so the table joins adjacent ranges of one
  stream, and losing the piece again leaves one entry and not two. A table that fills anyway
  refuses the range with `Full`, which the connection turns into INTERNAL_ERROR.

  30 mutations, 30 CAUGHT. Two cases were written for one mutation each: a range whose octets go
  out before its FIN, and a stream still in "Send" losing a range. One check in
  `is_all_acknowledged` was removed rather than tested, because an acknowledged FIN implies the
  stream was ended.

  `zig build test`: 1263 passed, 18 skipped.

  **Stream octets are sent, read through the stream provider, 2026-09-22**, `3c1453d`. Decision
  57's fourth piece. `stream_provider.StreamProvider` is design §4.5's vtable, one member,
  `read(stream_id, offset, output)`. `connection_send.send` takes one, and
  `StreamProvider.none()` serves a caller that sends no stream data. The caller opens a stream
  with `connection_stream_send.open` and says how far its octets reach with `supply`. It never
  passes octets.

  `connection_stream_send.write` puts one STREAM frame in an application-level packet (decision
  56; RFC 9000 §12.4, Table 3). The oldest lost range goes first (§13.3), and a lost range whose
  stream was reset or closed since is dropped. Otherwise the first stream in the table with new
  octets and credit sends them. Each new octet spends the stream's limit and the connection's
  (§4.1), and a lost range sent again spends neither. A packet that carries CRYPTO carries no
  STREAM frame, because the record holds one range. The provider writes its octets straight into
  the packet scratch after a header measured for the room. The Length field keeps that width even
  when the provider answers fewer octets, which RFC 9000 §16 permits, so no octet is moved. The
  field is always present, so PADDING may follow the frame. Choosing among streams is the frame
  scheduler's, [#29](https://github.com/c4milo/colibri/issues/29).

  The tests open each packet as the peer, run its frames through the receive path, and check
  every octet of the STREAM frame against its offset. They cover a lost range sent again before
  new octets, a lost range split to fit a smaller packet, a FIN sent alone and lost, a reset or
  closed stream's lost range dropped, both flow control limits, a provider with fewer octets than
  supplied, and CRYPTO and STREAM kept apart.

  34 mutations, 34 CAUGHT. The Length field's width was first NOT CAUGHT: no provider had
  answered fewer than 64 octets for a range measured at two, so the short read now reads 50. One
  check in `frame` was removed rather than tested, because the check after it answers the same
  case.

  `zig build test`: 1276 passed, 18 skipped.

  **Acknowledged and lost records reach the streams, 2026-09-22**, `f08de58`. Decision 57's last
  piece. Loss recovery is the caller's to drive, and `recovery_ack.on_ack_received` hands it the
  records an ACK took out and the ones it found lost. `connection_stream_recovery` reads the
  stream range each record names. `on_packets_acknowledged` counts the range toward its stream
  and writes the identifier of each stream that enters "Data Recvd" into a slice the caller
  places. From then on the caller may drop that stream's octets. `on_packets_lost` puts the
  ranges in the lost table for `send`, and a table that cannot hold one closes the connection
  with INTERNAL_ERROR (RFC 9000 §20.1). A record that carried CRYPTO or nothing is passed over.

  Four files now started `connection_stream_`, so `a0562d8` moved them into
  `connection/connection_stream/`, as CLAUDE.md asks, before this piece added two more.

  11 mutations, 11 CAUGHT.

  `zig build test`: 1282 passed, 18 skipped.

  What decision 57 leaves to other pieces: RESET_STREAM and STOP_SENDING are not sent yet
  ([#37](https://github.com/c4milo/colibri/issues/37)). A probe carries new octets or a PING and
  never a range in flight, which invariant 29 needs, but nothing writes a probe yet
  ([#29](https://github.com/c4milo/colibri/issues/29)). The simulator check that each stream's
  count reaches its final size belongs to the QUIC connection check
  ([#24](https://github.com/c4milo/colibri/issues/24)).

  **The handshake completes, and a server sends HANDSHAKE_DONE, 2026-09-22**, `064022f`. Nothing
  set `handshake_complete` outside the tests, so a server never confirmed its handshake or sent
  HANDSHAKE_DONE, and a colibri client never confirmed either. `connection_handshake.complete`
  marks the handshake complete once the provider reports it (RFC 9001 §4.1.1), after requiring
  the peer's transport parameters (§8.2). A server confirms at the same moment (§4.1.2), owes a
  HANDSHAKE_DONE frame and discards its Handshake keys (§4.9.2).

  The frame goes in a 1-RTT packet (RFC 9000 §12.4, Table 3), after the path frames and before
  any octets. RFC 9000 §13.3 retransmits it until it is acknowledged, and that needs only the
  number of the packet that last carried it. So the connection keeps that number and
  `recovery_sent.Record` stays at 40 octets. Losing that packet owes the frame again. An
  acknowledgment of it, and of no other packet or space, ends the obligation.

  At a client, `connection_frames.Report.handshake_done` says a HANDSHAKE_DONE confirmed the
  handshake, and the caller then discards the Handshake keys with
  `connection_keys.on_handshake_confirmed`, because `process` is not given the suite. The tests'
  suite now records key discards by level rather than treating one as unreachable.

  22 mutations, 22 CAUGHT. Matching a later packet number was first NOT CAUGHT, and a case now
  acknowledges a later packet that carried something else. A call in `complete` that read the
  peer's parameters was removed rather than tested, because reading them is the caller's step
  as the handshake carries them.

  `zig build test`: 1288 passed, 18 skipped.

  **The limit frames are sent, 2026-09-22**, `ad5cbe1`. Nothing gave a peer more credit, so a
  peer stopped at the first limit it reached. `connection_flow` writes MAX_DATA,
  MAX_STREAM_DATA and MAX_STREAMS (RFC 9000 §19.9 to §19.11) in 1-RTT packets, after
  HANDSHAKE_DONE and before any octets. `flow.Receiver` still decides when new credit is worth a
  frame. What it measures from is what the application consumed (§4.1), so
  `connection_flow.consume` is how the caller reports that it read a stream's octets.
  `Streams.close` gives a count back for each stream the peer opened (§4.6), which is what
  MAX_STREAMS then offers. MAX_STREAM_DATA stops once the stream's receiving part leaves "Recv"
  (§13.3's SHOULD).

  §13.3 resends a lost limit frame at the current value, and only when the lost packet carried
  the most recent frame for its scope. `flow.Advertised` holds that packet's number for each
  scope: the connection, each stream, and each stream type. A loss is matched by number, so an
  acknowledgment needs nothing, and a frame with no room stays owed for the next packet.

  Two defects came up on the way. With a window of 0 or 1, `window / flow_credit_fraction` is
  0, so `credit_frame_limit` offered a limit on every call, and MAX_STREAMS went out in every
  packet for a peer allowed one stream. Credit that raises nothing is now never offered (§4.1:
  a limit that does not rise "has no effect"). The second defect is filed, not fixed: every
  receiver starts with its cap equal to its window, so decision 49's growth never happens
  ([#42](https://github.com/c4milo/colibri/issues/42)). Choosing the cap is a named limit and the
  owner's to set. A test gives one connection a larger cap and shows the window doubling
  against the round trip.

  The caller still has no stream octets to read and report, because nothing hands received
  stream data to it ([#41](https://github.com/c4milo/colibri/issues/41)).

  22 mutations, 22 CAUGHT. The resend of a lost MAX_STREAMS and the round trip passed to the
  window's growth each got a test case for their mutation. One check in MAX_STREAM_DATA became an
  assertion, because credit comes only from `consume`, which already refuses a stream this
  endpoint does not receive on.

  `zig build test`: 1299 passed, 18 skipped.

  **The BLOCKED frames are sent, 2026-09-22**, `01bb196`. `connection_flow.write_blocked`
  writes DATA_BLOCKED, STREAM_DATA_BLOCKED and STREAMS_BLOCKED (RFC 9000 §19.12 to §19.14) after
  the limit frames. Each goes once per limit, through `flow.Sender.blocked_frame_limit`, and
  only while the limit holds something back. For the two data frames that means octets supplied
  and unsent on a stream still in "Ready" or "Send" (§4.1: a sender that "has data to write but
  is blocked"). For STREAMS_BLOCKED it means an open the peer's limit refused since the last
  stream this endpoint opened (§4.6: "unable to open a new stream"), which `Streams.open_local`
  now records. A lost one goes again at the current limit while the endpoint is still blocked,
  and the debt is dropped once it is not (§13.3). The same `on_packets_lost` covers all six flow
  control frames.

  Not done: §4.1's SHOULD to send a BLOCKED frame "periodically" while blocked with nothing in
  flight, which needs a timer and belongs with the scheduler
  ([#29](https://github.com/c4milo/colibri/issues/29)). A test that expected nothing after a
  stream limit now expects the one STREAM_DATA_BLOCKED that goes out.

  16 mutations, 16 CAUGHT. The tests read the frames back at the peer, because it ignores all
  three, so the limit and stream type each one names are checked.

  `zig build test`: 1303 passed, 18 skipped.

  **RESET_STREAM and STOP_SENDING are sent, 2026-09-22**, `861bc84` and `2d1f70f`. Nothing could
  end one direction of a stream, and a peer's STOP_SENDING went unanswered, which RFC 9000 §3.5
  says MUST be answered with RESET_STREAM. `connection_stream_send.reset` abandons a sending part
  (§3.1, §19.4). It enters "Reset Sent" when the reset is asked for, not when the frame goes out,
  so nothing is framed after the decision. The frame's final size is every octet framed, which
  can no longer change, so each copy is the same (§13.3: its content "MUST NOT change when it is
  sent again"). `stop_sending` asks the peer to stop, while the receiving part is in "Recv" or
  "Size Known" (§19.5). A STOP_SENDING from the peer now owes a reset with the peer's error code
  (§3.5). colibri resets at once in "Data Sent" too, where §3.5 allows but does not require a
  wait.

  A lost RESET_STREAM goes again until one copy is acknowledged, and that acknowledgment enters
  "Reset Recvd" (§3.1). A lost STOP_SENDING goes again while the peer may still send (§13.3). Both
  keep the packet that carried their most recent copy in `frame.Latest`, which `861bc84` renamed
  from `flow.Advertised` because the record is not about limits. `connection_stream_recovery`'s
  two functions now take the packet number space, because acknowledging a reset matches packet
  numbers, and a number means nothing outside its space (§12.3). An acknowledgment walks the
  streams only while one is in "Reset Sent".

  28 mutations, 28 CAUGHT: 4 on the renamed record and 24 on the endings. A check in the
  acknowledgment walk that could never fail was removed rather than kept as an equivalent mutant.

  `zig build test`: 1309 passed, 18 skipped.

  **The application frame scheduler, 2026-09-22**, `b020293`, `7a320ac` and `38b8326`.
  `packet_build_frames.zig`'s header now states the order frames compete in for one packet's
  room, with the rule behind each place. Three rules were missing from it.

  RFC 9000 §13.2.1: "An endpoint SHOULD send an ACK frame with other frames when there are new
  ack-eliciting packets to acknowledge." An ACK went out only once it was owed. Now a pending one
  is written whenever the packet carries anything else. If nothing follows, the ACK is taken back
  and the space's count and instant are restored, so a lone ACK still waits for its deadline.

  RFC 9002 §6.2.4's probes. `Recovery.Action.probe` asked the caller for ack-eliciting packets
  that nothing could build when there was nothing to send. `connection_send.owe_probes` records
  the count per level. Each ack-eliciting packet at that level counts one off, and one that would
  elicit nothing carries a PING. A probe carries new frames or a PING and never repeats a range
  in flight, which invariant 29 needs.

  RFC 9000 §2.3: an implementation "SHOULD provide ways in which an application can indicate the
  relative priority of streams." Until now the first stream in the table sent until it ran out.
  `connection_stream_send.set_priority` orders new octets, a lower value first, from
  `stream_priority_default` in the middle of the range. Streams of one value take turns, and one
  whose provider has nothing yet gives way to the next. Lost octets still go before new ones
  (§13.3).

  Not done: §4.1's SHOULD to send a BLOCKED frame "periodically" while nothing is in flight. It
  needs a timer of its own and the connection's own recovery bookkeeping, and it is filed as
  [#43](https://github.com/c4milo/colibri/issues/43).

  24 mutations: 22 CAUGHT and 2 equivalent. The ACK snapshot's at-once flag is always clear when
  an ACK is taken back, so it was removed. Two priority ranks are never equal, so no tie can
  break either way. Two mutations first NOT CAUGHT got a test case each: an ACK taken back that
  must leave its count, and a first-ranked stream that frames nothing.

  `zig build test`: 1318 passed, 18 skipped.

  **NEW_CONNECTION_ID and RETIRE_CONNECTION_ID are sent, 2026-09-22**, `0e074ef` and `e07bad8`.
  Nothing gave a peer a second connection ID. The retirements a peer's Retire Prior To owed were
  queued and never sent.

  `connection_id_frames.issue` takes a connection ID's octets and its Stateless Reset Token from
  the caller. colibri draws no random number for the octets (invariant 5), and RFC 9000 §10.3.2
  derives the token from a key colibri does not hold (non-negotiable 2), the division #31 settled
  for the Stateless Reset itself. It refuses:
  - an endpoint whose peer sends it zero-length IDs (§19.15);
  - octets of a length other than this endpoint's first, because a short header does not encode
    the length (§17.3.1);
  - more IDs than the peer's `active_connection_id_limit` (§5.1.1: "An endpoint MUST NOT provide
    more connection IDs than the peer's limit").

  The caller routes datagrams by Destination Connection ID and chose the octets, so it knows each
  one this connection answers to.

  Both frames travel in 1-RTT packets, after RESET_STREAM and STOP_SENDING. Each keeps a
  `frame.Latest`, so a lost one goes again with the same content (§13.3). A NEW_CONNECTION_ID
  stays owed-on-loss until the peer retires the ID. A retirement leaves once its frame is
  acknowledged, which `connection_id_frames.on_packets_acknowledged` does; before, the queue
  drained as the frame was read, whether or not it arrived. `0e074ef` split `connection_id.zig`'s
  tests out first, for length.

  Not built: NEW_TOKEN, which a server MAY send (§8.1.3). colibri asks the peer to retire none of
  its IDs, so every Retire Prior To it writes is 0.

  18 mutations, 18 CAUGHT. One first survived: no test checked that a retirement already sent is
  not written again.

  `zig build test`: 1325 passed, 18 skipped.

  **The simulator drives a QUIC connection, 2026-09-23**, `79d8d29`. Piece 10,
  [#24](https://github.com/c4milo/colibri/issues/24). Two colibri endpoints finish a handshake
  and move one 16,384-octet stream across the network of step 8. Each is a `Connection` with the
  null QUIC provider and the null suite. `src/sim/quic_endpoint.zig` plays the rest of a caller:
  - it derives the Initial keys from the client's first Destination Connection ID (RFC 9001
    §5.2);
  - it hands the provider this endpoint's transport parameters (§8.2);
  - it installs the Handshake and 1-RTT keys when the null provider's script reaches them
    (§4.1.4);
  - it keeps the octets of the stream it sends (decision 57).

  Each of 256 seeds draws up to 10% loss and 10% duplication over delays that reorder.
  `quic_invariants.zig` reads invariants 17 to 21 after every datagram and every step: numbers
  never reused, a server within three times what it received, flow control limits that never
  fall, every datagram to the one path's connection ID, and no call on a level without keys.

  Over 256 seeds on macOS 25.6 arm64: 13,986 datagrams, 13,991 packets, 722 dropped. Digest
  `0x1693a3d7` in Debug and in `-Drelease`. `zig build test-sim-run-quic` runs it, in the module
  with no HTTP module in its graph (decision 5).

  Building the check found six gaps, each fixed in a commit of its own before it:
  - `88c7945`: RFC 9001 §4.9.1's two triggers for discarding the Initial keys had no caller.
  - `d6c8970`, `4d87ab2`: receiving a datagram took seven steps that no library code ran, so the
    idle timer never restarted on receive. Decision 60 has `connection_datagram.receive` run
    them all in one call.
  - `695c63f`: the frame layer flattened stream, path, crypto and recovery refusals into one
    error, which closed with INTERNAL_ERROR where RFC 9000 names FLOW_CONTROL_ERROR and the
    rest. A TLS alert's description was dropped, so its CRYPTO_ERROR code was lost too.
  - `25bf319`: the peer's max_idle_timeout was never read, and no send restarted the idle timer
    (RFC 9000 §10.1).

  Running it found two more:
  - `feeb757`: a tiny packet's number widened for the header protection sample (decision 54)
    was left out of the planned length, so a server's padded PING sealed two octets past its
    RFC 9000 §8.1 allowance.
  - `10ce41f`: a handshake deadlocked. The client's lost Finished waited behind 1-RTT packets
    the server could not read yet. RFC 9002 §6.2.1 forbids an Application Data PTO before
    confirmation, and the Handshake space held nothing in flight. RFC 9002 §7.3.2's one
    datagram past the window on entering recovery is what lets the Finished go again.

  `306603e` has the null suite count each call at a level without keys, which is what invariant
  21's read compares against zero.

  Not built: pacing, ECN marking, and a server that coalesces its Handshake flight with its
  ServerHello. The last is the harness's: the null provider's keys can only be installed
  between `send` calls, so the ServerHello and the Handshake packets go in separate datagrams.

  Mutations: 13 over the check, 13 CAUGHT. The per-step read of invariants 19 and 21 first
  survived, because nothing broke one during a run; two faults now break each read mid-run.

  `zig build test`: 1379 passed, 18 skipped.

  **Received stream octets are reassembled, 2026-09-23**, `8bf3794` and `290fbf4`. Decision 61,
  [#41](https://github.com/c4milo/colibri/issues/41) and
  [#42](https://github.com/c4milo/colibri/issues/42). colibri had checked every STREAM frame and
  kept none of its octets, so no caller could read a stream and no window could grow.
  - `stream_incoming.Pool(capacity)` is one pool per connection, which the caller places and
    passes as `Options.receive`. Streams take its blocks of `stream_receive_block_len` = 1,024
    octets as they need them. Each block marks which of its octets arrived (RFC 9000 §2.2). One
    pool serves every stream because the octets waiting across them never pass the connection
    window. It holds two blocks per stream beyond its capacity for the ends of each stream's
    span, so a peer within its limits cannot exhaust it.
  - `connection_stream_read.read` copies a stream's octets in order up to the first gap and
    gives each block back once read. What it reads is what gives the peer credit (RFC 9000
    §4.1). Reading every octet moves the stream to "Data Read" (§3.2), and a reset is reported
    once as `StreamReset`.
  - The pool's capacity caps every receive window, the connection's and each stream's: decision
    49's cap, `receive_pool_len_default` = 1 MiB. A connection given no pool keeps no octets and
    its windows stay where they start.
  - The simulator's server now reads the client's stream and checks every octet against what the
    client sent. The census did not move: 16 KiB of reads earns no credit frame against 64 KiB
    windows, so the datagrams are the same.

  Mutations: 15 over the library, 14 CAUGHT. The fifteenth was equivalent: `contiguous_end`'s
  early stop repeated what its block-number check already does, so the stop went. Octets kept
  after a reset first survived; the test that catches it is new. 3 over the simulator, 3
  CAUGHT; dropping the octet check first survived, and a fault now changes an octet.

  `zig build test`: 1396 passed, 20 skipped.

  **A finished stream closes, 2026-09-23**, `9fb82ce`,
  [#44](https://github.com/c4milo/colibri/issues/44). Nothing closed a stream, so a finished one
  kept its table slot and the peer never got its stream count back (RFC 9000 §4.6). A connection
  could open 128 streams over its whole life.
  - `connection_stream_close.close_if_finished` closes a stream once each part it has is in a
    terminal state: "Data Recvd" or "Reset Recvd" for the sending part (§3.1), "Data Read" or
    "Reset Read" for the receiving part (§3.2). Closing frees the table slot and the stream's
    receive blocks.
  - Three events can finish a part, and each calls it: an acknowledgment of the last octets or
    of a RESET_STREAM, a read of the last octet, and a read that reports a reset.

  Mutations: 7, 7 CAUGHT. `zig build test`: 1400 passed, 20 skipped.

  **A colibri client and server finish a QUIC handshake over chapulin, 2026-09-23.** Piece 11's
  first part, [#25](https://github.com/c4milo/colibri/issues/25). It is the first run of
  colibri's connection with a real TLS 1.3 stack and real packet protection.
  - `src/testing/quic/chapulin_quic.zig` puts one `ch_quic` behind both `tls.QuicProvider` and
    `crypto.Suite` (decisions 10 and 48). A chapulin client stages one message for the caller to
    pull, and a chapulin server pushes its flight through a callback. Both land in one buffer per
    level, which `write_handshake` hands out.
  - chapulin reports each level ready from inside the call that fed it. The session keeps the
    report and the endpoint marks the level installed after the colibri call returns, as decision
    60 has the caller do.
  - `tools/quic_loopback.sh` runs a colibri client and a colibri server in one process over one
    chapulin object built `TRANSPORT=quic ROLE=both KEYLOG=on`. Datagrams move in memory, and the
    check advances its own instant 5 ms a round. The client verifies the server's chain, both
    select "hq-interop" (RFC 9001 §8.1), and the server reads a 1 MiB stream. That length takes
    the 1-RTT packet numbers past 256, where a one-octet Packet Number field no longer decodes
    without the largest number received (RFC 9000 Appendix A.3). The check requires four key log
    lines per endpoint.

  First run, on an Apple M1 Pro under macOS 26.6.2 with a chapulin copy patched as below:
  handshake complete and confirmed in round 5 and the stream read in round 43; 904 client
  datagrams, 1,082,906 octets; 44 server datagrams, 3,791 octets.

  Mutations of the adapter and the check: 17, 16 CAUGHT and one equivalent. Three were caught
  only after a change: a lost largest packet number needed the longer stream, and a discard not
  passed to chapulin and a wrong octet read as right each needed a test. The equivalent one read
  `keys_available` in the other direction, which cannot differ because chapulin sets and clears
  both directions of a level together.

  It found three defects:
  - colibri, fixed in `a7e5404`: a datagram grew to the peer's `max_udp_payload_size`, and the
    client sent 1,313 octets. RFC 9000 §14.2 says an endpoint without PMTU discovery "SHOULD NOT
    send datagrams larger than the smallest allowed maximum datagram size". Every datagram now
    stays at 1,200 octets, the size RFC 9002's controller already counted in. 3 mutations, 3
    CAUGHT. The simulator's census moved to 13,660 datagrams, 13,683 packets and 706 dropped.
  - chapulin: in a `ROLE=both` object every session derives the server's Initial keys, because
    `quic.c` picks the role with `#ifdef CH_ROLE_SERVER`. A client there seals under the wrong
    label, so no Initial opens.
  - chapulin: a QUIC server's EncryptedExtensions buffer has no room for the transport
    parameters, so the server fails with an internal_error alert after its ServerHello.

  chapulin fixed both in `9c903d8`, and `tools/quic_loopback.sh` passes against that commit
  unpatched, on the same machine, with the same rounds and datagram counts as the first run.

  The run also shows the cost of [#45](https://github.com/c4milo/colibri/issues/45). The client
  drops the Handshake packet that follows the ServerHello in the server's first datagram, and the
  handshake waits for the server's PTO.

  `zig build test`: 1403 passed, 23 skipped.

  **Each packet's handshake octets reach TLS before the next packet, 2026-09-23.** Decision 62,
  [#45](https://github.com/c4milo/colibri/issues/45).
  - `receive` advances the handshake after each packet it processes, and
    `connection_keys.take_available` then marks each level and direction the suite holds keys
    for. `receive` and `send` ask the same at their start. Callers no longer call
    `on_keys_installed`.
  - The null provider gives its suite each level's keys at the step that makes them, as a
    caller's code would. The simulator's endpoint and the loopback check lost their install
    loops.
  - `tools/quic_loopback.sh` against chapulin `9c903d8`, on the same machine: the handshake is
    confirmed in round 1 rather than 5, and the 1 MiB stream is read by round 8 rather than 43,
    in 901 client datagrams and 9 server datagrams. The old run also lost the 1-RTT packets that
    shared a datagram with the client's Finished, and those losses cut the congestion window.
  - The simulator's census keeps 13,660 datagrams and moves to 13,687 packets and 708 dropped.
    Its null server makes its Handshake keys while it writes the ServerHello, inside `send`, so
    its first datagram never carried a Handshake packet to lose.

  Mutations: 10, 9 CAUGHT and one equivalent. Asking the suite about the read direction alone
  was caught only after a test gave the two directions different answers. The equivalent one let
  the null provider hand over a discarded level, which never happens: colibri discards a level
  only after the script's last step.

  `zig build test`: 1407 passed, 23 skipped.

  **A colibri client fetches files from a colibri server over UDP, 2026-09-23.** Piece 11's
  second part, [#25](https://github.com/c4milo/colibri/issues/25).
  - `testing_udp` grew from the socket into §9's UDP QUIC endpoint, with the owner's leave for its
    new edge to `quic`. `zig build quic-udp` runs it as the hq-interop server or client over one
    chapulin session and Rotor's loop. Its instant comes from Rotor's `Loop.now_ns` (decision
    63, Rotor `ead3669`).
  - hq-interop is the QUIC Interop Runner's HTTP/0.9 over QUIC: one `GET /path` line per
    bidirectional stream, answered with the file and the end of the stream. The server refuses a
    path with an empty, "." or ".." segment, and resets the stream of a file it does not hold.
  - `tools/quic_udp.sh` runs both on 127.0.0.1. The client fetches files of 1,000, 100,000 and
    3,000,000 octets, each compared octet for octet. The server must exit within 5 seconds of the
    client's close, and a request for a missing file must end in a reset stream.

  It found a colibri defect, fixed in its own commit. A server treated the client's address as
  validated only after a PATH_RESPONSE, so RFC 9000 §8's three-times limit held it for the whole
  connection. The first run sent 6 KB of a 100 KB file and then as much as each small ACK
  allowed. RFC 9000 §8.1 lets an endpoint treat the address as validated once it "has
  successfully processed a Handshake packet from the peer", and a server now does. The
  simulator missed it because its server sends little. 2 mutations, 2 CAUGHT, one of them only
  after the test read an Initial packet first.

  The endpoint's mutations: 7, 7 CAUGHT. A receive that ran out of buffers was caught only after
  a test ran the group out, which moved the restart into `udp.zig`.

  `zig build test`: 1421 passed, 26 skipped.

  **Fuzzing, 2026-09-26.** `hq.zig` has a fuzz property ([#53](https://github.com/c4milo/colibri/issues/53)). An accepted path must be
  the request's own octets after `GET `, with only CR and LF after it. It must name a file inside
  the served directory, which the property checks again without `check_path`. 6 mutations, 6
  **CAUGHT**.

  **colibri meets another QUIC implementation, 2026-09-23.** `tools/quic_aioquic.sh` runs the
  UDP endpoint against aioquic 1.3.0's, a Python stack pinned and installed into a cached virtual
  environment, over 127.0.0.1 in both directions. `tools/quic_interop/hq_peer.py` is the
  aioquic side, a small hq-interop server and client on its public API.
  - colibri's client fetches files of 1,000, 100,000 and 3,000,000 octets from aioquic's server,
    and aioquic's client fetches the same three from colibri's. Every file arrives octet for
    octet, and colibri's server exits on aioquic's CONNECTION_CLOSE.
  - Both directions passed on the first run, on the same machine as above, with chapulin
    `9c903d8`. It is the first time colibri's connection or chapulin's QUIC mode exchanged a
    packet with another implementation.

  Mutations: 2, 2 CAUGHT, one for each direction's comparison.

  **The endpoint runs in the QUIC Interop Runner, 2026-09-23.** `tools/interop.sh` builds the
  `colibri-qns` image from the working tree and a chapulin checkout, and runs the runner at commit
  `740c05a` against each peer, with colibri as the server and as the client.
  - The image builds chapulin `TRUST=raw-ecdsa`, selected here with `-Dchapulin-quic-trust`. The
    runner's certificates carry no extended key usage, so they fail chapulin's Web PKI profile.
    Its client pins the server's P-256 key, which the runner's shared `/certs` holds.
  - `tools/quic_interop/qns_identity.py` converts the runner's PEM into the raw DER and key
    octets the endpoint reads. `run_endpoint.sh` maps `ROLE`, `TESTCASE` and `REQUESTS` onto
    `quic-udp`, and exits 127 for the cases the endpoint does not build.
  - The runner's simulator learns a server is listening by sending it an unknown version, so the
    endpoint now answers with Version Negotiation (RFC 9000 §6.1).
  - A server holds `quic_connections_max` connections, routed by the client's address, so a
    connection whose close was lost does not turn the next one away.
  - On a connection error the endpoint closes with its code (RFC 9000 §11) instead of exiting.
  - `tools/quic_interop/run_runner.py` lets the runner run on Python 3.14, which dropped two
    asyncio calls pyshark makes.

  Against quic-go on this machine, colibri client and server, and colibri against itself:

  | Test | colibri server | colibri client |
  |---|---|---|
  | handshake, transfer, chacha20, multiplexing, transferloss, handshakeloss | pass | pass |
  | retry | unsupported: the suite mints no token | pass |

  The runs found a colibri defect, fixed in its own commit. RFC 9000 §3.2 has a frame for a
  peer's stream open every lower stream too, and only the named stream got its §18.2 limits.
  The others kept a one-octet window, so their own frames, arriving late on a lossy path, broke
  flow control. 2 mutations, 2 CAUGHT.

  handshakeloss failed in both roles at first. A probe (RFC 9002 §6.2.4) carried a PING and never
  the unacknowledged CRYPTO octets, so under the case's bursty loss the probes that arrived gave
  the peer nothing it could use. Decision 64 has a PTO at the Initial or Handshake level declare
  that level's packets lost, so the probes carry the octets (`09da2fa`). 4 mutations, 4 CAUGHT,
  one by the simulator's check alone, whose census moved to 13,281 datagrams, 13,318 packets and
  690 dropped. The server side then failed on its own table: four connections whose clients'
  closes were lost filled it until their idle timeouts, so `6072b07` gives the next client the
  connection idle longest. The last run passed every case the endpoint builds, in both roles.

  Not built yet: a qlog, IPv6, Retry as a server, and `tools/ci.sh` running the runner. The hosted
  runner's tshark is older than the 4.5.0 the runner needs.

  **More peers, and the loss the random seeds missed, 2026-09-23.** Against ngtcp2, neqo and
  quinn, colibri's client passed every case the endpoint builds, and its server failed
  handshakeloss against all three, each for its own reason:
  - `193fa99`: neqo reused a UDP port for its next connection, and the server routed a datagram by
    its sender's address, so the new connection's Initial packets went to the old one and were
    dropped. It now routes by Destination Connection ID (RFC 9000 §5.2), which
    `Connection.addressed_by` answers. 7 mutations, 7 CAUGHT.
  - `2f5afeb`: quinn opens all 50 connections at once, and a table of 4 evicted connections still
    in their handshakes. The owner ruled a run-time option: the table holds
    `quic_connections_max`, 64, and `connections=<n>` uses fewer. 4 mutations, 4 CAUGHT.
  - `a5063ee` and `1360983`, decision 65: one ngtcp2 connection lost the server's first flight and
    the CRYPTO probe of each of the next three PTOs. The server now sends its Initial CRYPTO octets
    again at once when an ack-eliciting Initial packet brings no new CRYPTO octets, at most twice
    per connection (RFC 9002 §6.2.3). 11 mutations, 11 CAUGHT.

  quinn then showed the same failure in both roles: a request sent once and lost, the
  acknowledgments that would have shown the loss lost too, and probes that never carried the
  request. quinn's client probes carry NEW_CONNECTION_ID, and colibri's carried PING. Decision 66
  (`37df3cb`, `4789639`) has a PTO at the application level declare its oldest ack-eliciting
  packets lost, one for each probe, so the probes carry their frames. 7 mutations, 7 CAUGHT. The
  QUIC check's census moved to 13,181 datagrams, 13,217 packets and 674 dropped. colibri's server
  cannot change what quinn's probes carry, so handshakeloss with quinn as the client stays
  flaky: it failed 3 of the 5 runs today, each time on a request quinn never sent again.

  The random seeds never dropped every acknowledgment in a row, so two checks now look for exactly
  that:
  - Decision 67: `spec/tla/probe_timeout/ProbeTimeout.tla` lets the network drop every packet of
    ACK frames alone. TLC finds a lost frame never sent again under PING probes, and every frame
    delivered under decisions 64 and 66. `zig build tla` runs it through pepegrillo's `tla` tool.
  - `18f8aa0`: the QUIC check gains an adversary that drops every datagram of ACK frames alone,
    and the client sends a one-packet request under it. All 256 seeds deliver it: 5,170
    datagrams, 1,645 dropped by the adversary. 6 mutations, 6 CAUGHT, and reverting decision 64 or
    66 leaves seed 0 stuck.

  Also: `3747a77` writes the endpoint's key log after each step, because a server with many
  handshakes at once filled it; `9baa6f3` fixes a UDP test that failed on Linux, where io_uring
  delivers a datagram the receive group turned away and the next one in a single tick, which had
  kept CI red since `db27985`.

  The runner at `740c05a`, colibri at `18f8aa0`, on this machine:

  | Peer | colibri server | colibri client |
  |---|---|---|
  | quic-go, ngtcp2, neqo, quinn | pass: H, DC, C20, M, L1, L2; S unsupported | pass: H, DC, C20, M, L1, L2, S |
  | colibri | pass: H, DC, C20, M, L1, L2 | same run |

  colibri against itself first failed DC, C20 and M, while other Docker containers were compiling
  on the same machine: the runner's 60-second limit ran out. Run again alone, all three passed.

  **Retry as a server, 2026-09-23.** Decision 55, amended (`aa0b37a`), has a Retry token carry the
  client's first Destination Connection ID and the Retry's Source Connection ID, which RFC 9000 §7.3
  has the server send back and which a server that keeps no state has nowhere else.
  - `28375bb`: `retry_token_check` replaces `retry_token_valid` and gives both IDs back. A token
    returned to an ID its Retry did not name is invalid (§17.2.5.2), a token of another type is no
    token (§8.1.3), and a server routes the client's next Initial by the Retry's ID. 11
    mutations, 11 CAUGHT.
  - `f4f4ad0`: the UDP server's `retry` option answers each client's first Initial with a Retry
    whose token chapulin mints (`cc88adb`) under a key drawn per run. It starts a connection only
    for an Initial that returns the token, and derives its Initial keys from the Retry's ID
    (§17.2.5.2). 9 mutations, 9 CAUGHT: 7 by unit tests, and 2 by the runner's retry case.

  The runner at `740c05a`, colibri at `f4f4ad0`, chapulin `cc88adb` built `TRUST=raw-ecdsa`: retry
  and handshake pass with colibri as the server against quic-go, ngtcp2, neqo, quinn and colibri,
  and as the client against the four. The loopback, UDP and aioquic checks pass over chapulin
  `992043f`, which fixed the `TRUST=webpki` QUIC build `756ad91` had broken.

  **Key update, amplification and IPv6 in the runner, 2026-09-24.**
  - `cf3872c`: the runner's `amplificationlimit` case sends a chain of nine certificates, a 10 KB
    Handshake flight. Decision 64 sends a level's whole flight again on a PTO, and the 4 KiB
    `crypto_send_buffer_len` had already forgotten the flight's first octets, which closed the
    connection. The owner approved 16 KiB. 1 mutation, 1 CAUGHT.
  - `169c91d`: the UDP endpoint takes an IPv4 or an IPv6 address. A server binds `::`, which
    takes both families on Linux, because the runner gives the server no hint of which family its
    `ipv6` case uses. A client's `keyupdate` option starts one key update as soon as RFC 9001
    §6.1 permits. The runner gives the server `transfer` for all three cases. 4 mutations, 4
    CAUGHT: 2 by unit tests, once one of them checked the IPv6 port, and the key update and the
    `::` bind by the runner.

  The owner also approved three limits in `src/testing/constants.zig` that the nine-certificate
  chain needs:
  - `tls_der_len_max`, from 2 KiB to 8 KiB. The leaf carries twenty 250-octet DNS names, 5,514
    octets in all.
  - `quic_crypto_out_len`, from 8 KiB to 20 KiB. The Certificate message is 9,663 octets, and a
    comptime assert holds this limit above twice `tls_der_len_max`.
  - `quic_chain_len_max`, from 8 to 16. The chain is a leaf under eight intermediates.

  The runner at `740c05a`, colibri at `169c91d`, where "all" is H, DC, C20, M, L1, L2, S, U, A
  and 6:

  | Peer | colibri server | colibri client |
  |---|---|---|
  | quic-go | all but L1 | all but L1 |
  | ngtcp2, neqo | all | all |
  | quinn | all but L1 | all |
  | colibri | all | same run |

  Against quic-go, L1 passed in both roles when run again. In the failed client run every file
  had arrived, but the runner counted 51 handshakes where it expects 50: quic-go's server opened
  two connections, 12 seconds apart, for one connection of the client's. "`handshakeloss` against
  quic-go's server" below gives the cause. With quinn as the client, L1 stays flaky, as "More
  peers, and the loss the random seeds missed" records.

  **Rebinding in the runner, 2026-09-24.** The runner's `rebind-port` and `rebind-addr` cases
  give the client a new port, or a new address and port, one second into the run and every five
  seconds after. The server's first packet on each new path must carry a PATH_CHALLENGE, and the
  client must answer every such challenge.
  - [Decision 72](decisions.md) and its amendments: `0800bd4`, `ddf82ce`, `80240da`, `c679b56`
    and `1786088`. The last lets a moved path's challenge go out past the congestion window and
    the pacer, because RFC 9000 §9.4 keeps the old path's packets out of the new path's
    congestion control.
  - [Decision 73](decisions.md): `80240da`, with its TLA+ model in `9e6e0a0`.
  - `f155153`: the simulator rebinds the client as a NAT does. Over 256 seeds the server moves
    once for each rebind: 276 times in the port check and 275 in the address check.
  - `2a23bc7`: the UDP endpoint names each datagram's address, draws the challenge data, and
    issues spare connection IDs once the handshake is confirmed. quic-go's server waits for one
    before it sends on the client's new path (RFC 9000 §9.5). 3 mutations, 3 CAUGHT by the
    runner's `rebind-port` against quic-go: no challenge data, datagrams sent to the old
    address, and no spare connection IDs.

  Two runs of the runner at `740c05a`, with chapulin built `TRUST=raw-ecdsa`: the first at
  colibri `2a23bc7` with chapulin `992043f`, the second at colibri `66dd187` with chapulin
  `2262eee`.

  | Peer | colibri server | colibri client |
  |---|---|---|
  | colibri | first: `rebind-port`; second: `rebind-addr` | the same runs |
  | quic-go | both cases, both runs | both cases, both runs |
  | ngtcp2 | both cases, both runs | first: neither; second: `rebind-addr` |

  No failure is a rule colibri broke. There are two causes:
  - The network dropped the first PATH_CHALLENGE on the new path, three times: colibri's server
    against itself in both runs, and ngtcp2's server in the second run's `rebind-port`. Each
    time the server was sending to the client's old address near the path's 10 Mbps, so the
    25-packet queue was full. The next challenge was answered, and every file arrived. The
    runner checks only the first challenge on each path, so one lost datagram fails the case.
  - In the first run, colibri's client sent its first packet to ngtcp2's server 0.94 and 1.02
    seconds into the capture, where against quic-go it sent at 0.73. The runner's
    `wait-for-it.sh` polls once a second, so the first rebind came as the handshake ended. In
    `rebind-addr` ngtcp2's server went on sending to the old address, which no longer reached
    the client, and the handshake never finished. In `rebind-port` its first packet on the new
    path carried no PATH_CHALLENGE.

  **Resumption in the runner, 2026-09-24.** The runner's `resumption` case has the client fetch
  one file, keep the server's session ticket, and fetch a second file on a second connection
  that presents it. The runner fails the case if the second handshake carries a Certificate.
  chapulin `2262eee` issues and accepts tickets in both roles (chapulin's decision 51).
  - colibri itself needed no change. RFC 9001 §4.5 carries a NewSessionTicket in CRYPTO frames
    after the handshake, and colibri already moved CRYPTO frames at the application level.
  - `66dd187`: the UDP server draws its ticket key when it starts and takes its start time as
    `seconds=<unix-seconds>`, which Rotor's instant advances (decision 63). A client given
    `resumption` keeps the first connection's ticket and presents it once, on the second, with
    the age RFC 9846 §4.2.11 defines. RFC 9001 §4.5 says a client "SHOULD NOT reuse tickets".
  - chapulin fails a handshake whose ticket the server declines, so a second connection that
    fetches its file resumed. `tools/quic_udp.sh` now runs one such resumption between two
    colibri endpoints.

  14 mutations, 14 CAUGHT: 11 by `tools/quic_udp.sh` and 3 by unit tests. The runner at
  `740c05a`, chapulin `2262eee` built `TRUST=raw-ecdsa`, passed `resumption` in both roles
  against colibri, quic-go and ngtcp2 on the first run.

  **`handshakeloss` against quic-go's server, 2026-09-27**
  ([#72](https://github.com/c4milo/colibri/issues/72)). With colibri as the client, the case
  fails with "Expected 50 handshakes. Got: 51": 3 of 11 runs at `ecb5924`, and 1 of 2 at
  `a6a4791`. In the three captures below, the client opened 50 connections and completed 50
  handshakes, and quic-go's server opened 51. colibri needs no change.
  - The runner counts a handshake for each distinct Source Connection ID in the server's Initial
    packets, read from the server-side capture (`_count_handshakes` in its `testcase.py`).
  - In each capture, one client connection lost what the server sent back, and then every
    packet it sent for 5 seconds. Its probes were seconds apart by then, because its PTO doubles
    on each one (RFC 9002 §6.2.1). quic-go's server destroyed the connection 5 seconds after the
    client's last packet reached it, and logged "timeout: no recent network activity".
  - The client had received nothing from the server, so its next probe kept its first Destination
    Connection ID (RFC 9000 §7.2). quic-go started a second connection for it, under a second
    Source Connection ID, and the handshake completed on that one.
  - No endpoint broke a rule. quic-go's server had processed no Handshake packet from the client,
    so the client's address was not validated (RFC 9000 §8.1), and RFC 9000 §10 lets an endpoint
    discard connection state when it has no validated path.

  Three failed captures, each with quic-go at `9d085cc`:

  | Run | colibri | Client port | quic-go's Source Connection IDs | Apart |
  |---|---|---|---|---|
  | 2026-09-24 | `169c91d` | 55685 | `673c38de`, then `18a9a339` | 12 s |
  | 2026-09-27 | `ecb5924` | 55456 | `c1c1d964`, then `504eca39` | 6 s |
  | 2026-09-27 | `a6a4791` | 57256 | `0518e848`, then `ec4de6cd` | 6 s |

  In each, the capture holds 51 distinct Source Connection IDs in the server's Initial packets, and
  the client's key log holds 50 `CLIENT_TRAFFIC_SECRET_0` lines.

  [Decision 99](decisions.md), the same day: colibri's runs count the client's connection attempts,
  the distinct Destination Connection IDs of the client's Initial packets numbered 0.
  `tools/interop.sh` applies the change to the pinned runner, and it went upstream as
  [quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509).
  - Over 27 saved captures, the old count gave 51 and the new one 50 on the three failed runs
    above. The other 24 gave the same number both ways: `handshakeloss` with colibri's client once
    and quic-go's 15 times, `handshake`, `retry` and `resumption` for three client and server
    pairs, and `zerortt` for quic-go.
  - A count of the client's Source Connection IDs, or of the server's IDs the client later used, is
    wrong for quic-go's client. It uses zero-length connection IDs, and it moves to a
    NEW_CONNECTION_ID one during the handshake.
  - quic-go's own client failed 1 of 15 `handshakeloss` runs against quic-go's server. It gave up
    at its handshake timeout.
  - With the patch, colibri at `08d631e` passed 10 of 10 runs as the client. In one, quic-go
    dropped a connection and started a second for the same client 7 seconds later: the old count
    gives 51 there.
  - 1 mutation, **CAUGHT**: without the patch, the four captures with a dropped connection count
    51, and the case fails.

  **`rebind-port` with colibri on both sides, 2026-09-28**
  ([#78](https://github.com/c4milo/colibri/issues/78)). The weekly run at `a5a97d2` failed
  `rebind-port` with colibri's client against colibri's server, with "PATH_CHALLENGE without a
  PATH_RESPONSE: ['c2:0c:4d:ea:0d:78:8a:b2']", though every file arrived. From the run's captures
  and both endpoints' qlogs:
  - At the first rebinding, 1.001 s into the server's capture, the server sent two
    PATH_CHALLENGEs 21 µs apart. Packet 175 went to the client's old port, a path RFC 9000 §9.3.3
    has the server validate, and the NAT dropped it for its lost binding. Packet 176 went to the
    new port. It is in neither the client's capture nor its qlog, and the simulator logs no drop
    for it. The likely place is the scenario's 25-packet queue, which the transfer's data filled.
  - 95 ms later the server sent a new PATH_CHALLENGE on the new path, with new data (RFC 9000
    §13.3). The client answered it, and the PATH_RESPONSE reached the server 127 ms after packet
    176 left it. The second rebinding lost nothing on its new path.
  - The runner's check, `TestCasePortRebinding.check` in its `testcases_quic.py`, takes only the
    PATH_CHALLENGE in the server's first packet on each new path.

  [Decision 106](decisions.md), the same day: colibri's runs pass a new path once the client
  answers any PATH_CHALLENGE sent on it. `tools/interop.sh` applies the change to the pinned
  runner, and it went upstream as
  [quic-interop-runner#511](https://github.com/quic-interop/quic-interop-runner/pull/511).
  - Over the failed run's captures, the runner's check fails and the patched one passes.
  - 1 mutation, **CAUGHT**: with the client's PATH_RESPONSE frames left out of its capture, the
    patched check fails, and names both new paths.
  - `tools/interop.sh quic-go rebind-port,rebind-addr` with the patch, on an Apple M1 Pro:
    colibri's server passed both cases against colibri's client and quic-go's, and colibri's
    client passed both against quic-go's server. The 8 qlog directories passed
    `tools/qlog_check.py`.

  **Probes that repeat the latest ACK, 2026-09-28**
  ([#76](https://github.com/c4milo/colibri/issues/76)). [Decision 107](decisions.md): a PTO probe
  at the Handshake or application level carries its space's latest ACK frame, though nothing new
  asks for one (RFC 9000 §13.2). An Initial probe does not.
  - `repeats_ack` in `packet_build_frames.zig` decides it, beside decision 72's packets to a path
    awaiting validation. 3 tests in `packet_build_probe_test.zig`: an application probe and a
    Handshake probe each carry an ACK whose own packet the path lost, and an Initial probe
    carries none.
  - 3 mutations, each CAUGHT by `zig build test-quic`: no probe repeating an ACK, the application
    level's alone, and the Initial level's too.
  - The simulator's pinned censuses and logs changed, and Debug and ReleaseSafe agree on the new
    ones. Decision 107 gives the times, and `tools/quic_udp.sh` and `tools/quic_aioquic.sh`
    passed.
  - `tools/interop.sh quinn handshakeloss`, five times on an Apple M1 Pro: colibri's client passed
    all 10 of its runs, against colibri's server and against quinn's. quinn's client against
    colibri's server passed 4 of 5, where #76 counted 3 of 5 against the same quinn image before
    the change. The runs kept no logs, because `INTEROP_LOGS` was not set, so the failed case's
    cause is not known yet.

  **Three more pieces, 2026-09-23.**
  - `3d0b2d7`: `send` asks the provider whether the handshake completed, as `receive` does. A
    client's stack finishes once its own Finished is written, which happens inside `send`, so
    the client had stayed incomplete until the next datagram arrived (RFC 9001 §4.1.1). 3
    mutations, 3 CAUGHT.
  - `7d2c208`, [#43](https://github.com/c4milo/colibri/issues/43): a sender held back by flow
    control with no ack-eliciting packet in flight owes its DATA_BLOCKED and STREAM_DATA_BLOCKED
    frames again one PTO after its last ack-eliciting 1-RTT packet (RFC 9000 §4.1's
    "periodically"). `connection_timer` reports it as `Kind.blocked`. The period is the named
    limit `blocked_repeat_probe_timeouts`, one PTO. That is longer than a round trip, and a
    comptime assert holds it below the three PTOs RFC 9000 §10.1 sets as the idle timeout's
    floor. 10 mutations, 10 CAUGHT; a draining connection owing the frames first survived.
  - `5a64471`, [#33](https://github.com/c4milo/colibri/issues/33): the golden corpus gains
    `quic_receive`, 17 cases walked through `connection_receive` at a client in a state the
    manifest names. Each pins the first discard, or the connection error the walk returns.
    Together they cover RFC 9000 §7.2, §12.2 and §12.3, and RFC 9001 §4.9, §5.5, §5.7, §6.2,
    §6.4 and §6.6. The golden module is given `quic` and not `sim`, so the corpus has a suite
    of its own. The last octet of a packet's tag says which keys open it, which models what a
    real suite learns by trying its keys. 9 corpus mutations added. 9 mutations of the receive
    path, 9 CAUGHT by `zig build test-golden` alone.

  `zig build test`: 1382 passed, 18 skipped.

  **The connection drives loss recovery, 2026-09-23**, `d7b56e6`, `0319c7a`, `33f2c69` and
  `1dfc8e3`. Decision 59. Before it, `send` recorded no packet, an ACK frame updated only its
  packet number space, and nothing called the loss timeout, so RFC 9002 never ran on a connection.

  The four pieces:
  - `connection_recovery` hands each batch of acknowledged or lost packets to every piece that
    keeps a record of what it sent: CRYPTO, stream octets, the flow control frames,
    HANDSHAKE_DONE and the connection ID frames. A lost CRYPTO range the level's window has
    forgotten, or a full table of lost stream ranges, closes the connection with INTERNAL_ERROR
    (RFC 9000 §20.1).
  - An ACK frame runs Appendix A.7's `OnAckReceived` where `connection_frames.process` reads it.
    The ACK Delay is decoded by the peer's exponent (RFC 9000 §19.3) and ignored at the Initial
    level (RFC 9002 §5.3). The caller places a `connection_recovery.Scratch` for the packets.
  - `send` records each packet in flight (Appendix A.5). A packet of ACK frames alone is not
    recorded: Appendix A.1 tracks ack-eliciting packets, and a peer need not acknowledge one
    (RFC 9000 §13.2.1), so its record would hold a table slot until loss detection gave it up.
  - `connection_timer.on_instant` runs Appendix A.9's `OnLossDetectionTimeout`. The packets it
    declares lost go through `connection_recovery`, and a Probe Timeout owes the probes `send`
    builds. Discarding Initial or Handshake keys discards that space's records (RFC 9002 §6.4),
    and the peer's max_ack_delay now reaches the Probe Timeout.

  RFC 9002 §7 bounds what `send` puts in flight by the congestion window. A level sends
  ack-eliciting packets only while the window holds the rest of the datagram, so a packet is never
  cut short to fit and §14.1's padding fits too. Until then it sends only an ACK the space owes.
  A PTO probe and a CONNECTION_CLOSE go whatever the window says. A client the window holds back
  sends no Initial, because §14.1's padding would put it in flight. A space whose table is full
  sends nothing until an acknowledgment arrives.

  Appendix A.8's timer reads four facts from the rest of the connection: whether the handshake is
  confirmed, whether this endpoint holds Handshake keys, whether the peer has validated its
  address, and whether §8.1's limit leaves it anything to send. Nothing set any of them.
  `connection_recovery` now copies them in from the connection's own state before the timer is
  read.

  One defect showed up along the way. The anti-deadlock probe counted from the instant the timer
  was asked for, so each question moved it later and it never fired. It now counts from the last
  event that set the timer (A.5, A.7 or A.9), which `recovery_timer.State.armed_at_ns` holds, and
  `next_timer` takes no instant.

  Not built: pacing (§7.7), which `send` does not consult, and ECN marking. `send` records every
  packet as unmarked (RFC 9000 §13.4), so a caller that marks ECT would fail §13.4.2.1's
  validation and stop marking.

  Mutations: 8, 9, 21 and 23, all CAUGHT. Two first survived: an ACK that could still
  wait was sent past the window, and a server arming an anti-deadlock probe.

  `zig build test`: 1354 passed, 18 skipped.

  **The rest of §6 is done, 2026-09-21**, `871d034`, `6169041`, `adf663c` and `ac522a2`.

  §6.2's last paragraph refuses an acknowledgment carried under the old keys that names a packet
  this endpoint protected with the newer ones. It needs the ACK's contents beside the key set the
  packet opened under, and the frame layer was told neither, so `connection_frames.process` now
  takes the `receive.Opened` the receive path already built — which carries both and replaces
  three of its parameters. RFC 9000 §19.3 makes Largest Acknowledged a packet the frame
  acknowledges and no number it names is above that one, so that field alone answers §6.2's "any
  acknowledged packet".

  §6.6's two limits are the suite's counts, so each arrives as a refusal, and colibri had been
  throwing both away: a seal refusal became "the packet does not fit" and a failed open became
  §5.5's discard. §6.6 wants the opposite of each. On the confidentiality limit the send path
  initiates §6.1's key update and seals again, and closes with AEAD_LIMIT_REACHED only when no
  update is possible — below the application level that is always, because §6.1's Note updates no
  other level's keys. On the integrity limit the walk stops, because §6.6 says to "not process any
  more packets". `packet_build.connection_error_code` answers null for a space out of packet
  numbers: RFC 9000 §12.3 ends that connection with no CONNECTION_CLOSE at all.

  §6.5's two waits are both three Probe Timeouts and neither had a clock. The old read keys go
  three PTOs after a packet arrived under the new ones, and a key update this endpoint starts
  waits three PTOs from the acknowledgment that confirmed the current phase. §6.6's update skips
  the second wait, which is why there are two entry points: a SHOULD about packets a peer might
  discard does not hold up a MUST about what the AEAD is still safe to protect. `on_instant` is
  public so the timer piece can drive it; until then the receive path calls it on every 1-RTT
  packet that opens, which is when colibri is told an instant at all.

  The three loose fields `Connection` held for §6 became `key_update.Phase`, the way
  `connection_keys.Keys` holds invariant 21's, because §6.5's timing needed three more.

  Mutations: 31 applied across the three, 27 CAUGHT first time. The four gaps were all in the
  tests. Two were rules only reachable when §6.1 would have permitted an update, and the cases
  had set up a connection where it would not. One was the wire itself — reporting every packet as
  the current key set — which nothing caught until a test walked a packet and then read its
  frames. And one was a deadline the test computed from the same constant the code reads, so
  changing the constant moved both; a comptime assert pins the three to what §6.5 says instead.
  `zig build test`: 1170 passed, 18 skipped.

  **Three defects the mapping found in committed code, 2026-09-20.** A client could not send its
  first Initial: `Path.init` left every path unvalidated, so its allowance was three times nothing
  and `on_datagram_sent`'s assertion would have halted on the first datagram. Invariant 18 stated
  the claim for both roles and now names the server (`8f3152e`). `Record.in_flight` was documented
  against ack-eliciting alone, while RFC 9002 §2 counts a PADDING frame too, which is the datagram
  RFC 9000 §14.1 makes a client pad; `counts_in_flight` states it once (`e99d93d`). And
  `write_crypto` sized a CRYPTO frame's Offset from `consumed_len`, the receiving mark, while
  `write_frame` writes `sent_len`; the writer is bounds-checked so nothing overran, but a frame
  that fit was refused on an asymmetric flight (`9c37af2`).

  `zig build test` passes and `zig build lint` and `zig fmt --check` are clean after each of the
  seven commits. Mutations: four on the path, three on the in-flight rule, seven on the identity,
  seven on the key schedule, two on the offset and seventeen on the null provider. Three were
  NOT CAUGHT first time and each was a missing test — a zero-length connection ID never reaching
  the set §19.16 refuses a retirement for, no client ever processing a Handshake packet, and a
  server treating a poll of `write_handshake` as the start of its handshake.

  Two of the pieces above cannot be finished as the RFCs ask without a ruling: Retry's token needs
  a key and a clock, and invariant 20's positive half needs an address on `sim.network`, whose
  `Endpoint` is a client-or-server enum today, and a classifier for §9.1's probing frames.

  **`tls.Provider`'s QUIC mode is declared, 2026-09-20.** `src/tls/quic_provider.zig` is the
  eight members [decision 8](decisions.md#what-the-caller-supplies) names for this mode, with no
  implementation in the tree as non-negotiable 2 requires. A test holds the list to decision 8's
  and to invariant 23's rule that no member moves a key, a secret or an IV — decision 48 removed
  `on_secret` and `hkdf_expand_label`, so the secrets of RFC 9001 §4.1.4 go from the provider to
  the suite inside the caller's code and colibri asks `crypto.Suite.keys_available` instead.

  Three things are not in it, and each for a reason RFC 9001 states. There is no
  `encrypt_record` or `decrypt_record`, because §3 says QUIC "takes over the responsibilities of
  the TLS record layer" and `crypto.Suite` protects a packet instead. There is no
  `send_close_notify`, because §4.8 closes a QUIC connection with a CONNECTION_CLOSE frame. And
  `take_alert` answers an AlertDescription rather than a record, because §4.8 adds it to 0x0100
  to make a CRYPTO_ERROR code and makes every alert fatal, so there is no level to report beside
  it; `quic.error_code.crypto_error` already does that arithmetic.

  The encryption level moved to `core`. `crypto.Suite` protects a packet at a level and this
  vtable moves handshake octets at one, and design §3 makes `tls` and `crypto` siblings with no
  edge between them, so the type they share is `core.Level` and `crypto.suite.Level` is an alias
  of it. No module-graph edge was added: both already import `core`.

  `tls.constants` gains `alpn_h3`, RFC 9114 §3.1's token, beside `alpn_h2`.

  **The CRYPTO streams are done, 2026-09-20.** `src/quic/crypto_stream.zig` is RFC 9000 §19.6's
  one ordered flow of handshake octets per encryption level, reassembled from the frames that
  carried them. `src/quic/stream/` could not serve: a CRYPTO stream has no identifier, no FIN, no
  flow control and no final size, so none of §3.2's receiving states or §4.5's final-size rules
  apply to it. What it has instead is §7.5's buffer limit, which is the only thing bounding what
  a peer can make colibri hold, because "there is no flow control of CRYPTO frames".

  The window is anchored at what the handshake has read: `buffer[0]` is the octet at `base`,
  `contiguous` counts the octets from there with no gap, `readable` is the run the handshake may
  take now and `consume` slides the window. Data past the window is a connection error of
  CRYPTO_BUFFER_EXCEEDED, which §7.5 names for exactly it. The window is `crypto_buffer_len`,
  4096, which is the RFC's floor rather than a choice of colibri's — in-order data is handed over
  as it arrives and never sits here, so the number bounds only what a gap holds. Which octets are
  present is a bit each, not a byte: a byte would cost eight times the window per level.

  Mutations: eight applied, all **CAUGHT** — the window's last octet refused, the bound removed,
  the in-order run never extending, `consume` losing what was buffered above it, `consume` moving
  the marks and not the octets, a frame straddling the base written at the wrong offset, every
  level answering as one, and `consume` not advancing the base.

  Mutations: nine applied, all **CAUGHT** — two defaults changed, the 1200 floor removed,
  `max_ack_delay` admitting 2^14 itself, a repeat accepted, a client's server-only parameter
  accepted, an integer carrying trailing octets, a connection ID past 20 octets, and an unknown
  parameter refused instead of ignored. Writing them found a weak test of colibri's own: it
  compared a parsed value against the same constant it came from, so the constants are now pinned
  to the numbers §18.2 states. `zig build test` passes 996 of 996.

  **The TLA+ model, 2026-09-26** ([#49](https://github.com/c4milo/colibri/issues/49)).
  - `spec/tla/quic_keys` models both endpoints' handshake over Initial, Handshake and 1-RTT, as
    colibri installs and discards each level's keys, over a network that loses packets and
    delivers them in any order. It carries the server's anti-amplification credit (RFC 9000
    §8.1), the client's anti-deadlock probe (RFC 9002 §6.2.2.1), the PTO that resends a level's
    CRYPTO data (decision 64) and the server's early Initial resend (decision 65). The properties:
    a level's keys go from none to available to discarded and never back (invariant 21); an
    endpoint discards its Initial keys only once it holds Handshake keys (RFC 9001 §4.9.1); and
    both handshakes are confirmed in the end.
  - Three abstractions keep it small. Time is left out, so a timer that is set may fire at any
    moment; each level's probe is strongly fair, which RFC 9002 Appendix A.8's choice of the
    earliest deadline guarantees; and only the server's ACK frames are modeled, because nothing
    the server waits for depends on the client's.
  - It found no defect. Writing it found three abstractions of the model's own that were wrong,
    each caught by TLC as a stall no colibri connection can reach: a server that sent one level
    at a time where colibri coalesces them (RFC 9000 §12.2), an ACK that acknowledged CRYPTO data
    its sender never received, and an anti-deadlock probe sent before the ClientHello.
  - What `zig build tla` printed, on macOS arm64:
    - holds, as expected: `colibri`, 53059 distinct states; `tight_credit`, a server flight that
      takes the whole allowance a client datagram grants, 65876;
    - violated, as expected: `no_anti_deadlock`, where the client's first flight is acknowledged,
      the server's is lost, and neither side may send; `discard_on_complete`, a client that drops
      its Handshake keys on sending its Finished and cannot send it again; and
      `server_discard_on_send`, a server that drops its Initial keys on its first Handshake packet
      and cannot send its ServerHello again.

  **The runner in CI, 2026-09-27.** The workflow's `quic-interop-runner` job runs
  `tools/interop.sh` against quic-go, ngtcp2, neqo and quinn on Ubuntu 26.04, by hand and every
  Monday (decision 47 as amended). Its first runs found three faults, each fixed:
  - `b3088c5`: Zig 0.16.0 writes a zip package to `tmp/` in its global cache without creating
    that directory, so `zig build --fetch=all` failed on a fresh machine. The job creates it.
  - `653cbde`: the client wrote each download with mode 0o600. On Linux the file belongs to the
    container's root, and the runner, comparing it as its own user, got Permission denied, so
    every case with colibri as the client failed. Docker Desktop maps ownership, so runs on macOS
    passed.
  - `a1f557c`: decision 99's count took a client's first Initial to be numbered 0. ngtcp2's and
    neqo's clients began at 671978432 and 31, so every case with them failed although each
    transfer completed. Decision 99 as amended counts the connection IDs the client chose.

  Run 36367616620, at `a1f557c` on Ubuntu 26.04, passed every case in both roles against quic-go,
  ngtcp2, neqo and quinn, with `ecn` unsupported against quic-go alone. It took 72 minutes of the
  job's 150. In the push job, h3spec 0.1.13 printed "49 examples, 0 failures" (run 36357580797,
  at `54335d0`).

  The count at `a1f557c` scored 2 for one quic-go handshake against quic-go's own server, a
  pairing the job does not run: quic-go's client sends its last Initial packet to an ID from
  NEW_CONNECTION_ID. Decision 99, amended again, counts only client Initial packets that carry
  the start of the ClientHello. It gives each test's expected number on all 151 captures of run
  36359234791 and on 16 from macOS arm64.

  **Decision 64 amended, 2026-09-28.** With the count fixed, `handshakeloss` against quic-go's
  server still failed 2 of 8 runs at `c881163`. The client's Finished went in one probe datagram
  and a PING in the other, the network dropped the Finished's copy each time, and quic-go dropped
  the connection 5 seconds after the client's last packet, although it had announced a 30-second
  `max_idle_timeout` ([quic-go#4215](https://github.com/quic-go/quic-go/issues/4215)). The second
  probe at the Initial and Handshake levels now repeats the first one's CRYPTO octets.
  - Over 2,000 seeds of the simulator's runner network, colibri against itself, the mean
    handshake fell from 1.36 to 1.26 seconds, those over 8 seconds from 17 to 10, and the slowest
    from 34.2 to 32.2 seconds.
  - The QUIC check's census is now 13,719 datagrams, 13,790 packets, 684 dropped and 541 marked,
    crc32 `0xedec6668`, in Debug and in ReleaseSafe on macOS arm64. The other four QUIC censuses
    and both h3 digests moved with it.
  - 4 mutations, 4 CAUGHT: no repeat, a repeat with no probe owed, a repeat from offset 0, and a
    PTO that notes no offset.
  - The runner at `740c05a` against quic-go on macOS arm64, with the change at `c881163`: every
    case of `handshake`, `transfer`, `retry`, `resumption` and `handshakeloss` passed in both
    roles, and then `handshakeloss` passed 9 of 10 more runs as the client and 4 of 4 as the
    server. No run failed as the 2 of 8 had. The one that failed lost quic-go's ServerHello six
    times running, and quic-go ended the handshake at its 10-second limit, silently again.


- **Step 10 — loss recovery and congestion control.** RFC 9002: RTT estimation, packet and time
  threshold loss detection, PTO with backoff, NewReno, persistent congestion, pacing. All nine
  `now()` sites are caller-supplied parameters on the five entry points of §4.2. **Check:** the
  simulator's loss, reorder and blackhole scenarios with a census per seed; the interop runner's
  `handshakeloss`, `transferloss`, `blackhole`, `longrtt` and `ecn` cases; and, because RFC 9002's
  prose and its appendix pseudocode disagree over the round trip variation, a written decision in
  this document's §12, with a test pinning the choice. *Large.*

  **Done, 2026-09-20, but for the interop cases.** Eight files. `src/quic/rtt.zig` is §5's
  estimator and §6.2.1's Probe Timeout. `src/quic/recovery/recovery_sent.zig` is Appendix A.1.1's
  `sent_packets`, one ring per space in packet number order, so a number is found by halving and
  the acknowledged slots fall off either end. `recovery_loss.zig` is §6.1's two thresholds: both
  rise with the packet number, so the lost packets are a run at the front, the walk stops at the
  first survivor — which is also the instant §6.1.2 sets the timer for — and one range takes them
  out. `recovery_congestion.zig` is §7's NewReno, `recovery_pacing.zig` §7.7's leaky bucket,
  `recovery_timer.zig` Appendix A.8's one timer, and `recovery.zig` with `recovery_ack.zig` the
  five entry points of §4.2.

  Three things are worth naming. The octets in flight are the sum over the three tables and are
  held in no second place, because Appendix B.2's `bytes_in_flight` and the tables would
  otherwise be two records of one fact. Congestion avoidance counts octets rather than dividing:
  Appendix B.5's expression grows the window by nothing once it passes the maximum datagram size
  squared, under two megabytes on an ordinary path, and B.5 points at the alternative in the same
  paragraph. And the §5.3-versus-Appendix-A.7 disagreement is settled in
  [decision 50](decisions.md) and §12 question 4, with a test computing both orderings and
  pinning the factor between them.

  **Check:** `src/sim/recovery_check.zig` runs 256 seeds over four paths — quiet, one datagram in
  ten dropped, a delay range wide enough to reorder, and a stretch where the path swallows
  everything. The sender is the whole of `quic.recovery`; the receiver is `quic.space`, which
  writes real ACK frames, so what the sender reads back is octets off the wire. It printed
  `sent=16420 acked=11743 lost=4677 probes=746 scenarios={ 60, 57, 75, 64 }
  crc32=0x2c3cc41a` in Debug and in ReleaseSafe on macOS arm64. Every packet is accounted for
  exactly once — 11743 and 4677 sum to 16420 — no packet is both acknowledged and declared lost,
  the run drains, and the window never falls under §7.2's minimum.

  Those numbers moved on 2026-09-21, `53205ae`, and the move is the point. The receiver had been
  waiting for RFC 9000 §13.2.2's two ack-eliciting packets with no deadline under it, so a lone
  packet went unacknowledged and the sender probed for it; with §13.2.1's max_ack_delay applied,
  probes fall from 1354 to 746 over the same 256 seeds. The earlier figures were
  `sent=16873 acked=11997 lost=4876 probes=1354 crc32=0xb78a83fe`.

  Writing the check found two defects in the check itself and neither in the library, which is
  worth recording because both were rules the library already held. The first invariant written
  was that the octets in flight never pass the congestion window; §7 bounds what a sender adds,
  not what is already outstanding, and §7.5 exempts a probe from the window outright, so the
  check now tests the send and not the state. The second was a digest taken over a struct's
  bytes, padding included: padding is uninitialized memory, the two build modes disagreed about
  it, and [invariant 5](invariants.md#quic) forbids reading it. Each field is now fed in on its
  own, in network byte order.

  **Pacing, ECN and three runner cases, 2026-09-24.**
  - `ae82252`: `send` asks the pacer of RFC 9002 §7.7 before each datagram, and
    `connection_timer` names the instant the pacer has earned the next one as `Kind.pacing`. A
    sender the pacer holds counts as using its window (§7.8). 6 mutations, 6 CAUGHT.
  - [Decision 68](decisions.md) gives the caller two flags. With `ecn_reads`, an ACK frame carries
    RFC 9000 §13.4.1's counts. With `ecn_marks`, `Sent.ecn` names the codepoint the caller sets.
    11 mutations, 11 CAUGHT.
  - [Decision 69](decisions.md) tests the path as RFC 9000 Appendix A.4 describes. The first ten
    marked packets, or three PTOs, are the test. After it the endpoint sends Not-ECT until an
    ACK frame that passes validation shows a marked packet arrived, and then marks again. A path
    that drops marked packets therefore costs at most the test. 11 mutations, 11 CAUGHT.

  The QUIC check now marks, and its network sets ECN-CE on up to 100 datagrams in 1,000. Each
  seed ends with both endpoints' validation holding. Seed 0 found a defect: a packet of ACK frames
  alone was not counted as sent ECT(0), though the peer counts it, so the peer reported more
  ECT(0) packets than the sender had counted. With decision 69 the census is 13,215 datagrams,
  13,242 packets, 662 dropped and 487 marked ECN-CE, crc32 `0x1ce9af4a`, in Debug and in
  ReleaseSafe on macOS arm64.

  The runner at `740c05a`, in Docker on macOS arm64, chapulin `cc88adb` built `TRUST=raw-ecdsa`:

  | Peer | colibri server | colibri client |
  |---|---|---|
  | colibri, ngtcp2 | pass: ecn, longrtt, blackhole | pass: ecn, longrtt, blackhole |
  | quic-go | pass: longrtt, blackhole; ecn unsupported | pass: longrtt, blackhole; ecn unsupported |

  In each `ecn` pass both sides marked, and no datagram carried ECN-CE. Before decision 69 every
  datagram went out ECT(0). Now the datagrams between the test and the ACK that makes the path
  capable go out Not-ECT: against itself, colibri's client sent 48 datagrams ECT(0) and 4
  Not-ECT, and its server 87 and 2.

  Rotor 0.3.0 carried no codepoint in two places: on Linux, to or from an IPv4 client of a socket
  bound to `::`, and on macOS, over any IPv4 socket. So the server bound the IPv4 wildcard for
  `ecn`, and on macOS validation failed on the first ACK, as §13.4.2.2 asks. Rotor v0.4.0 fixes
  both (`400d748`, `fbe9311`). With it the server binds `::` again and still passes `ecn`
  against colibri and ngtcp2, and with `fbe9311` `tools/quic_udp.sh` on macOS received 2,793
  datagrams ECT(0) and 67 Not-ECT, the client's path ending capable.

  **`handshakeloss` between two colibri endpoints, 2026-09-24.** It failed one run on 2026-09-23.
  The datagram carrying the server's ServerHello was lost. Decision 65's two early resends went
  out 6 ms apart and were lost together. The server's Handshake probes then reached a client with
  no Handshake keys.
  - `65a0857`: the simulator can run the runner's drop-rate network, 30% of datagrams lost each
    way and at most three in a row, and times each handshake. Over 2,000 seeds one handshake took
    43 seconds, and 11 took 16 seconds or more.
  - [Decision 70](decisions.md): a PTO also probes every other space with ack-eliciting packets
    in flight (RFC 9002 §6.2.4), so a lost ServerHello goes out again with the Handshake probes.
    Over the same 2,000 seeds the slowest handshake took 34 seconds, and 3 took 16 or more.
  - [Decision 71](decisions.md): the second early resend waits one PTO after the first. The
    simulator cannot show this, because it delivers every datagram due at one instant before
    either endpoint sends.

  7 mutations, 7 CAUGHT. The census of the QUIC check is now 13,259 datagrams, 13,338 packets,
  686 dropped and 486 marked, crc32 `0x686522e4`; the adversary check's is 5,126 datagrams and
  1,678 dropped by the adversary; and the runner check's 256 seeds are 4,150 datagrams with the
  slowest handshake at 8.4 seconds. Each in Debug and in ReleaseSafe on macOS arm64.

  The runner at `740c05a` then passed `handshakeloss` and `transferloss` with colibri against
  itself, and in both roles against quic-go and ngtcp2. colibri against itself passed
  `handshakeloss` five more times in a row. With that, every runner case this step names passes.

  **The RTT estimate in the runner, 2026-09-27**
  ([#73](https://github.com/c4milo/colibri/issues/73)). The UDP endpoints pass colibri the instant
  Rotor's last tick read (decision 63). Rotor 0.4.0 read the clock again after a wait only when the
  wait produced no event. So a datagram that ended a wait was processed at the instant the tick
  started, and an RTT sample taken from it left out the wait. On the `handshake` case's path, 15 ms
  each way, a scratch build of colibri's client at `a6a4791` printed `latest=289us min=289us
  smoothed=289us variation=144us`, and its PTO was about 1.5 ms. Rotor v0.6.0, `59599a8`, reads the
  clock after every wait that blocked ([rotor#6](https://github.com/c4milo/rotor/issues/6)), and
  colibri pins it.

  With v0.6.0, a scratch build whose client printed its estimate as each connection ended ran
  `handshake` three times as the client against quic-go, in the runner at `740c05a` in Docker on
  macOS arm64. Each run passed. A wire sample is read from the client-side capture: the time from a
  client packet to the ACK frame that first names it as the largest acknowledged, for each ACK
  frame that arrived before the client's CONNECTION_CLOSE.

  | Run | Printed | Wire samples |
  |---|---|---|
  | 1 | `latest=39919us min=39919us smoothed=41999us variation=13904us` | 40.65, 49.92, 35.91 ms |
  | 2 | `latest=41542us min=41542us smoothed=43559us variation=17018us` | 43.23, 38.45 ms |
  | 3 | `latest=35643us min=35643us smoothed=39892us variation=16401us` | 39.89, 33.80 ms |

  Each `latest` is the last wire sample plus 1.8 to 4.0 ms. That sample's packet carries the
  instant its tick read before the tick processed the server's handshake messages, and Rotor sends
  a packet on the tick after the one that built it.

  With v0.6.0 pinned, `zig build test`, `tools/quic_udp.sh` and `tools/quic_aioquic.sh` pass on
  macOS arm64, and `tools/interop.sh quic-go` gave:
  - colibri's server and colibri's client: every case passed.
  - colibri's server and quic-go's client: every case passed but `ecn`, which quic-go does not run.
  - quic-go's server and colibri's client: every case passed but `ecn`, and `handshakeloss`, which
    failed as [#72](https://github.com/c4milo/colibri/issues/72) records. The server-side capture
    holds 51 Source Connection IDs in quic-go's Initial packets and 50 in the client's.

- **Step 11 — QPACK.** Static-table-only encoding first, because both QPACK settings default to
  zero and a static-only encoder is legal and useful; then the dynamic table with the encoder and
  decoder streams, Known Received Count, Required Insert Count, Base, relative and post-base
  indexing, and blocked streams. **Check:** `qpackers/qifs` vectors at the three settings its
  filenames encode, with the draft-05 caveat of [decision 25](decisions.md#correctness) applied —
  a mismatch is checked against RFC 9204 before it is treated as colibri's bug; RFC 9204 Appendix
  B's reference encodings; fuzzing; mutations. *Large.*

  **The static-only half is done, 2026-09-20.** Four files and a generated table.
  `src/qpack/static_table.zig` is RFC 9204 Appendix A, 99 entries numbered from 0, generated by
  the same `tools/static_table.zig` that generates HPACK's: the two appendices are the same rows
  of `| index | name | value |`, so the parser is shared and the difference is a `Variant`.
  `zig build qpack-static-table` rewrites it and `zig build test` fails when it differs from what
  the RFC yields.

  `representation.zig` and `representation_write.zig` are §4.5's five field line shapes and
  §4.5.1's field section prefix. `encoder.zig` and `decoder.zig` are the static-only pair, which
  is a complete encoder and decoder rather than a stage of one: §5 gives both QPACK settings a
  default of zero, so an endpoint using no dynamic table is conformant against every peer, needs
  no encoder stream, and can never block a request stream.

  One ruling is recorded here because the RFC leaves it open. A field line the caller marks never
  indexed is written as a literal **even where the static table holds it whole**. An index
  carries no `N` bit, so §7.1.3's signal to the next hop would be dropped, and §4.5.4 requires a
  literal on every hop that forwards one. The static reference itself would leak nothing — the
  table is public — but the next hop is what the bit is for.

  **Check so far:** Appendix B.1's octets in both directions, the encoder producing the RFC's own
  bytes for the RFC's own example and the decoder reading them back; 29 mutations over the four
  files, all caught after two missing tests were written. **Still owed:** the dynamic table with
  the encoder and decoder streams, and the `qpackers/qifs` vectors, which need it.

  **The decoder uses the dynamic table, and the vectors run, 2026-09-24.**
  - `5aa9ca5` and `8e2b8d8`: [decision 74](decisions.md). The decoder applies the encoder stream,
    resolves relative and post-Base references, blocks a stream until its Required Insert Count
    arrives, and writes Section Acknowledgments, Stream Cancellations and Insert Count
    Increments. RFC 9204 Appendix B.2 to B.5 pass in order through one decoder. The change also
    fixed a defect: a peer's literal longer than `field_name_len_max` reached an assertion in
    `FieldSection.append`, where RFC 9204 §7.4 makes it a decompression failure. 31 mutations,
    31 CAUGHT.
  - `9f94cbb`: RFC 9204 Appendix A wraps ten values onto a second row, and
    `tools/static_table.zig` read only the first row of each. Entry 52 was `text/html;`, and
    entries 57 and 58 were one value. The check in `zig build test` compared the table with the
    same parse, so nothing caught it until the vectors ran. 5 mutations, 5 CAUGHT.
  - `40723c8`: [decision 75](decisions.md). `zig build qpack-vectors` decodes the corpus, and
    `zig build test` runs it. 5 mutations, 5 CAUGHT.

  Before `9f94cbb`, 353 of the corpus's 529 files failed: 352 at a wrapped entry, and the
  corpus's examples file for the reason decision 75 gives. After it, the
  tool printed `files=528 sections=137984 lines=1820016 blocked=7342 skipped=1 failed=0` on macOS
  arm64: every file six encoders made, at capacities 0, 256, 512 and 4,096, with 0 or 100
  blocked streams, decodes to its input. 7,342 sections blocked and were decoded once their
  entries arrived. The file skipped is the corpus's examples file, for the reason decision 75
  gives.

  **Still owed:** the encoder's use of the dynamic table, with colibri's own encoded files for
  the offline interop; the two `.qif` tools of §9; and fuzzing.

  **The encoder uses the dynamic table, 2026-09-24.**
  - `ae3199b`: `EncoderState.referenced_floor` returned the lowest Required Insert Count among
    unacknowledged sections. That bounds a section's largest reference, not its smallest, so an
    eviction checked against it could remove an entry a section still needed (§2.1.1). Each
    outstanding section now records its smallest reference. 1 mutation, 1 CAUGHT.
  - `6860016`: [decision 76](decisions.md). The encoder inserts lines over the encoder stream,
    references them within the peer's blocked-stream limit, inserts speculatively when a stream
    may not block, evicts only evictable entries, and reads the decoder stream. 22 mutations, 22
    CAUGHT. Three first survived: one found a check no input could reach, now removed, and two
    found rules no test isolated.
  - `5c4bd0a`: `zig build qpack-vectors` also encodes every qifs input with colibri's encoder at
    four settings, and decodes it back in two modes. In one the decoder stream flows back after
    each section. In the other the encoder hears nothing, and the whole encoder stream arrives
    after the last section, the latest it can. All 56 runs decode exactly. The comparison's
    mutation is CAUGHT, and so are three encoder mutants the vectors alone catch.

  The octets the encoder wrote for the seven inputs, sections and encoder stream together, with
  acknowledgments flowing back:

  | Table capacity | Blocked streams | Octets |
  |---|---|---|
  | none | any | 714,888 |
  | 4,096 | 0 | 477,759 |
  | 4,096 | 100 | 280,040 |

  The inputs' names and values are 1,144,015 octets unencoded. These counts are the same on any
  machine; timing waits for `bench/` (decision 32).

  **Still owed:** the two `.qif` tools of §9, which write colibri's encoded files for other
  decoders to read; fuzzing; and the TLA+ model of the two tables' state (issue #46).

  **Lean proofs and a seeded check, 2026-09-24.**
  - `1434db1`: [decision 77](decisions.md). `spec/lean/` proves that §4.5.1.1's Required Insert
    Count comes back exactly whenever the decoder is at most `MaxEntries` behind it and less than
    `MaxEntries` ahead. §2.1.1's rule that no entry is evicted before it is acknowledged is what
    keeps a decoder that close. It also proves the §3.2.5, §3.2.6 and §4.5.1.2 index arithmetic.
    `zig build test` checks the Zig functions against the proved definitions' outputs, 2,361
    Required Insert Count rows and 162 Base rows. 6 mutations: 5 CAUGHT, and one equivalent, the
    zero check after the full-range check refusing the one count the weakened check lets through.
  - `f4aa8fe`: `src/sim/qpack_check.zig`. One seed draws the peer's settings, up to 24 sections
    on up to 8 streams, and the order the three streams arrive in, each cut at any octet, with
    streams cancelled. Every section must decode as written, and every run must end with nothing
    blocked, unread or unacknowledged. Each seed runs twice and must write the same trace.

  `zig build sim -- --qpack-check` printed, in Debug and in ReleaseSafe on macOS arm64:
  `seeds=256 decoded=2932 lines=19049 blocked=565 cancelled=194 inserts=4778 octets=350638
  trace_octets=529023 crc32=0xf7bc7677`. Of ten encoder and decoder mutants, six break one of the
  check's rules. Two change the digest and break no rule in these seeds: one evicts an entry
  before its acknowledgment, and one references a name its own line's insert evicted, which fails
  only when the section reaches the decoder after that insert. Two reach code colibri's encoder
  never exercises: a decoder stream written in part, and a dynamic name inside an insert. The unit
  tests catch all ten.

  **The QIF tools, the TLA+ model and fuzzing, 2026-09-24.** Every check this step names now
  exists.
  - `66b4133`: §9's two QIF tools. `zig build qif -- encode` writes a QIF text as a file in the
    QPACK Offline Interop format with colibri's encoder, in either acknowledgment mode, and
    `decode` reads such a file back into QIF with colibri's decoder. 11 mutations, 11 CAUGHT.
  - `916be43`: `tools/qif_interop.sh` runs the tools against ls-qpack, through aioquic's
    pylsqpack, in both directions. It takes three qifs inputs at three settings, with ls-qpack's
    sections ahead of their encoder stream where streams may block. All 45 runs decode exactly.
  - `ca6cccb`: `spec/tla/qpack_tables` models the encoder stream, the sections and the decoder
    stream, each able to fall behind the others, with cancellations. It checks that no referenced
    entry is evicted, no section reads a missing entry, no stream blocks past the limit, and every
    section finishes. `zig build tla` printed `holds, as expected, 192555 distinct states` with
    blocked streams allowed and `52633` with none. The three mutant configurations are violated
    as expected: an eviction of a referenced entry, an ignored blocked limit, and a ready stream
    counted as blocked.
  - `d83f157`: the last mutant was colibri's decoder. A stream whose entries had arrived, but
    whose section was not yet read again, still counted against the blocked-stream limit, while
    the encoder had stopped counting it (§2.2.1). [Decision 74](decisions.md) is amended. 2
    mutations, 2 CAUGHT.
  - `1f6e297`: fuzz property functions for the three inputs a peer controls: a field section, the
    encoder stream and the decoder stream. As in step 1, `zig build test` runs each over its
    corpus and every input of up to two octets, because the fuzzer does not build with Zig
    0.16.0. Two octets never reach a field line or a whole insert, so
    `src/sim/qpack_input_check.zig` also edits what the encoder writes, up to eight changed,
    inserted or removed octets or a cut end, and hands it to the reader under test. Every input
    must be read or refused with an error, never halt, and each seed must replay.

  `zig build sim -- --qpack-input-check` printed, in Debug and in ReleaseSafe on macOS arm64:
  `seeds=256 inputs=8192 taken=3935 blocked=86 refused=4171 crc32=0x0452f651`. 200,000 seeds, 6.4
  million inputs, ran in ReleaseSafe with none halted. 4 mutations, each removing one check on
  peer input: each is CAUGHT by its fuzz property and by the input check at 256 seeds.

  **The nudge edit, 2026-09-26.** The QUIC input check of step 9a shares these edits, now in
  `src/sim/input_edit.zig`, and added an octet moved up or down by one. The census changed to
  `seeds=256 inputs=8192 taken=3933 blocked=128 refused=4131 crc32=0x7971245b`, in Debug and in
  ReleaseSafe. 200,000 seeds, 6.4 million inputs, ran in ReleaseSafe with none halted.

- **Step 12 — h3.** Stream types, the frame layer, the one setting, the control stream rules,
  request and response mapping, GOAWAY, greasing. **Check:** `h3spec` against the h3 entry point,
  with every case accounted for; the interop runner's `http3` case; `h2load --h3`; and the h2
  suite's semantics tests re-run against h3, which proves the `http` module is
  shared rather than duplicated. *Medium.*

  **The message rules h3 will need are in `http` already, 2026-09-20.** `http/message_lines.zig`
  and `http/message_request.zig` hold every rule RFC 9113 §8 and RFC 9114 §4 both state, and
  return a reason rather than a verdict; h2's two files in `src/h2/message/` are now the mappers
  that name h2's errors for those reasons. h3's side of step 12 writes the second mapper and the
  five rules [decision 51](decisions.md) keeps per protocol, and writes no rule twice. The move
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
  [decision 35](decisions.md#memory) forbids. And a short read is not a protocol error —
  `Truncated` means the octets have not all arrived, while every other error names the §8.1 code
  the connection closes with. Telling those two apart is why the header is read on its own.

  **Check so far:** 32 mutations over the three files, all caught. **Still owed:** the request
  and response mapping of §4.1 to §4.3, which §12 question 6 must settle first; the connection
  itself, which needs QUIC streams and so waits on 9e; and h3spec, the interop runner's `http3`
  case and `h2load --h3`, which all need a connection.

  **Fuzzing, 2026-09-26.** `frame_fuzz.zig` reads a header and, when colibri reads the payload
  whole, the payload ([#53](https://github.com/c4milo/colibri/issues/53)). A short header must consume nothing. A whole payload must never
  be `Truncated`, which would have the caller wait for octets that are not coming. An accepted
  payload must be the type its header named and keep §7.2's rules, which the property reads
  again. Written again, it must read back the same. 10 mutations, 10 **CAUGHT** by the fuzz test
  alone, two of them only after the corpus gained a SETTINGS payload cut inside a pair and one
  holding a single setting.

  **The connection and its simulator check, 2026-09-24.** The owner ruled h3's send path first
  (decisions 78 and 79), and decision 80 followed:
  - `61443b6`: `quic` reports how far a stream is acknowledged from its start (decision 78), which
    h3's three streams need because they never end. 7 mutations, 7 CAUGHT.
  - `3e1ed79`: `quic` copies a stream's received octets without taking them (decision 80), so a
    field section blocked on QPACK stays in the receive pool. 7 mutations, 7 CAUGHT.
  - `1b5d763`: `quic` keeps the error code of a peer's RESET_STREAM for the application. 2
    mutations, 2 CAUGHT.
  - `929a760`: `src/h3/connection/`. It opens the control and QPACK streams and reads the peer's.
    It maps requests and responses (§4.1), with interim responses, trailers and content-length
    (§4.1.2). It covers GOAWAY (§5.2), refusals and resets (§4.1.1), and greasing (§7.2.4.1,
    §8.1). Every RFC 9114 rule it checks has a test that breaks it. 65 mutations, 65 CAUGHT. Three
    first survived and gained tests.
  - `1db9175`: `src/sim/h3_check.zig`. A colibri client and server exchange a seed's requests
    over step 8's network. Every field section and content octet must arrive as planned. The
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
    of 4,096 octets and 16 blocked streams, so each peer's encoder uses one.
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
    directions, octet for octet. aioquic's h3 uses ls-qpack with a dynamic table.
  - `tools/h3load.sh` printed `requests: 1000 total, 1000 started, 1000 done, 1000 succeeded,
    0 failed` with ALPN h3, three runs out of three. It saved 84% of the header octets, which
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
    ([decision 81](decisions.md)). 8 mutations, 8 CAUGHT.
  - The encoder-stream order is the rule `8accf3c` added after `h2load --h3` lost requests. The
    model shows that without it, blocked sections can hold the connection window.

  **The close after a failed handshake, 2026-09-24.** colibri's UDP server now sends the
  CONNECTION_CLOSE RFC 9001 §4.8 owes when its TLS stack refuses a handshake, and serves the next
  connection ([#59](https://github.com/c4milo/colibri/issues/59), [decision 84](decisions.md)).
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
  handshakes now complete ([decision 85](decisions.md)).
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
    aioquic's server, colibri's client ran TLS_AES_256_GCM_SHA384, so its key log held 48-octet
    secrets.
  - `tools/interop.sh <checkout> quic-go,ngtcp2`, whose image built chapulin `1558099` with the
    new make line: every case passed in both roles against both peers. quic-go reports its own
    side of the ECN case as unsupported.
  - 3 mutations of the switch, all CAUGHT: a define the object lacks, which `check_build`
    refuses; the resumption PSK's length ignored; and `no-ecn` ignored.

  **Trace validation, 2026-09-25**
  ([#58](https://github.com/c4milo/colibri/issues/58), [decision 87](decisions.md)).
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
      octet is already acknowledged. It is now its own action, `StopSending`, and no longer part
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

- **Step 13 — `bench/`.** The judge, the competitor matrix and the memory measurement, under
  §11's method on the `ubuntu-24.04-arm` runner (decision 33 as amended on 2026-09-30). Six parts;
  the owner ruled on 2026-09-30 that 13a and 13b come first:
  - **13a**, the judge. `bench/run.sh` builds colibri's test-only servers in ReleaseSafe, pins each
    server and h2load to cores of their own, and counts the server's instructions, cycles and
    system calls with `perf stat`, per request and per connection: h2 in cleartext and over TLS,
    with many requests on a connection and with one. `.github/workflows/bench.yml` measures a
    `base` and the change in turns in one job, five rounds each after a warm-up it discards, and
    reports each input's median and spread. **Check:** two jobs of a tree against itself give the
    noise floor, which `docs/performance.md` records, and a mutant that adds a known cost per
    request loses past it.
  - **13b**, static memory per connection: each connection struct's size, printed from the code
    being committed, the way chapulin's `bench/sram.sh` measures its rows. **Check:** the table in
    `docs/performance.md` matches what the build prints, and `zig build test` fails when a struct
    changes size without the table.
  - **13c**, h2 against h2o and nginx under h2load, in the same job.
  - **13d**, h3 against quiche and quic-go under `h2load --h3`, from `tools/h3load/`'s pinned
    build, with handshakes per second for §11.1's short connections.
  - **13e**, QUIC throughput under msquic's `secnetperf`, through the `perf` ALPN endpoint of §9.
  - **13f**, latency percentiles at stated offered loads, from a generator that sends on a
    schedule.

  *Medium.*

  **13a, 2026-09-30.** `bench/run.sh` builds the test-only h2 server in ReleaseSafe, pins it and
  h2load to cores of their own, and counts the server's instructions, cycles, CPU time and system
  calls per request and per connection with `perf stat`. `bench/report.py` gives each input's
  median and spread over five rounds after a warm-up it discards, and the ratio of the change to
  the base, losses first; a loss past the noise fails the run. `.github/workflows/bench.yml` runs
  both in two jobs on the `ubuntu-24.04-arm` runner: a Neoverse-N2 with 4 cores, Linux
  6.17.0-1022-azure and perf 6.17.13.

  What each check printed:
  - The floor. In five jobs of a tree against itself, no ratio of instructions per unit moved from
    1 by more than 0.13%, and the owner set the floor at 0.5%. `docs/performance.md` lists the
    runs.
  - The mutant: 150 iterations of a four-instruction loop in the server's `write_head`, 600
    instructions per response head by the disassembly, on a branch deleted after
    [run 36732471944](https://github.com/c4milo/colibri/actions/runs/36732471944). In both jobs
    h2-many lost at 1.0155 and h2-tls-many at 1.0071 and 1.0069, and each job failed. User
    instructions per request on h2-many rose by 604.1 in each job. h2-one and h2-tls-one stayed
    within the noise, as a cost of 0.2% and 0.001% of theirs should: **CAUGHT**.
  - `python3 bench/report.py --test`, which `tools/ci.sh` runs: 12 tests, and 17 mutations of the
    report, each **CAUGHT**. A server that never listens stops the run at the readiness probe,
    and a probe that trusts h2load's exit status lets it through: **CAUGHT**.
  - The first runs found three defects, each fixed on main: the probe (9ee28cb), perf 6.17's
    task-clock unit (9ee28cb and 55de1f4), and compiler_rt's `memset` in the timed programs
    (4267c63). [Run 36727035651](https://github.com/c4milo/colibri/actions/runs/36727035651)
    judged the last in both jobs: h2-one ran 0.355 of its instructions, h2-many 0.847,
    h2-tls-many 0.924 and h2-tls-one 0.989.
  - With it, [run 36727047216](https://github.com/c4milo/colibri/actions/runs/36727047216)
    counted 39,040 instructions per request on h2-many, 86,084 on h2-tls-many, about 304,600 per
    connection on h2-one and 55.57 million on h2-tls-one.

  **13b, 2026-09-30.** `bench/memory.zig` measures each struct a caller holds for one connection
  with `@sizeOf`, and `zig build bench-memory` prints the table for the objects the build targets,
  under a heading that names chapulin's `AES` value. x86-64 and arm64 build `AES=runtime` (decision
  97 as amended), so `docs/performance.md` holds one table, and `zig build test` checks it.

  What each check printed, on macOS arm64:
  - `zig build test-bench`, and `zig build test-bench -Dcpu=generic`: 1 of 1 test each.
    `zig build bench-memory` for `x86_64-macos`, run under Rosetta with `-Dcpu=znver3` and with
    `-Dcpu=x86_64`, printed the same table.
  - 2 mutations, each **CAUGHT**: a number changed in the table, and 8 bytes added to
    `h11.connection.Connection`.
  - The largest structs: `server.Connection` holds 306,272 bytes and `server.QuicConnection`
    717,520, the latter without the receive pool its caller passes, whose default holds 1,505,288.

  **13c, 2026-10-01.** `bench/run.sh --competitors` measures nginx 1.24.0 and h2o 2.2.5, from the
  runner's Ubuntu 24.04 packages and built with OpenSSL 3.0.13, in turns with colibri's server over
  the four inputs. Each answers the same eight octets from memory, with one worker on the server's
  core, and each presents the same P-256 identity and runs TLS_AES_256_GCM_SHA384 over X25519.
  `docs/performance.md` says how each is set up.

  [Run 36851113101](https://github.com/c4milo/colibri/actions/runs/36851113101), on cf7bcd2,
  printed these medians per request or per connection. Its two jobs agree within 0.6% on every
  instructions figure and within 5% on every cycles figure; this is the first job:

  | Input | Instructions: colibri | h2o | nginx | Cycles: colibri | h2o | nginx |
  | --- | ---: | ---: | ---: | ---: | ---: | ---: |
  | h2-many | 39,040 | 34,340 | 46,184 | 11,169 | 15,569 | 28,606 |
  | h2-tls-many | 85,507 | 37,699 | 41,522 | 29,934 | 20,683 | 21,680 |
  | h2-one | 304,215 | 143,544 | 141,706 | 171,778 | 104,541 | 98,323 |
  | h2-tls-one | 55,569,416 | 2,353,014 | 2,589,572 | 22,410,663 | 1,461,011 | 1,381,869 |

  Against decision 31's expectations:
  - Many requests on one connection: colibri makes 0.04 system calls per request, where h2o makes
    1.2 and nginx 2.1. It takes the fewest cycles of the three, 0.72 of h2o's and 0.39 of nginx's,
    and fewer instructions than nginx, 0.85 of its count, but more than h2o, 1.14.
  - A cleartext connection, where decision 31 expects colibri to win: colibri loses. It costs 2.1
    times the instructions of either competitor and 1.6 to 1.7 times the cycles, and 5 to 9 times
    their user instructions.
  - TLS, where decision 31 expects colibri to match, because every competitor calls the same
    asymmetric crypto: colibri loses. A handshake costs 21 to 24 times the instructions of either
    competitor and 15 to 16 times the cycles. A request over TLS costs 2.1 to 2.3 times the
    instructions and 1.4 times the cycles. Both are chapulin's work (decision 94), not OpenSSL's.
  - The first competitors run,
    [36813252981](https://github.com/c4milo/colibri/actions/runs/36813252981), failed before it
    measured: h2o, started by the runner's own user, refused the `user` line a container needs.
    cf7bcd2 keeps that line for root alone.

- **Step 14 — stdx's decoders, taken as a package.** The decoder of the `gzip` and `deflate`
  codings is stdx's ([decision 90](decisions.md)), and its own design names the check that proves
  it: https://github.com/c4milo/stdx/issues/1, with zlib and Wuffs as oracles and baselines.
  **Check:** colibri pins a stdx commit whose gzip and deflate decoders have passed that check,
  and CLAUDE.md lists stdx among the ruled dependencies. *Small.*

  **Check passed, 2026-09-26.** stdx's issue 1 closed that day, with its decoders checked against
  zlib and Wuffs. colibri pins stdx `b969898`, stdx's `main` then, whose CI passed, and CLAUDE.md
  lists stdx among the library's two dependencies. `build/modules.zig` gives h11 stdx's `codec`,
  `gzip` and `zlib` modules. stdx is not lazy in `build.zig.zon`, because the library imports it:
  a project that depends on colibri fetches it too. stdx's build declares `-Drelease` rather than
  `-Doptimize`, as colibri's does, so colibri passes it `release`. `zig build` and `zig build test`
  pass with it.
- **Step 15 — h11.** RFC 9112 as [decisions 88 and 91](decisions.md) rule it. The owner cut it
  into four parts on 2026-09-25, in the order h2's steps 1 to 4 took: the parsers first, then the
  connection over step 2's byte pipe, which already exists. Each part names its own check, and
  every request-parsing check has a mutation (decision 88). *Large.*

- **Step 15a — the message parsers and writers.** What RFC 9112 §2 to §7 put on the wire:
  - the request line (§3) and the status line (§4), with each element separated by one SP, and
    HTTP-version case-sensitive (§2.3);
  - the request-target in its four forms (§3.2), and the Host rules a server holds a request to
    (§3.2): 400 for none, for more than one, or for an invalid value;
  - field lines (§5): a field name and a colon with no whitespace between, which a server refuses
    with 400 (§5.1), and OWS trimmed from the value;
  - obs-fold (§5.2): a server refuses it with 400, and a client replaces each one with SP, which
    §5.2 makes a user agent's MUST;
  - a bare CR is invalid (§2.2), and so is whitespace between the start line and the first field
    line (§2.2);
  - §6.3's eight rules for the length of a body, with `http.content_length` for the list rule
    of item 5, and §6.1's rules for Transfer-Encoding with Content-Length and in HTTP/1.0;
  - the chunked coding (§7.1): the chunk size with no overflow, chunk extensions skipped within a
    named limit, the last chunk, and the trailer section.

  A parser reads a start line and field section only when the whole of it is in the caller's
  slice, up to a named limit, as h2 reads a whole frame (§4.1). Where RFC 9112 leaves a choice,
  such as a lone LF as a line end (§2.2) or whitespace other than SP between elements (§3, §4),
  colibri takes the strict side and refuses, because §11.2 traces request smuggling to parsers
  that differ in what they forgive. **Check:** a golden corpus with a manifest, valid and invalid,
  carrying one case per refusal and the smuggling shapes: Content-Length with Transfer-Encoding,
  `Transfer-Encoding: chunked` hidden behind whitespace or repeated, a chunk size that overflows,
  and obs-fold in a request. The step 2 byte pipe feeds every parser at seeded splits, and each
  split must give what the whole input gives. Fuzzing and mutations.

  **Check passed, 2026-09-25**, `91316b0` to `df09b96`, on macOS arm64 with Zig 0.16.0.
  - `91316b0`: the head. A resumable scanner finds a head's end, scanning each octet once however
    the head arrives, and refuses a bare CR and a lone LF. The start line and the field lines are
    read into `http.FieldSection`, and a client joins obs-fold with SP (RFC 9112 §5.2).
  - `c6257c2` and `6b8e1ca`: RFC 3986 in `docs/rfcs/`, and its grammar for host, port, authority,
    origin-form and absolute-URI in `http.uri`.
  - `694f1c8`: the request-target's form and the Host rules of RFC 9112 §3.2.
  - `1be3578`: §6.3's eight rules for the length of a body, and decision 91's codings.
  - `043d357`: the chunked decoder, which returns data as slices of the caller's octets.
  - `f55aa0b`: the request, response and chunk writers, which refuse what colibri would refuse
    to read.
  - `d42b181`: the golden corpus, 32 request and 12 response cases. The owner raised
    `case_len_max` to 256 and `manifest_len_max` to 32,768, and `decoded_len_max` doubled with them.
  - `bdeb891`: the split check, below.
  - `df09b96`: fuzz properties for the head and chunked parsers.

  What each check printed:
  - `zig build test`: 1730 of 1794 tests passed, 64 skipped. That run includes `golden-check`,
    which decodes every h11 case to its verdict.
  - `zig build sim -- --h11-split-check`, in Debug and in ReleaseSafe: `h11-split: seeds=256
    passed=170 rejected=86 messages=522 chunks=7161 trace_octets=69565 crc32=0x793d2f38`. Every
    seed read in seeded chunks what it read in one piece, every body matched the plan's, and each
    of the 86 planted defects was refused with its error.
  - `zig build test-h11 --fuzz=1M` does not build: Zig 0.16.0's own test runner fails to compile
    in fuzz mode, as it does for every module
    ([#53](https://github.com/c4milo/colibri/issues/53)). The fuzz properties run over their corpus
    and every input of up to two octets.
  - Mutations: 121 CAUGHT and 1 equivalent. By commit: 19 in the head, 17 of 18 in the URI
    grammar, 16 in the target and Host rules, 23 in the body rules, 18 in the chunked decoder, 17
    in the writers, 6 caught by the corpus alone, 3 caught by the split check alone, and 2 in the
    fuzz properties. The equivalent mutant lets userinfo hold "@", which the first "@" always
    ends.

  **RFC 7405, 2026-09-29.** RFC 9110 §2.1 and RFC 9112 §1.2 write their grammar in RFC 5234's
  ABNF with RFC 7405's `%s` prefix, and `docs/rfcs/` now holds RFC 7405. Its §2.1 replaced the
  note in RFC 5234 §2.3 that made every quoted string match in any case, and keeps that rule for a
  string with no prefix, so the four citations of the rule now name RFC 7405 §2.1. `http.uri`
  names RFC 3986 §3.2.2 instead, which says itself that IPvFuture's "v" is case-insensitive.
  - colibri reads three `%s` strings, and compares each octet for octet: HTTP-name in h11 (RFC 9112
    §2.3), the weak prefix `W/` in the server's ETag (RFC 9110 §8.8.3), and `clear` in the
    client's Alt-Svc (RFC 7838 §3). RFC 9110 §5.6.7's HTTP-date uses `%s` too, and colibri parses
    no HTTP-date.
  - Mutations, on macOS arm64 with Zig 0.16.0: HTTP-name compared in any case, `clear` compared in
    any case, and TE's "trailers" compared exactly, each **CAUGHT**. Two were **NOT CAUGHT**: the
    weak prefix compared in any case, and an IPvFuture that starts with "V" refused. A test for
    each now catches it.

- **Step 15b — the connection.** Persistence (§9.3), the client's pipelining with responses
  matched to requests in order (§9.3.2), a server that reads one request at a time, and closing
  (§9.6). **Check:** a simulator check over step 2's byte pipe. A colibri client and server
  exchange seeded requests, pipelined, with chunked and length-delimited bodies and early closes,
  in pieces, and a seed replays byte for byte (invariant 5). Golden cases and mutations.

  **Check passed, 2026-09-25**, `60cd6f6` to `199a52d`, on macOS arm64 with Zig 0.16.0.
  - `60cd6f6`: the connection. A server reads one request at a time and writes the error response
    a refused request owes. A client pipelines as decision 88 rules and gives each response to
    its oldest request.
  - `eda6c24`: the close option ends the connection after the response it names, at both ends
    (RFC 9112 §9.6). Writing the simulator check found the server's half.
  - `aa11d3f`: the simulator check, `src/sim/h11_exchange_check.zig`. It does not use
    `sim.pipe.run`, which feeds one stream fixed before the run to one subject. A client's
    requests depend on the responses it has read, so the check keeps one stream each way and cuts
    each into chunks of 1 to `chunk_len_max` octets, as the pipe does.
  - `199a52d`: 14 golden cases of the `h11_server` format, request streams a server reads, each
    with the error response it owes as its verdict. A 414 and a 431 need a head longer than
    `case_len_max`, so the connection's unit tests hold those two.

  What each check printed:
  - `zig build test`: 1752 of 1816 tests passed, 64 skipped.
  - `zig build sim -- --h11-connection-check`, in Debug and in ReleaseSafe: `h11-connection:
    seeds=256 answered=828 unanswered=82 steps=10864 trace_octets=122134 crc32=0x701b34cd`.
    Each seed's exchanges were the same in seeded chunks as delivered whole, every body matched
    the plan's, and the 82 requests pipelined past a close went unanswered.
  - Mutations: 62 CAUGHT and 1 NOT CAUGHT. 38 were caught by the connection's unit tests, 3 in the
    close fix, 13 by the simulator check alone and 8 by the golden cases alone. The NOT CAUGHT
    mutant passes the simulator check: a client that ignores its own close option. colibri's
    server always answers that request with the close, so the check cannot reach the rule, and
    the client's unit test catches it.

  **A body the caller sends itself, 2026-09-26.** `Connection.count_body` counts octets the
  caller sends from its own buffer against the body its head declared, and writes nothing
  ([decision 95](decisions.md)). A chunked body refuses it. 6 mutations, 6 **CAUGHT** by the
  connection's unit tests.

  **RFC 9931, 2026-09-29.** RFC 9931 updates RFC 9112 with rules for the octets a client sends
  before a CONNECT or an Upgrade is answered, and `docs/rfcs/` now holds it. The owner ruled on
  what h11 does with those octets ([decision 109](decisions.md)). What was checked, and what
  changed:
  - §8, the server: a proxy server MUST close the connection when it refuses a CONNECT. h11 read the
    next request after any final response to CONNECT other than 2xx, so it served the POST of
    RFC 9931 Figure 1. `f109a15` closes the connection after every such response, at every h11
    server.
  - §8, the client: a proxy client MUST wait for the 2xx before it forwards the tunnel's octets,
    or send `close`. h11's client pipelines nothing after a CONNECT, which is not idempotent, and
    opens the tunnel's writer only on the 2xx. Content declared on the CONNECT was the one way to
    write octets before the answer, and `de5b5f4` refuses it at both ends (RFC 9110 §9.3.6).
  - The tunnel: RFC 9110 §6.4.1 makes every 2xx to CONNECT a tunnel, a 204 too, and h11 read a
    204 as an ordinary response at both ends. `75d7320` opens the tunnel on it. A server now also
    refuses to write Content-Length or Transfer-Encoding on a 2xx to CONNECT, which RFC 9110 §8.6
    and RFC 9112 §6.1 forbid.
  - Upgrade: h11 implements none. Its server writes no 101 and reads the next request as HTTP/1.1,
    which RFC 9110 §7.8 and RFC 9931 §5 allow. Its client failed on a 101 but still sent the
    Upgrade a caller named, and `209d2a3` refuses that request, as the `client` module does.
  - §6.1: a TLS record sent after an ignored `Upgrade: TLS/1.2` is never read as a request. The
    head scanner refuses it once it meets a bare CR, a lone LF or a start line longer than
    `start_line_len_max`. It does not refuse the record's first octet, 22, on its own, so the
    server may wait for more octets before it answers. The paragraph below changes that.
  - §6.3 updates RFC 9298's `connect-udp`, which colibri does not implement (decisions 19 and 22).
    h2 and h3 are outside §8, which binds HTTP/1.1 alone.
  - The test-only server answered CONNECT with 200 and a Content-Length, and opens no tunnel.
    `8f842b9` answers 501 over h11 and h2, and h11 closes after it. The HTTP Garden sends it the
    golden corpus's CONNECT case, which now gets that 501.

  What each check printed, on macOS arm64 with Zig 0.16.0:
  - `zig build test`: 128 of 128 steps and 2361 of 2361 tests passed. `golden-check` read the new
    server case `h11_server_connect_content`, a CONNECT with content, which owes a 400.
  - `tools/h11_server_interop.sh --tls curl go` printed "every request ended with 200 over h11,
    in cleartext and TLS, from: curl go", and `tools/h11_interop.sh --tls go h2o` printed "every
    exchange ended as planned over h11, in cleartext and TLS, against: go h2o". `tools/h2spec.sh
    18443 --tls` passed 144 of 146 cases in cleartext and over TLS, skipping decision 41's two.
    The HTTP Garden needs Linux, and did not run.
  - Mutations: 24 **CAUGHT** and 1 equivalent. By commit: 4 in the close after a refused
    CONNECT, 6 in the 2xx rules, 8 in the content rules, 4 in the client, and 2 in the test
    server. The golden case alone catches the read side's content check dropped. Two of the
    client's were **NOT CAUGHT** until `209d2a3` added its test: CONNECT counted as idempotent,
    and the tunnel's writer opened with the CONNECT head. The equivalent mutant writes the test
    server's content after its 501, which the `server` module refuses.

  **The first octet of a request line, 2026-09-29.** The owner ruled that the head scanner refuse
  a request line at the first octet of its method that no token holds, and at an SP where the
  method would start (RFC 9110 §9.1, decision 109 as amended). A TLS record sent after an ignored
  Upgrade now gets its 400 at its first octet. `zig build test` passed 128 of 128 steps and 2370
  of 2370 tests, and the golden corpus's verdicts did not change. Mutations, each **CAUGHT**: the
  check dropped, only DEL refused, an empty method let through, the method never ending at its
  SP, status lines checked too, and the check running past the start line.

- **Step 15c — the `gzip` and `deflate` codings.** stdx's decoders from a pool the caller owns,
  under decision 91. It follows https://github.com/c4milo/stdx/issues/1. **Check:** step 15b's
  simulator check with coded bodies, the corrupt and refused verdicts each with a case, and
  mutations.

  **The codings, 2026-09-26.** `src/h11/coding.zig` holds the pool and one message's decoding, and
  the connection decodes a body carrying `gzip` or `deflate` into the buffer the caller passes to
  `receive` ([decision 98](decisions.md)).
  - A server with no pool answers a coded request 501 (RFC 9112 §6.1). With one, it answers 503
    when every decoder is taken (RFC 9110 §15.6.4), 400 when the body is corrupt or when octets
    follow a zlib stream inside the body, and 501 for a feature stdx refuses, such as a zlib preset
    dictionary. Every refusal gives the decoder back, and so does a server that answers before the
    body ends and closes (RFC 9112 §9.3).
  - A client with a pool sends `TE: gzip, deflate` with `Connection: TE` (RFC 9112 §7.4). One
    without refuses a response that uses either coding, because with no TE only chunked is
    acceptable. A coded response that runs until the close ended only if its stream did.
  - A chunked read that decoded only part of its data gives the rest back
    (`chunked.Decoder.give_back`), so the next call returns it again.
  - stdx sorts its refusals into corrupt and unsupported, and h11 keeps them apart. A zlib window
    size RFC 1950 does not allow is corrupt in stdx, so it is a 400, not the 501 decision 91 first
    named for it.
  - The test-only server gives its cleartext h11 connections a pool of
    `h11_decoders_per_worker` per worker and a decoded buffer of `h11_decoded_len`, so `--echo`
    returns a coded request decoded. Over TLS its sessions have none, and a coded request is a 501.

  What was checked, on macOS arm64 with Zig 0.16.0:
  - `zig build test` passes. `src/h11/coding.zig` and `connection_coding_test.zig` read gzip and
    deflate in any pieces, into rooms of 1, 7 and 11 octets and one that holds the whole body,
    with two gzip members, and with each refusal above.
  - `http-server --h11 --echo` returned, decoded, a two-member gzip body and a deflate body that
    Python's `gzip` and `zlib` modules coded, which are encoders other than stdx's. It answered a
    wrong CRC-32 with 400 and a preset dictionary with 501.
  - Mutations, each against `zig build test-h11`, all **CAUGHT**: undecoded octets not given back,
    every octet of a run counted as consumed, a body ending mid-stream not checked, octets after a
    zlib stream starting another, a second gzip member refused, a refused feature called corrupt,
    a stream cut short accepted, the free list not advanced, the stream's end not noted, 503
    answered as 400, a refused feature answered 400, a server or a client taking no decoder, an
    early close keeping its decoder, TE left out of the head, a close-delimited body whole without
    its stream, a failure keeping its decoder, and a given-back chunk keeping its `data_end` state.
    The TE mutation first did not compile and was rewritten so it did.

  **The check, 2026-09-26.** Step 15b's exchange runs a colibri client against a colibri server,
  and no colibri writer codes a body (decision 91), so the exchange cannot carry a coded one.
  `src/sim/h11_coding_check.zig` is the check instead:
  - The plan (`h11_coding_plan.zig`) writes one to four requests to a colibri server, or responses
    to a colibri client, each with a body in `gzip`, `deflate` or no compression under `chunked`,
    coded by stdx's encoders and cut into chunks of seeded lengths. A third of the gzip bodies are
    two members.
  - Half the seeds plant a defect in the last message: a checksum one bit off, the last coded octet
    left out, an octet after a zlib stream, a zlib preset dictionary, or the pool's one decoder
    taken. Each must meet decision 91's refusal: the server's 400, 501 or 503, or the client's
    matching failure.
  - The connection reads the stream in seeded pieces, with a seeded room of 1 to 48 octets for
    each call. Each seed runs twice in pieces and once whole with the most room, and the three
    traces must agree, every body must decode to the plan's octets, and the decoder must be back
    in the pool.
  - `zig build sim -- --h11-coding-check` printed, in Debug and in `-Drelease` alike:
    `h11-coding: seeds=256 messages=540 refused=127 two_members=72 stream_octets=116431
    pieces=13532 calls=27992 trace_octets=52145 crc32=0x4b48322b`. The test pins the digest.
  - Mutations of the library, each against `zig build test-sim-run` alone, all **CAUGHT** by the
    check: undecoded octets not given back, a stream cut short accepted, octets after a zlib
    stream starting another, a second gzip member refused, 503 answered as 400, and a failure
    keeping its decoder.

  The simulator's h11 commands moved to `src/sim/run_main_h11.zig` to keep `run_main.zig` under
  500 lines, and the check's limits are in `src/sim/constants_h11.zig`, which `constants.zig`
  exports as `h11_coding`.

- **Step 15d — the endpoints and conformance.**
  - The test-only h11 server and client on Rotor.
  - TLS over chapulin, with ALPN `http/1.1`, and the server choosing `h2` or `http/1.1`.
  - Interop in both directions, in cleartext and over TLS, with the versions recorded. The client
    runs against Go's `net/http` and h2o, and the server takes requests from curl and Go.
  - The HTTP Garden (https://github.com/narfindustries/http-garden), a differential fuzzer for
    HTTP/1.1 request streams, with colibri's server as one of its origins. Each discrepancy is
    judged against RFC 9112 before it counts as colibri's defect. The owner ruled it in on
    2026-09-25 ([decision 88](decisions.md)). It is GPL-3.0 and needs Docker, so it runs from
    `tools/` alone, cloned at a pinned commit.

  **The interop, 2026-09-26.** `tools/h11_interop.sh --tls <checkout> go h2o` and
  `tools/h11_server_interop.sh --tls <checkout> curl go`, at `03ab314` on macOS arm64 with chapulin
  `b32ad68`, printed "every exchange ended as planned over h11, in cleartext and TLS, against: go
  h2o" and "every request ended with 200 over h11, in cleartext and TLS, from: curl go". curl
  also ran over TLS with no ALPN offer. CI runs the cleartext half on each push.

  **The HTTP Garden, 2026-09-26.** `tools/http_garden.sh` runs in CI's `http-garden` job, which
  pulls the origins' images from `ghcr.io/c4milo/colibri-http-garden` (decision 88 as amended).
  - Run 36253110848, the Garden at `b417e806` and colibri at `dbf1d26`: 34 of 35 origins, pulled
    in 982 seconds. `eclipse_jetty` does not build, because a Maven download its image names has
    moved since the pinned commit. `protocol_http1` stopped on 8 cases; the run restarted it and
    compared those cases without it.
  - Four runs before it failed on the harness, not on colibri. The Garden's tools find containers
    on the network `http-garden_default`, so compose must run under that project name. Its REPL
    stops at the first origin it cannot reach, and refuses the name of an origin that stopped.
    Each case now runs in a REPL of its own, and an origin that stops is restarted.
  - 72 streams compared, 65 of them with at least one origin disagreeing. Judged against RFC 9112
    and RFC 9110, one disagreement was colibri's defect. colibri accepted whitespace that ends a
    chunk line, "5 " before CRLF, which §7.1.1 puts outside the grammar; `03ab314` refuses it.
  - colibri was right where it refused and many origins accepted. A second Host, a Host carrying
    userinfo, whitespace before a colon, and obs-fold get §3.2's and §5's 400. Codings that do
    not end with chunked get §6.3's 400. A chunk size past a u64, chunk data longer than its
    size, and a lone LF on a chunk line get 400 too.
  - colibri was right where it accepted and many origins refused. A leading empty line is
    ignored (§2.2). A quoted chunk extension, a CONNECT's authority-form target and `OPTIONS *`
    are parsed. An empty list member in Transfer-Encoding is ignored (RFC 9110 §5.6.1), and
    identical Content-Length values are taken (RFC 9110 §8.6). An HTTP/1.2 request is accepted,
    as RFC 9110 §2.5 has a recipient process a higher minor version, and trailer fields stay out
    of the header section (RFC 9110 §6.5.1). An empty Host and an empty port are both valid.
  - Where colibri chose among what the RFCs allow, the choice stands. It refuses a lone LF
    (§2.2) and a repeated `chunked`. It reports an absolute-form target as it arrived, since
    §3.3 makes it the target URI.
  - Two differences come from the harness. The body of `gzip, chunked` goes to the application
    still coded, because step 15c has not built the decoders. The echo server sends 100
    (Continue) when the content has already arrived, which RFC 9110 §10.1.1 allows, and the
    Garden reads it as the final response.
  - colibri answered 501 to `Transfer-Encoding: xchunked`, a coding it does not decode, as §6.1's
    SHOULD asks. §6.3 says a request whose final coding is not chunked "MUST" get 400, and the
    origins split 11 to 12 between the two. The owner amended decision 92 on 2026-09-26 to put
    §6.3 first, and `39c0c14` answers 400. A coding it does not decode ahead of a final chunked
    still gets 501.

- **Step 16 — chapulin in the library.** [Decision 94](decisions.md) has colibri link chapulin as
  its TLS stack and its packet protection. Five parts, in order:
  - **16a**, the package. chapulin is pinned by commit and hash in `build.zig.zon` once it offers
    a Zig build that compiles each configuration colibri uses with `RAND=extern`, and colibri's
    build checks each object's build record against the headers it compiled. The pin moves past
    the API changes https://github.com/c4milo/colibri/issues/65 tracks.
  - **16b**, the adapters. The record-mode provider and the QUIC provider and suite move from
    `src/testing/` into a library module, which design §3 gains. `tls.Provider` and
    `crypto.Suite` become internal, filled by that module and by the simulator's null
    implementations. Amended on 2026-09-26 (decision 94's amendment, decision 97): the plain-TLS
    part moves into chapulin as a Zig API, and colibri's `tls` module is the glue from it to
    `tls_provider.Provider` and `crypto.Suite`. 16b waits on that API.
  - **16c**, what a user sets: the server name, trust anchors with the wall-clock time as a value,
    SPKI pins, ALPN, and session tickets offered and handed back, as the owner ruled below.
  - **16d**, the checks. Every check that linked chapulin through `src/testing/` runs against the
    library's adapter, and the `-Dchapulin-*` options leave CLAUDE.md's commands.
  - **16e**, the caller's CPU answer. On x86-64 and arm64 both objects are built `AES=runtime`,
    and `values.Client` and `values.Server` require the caller's `aes_instructions`
    ([decision 97](decisions.md) as amended on 2026-09-29). The multiply's answer follows once
    chapulin offers it ([chapulin#186](https://github.com/c4milo/chapulin/issues/186)), which
    [#84](https://github.com/c4milo/colibri/issues/84) tracks, and colibri's programs take both
    from stdx's `platform` module once it exists
    ([stdx#15](https://github.com/c4milo/stdx/issues/15)).
    **Check:** the `tls` tests under both answers where the build target has the instructions,
    and under `absent` on a CPU model without them; a suite order that names AES-GCM refused
    under `absent`; every check of `tools/ci.sh`; and mutations.
  - **16f**, chapulin 0.2.0 ([#84](https://github.com/c4milo/colibri/issues/84)), the one bump the
    owner ruled. On x86-64 and arm64 both objects are chapulin's host objects, which take no
    `AES`, `WIDEMUL` or `CHACHA` value, and each session picks its paths from the CPU its caller
    describes (chapulin's decision 89). Two of chapulin's claims state a timing: that the AES
    instructions, and the widening multiply, run in data-independent time in the mode the
    session's thread runs in. `values.Client` and `values.Server` carry them as the owner rules
    between the shapes the proposal shows in code. The owner ruled the shape that makes
    `tls.Cpu` the probe and a `tls.Timing`, a new public name every program that links `tls`
    needs, since it says what mode its thread runs in. avx2 and vaes wait on
    [stdx#16](https://github.com/c4milo/stdx/issues/16).
    **Check:** the `tls` tests under every description where the build target has the
    instructions, and on a CPU model without them; each claim chapulin receives, read from the
    converted values; a suite order that names AES-GCM refused without the AES claim; on arm64,
    PSTATE.DIT set on the test programs' thread; h3spec, which offers AES-GCM alone; every check
    of `tools/ci.sh`; and mutations.

  **16c, ruled by the owner on 2026-09-26.** What a user sets is plain values, and chapulin's
  `ch_cfg` (its `cfg.h`, `webpki_cfg.h` and `srv_cfg.h`) is what they become. Each rule below is
  chapulin's, and colibri checks none of them twice.
  - A client names one of two kinds of trust. Web PKI takes the trust anchors, each a root's
    subject and SubjectPublicKeyInfo as DER; the server name the leaf must carry, which is also
    sent as `server_name`; and the wall-clock time in seconds, as a value (non-negotiable 3). It
    may add SPKI pins, which then narrow the anchors. Pins alone take one to four SHA-256 pins
    of a SubjectPublicKeyInfo, as chapulin's `webpki_cfg.h` defines them, read no clock, and send
    a server name only when one is given. That is how cocuyo reaches a DNS server it knows by
    its key and address alone.
  - Both roles set ALPN: a list, most preferred first. A client offers it, and a server picks
    from it in its own order (decision 88).
  - A client may offer a session ticket it kept, with the ticket's age in milliseconds, and may
    refuse a handshake that is not post-quantum (`require_pq`). After the handshake the client
    says whether the ticket was taken. Each ticket the server sends is copied into a slot the
    session holds, and taking it empties the slot and hands back a `Ticket` value in fixed-size
    fields, which the caller keeps as long as it likes: the identity, the PSK, `age_add`, the
    binding, and `lifetime_s`, the ticket_lifetime of RFC 9846 §4.7.1. colibri calls no callback
    of the user's. The value and its lifetime were settled the same day, after cocuyo showed that
    slices into the session could not outlive the connection a ticket is kept for.
  - A server sets its identities: one ECDSA P-256 and one RSA-PSS, each a certificate chain with
    the leaf first, a public key, and a pointer to a private key. It also sets the HelloRetry
    cookie key, an optional ticket key, the time in seconds as a value, whether a server name is
    required, and, in an AES build, its cipher suites in its order. After the handshake it
    reports the server name the client sent.
  - Keys stay in the caller's memory. colibri passes chapulin a pointer to each private key and
    to each cookie and ticket key, and never reads or copies one (non-negotiable 2).
  - The same values configure h11 and h2 over TCP and h3 over QUIC. The QUIC transport
    parameters and the key handover stay colibri's.
  - The session's memory is the caller's, sized by a comptime constant from chapulin's receive
    floor (decision 35). 16b decides whether it sits inside each connection struct or beside it.
  - Amended by the owner on 2026-09-26 (decision 97's amendment). chapulin's Zig API gives each
    object types of its own, so these values are colibri's, defined in `tls`. `tls` converts them
    once per object into that object's chapulin values, and a server identity types its keys.
  - Amended in 16b. The clock and a ticket to offer change with each connection, and a value
    converted once per object would carry a stale one, so a session's `start` takes them:
    `Client.start(config, now_seconds, resumption)` and `Server.start(config, now_seconds)`.

  ```zig
  pub const Anchor = struct { subject: []const u8, spki: []const u8 };
  pub const Pin = [32]u8; // SHA-256 of a DER SubjectPublicKeyInfo

  pub const Trust = union(enum) {
      web_pki: struct { anchors: []const Anchor, server_name: []const u8,
                        pins: []const Pin = &.{} },
      pins: struct { pins: []const Pin, server_name: ?[]const u8 = null },
  };

  // Sized from chapulin's CH_TICKET_ID_MAX, 320, and its largest hash, SHA-384's 48.
  pub const Ticket = struct { identity: [ticket_identity_len_max]u8, identity_len: u16,
                              psk: [ticket_psk_len_max]u8, psk_len: u8, age_add: u32,
                              lifetime_s: u32, binding: [32]u8 };

  pub const Client = struct { trust: Trust, alpn: []const []const u8, require_pq: bool = false };

  // What one connection offers, which a client session's `start` takes with the clock.
  pub const Resumption = struct { ticket: *const Ticket, age_ms: u64 };

  pub const EcdsaP256Identity = struct { chain: []const []const u8, public_key: *const [64]u8,
                                         private_key: *const [32]u8 };
  // chapulin's ch_rsa_priv is a type of each object, so this key stays opaque.
  pub const RsaPssIdentity = struct { chain: []const []const u8, public_key: []const u8,
                                      private_key: *const anyopaque };

  pub const Server = struct { ecdsa_p256: ?EcdsaP256Identity = null,
                              rsa_pss: ?RsaPssIdentity = null,
                              cookie_key: *const [32]u8, ticket_key: ?*const [32]u8 = null,
                              alpn: []const []const u8,
                              require_server_name: bool = false,
                              cipher_suites: []const u16 = &.{} };
  ```

  **Check:** `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `h2spec -t -k`, the h2 and h11
  interop over TLS, `tools/quic_loopback.sh`, `tools/quic_udp.sh`, `tools/quic_aioquic.sh`,
  `tools/h3spec.sh` and the interop runner all pass with no chapulin option passed; and a program
  that does not define `ch_rand_bytes` fails to link, naming it. *Large.*

  **16a, 2026-09-26.** chapulin `64e2f25` is pinned in `build.zig.zon`, lazy, and colibri's build
  compiles it from the package with `RAND=extern`
  ([#66](https://github.com/c4milo/colibri/issues/66)).
  - Two objects serve `src/testing/`. The TCP one, `TRANSPORT=tcp-nonblocking ROLE=both
    TRUST=webpki EXPORTER=on`, serves the h11 and h2 endpoints and the TLS checks, both roles in
    one object. The QUIC one is `TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm
    AES=hw KEYLOG=on` with `CH_NATIVE_AES`. A third, the QUIC object built `TRUST=raw-ecdsa`, is
    compiled only for `zig build interop-endpoint`.
  - `src/testing/` imports the module the package translates from chapulin's headers under the
    object's own defines, in place of `@cImport` under a define list colibri kept. That list had
    lost `HKDF_LABEL_MAX=32`, which `EXPORTER=on` adds. Each endpoint still calls
    `ch_build_matches`.
  - Each image defines `ch_rand_bytes` from `getentropy` (`src/testing/entropy.zig`), and the tests
    that stage one ClientHello twice switch it to a fixed stream. `RAND=drbg` and its seeding are
    gone, and with them the API changes https://github.com/c4milo/colibri/issues/65 tracked.
  - The `-Dchapulin-*` options are gone, which 16d had planned: no check takes a checkout, and
    `tools/ci.sh` runs the TLS and QUIC checks on every push.
  - chapulin's module at `8a813e2` lacked `SRV_TICKET_KEY_LEN`, which its `srv_cfg.h` names but
    `srv_ticket.h` defined. chapulin `64e2f25` defines it and `SRV_COOKIE_KEY_LEN` in `srv_cfg.h`.
  - The pin moved to chapulin `13f4692` on 2026-09-26, once its Zig API landed (`797fc73`). The
    module `chapulin` is now that API and carries the object, so `link_chapulin` no longer adds the
    object itself, and `src/testing/` imports the translated headers as `chapulin.c`. The key
    lengths are `CH_SRV_TICKET_KEY_LEN` and `CH_SRV_COOKIE_KEY_LEN` (chapulin `3ecd148`). The
    adapters still call the C API; 16b moves them onto the Zig one. On macOS arm64 at the new pin:
    `zig build test` passes; `tools/tls_handshake.sh`, `tools/tls_accept.sh`,
    `tools/quic_loopback.sh`, `tools/quic_udp.sh`, `tools/quic_aioquic.sh` and `tools/h3spec.sh`
    pass; `tools/h2spec.sh 18443 --tls` passes 144 of 146 both ways, the 2 skipped by name; and the
    h2 and h11 interop scripts pass in both directions over TLS.

  What each check printed, on macOS arm64 with no chapulin option passed:
  - `zig build test`: 1941 of 1941 tests, none skipped; before, 1823 of 1893 with 70 skipped for
    want of a checkout.
  - `tools/tls_handshake.sh` and `tools/tls_accept.sh`: `tls_handshake: ok` and `tls_accept: ok`,
    each with `alpn=h2 version=0x0304 suite=0x1303`.
  - `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, and the 2 skipped by
    name.
  - The h2 and h11 interop over TLS, in both directions: every exchange and every request ended as
    planned, against Go, nghttpd, h2o, curl and nghttp.
  - `tools/quic_loopback.sh`, `tools/quic_udp.sh` over h3 and hq-interop with resumption, and
    `tools/quic_aioquic.sh` against aioquic 1.3.0: ok.
  - `tools/h3spec.sh`: 49 examples, 0 failures.
  - `tools/interop.sh quic-go handshake,transfer,retry,resumption,keyupdate,http3`, its image now
    compiling chapulin from the package on Linux: every case passed in both roles against
    quic-go, and against colibri itself.
  - With the export of `ch_rand_bytes` removed, the link fails with `undefined symbol:
    _ch_rand_bytes`.

  **CI on Linux, 2026-09-26.** From 16a on, every CI check that starts a server failed on x86_64
  Linux, and the examples had failed to compile there since their first commit. macOS showed
  neither.
  - Zig 0.16's own x86_64 backend, which builds Debug there, placed `udp_run.memory`, a global
    whose type is 64-aligned, 16 octets past a multiple of 64. Rotor's io_uring loop then
    panicked on its first table. LLVM, which builds aarch64, places it right.
  - A global that states `align(@alignOf(T))` is placed right by both backends. pepegrillo
    `6fcb273`'s `static-alignment` rule requires that of every container-level `var` under `src`,
    `examples` and `tools`, and `zig build lint` now runs it. It found 325, each now stating its
    alignment.
  - `examples/link.zig` held both loops' memory in one array of byte arrays, which aligns only the
    first: a loop takes 1,456 octets on Linux, not a multiple of 64. Each loop's memory is now a
    struct of its own.

  What was checked, on macOS arm64:
  - A `quic-udp` cross-built for x86_64 Linux places `udp_run.memory` at a multiple of 64.
  - Both examples, built for arm64 Linux, run in Docker and print that every octet arrived as
    sent, and the h2 server keeps running.
  - Mutations, each **CAUGHT**:
    - `udp_run.memory` without its stated alignment fails the lint, and the cross-built binary
      places it 48 octets past a multiple of 64 again;
    - the rule left unregistered fails the lint's canary;
    - the examples' shared array fails `zig build examples -Dtarget=x86_64-linux-gnu`.

  With that fixed, CI's h2spec over TLS still ended in EOF. CI installs h2spec 2.6.0's release
  binary, built with Go 1.12, whose TLS client offers TLS 1.3 only with `GODEBUG=tls13=1`, and
  chapulin speaks TLS 1.3 alone. Homebrew builds h2spec with a current Go, so macOS passed.
  `tools/h2spec.sh` now sets the variable. Run in Docker against the server on macOS, that binary
  passes 144 of 146 over TLS, the 2 skipped by name, and without the variable it ends in EOF:
  **CAUGHT**.

  **Global state, 2026-09-26.** The same pepegrillo commit has `global-state`, which refuses a
  container-level `var` that is not `threadlocal`. Over the whole tree it found 510. `zig build
  lint` now runs it over the library modules alone, where it found 70:
  - `none_context`, the one byte `stream_provider.zig`'s `none()` points its context at, is now
    `threadlocal`;
  - test fixtures that one file uses are `threadlocal` too;
  - fixtures that several files' tests share move into `*_test_support.zig`, which the rule does
    not read. A test names such a fixture through a `const` holding its address, and a
    `threadlocal` has no address at compile time. `connection.zig`'s move to
    `connection_test_support.zig`, and `field_block.zig`'s to `field_block_test_support.zig`, made
    four `field_block` files, so they now sit in `src/h2/field_block/`.

  The rule leaves out `src/testing/`, `src/sim/`, `src/golden/` and the test files. The servers in
  `src/testing/` share arrays indexed by worker on purpose. Made `threadlocal`, each array would be
  copied into every thread, and glibc places a thread's static TLS on its stack. Mutations, each
  **CAUGHT** by `zig build lint`: `none_context` shared again, the rule unregistered (the
  canary), and the rule reading `*_test_support.zig`.

  **16b, the record side, 2026-09-26.** The library module `tls` (§3) holds step 16c's values and
  chapulin's record-mode sessions, on chapulin's Zig API at `13f4692`.
  - `tls.record.ClientConfig` and `ServerConfig` convert the values once per object. A conversion
    refuses only a list longer than the array it copies into. Every other rule is chapulin's, and
    a session's `start` or the server's `check` reports it.
  - A caller places a `tls.record.Client` or `Server` beside each connection, and the h11 or h2
    connection holds the session's provider, which settles what 16c left to 16b. A client's
    `handshake` writes what it owes before it reads, because chapulin reads no record while the
    client owes the server octets.
  - The provider hands a KeyUpdate's reply over through `handshake_write`, under the keys it
    replaces, and holds at most `key_update_replies_max` replies.
  - The TCP object is decision 97's: `SUITE=aesgcm`, `AES=hw` with `CH_NATIVE_AES` where the
    target has the AES instructions, and `TX_RECORD=16384`. `build.zig.zon` no longer marks
    chapulin lazy.
  - `src/testing/`'s h11 and h2 endpoints and the TLS checks run on `tls.record`. The adapters
    `chapulin_client.zig`, `chapulin_server.zig` and `chapulin_record.zig` are gone, and so is
    `zero_key_records.zig`, which faked a connected session the API cannot make. The endpoints'
    record tests run over a provider that protects nothing (`records_test_support.zig`), and
    `src/tls/` tests chapulin's records with real sessions.
  - `tls_keylog` runs the module's tests over a `KEYLOG=on` object. Its own tests seal a peer's
    KeyUpdate and an empty record under the logged secrets, because chapulin sends neither in
    record mode.

  Two chapulin defects, reported to chapulin on 2026-09-26 and confirmed there:
  - A record holding two KeyUpdates is answered twice. RFC 9846 §5.1 requires the connection to
    end with unexpected_message. colibri's test of it waits for chapulin's fix.
  - After a failed read, chapulin keeps no description of the alert it sent or received, so
    `take_alert` reports the peer's close_notify alone. chapulin adds `alertSent()` and
    `alertReceived()`.

  What each check printed, on macOS arm64:
  - `zig build test`: 1919 of 1919 tests.
  - `tools/tls_handshake.sh` and `tools/tls_accept.sh`: ok, each with `alpn=h2 version=0x0304
    suite=0x1303` and the two exporters equal.
  - `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name.
  - The h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned,
    against Go, nghttpd and h2o, and from curl, nghttp and Go.
  - 41 mutations of `src/tls/`, each **CAUGHT** by `zig build test-tls test-tls-keylog`: the
    owed ClientHello four ways, the clock, the ticket's fields, age and wipe, the server's clock
    and short output, every provider check, every copy bound, the identity check, the build-record
    assertion and `key_update_replies_max`. Two first attempts said otherwise: a completion test
    on a state no failed call reaches was equivalent, and colibri's refusal of an empty exporter
    label duplicated chapulin's, so it was removed.

  **16b, the QUIC side, 2026-09-27.** `tls.quic` holds chapulin's QUIC sessions: `Client` and
  `Server` behind `tls_provider.QuicProvider` and `crypto.Suite`, and `Retry`, the suite a server
  writes a Retry and checks its token with, under a key the caller draws once.
  - `config.zig` converts the values once for either object, as a function of the object's module,
    and `ticket.zig` converts a ticket both ways.
  - chapulin's session starts when colibri gives the provider its transport parameters (RFC 9001
    §8.2), so `start` prepares the connection's values alone. Every call that reads the session
    checks first that it started, so a struct reused for a new connection reports nothing of the
    last one.
  - The library links the QUIC object, and `tls_keylog` its `KEYLOG=on` copy, which
    `src/testing/`'s QUIC endpoints now use. `chapulin_quic.zig`, `chapulin_quic_suite.zig` and
    `chapulin_quic_c.zig` are gone, and `protection_vectors.zig` is
    `src/tls/quic/quic_vectors_test.zig`.
  - The owner ruled two things on 2026-09-26. `certificate_chain_len_max` is 16, for the runner's
    chain of nine. The interop endpoint is the UDP endpoint over the library's `TRUST=webpki`
    object, whose client pins the server's key with `pin`, in place of a `TRUST=raw-ecdsa` object;
    `qns_identity.py` writes the pin.
  - chapulin refuses `SUITE=aesgcm` with `AES=soft` (its `ct.h`, INV-26), which decision 97 did not
    know. An object for a target without the AES instructions carries `SUITE=chacha`: a server's
    suite order is then refused with `SuitesUnavailable`, and a client, which records no suite,
    reports ChaCha20. `zig build test-tls test-tls-keylog -Dcpu=<model>`, on a model without the
    AES instructions, runs the tests over such objects, and `tools/ci.sh` runs it. Decision 97
    carries a note for the owner to confirm, which the owner confirmed on 2026-09-27.

  A chapulin limit, reported on 2026-09-27: pins alone read the leaf alone, but chapulin refuses a
  chain of more than `CH_WEBPKI_FLIGHT_ENTRIES`, four entries, with bad_certificate. The runner's
  `amplificationlimit` case sends nine, so colibri as the client fails it, which it passed over
  `TRUST=raw-ecdsa`. The case waits for chapulin's answer.

  What each check printed, on macOS arm64:
  - `zig build test`: 1938 of 1938 tests. `zig build test-tls test-tls-keylog -Dcpu=generic`: 68 of
    68.
  - `tools/tls_handshake.sh` and `tools/tls_accept.sh`: ok.
  - `tools/quic_loopback.sh`, `tools/quic_udp.sh` over h3 and hq-interop with resumption, and
    `tools/quic_aioquic.sh` against aioquic 1.3.0: ok.
  - `tools/h3spec.sh`: 49 examples, 0 failures.
  - `tools/interop.sh quic-go`, every case of its default list: colibri as the server passed every
    case against quic-go, whose client does not run `ecn`, and every case but `amplificationlimit`
    against colibri's client. As the client against quic-go, colibri passed every case but
    `amplificationlimit` and `handshakeloss`, and quic-go's server does not run `ecn`.
  - `handshakeloss` with colibri as the client against quic-go failed 3 runs of 11 with "Expected
    50 handshakes. Got: 51", the failure recorded at `169c91d` above, and passed the other 8. The
    client's key log held 50 handshakes in the failed run. quic-go's server opened a second
    connection for one of the client's, and the runner counted both; step 9e's runner notes give
    the evidence ([#72](https://github.com/c4milo/colibri/issues/72)).
  - 41 mutations of `src/tls/quic/`, each **CAUGHT** by `zig build test-tls test-tls-keylog`, and
    the two checks of an object without AES-GCM, each **CAUGHT** under `-Dcpu=generic`. The first
    run left eleven otherwise. The session struct the tests reuse still held the previous test's
    closed session, so nine checks before chapulin's session starts read harmless answers; a test
    now restarts a session that resumed and was not closed. Two more tests were missing: an open at
    a level with no keys, and a Retry token checked a second later. A mapping of a capacity error
    chapulin cannot return with `receive_len` is gone.

  **16b at chapulin `e802399`, 2026-09-27.** The pin moved from `13f4692` to chapulin `e8023994`,
  which carries two of the fixes 16b asked for.
  - `9d604f7` ends the connection when a handshake message before a key change does not end its
    record (RFC 9846 §5.1). The test held back for it is in: two KeyUpdates sealed in one record
    fail the read, and neither is answered.
  - `e802399` has pins alone take any number of certificates after the leaf. A pinned client
    completes in memory against a chain of 16.
  - `7c18e3c` and `7d57fbc` change chapulin's Zig API and what its server refuses at init, and
    colibri needed no change for either.

  The runner's `amplificationlimit` case still fails with colibri as the client, for a second
  bound: pins alone read the leaf under `CH_WEBPKI_CERT_MAX`, 3,072 octets, and the case's leaf
  is 5,514 (`docs/chapulin.md`). Reported on 2026-09-27; the case waits for chapulin's answer.

  What each check printed, on macOS arm64:
  - `zig build test`: 1939 of 1939 tests. `zig build test-tls test-tls-keylog -Dcpu=generic`: 73 of
    73.
  - `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`
    and `tools/quic_aioquic.sh`: ok. `tools/h3spec.sh`: 49 examples, 0 failures.
  - `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
    h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
  - `tools/interop.sh quic-go`, every case of its default list: colibri as the server passed every
    case against quic-go, whose client does not run `ecn`, and against colibri's client every case
    but `amplificationlimit` and `rebind-port`. `rebind-port` then passed 3 runs of 3. As the
    client against quic-go, colibri passed every case but `amplificationlimit`.

  **CI on Linux, 2026-09-27.** CI failed on `ecb5924` and `94edca5` in its new section alone:
  `-Dcpu=generic` names an Arm model, and clang knows no x86 model by that name. `tools/ci.sh` now
  runs the section on `x86_64`, the x86-64 baseline, which has no AES instructions, and on
  `generic` elsewhere. Built for x86_64 Linux with `-Dcpu=x86_64` and run in an amd64 container on
  macOS arm64, the two test binaries passed 34 of 34 and 39 of 39.

  **16d, 2026-09-27.** Every check that linked chapulin through `src/testing/` has run over the
  library's `tls` since 16b, whose records hold what each printed, and the `-Dchapulin-*` options
  left CLAUDE.md in 16a. 16d adds the rest of the step's check, in `tools/consumer_check.sh`:
  - The consumer, a project that depends on colibri as a package, now links `tls`, defines the two
    hooks and starts a handshake. So a dependent links chapulin through colibri and runs it.
  - A second program links `tls` and defines no `ch_rand_bytes`, and the check requires its link to
    fail naming the hook. On macOS arm64 the linker printed `undefined symbol: _ch_rand_bytes`. Zig
    links an executable only when its file is used, so the step installs it.
  - Mutation: the second program given a `ch_rand_bytes` of its own links, and the check fails:
    **CAUGHT**.

  One case of the step's check still fails: the runner's `amplificationlimit` with colibri as the
  client, which waits for chapulin to read a pinned leaf longer than `CH_WEBPKI_CERT_MAX`. The owner
  approved that change on 2026-09-27, and it has not landed.

  **16b at chapulin `6fda41f`, 2026-09-27.** The pin moved to chapulin `6fda41f`, whose `df428cd`
  adds `ch_alert_sent` and `ch_alert_received`: a failed read now names the alert it sent and the
  fatal alert the peer sent. The record provider's `take_alert` reports the peer's close_notify
  first, then the peer's fatal alert as `peer`, then this side's as `local`, each once. chapulin no
  longer answers a peer's fatal alert. The same push refuses a KeyUpdate whose `request_update` is
  neither 0 nor 1 with illegal_parameter (RFC 9846 §4.7.3). A new keylog test sends one and reads
  that alert as `local`.

  What each check printed, on macOS arm64:
  - `zig build test`: 1940 of 1940 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 74
    of 74.
  - `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`,
    `tools/quic_aioquic.sh` and `tools/consumer_check.sh`: ok. `tools/h3spec.sh`: 49 examples, 0
    failures.
  - `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
    h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
  - The QUIC Interop Runner, `tools/interop.sh quic-go`. colibri's server passed every case against
    colibri's client but `amplificationlimit` and `rebind-port`. Against quic-go's client it passed
    every case but `rebind-addr`, and `ecn` was unsupported. colibri's client passed every case
    against quic-go's server but `amplificationlimit`, and `ecn` was unsupported.
    `amplificationlimit` waits for the leaf-size change above.
  - Two more rounds of `rebind-port` and `rebind-addr`, colibri as the server, against both
    clients: 7 of 8 passed, and `rebind-addr` against colibri's client failed once. Each rebinding
    failure printed a PATH_CHALLENGE with no PATH_RESPONSE. Only the last run's trace was kept. In
    it, the datagram that carried the server's first challenge on the new path never reached the
    client. The server's next challenge carried new data, as RFC 9000 §13.3 requires, and the
    client answered it. The runner checks only the first challenge on each new path, so losing that
    one datagram fails the case.
  - 5 mutations of the new `take_alert`, each **CAUGHT**: reporting before the session failed, each
    report made twice, and each origin swapped.

  **16d at chapulin `9bf41c9`, 2026-09-27.** The pin moved to chapulin `9bf41c9`, and step 16 is
  done. Under pins alone, chapulin now reads the leaf and each entry after it up to
  `CH_WEBPKI_LEAF_PIN_CERT_MAX`, 16,375 octets, the most one entry holds in the 16 KiB body
  chapulin allows a handshake message. The walk with anchors keeps `CH_WEBPKI_CERT_MAX`, 3,072. A session's buffer,
  `receive_len`, is 20 KiB, above the 16,410 octets chapulin's `docs/webpki.md` gives for the
  largest Certificate message over TCP. `827b5d4`, in the same push, answers a KeyUpdate whose
  body is not one octet, and a NewSessionTicket whose fields do not fill it, with decode_error in
  place of unexpected_message.

  What each check printed, on macOS arm64:
  - `zig build test`: 1940 of 1940 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 74
    of 74.
  - `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`,
    `tools/quic_aioquic.sh` and `tools/consumer_check.sh`: ok. `tools/h3spec.sh`: 49 examples, 0
    failures.
  - `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
    h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
  - The QUIC Interop Runner, `tools/interop.sh quic-go`: every case passed with colibri's server
    against colibri's client, with colibri's server against quic-go's client, and with colibri's
    client against quic-go's server. `ecn` was unsupported in the two pairings with quic-go.
    `amplificationlimit` now passes in all three.

  **After 0.1.0: chapulin `157d2ac`, 2026-09-27.** The pin moved to chapulin `157d2ac`, in which
  the call that fails a handshake writes its alert itself. The alert is in the clear before the
  failing side's write key is installed and sealed after it, and none follows the peer's own fatal
  alert. `ch_record_alert` is gone. Each record session's `failure_written` counts the octets a
  failed `handshake` wrote at the front of its output, the alert last, which the caller sends
  before it closes. A client reads nothing while its output has no room for a whole alert record,
  so the alert always fits the call that fails.

  What each check printed, on macOS arm64:
  - `zig build test`: 1948 of 1948 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 82
    of 82. `src/tls/record/record_failure_test.zig` adds four tests: a server's alert in the clear
    and sealed, a client's sealed, each read by the peer as its fatal alert, and a client's read
    waiting for room.
  - `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`,
    `tools/quic_aioquic.sh` and `tools/consumer_check.sh`: ok. `tools/h3spec.sh`: 49 examples, 0
    failures.
  - `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
    h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
  - 6 mutations, each **CAUGHT**: the client's alert left out of its count, the server's count not
    kept, a client read with no room for the alert, an alert counted after the peer's own, and each
    `failure_written` answering 0.

  **The endpoints send it, 2026-09-27.** `src/testing/`'s endpoints now send what a failed
  handshake wrote before they close. The server's TLS layer ends the connection on it as on a
  finished session, the client's loop closes once the socket has taken it, and the two TLS checks
  write it before they exit. Four cases require Go to read colibri's alert:
  - `tools/tls_accept.sh` and `tools/h2_server_interop.sh --tls`: a Go client that offers TLS 1.2
    alone reads "protocol version not supported" (RFC 9846 §4.3.1).
  - `tools/tls_handshake.sh`: Go's server logs "bad certificate" from colibri's client, which asked
    for a name the certificate does not carry.
  - `tools/h2_interop.sh --tls`: Go's server logs "unknown certificate authority" from colibri's
    client, which pins another root.

  What each check printed, on macOS arm64:
  - `zig build test`: 1948 of 1948 tests. The four scripts above, and the h11 interop scripts with
    `--tls`: ok, every exchange and request as planned.
  - 4 mutations, each **CAUGHT**: each TLS check sending nothing, which Go read as an EOF; the server
    layer counting no octets; and the client loop closing before its alert went out.

  **The limits a caller sizes by, 2026-09-27.** A caller cannot reach `chapulin.c`, so `tls` names
  the limits a caller sizes its buffers and lists by. cocuyo asked for them.
  - `record.alert_record_len` is chapulin's sealed alert record, 24 octets.
  - `record.Client.handshake_output_len_min` is chapulin's `REC_HDR + CH_TX_HELLO`, 2,421 octets on
    an object with AES-GCM: an output that long takes a whole ClientHello in one call.
  - Each configuration's `anchors_max` and `protocols_max` are chapulin's `CH_WEBPKI_ANCHOR_MAX`
    and `CH_ALPN_MAX`.

  `zig build test-tls test-tls-keylog`: 84 of 84, with and without `-Dcpu=generic`. A ClientHello
  that offers a ticket took 1,568 octets. 5 mutations, each **CAUGHT**: each list limit one above
  chapulin's, a hello bound shorter than a ClientHello, and an alert record one octet short.

  **Each session draws from its caller's source, chapulin `5ae9182`, 2026-09-27.** Decision 94 as
  amended on 2026-09-27, https://github.com/c4milo/colibri/issues/71. The pin moved to chapulin
  `5ae9182`, whose `e4b9c6f` adds `RAND=session`, and colibri's objects are built that way.
  - Each `tls` session's `start` takes a `tls.Random` after its configuration, and
    `ServerConfig.check` takes one for an RSA-PSS salt. chapulin refuses a session with none, so no
    draw falls back to another source.
  - No program defines `ch_rand_bytes`. `src/testing/entropy.zig` hands each endpoint session the
    octets of `getentropy`, and the tests pass a seeded SplitMix64 (`random_test_support.zig`).
  - `tools/lint/determinism.zig` lets `src/tls/values.zig`, which names the source's type, name
    `std.Random`. Every other file under `src/` still may not.
  - `tools/consumer_check.sh` now requires a program without `ch_assert_fail`, chapulin's one hook,
    to fail to link, naming it.

  What each check printed, on macOS arm64:
  - `zig build test`: 1954 of 1954 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 88
    of 88. Two tests replay a record and a QUIC handshake's first flights. One seed twice writes the
    same octets, and another seed for one side changes what that side writes and leaves the other
    side's ClientHello as it was.
  - The twelve scripts of the 157d2ac record, at `e4b9c6f`, whose C and Zig sources `5ae9182`
    keeps: ok, with h3spec's 49 examples and 0 failures and h2spec's 144 in cleartext and over TLS.
    `tools/consumer_check.sh` ran again at `5ae9182`: ok.
  - 7 mutations, each **CAUGHT**: a record client that passes no source, each of the four session
    kinds drawing from a fixed source in place of its caller's, `check` passing no source, and the
    program without the hook defining it.

  **A connection error ends the connection inside colibri, 2026-09-27.** cocuyo reported it in
  https://github.com/c4milo/colibri/issues/68.
  - h2 and h11: a record the provider refused, or an error alert, left the connection running,
    though RFC 9846 §5.2 says the receiver MUST terminate it. Now the connection fails at the
    record layer. It reads no record and writes no frame, `encrypt` writes only the alert the
    provider owes, and no close_notify follows (RFC 9846 §6). A seal the provider refuses ends it
    the same way, and an h11 server that owed an error response owes none after it.
  - QUIC: `receive` and `send` owe the CONNECTION_CLOSE for the connection error they return (RFC
    9000 §10.2), so a caller no longer asks for its code.
  - A TLS failure while `send` writes handshake octets closed with no frame at all. It now closes
    with its alert's CRYPTO_ERROR code (RFC 9001 §4.8).
  - A space out of packet numbers left the connection open, and the other spaces went on
    sending. Now it closes silently and sends nothing more (RFC 9000 §12.3).

  What each check printed, on macOS arm64:
  - `zig build test`: 1964 of 1964 tests.
  - `tools/h3spec.sh`: 49 examples, 0 failures. `tools/h2spec.sh 18443 --tls`: 144 passed in
    cleartext and over TLS. The QUIC, TLS and interop scripts of the 157d2ac record: ok.
  - 25 mutations, each **CAUGHT**: 10 in h2, 8 in h11 and 7 in QUIC. They include the failure
    not recorded, no alert owed, a record read, a frame written, a record sealed or a close_notify
    sent after the failure, each QUIC close not owed or carrying the wrong code, and packet-number
    exhaustion left open or owing a close.

  **h2's field sections in their order, 2026-09-27.** cocuyo asked for it in
  https://github.com/c4milo/colibri/issues/69.
  - `write_trailers` writes a trailer section, a HEADERS frame carrying END_STREAM, after the
    final header section of either side's message (RFC 9113 §8.1). No call could send one before,
    so cocuyo's test server wrote the frame and its HPACK by hand.
  - Each stream records whether colibri sent its final section, a request or a final response.
    Trailers before it are refused, and so is a response after it, which the peer would read as a
    trailer section carrying `:status`.
  - `write_response` now holds the caller's field lines to RFC 9113 §8.2 as `write_request` does.
    An uppercase or connection-specific field went out before, which §8.2.1 makes the peer treat
    as malformed. Trailers are held to the same rules, which refuse a pseudo-header field (§8.1).
  - `Event.ended_stream()` names the stream an event ended, where a caller checked a request, a
    response, DATA and trailers.

  What each check printed, on macOS arm64:
  - `zig build test`: 1970 of 1970 tests. `zig build examples`: every example ran.
  - `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name.
    `tools/h2_interop.sh --tls` and `tools/h2_server_interop.sh --tls`: every exchange and request
    ended as planned.
  - 13 mutations, each **CAUGHT**: each of the three order checks removed, an interim response
    counted as final, a final response or a request not recorded, either field-line check
    removed, trailers without END_STREAM, and each arm of `ended_stream` wrong.

  **chapulin `0adcf33`, 2026-09-27.** The pin moved to chapulin `0adcf33`, whose `19d6a13` sends
  a KeyUpdate before an AES-GCM write key reaches 2^24 records, under RFC 9846 §5.5's limit of
  2^24.5. colibri changes nothing: `encrypt_record` sizes each write with `writableLen`, which
  counts the 27-octet KeyUpdate, and `initiate_key_update` stays `Unsupported` over TCP.

  What each check printed, on macOS arm64, at `b31bce6`, whose code `0adcf33` keeps: it changes one
  proof floor. `zig build test`: 1970 of 1970 tests; `zig build test-tls test-tls-keylog
  -Dcpu=generic`: 88 of 88. The two TLS checks, h2spec's 144 in cleartext
  and over TLS, the h2 and h11 interop scripts with `--tls`, `tools/consumer_check.sh` and
  `tools/quic_udp.sh`: ok.

  **A record that fails, 2026-09-29.** https://github.com/c4milo/colibri/issues/74 asked the test
  endpoints to send the alert a record that does not authenticate owes (RFC 9846 §5.2). Since
  `ecffe73` and `16ddd3d` they run on the `server` and `client` modules, whose next `send` writes
  that alert, and each loop closes once the socket has taken it. Two things were missing:
  - A check. `tools/h2_interop/forged_record.go` completes a handshake and then writes a record no
    key sealed, as a client to colibri's server and as a server to colibri's client, offering one
    protocol. The four h2 and h11 interop scripts with `--tls` require Go to read colibri's
    `bad_record_mac`, and the two client scripts require the client to count the connection as
    failed.
  - A fix. Each module's `should_close` said to close once the record layer failed, before `send`
    had written the alert, so a caller that asked before its next `send` closed without it. It now
    waits until the alert is out. A test in each module feeds a forged record over h2 and over h11
    and requires one alert record, `bad_record_mac`, before the close.

  What each check printed, on macOS arm64:
  - `zig build test`: 2331 of 2331 tests. The four scripts with `--tls go`: "a forged record ends
    with the server's alert: bad record MAC" from both server scripts and "the client's alert: bad
    record MAC" from both client scripts, with every exchange and request as planned.
  - 8 mutations, each **CAUGHT**. `failure_sent` ignoring the owed alert, in each of its four arms,
    by the module tests. The server sealing nothing once stopped, by the server test and both server
    scripts. A failed record closing the client before its alert, by the client test and both client
    scripts. Each loop closing before its output drained, by the h11 scripts' forged record; in the
    h2 scripts the refused handshake fails first.

  **chapulin `10a5bc8`, 2026-09-29.** The pin moved to chapulin `10a5bc8`, which closes
  https://github.com/c4milo/chapulin/issues/180 for https://github.com/c4milo/colibri/issues/81.
  - An object with AES-GCM now prefers TLS_AES_256_GCM_SHA384, then TLS_AES_128_GCM_SHA256, then
    TLS_CHACHA20_POLY1305_SHA256, as a client and as a server (chapulin's decision 80). The owner
    put AES-256-GCM first for CNSA 2.0. An object without AES-GCM holds ChaCha20 alone, as before.
  - `tls.values.Client.cipher_suites` sets a client's order, as `tls.values.Server.cipher_suites`
    sets a server's, and the ClientHello offers exactly that list. An object without AES-GCM
    refuses any list with `SuitesUnavailable`, and chapulin refuses a suite named twice when the
    session starts.
  - chapulin's QUIC calls now take a version (its `9680043`). colibri's `quic` speaks version 1
    alone (RFC 9000 §15), so `tls.quic.version` names it once: each session starts in it, and every
    seal, open and Retry call passes it.

  What each check printed, on macOS arm64:
  - `zig build test`: 2337 of 2337 tests. `zig build test-tls test-tls-keylog -Dcpu=generic`: 96
    of 96.
  - `tools/tls_accept.sh`: `suite=0x1302` against Go's client. `tools/tls_handshake.sh`:
    `suite=0x1301` against Go's server, which takes its own order among the AES suites once the
    client lists one first. Before the pin, CI printed `suite=0x1303` for both.
  - `tools/quic_loopback.sh`, `tools/quic_udp.sh`, `tools/quic_aioquic.sh` against aioquic 1.3.0,
    h3spec's 49 examples, h2spec's 144 in cleartext and over TLS, and `tools/consumer_check.sh`:
    ok.
  - 11 mutations, each **CAUGHT**: the client's order not passed on, and its refusal in an object
    without AES-GCM; either role's version left unset; the version changed in the constant and in
    each of the five calls; and the shared length check. The close a failed session seals was
    caught only once a test opened it at the peer, which this change adds.

  **16e, 2026-09-30.** Both objects are built `AES=runtime` on x86-64 and arm64, and each session
  runs the AES instructions or ChaCha20 alone, as its caller answers (decision 97 as amended on
  2026-09-29).
  - `values.Client` and `values.Server` require `aes_instructions`, `present` or `absent`, with no
    default, and `config.zig` hands it to an object that takes it. An object built for another
    architecture fixes the choice when it is built, and there the answer changes nothing.
  - The tests pass the build target's answer (`testdata.aes_instructions_present`), and run both
    answers where the target has the instructions. In record mode and in QUIC every pair of
    answers completes a handshake, and runs AES-256-GCM only when both sides hold it. Under
    `absent` a suite order that names AES-GCM is refused when a session starts.
  - `src/testing/cpu.zig` answers for the test programs, and `tools/consumer` for itself, each for
    the target it was built for, until stdx's `platform` module answers
    ([stdx#15](https://github.com/c4milo/stdx/issues/15)). `tools/ci.sh`'s leg on a CPU model
    without the instructions runs the `tls` tests under `absent` alone.

  What each check printed, on macOS arm64:
  - `tools/ci.sh`: every section passed, with 2407 of 2407 tests in Debug and in ReleaseSafe.
  - 8 mutations, each **CAUGHT**: the client's or the server's answer not handed on, either answer
    handed on as the other, no object taking the answer, the build keeping the target's choice on
    x86-64 and arm64, and no constant-time statement, which chapulin's build refuses. The test
    programs answering `absent` was caught by `tools/h3spec.sh`, whose client offers AES-GCM
    alone. The build mutation first failed to compile, which showed that `config.zig` named
    chapulin's `AesInstructions` for an object without it. The answer's condition is now decided
    at compile time, and a test pins the choice.

  **16e with stdx `fa53aa4`, 2026-09-30.** The stdx pin moved from `342cb71` to `fa53aa4`, which
  carries stdx's `platform` module ([stdx#15](https://github.com/c4milo/stdx/issues/15)). The test
  programs and `tools/consumer` ask the CPU once through `platform.probe()` and pass `present` only
  when `aes_clmul` is `yes`, and colibri's package exports `platform` (decision 97 as amended on
  2026-09-30). The tests keep the build target's answer. The next record undoes the export.

  What each check printed, on macOS arm64:
  - `tools/ci.sh`: every section passed, with 2493 of 2493 tests in Debug and in ReleaseSafe.

  **16e at chapulin `900ce67`, 2026-09-30.** The pin moved from chapulin `044a49c` to `900ce67`,
  which carries the AES-GCM record path of [chapulin#184](https://github.com/c4milo/chapulin/issues/184).
  chapulin's `docs/performance.md` times one 16 KiB AES-256-GCM seal on an Apple M1 Pro at 5.4,
  5.7 and 5.6 µs, under macOS with Apple clang 21 and a Linux VM with clang 18 and gcc 13, where
  it took 26.8, 27.6 and 36.3 µs at `044a49c`. chapulin calls these the filter's figures, and
  colibri has none of its own. The pin also refuses a ClientHello too long to stage with nothing
  sent, and records internal_error when the transport refuses a send. Its vector Poly1305 runs
  only under `WIDEMUL=native`, which colibri does not build
  ([#84](https://github.com/c4milo/colibri/issues/84)).

  What each check printed, on macOS arm64:
  - `tools/ci.sh`: every section passed, with 2503 of 2503 tests in Debug and in ReleaseSafe.

  **16e, the probe as input, 2026-09-30.** `values.Client` and `values.Server` take `cpu`, the
  `platform.Cpu` the program's probe returned, in place of `aes_instructions`, and colibri's
  package no longer exports `platform` (decision 97 as amended again on 2026-09-30).
  - `tls` imports stdx's `platform` for the `Cpu` type alone. A session runs the AES instructions
    only when `aes_clmul` is `yes`.
  - The tests pass a probe of the build target, and run every answer, `yes`, `no` and `not_known`,
    where the target has the instructions. Under `no` and `not_known` alike a session runs
    ChaCha20 alone, and a suite order that names AES-GCM is refused.
  - `tools/consumer` depends on stdx itself, at the commit colibri pins and with the options
    colibri gives it, and compiles against the `platform.Cpu` that `tls` names.

  What each check printed, on macOS arm64:
  - `tools/ci.sh`, on the 0.7.0 release commit that carries it: every section passed, with 2505 of
    2505 tests in Debug and in ReleaseSafe.
  - 6 mutations, each **CAUGHT**: `yes` running no AES instruction, `no` or `not_known` running
    them, and the client's or the server's probe not handed on; and, by `tools/h3spec.sh`, the test
    programs' probe saying `no`, since h3spec's client offers AES-GCM alone.

  **16e at chapulin `c798fb8`, 2026-09-30.** The pin moved from chapulin `900ce67` to `c798fb8`,
  as the owner approved. No API changed. chapulin's `docs/performance.md` times one 16 KiB record
  on an Apple M1 Pro, under macOS with Apple clang 21 and a Linux VM with clang 18 and gcc 13:
  - An AES-256-GCM seal takes 3.6, 4.0 and 4.1 µs, where it took 5.4, 5.7 and 5.6 at `900ce67`.
    Counter mode and GHASH run in one loop over each pass of eight blocks (`gcm_hw.c`).
  - A ChaCha20-Poly1305 seal under `CHACHA=vector` takes 42.6, 37.3 and 55.4 µs, where it took
    47.5, 42.1 and 61.4. On NEON the ChaCha20 runs eight blocks a pass, two groups of four.
  - colibri has no figures of its own. Under `WIDEMUL=native` the ChaCha20-Poly1305 seal takes
    11.8 µs, which waits on [chapulin#186](https://github.com/c4milo/chapulin/issues/186) and
    [#84](https://github.com/c4milo/colibri/issues/84).

  What each check printed, on macOS arm64:
  - `tools/ci.sh`: every section passed, with 2528 of 2528 tests in Debug and in ReleaseSafe.

  **16f, 2026-10-09.** The pin moves from chapulin `c798fb8` to `v0.2.0` (`26fa782`). The proposal
  carried one shape for the timing claims in code, and showed two more, and the owner ruled for the
  one built, and for test programs that state the mode on x86-64, where no program can read DOITM
  ([decision 97](decisions.md) as amended on 2026-10-09).
  - `tls.Cpu` holds the probe and a `tls.Timing`, `not_stated` or `data_independent`. colibri
    claims constant-time AES under `data_independent` where the probe's `aes_clmul` is `yes`, and
    the constant-time multiply under `data_independent` alone. Without the AES claim a session
    holds ChaCha20 alone, and chapulin refuses a suite order that names AES-GCM.
  - The test programs set PSTATE.DIT on their thread on arm64 where the core has FEAT_DIT, and
    state the mode on x86-64, so their sessions run the AES-GCM suites h3spec offers alone. The
    examples state nothing and run ChaCha20.
  - On macOS arm64: the `tls` tests passed 58 of 58, and 122 of 122 with the `tls_keylog` tests on
    `-Dcpu=generic`; h3spec passed 49 of 49; `tools/quic_loopback.sh`, `tools/tls_handshake.sh` and
    `tools/tls_accept.sh` passed.
  - 8 mutations, each **CAUGHT** by a test: the AES claim without the mode, or without the probe;
    the multiply claim never made, or always; the client's description never reaching chapulin;
    the host objects built with ChaCha20 alone; and the test programs stating the mode without
    setting PSTATE.DIT, or stating none on arm64.
  - `zig build test`: 131 of 131 steps and 2662 of 2662 tests passed, the memory table unchanged.

- **Step 17 — the version-choosing client and server.** [Decision 100](decisions.md) has two
  library modules above h11, h2 and h3, for
  [#70](https://github.com/c4milo/colibri/issues/70). Nine parts. The owner ruled on 2026-09-27
  that 17c and 17d go before 17b, because cocuyo waits for the client and 17c does not depend on
  step 17b, and on 2026-09-28 that 17g goes after 17b. 17h came on 2026-09-30, after 17e, and 17i
  on 2026-10-04, after 17f. The order is 17a, 17c, 17d, 17b, 17g, 17e, 17h, 17f, 17i:
  - **17a**, the server over TCP. It takes octets tagged by connection, runs the handshake
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
    model's rules finds a violation ([decision 105](decisions.md)). The client fetches over h3
    from quic-go and aioquic, and falls back to h2 against a server with no UDP.
  - **17e**, content codings ([decision 101](decisions.md)). The server codes a response in
    `gzip` or `deflate` when the request accepts it and the caller marks the response, and the
    client offers both and decodes them. `zstd` decoding follows a stdx bump. colibri's package
    exports stdx's `codec`, `gzip`, `zlib`, `zstd` and `brotli`.
    **Check:** the simulator sends coded and uncoded responses through both modules over seeds,
    and every body arrives octet for octet. curl with `--compressed` and Go's client decode the
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
  - **17h**, the client decodes `zstd` and `br` ([decision 101](decisions.md) as amended on
    2026-09-30, [#80](https://github.com/c4milo/colibri/issues/80)). The caller places a pool for
    each coding. The client offers a coding only when its pool has a free decoder, takes one from
    each pool it offers as it writes the request, and gives back the others at the response's
    head. A `br` window holds 16 MiB, RFC 7932 §9.1's largest, and a `zstd` one 8 MB (RFC 9659
    §3).
    **Check:** client tests decode fixtures that the `zstd` and `brotli` programs wrote, in pieces
    as they arrive; a stream whose window passes the limit fails its response; a pool with no
    free decoder drops its coding from the offer; the client decodes `br` from h2o and `zstd`
    from Caddy, in cleartext and over TLS; and mutations.
  - **17i**, the server over QUIC owes the 100 (Continue) ([decision 116](decisions.md)). A
    request over h3 that expects one gets it at the connection's next `receive` or `send`,
    unless the caller answered it first, as a request over TCP does (RFC 9110 §10.1.1). A
    request whose stream ended gets none.
    **Check:** server tests that read one event at a time: the 100 at the next `receive` and
    before the next datagram; none after a final response, the caller's own 100, a cancel or
    the stream's end; a 100 that waits for a run of its response; and mutations. aioquic's
    client reads the 100 from §9's UDP server before it sends its content.

  **17a, 2026-09-27.** `src/server/` is the `server` module, exported by name. It imports `core`,
  `http`, `h11`, `h2`, `tls` and `tls_provider`.
  - A `Connection` serves one TCP connection. `receive(input, now_ns)` takes the octets the
    transport read and returns at most one event: a request's head, octets of its content, its
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
  - A connection is 284,360 octets: h2's connection, the TLS session, 33,033 octets of opened
    plaintext and 49,161 of output.
  - The first interop run over TLS stalled nghttp's upload of 300,000 octets. The opened plaintext
    held a frame and one record's plaintext, but a provider opens a record only into room for all
    that follows its header, which RFC 9846 §5.2 bounds by `record_ciphertext_len_max`. When a DATA
    frame began a record, the record held all of the frame but its last 9 octets, and the next
    record did not fit. The buffer now holds a frame and `record_ciphertext_len_max`, and a test
    that starts DATA frames on a record catches the old size.
  - 70 tests, handshakes against colibri's own client among them, and 83 mutations, each CAUGHT.
    The tests found that h2's `write_data` sent a server's DATA before any response head, which
    RFC 9113 §8.1 forbids; `write_data` now refuses it.
  - §9's h11 and h2 server runs each connection on `server` (`src/testing/server_session.zig`),
    in place of its own record half and protocol sessions.

  **17a check,** run on macOS 26.6.2 arm64 on 2026-09-27, the peers in Docker where the scripts
  put them:
  - `tools/h2spec.sh 18443 --tls`: h2spec 2.6.0 passed 144 of 146 cases in cleartext and 144 of
    146 over TLS. The two it fails are the cases the script names as skipped: RFC 7540 §5.3.1's
    self-dependency, which RFC 9113 §5.3.2 dropped.
  - `tools/h2_server_interop.sh --tls`: curl 7.88.1, nghttp2 1.52.0 and Go 1.27.1 each sent 64
    GETs on one connection and a POST of 300,000 octets, and each request ended with 200, in
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
  - A connection is 285,768 octets, and an exchange 152.
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
    GET of 1 MiB, a POST of 300,000 octets that Go echoes, an interim response, trailers and a 404.
    The client that pins another root sent the alert Go read as `unknown certificate authority`.
  - `tools/h11_interop.sh --tls`: against Go 1.27.1 and h2o 2.2.5, the same over h11, in
    cleartext and over TLS: Go's ALPN chose h11, and the client offered only h11 to h2o.
  - `zig build test` passed.

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
  - A `Channel` is 987,216 octets: a QUIC connection of 700,472 and a TCP one of 285,928. The
    caller places the QUIC connections' receive pool beside it (decision 61), sized with
    `ReceivePool`: 1,505,288 octets for the default 1 MiB of capacity, and 377,504 for 66,560.
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
      digest: each fetched 1,000, 100,000 and 1,000,000 octets with matching CRC-32s, sent a POST
      of 300,000 octets whole, and read a 404. Every exchange ran over h3, and TCP never opened.
    - Against Go 1.27.1's server over TLS, which listens on TCP alone: QUIC opened, TCP opened once
      the 250 ms fallback delay passed, and h2 carried a GET, a GET of 1 MiB and a POST of 300,000
      octets that Go echoed.
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
    (decision 103, `0fb5878`). h11 and h2 copy the octets, so a request is done after the call
    that writes its last one, and `receive` reports it before it reads more.
  - `QuicConnection` (`c533709`) serves h3 over one QUIC connection with the TCP connection's calls
    and events, in the shape the owner chose on 2026-09-28. `write_body` sends the caller's octets
    from where they are and keeps only each DATA frame's header. A request is `done` once the peer
    acknowledged every octet of its response (RFC 9000 §3.1), and `cancelled` once either side
    reset its stream. A request no record can hold is refused with H3_REQUEST_REJECTED.
  - `Endpoint` (`ba34897`) holds up to a build-time number of connections behind the caller's UDP
    socket. It routes each datagram by its first packet's Destination Connection ID (RFC 9000
    §5.2), starts a connection from a client's first Initial of at least 1,200 octets, and answers
    Version Negotiation and Retry itself. `send` writes what the endpoint owes, and `ended` hands
    back each connection that is over. A connection issues spare connection IDs once its handshake
    is confirmed, and validates a client's new path.
  - A `QuicConnection` is 716,128 octets. An `Endpoint` of the default 16 connections, each with a
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
    3,000,000 octets from the `h3` mode, each octet for octet. Two handshakes that offered another
    ALPN each ended with the server's CONNECTION_CLOSE carrying 0x178.
  - `tools/quic_udp.sh`: colibri's h3 client fetched the same three files from the `h3` mode, and
    a missing one was answered 404. The mode refused a client that offered hq-interop alone, and
    the refused connection ended its run with a failure.
  - `tools/h3load.sh`: h2load from nghttp2 1.70.0 sent 1,000 GETs over 10 connections to the `h3`
    mode, and each ended with a 2xx.
  - Mutations of the `h3` mode, each CAUGHT by `tools/quic_udp.sh`: a missing path answered 200, a
    file left uncounted, a run with `once` that never ends, content one octet short, and a failed
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
    each with a ring of `encoder_ring_len` coded octets, 64 KiB (the owner's ruling of
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
    `Blocked`, and a trailer section waits, with `Blocked`, until the coded octets before it are
    out.
  - Mutations: 62, each CAUGHT. On the first run 8 were NOT CAUGHT:
    - Three got a test each: an element with no coding, a second `*`, and a parameter other than
      `q`.
    - h3's limit on a response's runs got a test whose interim heads fill them.
    - A fourth decimal's check went, because the comma rule already refuses one.
    - The end written with no octets was dead code, since gzip and zlib end with a trailer. It
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
    with its body octet for octet.
  - Over its 32 seeds: 82 exchanges, 19 decoded, 4 passed on coded, and 8 too large. The census
    CRC-32, 0x69460a6e, is the same in Debug and ReleaseSafe.
  - `zig build test` passed: 2323 of 2323 tests.

  **17e part 4, interop, 2026-09-29.** The test-only server and client take `--coded`. The server
  codes its fixed answer in gzip or deflate, and echoes stay as they arrived, so the HTTP Garden
  sees the same octets. The client offers both codings and decodes, and names the coding it
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
    answers, `/` and the 1 MiB `/large`, and h2o 2.2.5's gzip `/text.txt`, octet for octet, on one
    connection and on 64, in cleartext and over TLS.
  - Mutations: 93, each CAUGHT: 62 of the server's rules and 31 of the client's.

  **17h, the client decodes `zstd` and `br`, 2026-09-30.**
  - `http.content_coding.Coding` gains `zstd` and `br`, and `from_name` reads both in any case.
    The server encodes `gzip` and `deflate` alone, and each server configuration asserts that it
    names no other coding.
  - `client.ZstdDecoderPool(count)` and `client.BrotliDecoderPool(count)` hold stdx's decoders.
    The caller places each pool, resets it with the CPU features its decoders run on, and gives a
    configuration its `storage()` as `zstd_decoders` or `br_decoders`. A `zstd` decoder is
    8,683,024 octets and a `br` one 19,483,040. A configuration names each coding once at most,
    each with its pool, and gives no pool for a coding it does not name.
  - Each request offers, in the configuration's order, each coding whose pool has a decoder free,
    and takes that decoder. A head that waits, for room or for the server's stream limit, offers
    again with the decoders it took. The response's head keeps the decoder of the coding it names
    and gives back the others. The slot records the codings its offer named, and the client
    decodes a response only in one of them.
  - A `zstd` decoder starts again after each frame (RFC 8878 §3.1), and a frame whose window
    passes 8 MB fails its response (RFC 9659 §3). A `br` stream ends with its last meta-block (RFC
    7932 §9.2), so an octet after it fails the response. Content that ends inside a frame or a
    stream fails it too.
  - The client module imports stdx's `zstd` and `brotli`, and no longer `gzip` and `zlib`, which
    only its tests import.
  - Each exchange's slot grows by 88 octets, for the handles of its `zstd` and `br` decoders and
    the codings its offer named: 1,408 per connection, which `docs/performance.md`'s table shows.
  - The tests decode the fixtures in `src/client/coding_fixtures/`, which zstd 1.5.7 and brotli
    1.2.0 wrote, in pieces of 1 octet, of 7 and whole, over h11, h2 and h3.
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
    Caddy 2.6.2's `zstd` of the 65,536-octet `/text.txt` octet for octet, in cleartext and over
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
    once. Both examples present the test identity ([decision 96](decisions.md) as amended).
  - docs/usage.md and README.md lead with the two modules. The guide's sections on the server,
    the client, the endpoint and the channel are excerpts of the two examples, and
    `tools/consumer/` builds `server`, `client` and `tls` as a dependent and runs an h2 exchange.
  - [Decision 115](decisions.md): a type's public functions are the calls a program makes. The
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
    and for no name that repeats its file's ([decision 115](decisions.md) as amended a third
    time). A script lists the names code outside a module uses, and each root is that list, so
    72 whole files are no longer exported. A type named after its file is exported under its own
    name: `http.Field`, `h2.Connection` and `quic.PeerAddress` replace `http.field.Field` and its
    like, which rewrote 147 call sites. `tools/lint/root_exports.zig` refuses a root that
    exports a file or lists nothing. h11's connection keeps 13 methods of 16, h2's 20 of 22 and
    h3's 15 of 16; a build with each candidate made private showed that the server calls `fail`
    on all three.
  - `server.Endpoint.init` returns `error.DeadlineInvalid` for limits a connection would refuse,
    as the owner ruled on 2026-10-04 ([decision 110](decisions.md) as amended), so its callers
    gained `try`. Before, each connection's start failed and the endpoint answered no client.
  - Writing the examples found four things a program must know, and the guide or the example it
    quotes now says each. A connection's deadlines count from the instant `init` is given. A
    client takes a QUIC datagram only from the address it sends to. Over QUIC a client that
    closes as its exchange ends acknowledges nothing more, so the server reports no `done`, and
    `ended` hands the connection back. Over h3 a request with no content may end in an empty
    `body` event.
  - Deliberate breaks of the examples: 13, each CAUGHT by `zig build examples`. For
    `tls_exchange`: the server never reports `done`, the server answers another status, the client
    keeps no wanted field, the client drops the last octet of content, the link drops an octet,
    the client asks for another server name, and the client never shuts the connection down,
    after which both sides sleep until the server's deadline and the example gives up. For
    `h3_exchange`: the server answers another status, the endpoint never hands back an ended
    connection, the client keeps no wanted field, the client drops the last octet, the link
    changes an octet of each datagram, and the client offers another ALPN token.
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
  - `zig build examples`: the four programs each printed that every octet arrived as sent.
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
  - [Decision 116](decisions.md): the server owes the 100 on the head alone, and a request whose
    stream h3 has read to its end gets none, whether the stream ended with the head or after it.
    Content that arrived with the head leaves the 100 owed, as over h2.
  - A 100 that finds no free run among its response's runs stays owed until the peer acknowledges
    one, and delays no other request.
  - `server.QuicConnection` gains no call and the root no name, so the lists of step 17f are
    unchanged. A `QuicConnection` is 721,384 octets, 256 more: each of its 32 request records
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
      alone; an unknown final size; and octets still to read taken for the end.
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
    arrived octet for octet, as before.
  - `tools/quic_udp.sh`: colibri's client fetched the three files from the `h3` mode, and each
    connection's qlog files passed `tools/qlog_check.py`.
  - `tools/h3spec.sh`: h3spec 0.1.13 passed 49 of 49 against the `h3` mode.
  - `zig build examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh` passed.

- **Step 18 — qlog.** [Decision 102](decisions.md) has colibri log a connection as qlog when its
  caller asks, from the drafts pinned in `docs/rfcs/qlog/`. Four parts, in order:
  - **18a**, the `qlog` module. A `Log` over a buffer the caller owns, the QlogFileSeq header of
    main schema §5, and the event envelope of §7, with each time in milliseconds after the
    connection's first instant. Each record is a JSON text between RS and LF (RFC 7464) with
    RFC 8259's escaping. An event that does not fit is dropped whole and counted.
    **Check:** byte-exact tests of the header and of each record, and a test that fills a buffer
    until an event is dropped.
  - **18b**, QUIC events. `Options.qlog`, null by default, and the Core events of quic-events §3:
    `version_information`, `alpn_information`, `parameters_set`, `packet_sent` and
    `packet_received` with their frames, `recovery_metrics_updated` and `packet_lost`. Also
    `connection_closed`, `connection_state_updated` and `packet_dropped`.
    **Check:** each QUIC check of the simulator gives the same census with a log as without one,
    and each record of those logs parses as JSON and carries the fields its event requires.
  - **18c**, the endpoints. §9's UDP endpoint writes each connection's log under `QLOGDIR`, named
    for its original destination connection ID and its vantage point (main schema §12.1), and
    the interop image passes on the runner's `QLOGDIR`.
    **Check:** a runner run leaves one file per connection, and each file parses.
  - **18d**, HTTP/3 events. h3-events' `parameters_set`, `stream_type_set`, `frame_created` and
    `frame_parsed`.
    **Check:** the simulator's h3 checks give the same census with a log as without one, and each
    record parses.

  **18a, 2026-09-27.** `src/qlog/` is the `qlog` module, exported by name, which imports `core`.
  - `Json` writes a JSON text through `core.Writer`: objects and arrays with a comma between
    members, strings of colibri's ASCII with RFC 8259 §7's escapes, hexstrings, unsigned integers,
    booleans, and milliseconds with a three-digit fraction from nanoseconds.
  - `Log` holds the records in a buffer the caller owns. `start` writes the QlogFileSeq header
    with the trace's group ID and vantage point, a monotonic clock whose epoch is "unknown", and
    the event schemas. `event` writes one record, whose time runs from the header's instant, or
    drops it whole and counts it. `bytes` and `clear` hand the records to the caller.
  - The drafts and RFCs 7464 and 8259 are in `docs/rfcs/qlog/`, with their SHA-256 in
    `docs/rfcs/SHA256SUMS`.
  - 9 tests, byte-exact, and 8 mutations, each CAUGHT: the record separator, the closing line
    feed, both escapes, the comma, an event committed in part, the fraction's unit, and the
    epoch.

  **18b, 2026-09-27.** `quic` imports `qlog`, and `Options.qlog`, null by default, is the log a
  connection writes into. The caller writes the log's header with `Log.start`, because the event
  schemas it names depend on whether h3 events go into the same log.
  - `connection_qlog.zig` writes the events. `Connection.init` logs `version_information` and the
    connection's own `parameters_set`. `seal_all` logs each packet it seals as `packet_sent`. The
    receive walk logs each packet as `packet_received` or `packet_dropped`, with the octets the
    walk stepped over as its length. A packet's frames are read a second time from its
    plaintext, and an ACK Delay is scaled by the exponent of the endpoint that sent it (RFC 9000
    §19.3).
  - `send`, `receive` and `on_instant` end in `log_changes`, which logs what changed since the
    last events: the peer's `parameters_set` and the `alpn_information` once the peer's
    parameters arrive, the state of quic-events §4.6, `connection_closed` when the connection
    stops being active, and each recovery metric whose value changed. A peer's close is logged
    where its frame is read, which is where its code is known.
  - `quic_event.zig` writes `version_information` and `alpn_information`, and `packet_lost`'s
    trigger is optional, for a loss either threshold of RFC 9002 §6.1 could have declared.
  - 10 tests in `connection_qlog_test.zig` and one in `quic_event.zig`. 20 mutations, each CAUGHT
    by `zig build test-quic`, broke: the PADDING of a sent packet; the length of a coalesced
    packet; one close per side; a close logged only once the connection stops being active; one
    event per state; the three rules of a metric logged on change; the peer's parameters and the
    protocol, once each and in that order; the two rules of the Handshake state; each side's ACK
    Delay exponent; two drop triggers; the version's byte order; the initiator of a connection's
    own parameters; a sent close's code; and a frame that does not parse, which was NOT CAUGHT
    until its test was written.
  - Each packet recovery declares lost is logged as `packet_lost`: with `time_threshold` from the
    loss timer, with `pto_expired` from a probe timeout (RFC 9002 §6.2.4), and with no trigger
    from an ACK, where either threshold of §6.1 could have declared it. 2 tests, and 5 mutations,
    each CAUGHT by `zig build test-quic`: each of the three triggers, the ACK's losses logged at
    all, and the lost packet's number.
  - The simulator check, 2026-09-28. The QUIC connection check runs its five networks again
    with a qlog on each endpoint, and each gives the digest it gives without one, which folds in
    every datagram's octets. The run takes each endpoint's records after every step, as a caller
    that writes them to a file would, and fails when an event was dropped. The logs replay too:
    Debug and ReleaseSafe wrote the same octets with the same digest on each network, 9,786,196
    octets over the lossy network's 256 seeds, and the test pins each network's length and
    digest.
  - 5 mutations, each CAUGHT by `zig build test-sim-run-quic`: the endpoints given no log, a
    dropped event left unreported, the records not taken after a step, and two changes a logger
    could make to what a connection sends: the count a PING waits for, and the congestion window.
    The third was NOT CAUGHT until the digest was pinned.
  - Not built yet: the check that each record parses as JSON and carries the fields its event
    requires. It waits for stdx's JSON decoder (decision 102 as amended).

  **18c, 2026-09-28.** The UDP endpoint takes `qlogdir=<directory>` in both roles, and each
  connection writes its qlog there, named as main schema §12.1 recommends:
  `<ODCID>_<vantage point>.sqlog` (`udp_qlog.zig`). A connection's buffer of `quic_qlog_len`
  octets holds one turn's events. The loop writes them to the file after each turn, through libc as
  `hq_file.zig` writes a download, and closes the file when the connection ends or the run fails.
  `run_endpoint.sh` passes the runner's `QLOGDIR` to both roles.
  - `tools/qlog_check.py` checks a directory of these files. Each record must be a JSON text
    between RS and LF (RFC 7464), the header's group ID and vantage point must be the file
    name's, and each event must carry the members main schema §7 and quic-events §3 require, at a
    time that never goes back. The packets sent in each space must be numbered without a gap,
    since colibri skips no number. With `complete` it also requires a client file and a server
    file per connection, each logging the connection's close.
  - `tools/quic_udp.sh` runs its hq-interop and h3 connections with `qlogdir`, requires that no
    event was dropped, and checks the four files with `complete`: 17,283 events, on an Apple M1
    Pro. `tools/interop.sh` checks every qlog directory colibri's side of a runner test case
    leaves. A local run against quic-go, handshake and transfer in both roles, left 8, and each
    passed.
  - 7 mutations, each CAUGHT. `zig build test-testing-udp` caught three: the file named for the
    other vantage point, the connection ID left out of its name, and an empty directory taken.
    `tools/quic_udp.sh` caught four: the records not written each turn, `qlogdir` refused by the
    server and by the client, and a connection given no log. The first and last of those four were
    NOT CAUGHT until `complete` required each file to log its connection's close.

  **18d, 2026-09-28.** `h3` imports `qlog`, and `Options.qlog`, null by default, is the log an h3
  connection writes its HTTP/3 events into. A caller that passes its QUIC connection's log keeps
  both in one trace (h3-events §1.1). Each call that writes or reads a frame takes the instant,
  `now_ns`, and `write_data_header` is a method that names its stream (decision 102 as amended).
  - `connection_qlog.zig` logs `stream_type_set` for each stream colibri or the peer opens, the
    SETTINGS frame each side sends with `parameters_set` for each, and `frame_created` and
    `frame_parsed` for HEADERS with their field lines, DATA, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH and
    reserved or unknown frames. A field line is text when printable ASCII and octets otherwise
    (h3-events §4.2.2). The UDP endpoint's h3 connections write into their QUIC connection's
    file, which names both event schemas.
  - 7 tests in `connection_qlog_test.zig` and 4 in `qlog/h3_event.zig`. 21 mutations, each CAUGHT
    by `zig build test-h3`, removed each hook, kept a stale instant on two calls, and swapped the
    reserved and unknown names and the field section size setting's. The stale instant on a DATA
    frame was NOT CAUGHT until its test gave the frame an instant of its own.
  - The simulator runs the h3 check's first 32 seeds twice, without logs and with one on each
    endpoint, and both give the same datagram digest. The logs' length and digest are pinned, and
    Debug and ReleaseSafe agree. A log too small for a step's events is reported. With logs, the
    whole h3 check wrote 91 MB and the long check 354 MB, and they made `zig build test-sim-run`
    43 and 122 seconds longer on an Apple M1 Pro, so the test runs 32 seeds, which cost 5.
  - 5 mutations, each CAUGHT by `zig build test-sim-run`: the endpoints given no log, the h3
    connection given none, a dropped event unreported, the records not taken after a step, and a
    logger that changes how field sections are encoded. A logger that changed the grease value
    after SETTINGS had gone out changed nothing sent, and was rightly NOT CAUGHT.
  - Not built yet: parsing each record as JSON in the simulator, which waits for stdx's decoder.

  **18b and 18d, the record check, 2026-09-28.** stdx's `json` module is pinned at eb0f0c7, so
  `qlog` writes each record with its `TextWriter`, `src/qlog/json.zig` is gone, and `qlog` imports
  stdx's `json` in place of `core` (decision 102 as amended). `member.zig` writes one member of an
  object, its name and its value. Every byte-exact test passes unchanged, and so do the
  simulator's pinned logs.
  - `src/sim/qlog_records.zig` reads back, with stdx's `TextReader`, each record a logged run
    takes. A log's first record must be the header, with the members main schema §3 and §5
    require. Every other record must be an event with a time, a name and data (§7), no earlier
    than the event before it (§7.1), and with the members its event requires: a packet's header
    and its type, each frame's type, a state's `new`, and a stream's ID and type. The QUIC
    connection check and the h3 check call it after each step and pin the events it read: 49,865
    on the lossy network's 256 seeds, and 47,715 on the h3 check's 32. Debug and ReleaseSafe
    agree.
  - 7 tests, and 12 mutations, each CAUGHT. `zig build test-sim-run-quic` caught the check not
    called, packet events without their header, and seven breaks of the check itself: the
    header's members, the event's members, a member `packet_sent` requires, a member an object
    must hold, a packet's frames skipped, a time that goes back, and a time without three digits
    of fraction. `zig build test-sim-run` caught the check not called, h3 frames without their
    type, and frames read at the instant of the call before. A DATA frame header written at the
    instant of the call before was NOT CAUGHT by the simulator, which writes each at the same
    instant as that call; `zig build test-h3` catches it (18d).
  - Cost, as user CPU time on an Apple M1 Pro. `zig build test-sim-run-quic` took 2.41 s in
    ReleaseSafe at a5a97d2, 2.57 s with stdx's writer, and 2.79 s with the check; in Debug, 15.3,
    16.7 and 18.8 s. The logged runs write 36.7 MB, so stdx's writer costs about 4 ns more per
    octet in ReleaseSafe. The check added 1.2 s to the 71.5 s of `zig build test-sim-run` in
    Debug.

  **18b and 18d, stdx's features, 2026-09-28.** stdx is pinned at f647da1, whose JSON writer and
  reader take the CPU features their vector paths may use (stdx's decision 30). As decision 102
  as amended rules, `qlog.Log.init(buffer, features)` takes them from its caller, and `qlog`
  imports stdx's `codec` for the type, which it exports as `qlog.Features`. The simulator and the
  unit tests pass `Features.none()`, and the UDP endpoint passes `Features.detect()`.
  - The records are the same octets for every value (stdx's invariant 5). Every byte-exact test
    and the simulator's pinned logs and event counts hold, and `zig build test` passed 2,244 of
    2,244. `tools/quic_udp.sh`: 4 files, 17,335 events, each record a JSON text.
    `tools/consumer_check.sh` passed.
  - `zig build test-sim-run-quic` in ReleaseSafe on an Apple M1 Pro, as user CPU time with both
    pins run side by side: 2.88 s at eb0f0c7 and 2.77 s at f647da1. The machine's load average
    was 77 during the run.

  **18b, tuples, 2026-09-28.** Each packet event names the tuple its datagram went to or came
  from (main schema §7.2), so a log shows which of the peer's addresses each packet used, which
  diagnosing [#78](https://github.com/c4milo/colibri/issues/78) took captures for. The first
  address a connection's log meets is tuple 0, which quic-events §4.7 makes the default, and its
  events name none. Each new address takes the next number, and `quic:tuple_assigned` names it,
  with the address's octets and port when it is IPv4 or IPv6 (§4.7, §8.4, §8.5). colibri knows
  the peer's half of a tuple alone (`connection_qlog_tuple.zig`).
  - 7 tests: 4 in `connection_qlog_tuple.zig`, one in `connection_migration_test.zig`, where a
    server follows its client to a new port and its challenge to the previous path names tuple 0,
    and one each in `qlog/log.zig` and `qlog/quic_event.zig`.
  - 7 mutations, each CAUGHT: sent packets and received packets naming no tuple, tuple 0 named,
    a known address numbered again, the newest address let go, IPv4 and IPv6 swapped, and tuple 0
    written as "0".
  - The simulator's logs gained one `tuple_assigned` for each endpoint of each seed, and one for
    each move on the rebinding networks. Their datagrams are the same, and Debug and ReleaseSafe
    agree. `tools/qlog_check.py` and the simulator's record check require `tuple_id`, and
    `tools/qlog_to_qvis.py` leaves the event out, since qlog 0.3 has none.
  - `tools/quic_udp.sh`: 4 files, 17,346 events, each record a JSON text.

  **18c and 18d, the server's connections, 2026-09-28.** `server.Endpoint` takes a log provider in
  its config (decision 102 as amended). Once a connection starts, the endpoint asks the provider
  for a log with the original destination connection ID, gives it to the QUIC connection and to
  h3 through `QuicConnection.attach_log`, and hands it back through `close` when `ended` returns
  the connection. The UDP endpoint's `h3` mode fills the provider from a pool of its logs, so the
  runner's `http3` cases and `tools/quic_udp.sh`'s h3 mode now leave a server qlog as well.
  - 2 tests in `endpoint_test.zig`: a connection's log carries its QUIC and h3 events and comes
    back once the connection is over, and a connection the provider gives no log writes none.
  - 5 mutations, each CAUGHT by `zig build test-server`: the provider never asked, the provider
    asked with the client's connection ID, the QUIC connection given no log, h3 given none, and
    the log never handed back.
  - `tools/quic_udp.sh`: the h3 mode's connection left 2 files, 8,692 events, each whole.
    `tools/interop.sh` no longer skips the `http3` server's qlog directory: `tools/interop.sh
    quic-go http3` on an Apple M1 Pro passed every pairing, and the 4 qlog directories colibri
    left, its server's two among them, passed `tools/qlog_check.py`.

  **18b and 18d, many tokens a call, 2026-09-29.** stdx is pinned at c134f2c, and `qlog` hands
  each record's tokens to stdx's `write_items` in lists (decision 102 as amended). `batch.zig`'s
  `Batch` has `TextWriter`'s calls, so the event writers changed only the type they name. It
  copies each name's, string's and hex string's octets as it takes them, and writes octets longer
  than its buffer at once.
  - Every byte-exact test and the simulator's pinned logs hold, so the records are the same octets.
    `zig build test` passed 2,327 of 2,327, and so did `tools/quic_udp.sh` and
    `tools/consumer_check.sh`.
  - 4 tests in `batch.zig`, and 4 mutations, each CAUGHT by `zig build test-qlog`: octets not
    copied, a long string written before what came earlier, the copies never freed, and items
    written past their array.
  - `zig build test-sim-run-quic` in ReleaseSafe on an Apple M1 Pro, as user CPU time over five
    rounds run side by side: 2.700 s at f647da1, 2.684 s at c134f2c writing one token a call, and
    2.612 s with `write_items`. c134f2c's own speed work was for text outside ASCII, which qlog
    does not write.

- **Step 19 — QUIC version 2.** [Decision 108](decisions.md) adds RFC 9369's version 2 beside
  version 1, with RFC 9368's compatible version negotiation, for
  [#54](https://github.com/c4milo/colibri/issues/54). chapulin derives both versions' keys (its
  decision 79), and colibri reads and writes the wire. Five parts, in order:
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
    version 1's octets are unchanged and a version 2 packet opens under version 2's keys alone.
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
    the Retry, octet for octet, and the Retry read back into its fields.
  - 9 mutations, each **CAUGHT**: version 2's type bits written or read as version 1's, byte 0
    carrying version 1's bits, the reader handing version 2 over as another version, either
    header writing version 1's Version field, and each of the three places a version 2 packet is
    refused letting it through.

  **19b, the keys, 2026-09-29.** chapulin `3f775fa` derives version 2's keys, lets a client
  switch once and a server choose the negotiated version, and binds tickets and Retry tokens to
  their version (its decision 79). colibri pins it.
  - RFC 9369 Appendix A's client Initial, server Initial and Retry seal, open and check octet for
    octet through `tls.quic`'s suite, from a session that starts in version 2. A client starts in
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
    than four octets or not a multiple of four, a version of zero, and a client's Chosen Version
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
  - Every handshake carries ten more octets, so the simulator's census digests moved and its
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
    letting a server switch, a client switch twice, after the server's CRYPTO octets, or to the
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
    opens, until it switched or read a CRYPTO octet from the server. A server is settled from the
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

- **Step 20 — denial of service at the server.** [Decision 110](decisions.md) rules the defences
  that [#82](https://github.com/c4milo/colibri/issues/82) planned, in three parts.
  - **20a**, Rapid Reset (CVE-2023-44487). h2 counts the streams the peer opens and then resets,
    and ends the connection past `peer_reset_rate_max` in one `peer_reset_rate_period_ns`.
    **Check:** unit tests at the limit and across a period, a client whose streams its server
    refuses never ending the connection, and mutations.
  - **20b**, the deadlines of decision 110 in `server.Connection`. **Check:** unit tests at each
    deadline's instant, a simulator check with seeded slow and flooding peers and an honest slow
    peer that is never cut, and mutations. It lands in three parts:
    - the first-request, idle and head deadlines, and the calls that run them;
    - the body and send rates, the cap per request, h2's floor on a DATA frame, the linger of a
      close, and 100 concurrent h2 streams;
    - the SETTINGS acknowledgment and drain deadlines, the close reasons, and the test-only server
      taking its instants from Rotor's loop.
  - **20c**, the same defences over h3 ([#95](https://github.com/c4milo/colibri/issues/95),
    decision 110 as amended). **Check:** unit tests at the reset limit and at each deadline's
    instant, a simulator check with seeded slow and flooding peers over QUIC and an honest slow
    peer that is never cut, a check over real sockets with aioquic as the slow peer, and
    mutations. It lands in four parts:
    - the reset limit in h3;
    - the first-request, idle and head deadlines in `server.QuicConnection`, and `Deadlines` in
      `server.QuicConfig`;
    - the body and send rates, and the cap per request;
    - drain, the close reasons, `set_deadlines`, and the calls in `docs/usage.md` and an example.

    It adds two public functions to `server.QuicConnection`, which a TCP connection has already:
    `set_deadlines`, for a server short of connections that shortens the deadlines of the ones
    it holds, and `close_reason`, for an operator's log that tells an attack from a limit set
    too tight. `examples/h3_exchange.zig` calls both.
  - **20d**, a TLA+ model of the h3 deadlines, `spec/tla/h3_deadlines`, which the owner asked for
    on 2026-10-08. It models one `server.QuicConnection`, an honest client and the application,
    with QUIC's flow control and congestion window, and checks two things:
    - what the server tells the client when it ends the connection on its own: at the close,
      the client knows which requests below the GOAWAY's identifier the server did not take,
      the close waits for the GOAWAY's acknowledgment until the drain deadline passes, and the
      server never counts a reset it asked for;
    - decision 110's rule 2 over QUIC, as `spec/tla/server_deadlines` states it for h2: each
      deadline runs only while the client holds the connection up, checked in the states where
      colibri has no step of its own left.

    **Check:** TLC finds colibri's rules holding, and each earlier rule, and each rule turned
    off, violated. It lands in two parts:
    - the model and its configurations;
    - the simulator's h3 deadline run written as traces of the model, which TLC checks are
      behaviors of it, as `tools/deadline_trace.sh` does for h2.

    The second part logs only what maps one to one, at the owner's ruling of 2026-10-09. colibri
    counts octets and the model units and packets, its congestion window grows with each
    acknowledgment while the model's is fixed, and its receive windows grow too (decision 49),
    so no run can match the model state for state.
    - A run, `h3_deadline_trace_*.zig`, acts out a seed's plan with the h3 deadline run's peer
      and a `server.Endpoint`, one queue of datagrams each way that loses and reorders nothing.
      The peer sends each request in the model's units: its head in `HeadUnits` pieces and its
      content in `Content`, each in a datagram of its own. The application writes each response
      in `ResponseUnits` calls. The program's shutdown and time are actions too. Time moves only
      while no datagram is in flight, to the instant the endpoint or the client next names, and
      never as far as QUIC's own idle timeout, which the model leaves out.
    - A seed may stop the client inside a head or a body, or the application inside an answer,
      so the head, body and drain deadlines pass. The client does not cancel: after a cancel its
      h3 stops reading the stream, where the model's client still learns the response.
    - After each action the run logs the client's side (what it opened, what it learned of each
      request, the GOAWAY and the close), colibri's (each request's phase, whether the
      application heard of it and waits for its content, what it wrote and reset, the GOAWAY's
      identifier, the shutdown, the close and its reason), and whether each of colibri's clocks
      runs. TLC finds the units, windows and packets in flight that fit, and each clock must run
      exactly when the model's rule says. colibri reads and writes all it can in the action that
      brings it, so each logged state is one where the model's colibri has no step left.
    - The run's windows are wide enough that flow control never binds, as the h3 trace run's
      are, so the credit rules are checked by TLC on the model and by the unit tests. The run
      turns the body rate off, because the meter of all bodies together, which the model leaves
      out, would close the connection; the body cap is the body clock.
    - `zig build sim -- --h3-deadline-trace-check [seeds]` runs it, `--h3-deadline-trace-write
      <directory>` writes each seed's trace as TLA+, and `tools/h3_deadline_trace.sh` has TLC
      check each one against `spec/tla/h3_deadlines/H3DeadlinesTrace.tla`. `tools/ci.sh` runs
      the script.

  **Rapid Reset, 2026-09-29.** h2 counts a RST_STREAM that closes a stream the peer opened, in the
  period its instant falls in, beside the count of the resets colibri sends. What was checked, on
  macOS arm64 with Zig 0.16.0:
  - `zig build test`: 128 of 128 steps and 2388 of 2388 tests passed, the simulator's h2 censuses
    unchanged.
  - `tools/h2spec.sh 18443 --tls` passed 144 of 146 cases in cleartext and over TLS, skipping
    decision 41's two.
  - Mutations, each **CAUGHT**: the peer's resets not counted, every reset counted, the reset at
    the limit refused, one past the limit allowed, the period never starting again, a period
    starting one nanosecond late, and the wrong error code.

  **The first-request, idle and head deadlines, 2026-09-29.** The first part of 20b.
  - `server.Connection.init` takes the instant the listener accepted the connection, and
    `Config.deadlines` holds each deadline's limit, or null to turn it off. `set_deadlines`
    changes one connection's limits. Both refuse 0, and a limit past `timeout_ns_max`, a day.
  - `deadline_ns` reports the soonest instant a deadline passes, and `on_instant` ends the
    connection then. `receive` and `send` end it first when their instant is past a deadline, so
    octets that arrive late are not read. `timed_out` names the deadline that ended it.
  - A silent or idle h11 connection closes with nothing sent, and a head that began and did not
    end gets a 408 with `Connection: close`. h2 sends GOAWAY with NO_ERROR, or with
    ENHANCE_YOUR_CALM for a field block left unfinished.
  - Only a request head starts or ends a deadline. An h2 PING does not, and no deadline runs
    while the application holds a request.
  - The deadline check (`zig build sim -- --deadline-check`) came first, in a commit of its own.
    Before the deadlines, every hostile peer held the server open until the end of the run. With
    them it also runs a peer that makes one exchange and then sends nothing but PINGs, over 256
    seeds.

  What each check printed, on macOS arm64 with Zig 0.16.0:
  - `zig build test`: 128 of 128 steps and 2408 of 2408 tests passed.
  - The deadline check over 256 seeds: 130 exchanges; 104 connections ended at the first-request
    deadline, 107 at idle and 45 at head, and none held open. Debug and ReleaseSafe print the
    same census.
  - 39 mutations, each **CAUGHT** by `zig build test-server` but one: the idle limit raised to
    31 s, which the unit tests read from its constant and the deadline check's census catches.
    - The calls: `receive`, `send` or `on_instant` not ending a connection past its deadline, or
      not noting a wait that began; a deadline passing a nanosecond late; and `deadline_ns`
      reporting the later deadline, or leaving out the head's or the first request's.
    - The limits: `init` or `set_deadlines` not validating them; `init` ignoring
      `Config.deadlines`; the clock starting at 0 rather than at `init`'s instant;
      `set_deadlines` keeping the old limits; and `validate` accepting 0 or a limit past a day,
      or refusing a day.
    - The waits: a request not ending the first-request deadline, or that deadline passing after
      the first request; a head's deadline outliving the head, or restarting at each call; idle
      running before the first request, never starting, or restarting at each call; the idle or
      head deadline never passing; and an unfinished h2 block, a begun h11 head, an h2 connection
      with open streams, or an h11 request being read taken for idle.
    - The actions: a begun h11 head ending without a 408, or an idle h11 connection with one; the
      408 without its reason phrase; an unfinished h2 block ending with NO_ERROR; an idle h2
      connection ending without a GOAWAY; a handshake deadline leaving the connection open; and a
      deadline not stopping the connection.
  - The deadline check caught 22 of the 39 by itself. It calls `receive`, `send` and `on_instant`
    at every instant, runs in cleartext, and leaves every limit at its default. So it cannot tell
    which call ended a connection, and it misses the handshake deadline, the checks on limits,
    the reason phrase, and idle running before a first request, which the first-request deadline
    always ends first.

  **The body deadlines, 2026-09-29.** The second part of 20b, after the deadline check's new peers.
  - From the end of a request's head, or from the 100 (Continue) the request is owed, its body
    must bring `body_rate_min` octets a second over each window of `rate_window_ns`, the first
    window taking `rate_grace_ns` more, and must end within `body_timeout_ns`. `server.rate.Meter`
    keeps the windows: one that brings its quota ends where the next starts, so a peer cannot bank
    octets from one window for the next.
  - Only a body's own octets count: in h11 what h11 reads of the body, its framing included, and
    in h2 the data of its DATA frames, without their padding.
  - In h11 a body that falls short ends the connection, with a 408 unless its response began. In
    h2 it ends its stream, with a 408 and RST_STREAM with NO_ERROR, or with CANCEL once the
    response began, and the caller reads `cancelled`, whose new `reason` names the deadline. h2
    also meters the bodies together, from the first body that waits until none does, and ends
    the connection with ENHANCE_YOUR_CALM when they fall short.
  - The cost: each h2 stream's body keeps the rate on its own. A client that uploads on several
    streams over a slow link, and starves one of them, loses that one. The check's honest uploads
    go one at a time.
  - The check gains an honest upload at two to four times the rate, a slow body under it, and a
    long body that keeps twice a shortened rate past a shortened cap. Each run starts at a drawn
    instant, and one plan in four shortens the server's limits.

  What each check printed, on macOS arm64 with Zig 0.16.0:
  - `zig build test`: 128 of 128 steps and 2428 of 2428 tests passed.
  - The deadline check over 256 seeds: 145 exchanges; 67 connections ended at the first-request
    deadline, 137 at idle, 26 at head, 14 for a body's rate and 12 for its cap; 28 h2 streams cut,
    and none held open. Debug and ReleaseSafe print the same census.
  - 41 mutations, each **CAUGHT** by `zig build test-server`. Two were **NOT CAUGHT** at first,
    the deadlines running on after h11 closes and a stopped meter counting, and a test now
    catches each.
    - The waits: a body's wait never starting, starting before its 100 (Continue), or starting
      again at each call; h11 or h2 counting no body octets; a body's end, its trailers, the
      peer's reset or the caller's cancel leaving its deadlines running; and the count of bodies
      that wait left as it was.
    - The bodies together: their meter running with no body, starting again with each body,
      never falling short, or left out of `deadline_ns`, and ending the connection with NO_ERROR.
    - The cap: never passing, passing a nanosecond late, or left out of `deadline_ns`.
    - The rate: never falling short, or its meter left out of `deadline_ns`; a window at its
      quota taken for short, in `check_ns` or in `short`; the next window keeping the last one's
      octets; two ended windows not short; the meter starting without its grace period; the quota
      rounding down; and `validate` accepting a rate or a grace period of 0.
    - The actions: h2 writing no 408 before a response, or resetting with CANCEL after one; an h2
      stream's deadline owing no `cancelled`, naming the cap for every body deadline, or ending
      the connection; and an h11 body deadline writing no 408.
    - The reasons: an h2 or h3 peer's reset read as a refusal, a refusal read as the peer's
      reset, and a STOP_SENDING read as a refusal.
  - The deadline check caught 21 of the 41 by itself. None of its peers sends trailers, cancels,
    holds two bodies at once or waits for a 100, and it leaves the limits valid and reads no
    reason but a deadline's.
  - The check's own commit reports three mutations, each **CAUGHT**: `init` ignoring
    `Config.deadlines`, the clock starting at 0, and h2 never crediting its connection window.

  **The send deadlines, 2026-09-29.** More of the second part of 20b, after the check's slow
  readers and a fix: the idle deadline had started when a response's last octets went into the
  output, not when the peer took them, and cut a peer that read a long response slowly.
  - While the connection holds octets its peer has not taken, the peer must take `send_rate_min`
    octets a second over each window, as a body brings them. The meter counts what `send` hands
    out and stops when the output is empty. A peer that takes too little ends the connection: h11
    sends nothing more, and h2 queues a GOAWAY with ENHANCE_YOUR_CALM.
  - In h2 a stream whose response waits on a flow-control window has a meter of its own, which
    counts what the window lets through. It runs only while the output is empty: a client that
    opens its window once it has read what fills it would otherwise be cut, and while the output
    holds octets the connection's meter judges the peer. When the stream's meter falls short, the
    stream is reset with CANCEL and the caller reads `cancelled`. When the connection's window is
    the one that holds it, the connection ends with ENHANCE_YOUR_CALM, a code decision 110 left
    open.
  - h2 sends no DATA frame shorter than `data_frame_len_min`, 1,024 octets, unless the window
    holds the whole payload (RFC 9113 §10.5). `server.Config` carries it, the h2 connection takes
    it as a field that is 0 for none, and `DataWritten` now says what held a frame short.
  - A connection that has ended with octets still to send closes once they are out or
    `close_linger_ns` after it ended, whichever comes first.
  - A body arrives a unit at a time, an h2 DATA frame or a TLS record of up to 16,384 octets. A
    peer at twice the minimum rate brings one each window only when the window's quota is half a
    unit or more, as the defaults' 10,240 octets are. `Deadlines` says so, and the check's stricter
    plans keep to it; an earlier plan whose windows held no whole frame cut an honest upload.

  What each check printed, on macOS arm64 with Zig 0.16.0:
  - `zig build test`: 128 of 128 steps and 2455 of 2455 tests passed.
  - The deadline check over 256 seeds: 141 exchanges; 45 connections ended at the first-request
    deadline, 114 at idle, 14 at head, 5 for a body's rate, 12 for its cap and 66 for the send
    rate; 33 h2 streams cut, and none held open. Debug and ReleaseSafe print the same census.
  - 34 mutations, each **CAUGHT** by `zig build test-h2` and `zig build test-server`. Three were
    **NOT CAUGHT** at first, and a test now catches each: a stream held after its window let a
    write through, a stream's meter running while the output holds octets, and a stream's octets
    left uncounted.
    - h2's floor: never holding a frame, holding a payload the window holds whole, or holding a
      window at the floor; the connection's window read as the stream's; room read as nothing
      held; and the server setting no floor.
    - The meters: a write a window held not noted; the connection's window noted as the stream's;
      the connection's meter running with an empty output; a running meter starting again at each
      call; `send`'s octets not counted; the connection's meter never falling short; and
      `deadline_ns` leaving out either meter.
    - The actions: a stream the connection's window holds cancelled rather than ending the
      connection; a held stream never cancelled; a cancelled one owing no `cancelled`, or reset
      with NO_ERROR; and h2 ending a send deadline with NO_ERROR.
    - The linger: never ending, ending a nanosecond late, never starting, ignored by
      `should_close`, or left out of `deadline_ns` once the connection has stopped.
    - The limits and the ends: `validate` accepting a send rate or a linger of 0; and trailers, a
      peer's reset, the caller's cancel or the other deadline leaving a stream's send meter, or its
      body's meter, behind.
  - The deadline check caught 23 of the 34 by itself. None of its peers sends trailers, cancels, or
    opens a window a floor at a time, and it leaves the limits valid.
  - The check's own commit reports one mutation, **CAUGHT**: idle starting with the output held.

  **The SETTINGS deadline, 2026-09-29.** The first piece of 20b's last part. An h2 peer that does
  not acknowledge the server's SETTINGS within `settings_timeout_ns`, 10 s, ends its connection
  with SETTINGS_TIMEOUT (RFC 9113 §6.5.3): h2 reports the instant with
  `Connection.settings_deadline_ns`, and the server's deadlines honour it. The deadline check
  found it cutting an honest upload whose acknowledgment arrived behind its own DATA, and the
  owner amended decision 110: the SETTINGS clock stops while a request body arrives.
  - `zig build test`: 128 of 128 steps and 2458 of 2458 tests passed. The deadline check's census
    did not change, and no connection in it ended at the SETTINGS deadline.
  - 8 mutations, each **CAUGHT** by `zig build test-server`: the deadline never passing, passing
    a nanosecond late, or left out of `deadline_ns`; the connection ending with another code; the
    clock not pausing while a body arrives, the pause adding nothing, or the deadline running
    while paused; and h2 reporting no SETTINGS deadline.

  **The drain deadline, 2026-09-29.** After the caller's `shutdown`, the requests the connection
  holds have `drain_timeout_ns`, 30 s, before it closes. `shutdown` takes no instant, so the drain
  runs from the first call after it. When it passes the connection stops: h2's GOAWAY went out
  with the shutdown (RFC 9113 §6.8), and h11 says nothing more.
  - `zig build test`: 128 of 128 steps and 2460 of 2460 tests passed. The deadline check's census
    did not change, since none of its runs shuts down.
  - 6 mutations, each **CAUGHT** by `zig build test-server`: the drain never starting, starting
    again at each call, never passing, or left out of `deadline_ns`; a drain ending as the other
    deadlines do, with a second GOAWAY; and `validate` accepting a drain of 0.

  **The floor, as amended, 2026-09-29.** h2spec failed six flow-control cases once the floor was
  in: each sets a window of one octet and waits for a DATA frame of one octet. The owner amended
  decision 110: the floor applies only while the peer's SETTINGS_INITIAL_WINDOW_SIZE is at least
  the floor.
  - `tools/h2spec.sh 18443 --tls`: 144 of 146 cases in cleartext and over TLS, the two decision
    41 skips.
  - 2 mutations, each **CAUGHT** by `zig build test-h2` or `zig build test-server`: the floor
    ignoring the peer's initial window, and a peer whose initial window is the floor counting as
    small.

  **The test-only server's clock, 2026-09-29.** Design §9's server ran each connection on a counter
  of a millisecond a step, so no deadline ever passed on a real socket. It now takes the instant
  its Rotor loop read at the last tick, as the UDP endpoints do (decision 63), and a tick waits no
  longer than the soonest deadline of its connections. `tools/deadlines.sh` runs it in h11 and h2,
  and `tools/ci.sh` runs that.
  - `tools/deadlines.sh`: half a head cut at 10.00 s, a silent peer at 10.00 s while another
    connection opens halfway, a body too slow at 20.00 s, and an h2 preface alone at 10.00 s.
  - `tools/h2spec.sh 18443 --tls`: 144 of 146 cases in each mode. `tools/h2_server_interop.sh
    --tls` and `tools/h11_server_interop.sh --tls`: every request answered.
  - 2 mutations, each **CAUGHT** by `tools/deadlines.sh`: the loop never waking a connection at
    its deadline, and a tick waiting Rotor's longest. The default deadlines are multiples of that
    wait, 10 s, so the second is caught only because another connection opens halfway.

  **100 concurrent h2 streams, 2026-09-30.** The last piece of 20b's second part. The server
  advertises a SETTINGS_MAX_CONCURRENT_STREAMS of `h2_streams_max`, 100, down from h2's 128, and
  refuses a stream past it with REFUSED_STREAM (RFC 9113 §5.1.2); `server.Config` lowers it. h2's
  `Connection.limit_peer_streams` sets what it advertises and enforces, before its preface.
  - `zig build test`: 128 of 128 steps and 2463 of 2463 tests passed. `tools/h2spec.sh 18443
    --tls`: 144 of 146 cases in each mode.
  - 5 mutations, each **CAUGHT** by `zig build test-h2` and `zig build test-server`: h2 refusing
    at its table's size rather than the limit, the limit not advertised or not enforced, the
    server setting no limit, and one stream past the limit allowed.
  - A peer that opens 110 streams at once joins the deadline check once h2's queue of replies can
    hold a reset for each stream a deadline cuts in one call: 32 fit today.

  **The close reasons, 2026-09-30.** The last piece of 20b. An operator cannot tell an attack from
  a limit set too tight unless the connection says what ended it
  ([#82](https://github.com/c4milo/colibri/issues/82)). `server.Connection.close_reason` replaces
  `timed_out`: it names the deadline that passed, or the limit the peer passed, and is null after
  any other end. h2 records which of its four limits ended a connection with ENHANCE_YOUR_CALM,
  and h11 names its one limit, on a run of records that carry no data.
  - `zig build test`: 128 of 128 steps and 2479 of 2479 tests passed. The deadline check's
    census did not change.
  - 15 mutations, each **CAUGHT** by `zig build test-h2`, `zig build test-server`, `zig build
    test-sim-run` or the deadline check: h2 naming no limit, naming one after an earlier failure,
    keeping the last connection's limit, or naming any of its four limits as another; the server
    naming no limit or no deadline, not reading h2's limits or h11's, or naming every h2 or h11
    failure a limit; and the simulator recording no close reason, or reading a limit as a
    deadline.

  **The peer that opens 110 streams, 2026-09-30.** It joins the deadline check now that decision
  113 lets a caller reset every stream it holds between two writes. The peer opens 110 streams at
  once, each a request whose body never comes. The server refuses the 10 past its 100 with
  REFUSED_STREAM. At the end of the first window it cuts the other 100 in one call, each with a
  408 and RST_STREAM with NO_ERROR, and the connection closes at the idle deadline.
  - `zig build sim -- --deadline-check`, in Debug and in ReleaseSafe: every seed passed, with
    `streams_refused=60` over six runs of the peer and the census CRC-32 `0xa02e1727`.
  - `zig build test`: 131 of 131 steps and 2493 of 2493 tests passed.
  - 3 mutations, each **CAUGHT** by the deadline check: the server leaving h2's limit at 128, h2
    refusing one stream past the limit too late, and a caller's RST_STREAM put back in the queue of
    `stream_replies_max` slots, which stops on the queue's assertion as before decision 113.

  **The deadline model, 2026-09-30** ([#86](https://github.com/c4milo/colibri/issues/86)). The
  simulator and h2spec found three rules that broke decision 110's rule 2, a deadline runs only
  while colibri waits on the peer, and no model had deadlines to find them.
  `spec/tla/server_deadlines` models one h2 server connection, an honest client and an
  application. It states rule 2 as four invariants and checks them in the states where colibri has
  no step of its own left to take, since its own steps take no time.
  - `zig build tla -- spec/tla/server_deadlines/*.cfg`, in about a minute: colibri's rules hold the
    idle, SETTINGS and send invariants over 6,380,329 states. Each rule this step replaced breaks
    one of them: the idle deadline starting once the response is written, the SETTINGS deadline
    running while a body waits, and the floor applied whatever the peer's window.
  - Two findings, each kept as a configuration TLC must find violated until it is ruled on:
    - `body_update_held`: a body's deadline runs while the client's window is spent and the
      WINDOW_UPDATE that reopens it waits in colibri's output
      ([#89](https://github.com/c4milo/colibri/issues/89)).
    - `floor_late_update`: the amended floor stalls a client that sends a WINDOW_UPDATE only for
      more credit than its window minus the floor
      ([#90](https://github.com/c4milo/colibri/issues/90)).
  - Checking the deadline check's runs against the model is the rest of
    [#86](https://github.com/c4milo/colibri/issues/86).

  **The floor after a small increment, 2026-09-30**
  ([#90](https://github.com/c4milo/colibri/issues/90)). Decision 110's third amendment. h2 notes
  a WINDOW_UPDATE whose increment is below `data_frame_len_min`, on the connection or on a stream,
  and the floor applies only from then.
  - `zig build test`: 131 of 131 steps and 2496 of 2496 tests passed. The deadline check's
    census moved to `0x6d3f1273`, the same in Debug and ReleaseSafe, with every count unchanged:
    one honest slow reader, seed `0x1b`, drains its last response 60 ms later, since colibri now
    sends a short frame the floor held before.
  - `zig build tla -- spec/tla/server_deadlines/*.cfg`: `late_update` holds. The first
    amendment's rule is violated, kept as `floor_any_update`, which the model named
    `floor_late_update` before.
  - `tools/h2spec.sh 28443 --tls`: 144 of 146 cases in each mode, the two decision 41 skips.
  - 7 mutations, each **CAUGHT** by `zig build test-h2` or `zig build test-server`: no increment
    turning the floor on, an increment of the floor turning it on, the floor applied before a small
    increment or whatever the peer's initial window, either reader of WINDOW_UPDATE noting nothing,
    and `init` keeping the last connection's note.

  **A body's rate and a held WINDOW_UPDATE, 2026-09-30**
  ([#89](https://github.com/c4milo/colibri/issues/89)). Decision 110's fourth amendment. h2 says
  whether it owes a WINDOW_UPDATE, and the server counts down the octets its output holds ahead of
  the last one it wrote. While either holds one, every body's rate meter and the bodies' shared
  meter stop, and they start again with a grace period once the update is out. The cap on a body
  keeps running. The count makes a `server.Connection` 8 octets larger, 306,280 in all, as
  `docs/performance.md`'s table says, and the reply queue is read only while a body waits.
  - `zig build test`: 131 of 131 steps and 2499 of 2499 tests passed. The deadline check's census
    did not change: none of its runs holds a WINDOW_UPDATE while a body's rate matters.
  - `zig build tla -- spec/tla/server_deadlines/*.cfg`: colibri's rules now hold all four
    invariants, and `upload_update_held` holds. The rule before the amendment is violated, kept as
    `body_update_held`.
  - 8 mutations, each **CAUGHT** by `zig build test-h2` or `zig build test-server`: an owed
    WINDOW_UPDATE on a stream, or on the connection, not counted; the rate ignoring h2's queue or
    the output; a written WINDOW_UPDATE not tracked, or never counted out; and the shared meter or
    a body's own meter not waiting. The first run found two NOT CAUGHT: the rate ignoring the
    output, and a written WINDOW_UPDATE not tracked. The test checked that the connection ended on
    the send deadline, and not that the body deadline had cut the stream first. It checks both now.

  **The deadline model in octets, 2026-09-30.** A run of colibri's h2 client and server can be
  checked against the model only if the model sends what they send
  ([#86](https://github.com/c4milo/colibri/issues/86)). It now counts octets as colibri does:
  - a frame is a header and its payload, colibri's output holds `OutputLen` octets and each
    direction `ChannelLen`;
  - a DATA frame from colibri is as long as the windows, the floor, the frame size and the room
    allow, as `sendable` has it;
  - both endpoints owe their replies as `connection_reply.zig` queues them: SETTINGS
    acknowledgments, one increment for the connection, then the streams' in order;
  - the client's preface and both acknowledgments of SETTINGS are frames of their own, and the
    client sends DATA frames of any length its windows allow, or with `MaximalUploads` only the
    longest, as colibri's h2 does.

  `zig build tla -- spec/tla/server_deadlines/*.cfg`, in about a minute and a half: colibri's
  rules hold the four invariants in two configurations, `colibri`, with two streams at once and
  small buffers (7,310,332 states), and `colibri_one_at_a_time`, with larger buffers (1,377,905
  states). The five earlier rules are each violated, as before.

  **The deadline model against colibri's runs, 2026-09-30**
  ([#86](https://github.com/c4milo/colibri/issues/86)). The model proves decision 110's rules
  only if colibri does what the model says. The simulator's deadline trace run acts out a seed's
  plan with colibri's h2 client and a `server.Connection` in cleartext. The client opens up to
  three streams, pipelined or one at a time, and the application answers each request with a body
  it offers a step at a time. Each action is one step of one side: the client writes or reads a
  frame, colibri reads one or hands one out, or the application answers or offers content. After
  each action the run offers `write_body` the rest of each response until colibri takes no more,
  since one call writes one DATA frame. It then logs the model's variables, read from the two
  endpoints and the octets between them, and whether colibri's SETTINGS, body and send clocks
  run. TLC checks that each seed's log is a behavior of the model, that each clock runs as the
  model's rules say, and that the model's colibri has no content left to take. A log that stops
  early is still a behavior, so the run also requires each seed to end with every exchange
  finished and nothing in flight or owed. No run lasts long enough for a deadline to pass, so the
  check covers when each clock runs, not when one expires.
  - The first run found the model adding a WINDOW_UPDATE's increment on a stream colibri had
    closed. colibri's h2 discards it, which RFC 9113 §6.9 says is no error, and notes no small
    increment from it. The model now does the same at both endpoints.
  - TLC evaluated the operator bound to the `Trace` constant again at each reference, so its cost
    per state grew with the log's length. The trace module reads the log through `Logged`, a
    definition TLC evaluates once. On macOS arm64, seed 0's 311 states took 5.6 s, not 90 s.
  - `tools/deadline_trace.sh`: 32 of 32 traces are behaviors of the model, in under a minute.
  - `zig build tla -- spec/tla/server_deadlines/*.cfg`: the nine configurations give their
    verdicts as before, `colibri` over 7,525,308 states and `colibri_one_at_a_time` over 1,413,735.
  - `zig build test`: 131 of 131 steps and 2505 of 2505 tests passed.
  - 9 mutations of colibri, each **CAUGHT** by `tools/deadline_trace.sh`. Five break a clock rule,
    and TLC found the rest of the traces behaviors: the SETTINGS clock never pausing (23 of 32), a
    body's rate running while a WINDOW_UPDATE is held (13), the floor applied before a small
    increment (22), the idle clock starting before the output empties (1), and a held stream's
    send meter running while the output holds octets (17).
  - Four more stop or slow colibri:
    - `write_body` taking nothing while the output holds octets: 1 of 32. Without the check that
      no content is left, **NOT CAUGHT**: 32 of 32.
    - The server writing no reply it owes: the run fails on seed 0, unfinished. Without the check
      that each seed finishes, **NOT CAUGHT**: 32 of 32.
    - h2 writing no SETTINGS acknowledgment: the run fails, unfinished.
    - `sendable` writing nothing when the room is short of a whole frame: the run fails, with more
      frames in flight than `frames_max`.

  **The rate meter proved, 2026-09-30** ([#87](https://github.com/c4milo/colibri/issues/87)).
  `spec/lean/Colibri/Server/RateMeter.lean` states `rate.zig`'s `Meter` and `deadline.zig`'s
  `quota` as colibri computes them. It also states a peer that sends a body in whole units at a
  steady rate, each unit arriving at the first nanosecond its last octet is sent. It proves:
  - the meter's windows: the first ends a grace period and a window after the start, each later
    one follows the one before, and a window that brought its quota gives way at its end with
    nothing counted, so octets that arrive at a window's end count in the next one;
  - `arrival_lt_iff` and `arrives_in_iff`: `brought`, the octets a window receives, counts exactly
    the units that arrive in it;
  - `never_short_iff`: a peer that sends whole units at twice the rate or more, and starts before
    the grace period ends, brings every window its quota exactly when twice the rate over one
    window is a whole unit or more;
  - `half_unit_quota_short` and `half_unit_and_one_enough`: the bound is on the rate times the
    window before the quota rounds it up. At 8,192 octets a second over windows of 999,999,999
    ns, a window owes half of 16,384 octets, and a peer at twice the rate can bring the first
    window nothing. A quota of half a unit and one octet always suffices.

  The note on `Deadlines` said a quota of half a unit was enough, and now states the proved bound.
  The defaults, 10,240 octets over 10 s, and the simulator's `window_quota_min` of 9,216 octets are
  past it. `src/server/rate_vectors.txt` holds 90 quotas and 404 honest peers. For each peer it
  names the first window the proved model leaves short: none for 374, and window 1, 2, 4 or 6 for
  30. A test in `deadline.zig` requires `quota` to give each quota. A test in `rate.zig` drives
  the meter as the server does, `short` at each arrival and at each instant `check_ns` names, and
  requires it to name the same window.
  - `zig build lean`: the proofs build, and every vector file is what the definitions give.
  - `zig build test`: 131 of 131 steps and 2507 of 2507 tests passed.
  - 5 mutations of `rate.zig` and `deadline.zig`, each **CAUGHT** by `zig build test-server`:
    octets at a window's end counted in that window, the next window starting where `short` is
    called, no grace period, a window after a full one never short, and the quota rounding down.
    Only the new meter test caught the second, because every earlier test called `short` at a
    window's exact end.
  - 2 mutations of the Lean definitions stop the proofs, and 1 edit to the vector file is refused
    by `zig build lean`.

  **Body rates an honest peer can meet, 2026-09-30.** Decision 110's fifth amendment.
  `server.Connection` refuses a `body_rate_min` under the bound that
  `spec/lean/Colibri/Server/RateMeter.lean` proves, at `init` and at `set_deadlines`, when its
  configuration has TLS or speaks h2 in cleartext (`Config.whole_units`). Twice the rate over one
  `rate_window_ns` must be a whole unit or more, where a unit, `body_unit_len`, is a record's or a
  DATA frame's 16,384 octets. `fits_unit` in `deadline.zig` computes the bound. The Lean
  `fitsUnit`, which `fitsUnit_iff` proves equal to `never_short_iff`'s condition, gives the same
  answer over 110 vectors. In h2 the deadline check's slow-body server now has windows of 32 s,
  over which twice its 256 octets a second is a unit. Every count of its census is unchanged, and
  its CRC-32 moved to `0x280860ff` in Debug and ReleaseSafe.
  - `zig build test`: 131 of 131 steps and 2513 of 2513 tests passed.
  - 7 mutations, each **CAUGHT** by `zig build test-server` or `zig build test-sim-run`: the bound
    itself refused, a peer at the minimum rate rather than twice it, TLS or h2 in cleartext not
    held to units, `init` or `set_deadlines` checking no unit, and the simulator's h2 slow-body
    server keeping its short window. 1 mutation of the Lean `fitsUnit` stops the proofs.

  **The floor and the server's timeout in the flow-control model, 2026-09-30**
  ([#88](https://github.com/c4milo/colibri/issues/88)). `spec/tla/h2_flow_control` sent each DATA
  frame as one unit and had no time, so two of decision 110's rules were outside it.
  - DATA frames carry lengths. A sender's caller offers `Chunk` units at a time, and a frame
    carries what both windows take of the offer, up to `FrameMax`, as `sendable` has it. The
    server holds a frame while the windows are below `Floor` and do not take the whole offer. It
    holds it only once the peer's initial window is at least the floor and the peer has sent an
    increment below it. The client has no floor. With `FrameMax` of 1 and no floor, every earlier
    configuration that holds explores the states it did before.
  - With `ServerTimeout`, the server ends the connection while the channel toward the client stays
    full: its send deadline passes, then its linger. `Finishes` now reads: every exchange
    finishes, or the server ends the connection.
  - `zig build tla -- spec/tla/h2_flow_control/*.cfg`: colibri's floor holds with the peer's window
    below it (`floor_small_peer_window`, 504 states) and above it (`floor`, 813 states, and
    `floor_two_streams`, 7,117). The rule before each amendment is violated: the floor whatever the
    peer's window (`floor_small_window`), and the floor after any increment (`floor_any_update`).
    The stall of [#85](https://github.com/c4milo/colibri/issues/85) is violated with no timeout
    (`queue_stall`) and holds with the server's (`queue_stall_timeout`, 137,068 states): the
    server's send deadline ends it. The client has no deadline, so the stall stays open on its side,
    which #85 rules on.
  - 144 small configurations of one stream under colibri's floor found no stall: the peer's
    window from 2 to 4 units, the floor 2 or 3, its threshold 1 to 3, offers of 1 to 4 units and
    bodies of 4 or 6.
  - 6 mutations of the model, each **CAUGHT** by the new configurations: the floor with no small
    increment, or whatever the peer's window; every increment counted as small; no floor; and the
    server's timeout never enabled, or not fair. The third was **NOT CAUGHT** until `floor` sent a
    body of 7 units rather than 4, long enough for a second round of the window after the floor
    turns on.

  **One `write_body` call writes every frame it can, 2026-10-01**
  ([#91](https://github.com/c4milo/colibri/issues/91)). The deadline trace above found that
  `server.Connection.write_body` wrote one DATA frame per call over h2, though its comment says it
  writes as much as the room and h2's windows allow. h11's call fills the room, and h3's takes
  every octet.
  - Over h2 it now calls `write_data` again while the last frame stopped at the peer's
    SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2), and stops at the windows, the room or the content's
    end. `data_frames_per_write_max` bounds the calls: every frame but the last carries 16,384
    octets at least, and all of them fit the output.
  - A test offers content of two whole frames and an octet, and one call takes it as three
    frames, the last with END_STREAM. Another writes an empty last piece, which goes out as an
    empty DATA frame with END_STREAM.
  - Three tests assumed one frame per call. Two coded responses now fill the output in one call,
    so each test sends before the next stream's head, as a caller must when `respond` returns
    `NoSpaceLeft`. A send-deadline test now offers one frame's octets, as its comment says.
  - The deadline check's census digest changed: in 2 of its 256 seeds the server's output drains
    226 ms and 69 ms later, and the idle deadline that ends each moves with it. The octets sent
    and every other count stay the same, and the Debug and ReleaseSafe builds print the same
    census, so `census_crc32_expected` is now `0x9369abbc`.
  - `zig build test`: 131 of 131 steps and 2538 of 2538 tests passed.
  - 4 mutations, each **CAUGHT**: one frame per call again; each frame offering the content from
    its start; a bound of one frame; and an empty last piece reported as `Blocked`, which was
    **NOT CAUGHT** until the empty-piece test above.

  **The reset limit over h3, 2026-10-04** ([#95](https://github.com/c4milo/colibri/issues/95)).
  The first part of 20c. QUIC's stream limit bounds how many request streams are open at once,
  and nothing bounded how fast a client opens and cancels them.
  - `server.QuicConnection` counts a request stream the client opened and then cancelled, in the
    period its latest instant falls in. A client cancels with a RESET_STREAM, which h3 reports
    even before the request's head is whole, or with a STOP_SENDING that stops its response,
    which the connection sees when it settles each response.
  - A request cancelled with both frames counts once. One the server cancelled or refused does
    not count: the RESET_STREAM a client owes a STOP_SENDING (RFC 9000 §3.5) is no cancel of
    its own.
  - Past `quic_peer_reset_rate_max` in one `quic_peer_reset_rate_period_ns`, which are h2's 100
    and one second, the connection closes with H3_EXCESSIVE_LOAD (RFC 9114 §10.5).
  - The connection grows by 16 octets, to 717,536 (`docs/performance.md`).
  - `zig build test`, on 590b3d8: 131 of 131 steps and 2543 of 2543 tests passed.
  - 8 mutations, each **CAUGHT**: a RESET_STREAM not counted; a STOP_SENDING not counted; a
    request cancelled with both frames counted twice; one cancel past the limit allowed; the
    cancel at the limit refused; the period never starting again; the period starting one
    nanosecond late; and another error code.

  **The first-request, idle and head deadlines over h3, 2026-10-04**
  ([#95](https://github.com/c4milo/colibri/issues/95)). The second part of 20c.
  - `server.QuicConfig` carries `deadlines`, the `Deadlines` a TCP connection takes. A
    connection refuses to start with limits `Deadlines.validate` refuses, and `Endpoint`
    asserts they are valid when it starts: `Endpoint.init` returns no error, and an endpoint
    whose every connection refused to start would answer no client. Whether `init` returns
    `DeadlineInvalid`, as `server.Connection.init` does, changes a public call and is the
    owner's to rule.
  - A connection's deadline is the sooner of QUIC's next timer and its own deadlines, and it
    fires each one that passed at `on_instant` and at `receive`. A program that runs QUIC's
    timers through `server.Endpoint`, with its `deadline_ns` and `on_instant`, runs these with
    no new call.
  - The first-request deadline counts from the client's first datagram until a whole request
    head arrives, so it covers the handshake. The idle deadline counts from the instant no
    request is open, after the first one. Each closes the connection with H3_NO_ERROR (RFC 9114
    §8.1), and `receive` reports no failure. Before the handshake completes, `quic` sends the
    close as RFC 9000 §10.2.3 has it.
  - A request is open from its whole head until its `done` or `cancelled` event. A request
    stream that waits for its head does not stop the idle deadline (decision 110 as amended).
  - h3 keeps the instant it first saw each request stream, and `oldest_head_wait` names the
    stream that has waited longest for its head. A look that finds none is not repeated until
    another request stream opens, so a connection whose heads arrive whole walks its request
    streams once for each stream, and not at each call. Past the head deadline the server asks the
    client to stop sending with H3_NO_ERROR, answers 408 (RFC 9110 §15.5.9, RFC 9114 §4.1), and
    the connection goes on. The caller never hears of the request, and the RESET_STREAM the
    client owes the STOP_SENDING (RFC 9000 §3.5) does not count toward the reset limit. With no
    record free for a response, the server resets the stream with H3_REQUEST_REJECTED (RFC
    9114 §4.1.1).
  - **Not done: the GOAWAY.** Decision 110 has these deadlines close the connection after a
    GOAWAY, and RFC 9114 §5.2 says a server SHOULD send one when it knows of the close in
    advance. `quic` writes a CONNECTION_CLOSE alone once it owes one (RFC 9000 §10.2.1), so a
    GOAWAY written at the deadline's instant is never sent. `shutdown` on a connection with no
    request open has the same fault. The last part of 20c owns both, with the drain deadline.
  - `h3.Connection` grows by 800 octets, 8 for each of its 100 request streams, to 146,312, and
    `server.QuicConnection` by 960, to 718,496 (`docs/performance.md`).
  - `zig build test`, on 590b3d8: 131 of 131 steps and 2555 of 2555 tests passed.
  - 34 mutations. 33 were **CAUGHT**: a deadline passing one nanosecond late; the first-request
    deadline never firing, waiting for the handshake, or not ending at a whole head; the idle
    deadline running before the first request, running with a request open, stopped by a
    partial head, restarting at each call, or never firing; a late head with no response, still
    read, reported to the caller, left open with no record free, cancelled where it must be
    rejected, or answered 400; the caller not woken for a late head or for the idle deadline;
    `deadline_ns`, `on_instant` and `receive` each ignoring the connection's deadlines; the
    deadlines running on a stopped connection; a late head's deadline never firing; the close
    carrying H3_INTERNAL_ERROR or sent as a transport close; and nine in h3, a stream's first
    instant not kept, the newest stream named, a stream whose head arrived still waiting, no
    STOP_SENDING sent, a stopped stream still waiting for its head, a stream that opens asking
    for no look, a look that found none repeated at each call, a look that found a stream not
    repeated, and every call walking the streams.
    The STOP_SENDING carrying H3_REQUEST_REJECTED was **NOT CAUGHT** until the late-head test
    read the code the server's stream holds.

  **The body and send rates over h3, 2026-10-04**
  ([#95](https://github.com/c4milo/colibri/issues/95)). The third part of 20c.
  - A request's body waits from the call that reads its head until its content or its stream
    ends (`quic_body.zig`). Each body keeps the minimum rate over each window and ends within
    the cap, and the bodies of a connection keep the rate together. Only the data of DATA
    frames counts.
  - A body that falls short ends its request alone. With no final response begun, the request
    gets a 408 and the server asks the client to stop with H3_NO_ERROR. With one begun, the
    server resets the stream with H3_REQUEST_CANCELLED. With one ended, the server asks the
    client to stop and the response arrives whole. The caller reads `cancelled`, naming the
    deadline, unless the response had ended. Bodies that together fall short close the
    connection with H3_EXCESSIVE_LOAD.
  - A connection refuses to start with a body rate `Deadlines.validate_units` refuses, and
    `Endpoint` asserts its configuration holds none.
  - The send meters count the octets the peer acknowledged (`quic_sends.zig`). The connection
    reads them from each response's stream when it settles its requests, after each datagram.
    A response is busy while it holds octets its stream's credit covers and the peer has not
    acknowledged, its FIN among them. It is bound while it holds octets the credit does not
    cover.
  - While any response is busy, the peer acknowledges the minimum send rate across the
    responses, or the connection closes with H3_EXCESSIVE_LOAD. That ends a peer that
    acknowledges too little and one that withholds the connection's credit.
  - A bound response has a meter of its own, which runs while no other response is busy. Under
    the rate, the server resets its stream with H3_REQUEST_CANCELLED and the caller reads
    `cancelled`. The meter keeps its window while the stream's own credit grows.
  - A connection fires the deadlines that passed before it takes a datagram, as it does at
    `receive` and at `on_instant`, so octets acknowledged after a window's end count in the
    next window.
  - Not done: the QUIC server owes no 100 (Continue) of its own (RFC 9110 §10.1.1), so a
    body's wait starts at its head. Over TCP it starts once the 100 is written.
  - `server.QuicConnection` grows by 2,632 octets, to 721,128 (`docs/performance.md`).
  - `zig build test`, with the three parts replayed on ecd57e1: 131 of 131 steps and 2592 of
    2592 tests passed.
  - `tools/quic_udp.sh`, `tools/h3spec.sh` and `tools/quic_aioquic.sh`, on macOS arm64 before
    the replay: each passed with the default deadlines on.
  - 32 mutations of the body deadlines. 29 were **CAUGHT**: a wait never starting; content not
    counted for a body or for the bodies together; the bodies never judged; the cap not kept,
    or one nanosecond late; a body's own rate not judged; the wait not ended by the content's
    end, a reset, the caller's cancel, a refusal, or the end of a request the caller hears of
    no more; a reset in place of the 408; a response that ended reset, or one acknowledged
    cancelled; either STOP_SENDING carrying H3_REQUEST_CANCELLED; the server reading on after
    a 408; no `cancelled` event, or a `done` after it; a coded response keeping its encoder; a
    rate under the unit bound accepted; the caller not woken; no deadline fired; the bodies'
    meter never starting, or running on after the last body; another close code; the cap not
    reported; and the deadline that closed the connection not kept.
    Three were **NOT CAUGHT** until tests were added: a trailer section that arrives before
    its stream's end not ending the wait, and a body's window and the bodies' window each not
    reported to the caller's loop, which the first tests hid because both fell at one instant.
    A 33rd found a line with no effect, which is gone.
  - 24 mutations of the send rate. 23 were **CAUGHT**: acknowledged octets not counted for the
    connection, or for the stream; a response never busy, or never bound; a stream's own octets
    stopping its meter; a stream's meter running while another response is busy; the
    connection's meter, or a stream's, never judged; another reset code; no `cancelled` event;
    the caller not woken; no deadline fired; the meters never started; the server never looking
    at a response; a record keeping the last response's count; a datagram taken with no window
    judged before it counts; a stream's window, or the connection's, not reported; meters that
    ran not stopped; a FIN alone not making a response busy; octets past the stream's credit
    making one busy; a stream a send deadline ends still waiting for its body; and another
    close code.
    A reset stream keeping its state was **NOT CAUGHT** until the cancel test kept the stream
    open.
  - The mutations of the three parts ran on 590b3d8. The replay on ecd57e1 moved the calls the
    endpoint makes into `quic_connection_internal.zig` and changed no rule.

  **The calls of the fourth part, 2026-10-04** ([#95](https://github.com/c4milo/colibri/issues/95)).
  - `QuicConnection.set_deadlines` replaces one connection's limits, and refuses what a
    connection refuses at its start. `QuicConnection.close_reason` names the deadline that
    closed a connection, or `Limit.peer_resets` for the reset limit, and is null after any other
    end. Both are on the list in the test of `quic_connection.zig` (decision 115).
  - `examples/h3_exchange.zig` sets `QuicConfig.deadlines`, shortens one connection's idle
    deadline with `set_deadlines`, and reads `close_reason` from each connection `ended` hands
    back. docs/usage.md quotes each, and no longer says that nothing bounds a slow h3 peer.
  - Decision 110's amendment records the owner's rulings of 2026-10-04: a GOAWAY before a
    close, an error from `Endpoint.init`, and the body and send rates over QUIC as built. The
    first two are not built yet.
  - `zig build test`, on 93ced64: 131 of 131 steps and 2593 of 2593 tests passed, and `zig build
    examples` ran all four.
  - 7 mutations, each **CAUGHT**: `set_deadlines` keeping the old limits, taking a limit of 0,
    or taking a rate under the unit bound; `close_reason` naming no deadline, or no limit; the
    reset limit not kept as the reason; and a public function added and not listed.

  **A GOAWAY before the close, and the drain deadline, 2026-10-04**
  ([#95](https://github.com/c4milo/colibri/issues/95)). The owner's ruling, in decision 110 as
  amended.
  - At its first-request or idle deadline a connection whose h3 runs sends a GOAWAY and takes
    no new request. It closes with H3_NO_ERROR once its requests are over and the client has
    acknowledged the GOAWAY. h3's `goaway_acknowledged` says whether the client acknowledged
    every octet of the control stream. `server` calls it, so it is a method of
    `h3.Connection`, the sixteenth on the list in its test (decision 115).
  - `shutdown` ends a connection the same way, so a shutdown with no request open now sends
    its GOAWAY before it closes.
  - The drain runs from the first call that sees the connection shutting down. When it passes,
    the connection closes with the requests it still holds. `close_reason` names the deadline
    that began the shutdown, or `drain` after the program's own `shutdown`. With `drain_ns`
    null nothing of colibri's bounds the wait for the acknowledgment, and the comment on
    `Deadlines.drain_ns` says so.
  - A connection that is shutting down runs no first-request and no idle deadline. One whose
    h3 never started has no stream to send a GOAWAY on, and closes at once (RFC 9000 §10.2.3).
  - `server.QuicConnection` grows by 16 octets, to 721,400 (`docs/performance.md`).
  - `zig build test`, on 93ced64: 131 of 131 steps and 2600 of 2600 tests passed.
  - `tools/quic_udp.sh`, `tools/h3spec.sh`, `tools/quic_aioquic.sh` and
    `tools/channel_interop.sh`, on macOS arm64: each passed.
  - 12 mutations, each **CAUGHT**: the close not waiting for the GOAWAY's acknowledgment; a
    deadline closing at once with no GOAWAY; the drain never firing, not reported, starting
    again at each call, or never starting; a drain a deadline began reported as the reason;
    the idle deadline firing again on a connection shutting down; a connection whose h3 never
    started waiting for a GOAWAY; a shutdown sending no GOAWAY; and in h3, a GOAWAY that
    never went out read as acknowledged, and one read as acknowledged before the peer
    acknowledged it.

  **The h3 deadlines over real sockets, 2026-10-04**
  ([#95](https://github.com/c4milo/colibri/issues/95)).
  - `tools/h3_deadlines.sh` runs the test-only h3 server on its loop's clock, and four aioquic
    peers at the default limits (`tools/quic_interop/slow_peer.py`). The server must end each
    within a second after its instant, and not before it. `tools/ci.sh` runs it after
    `tools/deadlines.sh`.
  - What it printed on macOS arm64, with a load average over 100:
    - a peer that sends a PING every second and no request: a GOAWAY, then H3_NO_ERROR, after
      10.21 s;
    - half a request's head, after one whole fetch: 408 after 10.01 s, and the connection
      served a later fetch;
    - a head and three octets of content: 408 after 20.02 s;
    - a peer that acknowledges nothing of a response: H3_EXCESSIVE_LOAD after 20.02 s.
  - aioquic reports a close only when its draining period ends, three PTOs after the close
    arrived, and a peer whose datagrams are dropped has a PTO that has grown past a second. So
    the peer reads the close from aioquic's `_close_event`, at the datagram that carried it.
  - 5 mutations of the server, each **CAUGHT** by the peer that covers it: the first-request
    deadline never firing; the close not waiting for the GOAWAY's acknowledgment, which the
    silent peer reports as a close with no GOAWAY before it; a late head never answered; a
    body's rate not judged; and the connection's send meter not judged.

  **A body's wait and the 100 (Continue), 2026-10-04**
  ([#95](https://github.com/c4milo/colibri/issues/95)). The owner ruled on 2026-10-04 that h3
  adds no code for it.
  - Over TCP a body's wait starts once the 100 (Continue) its request is owed is written. Over
    h3 it starts at the request's head, also when a 100 is owed (decision 116, step 17i).
  - The connection writes the 100 at its next call after the head, before the next datagram it
    sends, so the two instants are most often one.
  - The wait starts before the 100 in two cases. The caller filled the response's 16 runs with
    interim responses before its next call, so the 100 waits for the client to acknowledge one.
    Or the caller made its next call late. The grace period covers both while the caller's
    loop keeps turning.

  **A request whose head is unread at a shutdown, 2026-10-04**
  ([#95](https://github.com/c4milo/colibri/issues/95)). The h3 deadline check, below, found it.
  - A connection that shut down while a request stream still waited for its head closed with
    nothing said of that request. The GOAWAY names the first stream the server has not seen,
    so that stream was below it, and its client could not tell whether the server took the
    request.
  - When the server sends the GOAWAY, at a deadline or at `shutdown`, it now resets each such
    stream with H3_REQUEST_REJECTED (RFC 9114 §4.1.1), and the client may send the request
    again (decision 110 as amended). The owner has not ruled on it.
  - A connection answers each head that is late before its own deadline shuts it down. So a
    head that is late at that instant gets its 408, and only a head that is not late is
    rejected.
  - `zig build test-server`, on ae1f066 with the commits before this one: 298 of 298 tests
    passed.
  - 5 mutations, each **CAUGHT**: no stream rejected; H3_REQUEST_CANCELLED in place of
    H3_REQUEST_REJECTED; the connection's deadline fired before a late head is answered; the
    oldest unread head rejected alone; and a stream asked to stop but not reset.

  **The h3 deadline check, 2026-10-04** ([#95](https://github.com/c4milo/colibri/issues/95)).
  - `zig build sim -- --h3-deadline-check [seeds]` runs each seed's plan between a server
    `Endpoint` and a scripted client over QUIC in simulated time, through the calls a program
    makes. `--h3-deadline-seed <hex>` prints one seed's trace. Each seed runs twice and must
    write one trace. `zig build test` runs 256 seeds and pins the CRC-32 of their traces, and
    `tools/ci.sh` runs them in Debug and in ReleaseSafe and compares the two.
  - A plan draws one of eighteen peers, decision 110's default limits or stricter ones in one
    plan of four, and how long the application holds each request before it answers, up to
    25 s. The application writes half of its answers to honest peers in two halves, up to 25 s
    apart.
  - Five peers are honest, and each must read every response whole:
    - one that makes up to three exchanges at once;
    - one whose request heads arrive in two parts, up to 2 s apart;
    - one that uploads content at two to four times the minimum body rate;
    - one that reads long responses at two to four times the minimum send rate, from streams
      whose credit starts at 8,192 octets;
    - one behind a link that carries four to eight times the minimum send rate and drops the
      datagrams its queue of eight cannot hold. Its responses stay unacknowledged for whole
      windows, so the connection's send meter judges it at each one.
  - Thirteen are slow or flooding, and the server must end each at the instant decision 110
    names:
    - a peer that sends nothing after the handshake, and one that sends only PINGs: a GOAWAY
      at the first-request deadline;
    - a peer that sends only PINGs after one exchange: a GOAWAY at the idle deadline, counted
      from the instant the server reported the response done;
    - a head short of its last octet, the connection's first or one after an exchange: a 408
      at the head deadline, or a reset with H3_REQUEST_REJECTED when the connection's own
      deadline comes first. The connection ends at its own deadline either way;
    - a body under the rate: a 408 at the end of its first window. A body that keeps the rate
      for longer than the cap: a 408 at the cap. The application reads `cancelled` for each,
      naming the deadline;
    - a long response to a peer that reads none of it, or reads far under the rate: a reset
      with H3_REQUEST_CANCELLED at the end of the first window, and `cancelled`;
    - a peer that acknowledges nothing, one that holds an open response with its connection's
      credit, two bodies that bring nothing, and a peer that cancels requests past the reset
      limit: a close with H3_EXCESSIVE_LOAD, whose `close_reason` names the deadline or the
      limit. The flood is closed with the batch that carries its 101st cancelled request.
  - A connection that ended one request runs on to its idle deadline, counted from that end.
  - The peer must read each GOAWAY at the deadline's instant, and the close must follow with
    H3_NO_ERROR within the 25 ms the peer takes to acknowledge the GOAWAY. A slow link adds the
    time it takes to carry a datagram to each.
  - What it printed on macOS arm64, in Debug and in ReleaseSafe: `h3-deadline: seeds=256
    exchanges=129 first_request=34 idle=151 body_rate=15 send_rate=38 peer_resets=18
    requests_cut=78 trace_octets=116332 crc32=0xd51694dc`.
  - The slow link dropped 13 to 19 datagrams in each of its 13 seeds, and the server cut none
    of them.
  - The check found one fault in the server: the request whose head is unread at a shutdown,
    above.
  - Not covered: the application answers only after a request's content has ended, so a
    body's deadline always finds no response begun. The unit tests cover the reset of a
    response that began and the response that ended.
  - `zig build test`, on faa6575 with the commits of the fourth part: 131 of 131 steps and
    2644 of 2644 tests passed.
  - 31 mutations of the server, each **CAUGHT**:
    - a deadline passing one nanosecond late; the first-request deadline never closing a
      connection; the idle deadline running with a request open, or stopped by an unfinished
      head;
    - a late head never answered, its deadline counted from the connection's start, or the
      caller not woken for it;
    - the close not waiting for the GOAWAY's acknowledgment, or never reading it as
      acknowledged; a shutdown keeping no deadline as its reason;
    - a body's wait never starting, or going on after its content ended; its octets not
      counted; its own window, or the bodies' together, never judged; the cap one nanosecond
      late, or reported as the rate; a late body's request reset in place of its 408; the
      caller not told of it;
    - the connection's send meter, or a stream's, counting nothing; the connection's meter
      never judged; a stream its credit holds never reset; a response its connection's credit
      holds not waiting on its peer; a response whose end is not written waiting on its peer;
    - the reset limit never closing the connection, letting one more cancelled request
      through, or keeping no reason;
    - no unread head rejected at a shutdown, another code for it, and the connection's
      deadline fired before a late head is answered.
  - One of them was **NOT CAUGHT** at first, by the check and by the unit tests: a response
    its connection's credit holds not waiting on its peer. Every answer ended as it was
    written, and the unacknowledged end alone kept the response waiting. `quic_sends_test.zig`
    has the test now, and the check's application leaves that peer's answer open.
  - Three parts of the check came from reading the mutations before running them. No honest
    peer kept the connection's send meter running for a whole window, so one is behind the
    slow link. A flood in batches of four could not find the limit's last request, so a plan
    draws the batch, and a batch of one finds it. And the peer says when it read the GOAWAY,
    where the run first read the server's clock.
  - The mutations ran in copies of this tree with `zig build sim -- --h3-deadline-check`. One
    is caught when the command fails or prints another CRC, which is what the module's test
    compares.

  **The h3 deadline model, 2026-10-08.** The first part of 20d. `spec/tla/h3_deadlines` models
  one `server.QuicConnection`, an honest client and the application, with QUIC's credit and
  congestion window. Its header says what it leaves out.
  - `zig build tla -- spec/tla/h3_deadlines/*.cfg`, on macOS arm64: the fourteen configurations
    give their verdicts in two to three and a half minutes. colibri's rules hold GoawayBeforeClose,
    RejectedUnprocessed and OnlyChosenCounted over 3,304,818 states with two streams and over
    372,018 with bodies and the client's cancels, and SendWaitsOnPeer over 370,167.
  - Each earlier rule, and each rule turned off, is violated: a shutdown that leaves an unread
    head unanswered, as before 4b4749c (NothingUnsaid); a close that does not wait for the
    GOAWAY's acknowledgment, as before 76545f7 (GoawayBeforeClose); and a reset on a stream
    colibri abandoned counted toward the limit (OnlyChosenCounted).
  - Two findings, each kept as configurations TLC must find violated until it is ruled on:
    - `rejection_lost`: colibri closes once the client acknowledged the GOAWAY, while the
      rejection of a request whose head it had not read is still owed. Once a close is owed,
      colibri's QUIC sends nothing else, so the client never learns that it may send that
      request again. One datagram most often carries the GOAWAY and the rejections together,
      and a datagram that fills, or a lost packet, splits them. With the close also waiting
      for the client's acknowledgment of every RESET_STREAM colibri sent, NothingUnsaid holds
      (`close_after_resets` over 3,125,954 states, and `close_after_resets_cancels`).
    - `credit_held_body`, `credit_held_head` and `credit_held_idle`: a body's clock, a head's
      and the idle clock run while the credit the client needs waits in colibri behind its
      congestion window, which the client's next acknowledgment frees. It is the QUIC form of
      what `spec/tla/server_deadlines` found for h2
      ([#89](https://github.com/c4milo/colibri/issues/89)). With the head, body and idle clocks
      waiting while colibri holds credit, every rule-2 invariant holds (`pause_for_credit`, and
      `pause_for_credit_three` over 2,183,812 states with three streams).
  - The first runs let colibri's packets reach the client in any order: 80 million states in
    ten minutes, and still growing. In order, with the close free to pass every packet sent
    before it, each scope finishes in seconds and keeps every case the invariants need.
  - Three counterexamples were the model's own, and are fixed. A credit packet carried one
    limit, so the connection's credit took the window from the stream's, where colibri writes
    every limit in one packet. And the head and idle invariants judged a head already on its
    way to colibri.
  - Each invariant constrains states the model reaches. A module that extends the model named
    one such state for each, and TLC reached every one. An idle client whose next request
    needs held connection credit is reached only with three streams, which `credit_held_idle`
    runs.
  - Next: the simulator's h3 deadline run written as traces of the model, the second part of
    20d.

  **The close waits for every reset, 2026-10-08.** Decision 110's seventh amendment, the owner's
  ruling on `rejection_lost`.
  - `finish_if_drained` also waits until no stream of the connection is in "Reset Sent", which
    `quic.connection_stream_acknowledged.resets_acknowledged` answers from QUIC's stream table.
    It is a new public name of `quic`, and the server calls it.
  - The model now parts a datagram's arrival from h3's read of it, as colibri does: `take` hands
    the datagram to QUIC, and h3 reads it at the caller's next `receive`. `settle`, which
    decides the close, runs at both. A server test first found a close coming before h3 read a
    request stream the closing datagram opened, and TLC finds it harmless: that stream is at or
    above the GOAWAY's identifier, which tells the client the server did not take it.
  - `zig build tla -- spec/tla/h3_deadlines/*.cfg`: the twelve configurations give their
    verdicts in 3 minutes 37 seconds. colibri's rules hold NothingUnsaid with the other three
    over 8,133,722 states with two streams, and over 774,510 with bodies and the client's
    cancels. `rejection_lost` keeps the rule before this change, violated.
  - A test splits the rejection from the GOAWAY with datagrams of 36 octets and loses the one
    that carries the rejection (`quic_drain_test.zig`). The events the harness keeps moved to
    `quic_seen_test_support.zig`, which leaves room for the two settings the test needs.
  - 3 mutations, each **CAUGHT**: the close not waiting for the resets, by the drain test; and a
    reset read as waiting only once acknowledged, and every reset read as acknowledged, by
    `zig build test-quic` and the drain test.
  - `zig build test`: 131 of 131 steps and 2646 of 2646 tests passed, the h3 deadline check's
    census unchanged.

  **The clocks wait for held credit, 2026-10-09.** Decision 110's seventh amendment, the owner's
  ruling on `credit_held_body`, `credit_held_head` and `credit_held_idle`.
  - colibri holds credit while QUIC owes a MAX_DATA, MAX_STREAMS or MAX_STREAM_DATA frame it has
    not sent: a new limit worth a frame, or one lost and owed again.
    `quic.connection_flow.credit_owed` answers it, and `flow.Receiver.owes_credit` is the test
    `credit_frame_limit` already made. The server calls it at each `take`, `receive` and
    `on_instant`, and after a `send` while credit is held, so the hold ends at the send that
    carries the credit.
  - While credit is held, the body meters stop and the head and idle deadlines do not run. Once
    the credit is out, the meters start again with a grace period, as h2's do, and the head and
    idle deadlines move by the time it was held: one that began during the hold starts at its
    end. h3 moves the instants of the heads it waits for, through `h3.Connection`'s new
    `delay_head_waits`. Both new public names are the server's. The body cap and the
    first-request deadline run on, as the ruling names neither.
  - `server.QuicConnection` grows by 16 octets, to 721,416, for the instant the hold began
    (`docs/performance.md`).
  - `zig build tla -- spec/tla/h3_deadlines/*.cfg`: the eleven configurations give their
    verdicts in 2 minutes 55 seconds. colibri's rules hold every rule-2 invariant over 754,135
    states with two streams (`colibri_flow`) and over 4,789,077 with three
    (`colibri_flow_three`). The three `credit_held_*` configurations keep the clocks before this
    change, violated.
  - Four tests hold the credit by leaving the server's congestion window no room
    (`quic_deadline_credit_test.zig`): a head whose deadline moves, an idle deadline that moves,
    one that starts once the credit is out, and a body whose meters start again.
  - Mutations, by `zig build test-quic`, `test-h3` and `test-server`:
    - 9 of the credit query, each **CAUGHT**: each limit, fresh or lost, not counted; a stream
      past "Recv" counted; the fraction off by one; and a limit that does not rise offered.
    - 15 of the server and of h3, each **CAUGHT**: the credit never observed, or not at a send;
      a wait moved wrongly whether it began before the hold or inside it; the idle or head
      instants not moved; the idle or head deadline reported or fired during a hold; either
      meter running during a hold; the hold restarted at each call; and the first-request
      deadline not reported.
    - 3 **NOT CAUGHT**, which change no behaviour: two skip a fast path, and one moves the
      instant of a request whose head arrived, which nothing reads again.
  - `zig build test`: 131 of 131 steps and 2652 of 2652 tests passed, the h3 deadline check's
    census unchanged.

  **The h3 deadline trace check, 2026-10-09.** The second part of 20d, which logs only what maps
  one to one, at the owner's ruling.
  - `zig build sim -- --h3-deadline-trace-check`, on macOS arm64: `seeds=32 states=418 opened=61
    responses=24 timeouts=2 rejected=26 cancelled=0 drained=21 drain_passed=11`. Each seed runs
    twice and goes through the same states.
  - `tools/h3_deadline_trace.sh`: 32 of 32 traces are behaviors of the model, in 96 seconds of
    TLC. The largest seed takes 2,744,823 states.
  - What the first runs found was the run's mapping, not colibri:
    - h3 forgets a request stream in the call that reads its end, so the run takes a request's
      end from the server's events;
    - colibri frees its records when the connection stops, so the trace compares `bodyWaits`
      only while the connection is open;
    - with nothing of colibri's due, a wait reached QUIC's own idle timeout, so one wait moves
      time 30 seconds at most.
  - Matching only states where the model's colibri has no step left cut one seed from 5,781,839
    states to 513,029.
  - Clients and applications that stop short are what make deadlines pass: before them, 256
    seeds reached 4 timeouts and 4 drains, and after them 18 and 88.
  - 6 mutations of colibri, each **CAUGHT** by `tools/h3_deadline_trace.sh`. TLC finds a trace
    the model cannot reach for a shutdown that leaves unread heads unrejected (10 seeds), a close
    that does not wait for the GOAWAY's acknowledgment (8), an idle clock that runs while a
    request is open (20), and a late head rejected rather than answered with a 408 (1). The run
    fails before TLC for a drain that never starts, whose client never reads the close, and an
    assertion in colibri for a body's wait that goes on after its content ended.
  - `zig build test`: 131 of 131 steps and 2654 of 2654 tests passed, the trace run's test among
    them.

- **Step 21 — one HTTP API.** [Decision 117](decisions.md) has a program that uses `server` and
  `client` name no HTTP version outside `versions`, and serve every connection through one
  endpoint ([#96](https://github.com/c4milo/colibri/issues/96)). Six parts. Each starts with the
  tests that list its public names, beside each type it changes and beside each root (CLAUDE.md,
  "The public API is written first").
  - **21a, the configuration.** `versions` and `limits`, and cleartext detected.
    - `server.Versions` and `client.Versions`: `h11`, `h2` and `h3`, each true by default.
      `server.Config.versions` and `client.Config.versions` replace `cleartext`.
    - A server connection in cleartext reads its first octets before it chooses a version: the
      24 octets of the connection preface (RFC 9113 §3.3) choose h2, and any other octets h11,
      among the versions `versions` allows. It consumes nothing until it has chosen. A client in
      cleartext speaks h11 when `versions.h11` is set, and h2 with prior knowledge when it is not.
    - `server.Limits` holds `requests_max`, the requests a connection holds at once, which was
      `h2_streams_max`, and `data_frame_len_min`, which leaves the configuration's top level.
      `server.Config.limits` holds them. From 21b, `requests_max` bounds an h3 connection's
      requests too, up to the `quic_requests_max` its table holds.
    - #96 put one TLS value in this part. It comes with 21b, because the endpoint builds both TLS
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
      speaks both read octets that are not the preface as h11. Tests show the preface choosing
      h2, other first octets choosing h11, a partial preface waiting for more, and each version
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
      `Event` gains `writable`, `send` (a TCP connection owes octets), `close` (close its
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
        8 octets starts no connection. Today a 0-octet one reaches an assertion (INV-24).
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
  - **21c, the client.** One TLS value, with the ALPN lists filled in. The channel draws its
    QUIC connection IDs and h3's grease value from the source `start_quic` is given, so
    `QuicStart` leaves the API. The test-only clients use channels with TCP alone in place of
    `client.Connection`. **Check:** `tools/channel_interop.sh` and the h11 and h2 client interop
    scripts pass through the channel.
  - **21d, the roots.** They stop exporting `server.Connection`, `server.QuicConnection`,
    `client.Connection` and `client.QuicConnection`. One server example and one client example
    replace the four, and the guide follows them. **Check:** `zig build examples`,
    `tools/doc_snippets.sh` and `tools/consumer_check.sh` pass, and no root's list holds a
    connection type.
  - **21e, the router.** `server.routes`, a table of methods and paths the program declares at
    compile time, matched through a trie of path segments as #96 describes. **Check:** tests for
    literal segments, captures, a trailing wildcard, precedence whatever the table's order, 404,
    405 with its Allow list, and a path with an encoded octet, a dot segment or an empty segment
    matching nothing. Each malformed or conflicting table fails to compile. An example routes
    with it. Each rule has a mutation a test catches.
  - **21f, the package.** Whether `h11`, `h2`, `h3` and `quic` stay exported (decision 86).
    **Check:** the owner's ruling, once the dependent that uses `h11` directly can use `client`.

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
    first octets was lost: the connection now ends at once, as an idle h11 connection does, and
    a shutdown asked for during a TLS handshake, lost the same way before this step, now reaches
    the protocol the handshake opens. A drain that passed before any protocol served a
    connection stopped it without closing it: it now closes.
  - 21 mutations, each **CAUGHT**:
    - the whole preface choosing h11; a four-octet prefix choosing h2; a differing octet
      choosing nothing; the octets that chose not read;
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
    shorter than 8 octets reached an assertion (INV-24). A poll that read an event moved its
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
    - 21b.1: no length check; an 8-octet ID refused; a 7-octet one taken, which the test first
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
    a build before 21b.1 can name a first Destination Connection ID under 8 octets. Under a key
    shared across an upgrade, the Initial that returned it reached `start`'s assertion (INV-24).
    `start` now checks the ID's length on every path. Mutations: no check at `start`, and a
    check that refuses an empty ID alone, each **CAUGHT**.
  - One mutant was equivalent: `ended` reported with requests still open. A connection always
    stops before it ends, and a stopped one gives each open request its `cancelled` first, so the
    condition became INV-30's assertion.

Steps 0 to 6 are h2 and deliver a shippable library. Steps 7 to 12 are h3, and step 13 benchmarks
both. Steps 14 and 15 are h11: the decoder package first, because h11 imports it. Step 6 exists
where it does on purpose: the cheap regression check is in place before the larger half begins.
Step 16 moves chapulin, which the checks from step 5 on linked in `src/testing/`, into the
library.

## 9. Test-only entry points

Five, and they are not interchangeable. Each lives in `src/testing/`, is excluded from the
packaged library, does its I/O without blocking ([decisions 46 and 58](decisions.md)), and is the
only place in the tree permitted to touch a socket
([invariant 2](invariants.md#inv-2--colibri-performs-no-io) is scoped to `src/` outside it).

1. **A server**, `http-server`, answering `GET /` and `POST /` with 200 and a non-empty body,
   and CONNECT with 501, since it opens no tunnel (decision 109), in both cleartext and TLS
   modes, and **a client**, `http-client`, that runs a plan of
   exchanges against another implementation's server and reports how each ended. For h2spec,
   h2load and `tools/h2_interop.sh`. They landed as `h2-server` and `h2-client` with step 4
   (cleartext) and step 5 (TLS), and the owner renamed them on 2026-09-25, when step 15d gave
   them h11 as well. In cleartext the client speaks h2 with prior knowledge, or h11 with `--h11`.
   The server in cleartext names no version and speaks h2 when a connection's first octets are
   h2's preface and h11 otherwise (decision 117, step 21a), or one alone with `--h11` or `--h2`.
   Over TLS, both offer `h2` and then `http/1.1` through ALPN, or one alone with `--h11` and, for
   the server, `--h2`, and each connection speaks what the handshake selected: h2 for `h2`, and h11
   for `http/1.1` or for no selection (decision 88). With `--channel` and `--tls` the client hands
   its plan to one `client.Channel` instead, which tries h3 over QUIC first and falls back to TCP
   (step 17d), and `tools/channel_interop.sh` runs it.
2. **A QUIC and h3 server** with ALPN `h3` and a self-signed certificate. For h3spec and
   `h2load --h3`. Lands with step 12. From step 17b it runs on `server`: the UDP endpoint's `h3`
   mode serves h3 alone through `server.Endpoint`, and h3spec, `h2load --h3` and the interop
   endpoint's `http3` server run it. It writes no qlog, because `server` takes no log yet.
3. **An interop endpoint**, both roles: a server on port 443 serving `/www` with `/certs`, and a
   client that parses `REQUESTS` and writes to `/downloads`, reading `ROLE` and `TESTCASE`,
   emitting a keylog and qlog, and **exiting 127 for any case it does not support**. It must speak
   HTTP/0.9 over ALPN `hq-interop` as well as h3, because most of the matrix's transfers use it.
   Lands with step 9.
4. **A `perf` ALPN endpoint** for `secnetperf`, which measures the transport and not HTTP. Lands
   with step 13.
5. **Two QPACK command-line tools**, `.qif` to encoded and back, to take part in the QIF interop.
   Lands with step 11.

The HPACK and frame vectors need none of these; they are in-process unit tests.

Each server among them takes the port its caller names. With port 0 it takes the one the kernel
chooses, and it prints `listening on port <port>` once its socket is bound. The check scripts
start every peer that way and read the port from that line, so no check binds a fixed port, and
two runs on one machine do not collide ([decision 114](decisions.md),
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
function** — appending a 16-octet tag, and masking byte 0 and the packet number from a 16-octet
sample, exactly as a real suite would — because RFC 9001 §5.3's expansion feeds §5.4.2's sample
offset, the packet's Length varint, RFC
9000 §14.1's 1200-octet minimum and the anti-amplification count of
[invariant 18](invariants.md#inv-18--the-anti-amplification-limit-holds). A suite that shortened
packets would simulate a protocol QUIC does not have.

The simulator is written before the protocol it drives. For QUIC that ordering is the whole
difficulty, and steps 2 and 8 are where it is paid for.

## 11. Performance

### 11.1 The workload

Many short connections, small requests, high connection churn — one connection per agent process,
a little work, then gone. Handshake cost and per-connection memory dominate; single-stream bulk
throughput does not. [Decision 31](decisions.md#performance) states where colibri expects to win,
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
quiche and quic-go for h3. h2o and nginx as the h2 server bar. aioquic is a correctness reference
and not a performance target.

### 11.4 Method

[Decision 33](decisions.md#performance) fixes it before the first measurement so the numbers
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
[Decision 47](decisions.md) runs the cheap layer on each push to main and prints an h2load figure
beside it, which is indicative and carries no threshold: the push job's x86-64 runner counts no
instructions and draws a different CPU from run to run.

## 12. Open questions for the owner

1. **QUIC as a module or its own repository** ([decision 3](decisions.md#scope-and-shape)).
   Ruled 2026-09-16: a module with a mechanically enforced boundary, which step 0 built and proved.
2. **The packet-protection vtable** ([decision 9](decisions.md#what-the-caller-supplies)). Ruled
   2026-09-16: two vtables, `tls.Provider` and `crypto.Suite`. Ruled again 2026-09-19
   ([decision 48](decisions.md#what-the-caller-supplies)): the two vtables stay, the suite holds
   every key, and its members seal and open whole packets. Step 7 builds against that.
3. **The ask to chapulin** ([decision 10](decisions.md#what-the-caller-supplies)). Ruled 2026-09-16:
   chapulin provides all of colibri's crypto by filling both vtables, and `src/testing/` links it.
   The request is [docs/chapulin.md](chapulin.md), and sending it is the owner's.
4. **RFC 9002's one internal disagreement**, which step 10 must settle in writing and pin with a
   test. Its §5.3 updates `smoothed_rtt` first and then computes `rttvar` against the new value,
   while its Appendix A.7 computes `rttvar` first against the old value. These produce different
   numbers on every sample. It is not a bug in the RFC; it is a place where an implementation must
   choose, and interop will show which choice the field made.

   **Ruled 2026-09-20: Appendix A.7** ([decision 50](decisions.md#the-h2-connection)). §5.3's new
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

   **Ruled 2026-09-20: share through `http`** ([decision 51](decisions.md)). The shared checks
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
     what [decision 15](decisions.md) already says the split is — "`http` returns reasons and
     this file names h2's errors" — so this is finishing that split rather than changing it. The
     cost is a refactor of working, fuzzed h2 code, and the risk is that a rule that looked
     shared turns out to differ in a way the reasons cannot carry.

   It is the owner's because it moves tested h2 code for h3's benefit, which is the one direction
   CLAUDE.md's rule about taking a decision for another module's sake is meant to catch.

## 13. Risks

- **Step 9.** QUIC transport is the largest single body of work and every later
  step depends on it. The mitigation is that steps 0 to 6 deliver a complete, shippable h2 library
  first, so a QUIC schedule overrun costs h3 and nothing else. It was cut into 9a to 9e on
  2026-09-19 (§12 question 5), which makes the overrun visible part by part rather than at the
  end, and leaves only 9e waiting on chapulin.
- **The conformance suites are older than the RFCs they test.** h2spec is written against RFC 7540
  and 7541 and last released in 2020. A disagreement is checked against RFC 9113 before it is
  treated as colibri's bug, and the version is pinned so the answer does not move.
- **The QPACK vectors are stale.** `qpackers/qifs` targets draft-05 and has not moved since 2021.
  RFC 9204 Appendix B is the authority where they disagree.
- **CI runs what a hosted runner can.** [Decision 47](decisions.md) runs the checks on each push
  to main and leaves a report, runs the module tests on Linux and macOS arm64 too, and runs the
  HTTP Garden and the QUIC Interop Runner every Monday.
  What needs a machine it does not have — the published numbers of §11 — is still run by a
  person, and the step's entry in §8 records what was run, on what, and what it printed.
- **Every check that needs crypto waits on chapulin.**
  [Decision 10](decisions.md#what-the-caller-supplies) has chapulin fill both vtables, and what
  chapulin must add first reverses five of its recorded decisions: a server role with constant-time
  signing, a non-blocking handshake with no global state, a QUIC mode and host-side AES
  ([docs/chapulin.md](chapulin.md)). That work runs on chapulin's schedule, not colibri's. Step 5's
  h2spec TLS mode and interop, step 7's RFC 9001 Appendix A vectors, and the interop endpoint,
  h3spec and `secnetperf` of steps 9, 10, 12 and 13 all wait for it. The mitigation is the order of
  the plan: steps 0 to 4, 6, 8 and 11 need no crypto, and step 4's cleartext h2 is a working library
  with no TLS. colibri still cannot ship a working client on its own, and a consumer with no TLS
  stack still has no h2-over-TLS.
- **The development machine is not the measurement machine.** Every real number needs Linux.
  A macOS-only development loop can hide a regression that only a kernel mechanism would show.
