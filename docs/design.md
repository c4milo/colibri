# colibri — HTTP/2 and HTTP/3 Design Document

Status: v1 (design, pre-implementation). Owner: Camilo. Scope: the library, both protocols, both
roles. Sibling to [decisions.md](decisions.md) and [invariants.md](invariants.md); decisions there
are taken as given and cited, not relitigated.

Every section is cited by number in commits and comments ("§8 step 4").

---

## 1. Thesis and scope

colibri is an HTTP/2 and HTTP/3 library, client and server, written from the RFCs. It owns no
I/O, no crypto and no clock: bytes, keys and time all arrive from the caller. What it owns is the
part that is hard to get right and easy to get wrong — framing, field compression, stream state,
flow control, loss recovery — and it owns it under static allocation, bounded loops and assertions
that stay on in production.

The narrowness is the point. A library that owns no sockets can be driven by a deterministic
simulator, replayed from a seed, and embedded in a runtime whose I/O model it never heard of.
stompy is the first consumer and will vendor colibri the way it vendors chapulin; colibri never
depends on stompy and never names it in source.

**Deliberately excluded:** HTTP/1.1, caching, server push, priority scheduling, extended CONNECT,
0-RTT, active connection migration, QUIC datagrams and multipath. [decisions 2, 16 to
23](decisions.md)
give each one a reason and state what saying no still costs on the wire.

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
core   <- http   <- h2, h3
core   <- tls    <- h2, quic
core   <- crypto <- quic
core   <- wire   <- quic  <- h3
core, tls, crypto <- sim
core             <- golden
```

| Module | Holds | Imports | RFCs |
|---|---|---|---|
| `core` | limits, assertions, the bounded reader and writer, the slot pool | nothing | — |
| `wire` | varint, prefixed integer, Huffman, string literal | `core` | 9000 §16, 7541 §5.1, §5.2, App. B |
| `http` | the version-independent semantics core | `core` | 9110 |
| `tls` | the TLS provider vtable, no production implementation | `core` | 8446, 7301, 9001 §4 |
| `crypto` | the packet-protection vtable, no production implementation | `core` | 9001 §5 |
| `hpack` | HPACK | `core`, `wire`, `http` | 7541 |
| `qpack` | QPACK | `core`, `wire`, `http` | 9204 |
| `quic` | the transport: packets, frames, streams, recovery | `core`, `wire`, `crypto`, `tls` | 8999, 9000, 9001, 9002 |
| `h2` | HTTP/2 | `core`, `wire`, `http`, `hpack`, `tls` | 9113 |
| `h3` | HTTP/3 | `core`, `wire`, `http`, `qpack`, `quic` | 9114 |
| `sim` | deterministic clock, byte pipe, datagram network, null providers | `core`, `tls`, `crypto` | — |
| `golden` | the byte-exact corpus and its manifest | what it checks | — |

Three edges are load-bearing and one is forbidden.

- **`quic` does not import `http`, `h2`, `h3`, `hpack` or `qpack`.** This is
  [invariant 26](invariants.md#inv-26--quic-imports-no-http-module) and
  [decision 5](decisions.md#scope-and-shape). The gate that proves it is that the QUIC simulator
  builds and runs with no HTTP module in the graph at all — not a lint rule, a link.
- **`sim` imports `core`, `tls` and `crypto`, and no protocol module.** It implements the same two
  vtables a real caller does, so the build hands its null providers to the protocol modules in
  place of the caller's and nothing is conditionally compiled. It cannot import a protocol module,
  which is what keeps the harness from knowing anything the caller would not.
- **`wire` is shared by both families and holds two different integer codecs.** That is not an
  accident of packaging; [decision 11](decisions.md#what-is-shared-between-h2-and-h3) explains why
  the split is *field compression against framing* and not h2 against h3.
- **Nothing imports `h2` or `h3`.** They are the roots. A consumer picks one or both.

## 4. The seams

Four things cross the boundary out of colibri. Each is a value or a vtable, never a callback
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
the congestion controller's `OnCongestionEvent`, so the instant threads down there too rather than
stopping at the loss detector. colibri passes one instant through a whole call, which RFC 9002
permits and determinism requires.

colibri never sets a timer. It returns the instant at which it next wants to be called, and the
caller arranges that. An idle timeout, a PTO and a `SETTINGS_TIMEOUT` are all the same shape: a
deadline colibri computes and the caller honours.

### 4.3 The TLS provider

Two modes, because RFC 9001 §3 says QUIC "takes over the responsibilities of the TLS record
layer". The full list is [decision 8](decisions.md#the-seams); the shape is:

| Operation | Record mode (h2) | QUIC mode (h3) |
|---|---|---|
| handshake bytes | record-framed, over TCP | unframed messages, per encryption level |
| application protection | `encrypt_record` / `decrypt_record` | absent — colibri protects packets itself |
| secrets | never exposed | `on_secret(level, direction, secret, aead_id, kdf_hash)` |
| key derivation | provider-internal | `hkdf_expand_label` exposed as a primitive |
| transport parameters | absent | `set_transport_params` / `peer_transport_params` |
| ALPN | `negotiated_alpn` | `negotiated_alpn` |
| alerts | `take_alert` | `take_alert`, mapped to `0x0100 + AlertDescription` |
| key update | `initiate_key_update` | forbidden — QUIC's Key Phase instead |
| exporter | `export_keying_material` | `export_keying_material` |

Two facts constrain the ALPN half and are easy to get wrong. In TLS 1.3 the selected protocol
travels in EncryptedExtensions, not ServerHello, so it is only readable after the provider has
decrypted EE — colibri must not assume it knows the ALPN earlier. And `"h2"` is the two octets
`0x68 0x32` (RFC 9113 §3.1) while `"h3"` is `0x68 0x33` (RFC 9114 §11.1); no overlap is a fatal
`no_application_protocol` alert, value 120 (RFC 8446 §6, RFC 7301 §3.2), which RFC 9001 §8.1
extends by requiring QUIC *clients* to use it too.

One state colibri owns and no provider will supply: **handshake confirmed**. RFC 8446 has no such
concept; it is defined only in RFC 9001 §4.1.2 — at the server when the handshake completes, at
the client when `HANDSHAKE_DONE` arrives.

### 4.4 The crypto suite

`aead_seal`, `aead_open`, `header_protection_mask(hp_key, sample) -> [5]u8`, `hkdf_extract`,
`hkdf_expand_label`. QUIC only; h2 needs none of it, because the provider does the record layer.

Header protection is a mask function rather than a block cipher because the two algorithms are not
the same primitive: RFC 9001 §5.4.3 makes it AES in Electronic Codebook mode under a 128- or
256-bit key, and §5.4.4 makes it the raw ChaCha20 function over a 4-octet counter and a 12-octet
nonce taken from the sample, encrypting five zero octets. A vtable exposing a single ECB block
could not protect a ChaCha20 connection at all.

AES-128-GCM, AES-128-ECB and HKDF-SHA256 are mandatory members whatever suite TLS negotiates,
because RFC 9001 fixes three things to AES: Initial packet protection (§5, §5.2), AES-based header
protection, which is what is used before a suite is selected (§5.4.1, §5.4.3), and the Retry
integrity tag (§5.8). The suite must additionally carry the AEAD and header-protection algorithm
TLS goes on to negotiate (§5.3, §5.4.1). A suite missing one of the three mandatory members is
refused when the endpoint is constructed
([invariant 25](invariants.md#inv-25--a-suite-without-aes-is-refused-at-init)), never at the first
packet. [decision 9](decisions.md#the-seams) is why this is a separate vtable and what it buys.

## 5. What is shared, and what only looks shared

[decisions 11 to 16](decisions.md#what-is-shared-between-h2-and-h3) argue each of these from the
RFC text. The summary, because it is the question the module graph answers:

| Candidate | Verdict | Where it lives |
|---|---|---|
| Huffman code, RFC 7541 App. B | **shared**, verbatim — RFC 9204 §4.1.2 | `wire/huffman.zig` |
| Prefixed integers, RFC 7541 §5.1 | **shared**, unmodified — RFC 9204 §4.1.1 | `wire/prefix_int.zig` |
| String literals, RFC 7541 §5.2 | **shared**, with QPACK's mid-byte prefix added | `wire/string.zig` |
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

The last three rows correct candidates that looked shared. Flow control is the sharpest: h2 is a
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
| 8 | Type | unknown types are ignored and discarded, but must still be consumed |
| 8 | Flags | unused flags ignored on receipt, unset on send |
| 1 | Reserved | ignored on receipt, unset on send — mask it, never reject it |
| 31 | Stream Identifier | 0x00 means the connection as a whole |

Frame types, RFC 9113 §6: `DATA` 0x00, `HEADERS` 0x01, `PRIORITY` 0x02, `RST_STREAM` 0x03,
`SETTINGS` 0x04, `PUSH_PROMISE` 0x05, `PING` 0x06, `GOAWAY` 0x07, `WINDOW_UPDATE` 0x08,
`CONTINUATION` 0x09.

Settings, RFC 9113 §6.5.2:

| Name | Id | Initial value | colibri |
|---|---|---|---|
| `SETTINGS_HEADER_TABLE_SIZE` | 0x01 | 4096 | advertised small (§7) |
| `SETTINGS_ENABLE_PUSH` | 0x02 | 1 | sent as 0 by the client; omitted by the server |
| `SETTINGS_MAX_CONCURRENT_STREAMS` | 0x03 | unlimited | **must** be advertised, or nothing is bounded |
| `SETTINGS_INITIAL_WINDOW_SIZE` | 0x04 | 65,535 | §7 |
| `SETTINGS_MAX_FRAME_SIZE` | 0x05 | 16,384 | left at the default; the range is 2^14 to 2^24−1 |
| `SETTINGS_MAX_HEADER_LIST_SIZE` | 0x06 | unlimited | **must** be advertised |

Two of the six initial values are literally unlimited. An implementation that does not advertise
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
- **The simulator trace record**, one per abstract transition, which is what the replay gate
  compares byte for byte.

## 7. Named limits

Every one lives in a `constants.zig` and never inline. The RFCs leave most of these to the
implementation and say so, which is exactly why they are named here rather than chosen at a call
site.

**Shared** (`core`): `field_name_len_max` · `field_value_len_max` · `field_count_max` ·
`field_section_size_max` · `connections_max` · `streams_per_connection_max`.

**h2** (`h2`): `frame_size_max` (16,384, the RFC 9113 §4.2 floor, and colibri does not raise it) ·
`continuation_count_max` · `concurrent_streams_max` · `window_initial` · `window_max` (2^31 − 1) ·
`settings_pending_max` · `ping_pending_max` · `rst_stream_rate_max` · `settings_timeout_ns`.

**HPACK / QPACK** (`hpack`, `qpack`): `dynamic_table_capacity_max` · `integer_octets_max` ·
`huffman_expansion_max` (a 5-bit minimum code means Huffman data expands by up to 1.6x, so
bounding the input does not bound the output) · `blocked_streams_max` · `encoder_stream_bytes_max`.

**QUIC** (`quic`): `datagram_size_max` · `datagram_size_min` (1200) · `ack_ranges_max` ·
`crypto_buffer_bytes_max` · `connection_ids_active_max` (at least 2; the default is 2) ·
`connection_ids_retire_pending_max` · `sent_packets_max` (per packet number space, three tables) ·
`paths_probing_max` · `token_len_max` · `reason_phrase_len_max` · `idle_timeout_ns` ·
`pto_backoff_max`.

**h3** (`h3`): `uni_streams_max` · `push_ids_max` (0 — colibri never sends `MAX_PUSH_ID`) ·
`frame_length_max`.

Four of these exist only because an RFC declines to bound something and hands the job to the
implementation: `ack_ranges_max` (RFC 9000 §13.2.3, "limits the number ... to avoid resource
exhaustion", no maximum given), `crypto_buffer_bytes_max` (§7.5 — CRYPTO data is not flow
controlled and a peer could force unbounded buffering; the defence is this constant plus
`CRYPTO_BUFFER_EXCEEDED` 0x0d), `continuation_count_max` (RFC 9113 §6.10 sets no cap), and
`field_section_size_max` (RFC 9110 §5.4 says no predefined limits exist, and RFC 9113 §10.5.1 says
there is no hard limit on field block size). Each is a named limit precisely because the RFC does
not name one.

## 8. Build plan

Each step names the gate that proves it. **A step with no gate is not a step.** Reading the RFC is
not evidence. Every step that adds a check reports its mutations as `CAUGHT` or `NOT CAUGHT`, and
a `NOT CAUGHT` blocks the step.

Sizes are the owner's estimate of effort, given for planning and not as a commitment.

- **Step 0 — scaffolding.** `build.zig` with the §3 module graph, `constants.zig` per module, the
  linters ported from stompy (cognitive complexity, file length, heap, determinism, unbounded
  loop, relative-import, magic numbers, markdown GFM) plus colibri's own three: the `io` import
  denylist, the module-graph rule, and the RFC-citation rule, which fails a validation branch
  carrying no RFC section comment. Commit hooks.
  **Gate:** `zig build lint` and `zig build test` pass on an empty tree, and a deliberately added
  `@import("http")` inside `src/quic/` fails to build. That last clause is the one that matters —
  it proves [invariant 26](invariants.md#inv-26--quic-imports-no-http-module) is enforced by the
  build rather than by review. *Small.*

- **Step 1 — `wire` and `http`.** The varint (RFC 9000 §16), the prefixed integer generic over N
  in 1..8 and sized for 62 bits, the Huffman coder over RFC 7541 Appendix B, the string literal
  including QPACK's mid-byte prefix form, the `tchar` and field-value validators, the
  connection-option denylist, the status and method models. **Gate:** a golden corpus with a
  manifest, valid and invalid, including one case per Huffman decode error (padding over 7 bits,
  padding that is not EOS's high bits, EOS inside the data) and one per varint length; RFC 9000
  Appendix A's sample varint decodings; fuzzing of every decoder; and a mutation per check
  reported `CAUGHT`. *Small to medium.*

- **Step 2 — the deterministic driver.** A seeded harness that feeds bytes in arbitrary chunks,
  supplies instants, and substitutes null TLS and crypto providers. This is the simulator for the
  h2 half, and it exists before there is a connection to drive, which is possible only because
  §4 made I/O, time and crypto into seams. **Gate:** the step 1 decoders driven through the
  harness at seeded chunk boundaries over a seed range, with the §6.6 trace records compared byte
  for byte across macOS and Linux and across Debug and ReleaseSafe. Say plainly what this does and
  does not prove: at step 2 nothing but the harness can differ, so it shows the harness is
  self-consistent. The same gate re-run over a connection at step 4 is the first point at which it
  can fail for any other reason. *Small.*

- **Step 3 — HPACK.** Static table, dynamic table with the shared size arithmetic, all five
  representations, the size-update instruction. **Gate:** `http2jp/hpack-test-case` decoded across
  **every** encoder directory, not only nghttp2's — the naive, static and linear strategies crossed
  with Huffman and plain are what exercise the dynamic table; round-trip of `raw-data`; the three
  interop breaks of §6.2 each with a named error and a corpus case; fuzzing; mutations. *Medium.*

- **Step 4 — h2 connection and streams, cleartext, prior knowledge.** Frame reader and writer,
  the two prefaces, settings with the ACK discipline, the stream state machine, the signed send
  window and the retroactive settings sweep, GOAWAY, `RST_STREAM`, the field-block reassembly
  slot, request and response validation. Push refused per [decision 17](decisions.md), priority
  parsed but never scheduled per [decision 18](decisions.md). **Gate:** `h2spec` green at the
  pinned version against the test-only prior-knowledge cleartext h2 server of §9 — h2spec connects
  in cleartext unless `-t` is given — with every skipped case named and justified;
  `http2jp/http2-frame-test-case`; the step 2 driver checking
  [invariants 13 to 16](invariants.md#http2) after every step of every seed; fuzzing; mutations.
  **This is the largest single step and the first shippable thing.** *Large.*

- **Step 5 — the TLS provider seam and h2 over TLS.** The record-mode vtable, ALPN, the
  handshake-complete signal, `close_notify` as end of data. Still no implementation in the packaged
  library. **Gate:** `h2spec -t -k` against the TLS entry point; interop against nghttp2, curl,
  Go's `net/http2` and h2o, **both directions**, with the exact versions recorded.

  **This step is blocked on an unanswered question, and so is every step after it.** The gate needs
  a TLS 1.3 *server* — certificate signing included — and nothing in colibri supplies one:
  [decision 8](decisions.md#the-seams) keeps production implementations out of the tree, and
  [decision 10](decisions.md#the-seams) deliberately does not ask chapulin for a server role.
  Steps 9, 12 and 13 need the same thing for the interop endpoint, h3spec and `secnetperf`. The
  answer is a test-only TLS dependency linked by `src/testing/` alone and never by the packaged
  library, and naming it is an "Ask before" under CLAUDE.md that nobody has answered. *Medium,
  once that is settled.*

- **Step 6 — the counted-cost gate.** Allocations, syscalls the caller would have made, copies and
  bytes per request, counted inside the simulator and committed as exact numbers. **Gate:** the
  numbers are in the tree and a diff that changes one fails `zig build test` until the new number
  is committed on purpose. This is the cheap half of [decision 34](decisions.md#performance) and it
  lands before any QUIC code, so the h2 half has a regression floor while the larger half is
  built. *Small.*

- **Step 7 — QUIC packet formats and the crypto seam.** The RFC 8999 invariant reader as its own
  file with an empty import set, the version-1 reader above it, long and short headers, packet
  number encoding and decoding, the Initial key schedule, packet protection, header protection,
  Retry integrity. **Gate:** RFC 9001 Appendix A's sample packet protection, byte for byte, in the
  golden corpus; RFC 9000 Appendix A.2 and A.3's packet number encoding and decoding; corpus cases
  with connection IDs longer than 20 octets under an unknown version, which must **parse** rather
  than fail; a mutation that applies the 20-octet cap in the invariant reader, reported `CAUGHT`;
  fuzzing of the packet reader. *Medium to large.*

- **Step 8 — the QUIC simulator.** A datagram network with delay, drop, reorder, duplication and
  ECN marking, over the step 2 clock, with a null crypto suite. **Gate:** one seed replays
  byte-identically across hosts and build modes — and the harness **builds and runs with no HTTP
  module in the graph**, which is the gate for [decision 5](decisions.md#scope-and-shape). *Medium.*

- **Step 9 — QUIC transport.** The handshake over CRYPTO frames, the three packet number spaces,
  ACK generation and processing, streams with both state machines, offset-based flow control,
  `MAX_STREAMS`, connection IDs, path validation, anti-amplification, idle timeout, the close and
  drain states. `disable_active_migration` per [decision 21](decisions.md), which saves less than
  it sounds like. **Gate:** the step 8 simulator checking
  [invariants 17 to 21](invariants.md#quic) after every step; the QUIC Interop Runner's
  `handshake`, `transfer`, `retry`, `resumption`, `keyupdate`, `multiplexing`, `ipv6`,
  `amplificationlimit`, `rebind-port` and `rebind-addr` cases against the endpoint of §9, with
  **exit 127** for everything not yet supported — `connectionmigration` and `zerortt` are permanent
  127s by decisions 21 and 20. **This is the largest step of the two protocols and should be split
  once its shape is real.** *Very large.*

- **Step 10 — loss recovery and congestion control.** RFC 9002: RTT estimation, packet and time
  threshold loss detection, PTO with backoff, NewReno, persistent congestion, pacing. All nine
  `now()` sites are caller-supplied parameters on the five entry points of §4.2. **Gate:** the
  simulator's loss, reorder and blackhole scenarios with a census per seed; the interop runner's
  `handshakeloss`, `transferloss`, `blackhole`, `longrtt` and `ecn` cases; and, because RFC 9002's
  prose and its appendix pseudocode differ in two places, a written decision in this document's
  §12 for each, with a test pinning the choice. *Large.*

- **Step 11 — QPACK.** Static-table-only encoding first, because both QPACK settings default to
  zero and a static-only encoder is legal and useful; then the dynamic table with the encoder and
  decoder streams, Known Received Count, Required Insert Count, Base, relative and post-base
  indexing, and blocked streams. **Gate:** `qpackers/qifs` vectors at the three settings its
  filenames encode, with the draft-05 caveat of [decision 25](decisions.md#correctness) applied —
  a mismatch is checked against RFC 9204 before it is treated as colibri's bug; RFC 9204 Appendix
  B's reference encodings; fuzzing; mutations. *Large.*

- **Step 12 — h3.** Stream types, the frame layer, the one setting, the control stream rules,
  request and response mapping, GOAWAY, greasing. **Gate:** `h3spec` against the h3 entry point,
  with every case accounted for; the interop runner's `http3` case; `h2load --h3`; and the h2
  suite's semantics tests re-run against h3, which is what proves the `http` module is genuinely
  shared rather than duplicated. *Medium.*

- **Step 13 — `bench/`.** The competitor matrix, the committed baselines, the memory measurement.
  **Gate:** §11's method, run on Linux, five runs reported as median with spread, the A/B in the
  same session, and the machine written down beside the numbers. *Medium.*

Steps 0 to 6 are h2 and deliver a shippable library. Steps 7 to 12 are h3, and step 13 benchmarks
both. Step 6 exists where it does on purpose: the cheap regression gate is in place before the
larger half begins.

## 9. Test-only entry points

Five, and they are not interchangeable. Each lives in `src/testing/`, is excluded from the
packaged library, and is the only place in the tree permitted to touch a socket
([invariant 2](invariants.md#inv-2--colibri-performs-no-io) is scoped to `src/` outside it).

1. **An h2 server** answering `GET /` and `POST /` with 200 and a non-empty body, in both
   cleartext and TLS modes. For h2spec and h2load. Lands with step 4 (cleartext) and step 5 (TLS).
2. **A QUIC and h3 server** with ALPN `h3` and a self-signed certificate. For h3spec and
   `h2load --h3`. Lands with step 12.
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
function** — appending a 16-octet tag and returning a 5-octet mask exactly as a real suite would —
because RFC 9001 §5.3's expansion feeds §5.4.2's sample offset, the packet's Length varint, RFC
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
cannot be shaped afterwards: Linux for every real number, pinned cores, a fixed governor, warmup
discarded, at least five runs reported as median with spread and never a best-of, the A/B in the
same session on the same kernel, and the machine written down beside the numbers. Anything under
about 5% is noise until shown otherwise.

### 11.5 The gate

Two layers, because there is no CI here. The cheap layer is step 6's counted costs in the
simulator — exact numbers a diff must change on purpose — and it runs in `zig build test`. The
expensive layer is `bench/` with committed baselines and a threshold that fails, run by a person
before a step is called done.

## 12. Open questions for the owner

1. **QUIC as a module or its own repository** ([decision 3](decisions.md#scope-and-shape)). The
   recommendation is a module with a mechanically enforced boundary. This sets the module graph, so
   it is answered before step 1.
2. **The packet-protection vtable** ([decision 9](decisions.md#the-seams)). Splitting packet
   protection away from the TLS provider is what lets h3 have AES without chapulin having AES. It
   is the single most consequential shape decision in the document.
3. **The ask to chapulin** ([decision 10](decisions.md#the-seams)). ALPN, and the field reporting
   what was negotiated. Nothing else. Not colibri's to send.
4. **RFC 9002's one internal disagreement**, which step 10 must settle in writing and pin with a
   test. Its §5.3 updates `smoothed_rtt` first and then computes `rttvar` against the new value,
   while its Appendix A.7 computes `rttvar` first against the old value. These produce different
   numbers on every sample. It is not a bug in the RFC; it is a place where an implementation must
   choose, and interop will show which choice the field made.

   The PTO composition looked like a second disagreement and is not one, which is worth recording
   so nobody re-opens it: §6.2.1 sets `max_ack_delay` to 0 for the Initial and Handshake spaces,
   and Appendix A.8 adds `max_ack_delay * (2 ^ pto_count)` only in the Application Data arm. The
   two texts agree.
5. **Whether step 9 stays one step.** It is estimated very large and almost certainly wants
   splitting once its shape is real. Splitting it before writing any of it would be guessing.

## 13. Risks

- **Step 9 is the project.** QUIC transport is the largest single body of work and every later
  step depends on it. The mitigation is that steps 0 to 6 deliver a complete, shippable h2 library
  first, so a QUIC schedule overrun costs h3 and nothing else.
- **The conformance suites are older than the RFCs they test.** h2spec is written against RFC 7540
  and 7541 and last released in 2020. A disagreement is checked against RFC 9113 before it is
  treated as colibri's bug, and the version is pinned so the answer does not move.
- **The QPACK vectors are stale.** `qpackers/qifs` targets draft-05 and has not moved since 2021.
  RFC 9204 Appendix B is the authority where they disagree.
- **No CI.** Every gate a script cannot run inside `zig build test` is run by a person, and the
  step's entry in §8 records what was run, on what, and what it printed. This is the same
  arrangement stompy's full crash tier runs under, and it works only if the recording is honest.
- **The TLS provider has no implementation, and this blocks more than it looks like.** colibri
  cannot ship a working client on its own, and a consumer with no TLS stack has no h2-over-TLS.
  Worse for the plan: every gate from step 5 onward needs a TLS 1.3 *server* with certificate
  signing, for h2spec's TLS mode, the interop endpoint, h3spec and `secnetperf`. Step 4's cleartext
  h2 unblocks step 4 and nothing beyond it, which is why cleartext comes first — and why step 5
  opens with the unanswered question rather than a gate.
- **The development machine is not the measurement machine.** Every real number needs Linux.
  A macOS-only development loop can hide a regression that only a kernel mechanism would show.
