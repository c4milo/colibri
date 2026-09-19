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
flow control, loss recovery — and it owns it with no heap, bounded loops and assertions that stay
on in production.

The narrowness is the point. A library that owns no sockets can be driven by a deterministic
simulator, replayed from a seed, and embedded in a runtime whose I/O model it never heard of.
stompy is the first consumer and will vendor colibri the way it vendors chapulin; colibri never
depends on stompy and never names it in source.

**Deliberately excluded:** HTTP/1.1, caching, server push, priority scheduling, extended CONNECT,
0-RTT, active connection migration, QUIC datagrams and multipath.
[Decisions 2, 16 to 23](decisions.md) give each one a reason and state what saying no still costs
on the wire.

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
core, wire, sim, h2 <- sim_run
core, wire, hpack <- golden
core, h2         <- testing
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
| `sim_run` | the checks of §8 run over `sim`, and the `zig build sim` command line | `core`, `wire`, `sim`, then each module a check drives: `h2` at step 4 | — |
| `golden` | the byte-exact corpus and its manifest | what it checks | — |
| `testing` | the test-only endpoints of §9, and the only socket in the tree | `core`, then each module an endpoint serves | — |

The architecture depends on three of these edges and forbids one.

- **`quic` does not import `http`, `h2`, `h3`, `hpack` or `qpack`.** This is
  [invariant 26](invariants.md#inv-26--quic-imports-no-http-module) and
  [decision 5](decisions.md#scope-and-shape). The check that proves it is that the QUIC simulator
  builds and runs with no HTTP module in the graph at all — not a lint rule, a link.
- **`sim` imports `core`, `tls` and `crypto`, and no protocol module.** It implements the same two
  vtables a real caller does, so the build hands its null providers to the protocol modules in
  place of the caller's and nothing is conditionally compiled. It cannot import a protocol module,
  which is what keeps the harness from knowing anything the caller would not. A check drives a
  protocol module through the harness, so the one module that imports both is `sim_run`, rooted at
  `src/sim/run.zig`, and `sim` never imports it back ([decision 37](decisions.md#the-simulator)).
- **`wire` is shared by both families and holds two different integer codecs.**
  [decision 11](decisions.md#what-is-shared-between-h2-and-h3) explains why the split is *field
  compression against framing* and not h2 against h3.
- **Nothing imports `h2` or `h3`.** They are the roots. A consumer picks one or both, and
  `testing` is a consumer like any other: the library it drives cannot use the socket it opens,
  because the edge runs one way and nothing imports `testing` back.

## 4. What the caller supplies

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
| secrets | never exposed | `on_secret(level, direction, secret, aead_id, kdf_hash)` |
| key derivation | provider-internal | `hkdf_expand_label` exposed as a primitive |
| transport parameters | absent | `set_transport_params` / `peer_transport_params` |
| ALPN | `negotiated_alpn` | `negotiated_alpn` |
| alerts | `take_alert` | `take_alert`, mapped to `0x0100 + AlertDescription` |
| key update | `initiate_key_update` | forbidden — QUIC's Key Phase instead |
| exporter | `export_keying_material` | `export_keying_material` |

Two facts constrain the ALPN half and are easy to get wrong. In TLS 1.3 the selected protocol
is sent in EncryptedExtensions, not ServerHello, so it is only readable after the provider has
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
integrity tag (§5.8). The suite must additionally carry the AEAD and header-protection algorithm TLS
goes on to negotiate (§5.3, §5.4.1). A suite missing one of the three mandatory members is refused
when the endpoint is constructed
([invariant 25](invariants.md#inv-25--a-suite-without-aes-is-refused-at-init)), never at the first
packet. [decision 9](decisions.md#what-the-caller-supplies) is why this is a separate vtable and
what it buys.

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
`settings_pending_max` · `ping_pending_max` · `rst_stream_rate_max` · `settings_timeout_ns` ·
`representation_len_max` (31,721 encoded octets: the longest field line within
`field_name_len_max`, `field_value_len_max` and `integer_len_max`, Huffman-coded at 30 bits an
octet, so it refuses no line those limits admit) · `field_block_buffer_len` (one cut representation
plus one frame, decision 40) · `send_block_len_max` (two frames' worth of field block colibri
sends, cut into a HEADERS frame and the CONTINUATION frames it needs) · `settings_ack_pending_max`
· `ping_ack_pending_max` · `stream_replies_max` (the reply queues of decision 39: a full queue
stops the reading, and no reply is ever dropped).

**wire** (`wire`): `varint_value_max` (2^62 − 1, RFC 9000 §16) · `integer_value_max` (2^62 − 1, the
62 bits RFC 9204 §4.1.1 requires) · `integer_len_max` (10 octets, the length those 62 bits need
past a 1-bit prefix) · `huffman_padding_bits_max` (7, RFC 7541 §5.2).

**HPACK / QPACK** (`hpack`, `qpack`): `dynamic_table_capacity_max` (16,384, ruled 2026-09-16) ·
`dynamic_table_entries_max` (the capacity over the 32-octet overhead) · `size_updates_per_block_max`
(2, RFC 7541 §4.2) · `blocked_streams_max` · `encoder_stream_bytes_max`. Huffman data expands by up
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

- **Step 2 — the deterministic driver.** A seeded harness that feeds bytes in arbitrary chunks,
  supplies instants, and substitutes null TLS and crypto providers. This is the simulator for the h2
  half, and it exists before there is a connection to drive, which is possible only because §4 put
  I/O, time and crypto in the caller's hands. **Check:** the step 1 decoders driven through the
  harness at seeded chunk boundaries over a seed range, with the §6.6 trace records compared byte
  for byte across macOS and Linux and across Debug and ReleaseSafe. What this does and does not
  prove: at step 2 nothing but the harness can differ, so it shows the harness is self-consistent.
  The same check re-run over a connection at step 4 is the first point at which it can fail for any
  other reason. *Small.*

  **Check passed on macOS, 2026-09-16; the Linux half is the owner's.** `zig build test` exits 0 on
  Zig 0.16.0, macOS 25.6, arm64, in Debug and with `-Drelease`, and the lint scores 460 functions
  with a highest score of 12. `zig build sim -- --chunk-check` prints the same census in both modes:
  `seeds=256 passed=193 rejected=63 chunks=2551 trace_octets=278839 crc32=0x11c9c07a`. That
  digest is `chunk_check.census_crc32_expected`, and the check's test requires it, so the Linux run
  is `zig build test-sim-run` in both modes on a Linux host. It has not been run yet:
  [issue 1](https://github.com/c4milo/colibri/issues/1).

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
  reach h2 as nothing, a peer `close_notify` is the end of data (RFC 8446 §6.1) and every other
  alert ends the transport. Both buffers stay the caller's, so a connection carries no record
  storage.

  `src/sim/null_provider.zig` fills the vtable with no cryptography, framing records at the sizes
  RFC 8446 §5.1 and §5.2 give them. `src/sim/tls_check.zig` drives one connection over it three
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

  **Still owed for the step.** A TLS 1.3 server with certificate signing, which no implementation
  in this tree supplies ([decision 10](decisions.md#what-the-caller-supplies)); `h2spec -t -k`;
  interop against nghttp2, curl, Go's `net/http2` and h2o in both directions. RFC 9113 Appendix A's
  prohibited suites are not checked and will not be: decision 45 records why.

- **Step 6 — the counted-cost check.** Syscalls the caller would have made, copies and bytes per
  request, counted inside the simulator and committed as exact numbers. Allocations are not
  counted: [decision 35](decisions.md#memory) makes them zero, and `tools/lint/heap.zig` holds
  it. **Check:** the numbers are in the tree and a diff that changes one fails `zig build test`
  until the new number is committed on purpose. This is the cheap half of
  [decision 34](decisions.md#performance) and it lands before any QUIC code, so the h2 half has a
  regression floor while the larger half is built. *Small.*

- **Step 7 — QUIC packet formats and the crypto vtable.** The RFC 8999 invariant reader as its own
  file with an empty import set, the version-1 reader above it, long and short headers, packet
  number encoding and decoding, the Initial key schedule, packet protection, header protection,
  Retry integrity. **Check:** RFC 9001 Appendix A's sample packet protection, byte for byte, in the
  golden corpus; RFC 9000 Appendix A.2 and A.3's packet number encoding and decoding; corpus cases
  with connection IDs longer than 20 octets under an unknown version, which must **parse** rather
  than fail; a mutation that applies the 20-octet cap in the invariant reader, reported `CAUGHT`;
  fuzzing of the packet reader. *Medium to large.*

- **Step 8 — the QUIC simulator.** A datagram network with delay, drop, reorder, duplication and ECN
  marking, over the step 2 clock, with a null crypto suite. **Check:** one seed replays
  byte-identically across hosts and build modes — and the harness **builds and runs with no HTTP
  module in the graph**, which is the check for [decision 5](decisions.md#scope-and-shape).
  *Medium.*

- **Step 9 — QUIC transport.** The handshake over CRYPTO frames, the three packet number spaces,
  ACK generation and processing, streams with both state machines, offset-based flow control,
  `MAX_STREAMS`, connection IDs, path validation, anti-amplification, idle timeout, the close and
  drain states. `disable_active_migration` per [decision 21](decisions.md), which saves less than
  it sounds like. **Check:** the step 8 simulator checking
  [invariants 17 to 21](invariants.md#quic) after every step; the QUIC Interop Runner's
  `handshake`, `transfer`, `retry`, `resumption`, `keyupdate`, `multiplexing`, `ipv6`,
  `amplificationlimit`, `rebind-port` and `rebind-addr` cases against the endpoint of §9, with
  **exit 127** for everything not yet supported — `connectionmigration` and `zerortt` are permanent
  127s by decisions 21 and 20. **This is the largest step of the two protocols and should be split
  once its shape is real.** *Very large.*

- **Step 10 — loss recovery and congestion control.** RFC 9002: RTT estimation, packet and time
  threshold loss detection, PTO with backoff, NewReno, persistent congestion, pacing. All nine
  `now()` sites are caller-supplied parameters on the five entry points of §4.2. **Check:** the
  simulator's loss, reorder and blackhole scenarios with a census per seed; the interop runner's
  `handshakeloss`, `transferloss`, `blackhole`, `longrtt` and `ecn` cases; and, because RFC 9002's
  prose and its appendix pseudocode differ in two places, a written decision in this document's
  §12 for each, with a test pinning the choice. *Large.*

- **Step 11 — QPACK.** Static-table-only encoding first, because both QPACK settings default to
  zero and a static-only encoder is legal and useful; then the dynamic table with the encoder and
  decoder streams, Known Received Count, Required Insert Count, Base, relative and post-base
  indexing, and blocked streams. **Check:** `qpackers/qifs` vectors at the three settings its
  filenames encode, with the draft-05 caveat of [decision 25](decisions.md#correctness) applied —
  a mismatch is checked against RFC 9204 before it is treated as colibri's bug; RFC 9204 Appendix
  B's reference encodings; fuzzing; mutations. *Large.*

- **Step 12 — h3.** Stream types, the frame layer, the one setting, the control stream rules,
  request and response mapping, GOAWAY, greasing. **Check:** `h3spec` against the h3 entry point,
  with every case accounted for; the interop runner's `http3` case; `h2load --h3`; and the h2
  suite's semantics tests re-run against h3, which proves the `http` module is
  shared rather than duplicated. *Medium.*

- **Step 13 — `bench/`.** The competitor matrix, the committed baselines, the memory measurement.
  **Check:** §11's method, run on Linux, five runs reported as median with spread, the A/B in the
  same session, and the machine written down beside the numbers. *Medium.*

Steps 0 to 6 are h2 and deliver a shippable library. Steps 7 to 12 are h3, and step 13 benchmarks
both. Step 6 exists where it does on purpose: the cheap regression check is in place before the
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

### 11.5 What must hold

Two layers, because there is no CI here. The cheap layer is step 6's counted costs in the
simulator — exact numbers a diff must change on purpose — and it runs in `zig build test`. The
expensive layer is `bench/` with committed baselines and a threshold that fails, run by a person
before a step is called done.

## 12. Open questions for the owner

1. **QUIC as a module or its own repository** ([decision 3](decisions.md#scope-and-shape)).
   Ruled 2026-09-16: a module with a mechanically enforced boundary, which step 0 built and proved.
2. **The packet-protection vtable** ([decision 9](decisions.md#what-the-caller-supplies)). Ruled
   2026-09-16: two vtables, `tls.Provider` and `crypto.Suite`. Splitting packet protection away from
   the TLS provider is what lets h3 have AES without chapulin having AES, and step 7 builds against
   it.
3. **The ask to chapulin** ([decision 10](decisions.md#what-the-caller-supplies)). Ruled 2026-09-16:
   chapulin provides all of colibri's crypto by filling both vtables, and `src/testing/` links it.
   The request is [docs/chapulin.md](chapulin.md), and sending it is the owner's.
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

- **Step 9.** QUIC transport is the largest single body of work and every later
  step depends on it. The mitigation is that steps 0 to 6 deliver a complete, shippable h2 library
  first, so a QUIC schedule overrun costs h3 and nothing else.
- **The conformance suites are older than the RFCs they test.** h2spec is written against RFC 7540
  and 7541 and last released in 2020. A disagreement is checked against RFC 9113 before it is
  treated as colibri's bug, and the version is pinned so the answer does not move.
- **The QPACK vectors are stale.** `qpackers/qifs` targets draft-05 and has not moved since 2021.
  RFC 9204 Appendix B is the authority where they disagree.
- **No CI.** Every check a script cannot run inside `zig build test` is run by a person, and the
  step's entry in §8 records what was run, on what, and what it printed. This is the same
  arrangement stompy's full crash tier runs under, and it works only if the recording is honest.
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
