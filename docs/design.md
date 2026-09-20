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
core, sim, quic  <- sim_run_quic
core, wire, hpack, quic <- golden
core, h2         <- testing, testing_client
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
| `sim_run_quic` | the QUIC checks of §8 run over `sim`, from step 7 on | `core`, `sim`, `quic`, and no HTTP module | — |
| `golden` | the byte-exact corpus and its manifest | what it checks | — |
| `testing` | the test-only endpoints of §9, and the only socket in the tree | `core`, then each module an endpoint serves | — |
| `testing_client` | the same directory under a second root, because an executable has one `main`: the h2 client of §9 | what `testing` imports | — |

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
  The QUIC checks have a root of their own, `sim_run_quic` at `src/sim/run_quic.zig`, because
  `sim_run` imports `h2`: a QUIC check placed there would run with an HTTP module in its graph,
  and the first edge of this list is proved by a build that has none.
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

- **Step 9d — connection IDs, path validation and anti-amplification.** NEW_CONNECTION_ID and
  RETIRE_CONNECTION_ID (RFC 9000 §5.1), PATH_CHALLENGE and PATH_RESPONSE (§8.2), the
  anti-amplification limit of §8, and the Stateless Reset of §10.3.
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

- **Step 9e — the handshake over CRYPTO frames, and the interop runner.** CRYPTO frame
  reassembly by offset, the handshake driven through `tls.Provider`'s QUIC mode, and the
  transport parameters of §7.4. **This is the only part of step 9 that waits on chapulin**: its
  `ch_quic_*` calls were stubs until 2026-09-20, when chapulin implemented all fifteen; the
  client role is on its `main` and the server role has no driver yet. **Check:** step 9's,
  above. *Large.*


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
  `sent=16873 acked=11997 lost=4876 probes=1354 scenarios={ 60, 57, 75, 64 }
  crc32=0xb78a83fe` in Debug and in ReleaseSafe on macOS arm64. Every packet is accounted for
  exactly once — 11997 and 4876 sum to 16873 — no packet is both acknowledged and declared lost,
  the run drains, and the window never falls under §7.2's minimum.

  Writing the check found two defects in the check itself and neither in the library, which is
  worth recording because both were rules the library already held. The first invariant written
  was that the octets in flight never pass the congestion window; §7 bounds what a sender adds,
  not what is already outstanding, and §7.5 exempts a probe from the window outright, so the
  check now tests the send and not the state. The second was a digest taken over a struct's
  bytes, padding included: padding is uninitialized memory, the two build modes disagreed about
  it, and [invariant 5](invariants.md#quic) forbids reading it. Each field is now fed in on its
  own, in network byte order.

  **Still owed:** the interop runner's `handshakeloss`, `transferloss`, `blackhole`, `longrtt`
  and `ecn` cases, which need a connection to drive and so wait on 9e.

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

- **Step 12 — h3.** Stream types, the frame layer, the one setting, the control stream rules,
  request and response mapping, GOAWAY, greasing. **Check:** `h3spec` against the h3 entry point,
  with every case accounted for; the interop runner's `http3` case; `h2load --h3`; and the h2
  suite's semantics tests re-run against h3, which proves the `http` module is
  shared rather than duplicated. *Medium.*

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

- **Step 13 — `bench/`.** The competitor matrix, the committed baselines, the memory measurement.
  **Check:** §11's method, run on Linux, five runs reported as median with spread, the A/B in the
  same session, and the machine written down beside the numbers. *Medium.*

Steps 0 to 6 are h2 and deliver a shippable library. Steps 7 to 12 are h3, and step 13 benchmarks
both. Step 6 exists where it does on purpose: the cheap regression check is in place before the
larger half begins.

## 9. Test-only entry points

Five, and they are not interchangeable. Each lives in `src/testing/`, is excluded from the
packaged library, does its I/O without blocking ([decision 46](decisions.md)), and is the only
place in the tree permitted to touch a socket
([invariant 2](invariants.md#inv-2--colibri-performs-no-io) is scoped to `src/` outside it).

1. **An h2 server** answering `GET /` and `POST /` with 200 and a non-empty body, in both
   cleartext and TLS modes, and **an h2 client** that runs a plan of exchanges against another
   implementation's server and reports how each ended. For h2spec, h2load and
   `tools/h2_interop.sh`. Land with step 4 (cleartext) and step 5 (TLS).
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
cannot be shaped afterwards: Linux for every real number, pinned cores, a fixed governor, warmup
discarded, at least five runs reported as median with spread and never a best-of, the A/B in the
same session on the same kernel, and the machine written down beside the numbers. Anything under
about 5% is noise until shown otherwise.

### 11.5 What must hold

Two layers. The cheap layer is step 6's counted costs in the simulator — exact numbers a diff
must change on purpose — and it runs in `zig build test`. The expensive layer is `bench/` with
committed baselines and a threshold that fails, run by a person before a step is called done.
[Decision 47](decisions.md) runs the cheap layer on each push to main and prints an h2load
figure beside it, which is indicative and carries no threshold: a hosted runner cannot meet §11.4.

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
- **CI runs what a hosted runner can.** [Decision 47](decisions.md) runs every check on each push
  to main and leaves a report. What needs a machine it does not have — the published numbers of
  §11, the QUIC interop matrix — is still run by a person, and the step's entry in §8 records what
  was run, on what, and what it printed.
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
