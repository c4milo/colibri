# Invariants

[docs/decisions.md](decisions.md) answers "why is it built this way". This document answers "what
must a change never break". Every entry here becomes at least one runtime assertion, and a
violated invariant halts with the seed and the byte offset that produced it.

Each entry has four fields. **Claim** is the invariant. **Mechanism** is what makes it true.
**Check** is what would catch a violation, graded on this scale, strongest first:

1. *type system* — a violation does not compile.
2. *comptime assert* — the property is pinned when the program is built; a violation fails the
   build with the assert's own message.
3. *structural arithmetic* — the property holds by construction, and there is no code path that
   could break it without rewriting the construction.
4. *runtime assertion* — asserted on every execution, in production, at a contract point that
   peer input cannot reach (see INV-24).
5. *simulator invariant* — checked after every step of every seed, so a violation names the seed
   that produced it.
6. *golden corpus* — a named mutation of the corpus must produce a named verdict; a mutation that
   no test fails is recorded `NOT CAUGHT` and is a missing test.
7. *lint rule* — a structural or syntactic rule over the tree; catches any violation, deliberate or
   not, that the rule can express.
8. *convention* — code review is the only check.

**Violation** is what a breaking change looks like, so review can recognise one. An entry whose
Check is grade 7 or 8 is a weaker entry, and the scale says so.

The invariants whose build-plan step has landed are implemented; the rest are not. Each entry names
the build-plan step (design §8) that lands its check. Each entry names the build-plan step (design
§8) that lands its check.

## Allocation and ownership

### INV-1 — colibri never allocates

- **Claim.** colibri never allocates. Every buffer a connection uses is either inside a struct the
  caller owns, sized at comptime from `constants.zig`, or was handed in by the caller for the
  duration of one call.
- **Mechanism.** No module takes, holds or names an `Allocator`, and no source under `src/`
  references `std.heap` (decision 35). The caller owns every struct colibri defines and places it
  where it chooses. The connection struct's size is a comptime constant, so `@sizeOf` gives its
  total memory use.
- **Check.** Lint rule (`tools/lint/heap.zig`: no parameter whose type names `Allocator` on any
  function in `src/`, `init` included, and no reference to `std.heap` or to the allocators of
  `std.testing`) at step 0, with the `init` exception removed when decision 35 was ruled; plus a
  comptime assert pinning each connection struct's size, which lands with the struct it pins (steps
  4 and 9; h2's is not written yet) and is cross-checked against what `bench/run.sh` publishes when
  `bench/` lands at step 13.
- **Violation.** A "temporary" growable buffer for an oversized field section, so the static
  memory table silently stops being true. Or an `init` that takes an allocator "only once".
- See [decisions 31, 34](decisions.md#performance) and [35](decisions.md#memory).

### INV-2 — colibri performs no I/O

- **Claim.** No colibri source opens, reads, writes, polls or closes anything. It has no file
  descriptors, no sockets, no threads and no timers.
- **Mechanism.** The module graph gives no module access to `std.posix`, `std.fs`, `std.net`,
  `std.Thread` or `std.time`. Every function that would block returns the I/O it needs instead.
- **Check.** Lint rule (`tools/lint/io.zig`, an import denylist over `src/` excluding
  `src/testing/`, which design §9 makes the one place a socket may be opened). Step 0.
- **Violation.** A convenience helper that takes a socket "just for the test server" and is written
  in a library module instead of in `src/testing/`.
- See [decisions 6](decisions.md#what-the-caller-supplies).

### INV-3 — every write is inside the caller's buffer

- **Claim.** colibri never writes outside the bounds of the slice it was given, and it never
  reads past the end of the bytes it was told are present.
- **Mechanism.** All output goes through one bounds-checked writer and all parsing through one
  bounds-checked reader. No raw pointer arithmetic exists outside those two files.
- **Check.** Lint rule (`tools/lint/peer_index.zig`: no index or slice bound that reads a value
  a `Reader` produced, followed through one function, outside the reader and writer), plus
  a runtime assertion at every reader and writer entry that the cursor is within the slice, plus
  fuzzing of every parser. Step 1.
- **Violation.** A parser that reads a length, then slices with it, and checks the length
  afterwards.

## Determinism

### INV-4 — no source reads a clock

- **Claim.** Every instant colibri uses arrived as a parameter from the caller. No source file
  reads the wall clock or a monotonic clock.
- **Mechanism.** `std.time` is not in any module's import set, and every function needing an
  instant takes a `now_ns: u64` parameter. RFC 9002 reads `now()` at nine sites across five entry
  points, and all nine are parameters on those five.
- **Check.** Lint rule (`tools/lint/determinism.zig`), plus the simulator's replay check, which
  fails if two runs of one seed differ by a byte. Steps 0 and 10.
- **Violation.** An idle-timeout helper that reads the monotonic clock "because the caller would
  only pass the same value anyway".
- See [decisions 7](decisions.md#what-the-caller-supplies).

### INV-5 — no source reads randomness or uninitialised memory

- **Claim.** colibri draws no random bytes and reads no uninitialised memory. Where a protocol
  needs unpredictable bytes — QUIC connection IDs, `PATH_CHALLENGE` payloads, stateless reset
  tokens, a `PING` opaque payload — the caller supplies them.
- **Mechanism.** No `std.Random` import. Every such value is a parameter or a field the caller
  filled before the call. `undefined` appears only in a declaration immediately followed by a
  full initialisation in the same function.
- **Check.** Lint rule (`std.Random` denylist; `undefined` audited per site with a comment naming
  the initialiser), plus the simulator's replay check. Step 0.
- **Violation.** A connection-ID generator inside `src/quic/`, which would make every QUIC seed
  irreproducible and would also be the wrong place to make a security decision.

### INV-6 — a connection is a pure function

- **Claim.** A connection's output bytes and state transitions are a pure function of its
  configuration, the bytes it has been fed, and the instants it has been given, in order.
- **Mechanism.** INV-1, INV-2, INV-4 and INV-5 together leave no other input. No branch reads a
  pointer value, an address, or a hash of one.
- **Check.** Simulator invariant: every check runs each seed twice and requires the two runs to
  produce byte-identical output, byte-identical traces and the same outcome, on macOS and Linux
  and in both optimization modes. Steps 2 and 8.
- **Violation.** Iterating a hash map whose order depends on a pointer, then writing frames in
  that order.
- See [decisions 30](decisions.md#correctness).

## Parsing

### INV-7 — validation precedes interpretation

- **Claim.** A frame, packet or representation is validated in a fixed order, and the first
  failure returns the error named for that step. No field is interpreted before the checks that
  make interpreting it safe have passed.
- **Mechanism.** Each parser states its check order as a numbered list in its doc comment and
  implements exactly that order, in the shape stompy's `obi-formats` §1.3 uses. Length and type
  checks precede payload reads; a payload is never read before the header that describes it has
  been fully accepted.
- **Check.** Golden corpus: an invalid case per check step, each naming the verdict it must
  produce, plus a mutation per step that must be `CAUGHT`. Steps 1, 4, 7.
- **Violation.** Reading a `SETTINGS` payload to see whether it is worth range-checking the frame
  length first.

### INV-8 — every loop over peer-supplied counts is bounded by a named limit

- **Claim.** No loop's trip count is controlled by a peer without a named constant capping it.
- **Mechanism.** Every such loop reads its bound from a `constants.zig` value, never from a
  literal and never from the peer's value alone. The RFCs leave most of these bounds to the
  implementation and say so: RFC 9000 §13.2.3 on ACK ranges, §12.3 on duplicate-detection state,
  §7.5 on CRYPTO buffering, §5.1.1 on issued connection IDs; RFC 9113 §6.10 with §10.5 on
  CONTINUATION count; RFC 7541 §7.4 on integer and string lengths; RFC 9113 §10.5.1 and RFC 9110
  §5.4 on field-section size.
- **Check.** Lint rule (`tools/lint/unbounded_loop.zig`), plus a runtime assertion per loop that
  the trip count stayed at or below its named limit, plus fuzzing. Steps 1, 4, 9.
- **Violation.** `while (reader.remaining() > 0)` over a peer-controlled buffer with no counter.

### INV-9 — a declared length is checked against the bytes present

- **Claim.** Every length or count read off the wire is compared against both its protocol
  maximum and the bytes actually available, before any use.
- **Mechanism.** The reader's `take(n)` returns an error rather than a short slice, and no caller
  may construct a slice from a peer length by any other route.
- **Check.** Type system (the reader returns an error union that cannot be ignored), plus golden
  corpus cases that truncate every length-bearing structure by one byte. Step 1.
- **Violation.** A varint decoder that returns a value without reporting how many octets it
  consumed, so the caller guesses.

## Field compression

### INV-10 — every octet of a field block is decoded, even when the result is discarded

- **Claim.** When colibri refuses a field section for exceeding its own limit, it still runs every
  octet through the decoder so the dynamic table stays synchronised with the peer's.
- **Mechanism.** The size limit is enforced on the *emitted* fields, not on the input, and the
  decode loop has no early return that skips input. RFC 9113 §4.3 makes a decode failure a
  connection error of `COMPRESSION_ERROR`, and RFC 9113 §10.5.1 states there is no hard limit on
  field block size while still requiring the block to be processed to keep connection state
  consistent.
- **Check.** Runtime assertion that the decoder consumed exactly the block's length on both the
  accept and the refuse path, plus a golden corpus case that overruns the limit mid-block and
  then sends a second block depending on the first's table mutations. Steps 3 and 11.
- **Violation.** An early `return error.FieldSectionTooLarge` in the decode loop, which
  desynchronises the table and turns the next request into a `COMPRESSION_ERROR` that looks like
  the peer's fault.

### INV-11 — the dynamic table's accounted size equals the sum of its entries

- **Claim.** The table's tracked size is always exactly the sum over its entries of
  `name_len + value_len + 32`, measured on the unencoded strings, and never exceeds the capacity
  in force.
- **Mechanism.** One insert path and one evict path, each adjusting the accounted size in the same
  statement that moves the entry. The formula is RFC 7541 §4.1 and RFC 9204 §3.2.1, identical in
  both, and is written once, in one shared function (decision 11).
- **Check.** Runtime assertion recomputing the sum on every insert and evict, plus the
  `http2jp/hpack-test-case` and `qpackers/qifs` vectors, plus a mutation of the 32-octet constant
  that must be `CAUGHT`. Steps 3 and 11.
- **Violation.** Accounting the Huffman-encoded length instead of the unencoded one, which passes
  every round-trip test against itself and fails against every other implementation.

### INV-12 — the three Huffman decode errors are rejected

- **Claim.** A Huffman-coded string is rejected, per RFC 7541 §5.2, when its padding is strictly
  longer than 7 bits, when the padding is not the most significant bits of EOS, or when a complete
  EOS symbol appears inside the data.
- **Mechanism.** One decoder, shared by HPACK and QPACK (RFC 9204 §4.1.2 adopts RFC 7541 Appendix
  B without modification). EOS is `0x3fffffff`, thirty set bits. The two padding rules reduce to
  run-of-ones arithmetic on the tail; the third does not, and must be a symbol-boundary check
  inside the decode loop. A run of thirty ones can occur with no EOS present — Appendix B's symbol
  204 ends in five ones and symbol 22 begins with twenty-nine, so `0xCC 0x16` encodes to a run of
  thirty-four — and a decoder that scans for a run rejects legal input.
- **Check.** Golden corpus with one case per condition and a mutation per condition that must be
  `CAUGHT`, plus fuzzing. Step 1.
- **Violation.** Treating a trailing run of ones as benign padding regardless of length, which
  accepts a stream every conformant peer rejects.

## HTTP/2

### INV-13 — stream identifiers are monotonic per parity and never reused

- **Claim.** A stream identifier, once used, is never used again on that connection; identifiers a
  peer opens are strictly increasing; and every identifier below the watermark for its parity is
  closed, whether or not colibri ever held a record for it.
- **Mechanism.** Two watermarks, one per parity, and a fixed slot pool. "Closed" is the implicit
  default below the watermark rather than a stored record, which keeps a 31-bit identifier space
  from becoming a 31-bit table (RFC 9113 §5.1.1). The pool does keep the most recent closes, so
  §5.1 can decide a late frame by how its stream closed, and an open drops the oldest of them when
  it needs the slot. This is the shared slot-pool structure of decision 14.
- **Check.** An identifier at or below the watermark that the table holds no record for is a
  connection error of `PROTOCOL_ERROR`; one whose record the table still keeps takes the verdict
  §5.1 gives for the way it closed. Neither is an assertion, because a peer supplies the value
  (INV-24). The runtime assertion is on colibri's own bookkeeping: that a watermark never
  decreases. Plus a simulator invariant checked after every step, and the h2spec cases for §5.1.1.
  Step 4.
- **Violation.** A hash map keyed by stream identifier, which one frame can grow by 2^31 entries.

### INV-14 — exactly one field-block reassembly is in progress

- **Claim.** At most one field block is being reassembled on a connection at a time, and no frame
  of any type, from any stream, may be processed while one is.
- **Mechanism.** A single `?{stream_id, origin}` slot on the connection. RFC 9113 §4.3 requires
  field blocks to be a contiguous sequence with nothing interleaved, which makes
  one slot sufficient rather than a per-stream buffer.
- **Check.** An interleaved frame or an orphan CONTINUATION returns a connection error of
  `PROTOCOL_ERROR` (RFC 9113 §4.3) — not an assertion, because a peer produces both (INV-24). The
  h2spec §4.3 cases and a golden corpus case interleaving a PING inside a block prove it.
  The runtime assertion is on colibri's own bookkeeping: the reassembly byte count never exceeds
  `(continuation_count_max + 1) * frame_size_max`, one HEADERS or PUSH_PROMISE frame and at most
  `continuation_count_max` CONTINUATION frames, each at most `frame_size_max`. Step 4.
- **Violation.** A per-stream reassembly buffer, which is both unnecessary and a memory
  amplification path.

### INV-15 — flow-control windows stay in range, and a send window may be negative

- **Claim.** Both windows are *signed* quantities in `[-(2^31 - 1), 2^31 - 1]`. A send window goes
  below zero when a reduction in `SETTINGS_INITIAL_WINDOW_SIZE` exceeds the data already
  sent, and RFC 9113 §6.9.2 requires tracking that. A receive window goes below zero for the mirror
  reason: RFC 9113 §6.9.3 says a receiver that reduces its initial window "MUST be prepared to
  receive data that exceeds this window size". A `WINDOW_UPDATE` that would push a window above
  `2^31 - 1` is an error, not a clamp.
- **Mechanism.** Both windows are `i64` with a runtime range assertion on colibri's own arithmetic.
  The settings sweep iterates the whole fixed stream array, which is why the array is directly
  iterable rather than a map (decision 13).
- **Check.** Runtime assertion on the range after every adjustment; simulator invariant after every
  step; h2spec §6.9 cases; a mutation making either window unsigned that must be `CAUGHT`. Step 4.
- **Violation.** A `u32` send window, which turns a legal settings reduction into a wrap and then
  into sending far more data than the peer allowed.

### INV-16 — GOAWAY's last-stream-id never increases

- **Claim.** Successive GOAWAY frames colibri sends carry non-increasing last-stream-id values,
  and colibri never processes a stream above a last-stream-id a peer sent it.
- **Mechanism.** One stored value per direction. colibri's own setter asserts the new value is not
  greater; a peer's second GOAWAY carrying a larger value is a connection error of
  `PROTOCOL_ERROR`, never an assertion (RFC 9113 §6.8, INV-24).
- **Check.** Runtime assertion in colibri's setter, a connection error on the receive path, plus a
  simulator invariant and the h2spec §6.8 cases. Step 4.
- **Violation.** Sending a second GOAWAY with a fresh high-water mark after a graceful shutdown
  began, which withdraws the guarantee the first one gave.

## QUIC

### INV-17 — a packet number is never reused in its space

- **Claim.** Within one packet number space, colibri never sends two packets with the same packet
  number, and the number never decreases. The three spaces are independent.
- **Mechanism.** One monotonic counter per space (RFC 9000 §12.3), incremented in the same
  statement that commits the packet to the sent-packet table. A retransmission carries new frame
  content under a new number; frames are never retransmitted whole (RFC 9000 §13.3).
- **Check.** Runtime assertion in the send path, plus a simulator invariant over every seed's
  packet log. Step 9.
- **Violation.** Re-sending a buffered packet verbatim after a loss, which reuses its number and
  breaks the AEAD nonce construction.

### INV-18 — the anti-amplification limit holds, and it is the server's

- **Claim.** As a server, before it has validated the client's address, colibri never sends more
  than three times the number of bytes it has received from that address. As a client establishing
  a connection, colibri is not limited: RFC 9000 §21.1.1.1 says the limit "does not apply to
  clients when establishing a new connection", and §8.1 says why — the client chose the
  Destination Connection ID the server's Initial keys derive from, so a packet it can read at all
  came from the address it sent to. A path validated later by RFC 9000 §8.2.3 is unlimited in
  either role.
- **Mechanism.** Two counters per unvalidated path, checked before every datagram is returned to the
  caller (RFC 9000 §8). The check is on the datagram, not on the frame, because the limit counts
  bytes on the wire. `Path.init` takes how the path begins and the connection answers it from the
  role, so the exemption is decided once rather than at each send.
- **Check.** Runtime assertion before every send on an unvalidated path, plus a simulator
  invariant, plus the interop runner's `amplificationlimit` case. Step 9.
- **Violation.** Counting QUIC frame bytes instead of whole datagram sizes, or counting after the
  send rather than before. Also applying the limit to a client, which leaves it unable to send its
  first Initial at all: a fresh client has received nothing, so three times nothing is nothing, and
  the assertion in `Path.on_datagram_sent` halts on the first datagram.

### INV-19 — flow-control limits are non-decreasing offsets, never credits

- **Claim.** `MAX_DATA` and `MAX_STREAM_DATA` values colibri sends never decrease, and a received
  value that decreases is ignored rather than applied. A stream's final size, once known, never
  changes.
- **Mechanism.** QUIC flow control is a high-water mark and not a credit counter (decision 13),
  so the state is one offset per direction per scope and the update is `@max`. The final size is
  written once through a function that asserts it was unset or equal.
- **Check.** Runtime assertion in both setters, plus a simulator invariant, plus the golden corpus
  case that re-sends a lower `MAX_STREAM_DATA`. Step 9.
- **Violation.** Treating `MAX_DATA` as an increment, which is the h2 habit and silently doubles
  every limit.

### INV-20 — colibri holds one path, and refusing a migration emits nothing

- **Claim.** A connection holds exactly one path for its life, so colibri never initiates a
  migration and never sends anything on a path it did not already have. When a peer migrates,
  colibri emits nothing in response to the migration itself: no Stateless Reset and no
  CONNECTION_CLOSE. What it may send on the one path it holds is RFC 9000 §8's limit, which is
  [invariant 18](#inv-18--the-anti-amplification-limit-holds-and-it-is-the-servers).
- **Mechanism.** `Connection` holds one `Path` and no way to name a second, so a send has no
  other path to choose. No Stateless Reset can be reached from a connection, which is what §9
  forbids as an answer: "Generating a Stateless Reset or closing the connection would allow third
  parties in the network to cause connections to close by spoofing or otherwise manipulating
  observed traffic." `stateless_reset.write` exists, because RFC 9000 §10.3 answers a datagram no
  connection could be found for, and it takes no `Connection` — a migration is something that
  happens to a connection, so a function that cannot see one cannot be called from there. The
  shape is what holds the rule, not the absence of the capability.
- **Check.** A test that `Connection` holds one path and that no function takes a second; a test
  that no function in `src/quic/stateless_reset.zig` takes a `Connection`; a simulator invariant
  that a connection's output is always attributable to the one path it holds.
  The interop runner's `rebind-port` and `rebind-addr` cases are what show a refusing endpoint
  still works, and `connectionmigration` is a case colibri exits 127 on, by decision 21. Step 9.
- **Violation.** A `MIGRATION_REFUSED`-shaped error code, which does not exist in RFC 9000 §20.1
  and would let a third party close connections by spoofing traffic.
- **Why this is not about detecting a migration.** Every rule in RFC 9000 §9 turns on observing an
  address: an endpoint acts "if it detects any change to a peer's address", a server waits until
  it sees "a non-probing packet from that address", and a client discards packets "from an unknown
  server address". Non-negotiable 1 gives colibri no socket, so it never learns an address and
  never compares two, and it therefore cannot tell a migrated datagram from any other. Detecting
  one, and dropping it, is the caller's. This entry used to claim colibri did that, and to name a
  path handle the type system would check — a mechanism for choosing between several paths, which
  decision 21 leaves colibri without.
- See [decisions 21](decisions.md#what-colibri-does-not-build).

### INV-21 — a level is protected only while its keys are available

- **Claim.** colibri calls `seal` and `open` at an encryption level only after the suite said that
  level's keys are available in that direction, and never after colibri discarded them. Once a
  level is discarded nothing is sent at it and nothing received at it is opened.
- **Mechanism.** The connection holds one state per level and direction: none, available,
  discarded. Both call sites assert it. RFC 9001 §4.9 says when the state moves to discarded: the
  Initial keys when a client first sends a Handshake packet and when a server first processes
  one (§4.9.1), the Handshake keys when the handshake is confirmed (§4.9.2).
  [Decision 48](decisions.md#what-the-caller-supplies) leaves every key with the suite, so this
  state is all colibri knows about one. The rule this entry used to hold, that the
  header-protection key is installed once and survives a key update (RFC 9001 §5.4, §6.1), is
  now the suite's to keep, and the null suite models it: a key update changes what its tag is
  computed under and leaves its mask alone.
- **Check.** Runtime assertions at the two call sites (step 9). The null suite answers
  `KeysUnavailable` for a level it never installed or has discarded, and the QUIC simulator
  treats that answer as a violation rather than a lost packet (steps 7 and 8). The interop
  runner's `keyupdate` case is what shows a real suite keeps the header-protection key (step 9).
- **Violation.** Acknowledging an Initial packet in the Initial space after the first Handshake
  packet went out, which a peer that has discarded its Initial keys can never read.

### INV-22 — a version-independent parse reads only RFC 8999 fields

- **Claim.** Before the QUIC version is known, colibri reads only: bit 0x80 of the first byte; for
  a long header, the 32-bit version at offset 1, the DCID length byte, up to 255 DCID bytes, the
  SCID length byte, up to 255 SCID bytes. It reads exactly one packet per datagram at that layer
  and stops.
- **Mechanism.** Two files. `src/quic/packet/invariant.zig` implements RFC 8999 alone and has no
  access to any version-1 constant; the version-1 reader is a separate file that the invariant
  reader never calls. RFC 8999 §5 scopes the invariants to the *first* packet in a datagram, and the
  Length field that makes coalescing parseable is a version-1 field (RFC 9000 §12.2), so the
  invariant layer cannot find the second packet and must not try.
- **Check.** A comptime block in `src/quic/packet/packet_header.zig` reads the invariant file's
  source and fails the build when it imports anything but `std` and `core`, or names the version 1
  connection-ID maximum; it replaces the lint rule this entry first planned, because a build
  that fails cannot be skipped. Golden corpus cases carry connection IDs longer than 20 bytes
  under an unknown version, which must parse rather than fail, and a corpus mutation moves the
  same bytes to version 1, where the version 1 reader must drop them. Step 7.
- **Violation.** Applying RFC 9000's 20-byte connection-ID maximum in the invariant reader, which
  RFC 9000 §17.2.1 forbids from influencing whether a Version Negotiation packet is sent.

## What the caller supplies

### INV-23 — colibri holds no secret

- **Claim.** colibri never holds a private key, a traffic secret, a packet protection key or an
  IV, in either mode, so it has nothing to wipe and nothing to leak.
- **Mechanism.** Neither vtable has a member that takes or returns one. In record mode the
  provider keeps the whole key schedule (decision 8). In QUIC mode the secrets of RFC 9001 §4.1.4
  go from the provider to the suite inside the caller's code, and the suite seals and opens whole
  packets ([decision 48](decisions.md#what-the-caller-supplies)). What colibri keeps from a
  handshake is public on the wire or meant for the application: the ALPN name, the transport
  parameters, the connection IDs.
- **Check.** A test in `src/crypto/suite.zig` compares the vtable's member names with the twelve
  decisions 48 and 55 list, so a member added "to export a secret" fails until the list is changed
  on purpose, beside the decision that forbids it. Decision 55's two are the precedent for how
  that is done: an address validation token needs a key and an expiry, so it went to the suite
  and the list moved with it. Step 7. Step 9's `resumption` case is where a
  session ticket first appears, and it stays with the provider.
- **Violation.** A vtable member that returns a traffic secret so colibri can write a key log.
  The interop runner wants one (design §9), and it comes from the provider. Caching a resumption
  secret across connections "to make reconnects cheap" is the same violation, and is also 0-RTT,
  which decision 20 rules out.

### INV-24 — no assertion is reachable from peer input

- **Claim.** Bad peer input produces an error value and a closed connection, never an abort.
  Assertions guard programmer error only: contract points, state-enum validity, and arithmetic
  colibri controls.
- **Mechanism.** Parsers return error unions. Assertions run at function entry and exit on values
  colibri computed, never on values it just read off the wire.
- **Check.** Fuzzing every parser to exhaustion with abort-on-panic, which is the direct test of
  this claim, plus convention on where an assert may be written. Steps 1, 4, 9.
- **Violation.** `assert(frame_len <= max_frame_size)` on a value read from the wire, which turns
  a conformance test into a crash.

### INV-25 — a suite that cannot protect Initial packets is a configuration error

- **Claim.** A suite that refuses `install_initial_keys` ends the connection with a configuration
  error the caller sees, distinct from every protocol error, and nothing is sent to the peer. A
  client learns it when the connection is constructed; a server learns it at the first Initial
  packet, which is the first moment it has the Destination Connection ID the keys derive from
  (RFC 9001 §5.2).
- **Mechanism.** RFC 9001 fixes Initial packets (§5, §5.2), the header protection used before a
  suite is selected (§5.4.1, §5.4.3) and the Retry tag (§5.8) to AES whatever TLS negotiates, so a
  suite without AES cannot start a connection at all.
  [Decision 48](decisions.md#what-the-caller-supplies) leaves colibri unable to see what a suite
  carries, so the one call that shows it is the check. A suite that lacks the AEAD or
  header-protection algorithm TLS goes on to negotiate (§5.3, §5.4.1) fails the same way at the
  first Handshake packet, with the same error class.
- **Check.** A unit test per refusal, with a suite that refuses, once the connection exists
  (step 9). The error set of `install_initial_keys` carries the refusal from step 7.
- **Violation.** Reporting the refusal as a handshake failure, which sends the peer a
  CONNECTION_CLOSE for the caller's own misconfiguration and looks like an attack in the log.
- See [decisions 9 and 48](decisions.md#what-the-caller-supplies).

### INV-26 — `quic` imports no HTTP module

- **Claim.** `src/quic/` never imports `http`, `h2`, `h3`, `hpack` or `qpack`, and contains no
  identifier naming an HTTP concept.
- **Mechanism.** The module graph in `build.zig` gives `quic` only `core`, `wire`, `crypto` and
  `tls`. A module can import only what the build gives it, so a forbidden import does not
  compile.
- **Check.** Type system, by way of the build graph — and the check that proves it is that the QUIC
  simulator builds and runs with no HTTP module in the graph at all. A lint rule covers the
  identifier half. Steps 0 and 8.
- **Violation.** A stream-type constant for h3's control stream inside `src/quic/`, which is how a
  transport quietly becomes an HTTP transport.
- See [decisions 3, 5](decisions.md#scope-and-shape).

## Errors

### INV-27 — a connection error and a stream error are distinct types

- **Claim.** The two error classes never coerce into one another. A function that can only produce
  a stream error cannot return a connection error, and the compiler says so.
- **Mechanism.** Two Zig error sets per protocol, and the escalation from stream to connection is
  an explicit function with the RFC section that justifies it cited on the line. The cases that
  need this are three: RFC 9113 §4.2 makes a frame-size error a *connection* error when it appears
  in a frame that could alter connection state; RFC 9114 §4.1 makes a `DATA` frame before any
  `HEADERS` a *connection* error rather than a stream error; and an undefined pseudo-header makes a
  message malformed (RFC 9113 §8.3), which §8.1.1 makes a *stream* error, which makes
  refusing extended CONNECT free (decision 19).
- **Check.** Type system, plus h2spec and h3spec, which assert the exact error code and level per
  case. Steps 4 and 12.
- **Violation.** One `ProtocolError` set for both, so an unexpected `:protocol` closes the
  connection instead of the stream, and every extended-CONNECT client sees colibri as broken.

### INV-28 — an error's wire code is chosen in one place per protocol

- **Claim.** Each protocol has exactly one function mapping an internal error to a wire error
  code, and no other site writes a numeric error code.
- **Mechanism.** One `wire_code` function per protocol, with the RFC's code table beside it: RFC
  9113 §7 for h2, RFC 9114 §8.1 for h3, RFC 9000 §20.1 for QUIC transport, RFC 9204 §6 for QPACK,
  and RFC 9001 §4.8's rule that a TLS alert becomes `0x0100 + AlertDescription`.
- **Check.** Lint rule (no integer literal in an error position outside the mapping file), plus
  golden corpus cases naming the expected code per error. Steps 4, 9, 12.
- **Violation.** A hand-written `0x02` at a call site. It is `INTERNAL_ERROR` in h2 and
  `CONNECTION_REFUSED` as a QUIC transport code, and it is not an h3 error code at all — h3's
  space starts at 0x0100, and RFC 9114 §8.1 makes an unrecognised code equivalent to `H3_NO_ERROR`,
  so the literal silently means "no error" in h3.
