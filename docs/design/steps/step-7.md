# Design §8 step 7: QUIC packet formats and the crypto vtable

[Design §8, the build plan](../../design.md#8-build-plan)

The RFC 8999 invariant reader as its own file with an empty import set, the version-1 reader above
it, long and short headers, packet number encoding and decoding, the Initial key schedule, packet
protection, header protection, Retry integrity. **Check:** RFC 9001 Appendix A's sample packet
protection, byte for byte, in the golden corpus; RFC 9000 Appendix A.2 and A.3's packet number
encoding and decoding; corpus cases with connection IDs longer than 20 bytes under an unknown
version, which must **parse** rather than fail; a mutation that applies the 20-byte cap in the
invariant reader, reported `CAUGHT`; fuzzing of the packet reader. *Medium to large.*

**The formats, 2026-09-19.** The half of this step that touches no key is built, in
`src/quic/packet/`. `invariant.zig` reads RFC 8999 alone: the Header Form bit, the long header's
Version and connection IDs of 0 to 255 bytes, the short header, and the Version Negotiation
packet of §6 in both directions. It imports `std` and `core` and nothing else, and a comptime
block in `packet_header.zig` fails the build if it imports a third module or names version 1's
connection ID maximum ([invariant 22](../../invariants.md#inv-22)).
`packet_header.zig` is the version 1 reader above it (RFC 9000 §17): the four long types, the
Initial token, the Length that ends a packet so the next one of the datagram can be read
(§12.2), Retry with its tag, and the short header. It reads as far as header protection
allows and reports where the Packet Number field starts; `unprotected_long` and
`unprotected_short` read byte 0 once protection is removed, and refuse set Reserved Bits.
`packet_header_write.zig` writes the same headers and the Retry Pseudo-Packet of RFC 9001 §5.8.
`packet_number.zig` is Appendix A.2 and A.3.

What was checked, on macOS 25.6 arm64, with `zig build test` at 685 of 685:

- The writers produce RFC 9001 Appendix A's published headers byte for byte: the client
  Initial of A.2, the server Initial of A.3, the Retry packet of A.4 less its tag, and the short
  header of A.5. The reader takes A.4's Retry packet apart into its fields.
- Packet numbers: A.2's two sample encodings and A.3's sample decoding, the boundary of every
  field length, and every length encoded and decoded back. Appendix A.3's sample leaves one
  case out: when the largest number processed is 2^62-1 every candidate is a window past the
  largest packet number §12.3 permits. `decode` returns the number one window below, which is
  the closest one that exists.
- The golden corpus gains two formats, `quic_invariant` with 8 cases and `quic_packet` with 18,
  and seven mutations. Connection IDs of 21 bytes parse under an unknown version in both
  readers, and the same bytes are dropped once one edited byte makes the version 1.
- Both readers have a fuzz property, run over a corpus and over every input of up to two
  bytes: a header that is read accounts for every byte of its datagram.

Mutations: 34 applied over the four files, each against `zig build test-quic` and
`zig build test-golden`. 32 were **CAUGHT**, the one this step names among them: the 20-byte
maximum applied inside `invariant.zig` fails both. One was **NOT CAUGHT**, a decode that leaves
the last window upward, and got its test. The last removed the comptime guard of invariant
22, which no test can see; it was replaced by three mutations that break what it guards — a
third import, an import of the version 1 constants, and the maximum's name — and each fails
the build.

**The crypto vtable, 2026-09-19.** The owner ruled the same day
([decision 48](../../decisions/0048-the-suite-holds-every-key-and.md)): the suite holds every key and protects
every packet, and colibri holds none. So this step no longer builds the Initial key schedule,
packet protection, header protection or the Retry tag, which its first sentence still lists as
it was planned. It builds what calls them. `src/crypto/suite.zig` is the vtable: ten members,
each about a whole packet at an encryption level, and none that takes or returns a key. A test
holds the member names to the decision's list
([invariant 23](../../invariants.md#inv-23)). The `Suite` wrapper asserts
colibri's half of the contract: a packet number inside its range, a Packet Number field of 1 to
4 bytes, and the four bytes RFC 9001 §5.4.2 needs before the sample. Recovering a packet
number (RFC 9000 Appendix A.3) moved to `src/crypto/packet_number.zig`, because §9.5 makes it
the suite's step; `quic` keeps Appendix A.2, and its tests encode with one module and decode
with the other.

`src/sim/null_suite.zig` fills the vtable with no cryptography
([issue 4](https://github.com/c4milo/colibri/issues/4)). It is size-faithful, as §10 requires:
header, payload and a 16-byte tag, with byte 0 and the Packet Number field masked from a
16-byte sample four bytes past the field. It models keys as names, because colibri's
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
256 seeds, 512 packets, 128,870 bytes, every field length drawn, digest `0xf0818926` in Debug
and in `-Drelease`, on macOS 25.6 arm64. The check's module imports `sim` and `quic` and no
HTTP module, so it is also the first build that holds
[decision 5](../../decisions/0005-quic-knows-nothing-about-http.md)'s boundary; step 8 inherits that root. It has no
command line until step 8, and its test pins the digest.

`zig build test` passes 705 of 705. Mutations: 30 applied over the null suite, its keys, and
three places where framing and protection must agree (the Length counting the tag, the
reported offset of the Packet Number field, the field's length). All 30 **CAUGHT**; the three
cross-module ones are caught by the packet check and by `quic`'s own tests.

**Still owed for the step.** RFC 9001 Appendix A's sample packet protection, byte for byte.
Under decision 48 those vectors check a provider through the vtable, so they need chapulin's
`ch_quic_*` calls, which chapulin implemented on 2026-09-20, and they will run from
`src/testing/` and not from
the corpus, whose cases are 64 bytes at most. The headers of those samples are already
checked, byte for byte, above.

**Check passed, 2026-09-25**, on macOS arm64 with Zig 0.16.0 and chapulin's QUIC object at
`b32ad68`. `src/testing/quic/protection_vectors.zig` runs RFC 9001 Appendix A through
`crypto.Suite` as chapulin fills it, with the hex copied from `docs/rfcs/rfc9001.txt` line for
line. One client session, holding the A.1 connection ID's Initial keys:
- A.2: seals the client's Initial, which comes out as the published 1200 bytes;
- A.3: opens the server's published Initial, which gives back its header, packet number 1 and
  its 99-byte payload, with the keys of the other direction;
- A.4: checks the Retry Integrity Tag over the pseudo-packet colibri's
  `write_retry_pseudo_packet` builds, and chapulin writes the published tag over it.

A.1's keys are what makes A.2 and A.3 match byte for byte. A.5 is chapulin's to check, and
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
- `encode_none`: `encode` refuses exactly when four bytes do not;
- `decode_closest`: `decode` rebuilds every packet number within half a window of the one
  expected;
- `decode_encode`: a receiver that has processed at least the number the sender saw
  acknowledged, and none at or past the one sent, rebuilds the number `encode` truncated;
- `decode_bound` and `decode_field`: any field decodes to a packet number (§12.3) that ends in
  the field's bytes;
- `field_read_write`: the field's bytes, most significant first, read back to its value.

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
