# Design §8 step 9a: the frame layer

[Design §8, the build plan](../../design.md#8-build-plan)

Every frame type of RFC 9000 §19, read and written.
**Check:** each type round-trips, every rule §19 states as a FRAME_ENCODING_ERROR refuses the
frame it names, and a frame cut anywhere is a truncation that consumes nothing. *Small.*

**The frame layer, 2026-09-19.** `src/quic/frame/` reads and writes all twenty frame types of
RFC 9000 §19. It is the piece of this step that needs no key, no handshake and no connection
state: a frame is read out of bytes and written into them, and what it means is the
connection's business.

Three types carry their shape in the type itself, and each is decoded into a field so nothing
downstream reads a bit out of a number: a STREAM frame's OFF, LEN and FIN bits (§19.8), an ACK
frame's ECN bit (§19.3.2), and the directionality bit of MAX_STREAMS and STREAMS_BLOCKED
(§19.11, §19.14). A CONNECTION_CLOSE carries the frame type that caused it only when it speaks
for the transport (§19.19).

ACK ranges are walked, not expanded. A frame names the largest packet number acknowledged and
then descends through alternating gaps and runs, so expanding it into a set would cost storage
proportional to what a peer claims. `AckRanges` keeps the bytes and yields one range at a
time, and the arithmetic is checked once when the frame is read: §19.3.1 makes a computed
packet number below zero a connection error, so a later walk cannot fail.

Every rule §19 states as a FRAME_ENCODING_ERROR is enforced and cited on the line that
enforces it: a range below zero (§19.3.1), a stream or crypto offset past 2^62-1 (§19.8,
§19.6), an empty NEW_TOKEN (§19.7), a stream limit above 2^60 (§19.11, §19.14), a connection
ID outside 1 to 20 bytes and a Retire Prior To above its own Sequence Number (§19.15), and a
frame of unknown type (§12.4), which is refused rather than ignored because §12.4 admits no
extension frame this version does not define.

`zig build test` passes 734 of 734 and the lint is clean. Two of its rules caught real defects
while this landed. `peer-index` found the reader's bytes being indexed directly, which
invariant 3 forbids; `core.Reader` now has `consumed_since(mark)`, so a parser that learns a
structure's length only by reading it still takes its slice from the reader. `rfc-citation`
found two refusals whose citation sat a line away from the check.

Mutations: 27 applied, 26 **CAUGHT** and one equivalent. Two gaps were real and both were in
the tests: three frame types were missing from the round-trip table, so nothing cut a
CONNECTION_CLOSE short, and nothing checked that a frame too large for the buffer writes
nothing at all. The equivalent one replaces the bound on the ACK range walk with a huge
number. Each turn of that loop reads two variable-length integers and each needs a byte, so
the reader ends the loop whatever the bound says; the bound is there because non-negotiable 4
asks for one a reader can see.

**Fuzzing, 2026-09-26.** `frame_fuzz.zig` reads a payload frame by frame, as a connection
does ([#53](https://github.com/c4milo/colibri/issues/53)). Three things must hold:
- A refused frame consumes nothing.
- A frame that is read keeps every rule the writer asserts, so no peer's frame can halt colibri
  when it is written again.
- A frame is written with the type it was read from, and reads back as the same frame.

It runs over 23 corpus inputs, most of them one on each side of a §19 refusal, and over every
input of up to two bytes; the fuzzer does not build with Zig 0.16.0 (step 1). 18 mutations,
18 **CAUGHT** by the fuzz test alone: ten §19 refusals removed or loosened, a refusal that
consumes bytes, three writer faults, and four type bits misread, which the round trip saw only
once it compared the types.

**The input check, 2026-09-26.** `src/sim/quic_input_check.zig` gives the QUIC readers inputs
longer than two bytes, as `qpack_input_check.zig` does for QPACK ([#53](https://github.com/c4milo/colibri/issues/53)). Each input starts
from what colibri's writer produces and takes up to eight edits from `src/sim/input_edit.zig`,
which gained a fifth edit: a byte moved up or down by one, which takes a value at a bound
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
misses, and a one-byte edit cannot reach two of them: `max_ack_delay`'s bound needs a longer
encoding than the writer uses, and `active_connection_id_limit`'s is its default, which the
writer leaves out. The third, a CRYPTO offset one past 2^62-1, did not come up in 32,768
inputs.
