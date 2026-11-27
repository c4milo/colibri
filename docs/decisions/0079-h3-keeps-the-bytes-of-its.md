# Decision 79: h3 keeps the bytes of its own three streams, and the caller keeps every request stream's

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24, for design §8 step 12. Entry 57 left the bytes h3 writes itself
for h3 to settle.
- The control stream and QPACK's encoder and decoder streams are h3's. It writes them and
  holds each in a fixed buffer on the h3 connection. It drops the part below the stream's
  acknowledged end (entry 78) and moves the rest to the front, so the free room is one slice
  a writer can fill. A buffer with no room never drops a byte. The encoder then does not
  insert, and the decoder holds the instructions it owes, as entry 74 has it.
- A request stream's bytes are the caller's: the HEADERS frame, each DATA frame's header, and
  the body. h3 writes the frames' bytes into the caller's buffer, as `h2`'s write path does.
  The caller keeps them with the body until the stream reaches "Data Recvd" or is reset. h3
  keeps nothing per request stream but its state.
- h3 hands `quic` one stream provider. It answers h3's three streams from the rings and
  passes every other stream to the caller's provider.

The alternative refused: h3 keeps the frame bytes of each request stream and asks the
caller's provider for body bytes only. The caller's provider is simpler. But h3 would then
hold up to one encoded field section per open stream, `field_section_size_max` bytes each,
in memory decision 35 counts.
