# Decision 11: The Huffman coder and the prefixed-integer codec are shared, and both are RFC 7541's

[All decisions](../decisions.md) · Section: [What is shared between h2 and h3](../decisions.md#what-is-shared-between-h2-and-h3)

RFC 9204 §4.1.2 says the Huffman table of RFC 7541 Appendix B "is used without modification": 257
symbols, codes of 5 to 30 bits, EOS = 0x3fffffff. One table in `.rodata`, one coder, no divergence.
The coder also implements the three mandatory decode errors of RFC 7541 §5.2: padding strictly
longer than 7 bits, padding that is not the high bits of EOS, and a complete EOS inside the data.

The two padding rules reduce to run-of-ones arithmetic on the tail, because EOS is thirty set
bits. **The third does not, and a decoder written as though it did rejects legal input.** A run
of thirty ones can be produced by adjacent long codes with no EOS present: Appendix B's symbol
204 is 27 bits ending in five ones and symbol 22 is 30 bits beginning with twenty-nine, so the
two-byte string `0xCC 0x16` encodes to a run of thirty-four ones containing no EOS. EOS must
therefore be detected at a symbol boundary inside the decode loop, never by scanning for a run.

**Correction to a premise:** the prefixed integer codec is shared too. RFC 9204 §4.1.1 says "The
format from [RFC7541] is used unmodified", so HPACK and QPACK read the same integers. The
distinction is easy to miss: QUIC's variable-length integer (RFC 9000 §16) is a *different*
primitive, used by the QUIC and h3 framing layers and never by a field-section representation.
colibri therefore has two integer codecs, and the split is not h2-against-h3 — it is *field
compression* against *framing*. `src/wire/` holds both codecs and its file header states the
split.

Two details the codec must carry: QPACK uses prefix widths HPACK never uses (RFC 9204 §4.1.1
notes it), so the codec is generic over N in 1..8 rather than specialised to HPACK's 4, 5, 6
and 7; and RFC 9204 §4.1.1 requires decoding integers up to and including 62 bits, where RFC
7541 §7.4 only says to pick a limit. Size for 62 bits and both are satisfied.

One more shared piece: the dynamic-table size formula. RFC 7541 §4.1 and RFC 9204 §3.2.1 give
the same rule word for word — name length plus value length plus 32, measured on the
unencoded strings — and the eviction loop is the same shape. The arithmetic is shared; the
tables are not, which is the next entry.
