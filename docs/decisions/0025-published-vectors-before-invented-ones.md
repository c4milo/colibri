# Decision 25: Published vectors before invented ones

[All decisions](../decisions.md) · Section: [Correctness](../decisions.md#correctness)

HPACK and the h2 frame layer both have published corpora and colibri uses them rather than writing
its own: `http2jp/hpack-test-case` and `http2jp/http2-frame-test-case`. **Correction worth
recording:** there is no `httpwg/hpack-test-case`; that path does not exist, and the canonical
repository is `http2jp/`. Decode every encoder directory in it, not only nghttp2's — the naive,
static and linear strategies crossed with Huffman and plain are what exercise the dynamic table and
the Huffman paths.

QPACK's equivalent is `qpackers/qifs` in the QIF format, and its maturity must be stated
rather than assumed: its newest outputs target draft-ietf-quic-qpack-05 rather than RFC 9204,
and the repository has not moved since January 2021. A mismatch is checked against the RFC
first and is not automatically colibri's bug. RFC 9204 Appendix B carries the only reference
encodings inside the RFC itself, and RFC 9001 Appendix A carries sample packet protection —
both are corpus cases in `src/golden/` on the first commit of their step.
