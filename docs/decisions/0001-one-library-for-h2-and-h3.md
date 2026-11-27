# Decision 1: One library for h2 and h3, not two in one repository

[All decisions](../decisions.md) · Section: [Scope and shape](../decisions.md#scope-and-shape)

Cost: a module graph that has to be defended, and a build that must prove the boundaries rather than
assert them (§3 of docs/design.md). Gain: the code both protocols share — the Huffman coder, the
prefixed integer codec, the RFC 9110 semantics core, the field validators, and every harness — is
written once and tested once. Entries 11 to 16 say exactly what shares and what does not, each from
the RFC text rather than from the shape of the two protocols.

Two separate libraries was the alternative. It was rejected because the shared surface is not
incidental: RFC 9204 §4.1.2 adopts the RFC 7541 Appendix B Huffman code "without modification",
and RFC 9114 §4.2 delegates the connection-specific field rules to RFC 9110 §7.6.1 rather than
restating them. Two libraries would copy both, and two copies of a 257-symbol code table diverge
over time.
