# Decision 45: colibri admits TLS 1.3 alone, and three cipher suites

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-18. The negotiated version must be 0x0304, and the suite must be one
of TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256 (RFC 9846 Appendix
B.4). These are the three RFC 9846 §9.1 names: a compliant application MUST implement the first and
SHOULD implement the other two. They are also the three RFC 9001 §5.3 permits for QUIC, which
excludes TLS_AES_128_CCM_8_SHA256 by name for its 64-bit tag, so h2 and h3 admit the same set.

RFC 9113 §9.2 makes TLS 1.2 the floor. Admitting 1.3 alone is stricter than the floor and so
inside it; a peer that offers less is refused before any HTTP/2 byte moves, and §7's
INADEQUATE_SECURITY names the class.

The alternative lost is honouring §9.2 as written: admit TLS 1.2 and refuse the suites
RFC 9113 Appendix A prohibits. It fails on a practical point that is worth recording, because
it is not obvious. Appendix A lists 276 suites **by name with no codepoint**, and the wire
carries a codepoint. Mapping one to the other needs the IANA TLS Cipher Suite registry, which
is not an RFC and is not in `docs/rfcs/`, so the check could not be written from the documents
non-negotiable 10 permits. An allowlist needs no registry: Appendix B.4 carries the five
TLS 1.3 codepoints in the RFC itself. The narrower rule is both safer and the only one this
repository can source.
