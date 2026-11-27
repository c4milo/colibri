# Decision 43: The record-mode vtable carries `negotiated_parameters`, an eleventh member

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-18, amending entry 8. The member returns the version and cipher suite
codepoints the handshake selected, or null before it has them. RFC 9113 §9.2 puts a MUST on
implementations of HTTP/2 to use TLS 1.2 or higher, and colibri is the implementation that sentence
addresses; §9.2.2 lets an endpoint answer a suite Appendix A prohibits with INADEQUATE_SECURITY, and
it puts a MUST NOT on generating that error for any suite that is not prohibited, which needs the
exact codepoint rather than a summary. Entry 8's ten members supply neither number.

The alternative lost is enforcing none of §9.2 and recording that compliance is the
deployment's, which §9.2's own closing sentence would support. It was rejected because the
version floor is a MUST addressed to implementations. Reading two codepoints is not a crypto
operation: colibri chooses no suite and holds no key, so non-negotiable 2 is untouched.

§9.2.1 and §9.2.2 are TLS 1.2 rules alone. §9.2 says so: deployments that negotiate TLS 1.3
are subject to §9.2.3 instead. A check reads the version first and skips the whole set on
1.3, where §9.2.3's one rule is that a post-handshake CertificateRequest is a connection error
of PROTOCOL_ERROR, which `decrypt_record`'s `Content` already carries.
