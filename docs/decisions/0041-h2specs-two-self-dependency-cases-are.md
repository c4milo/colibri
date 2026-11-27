# Decision 41: h2spec's two self-dependency cases are skipped, because RFC 9113 is the authority

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-18. h2spec 2.6.0 runs `http2/5.3.1/1` and `/2`, which send a HEADERS
frame and a PRIORITY frame whose stream depends on itself and require a stream error of
PROTOCOL_ERROR. That rule is RFC 7540 §5.3.1. RFC 9113 obsoletes RFC 7540, §5.3.2 drops the priority
scheme and says its text is not included, and §6.3 keeps two rules about PRIORITY, both of which
colibri enforces: a stream identifier of 0x00 is a connection error of PROTOCOL_ERROR, and a
PRIORITY frame may not come between the frames of a field block.

colibri parses the priority fields and acts on none of them (entry 18), so a stream that
depends on itself is a signal it ignores rather than an error it reports. The alternative lost
is adding the check for the suite's sake, which would put a rule in the code that the RFC
colibri implements does not state, cited to a document CLAUDE.md forbids reading. The cost is
that h2spec never prints 146 of 146; `tools/h2spec.sh` names the two cases and fails if any
other case fails.
