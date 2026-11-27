# Decision 5: `quic` knows nothing about HTTP

[All decisions](../decisions.md) · Section: [Scope and shape](../decisions.md#scope-and-shape)

RFC 9000 defines a transport with streams and no opinion about payloads. Cost: h3 cannot use a QUIC
internal as a shortcut, and anything h3 needs from a stream must be expressible in transport terms.
Gain: the boundary is the same one the RFCs draw, so a rule is only ever in one place, and the QUIC
simulator is a transport simulator that no HTTP change can perturb. Violation: a `if (stream_type ==
control)` inside `src/quic/`.
