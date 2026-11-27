# Decision 4: Client and server, both, from the first step

[All decisions](../decisions.md) · Section: [Scope and shape](../decisions.md#scope-and-shape)

Cost: roughly a third more state machine — stream-id parity in both directions (RFC 9113 §5.1.1),
the two connection prefaces (§3.4), and both halves of every settings exchange. Gain: the
conformance suites are server-side (h2spec, h3spec) and the interop runner needs both roles (design
§9), so a client-only library could not be tested against anything. The server also *is* the product
for stompy's `ops-api` and `platform-api`; a client-only library would be half a deliverable.
