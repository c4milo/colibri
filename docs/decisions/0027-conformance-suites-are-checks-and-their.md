# Decision 27: Conformance suites are checks, and their versions are pinned

[All decisions](../decisions.md) · Section: [Correctness](../decisions.md#correctness)

h2spec for the h2 server, h3spec for the h3 server. Both need a test-only server entry point, which
design §9 names, and their maturity is not equal: h2spec has 147 cases but is written against RFC
7540 and 7541 rather than 9113, with its last release in 2020 — so its version is pinned and a
disagreement is checked against RFC 9113 before it is treated as colibri's bug. h3spec is narrower,
roughly 50 cases and error cases only, with no happy path and no flow control, but it is the better
maintained of the two. Neither is sufficient alone, so entry 28 adds interop testing.
