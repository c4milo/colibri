# Decision 23: Multipath: no, and there is nothing to decline

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

RFC 9000 is single-path by construction — §9.3 chooses the active path by the highest-numbered
non-probing packet, one integer of state. Multipath is an extension defined outside the set colibri
read, and RFC 9000 §7.4.2 says the absence of a transport parameter disables any optional feature
negotiated by it, so the conformance cost of saying no is zero. The one related obligation is to
ignore reserved transport-parameter identifiers of the form 31*N+27 (§18.1), which exist to exercise
that ignore path — and colibri tests it rather than assuming it.
