# Decision 148: Prague congestion control: no

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

Ruled by the owner on 2026-11-04, during https://github.com/c4milo/colibri/issues/123. Prague is the
scalable controller of L4S, after DCTCP. Its one document is
draft-briscoe-iccrg-prague-congestion-control-04 of July 2024, an individual draft for Experimental
status, which expired in January 2025. Its authors write that their code does not yet meet all of
Prague's requirements. colibri reads RFCs and the drafts its decisions pin (non-negotiable 10), and
an expired individual draft is a poor one to pin. Prague also gains only where the bottleneck runs
an L4S queue (RFC 9330 to RFC 9332), which few paths do. colibri asks again if ICCRG publishes
Prague.

Cost of refusing: nothing on the wire. colibri marks its packets ECT(0) (RFC 9000 §13.4.2),
never ECT(1), which RFC 9331 gives to L4S, so no L4S queue takes its packets as Prague's.
