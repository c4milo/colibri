# Decision 60: One call takes a received datagram

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23, and amended the same day by entry 62, which has colibri, not the
caller, mark each level's keys installed.

Receiving a datagram took seven steps, and no library code ran them. They were: count the
datagram toward RFC 9000 §8.1's limit; walk its packets (§12.2); process each packet's
frames; record each packet in its space once its frames are processed (§13.1); discard the
Handshake keys when a HANDSHAKE_DONE arrives (RFC 9001 §4.9.2); hand the provider what arrived
(§4.1.3); and ask whether the handshake completed (§4.1.1). Only tests ran them, each in its
own order. A Retry or a Version Negotiation packet needed a function of its own besides.

So `connection_datagram.receive` takes one datagram and runs every step in the order the RFCs
set. That is CLAUDE.md's "cross the caller's boundary in bulk" for the receive side. It reports
the peer's CONNECTION_CLOSE, the streams that finished, and what a Retry or a Version
Negotiation packet did. An error is a connection error, and
`connection_datagram.connection_error_code` names its code. The caller still owns the bytes,
the instant and the scratch (decision 35), and still installs each level's keys as its provider
produces them (decision 48).

The alternative refused: the caller keeps the steps, and the simulator is the reference
caller that every other caller copies. A caller that records a packet before its frames, or
never counts a datagram, then breaks §13.1 or §8.1 with nothing to say so. It is decision 59's
reasoning, applied to the receive side.
