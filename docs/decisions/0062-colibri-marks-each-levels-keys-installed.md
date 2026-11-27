# Decision 62: colibri marks each level's keys installed, reading them from the suite, before the next packet

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23. It amends entry 60 and settles
[#45](https://github.com/c4milo/colibri/issues/45).

Entry 60 had the caller mark each level installed once `receive` returned. A server's first
datagram coalesces its Initial packet, which carries the ServerHello, with Handshake packets
(RFC 9000 §12.2). The client had no Handshake keys while it walked that datagram, so it dropped
the Handshake packets, and every handshake waited for the server to send them again. A 1-RTT
packet coalesced behind the client's Finished was dropped at the server the same way. RFC
9001 §4.1.4 says an endpoint "SHOULD buffer received packets if they might be processed using
keys that are not yet available".

So `receive` advances the handshake after each packet it processes. It hands TLS the bytes
that packet's CRYPTO frames completed, takes the peer's parameters and asks whether the
handshake completed. Then it asks `crypto.Suite.keys_available` about each level and
direction still in state `none` (invariant 21) and marks the ready ones installed, before it
walks to the next packet. `receive` and `send` ask the same at their start, which covers the
Initial keys. The caller still derives the Initial keys (RFC 9001 §5.2) and still moves each
level's secrets from its provider to its suite (entry 48). It no longer tells colibri about
either.

Cost: during the handshake, a few provider calls per datagram instead of one, and one
`keys_available` call per level still waiting. Once every level is available or discarded,
the question asks the suite nothing. A peer that coalesces a packet ahead of the one that
makes its keys still loses it, which §12.2 asks senders not to do.

Two alternatives were refused. `receive` could report the packets it refused for want of keys
and the caller feed them in again, but their bytes would count twice toward RFC 9000 §8.1's
limit unless a second entry point skipped the count. Leaving it costs every handshake at least
one round trip.
