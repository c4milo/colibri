# Decision 70: A PTO also probes every other packet number space that has ack-eliciting packets in flight, one packet each, coalesced into the same datagram when it fits

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24. It takes RFC 9002 §6.2.4's SHOULD, which colibri had not.

§6.2.4: "In addition to sending data in the packet number space for which the timer expired,
the sender SHOULD send ack-eliciting packets from other packet number spaces with in-flight
data, coalescing packets if possible. This is particularly valuable when the server has both
Initial and Handshake data in flight or when the client has both Handshake and Application
Data in flight because the peer might only have receive keys for one of the two packet
number spaces."

A colibri pair failed the QUIC Interop Runner's handshake loss case that way: the datagram
carrying the server's ServerHello was lost, and the server's Handshake probes arrived at a
client that could not read them. The simulator's copy of the runner's network (2,000 seeds,
30% loss each way, at most three in a row) showed the same stall: one seed took 43 seconds to
confirm the handshake. With this rule it took 15, and seeds at 16 seconds or more fell from
11 to 3.

Each other space's packet follows the rule of its level: decision 64 declares an Initial or
Handshake space's packets in flight lost, so the probe carries their CRYPTO bytes, and
decision 66 declares the oldest application packet lost.

The alternative refused: probing only the space whose timer expired, which is what colibri
did, and which leaves the peer holding packets it has no keys for.
