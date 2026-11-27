# Decision 64: A PTO at the Initial or Handshake level declares that level's packets in flight lost, so its probe carries their CRYPTO bytes

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23. It keeps entry 57's rule that no byte is in two packets at once,
and settles the QUIC Interop Runner's handshake loss case.

A probe (RFC 9002 §6.2.4) carried new bytes or a PING, and at the handshake levels there are
rarely new bytes, so it carried a PING. Lost CRYPTO bytes were sent again only once an
acknowledgment showed them lost. Under bursty loss the probes that did arrive gave the peer
nothing it could use, and the runner's handshake loss case failed in both roles.

§6.2.4 offers: "instead of sending an ack-eliciting packet, the sender MAY mark any packets
still in flight as lost." colibri does that at the Initial and Handshake levels when their PTO
fires, and then sends the probes. Their CRYPTO bytes enter the lost ranges, so the probes
carry them, and each byte is still in exactly one place.

These packets are declared lost to move their bytes, not because the path signalled
congestion, so they are no congestion event. §6.2.4 names "an unnecessary rate reduction by the
congestion controller" as the risk of this choice, and colibri takes none.

Two alternatives were refused. Letting a probe repeat bytes still in flight breaks entry 57's
rule, and the CRYPTO stream's accounting would have to take one byte in two packets. Leaving
PING-only probes keeps every lossy handshake waiting on a round trip it need not.

Amended by the owner on 2026-09-28: when a PTO at the Initial or Handshake level owes two
probes and the first carries all of the level's CRYPTO bytes, the second carries them again
in place of a PING. This reverses the first alternative refused above, for CRYPTO bytes
alone.
- In the QUIC Interop Runner's `handshakeloss` case against quic-go, colibri's client lost 2
  of 8 runs to one pattern. Its Finished went in one probe datagram and a PING in the other,
  the network dropped the Finished's copy each time, and quic-go's server dropped the
  connection after 5 seconds without a packet from the client
  ([#72](https://github.com/c4milo/colibri/issues/72)). In both runs a PING arrived where a
  second copy of the Finished would have ended the handshake.
- RFC 9002 §6.2.4 permits it: "Previously sent data MAY be sent if no new data can be sent",
  and a second datagram is there "to avoid an expensive consecutive PTO expiration due to a
  single lost datagram". RFC 9000 §2.2 has the receiver discard bytes it already holds.
- The CRYPTO accounting already takes it. A CRYPTO stream keeps no record of which bytes
  were acknowledged: a lost packet rewinds the level's send offset, "the lowest rewind wins",
  and nothing is tracked per packet. So a copy in flight changes no count. Stream bytes keep
  entry 57's rule and INV-29 unchanged.
- `Connection.crypto_probe_from` notes where the PTO's rewind left each level. A packet
  built while a probe is owed, with nothing left unsent at its level, rewinds there and
  frames the bytes again. A single probe, such as decision 70's in another space, and a
  flight longer than one packet, whose second probe carries the next bytes, are as before.
