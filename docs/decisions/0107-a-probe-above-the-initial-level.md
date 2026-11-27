# Decision 107: A probe above the Initial level repeats the latest ACK frame

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-09-28 for [#76](https://github.com/c4milo/colibri/issues/76); the owner may overrule
it.

RFC 9000 §13.2: "When sending a packet for any reason, an endpoint SHOULD attempt to include
an ACK frame if one has not been sent recently." colibri wrote an ACK frame only when its
space owed one or had new ack-eliciting packets, so once its ACK frames were lost, a probe
carried a PING alone. In the QUIC Interop Runner's `handshakeloss` case, quinn's client lost
its request, and colibri's server acknowledged the client's later packets in five packets the
network dropped. The server's probes then carried PINGs, the client never learned which of
its packets arrived, and it never sent the request again.
- A PTO fires when none of an endpoint's recent packets was acknowledged, and the ACK frames it
  sent in them may be what the path lost. So each probe at the Handshake or application level
  carries its space's latest ACK frame, as a packet to a path awaiting validation does
  (decision 72).
- An Initial probe does not. RFC 9002 §5.3 lets the peer ignore the ACK Delay of an Initial
  ACK, as colibri does. An old one repeated gives the peer a round trip that includes the
  whole wait, and a probe timeout as long.

Over 256 seeds of the simulator's QUIC connection check, against the rule before it:
- on the network that drops every datagram of ACK frames alone, the median handshake took
  604 ms instead of 1,078, and the mean transfer 784 ms instead of 953;
- on the handshakeloss network, the mean handshake took 989 ms instead of 1,092 and the
  slowest 8.2 s instead of 10.3, and the mean transfer 1,164 ms instead of 1,325;
- on the lossy network and the two rebinding networks, the mean handshake took 0.9% less, and
  the mean transfer 0.3% to 0.6% more.

The alternatives refused:
- Repeat it at the Initial level too. On the handshakeloss network one seed's handshake took
  16.5 s instead of 5.1, and another seed's transfer 48.8 s instead of 17.4.
- Repeat it at the application level alone. On the network that drops ACK frames alone, the
  median handshake stays at 1,078 ms.
- Leave probes as they were. A request whose acknowledgments were all lost waits for the
  peer's idle timeout.
