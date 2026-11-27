# Decision 66: A PTO at the application level declares the oldest ack-eliciting packets in flight lost, as many as the probes it owes, so the probes carry what those packets held

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23. It extends entry 64 to the application level with a bound.

Against quinn in the QUIC Interop Runner's handshake loss case, colibri's client sent its
request once, in a 1-RTT packet the path lost. The four acknowledgments that would have shown
the loss were lost too. Each PTO's probes carried a PING, because at the application level no
packet was declared lost, and the connection reached its idle timeout with the request never
sent again.

RFC 9002 §6.2.4 lets a sender "mark any packets still in flight as lost". At the application
level colibri marks the oldest ack-eliciting ones, `probe_packets` of them, and the probes
carry their frames. Each byte is still in one place (entry 57). Like entry 64, this is no
congestion event.

Two alternatives were refused. Declaring every application packet in flight lost, as entry 64
does at the handshake levels, sends a whole window again on each PTO, and on a path that is
only slow most of it arrives twice. Leaving PING probes keeps a lost request waiting on an
acknowledgment that may be lost as well.
