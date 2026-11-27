# Decision 65: A server whose client shows it lacks the server's Initial CRYPTO bytes sends them again at once, at most twice per connection

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23. It takes RFC 9002 §6.2.3's option to speed up handshake
completion, and moves the bytes as entry 64 does.

In the QUIC Interop Runner's handshake loss case, one connection lost the server's first
flight and the CRYPTO probe of each of the next three PTOs, while the PING probes arrived.
The client repeated its ClientHello and then sent padded Initial PINGs. The server answered
each with an ACK and waited for its next PTO, which doubled each time, and the client gave up.

§6.2.3: "When a server receives an Initial packet containing duplicate CRYPTO data, it can
assume the client did not receive all of the server's CRYPTO data sent in Initial packets."
An endpoint then "MAY, for a limited number of times per connection, send a packet containing
unacknowledged CRYPTO data earlier than the PTO expiry". A padded Initial PING shows the same
thing: §6.2.2.1 has a client send one when its PTO fires only if it has no Handshake keys, and
a client with the server's Initial CRYPTO bytes has them.

So a server takes either as the signal: an ack-eliciting Initial packet that brings no new
CRYPTO bytes, while its own Initial CRYPTO bytes are in flight. It declares its Initial
packets in flight lost, and the next datagram carries their bytes. Like entry 64, this is no
congestion event.

The limit is `early_crypto_resends_max`, 2. §6.2.3 warns that "An endpoint that always
retransmits packets in response to receiving packets that it cannot process risks creating an
infinite exchange of packets." It calls one resend "adequate to quickly recover from a single
packet loss", and the runner's losses come in bursts, so colibri allows a second.

colibri takes the server's half alone. §6.2.3 also lets a client that receives Handshake
packets before it has Handshake keys resend early. colibri's client passes the handshake loss
case without it.

Two alternatives were refused. One resend, the RFC's example, leaves nothing when that resend
is lost too. Resending on every such packet, with no limit, is the exchange §6.2.3 warns of.

Decision 71 amends this entry: the second resend waits until one PTO has passed since the
first.
