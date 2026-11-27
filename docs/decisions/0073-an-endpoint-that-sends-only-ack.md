# Decision 73: An endpoint that sends only ACK frames adds a PING about once a round trip, as RFC 9000 §13.2.4 suggests

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-09-24, while building decision 72; the owner may overrule it.

§13.2.4: "A receiver that sends only non-ack-eliciting packets, such as ACK frames, might not
receive an acknowledgment for a long period of time ... a receiver could send a PING or other
small ack-eliciting frame occasionally, such as once per round trip, to elicit an ACK from
the peer." A colibri client that only downloads sent only ACK frames, so it had nothing in
flight and no PTO armed. In the QUIC Interop Runner's rebind case, quic-go's server followed
the client to its new port and sent one PATH_CHALLENGE, padded to all the bytes §8 allowed
it. The challenge was lost, and the server could send nothing more until the client sent
again, which a client that receives nothing and owes nothing never did. With a PING in flight
the client's PTO stays armed, and its probes give the server the bytes to challenge again.
(A first reading, that quic-go ignored packets of ACK frames alone, was wrong: it was waiting
for a spare connection ID, RFC 9000 §9.3, which colibri's test endpoint now issues.)

So at the application level colibri adds a PING to a packet carrying an ACK the space owes,
when that packet elicits nothing else, a smoothed round trip has passed since its last
ack-eliciting packet there, and it has sent `ack_only_packets_before_ping` packets of ACK
frames alone since. The last condition ends the exchange: the peer answers a PING with one
such packet, which is not enough to add a PING of its own. Without it, two colibri endpoints
each added a PING to the answer and never went quiet. `spec/tla/ack_elicitation/` checks it
under entry 67: with the count, two endpoints always go quiet, with or without loss; with a
PING on every ACK, TLC finds the exchange that never ends.

The alternatives refused:
- Never adding one, which is what colibri did. A peer that follows only ack-eliciting packets
  never learns a client's new address.
- A PING on a timer of its own. It would send packets when nothing needs acknowledging, and
  §10.1.2 leaves keeping a connection alive to the application.

Amended by the owner on 2026-09-29: the count stays at two. In the QUIC Interop Runner's
`handshakeloss` case, colibri's server acknowledged quinn's client in two packets of ACK frames
alone, the network dropped both, and the PING would have gone with a third that the client
never asked for ([#76](https://github.com/c4milo/colibri/issues/76)). With nothing in flight
the server armed no PTO, so it sent nothing more, and quinn's probes never carried its lost
request again ([quinn#2893](https://github.com/quinn-rs/quinn/issues/2893)). Refused: a count
of one, which would have armed a PTO there, and whose probe would have repeated the ACK
(decision 107). colibri follows RFC 9000 in this case, and the count of two is what TLC
checks ends the exchange.
