# Decision 123: QUIC skips packet numbers in its 1-RTT space to catch an optimistic ACK

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-17, after the review of design §8 step 20e.

RFC 9000 §21.4: a peer that acknowledges packets it has not received makes a sender's
congestion controller send faster than the path carries. colibri refused an ACK of a number
it never sent (§13.1), but it sent every number in turn. So it could not tell an honest peer
from one that acknowledged the packets it had just sent. §21.4 says "An endpoint MAY skip
packet numbers when sending packets to detect this behavior."
- The 1-RTT space skips one number after each interval. An ACK frame that covers the number
  skipped last is one for a packet never sent, and the connection closes with
  PROTOCOL_VIOLATION, as for any packet never sent.
- The intervals are the eight bytes of one value the caller draws from its source at start,
  the option `packet_number_skips` of `quic.Connection`. Each byte is added to
  `packet_number_skip_interval_min`, 128, and the bytes are taken in turn. So a skip comes
  128 to 383 packets after the one before. colibri holds no generator (invariant 5), and one
  seed still replays.
- The server's and the client's QUIC connections draw the value. A program that drives
  `quic.Connection` itself passes null to skip none.
- The Initial and Handshake spaces skip none: they carry too few packets.

The alternatives refused:
- The gap recorded and nothing changed. An optimistic ACK costs the server bandwidth toward
  that peer, not slots or CPU.
- An interval drawn for each skip, through a new call on `quic.Connection` that the server
  and the client answer. No pattern repeats, but each send path takes another step.
- One interval for the whole connection. A peer that sees one skip knows the rest, and leaves
  them out of its forged frames.
