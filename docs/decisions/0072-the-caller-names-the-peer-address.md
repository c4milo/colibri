# Decision 72: The caller names the peer address each datagram came from, and colibri decides when the path moves

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24. It carries out what entry 21 requires of an endpoint that refuses
migration: RFC 9000 §9's rules for a peer whose address changes anyway, as NAT rebinding does.

colibri owns no socket (non-negotiable 1), so it cannot see an address. The caller passes one
with each datagram: up to `peer_address_len_max` bytes and a port, which colibri compares
and never reads otherwise. From that:
- A client discards a datagram from any address but its server's. §9: "If a client receives
  packets from an unknown server address, the client MUST discard these packets."
- A server moves its path to a new address when a datagram from it carries the
  highest-numbered non-probing packet. §9.3: "An endpoint only changes the address to which
  it sends packets in response to the highest-numbered non-probing packet."
- On a move, `Received` says so. The caller then gives colibri the data of two
  PATH_CHALLENGE frames: one for the new path (§9.3) and one for the previously active path
  (§9.3.3). Invariant 5 forbids colibri a random number, and §8.2.1 wants the data
  unpredictable.
- `Sent` names the address each datagram goes to, because the challenge to the previous path
  goes out in a datagram of its own.
- The new path starts unvalidated, so §8's anti-amplification limit applies to it (§9.3.1).
  If its validation fails, colibri moves back to the last validated address, and with none
  it closes silently (§9.3.2).
- Once the new address is validated, colibri resets its congestion controller and RTT
  estimator (§9.4), except when only the port changed. §9.4 lets an endpoint keep both then,
  "Because port-only changes are commonly the result of NAT rebinding", and colibri does.

The alternative refused: the caller compares addresses itself and passes flags for a change
and for a change of port alone. colibri would decide the same things, but the caller would
also have to keep the previous address and map colibri's names for the two paths back to
sockets, which is state colibri already has to hold to revert.

Amended the same day, while building it: one PATH_CHALLENGE on the new path is not enough.
RFC 9000 §13.3 sends one "periodically until a matching PATH_RESPONSE frame is received",
each with "a different payload". A NAT's old binding answers nothing, so if the one challenge
on the new path is lost too, both attempts run out together and the connection closes. So
the caller gives `path_challenge_attempts` payloads for the new path with the one for the
previous path. colibri sends the next each PTO without an answer, and a response to any of
them validates the path (§8.2.3).

Amended again after the QUIC Interop Runner's rebind cases, where a colibri server lost the
first challenge on a new path and then had no room to send another. The client's 117 bytes
from its new port allowed 351, and the challenge's packet was filled with stream data. So,
until a path the peer moved to is validated, colibri sends ACK and path frames alone there,
and a datagram carrying a path frame is padded only when all 1,200 bytes fit (§8.2.1 excepts
the rest, and part of the padding validates no path MTU). The bytes §8 allows then go to the
challenges §13.3 sends. The ACK frames stay because withholding them deadlocked the
simulator: a peer whose window was full of unacknowledged data could not send its
PATH_RESPONSE. Each challenge also repeats the latest ACK, whether or not anything new asks
for one: `spec/tla/path_validation/` found that if the first challenge's packet carried the
ACK and was lost, a client whose window that ACK would have freed could not answer the
resends. The cost is a pause of about one round trip in data on each move.
