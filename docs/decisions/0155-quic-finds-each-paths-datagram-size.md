# Decision 155: QUIC finds each path's datagram size by DPLPMTUD (RFC 9000 §14.3, RFC 8899)

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-05 (design §8 step 40), after decision 154 found that 1,200-byte
datagrams cost colibri about a fifth of quic-go's goodput at 1% loss (design §8 step 34). RFC 8899
is pinned in `docs/rfcs/`.
1. Each path starts at RFC 8899's BASE_PLPMTU, 1,200 bytes (RFC 9000 §14.1), and searches
   upward once the handshake is confirmed. A probe is a PING padded to its size (RFC 9000
   §14.4). The search stops at the smallest of the peer's `max_udp_payload_size` (§18.2),
   colibri's own limit, and a new connection option, `datagram_len_max`, 1,452 bytes by
   default: a 1,500-byte link less the IPv6 and UDP headers.
2. A lost probe is no congestion: RFC 9000 §14.4 says it "SHOULD NOT trigger a congestion
   control reaction". Its bytes count in flight.
3. Black-hole detection (RFC 8899 §4.3): repeated losses of full-size packets, while smaller
   ones arrive, return the path to the base size. PMTU_RAISE_TIMER (RFC 8899 §5.1.1) starts
   the search again later.
4. The congestion window stays in bytes. A larger datagram raises the minimum window, the
   initial window and each step of growth, under CUBIC, NewReno and BBRv3 alike.
5. The send buffers and the frame scratch grow from 1,200 bytes to `datagram_len_max`, so
   each QUIC connection grows. Each new limit is named, and each new name goes on its list.
6. Amended by the owner on 2026-11-05, so a datacenter path with 9,000-byte frames is found:
   `datagram_len_max` may go up to 65,527 bytes, the largest `max_udp_payload_size` RFC 9000
   §18.2 allows, and colibri advertises the option's value as its own
   `max_udp_payload_size`. The send buffers, the frame scratch, and the receive buffers where
   the kernel coalesces nothing size from the option, so memory grows with the ceiling a
   program chooses and stays as the default sets it otherwise. The search reaches a high
   ceiling in about 13 probes, by halving the interval it has left (RFC 8899 §5.3).

Alternatives that lost:
- PMTUD from ICMP (RFC 9000 §14.2.1). Rotor reads no ICMP, and §14.2.1 asks that a message be
  validated before it is used.
- Trust the peer's `max_udp_payload_size` alone. It says nothing of the path between.
- Stay at 1,200 bytes, as RFC 9000 §14.2 allows. It costs every controller.
