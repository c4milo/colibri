# Decision 31: The workload colibri intends to win is many short connections with small requests and high connection churn

[All decisions](../decisions.md) · Section: [Performance](../decisions.md#performance)

, not single-stream bulk throughput. Handshake cost and per-connection memory dominate there.
colibri states where it expects to win, where it expects only to match, and where it expects to
lose, and reports all three:

- **Win, plausibly:** per-connection memory, no allocation at all, and the teardown cost
  nobody optimises. A fixed connection struct whose size is a comptime constant and whose
  storage the caller owns (entry 35), a small advertised field-table capacity, windows sized
  for small requests rather than bulk transfer, and reset-instead-of-construct on reuse. Also
  tail latency under churn, by having no garbage collector.

  Two QUIC-specific optimizations are worth naming and are **not** colibri's to claim as the
  vtables stand: batching header protection across a datagram's packets into one pass, and
  precomputing the key schedule for the fixed Initial salt. Both are implemented behind
  `crypto.Suite` (entries 9 and 48), so they belong to the caller. The second needs nothing
  from colibri. The first means a `seal` that takes every packet of a datagram at once, which
  is a decision nobody has taken.
- **Match, at best:** the asymmetric crypto, which is a caller-supplied primitive and the same
  one every competitor calls; AEAD bulk throughput; HPACK on small field sections; and the
  syscalls, which are the caller's.
- **Lose, probably:** bulk single-stream throughput, where msquic's GSO and GRO work is years
  deep; congestion control and ACK policy maturity, where getting ACK frequency wrong costs
  more than every memory win combined; and the whole maturity surface — PMTUD, ECN
  validation, key update, stateless reset, QPACK dynamic tables under load.

The opportunity is narrower than "we beat quiche" and worth more. With an ECDSA certificate the
asymmetric work in a TLS 1.3 handshake is tens of microseconds rather than hundreds, and a short
connection stops being crypto-bound and becomes bound by syscalls, allocation and state-machine
work — which is the part colibri controls. And there is no credible apples-to-apples
handshakes-per-second or bytes-per-idle-connection comparison across QUIC implementations in
public. Publishing a rigorous one is a contribution nobody has made, and it is a stronger
position than a throughput claim colibri would lose.
