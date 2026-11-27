# Decision 133: The congestion controller is CUBIC (RFC 9438), in place of RFC 9002's NewReno

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-29, after design §8 step 26 and a comparison of three controllers.

Under random loss on a long path, colibri's h3 still lagged quic-go and quinn after decision
131, and both of those run CUBIC. In the Linux container of step 13i, axum's h3 server ran
on quinn's NewReno, CUBIC and BBR in turns, with nothing else changed, two runs each. CUBIC
beat NewReno on every profile and rate, mostly by removing NewReno's bad runs: at `lossy`
and 4,000 requests a second, NewReno's p99 was 141 and 211 ms, and CUBIC's 130 and 124 ms.
BBR was no better than CUBIC on the p99, and varied more. The literature agrees: BBRv3 does
"only slightly, but consistently better than CUBIC" on short flows (Bless et al., IFIP
Networking 2025), shares badly with CUBIC, and its specification is an Internet-Draft.

The rulings:
1. `recovery_congestion` follows RFC 9438 §4: the cubic increase of §4.2, the Reno-friendly
   estimate of §4.3, the concave and convex regions of §4.4 and §4.5, a decrease to 0.7 of
   the window on a congestion event (§4.6), and fast convergence (§4.7). RFC 9002's loss
   detection, recovery period, persistent congestion and pacing stay as they are.
2. The arithmetic is integer. Windows are in bytes, as §4.1 permits. `C`, `β` and `α` are
   rational constants, time is in microseconds, and §4.2's cube root is an integer cube
   root with a bounded loop. So one seed replays on every host (non-negotiable 5).
3. `on_ack` takes the instant and the smoothed RTT, which §4.2 reads (non-negotiable 3).
   The time an acknowledgment marks as limited (RFC 9002 §7.8) is left out of `t`, as §4.2
   requires.
4. The smallest window stays RFC 9002 §7.2's two datagrams, which governs QUIC.
5. Slow start stays RFC 9002's. §4.10 asks for HyStart++ (RFC 9406), which a later step
   brings to the owner. §4.9.2's undo of a spurious loss, a MAY, is not built.
6. `quic.constants.congestion_loss_reduction_divisor` goes, and `quic.constants.cubic` holds
   CUBIC's constants. That changes a public name, so the next release notes list it.

Alternatives that lost:
- Keep NewReno. Its bad runs are what the comparison found.
- CUBIC with NewReno as a choice in the configuration. One controller is less to test; a
  choice comes with BBRv3, if decision 134 builds it.
- BBRv3 now. Its specification is a draft, and it measured no better here.

Amended by the owner on 2026-11-04 (design §8 step 34). After step 29c.3 the owner asked
for RFC 9002's NewReno as a choice in the configuration, which the second alternative above
had lost to one controller. `quic.CongestionController` gains `newreno`, beside `cubic` and
`bbr`, and BBRv3 stays the default (decision 143). NewReno follows RFC 9002 §7.3 and
Appendix B as written, with no HyStart++. The cost is a third controller to test: a
simulator check, a TLA+ model and a Lean proof of its own, as CUBIC has.
