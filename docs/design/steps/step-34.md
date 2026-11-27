# Design §8 step 34: NewReno beside CUBIC and BBRv3

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 133](../../decisions/0133-the-congestion-controller-is-cubic-in.md) as amended on 2026-11-04 adds RFC 9002's own NewReno (§7.3
and Appendix B) as a third controller, never the default. The owner asked for it after step 29c.3,
to measure RFC 9002's controller beside the other two.
- **The public names.** `quic.CongestionController` gains `newreno`, and
  `quic.constants.recovery` gains `newreno`, with `loss_reduction_numerator` and
  `loss_reduction_denominator`, Appendix B.1's kLossReductionFactor of 1/2. A program that
  sets `server.Config.congestion_controller` or `client.Config.congestion_controller` to
  `.newreno` needs the first.
- **The rules.** `recovery_congestion_newreno.zig` holds the controller's own state: the carry
  of Appendix B.5's increase. Slow start adds what was acknowledged (§7.3.1). Congestion
  avoidance adds `max_datagram_size × acknowledged / window`, with the rest carried (§7.3.3).
  A new congestion event sets ssthresh to half the window, and the window to the larger of
  ssthresh and the minimum (Appendix B.6). A limited acknowledgment and one in the recovery
  period grow nothing (§7.8, Appendix B.5). No HyStart++ runs, because RFC 9002 names none.
- **The checks.**
  - 9 tests in `recovery_congestion_newreno_test.zig` and `constants_newreno.zig`.
  - `quic_connection_newreno_check.zig` runs the QUIC connection check with both endpoints
    on NewReno, over the lossy network and each adversary, with each census pinned. It passes
    in Debug and with `-Drelease`.
  - `spec/lean/Colibri/Quic/NewReno.lean` proves that one acknowledgment loses no byte to the
    carry, and that one of at most a window adds at most one datagram. It also proves that an
    event never raises the window nor leaves it below the minimum.
  - `spec/tla/newreno_congestion` holds over 160,008 states. Each of its 5 mutants is
    violated: a second reduction in one period, growth in the period, growth on a limited
    acknowledgment, no minimum, and a datagram on each acknowledgment.
  - The UDP server's `h3` mode takes `newreno`, and `tools/quic_udp.sh` requires its summary
    to name the controller. The bulk run measures it as `colibri-newreno`.
- 9 mutations, each **CAUGHT**: growth on a limited acknowledgment, growth in the recovery
  period, avoidance that grows as slow start, the carry dropped, a cut to 0.7 in place of 0.5,
  no minimum after an event, no packet past the window after an event, persistent congestion
  that keeps the carry, and the UDP server that ignores `newreno`.
- **The judge's bulk run**, [run 42069619121](https://github.com/c4milo/colibri/actions/runs/42069619121)
  on 7b9b9100, 3 rounds, two jobs on `ubuntu-24.04-arm`. Goodput in Mbit/s, for 1 and 4
  connections, each job's median, and the download p50 for 1 connection:

  | Path | colibri-newreno | colibri (CUBIC) | colibri-bbr | chi (quic-go) |
  | --- | --- | --- | --- | --- |
  | 20 Mbit/s, 25 ms | 17.34 and 17.90; 946 ms | 17.34 and 17.90; 946 ms | 16.78 and 17.34; 952 ms | 17.34 and 17.90; 938 ms |
  | the same, 1% loss | 1.68 and 7.27; 8,446 to 8,700 ms | 2.24 and 8.39 to 8.95; 7,189 to 7,576 ms | 14.54 and 17.34; 1,143 to 1,162 ms | 3.36 and 12.86 to 13.42; 4,358 to 4,524 ms |

  - With no loss, NewReno fills the link as CUBIC does. Its GET p99 with 4 connections is
    686 to 718 ms, against CUBIC's 519 to 595.
  - At 1% loss, NewReno gets three quarters of CUBIC's goodput: each loss halves its window
    (RFC 9002 Appendix B.6), and CUBIC grows back faster (RFC 9438 §4.3). BBRv3 stays the
    default (decision 143).
  - quic-go's Reno, under chi, gets twice colibri's at 1% loss. The owner asked why on
    2026-11-05, and decision 154 allowed one reading of quic-go v0.55.0 for that question.
- **Why quic-go gets more** (decision 154). An audit against RFC 9002 found that colibri's
  NewReno follows §6.1's thresholds, §7.3.2's cut to one half once each recovery period,
  §7.3.3's growth of one datagram each window, and §7.7's pacing. quic-go differs in three ways:
  - Its server builds its sender with Reno, which cuts the window to 0.7 on a loss and still
    grows one datagram each round trip. RFC 9002 §7.3.2 says the threshold "MUST" be half, and
    RFC 9438 §4.3 pairs a cut to 0.7 with a growth of 0.53 datagrams, so that it stays fair to
    Reno. A rate model gives the cut about 1.37 times Reno's goodput at 1% loss.
  - It runs DPLPMTUD up to 1,452 bytes, and colibri sends 1,200 bytes always (RFC 9000
    §14.2). About 1.2 times the goodput at a loss rate counted in packets. RFC 9000 §14.3
    supports it.
  - Its initial window is 32 datagrams, against RFC 9002 §7.2's 10, and its window grows within
    3 datagrams of full (§7.8 allows it). A few percent together.
  - The model puts colibri at about 2.25 Mbit/s and quic-go at about 3.75 Mbit/s, against
    downloads of about 8.5 s and 4.4 s on the judge. colibri keeps RFC 9002's cut. DPLPMTUD is
    the gain the RFCs allow, for every controller.
