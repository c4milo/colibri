# Design §8 step 10: loss recovery and congestion control

[Design §8, the build plan](../../design.md#8-build-plan)

RFC 9002: RTT estimation, packet and time threshold loss detection, PTO with backoff, NewReno,
persistent congestion, pacing. All nine `now()` sites are caller-supplied parameters on the five
entry points of §4.2. **Check:** the simulator's loss, reorder and blackhole scenarios with a census
per seed; the interop runner's `handshakeloss`, `transferloss`, `blackhole`, `longrtt` and `ecn`
cases; and, because RFC 9002's prose and its appendix pseudocode disagree over the round trip
variation, a written decision in this document's §12, with a test pinning the choice. *Large.*

**Done, 2026-09-20, but for the interop cases.** Eight files. `src/quic/rtt.zig` is §5's
estimator and §6.2.1's Probe Timeout. `src/quic/recovery/recovery_sent.zig` is Appendix A.1.1's
`sent_packets`, one ring per space in packet number order, so a number is found by halving and
the acknowledged slots fall off either end. `recovery_loss.zig` is §6.1's two thresholds: both
rise with the packet number, so the lost packets are a run at the front, the walk stops at the
first survivor — which is also the instant §6.1.2 sets the timer for — and one range takes them
out. `recovery_congestion.zig` is §7's NewReno, `recovery_pacing.zig` §7.7's leaky bucket,
`recovery_timer.zig` Appendix A.8's one timer, and `recovery.zig` with `recovery_ack.zig` the
five entry points of §4.2.

Three things are worth naming. The bytes in flight are the sum over the three tables and are
held in no second place, because Appendix B.2's `bytes_in_flight` and the tables would
otherwise be two records of one fact. Congestion avoidance counts bytes rather than dividing:
Appendix B.5's expression grows the window by nothing once it passes the maximum datagram size
squared, under two megabytes on an ordinary path, and B.5 points at the alternative in the same
paragraph. And the §5.3-versus-Appendix-A.7 disagreement is settled in
[decision 50](../../decisions/0050-where-rfc-9002-disagrees-with-itself.md) and §12 question 4, with a test computing both orderings and
pinning the factor between them.

**Check:** `src/sim/recovery_check.zig` runs 256 seeds over four paths — quiet, one datagram in
ten dropped, a delay range wide enough to reorder, and a stretch where the path swallows
everything. The sender is the whole of `quic.recovery`; the receiver is `quic.space`, which
writes real ACK frames, so what the sender reads back is bytes off the wire. It printed
`sent=16420 acked=11743 lost=4677 probes=746 scenarios={ 60, 57, 75, 64 }
crc32=0x2c3cc41a` in Debug and in ReleaseSafe on macOS arm64. Every packet is accounted for
exactly once — 11743 and 4677 sum to 16420 — no packet is both acknowledged and declared lost,
the run drains, and the window never falls under §7.2's minimum.

Those numbers moved on 2026-09-21, `53205ae`, and the cause of the move is this. The receiver had been
waiting for RFC 9000 §13.2.2's two ack-eliciting packets with no deadline under it, so a lone
packet went unacknowledged and the sender probed for it; with §13.2.1's max_ack_delay applied,
probes fall from 1354 to 746 over the same 256 seeds. The earlier figures were
`sent=16873 acked=11997 lost=4876 probes=1354 crc32=0xb78a83fe`.

Writing the check found two defects in the check itself and neither in the library, which is
worth recording because both were rules the library already held. The first invariant written
was that the bytes in flight never pass the congestion window; §7 bounds what a sender adds,
not what is already outstanding, and §7.5 exempts a probe from the window outright, so the
check now tests the send and not the state. The second was a digest taken over a struct's
bytes, padding included: padding is uninitialized memory, the two build modes disagreed about
it, and [invariant 5](../../invariants.md#inv-5) forbids reading it. Each field is now fed in on its
own, in network byte order.

**Pacing, ECN and three runner cases, 2026-09-24.**
- `ae82252`: `send` asks the pacer of RFC 9002 §7.7 before each datagram, and
  `connection_timer` names the instant the pacer has earned the next one as `Kind.pacing`. A
  sender the pacer holds counts as using its window (§7.8). 6 mutations, 6 CAUGHT.
- [Decision 68](../../decisions/0068-a-caller-says-with-two-flags.md) gives the caller two flags. With `ecn_reads`, an ACK frame carries
  RFC 9000 §13.4.1's counts. With `ecn_marks`, `Sent.ecn` names the codepoint the caller sets.
  11 mutations, 11 CAUGHT.
- [Decision 69](../../decisions/0069-an-endpoint-with-ecnmarks-tests-a.md) tests the path as RFC 9000 Appendix A.4 describes. The first ten
  marked packets, or three PTOs, are the test. After it the endpoint sends Not-ECT until an
  ACK frame that passes validation shows a marked packet arrived, and then marks again. A path
  that drops marked packets therefore costs at most the test. 11 mutations, 11 CAUGHT.

The QUIC check now marks, and its network sets ECN-CE on up to 100 datagrams in 1,000. Each
seed ends with both endpoints' validation holding. Seed 0 found a defect: a packet of ACK frames
alone was not counted as sent ECT(0), though the peer counts it, so the peer reported more
ECT(0) packets than the sender had counted. With decision 69 the census is 13,215 datagrams,
13,242 packets, 662 dropped and 487 marked ECN-CE, crc32 `0x1ce9af4a`, in Debug and in
ReleaseSafe on macOS arm64.

The runner at `740c05a`, in Docker on macOS arm64, chapulin `cc88adb` built `TRUST=raw-ecdsa`:

| Peer | colibri server | colibri client |
|---|---|---|
| colibri, ngtcp2 | pass: ecn, longrtt, blackhole | pass: ecn, longrtt, blackhole |
| quic-go | pass: longrtt, blackhole; ecn unsupported | pass: longrtt, blackhole; ecn unsupported |

In each `ecn` pass both sides marked, and no datagram carried ECN-CE. Before decision 69 every
datagram went out ECT(0). Now the datagrams between the test and the ACK that makes the path
capable go out Not-ECT: against itself, colibri's client sent 48 datagrams ECT(0) and 4
Not-ECT, and its server 87 and 2.

Rotor 0.3.0 carried no codepoint in two places: on Linux, to or from an IPv4 client of a socket
bound to `::`, and on macOS, over any IPv4 socket. So the server bound the IPv4 wildcard for
`ecn`, and on macOS validation failed on the first ACK, as §13.4.2.2 asks. Rotor v0.4.0 fixes
both (`400d748`, `fbe9311`). With it the server binds `::` again and still passes `ecn`
against colibri and ngtcp2, and with `fbe9311` `tools/quic_udp.sh` on macOS received 2,793
datagrams ECT(0) and 67 Not-ECT, the client's path ending capable.

**`handshakeloss` between two colibri endpoints, 2026-09-24.** It failed one run on 2026-09-23.
The datagram carrying the server's ServerHello was lost. Decision 65's two early resends went
out 6 ms apart and were lost together. The server's Handshake probes then reached a client with
no Handshake keys.
- `65a0857`: the simulator can run the runner's drop-rate network, 30% of datagrams lost each
  way and at most three in a row, and times each handshake. Over 2,000 seeds one handshake took
  43 seconds, and 11 took 16 seconds or more.
- [Decision 70](../../decisions/0070-a-pto-also-probes-every-other.md): a PTO also probes every other space with ack-eliciting packets
  in flight (RFC 9002 §6.2.4), so a lost ServerHello goes out again with the Handshake probes.
  Over the same 2,000 seeds the slowest handshake took 34 seconds, and 3 took 16 or more.
- [Decision 71](../../decisions/0071-decision-65s-second-early-resend-waits.md): the second early resend waits one PTO after the first. The
  simulator cannot show this, because it delivers every datagram due at one instant before
  either endpoint sends.

7 mutations, 7 CAUGHT. The census of the QUIC check is now 13,259 datagrams, 13,338 packets,
686 dropped and 486 marked, crc32 `0x686522e4`; the adversary check's is 5,126 datagrams and
1,678 dropped by the adversary; and the runner check's 256 seeds are 4,150 datagrams with the
slowest handshake at 8.4 seconds. Each in Debug and in ReleaseSafe on macOS arm64.

The runner at `740c05a` then passed `handshakeloss` and `transferloss` with colibri against
itself, and in both roles against quic-go and ngtcp2. colibri against itself passed
`handshakeloss` five more times in a row. With that, every runner case this step names passes.

**The RTT estimate in the runner, 2026-09-27**
([#73](https://github.com/c4milo/colibri/issues/73)). The UDP endpoints pass colibri the instant
Rotor's last tick read (decision 63). Rotor 0.4.0 read the clock again after a wait only when the
wait produced no event. So a datagram that ended a wait was processed at the instant the tick
started, and an RTT sample taken from it left out the wait. On the `handshake` case's path, 15 ms
each way, a scratch build of colibri's client at `a6a4791` printed `latest=289us min=289us
smoothed=289us variation=144us`, and its PTO was about 1.5 ms. Rotor v0.6.0, `59599a8`, reads the
clock after every wait that blocked ([rotor#6](https://github.com/c4milo/rotor/issues/6)), and
colibri pins it.

With v0.6.0, a scratch build whose client printed its estimate as each connection ended ran
`handshake` three times as the client against quic-go, in the runner at `740c05a` in Docker on
macOS arm64. Each run passed. A wire sample is read from the client-side capture: the time from a
client packet to the ACK frame that first names it as the largest acknowledged, for each ACK
frame that arrived before the client's CONNECTION_CLOSE.

| Run | Printed | Wire samples |
|---|---|---|
| 1 | `latest=39919us min=39919us smoothed=41999us variation=13904us` | 40.65, 49.92, 35.91 ms |
| 2 | `latest=41542us min=41542us smoothed=43559us variation=17018us` | 43.23, 38.45 ms |
| 3 | `latest=35643us min=35643us smoothed=39892us variation=16401us` | 39.89, 33.80 ms |

Each `latest` is the last wire sample plus 1.8 to 4.0 ms. That sample's packet carries the
instant its tick read before the tick processed the server's handshake messages, and Rotor sends
a packet on the tick after the one that built it.

With v0.6.0 pinned, `zig build test`, `tools/quic_udp.sh` and `tools/quic_aioquic.sh` pass on
macOS arm64, and `tools/interop.sh quic-go` gave:
- colibri's server and colibri's client: every case passed.
- colibri's server and quic-go's client: every case passed but `ecn`, which quic-go does not run.
- quic-go's server and colibri's client: every case passed but `ecn`, and `handshakeloss`, which
  failed as [#72](https://github.com/c4milo/colibri/issues/72) records. The server-side capture
  holds 51 Source Connection IDs in quic-go's Initial packets and 50 in the client's.
