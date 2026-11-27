# Decision 135: CUBIC's first slow start is HyStart++ (RFC 9406)

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-29, as design §8 step 28. RFC 9438 §4.10 says CUBIC SHOULD use it.

Slow start doubles the window each round trip until a loss. On a path with a deep queue,
that overshoot loses many packets at once. HyStart++ ends slow start when a round's minimum
round trip grows, which shows that a queue fills, before a loss does.

The rulings:
1. RFC 9406 §4.3's recommended constants: MIN_RTT_THRESH 4 ms, MAX_RTT_THRESH 16 ms,
   MIN_RTT_DIVISOR 8, N_RTT_SAMPLE 8, CSS_GROWTH_DIVISOR 4 and CSS_ROUNDS 5.
   `quic.constants.hystart` holds them.
2. L is infinity, because colibri paces (RFC 9002 §7.7), and §4.3 says a paced sender SHOULD
   use it.
3. A round ends when an acknowledged packet went out at or after the round's start. §4.2
   counts in sequence numbers, and the window holds no packet numbers, but the send instant
   of each acknowledged packet is in its record.
4. An RTT sample is RFC 9002 §5.1's latest_rtt, one per ACK frame at most. An ACK frame
   with no sample neither moves a round's minimum nor counts toward N_RTT_SAMPLE.
5. HyStart++ runs in the first slow start alone (§4.3). A congestion event ends it, and the
   decrease of decision 133 then applies. When CSS ends, the window enters congestion
   avoidance with W_max at the window and K = 0, as RFC 9438 §4.10 says.

Alternatives that lost:
- Standard slow start, which RFC 9438 §4.10 permits only "in the rare cases when HyStart++
  is not suitable".
- Rounds in packet numbers. Each space numbers its own packets, and the window would need
  the numbers of all three.
- L = 8, for a sender that does not pace. colibri paces.
