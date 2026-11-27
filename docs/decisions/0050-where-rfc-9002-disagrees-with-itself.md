# Decision 50: Where RFC 9002 disagrees with itself about the round trip variation, colibri follows Appendix A.7

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

This is design §12 question 4, which step 10 was required to settle in writing and pin with a test.

The disagreement is one arithmetic ordering. §5.3 updates the smoothed estimate and then
measures the variation against the value it has just written; Appendix A.7 measures the
variation against the value as it stood and then updates. Written with `S` for the smoothed
estimate, `V` for the variation and `A` for the adjusted sample:

```text
Appendix A.7:  V' = 3/4 V + 1/4 |S  - A|   then   S' = 7/8 S + 1/8 A
§5.3:          S' = 7/8 S + 1/8 A          then   V' = 3/4 V + 1/4 |S' - A|
```

They differ by an exact factor, not by a rounding. `S' - A` is `7/8 S + 1/8 A - A`, which is
`7/8 (S - A)`, so §5.3's new term is always exactly seven eighths of Appendix A.7's. A path
holding steady drives the variation to the mean of that term, so §5.3's variation settles at
seven eighths of Appendix A.7's, and §6.2.1's Probe Timeout carries four times the variation,
so the timeout is shorter by an eighth of that term. On one sample with `S` at 100 ms, `V` at
25 ms and `A` at 140 ms, Appendix A.7 gives a variation of 28.75 ms and a timeout of 220 ms,
and §5.3 gives 27.5 ms and 215 ms.

Appendix A.7 wins on three grounds. It is the executable text: Appendix A is presented as the
complete algorithm and §5 as prose describing it, so where they part the algorithm is what an
implementation transcribes. It is the more conservative of the two, since its variation is the
larger, and a Probe Timeout that is too short sends a probe the path did not need, which costs
the peer bandwidth and can pull the congestion window down for no loss — colibri fails closed
everywhere else and does so here. And it is the ordering that makes the variation a measure of
the estimate the sample was compared against rather than of an estimate the sample has already
moved, which is the quantity §5.3's own prose says it wants.

**One piece of evidence was not gathered.** §5.3 says its method is similar to RFC 6298's, so
RFC 6298 would say which ordering the family intends. It is not in `docs/rfcs/`, and
CLAUDE.md non-negotiable 10 forbids reading a summary of it, so it was not read. Vendoring
RFC 6298 is what would settle the question from outside rather than from the two texts alone.

The alternative lost is §5.3's ordering. It is the shorter timeout, so it recovers from real
loss marginally sooner, and it is what a reader following the prose alone would write. It was
rejected because the appendix is the algorithm and because the error it makes when it is wrong
is a spurious probe rather than a late one.
