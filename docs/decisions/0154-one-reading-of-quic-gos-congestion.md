# Decision 154: One reading of quic-go's congestion controller, to explain a gap the judge measured

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-05. It makes one exception to non-negotiable 10. At 1% loss on the
judge's bottleneck, quic-go's NewReno gets twice the goodput of colibri's (design §8 step 34), and
the owner asked why.
1. The question is answered three ways: the qlog of each sender over one bulk run, an audit of
   colibri's NewReno and loss detection against RFC 9002 §6, §7 and Appendix B, and one
   reading of quic-go's congestion and loss detection code at the version the bench pins.
2. The reading answers this question alone. A change it suggests is made only from a section
   of RFC 9002 or RFC 9438 that states the rule, and the commit cites that section, never
   quic-go. A behaviour no RFC states comes to the owner as a question.
3. Nothing is copied: no code, no constant and no comment.

Alternatives that lost:
- The qlog and the audit alone. They show what differs, but may not show why.
- No question: the gap stays unexplained.
