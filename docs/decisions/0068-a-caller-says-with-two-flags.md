# Decision 68: A caller says, with two flags, whether it reads received ECN codepoints and whether it sets them on what it sends

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24.

RFC 9000 §13.4 splits ECN into two halves, and each needs something only a socket has.
Reporting ECN counts in ACK frames (§13.4.1) needs the codepoint of every received datagram,
and "If an endpoint does not implement ECN support or does not have access to received ECN
codepoints, it does not process or report ECN". Marking packets ECT(0) and validating the path
(§13.4.2) needs the codepoint set on every sent datagram. colibri owns no socket
(non-negotiable 1), so the caller says which halves it can do:
- `ecn_reads`: the caller passes each datagram's real codepoint, and colibri reports the counts
  in its ACK frames.
- `ecn_marks`: colibri names in `Sent` the codepoint the caller sets on the datagram. It is
  ECT(0) while §13.4.2's validation holds, and Not-ECT once validation fails (§13.4.2.2).
  Decision 69 narrows when it marks: through a testing period, then once the path is capable.

Both default to false, which is what colibri did before: no report and no mark.

The alternative refused: one flag for both halves. A caller whose socket can do only one half
would then get neither, though the RFC treats the two as separate.
