# Decision 134: colibri may read the BBR draft, and builds BBRv3 beside CUBIC once CUBIC has landed

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-29, with decision 133. A third exception to non-negotiable 10, after
decisions 102 and 127.

BBR models the path's bottleneck rate and round trip, and paces to them, rather than reading
each loss as congestion. Under random loss it can keep a window that CUBIC halves, and the
owner wants colibri to have the better controller where one exists. BBRv3 is specified only in
an Internet-Draft, so colibri needs the owner's leave to read it.

The rulings:
1. `docs/rfcs/bbr/` pins draft-ietf-ccwg-bbr-06 of 2026-07-06, unmodified, in
   `docs/rfcs/SHA256SUMS`. colibri cites it by revision and section, and reads no other
   implementation's source, as for the RFCs.
2. BBRv3 comes after CUBIC (decision 133) and HyStart++, as a choice in a connection's
   configuration, with CUBIC the default. The step that builds it lists the public name.
3. The step measures BBRv3 against CUBIC on the judge's `network` input, and against the
   fairness and queue findings of the literature, before the owner rules on a default. A
   later revision of the draft, or its RFC, replaces this copy by a new ruling.

Alternatives that lost:
- CUBIC alone. The owner wants the better controller measured, not assumed.
- BBRv1, which quinn ships. Google replaced it, and its losses in shallow buffers are orders
  of magnitude above CUBIC's (Cao et al., IMC 2019).
