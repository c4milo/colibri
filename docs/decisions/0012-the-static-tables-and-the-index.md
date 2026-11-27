# Decision 12: The static tables and the index address space are not shared, and cannot be

[All decisions](../decisions.md) · Section: [What is shared between h2 and h3](../decisions.md#what-is-shared-between-h2-and-h3)

HPACK's static table has 61 entries numbered from 1 (RFC 7541 Appendix A); QPACK's has 99 numbered
from 0 (RFC 9204 Appendix A), and RFC 9204 §3.1 states the off-by-one deliberately. Worse than
different contents: RFC 7541 §2.3.3 fuses static and dynamic into one address space where an index
above the static length addresses the dynamic table, and RFC 9204 §3 opens by saying the opposite —
"entries in the QPACK static and dynamic tables are addressed separately" — with a `T` bit in the
representation to say which. A shared "resolve an index to an entry" function would be a bug.
colibri implements two tables and two resolvers.

The representations do not share either. Every QPACK *field line* representation (RFC 9204 §4.5)
has a different bit pattern and prefix width from its HPACK analogue, and two of them — indexed
with post-base index, and literal with post-base name reference — have no HPACK analogue at all.
The one exception is the table-size instruction: HPACK's Dynamic Table Size Update (RFC 7541
§6.3) and QPACK's Set Dynamic Table Capacity (RFC 9204 §4.3.1) share the `001` pattern and the
5-bit prefix, and they are still implemented in different modules because they arrive on
different streams.

The difference is not only in the encoding. RFC 9204 §2.2 names it: in HPACK the encoded field
section carries the instructions that mutate the dynamic table, while in QPACK the field
sections and the table-mutating instructions arrive on separate streams. That one difference
is why QPACK needs Known Received Count, Required Insert Count, a Base, blocked-stream
accounting and per-entry reference counts, and why HPACK needs none of them. HPACK also
assumes a reliable, ordered byte stream and says nothing about out-of-order delivery — a
structural assumption, not a syntactic one.
