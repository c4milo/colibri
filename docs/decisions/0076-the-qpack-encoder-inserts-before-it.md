# Decision 76: The QPACK encoder inserts before it writes a section, and references only entries that are safe to reference

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-09-24 for design §8 step 11; the owner may overrule it.

RFC 9204 §2.1 leaves to the encoder what to insert and when to risk a blocked stream.
colibri's encoder decides this way:
- `write_section` takes the field section and writes two outputs: the encoded section and the
  encoder stream. It first decides every line, writing each insert to the encoder stream as it
  goes. It then writes the prefix and the lines, with the Base at the insert count, which
  §4.5.1.2 names as one of an encoder's choices. No line then needs a post-Base index.
- The caller marks each line `may_insert`, `no_insert` or `never_indexed`, as h2's callers mark
  each line for HPACK. A `never_indexed` line is a literal with its N bit, naming at most a
  static name, and is never inserted (§7.1.3).
- A `may_insert` line the static table does not hold whole is inserted when four things hold.
  The peer permits a table. The entry takes at most the capacity over `insert_size_divisor`,
  so one line cannot evict every other. Making room evicts only evictable entries: §2.1.1 makes
  an entry evictable once its insertion is acknowledged and no unacknowledged section
  references it, this section included. And the whole instruction fits the encoder stream
  writer, which is how the caller passes the flow-control credit §2.1.3 asks the encoder to
  respect.
- An entry at or above the Known Received Count is referenced only when the stream may block
  under the peer's SETTINGS_QPACK_BLOCKED_STREAMS (§2.1.2). Otherwise the section references
  only acknowledged entries and cannot block. It still inserts a line the table lacks, and
  writes that line as a literal: later sections reference the entry once the decoder
  acknowledges it, as Appendix B.3's speculative insert does. Without this, a peer that
  advertises no blocked streams, which is §5's default, would never see the table used.
- A line already in the table but not yet acknowledged is not inserted a second time.
- Set Dynamic Table Capacity goes out once, before the first insert, at the peer's maximum or
  `dynamic_table_capacity_max`, whichever is lower (§3.2.2, §3.2.3). The Required Insert Count
  is encoded against the peer's maximum, which is what the peer's decoder uses (§4.5.1.1).
- When `outstanding_sections_max` sections are unacknowledged, the next section references no
  dynamic entry, so it needs no record.
- The encoder stream bytes it wrote are owed even when the field section did not fit. The
  inserts are in the encoder's table, so the decoder must receive them too.

The alternatives refused:
- Appendix C's single pass, which writes each line as it decides it and the prefix last. It
  needs the prefix in a second buffer, and a line inserted mid-section needs a post-Base index.
- A draining index and the Duplicate instruction (§2.1.1.1). They keep a table from filling
  with referenced entries. Without them an encoder whose peer acknowledges late writes literals
  until the acknowledgments arrive, which is correct and costs compression only. Design §11
  measures before adding them.
- A dynamic name reference in an insert. The static name or a literal name serves, and a
  reference to the dynamic table's own bytes would need a copy before the insert evicts them.
