# Decision 74: The QPACK decoder hands a blocked field section back to the caller unread, and holds the decoder instructions it owes until the caller asks for them

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-09-24 for design §8 step 11; the owner may overrule it.

RFC 9204 §2.2.1 blocks a stream whose field section needs dynamic table entries that have not
arrived yet. colibri owns no I/O and no heap (non-negotiables 1 and 4), so the decoder holds
none of the section's bytes:
- `read_section` reads the prefix. When the Required Insert Count is above the decoder's
  insert count, it records the stream as blocked and returns `blocked`. The caller keeps the
  bytes, which §2.2.1 already asks it to leave in the stream's flow-control window.
- `ready_stream` names a blocked stream whose section can now be decoded, and the caller
  calls `read_section` for it again. The decoder holds each blocked stream's ID and Required
  Insert Count, at most `blocked_streams_max` of them. That limit is also the most the caller
  may advertise as SETTINGS_QPACK_BLOCKED_STREAMS, and one blocked stream more than it
  advertised is QPACK_DECOMPRESSION_FAILED (§2.1.2).
- `read_encoder_stream` applies every whole encoder instruction the caller has and leaves a
  partial one unread. An instruction longer than `encoder_instruction_len_max` is
  QPACK_ENCODER_STREAM_ERROR, which §7.4 permits, so the caller never holds more than that.
- The decoder owes Section Acknowledgments (§4.4.1), Stream Cancellations (§4.4.2) and Insert
  Count Increments (§4.4.3). It queues the first two, at most
  `decoder_instructions_owed_max`, and works out the increment when it writes: the insert
  count less the Known Received Count that the queued acknowledgments leave. So every insert
  is reported, once, in the next `write_decoder_stream`.
- When the queue is full, `read_section` and `abandon_stream` return `owes_instructions` and
  do nothing, so no instruction is ever dropped. Decision 39 has h2's replies work the same
  way.
- A Required Insert Count larger than the largest reference needs is refused as
  QPACK_DECOMPRESSION_FAILED. §2.2.1 says a decoder "MAY" refuse it, and a count set too
  high blocks a stream for nothing.

The alternatives refused:
- The decoder copies a blocked section's bytes. That needs room for `blocked_streams_max`
  sections, and the caller already holds the bytes.
- A callback when a stream unblocks. Design §4 forbids colibri a call into the caller at a
  time of its choosing.
- Each decoder instruction written into the caller's buffer as it arises. That crosses the
  caller's boundary once per instruction, where one `write_decoder_stream` crosses it once.

Amended the same day, after `spec/tla/qpack_tables/` found an error in the first version. The
decoder counted every stream it held against SETTINGS_QPACK_BLOCKED_STREAMS, including one
whose entries had arrived but whose section the caller had not read again. An encoder told of
those entries by an Insert Count Increment no longer counts that stream, and may send a section
that blocks another, so the decoder refused a peer that kept the rule. §2.2.1 says a stream
"becomes unblocked when the Insert Count becomes greater than or equal to the Required Insert
Count", so the decoder now counts only streams still waiting for entries. Its list of held
streams can then fill with streams that are ready, and `read_section` returns
`read_ready_first`, consuming nothing, until the caller reads one.
