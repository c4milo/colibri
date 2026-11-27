# Decision 113: A RST_STREAM the caller asks for is owed by the stream's record, not queued

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-09-30, after the deadline work of [#82](https://github.com/c4milo/colibri/issues/82)
found the crash; the owner may overrule it. h2's reply queue asserted a free slot on each push,
among `stream_replies_max`, 32. The reading checks for one before each frame, but `reset_stream`
pushed with no check, and a server holds up to `concurrent_streams_max`, 128, streams. Assertions
stay on in production, so a caller that cancelled 33 requests between two writes stopped the
program, and so did one cancel after the peer's DATA filled the queue with WINDOW_UPDATE frames.
- `reset_stream` closes the stream, drops the credit owed on it, and marks its record with
  the error code. `write_pending` writes the marked records' RST_STREAM frames after the
  queued replies and before the GOAWAY, and clears each mark once its frame is written whole.
  `resets_owed` counts the marks, so a write with none walks no record.
- A marked record is not dropped. An open that finds every slot held by an active stream or
  a marked one waits for a write: a server consumes no HEADERS frame, and `has_pending` says
  why, and a client's `write_request` returns `error.Full`. A stream past the limit a server
  advertises is refused, which takes no slot, so it waits for nothing.
- A stream owes one RST_STREAM at most, because the reset closes it. RFC 9113 §5.4.2 says an
  endpoint "SHOULD NOT send more than one RST_STREAM frame for any stream".
- The queue holds the replies to the frames colibri reads, under the same limit. One frame
  owes at most one reply about one stream, which `receive` now asserts, so the free slot
  `is_full` leaves holds it.
- `reset_stream` keeps its signature, and no longer depends on room.

The alternatives refused:
- A queue sized for every reply that can be owed. A server's resets need active streams, so
  its queue is bounded by `stream_replies_max` plus `concurrent_streams_max`. A client's is
  not: it opens streams with `write_request`, so opens and resets in a loop grow the queue
  without end, unless opens wait on it too. It also changes a named limit.
- `reset_stream` failing with a named error, which each caller retries after it writes. Each
  caller would keep its own list of the resets it still owes: the server's `cancel`, the
  client's, and the server's deadlines, which reset many streams at once.
- A mark on the record for every RST_STREAM about a stream with one, those the reading
  decides included. The reading already stops for a full queue, so this changes the order of
  the frames it owes, and the simulator's bound on them, for no case the queue fails.

`spec/tla/h2_flow_control` models the caller's resets: the queue stays within its limit with
the resets on the records, and passes it with the resets queued and no room checked.
