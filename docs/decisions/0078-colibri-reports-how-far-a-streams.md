# Decision 78: colibri reports how far a stream's bytes are acknowledged from its start

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24, for design §8 step 12. It amends entry 57, which said colibri
reports no acknowledged prefix.

h3 writes three streams of its own that never end: its control stream (RFC 9114 §6.2.1) and
QPACK's encoder and decoder streams (RFC 9204 §4.2). Closing any of them is a connection
error. Entry 57 lets a caller drop a stream's bytes only once the stream reaches "Data
Recvd" or is reset, and these three do neither. So every byte h3 writes on them would stay
in memory for the whole connection, and the encoder stream grows with every insert.

`connection_stream_acknowledged.acknowledged_end(connection, id)` returns the offset below
which the peer has acknowledged every byte of the stream, and the caller may drop those
bytes. It keeps no new state. Each framed byte sits in one packet in flight, in the lost
table, or is acknowledged (invariant 29). So the answer is the lowest offset that an
in-flight record or a lost range of the stream holds, or the end of what was framed when
neither holds any. It scans the application space's sent records and the lost table, at most
`sent_packets_max` and `stream_lost_ranges_max` entries, and a caller asks only when it needs
room. Entry 57 refused per-stream bookkeeping of acknowledged ranges, and this adds none.

The alternatives refused:
- Emptying h3's storage for a stream only when everything framed on it is acknowledged, which
  the existing count shows. Under steady load something is always in flight, so a full
  buffer would stop inserts and acknowledgments for up to a round trip.
- A static-table-only h3: a QPACK table capacity of 0 advertised, and an encoder that stops
  inserting after a fixed budget. It needs nothing from `quic`, but no peer could use a
  dynamic table toward colibri.
