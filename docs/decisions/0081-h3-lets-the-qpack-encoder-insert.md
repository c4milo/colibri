# Decision 81: h3 lets the QPACK encoder insert only what the encoder stream's flow-control credit carries

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-09-24 for design §8 step 12; the owner may overrule it. It carries out entry 76,
whose encoder takes the room of the encoder stream's writer as "the flow-control credit §2.1.3 asks
the encoder to respect".

h3 gave the encoder its buffer's free room instead of the credit. `spec/tla/h3_connection`
then found the deadlock RFC 9204 §2.1.3 warns of:
1. The encoder wrote an insert while the encoder stream had no credit.
2. The section that referenced the insert went out on a request stream, which had credit, and
   blocked at the peer (§2.2.1).
3. A blocked section stays unread (entry 80), so blocked sections held the peer's whole
   connection window.
4. The peer consumed nothing more and sent no credit, so the insert never went out.

`connection_stream_credit.send_credit(connection, id)` returns the bytes a stream can still
send. That is the smaller of the stream's credit and the connection's, each less the bytes
not yet framed that spend it first. For the connection's credit, those are the bytes of every
stream that RFC 9000 §2.3's order frames before this one or in turn with it. h3 cuts the
encoder's writer to that length. An insert the credit cannot carry is not made, and the
encoder writes the line as a literal.

The alternatives refused:
- Leave it to the receiver's windows. Blocked sections cannot fill a connection window larger
  than SETTINGS_QPACK_BLOCKED_STREAMS times a request stream's window. But the encoder's side
  sets neither window, and windows grow (entry 49).
- Hold the insert in the encoder until credit arrives. Entry 76 inserts before it writes the
  section, and a section that references a held entry blocks all the same.
