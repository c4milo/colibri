# Decision 69: An endpoint with `ecn_marks` tests a path with its first ten marked packets or three PTOs, whichever ends first, as RFC 9000 Appendix A.4 describes

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24.

Decision 68 marked every datagram until §13.4.2.1's count checks failed. A path that drops
marked packets never lets an ACK through to fail them, so every packet is lost and the
connection dies. §13.4.2 names the remedy: "the endpoint could set an ECT codepoint for only
the first ten outgoing packets on a path, or for a period of three PTOs". Appendix A.4 gives
the path four states:
- testing: marks ECT(0). It ends once ten marked packets have gone out
  (`ecn_testing_packets`) or three PTOs have passed since the first did
  (`ecn_testing_probe_timeouts`), whichever comes first.
- unknown: sends Not-ECT. An ACK frame that passes validation, once any marked packet has been
  acknowledged, makes the path capable.
- capable: marks ECT(0).
- failed: sends Not-ECT for the rest of the connection. Validation failing reaches it from any
  state (§13.4.2.2).

The two limits are §13.4.2's numbers. Ten packets alone was ruled first and replaced the same
day: before any round trip sample the PTO is about one second and doubles with each expiry,
and a client sends at most two probes each time, so a handshake on a path that drops marked
packets would take about 31 seconds to send ten, past a 30-second idle timeout. Three PTOs
end the test after about seven.

The alternatives refused:
- Mark every packet until validation fails, which decision 68 did alone. A path that drops
  marked packets ends the connection.
- Fail validation once every marked packet sent so far is declared lost. The first Initial
  lost to ordinary loss would then turn ECN off for the whole connection. Appendix A.4 lets an
  endpoint mark such a path failed; here it stays unknown, which sends the same Not-ECT and
  still becomes capable if a late acknowledgment shows a marked packet arrived.
