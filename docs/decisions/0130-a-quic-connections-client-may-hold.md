# Decision 130: A QUIC connection's client may hold 100 requests open, and gets each stream back as it closes

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-29, after design §8 step 13i's first run on the judge.

Over h3 on a loopback path of 50 ms round trip, with 512 requests in flight over 8
connections, colibri's server reached about 2,100 requests a second. chi on quic-go and axum
on quinn reached the 4,000 offered, with a p99 near 60 ms. Two choices set colibri's rate:
- The server granted 32 request streams for each connection (`quic_requests_max`). quinn and
  quic-go grant 100.
- A stream comes back only when it closes, after the peer acknowledges the whole response.
  The server then waited until 16 streams had closed before it sent MAX_STREAMS
  (`flow_credit_fraction`).

So a stream was free again about two round trips after its request. 8 connections of 32
streams over about 120 ms give the 2,100 measured.

The rulings:
1. `quic_requests_max` is 100, h3's own count (`h3.constants.request_streams_max`). Each
   request's record holds an 8,192-byte buffer for its kept frames (decision 79), so each
   QUIC slot of an endpoint grows from 724,192 bytes to 1,328,032.
2. A stream count owes a MAX_STREAMS frame as each stream the peer opened closes, which RFC
   9000 §4.6 suggests. Data keeps decision 49's rule: credit once half the window is used.

Alternatives that lost:
- Keep 32 and send MAX_STREAMS at each close. No memory changes. By estimate, 8 connections
  then reach about 4,300 requests a second at 50 ms, against about 13,000 at 100 streams.
- 64 streams, about 1.01 MB for each QUIC slot.
- A pool of kept buffers shared by a connection's requests, so that a larger limit costs
  less. It changes decision 79 and needs a design of its own.

**Amended by the owner on 2026-11-19, for
[#139](https://github.com/c4milo/colibri/issues/139) (design §8 step 66).** A stream closes
when the peer acknowledges the whole response, so ruling 2's MAX_STREAMS often left in a
packet of its own, which the peer then acknowledged. In a qlog of 500 requests at a low rate,
199 of the server's 405 packets held a MAX_STREAMS frame alone, and an h3 request took 1.4 to
1.5 times the datagrams it took with axum on quinn. RFC 9000 §4.6 leaves to the receiver
"when and how many streams should be advertised". The ruling:

- A stream count still owes a MAX_STREAMS frame as each stream the peer opened closes.
- The frame goes out at once, in a packet of its own when no other packet goes, while the
  peer holds `flow_credit_fraction`'s half of its count unused, or less, or when a lost frame
  is owed again (§13.3).
- Above that, the frame waits, and rides after the STREAM frames of the next packet that
  elicits an acknowledgment for another reason. The peer still holds half its count, so it
  waits for no stream.

The alternative that lost: keep ruling 2 as it was, with the extra packets.
