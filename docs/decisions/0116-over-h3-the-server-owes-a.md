# Decision 116: Over h3 the server owes a 100 (Continue) on a request's head alone, and none to a request whose stream has ended

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-10-04 for design §8 step 17i; the owner may overrule it. The server over TCP owes a
100 (Continue) to a request that expects one and has content (design §8 step 17a). The server over
QUIC owed none, so a client that sent `expect: 100-continue` waited until the caller answered or its
own timer ran out.
- RFC 9110 §10.1.1 has a server that reads the expectation send a final response at once
  or "an immediate 100 (Continue) response". It may omit the 100 when it "has already
  received some or all of the content", or when "the framing indicates that there is no
  content".
- Over h11 and h2 the head says whether content follows, and `request.end` reports it. h3
  ends a request where its stream ends (RFC 9114 §4.1) and reports that apart from the
  head, so a `request` event over h3 never says the request ended. So the server owes
  the 100 on the head alone.
- When the connection writes the 100, it looks at the request's stream. Once the stream's
  final size is known (RFC 9000 §4.5) and h3 has taken every byte below it, nothing more
  of the request arrives: the stream ended with the head, or every byte of the content
  has been read. Such a request gets no 100. Every other request that expects one gets
  it, whether or not content has begun to arrive, as over h2.
- The connection writes the 100 when it next settles its requests, which `receive` does
  first and `send` does when a 100 may be owed. A caller that answers the request before
  its next call answers first: a final response or `cancel` leaves no 100 to write, and
  the caller's own 100 is the one owed.
- A 100 that finds no free run among its response's runs stays owed until the peer
  acknowledges one (RFC 9000 §3.1), and delays no other request.

The alternatives refused:
- A 100 for every request that expects one, whether or not its stream has ended. It needs
  nothing from the stream, but a request with no content gets an interim response no
  client waits for, where the server over TCP sends none.
- h3's `request` event saying that the stream ended with the head, so that `request.end`
  is true over h3 as over h2. It changes h3's event and what a program reads over h3, and
  a FIN that arrives in a later packet is still unknown at the head.
- Omitting the 100 once the stream's final size is known, since the client has then sent
  its last byte. When the content was lost and the FIN alone arrived, the server has
  received none of the content, and RFC 9110 §10.1.1 then requires the 100.
- Waiting for content, or for the request's end, before deciding. RFC 9110 §10.1.1: the
  server "MUST NOT wait for the content before sending the 100 (Continue) response".
- One 100 owed for each connection, as over TCP, with `receive` reporting nothing while it
  waits for room. A TCP connection has one output for every stream. Over QUIC one
  request's response would delay the events of every other stream.

Cost: 8 bytes for each request a QUIC connection holds, 256 for a connection, and a branch
for each request each time the connection settles them.

**Amended on 2026-11-05, for design §8 step 29d.15, at the owner's ruling.** The owner asked
why each h3 GET costs three events. A request whose FIN arrives with its HEADERS frame now
reports `request.end` true over h3, as h2 reports `end_stream` (RFC 9113 §8.1).
- h3 reads the HEADERS frame and then takes the bytes after it from `quic`. When that take
  reaches the stream's final size (RFC 9000 §4.5), the stream ended with the head. h3 then
  runs the checks of its end at once: a content-length that is not zero is malformed (RFC
  9114 §4.1.2), and h3 refuses the stream.
- h3's `request` event gains one field, `end`. When it is true, no `end` event follows for
  that stream. The server sets `request.end` from it, starts no body deadline, and reports
  no `body` event.
- A FIN that arrives in a later packet is still unknown at the head. That request reports
  `end` false, then an empty `body` with `end` true, as before. A program must still read
  both forms, as it does over h11 and h2.
- The rule of the 100 (Continue) above stays for that later FIN. A request whose head says
  it ended gets no 100, as over h2: "the framing indicates that there is no content" (RFC
  9110 §10.1.1).
- A head with a content-length above zero and a FIN with it is refused before the program
  hears of it. Before, the program read the request and then its cancellation.

What it gains: one event and one call of `receive` less for each such request. Callgrind on
a laptop counted about 340 of the server's instructions for each event on h3-many, where
h2load sends each GET's FIN with its head. The judge measures it before the step lands.

Why the refusal above no longer holds:
- "It changes h3's event and what a program reads over h3." The change is one field of
  h3's event. The server's event already has `end`, which h11 and h2 set, so a program of
  the server reads nothing new.
- "A FIN that arrives in a later packet is still unknown at the head." It still is, and
  that request keeps the old order. The amendment only reports a FIN that h3 has already
  read.

Cost: one field on a public type of `h3`, and a second order of events over h3 that the
simulator's h3 endpoints and the test-only h3 server must each handle.
