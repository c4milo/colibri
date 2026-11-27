# Decision 92: How an h11 connection runs

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-25, for design §8 step 15b.
- colibri writes a server's error responses itself, as h2 writes its own GOAWAY and
  RST_STREAM. The response carries `Connection: close` and no content, and the connection
  closes after it. The statuses:
  - 400 for a malformed request (RFC 9112 §2.2, §3.2, §5.1, §6.3; RFC 9110 §15.5.1), and for
    a CONNECT request that declares content (RFC 9110 §9.3.6, decision 109);
  - 414 for a request line longer than `start_line_len_max` (RFC 9112 §3, RFC 9110 §15.5.15),
    unless its method holds a byte no token holds, which is a 400 at once (decision 109);
  - 431 for a head, field section or trailer section past colibri's limits (RFC 6585 §5, now in
    `docs/rfcs/`);
  - 501 for a transfer coding h11 does not decode, when chunked is the final coding (RFC 9112
    §6.1, RFC 9110 §15.6.2, decision 91). A request whose final coding is not chunked gets 400
    whatever codings it names, because RFC 9112 §6.3 makes that 400 a MUST and §6.1's 501 is a
    SHOULD. The owner amended this on 2026-09-26: the HTTP Garden showed colibri answering 501
    to `Transfer-Encoding: xchunked`, where 11 of its origins answer 400 and 12 answer 501;
  - 505 for a major version other than 1 (RFC 9110 §15.6.6).
- HTTP/1.0 keep-alive is not honoured. An HTTP/1.0 exchange closes after its response, which
  RFC 9112 §9.3 allows. HTTP/1.1 connections persist unless either side sends
  `Connection: close`, or a server refuses a CONNECT (RFC 9931 §8, decision 109).
- A server reads one request at a time. It reads the next request only after it has written
  the final response to the current one, so later pipelined requests stay unread in the
  caller's buffer. Responses go out in order with no queue (RFC 9112 §9.3.2).

The alternatives refused:
- The application writes the error response. It gains control of the content, but every
  application would have to handle every refusal the same way.
- Honouring HTTP/1.0 keep-alive. RFC 9112 Appendix C.2.2 describes how often HTTP/1.0
  implementations get it wrong.
- Reading pipelined requests ahead, up to a named limit. It allows parallel processing of safe
  methods, at the cost of a queue of pending requests on every connection.
- Answering an oversized field section with 400, which RFC 9110 §5.4's "appropriate 4xx"
  allows. 431 tells the client which limit it passed.
