# Decision 109: What h11 does with the bytes after a CONNECT or an Upgrade request

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-29, after RFC 9931 joined `docs/rfcs/`. It amends decision 92. RFC
9931 §4.1 names the hazard: until the answer arrives, the client cannot know whether the server
reads what follows as HTTP/1.1 or in the new protocol, and a server that reads it as HTTP/1.1 can
take a smuggled request from it.
- A final response to CONNECT other than 2xx ends the connection: h11 adds
  `Connection: close` to it and reads nothing after it (RFC 9931 §8). h11 cannot tell a proxy
  from an origin, so the rule holds at every h11 server. RFC 9931 §8 lets a proxy skip it for
  a client known to wait for the 2xx, and h11 does not.
- Every 2xx to CONNECT opens the tunnel, 204 included (RFC 9110 §6.4.1, §9.3.6). h11 applied
  RFC 9112 §6.3 rule 1 to a 204 before rule 2, so it read the bytes after one as HTTP where
  the peer had started the tunnel. A server refuses Content-Length and Transfer-Encoding on a
  2xx to CONNECT (RFC 9110 §8.6, RFC 9112 §6.1).
- A CONNECT request declares no content (RFC 9110 §9.3.6). A client's `write_request` refuses
  one that does, with `FramingInvalid`, and a server answers one with 400 and closes, as it
  answers any malformed request. `Content-Length: 0` declares none. So every byte after a
  CONNECT head belongs to the tunnel a 2xx opens, and is never read otherwise.
- A client refuses a request carrying Upgrade, with `UpgradeUnsupported`, as the `client`
  module does. h11 implements no upgrade: its server writes no 101 and its client fails on
  one, so the invitation could only make a server read what follows in a protocol the client
  does not speak.

The alternatives refused:
- For a refused CONNECT: the close with an opt-out for a client the caller knows waits for
  the 2xx, which is RFC 9931 §8's MAY and more API; and leaving the close to the application,
  which every proxy would have to remember.
- For a 2xx to CONNECT: the tunnel fixed and the framing fields left for later; and both left
  as they were.
- For content on CONNECT: a refusal at the client alone, so a server still reads a body that
  RFC 9110 §9.3.6 says the request does not have; and both ends left as they were.
- For Upgrade: sending it but pipelining nothing after it until its final response, which
  would amend decision 88; and leaving it, so a 101 fails the connection and the requests
  pipelined after it go unanswered.

Amended by the owner on 2026-09-29: the head scanner refuses a request line at the first
byte of its method that no token holds, and at an SP where the method would start (RFC 9110
§9.1), with 400. A TLS record sent after an ignored `Upgrade: TLS/1.2` starts with 22, so the
server now answers it at once (RFC 9931 §6.1). The scanner judged a line only when it ended,
so such a record got 400 when it held a stray CR or LF, 414 after `start_line_len_max` bytes
without one, and otherwise nothing while the server waited for more. The alternatives
refused: checking the request line's first byte alone, and leaving the scanner as it was.
