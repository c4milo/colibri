# Decision 126: The `server` and `client` APIs name each HTTP concept once, in colibri's own model

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-20 and 2026-10-21. The RFCs name one concept in different words for
each version, so they cannot give one API across h11, h2 and h3. The owner: "clearly the RFCs are
not letting us align concepts and API across the different http versions", and "So, we have to model
it ourselves".

The rule:
- `server` and `client` name each concept once, the same for h11, h2 and h3, with the word
  programmers know. A name a program writes is the same whichever version carries it.
- The protocol modules (`h11`, `h2`, `h3`, `hpack`, `qpack`, `quic`, `http`) keep each RFC's
  own words, and every comment that cites an RFC keeps them too.
- docs/usage.md defines each API word once, with the term each version's RFC uses for it.

The model, against each RFC's words:

| Concept | API name | RFC 9110 | h11 (RFC 9112) | h2 (RFC 9113) | h3 (RFC 9114) |
| --- | --- | --- | --- | --- | --- |
| One name and value | `Header` | field line (§5.2) | field line (§5) | field (§8.2) | field line (§4.2) |
| The set of them | `Headers` | header section (§6.3) | "headers" or header section (§2.1) | field block (§4.3) | header section in a HEADERS frame (§4.1) |
| Fields after the content | `Trailers` | trailer section (§6.5) | trailer section (§7.1.2) | trailers in a field block (§8.1) | trailer section in a HEADERS frame (§4.1) |
| The bytes of a message | `RequestBody`, `ResponseBody`, `body` | content (§6.4) | message body (§6) | DATA frames (§8.1) | DATA frames (§4.1) |
| A unit of the wire | bytes | octets | octets | octets | octets |
| Which HTTP | `Protocol`, `Protocols` | protocol version (§2.5) | HTTP/1.1 | h2 | h3 |
| A request's name | `RequestId` | none | its place on the connection | stream identifier (§5.1.1) | stream ID (RFC 9000 §2.1) |
| How long a peer may take | `Timeouts` | none | none (§9.5 names a timeout) | none | none |

The rulings, each against what it beat:
1. Headers. `Header`, `Headers` and `headers` replace `Field`, `Fields`, `FieldSection` and
   `fields` in `server` and `client`. `Trailers` holds `headers: Headers`, as Go's `Trailer`
   holds an `http.Header`. `WantedHeader` replaces `Wanted`, and `NeverIndexed.headers`
   replaces `NeverIndexed.fields`. Beat: "field section" and "field line", which CLAUDE.md
   settled for the API until now.
2. Bodies. `RequestBody` replaces `server.Body`, `ResponseBody` replaces `server.Content`,
   and `client.Request.body` replaces `client.Request.content`. Beat: "content", RFC
   9110's word, which h11's own RFC calls the message body.
3. The end of a request. Both sides report one `finished` event, with a `Result`. The
   server's `done` and `cancelled` merge into it: its result is `sent`, or `cancelled` with
   its reason. `client.Result` replaces `client.Outcome`, as the owner ruled on 2026-10-21:
   "outcome" is not a common word. Beat: the two events of decision 119, a rename alone, and
   `End` and `Status`, which name a frame's end and the HTTP status code.
4. `RequestId` names a request on both sides. Beat: `Id`, which named a request on the
   server and an exchange on the client.
5. `server.Request` and `server.Response` keep their names. Beat: `RequestHead` and
   `ResponseHead`.
6. `Protocols` replaces `Versions`, beside `Protocol`. `server.Version` keeps the number a
   request carried, since h11 has 1.0 and 1.1.
7. `Timeouts` replaces `Deadlines`, `Timeout` replaces `Deadline`, and the close reason
   `timeout` replaces `deadline`. Their values are durations; a deadline is an instant, so
   `deadline_ns()` keeps its name.
8. `client.ConnectionPool` and `client.ConnectionPoolOf` replace `Pool` and `PoolOf`, the
   owner's own names. Beat: one word `Pool` for the client's connections, its codec pools and
   its receive pool.
9. `server.Endpoint` keeps its name: RFC 9000 §1.2 calls each side an endpoint, and a server
   endpoint takes part in many connections. CLAUDE.md's definition says so now. Beat:
   `server.Server` and `server.ConnectionPool`.
10. `client.HttpsRecord` replaces `client.Https`. Beat: `Svcb` and `HttpsRr`. A program that
    uses cocuyo also meets `cocuyo.Https`, its configuration of DNS over HTTPS.
11. Bytes. `StreamBytes` replaces `StreamOctets`, and fields named `octets` become `bytes`.
12. `accept` takes `.{ .tls = false }` for a cleartext socket, and runs TLS by default, as the
    owner ruled on 2026-10-24. Beat: the `Security` enum, and cleartext by default.
13. `client.Destination` and `set_destination` replace `Values` and `set_values`. Beat:
    `Resolved`, since the Alt-Svc alternative does not come from DNS.
14. `client.Options` folds into `client.Config`. The client then has `Capacity` and `Config`,
    as the server has. `memory_bytes` takes the two counts, `.{ .tcp_connections = n }`,
    because a `Config` with TLS values cannot size a static array (the owner, 2026-10-24).
    Amends decision 125 ruling 2.
15. `ReceiveResult` replaces `Received`, what `receive` returns: the bytes taken and one
    event. Beat: `ReceivedBytes`, which names only the first half.
16. `CpuFeatures` names the CPU's answers in both places: the codec pools' `Features`, and
    the probe beside `Timing` in `tls.Cpu`. Its design waits for stdx, and comes back to the
    owner before code.
17. Kept: exchange (decision 125), `ended`, `close` and `closed`.

Every rename is breaking, and 0.9.0's notes list each one.

Amended by the owner on 2026-11-27, as "Bytes in all prose" and "Change it all now", while
design §8 step 79 was built:
- **All prose and every comment say "bytes", the API's word.** This holds in the protocol
  modules and in a comment that cites an RFC too. A quotation of an RFC keeps its words, and
  so do an ABNF rule such as `OCTET` (RFC 5234 Appendix B.1) or `dec-octet` (RFC 3986
  §3.2.2) and a name in the code, such as `first_octet`. The protocol modules keep "field
  line", "field section" and "content", as ruled.
- **The text in the tree changed at once.** One commit changed each "octet" of the prose
  and the comments, and left the code, its strings and each quotation as they were. The
  tables that give each RFC's own term, here and in docs/usage.md, keep "octets".
- The alternatives refused:
  - "bytes" in docs/ and CLAUDE.md alone, which leaves the comments in two words.
  - "bytes" in CLAUDE.md's own text alone, under the rule as it stood.
  - Changing the old text only when a later change edits it.
