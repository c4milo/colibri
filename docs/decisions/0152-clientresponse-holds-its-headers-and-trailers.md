# Decision 152: `client.Response` holds its headers and trailers in a `Headers` and a `Trailers`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-05 (design §8 step 38), with points 7 to 9 added the same day, for a
dependent that implements Connect and gRPC, whose status arrives in trailer fields such as
`grpc-status`. Until now the client dropped each trailer section, and kept only the header fields a
program listed in `wanted`. The owner found `WantedHeader` "weird and uncommon" as a type name. This
amends ruling 1 of decision 124.
1. `Response.headers` is a `client.Headers`, and `Response.trailers` is a `client.Trailers`.
   Each one holds a buffer the program gives, and the client copies each field line of its
   section into it.
2. `get(name)` returns the value of the first field line with that name, compared
   case-insensitively (RFC 9110 §5.1), or null. `iterator()` returns each field line in
   the order it arrived, for a field such as Set-Cookie that cannot be joined (RFC 9110
   §5.3).
3. A section that does not fit its buffer ends the exchange `too_large`. A program that gives
   no buffer for a section drops it: no trailers, as before, and no headers.
4. The client keeps trailer fields apart from header fields (RFC 9110 §6.5.1).
5. `Response.wanted`, `Response.values`, `Response.values_len` and `WantedHeader` leave the
   API. A dependent's code breaks at the next release.
6. Two types, not one, so that a program cannot pass trailers where headers go. The names
   are the words programmers know (decision 126), and `trailers` is the word the server's
   `ResponseWriter.trailers` already uses.
7. When `Response.trailers` has a buffer, the client sends `te: trailers` (RFC 9110 §10.1.4),
   unless the program's headers name TE. A gRPC server over h2 refuses a request without it.
8. A program sends trailers with `Request.trailers: []const Header`, empty by default, the
   type `Request.headers` has. Over h11 such a request is sent chunked, never with a
   Content-Length (RFC 9112 §7.1.2). Over h2 and h3 the trailers end the stream in a
   HEADERS frame (RFC 9113 §8.1, RFC 9114 §4.1). The client names each trailer field in a
   `Trailer` header field (RFC 9110 §6.6.2).
9. `request` refuses a trailer field that frames or routes the message (RFC 9110 §6.5.1):
   Content-Length, Transfer-Encoding, Host, TE and Trailer. It returns a new member of
   `RequestError`, `InvalidTrailer`.

Alternatives that lost:
- Keep `wanted` and type trailers as `[]WantedHeader`. It names a trailer a header, and
  programmers do not know the pattern.
- Keep the list of names and only rename the type. A lookup over the whole section is the
  shape Go's `Header.Get` and fetch's `headers.get` give.
- `trailing_headers`. RFC 9110 §6.5 calls them trailer fields, and Go, Node and curl call
  them trailers.
- Wait for streamed bodies. Trailers do not depend on them.

Amended by the owner on 2026-11-06, after the build of design §8 step 38b:
- `InvalidTrailer` refuses more than ruling 9 names, and the owner accepted each refusal.
  It also refuses the connection-specific fields Connection, Keep-Alive, Proxy-Connection
  and Upgrade (RFC 9113 §8.2.2). It refuses a name with an uppercase letter, which h2 and h3
  refuse (RFC 9113 §8.2.1, RFC 9114 §4.2). It refuses a name or a value that RFC 9110 §5.1
  or §5.5 refuses, and a section larger than `field_section_size_max`.
- Over h3 the header section and the trailer section share one prefix of 16,436 bytes for
  each stream. A request whose two sections do not fit in it together ends `invalid` at
  `open`. docs/usage.md states it.
- `added_fields_max` goes from 3 to 5, for TE and, over h11, Connection.
