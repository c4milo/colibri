# Decision 88: colibri builds HTTP/1.1 as h11, client and server

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24 and 2026-09-25, for https://github.com/c4milo/colibri/issues/60. It
amends entry 2.
- Both roles, for completeness. The server takes on the request smuggling surface of RFC 9112
  §11.2, so every request-parsing check has a test proved by mutation.
- The name is h11, as h2 and h3 name the other two, in prose, in the module name `src/h11/`
  and as a commit scope.
- The order is h3, then h2, then h11. RFC 9114 §3.1 lets a client try QUIC with ALPN `h3`
  first, and says clients "SHOULD attempt to use TCP-based versions of HTTP" when that fails.
  The TCP connection's ClientHello offers `h2` and then `http/1.1` (RFC 7301). colibri opens no
  connection, so the caller follows the order, and the test-only client of `src/testing/`
  does.
- The client pipelines (RFC 9112 §9.3.2). The connection keeps its requests in order and gives
  each response to the oldest one. It does not pipeline after a non-idempotent method until
  that method's final status arrives. When the connection closes, colibri reports which
  requests went unanswered, and the caller opens the next connection, on which the client
  does not pipeline at once.
- `h11` imports `core`, `http`, `tls` and `deflate`. `tls` lets it attach to a finished
  handshake and check what ALPN selected. Entry 90 moves `deflate` to stdx.
- Amended by the owner on 2026-09-25, for design §8 step 15d: h11 runs when ALPN selected
  `http/1.1` or selected nothing, and refuses any other selection (RFC 7301 §3.2). RFC 9846
  §4.2.2 has a server ignore an extension it does not recognise, so a server without ALPN
  answers with none, and RFC 9112 §9.7 asks for no ALPN. curl, Go's `net/http`, browsers,
  nginx and h2o all speak HTTP/1.1 on such a connection. The alternative refused: h11 runs
  only when ALPN selected `http/1.1`, as h2 runs only on `h2`. It is the strict side, but h2
  has RFC 9113 §3.3's MUST behind it and h11 has none, and it would refuse every peer that
  does not negotiate ALPN.
- h11 decodes three transfer codings: `chunked` (RFC 9112 §7.1), `gzip` and `deflate` (§7.2).
  A server answers 501 to any other coding, `compress` included (§6.1). It answers 400 and
  closes the connection when a request's last coding is not `chunked` (§6.3).
- The test-only endpoints run on Rotor from their first commit (entry 83).
- The HTTP Garden (https://github.com/narfindustries/http-garden) checks h11's server, ruled
  by the owner on 2026-09-25. It is a differential fuzzer of HTTP/1.1 request streams. It runs
  from `tools/` alone, cloned at a pinned commit into a cache as `tools/interop.sh` clones the
  QUIC Interop Runner, and nothing of it is linked or shipped. Its license is GPL-3.0, which
  reaches no colibri code, because colibri only runs it. It needs Docker.
- Amended by the owner on 2026-09-25, for design §8 step 15d: the Garden's job publishes the
  images it builds as public images in one package, `ghcr.io/c4milo/colibri-http-garden`,
  tagged by the Garden's commit, so a later run pulls them instead of building every origin
  for hours. The images carry the Garden's GPL-3.0 code and each origin's own; their source is
  the pinned public repositories they are built from. colibri's own image is never published.
  The alternatives offered: the Actions cache, whose 10 GB the push job's Zig caches already
  fill; private images, whose free storage is far smaller than the images; and rebuilding on
  every run.
- Amended by the owner on 2026-09-28: the clone carries one patch,
  `tools/http_garden/jetty_maven.patch`. The pinned eclipse_jetty image fetches Maven
  4.0.0-rc-5 from dlcdn.apache.org, which no longer serves it, and the patch fetches it from
  archive.apache.org. The alternative offered: leaving jetty out, as the script does with any
  origin whose image no longer builds.

The alternatives refused for transfer codings, both offered on 2026-09-25:
- `chunked` alone, refusing the rest. It is the smallest surface, and needs no decoder.
- `chunked` removed and the other codings passed to the caller still encoded. It moves the
  decoding into every caller, and the server still needs the caller to accept or refuse.
