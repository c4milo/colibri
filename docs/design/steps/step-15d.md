# Design §8 step 15d: the endpoints and conformance

[Design §8, the build plan](../../design.md#8-build-plan)

- The test-only h11 server and client on Rotor.
- TLS over chapulin, with ALPN `http/1.1`, and the server choosing `h2` or `http/1.1`.
- Interop in both directions, in cleartext and over TLS, with the versions recorded. The client
  runs against Go's `net/http` and h2o, and the server takes requests from curl and Go.
- The HTTP Garden (https://github.com/narfindustries/http-garden), a differential fuzzer for
  HTTP/1.1 request streams, with colibri's server as one of its origins. Each discrepancy is
  judged against RFC 9112 before it counts as colibri's defect. The owner ruled it in on
  2026-09-25 ([decision 88](../../decisions/0088-colibri-builds-http11-as-h11-client.md)). It is GPL-3.0 and needs Docker, so it runs from
  `tools/` alone, cloned at a pinned commit.

**The interop, 2026-09-26.** `tools/h11_interop.sh --tls <checkout> go h2o` and
`tools/h11_server_interop.sh --tls <checkout> curl go`, at `03ab314` on macOS arm64 with chapulin
`b32ad68`, printed "every exchange ended as planned over h11, in cleartext and TLS, against: go
h2o" and "every request ended with 200 over h11, in cleartext and TLS, from: curl go". curl
also ran over TLS with no ALPN offer. CI runs the cleartext half on each push.

**The HTTP Garden, 2026-09-26.** `tools/http_garden.sh` runs in CI's `http-garden` job, which
pulls the origins' images from `ghcr.io/c4milo/colibri-http-garden` (decision 88 as amended).
- Run 36253110848, the Garden at `b417e806` and colibri at `dbf1d26`: 34 of 35 origins, pulled
  in 982 seconds. `eclipse_jetty` does not build, because a Maven download its image names has
  moved since the pinned commit. `protocol_http1` stopped on 8 cases; the run restarted it and
  compared those cases without it.
- Four runs before it failed on the harness, not on colibri. The Garden's tools find containers
  on the network `http-garden_default`, so compose must run under that project name. Its REPL
  stops at the first origin it cannot reach, and refuses the name of an origin that stopped.
  Each case now runs in a REPL of its own, and an origin that stops is restarted.
- 72 streams compared, 65 of them with at least one origin disagreeing. Judged against RFC 9112
  and RFC 9110, one disagreement was colibri's defect. colibri accepted whitespace that ends a
  chunk line, "5 " before CRLF, which §7.1.1 puts outside the grammar; `03ab314` refuses it.
- colibri was right where it refused and many origins accepted. A second Host, a Host carrying
  userinfo, whitespace before a colon, and obs-fold get §3.2's and §5's 400. Codings that do
  not end with chunked get §6.3's 400. A chunk size past a u64, chunk data longer than its
  size, and a lone LF on a chunk line get 400 too.
- colibri was right where it accepted and many origins refused. A leading empty line is
  ignored (§2.2). A quoted chunk extension, a CONNECT's authority-form target and `OPTIONS *`
  are parsed. An empty list member in Transfer-Encoding is ignored (RFC 9110 §5.6.1), and
  identical Content-Length values are taken (RFC 9110 §8.6). An HTTP/1.2 request is accepted,
  as RFC 9110 §2.5 has a recipient process a higher minor version, and trailer fields stay out
  of the header section (RFC 9110 §6.5.1). An empty Host and an empty port are both valid.
- Where colibri chose among what the RFCs allow, the choice stands. It refuses a lone LF
  (§2.2) and a repeated `chunked`. It reports an absolute-form target as it arrived, since
  §3.3 makes it the target URI.
- Two differences come from the harness. The body of `gzip, chunked` goes to the application
  still coded, because step 15c has not built the decoders. The echo server sends 100
  (Continue) when the content has already arrived, which RFC 9110 §10.1.1 allows, and the
  Garden reads it as the final response.
- colibri answered 501 to `Transfer-Encoding: xchunked`, a coding it does not decode, as §6.1's
  SHOULD asks. §6.3 says a request whose final coding is not chunked "MUST" get 400, and the
  origins split 11 to 12 between the two. The owner amended decision 92 on 2026-09-26 to put
  §6.3 first, and `39c0c14` answers 400. A coding it does not decode ahead of a final chunked
  still gets 501.
