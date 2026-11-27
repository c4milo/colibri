# Design §8 step 15b: the connection

[Design §8, the build plan](../../design.md#8-build-plan)

Persistence (§9.3), the client's pipelining with responses matched to requests in order (§9.3.2), a
server that reads one request at a time, and closing (§9.6). **Check:** a simulator check over step
2's byte pipe. A colibri client and server exchange seeded requests, pipelined, with chunked and
length-delimited bodies and early closes, in pieces, and a seed replays byte for byte (invariant 5).
Golden cases and mutations.

**Check passed, 2026-09-25**, `60cd6f6` to `199a52d`, on macOS arm64 with Zig 0.16.0.
- `60cd6f6`: the connection. A server reads one request at a time and writes the error response
  a refused request owes. A client pipelines as decision 88 rules and gives each response to
  its oldest request.
- `eda6c24`: the close option ends the connection after the response it names, at both ends
  (RFC 9112 §9.6). Writing the simulator check found the server's half.
- `aa11d3f`: the simulator check, `src/sim/h11_exchange_check.zig`. It does not use
  `sim.pipe.run`, which feeds one stream fixed before the run to one subject. A client's
  requests depend on the responses it has read, so the check keeps one stream each way and cuts
  each into chunks of 1 to `chunk_len_max` bytes, as the pipe does.
- `199a52d`: 14 golden cases of the `h11_server` format, request streams a server reads, each
  with the error response it owes as its verdict. A 414 and a 431 need a head longer than
  `case_len_max`, so the connection's unit tests hold those two.

What each check printed:
- `zig build test`: 1752 of 1816 tests passed, 64 skipped.
- `zig build sim -- --h11-connection-check`, in Debug and in ReleaseSafe: `h11-connection:
  seeds=256 answered=828 unanswered=82 steps=10864 trace_octets=122134 crc32=0x701b34cd`.
  Each seed's exchanges were the same in seeded chunks as delivered whole, every body matched
  the plan's, and the 82 requests pipelined past a close went unanswered.
- Mutations: 62 CAUGHT and 1 NOT CAUGHT. 38 were caught by the connection's unit tests, 3 in the
  close fix, 13 by the simulator check alone and 8 by the golden cases alone. The NOT CAUGHT
  mutant passes the simulator check: a client that ignores its own close option. colibri's
  server always answers that request with the close, so the check cannot reach the rule, and
  the client's unit test catches it.

**A body the caller sends itself, 2026-09-26.** `Connection.count_body` counts bytes the
caller sends from its own buffer against the body its head declared, and writes nothing
([decision 95](../../decisions/0095-h11-counts-body-bytes-the-caller.md)). A chunked body refuses it. 6 mutations, 6 **CAUGHT** by the
connection's unit tests.

**RFC 9931, 2026-09-29.** RFC 9931 updates RFC 9112 with rules for the bytes a client sends
before a CONNECT or an Upgrade is answered, and `docs/rfcs/` now holds it. The owner ruled on
what h11 does with those bytes ([decision 109](../../decisions/0109-what-h11-does-with-the-bytes.md)). What was checked, and what
changed:
- §8, the server: a proxy server MUST close the connection when it refuses a CONNECT. h11 read the
  next request after any final response to CONNECT other than 2xx, so it served the POST of
  RFC 9931 Figure 1. `f109a15` closes the connection after every such response, at every h11
  server.
- §8, the client: a proxy client MUST wait for the 2xx before it forwards the tunnel's bytes,
  or send `close`. h11's client pipelines nothing after a CONNECT, which is not idempotent, and
  opens the tunnel's writer only on the 2xx. Content declared on the CONNECT was the one way to
  write bytes before the answer, and `de5b5f4` refuses it at both ends (RFC 9110 §9.3.6).
- The tunnel: RFC 9110 §6.4.1 makes every 2xx to CONNECT a tunnel, a 204 too, and h11 read a
  204 as an ordinary response at both ends. `75d7320` opens the tunnel on it. A server now also
  refuses to write Content-Length or Transfer-Encoding on a 2xx to CONNECT, which RFC 9110 §8.6
  and RFC 9112 §6.1 forbid.
- Upgrade: h11 implements none. Its server writes no 101 and reads the next request as HTTP/1.1,
  which RFC 9110 §7.8 and RFC 9931 §5 allow. Its client failed on a 101 but still sent the
  Upgrade a caller named, and `209d2a3` refuses that request, as the `client` module does.
- §6.1: a TLS record sent after an ignored `Upgrade: TLS/1.2` is never read as a request. The
  head scanner refuses it once it meets a bare CR, a lone LF or a start line longer than
  `start_line_len_max`. It does not refuse the record's first byte, 22, on its own, so the
  server may wait for more bytes before it answers. The paragraph below changes that.
- §6.3 updates RFC 9298's `connect-udp`, which colibri does not implement (decisions 19 and 22).
  h2 and h3 are outside §8, which binds HTTP/1.1 alone.
- The test-only server answered CONNECT with 200 and a Content-Length, and opens no tunnel.
  `8f842b9` answers 501 over h11 and h2, and h11 closes after it. The HTTP Garden sends it the
  golden corpus's CONNECT case, which now gets that 501.

What each check printed, on macOS arm64 with Zig 0.16.0:
- `zig build test`: 128 of 128 steps and 2361 of 2361 tests passed. `golden-check` read the new
  server case `h11_server_connect_content`, a CONNECT with content, which owes a 400.
- `tools/h11_server_interop.sh --tls curl go` printed "every request ended with 200 over h11,
  in cleartext and TLS, from: curl go", and `tools/h11_interop.sh --tls go h2o` printed "every
  exchange ended as planned over h11, in cleartext and TLS, against: go h2o". `tools/h2spec.sh
  18443 --tls` passed 144 of 146 cases in cleartext and over TLS, skipping decision 41's two.
  The HTTP Garden needs Linux, and did not run.
- Mutations: 24 **CAUGHT** and 1 equivalent. By commit: 4 in the close after a refused
  CONNECT, 6 in the 2xx rules, 8 in the content rules, 4 in the client, and 2 in the test
  server. The golden case alone catches the read side's content check dropped. Two of the
  client's were **NOT CAUGHT** until `209d2a3` added its test: CONNECT counted as idempotent,
  and the tunnel's writer opened with the CONNECT head. The equivalent mutant writes the test
  server's content after its 501, which the `server` module refuses.

**The first byte of a request line, 2026-09-29.** The owner ruled that the head scanner refuse
a request line at the first byte of its method that no token holds, and at an SP where the
method would start (RFC 9110 §9.1, decision 109 as amended). A TLS record sent after an ignored
Upgrade now gets its 400 at its first byte. `zig build test` passed 128 of 128 steps and 2370
of 2370 tests, and the golden corpus's verdicts did not change. Mutations, each **CAUGHT**: the
check dropped, only DEL refused, an empty method let through, the method never ending at its
SP, status lines checked too, and the check running past the start line.
