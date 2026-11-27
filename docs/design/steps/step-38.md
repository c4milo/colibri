# Design §8 step 38: response headers and trailers in the client, proposed 2026-11-05

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 152](../../decisions/0152-clientresponse-holds-its-headers-and-trailers.md). A dependent that implements Connect and gRPC needs
`grpc-status` and `grpc-message`.
- **The public names:** `client.Headers` and `client.Trailers`, each with `get` and
  `iterator`, the fields `Response.headers`, `Response.trailers` and `Request.trailers`, and
  `RequestError.InvalidTrailer`. `Response.wanted`,
  `Response.values`, `Response.values_len` and `client.WantedHeader` leave the root's list.
- **The commits.** Step 38a, the response's header and trailer sections, shipped in v0.14.0.
  Step 38b, `Request.trailers`, `RequestError.InvalidTrailer` and `te: trailers`, ships in
  v0.15.0, after step 39, because both change the client's request path (the owner's ruling of
  2026-11-05). v0.15.0 ships without step 44, which moves to v0.16.0 (the owner's ruling of 2026-11-08).
- **The rules.** The client copies each field line into its section's buffer before
  `finished`: the header section over each protocol, and the trailer section from h11's
  chunked trailer section (RFC 9112 §7.1.2) and from the trailing HEADERS frame of h2 (RFC 9113
  §8.1) and of h3 (RFC 9114 §4.1).
- **The checks.** Over each protocol, a server sends `grpc-status` in its trailers and the
  program reads it with `get`. A header field of the same name stays apart. Two Set-Cookie
  lines come back from `iterator` in order. A section too long for its buffer ends
  `too_large`. A request with trailers reaches each protocol's server with them, chunked over
  h11 and with a `Trailer` header. A response with a trailer buffer sends `te: trailers`. A
  trailer named Content-Length is refused. The examples, docs/usage.md and the client trace
  run move to the new fields.
- **The build of 38b, 2026-11-06.** `Request.trailers` is a field, and `InvalidTrailer` joins
  the switch of the root's test of `RequestError`. No name joins a public list.
  - Over h11 a request with trailers goes chunked with no Content-Length, and the last chunk
    carries the section. A whole body goes as one chunk, from the program's memory.
  - Over h2 no DATA frame carries END_STREAM, and a HEADERS frame of the section ends the stream
    after the last piece.
  - Over h3 the section is encoded at `open`, after the HEADERS frame in the stream's `prefix`.
    The stream supplies it after the last piece, with FIN. `prefix_len` became a `u32`, and the
    new `trailers_len` is a `u32`, so `RequestStream` keeps its size.
  - Each protocol sends one `Trailer` line for each trailer field. With a trailer buffer, and
    no TE among the program's headers, the client sends `te: trailers`. h11 also sends
    `Connection: TE` whenever the request carries TE (RFC 9110 §10.1.4).
  - `added_fields_max` went from 3 to 5, for TE and h11's Connection. The Trailer lines count
    apart. The owner approved the change on 2026-11-06, and the test of
    `src/client/constants_limits.zig` pins 5.
  - `request` refuses with `InvalidTrailer` the five names of decision 152 ruling 9 and the other
    connection-specific fields. It also refuses a name with an uppercase letter, which h2 and h3
    refuse (RFC 9113 §8.2.1, RFC 9114 §4.2), and a name or value RFC 9110 §5.1 or §5.5 refuses.
    The pool chooses the protocol, so a field that one protocol refuses is refused on all.
  - A review found that `request` did not limit the size of a trailer section. A section too
    large for h11's output ended the whole connection, and over h2 it ended the exchange after
    the body went out. `request` now refuses a section larger than `field_section_size_max`, so
    h11 and h2 always write it, and an assertion states it. Over h3 the two sections share the
    stream's `prefix`, so a request whose sections do not fit it together ends `invalid` at
    `open`. A test drives that path, and its removal is **CAUGHT**.
  - `examples/client_stream.zig` sends `x-message-count` as a request trailer, and its server
    reads it and then ends the response.
  - In the client trace run, each request with content carries `grpc-status: 0`. No draw decides
    it, so each seed draws what it drew before. Each server notes whether a request's end came
    after that section, and the run requires it for each such request and for no other. The
    census gains `trailers=113`, and every other count stays. The 72 TLA+ logs of
    `--client-trace-write` are identical byte for byte to those of `174030a5`, so no model or
    configuration changed.
- **What was run for 38b, 2026-11-06,** on macOS 26.6.2 arm64 with Zig 0.16.0. Each exited 0:
  `zig build lint`, `zig fmt --check build.zig bench build examples src tools`, `zig build
  test`, `zig build test-sim-run`, `zig build examples`, `tools/doc_snippets.sh`,
  `tools/consumer_check.sh` and `tools/pool_interop.sh`.
- **The mutations of 38b.** Each was **CAUGHT** by `zig build test-client`:
  - Each refusal: Content-Length, Host and Trailer allowed; the connection-specific fields and
    TE allowed; an uppercase name allowed; no check of the name; no check of the value; no check
    of the trailers at all.
  - `te: trailers` omitted over h11, h2 and h3; sent with no trailer buffer; sent beside the
    program's own TE; h11's `Connection: TE` omitted.
  - The section dropped over h11, h2 and h3.
  - The `Trailer` line omitted over h11, h2 and h3.
  - A body with trailers not chunked over h11; END_STREAM on h2's last DATA frame before the
    section.
  - `zig build test-sim-run` **CAUGHT** the section dropped over h2 and over h3.
- **The owner's rulings of 2026-11-06** (decision 152 as amended on that day):
  - `added_fields_max` of 5 is approved. A mutation that sets it to 4 is **CAUGHT** by `zig
    build test-client`: the test of decision 137 expects 5 and finds 4.
  - `InvalidTrailer` refuses more than ruling 9 named, and the owner accepted each refusal of
    the build above.
  - Over h3 the header section and the trailer section share one `prefix` of 16,436 bytes for
    each stream. A request whose two sections do not fit in it together ends `invalid` at
    `open`. The owner accepted this, and docs/usage.md states it.
