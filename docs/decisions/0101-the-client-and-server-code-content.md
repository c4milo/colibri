# Decision 101: The client and server code content with stdx's encoders and decoders

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-27, for [#70](https://github.com/c4milo/colibri/issues/70). It adds
content codings (RFC 9110 §8.4) to decision 100's modules.
- The server's configuration names the codings it may apply, in its order of preference, and
  each response says whether its body may be coded. Only the caller knows whether a body
  mixes a secret with bytes a peer chose, and a coded length leaks such a secret (RFC 7932
  §12).
- The server applies the coding the request's `Accept-Encoding` accepts with the highest
  nonzero qvalue, and the configuration's order breaks a tie (RFC 9110 §12.5.3). It codes
  nothing for a request with no `Accept-Encoding`, for an HTTP/1.0 request, for a 206, or
  when its encoder pool is empty. When no coding is acceptable, `identity` included, it sends
  the body uncoded and disregards the field, as RFC 9110 §12.4.1 permits.
- A coded response gains `Content-Encoding` (RFC 9110 §8.4) and `Vary: accept-encoding`
  (§12.5.5). It loses the caller's `Content-Length`, which would have to count the coded
  bytes (§8.6), and a strong `ETag` becomes weak (§8.8.1). A response to HEAD gets the same
  fields and no body (§9.3.2), and a 304 gets the `Vary` and the weak `ETag` alone (§15.4.5).
- The client offers its configuration's codings in `Accept-Encoding`, unless the caller's
  request carries that field. It takes a decoder from the caller's pool when it sends the
  request, and offers nothing when the pool is empty. It decodes a response whose
  `Content-Encoding` names one coding it offered, reads `x-gzip` as `gzip` (RFC 9110
  §8.4.1.3), and reports the coding it removed. Any other `Content-Encoding` reaches the
  caller as it arrived, with the field. The decoded body must fit the caller's body memory,
  and a corrupt one fails the response. `deflate` is the zlib format alone, as decision 91
  rules for h11's transfer codings.
- Encoders and decoders live in pools the caller owns, sized by named limits, and a message
  holds one only while it is coded. The caller chooses each encoder's level at build time,
  because stdx's encoder is one type per level.
- `gzip` and `deflate` come first, because the pinned stdx has both directions. `zstd`
  decoding follows a stdx bump and keeps RFC 9659 §3's window of 8 MB. `zstd` encoding and
  `br` follow when stdx writes them.
- Request content passes through both modules unchanged. colibri's package exports stdx's
  `codec`, `gzip`, `zlib`, `zstd` and `brotli`, so a caller codes request content, or
  anything else, with the stdx the library pins.

The alternatives refused:
- Export stdx's modules alone, and let each caller code bodies. Every caller would write the
  rules above, which decision 100's modules exist to hold.
- Content codings in h11, h2 and h3. The rules do not depend on the version, so there would
  be three copies, and a program that uses one protocol module would carry coding it may not
  want.
- An encoder in each connection. An h2 or h3 connection codes several responses at once, and
  an idle connection would hold an encoder it rarely uses. Decision 91's pool avoids the same
  cost for decoders.
- Coding a response to a request with no `Accept-Encoding`, which RFC 9110 §12.5.3 permits.
  A client that decodes nothing, such as curl without `--compressed`, would receive bytes
  it cannot read.
- Coding every response unless the caller opts out. The caller would have to find every body
  that mixes a secret with a peer's bytes, and each one it missed would leak.

Cost: a coded response has no `Content-Length`, so h11 sends it chunked, and a strong `ETag`
on it becomes weak. The server's encoder pool is memory the caller places. Design §3 gains
edges from `client` and `server` into stdx, and design §8 step 17 gains a part.

Amended by the owner on 2026-09-28, while building step 17e: every marked final response that
Accept-Encoding could choose carries `Vary: accept-encoding`, coded or not. RFC 9110 §8.8.3.3's
example sends it on the uncoded response too, and §12.5.5 has Vary tell a recipient that the
response was subject to content negotiation. A 206, a 204 and a 2xx to CONNECT still carry
none, because no coding could apply to them. The client decodes `gzip` and `deflate` in step
17e, and `zstd` and `br` in the part after it
([#80](https://github.com/c4milo/colibri/issues/80)), whose decoders the pinned stdx already
has.

**Amended by the owner on 2026-09-30, for [#80](https://github.com/c4milo/colibri/issues/80)
and design §8 step 17h.** The client decodes `zstd` (RFC 8878 §7.2) and `br` (RFC 7932 §13)
beside `gzip` and `deflate`.
- The caller places and manages a pool for each coding it decodes:
  `client.DecoderPool(count)` for `gzip` and `deflate`, whose decoders hold a window of 32 KiB;
  `client.ZstdDecoderPool(count)`, whose decoders hold RFC 9659 §3's window of 8 MB; and
  `client.BrotliDecoderPool(count)`, whose decoders hold 16 MiB, RFC 7932 §9.1's largest
  window, which the named limit `brotli_window_bits_max` sets. A caller that decodes `gzip`
  alone places no large window.
- The client offers a coding in Accept-Encoding only when its configuration names it and the
  coding's pool has a free decoder. As this decision already has it take a decoder when it
  sends the request, it takes one from the pool of each coding it offers, and gives back the
  others once the response's Content-Encoding names one, so the response finds its decoder.
- The server codes `gzip` and `deflate` alone until stdx writes the other encoders, so a server
  configuration that names `zstd` or `br` is the caller's error.
- The check: client tests over fixtures the `zstd` and `brotli` programs wrote, and the
  client against h2o for `br` and Caddy for `zstd`, both from Debian's packages in the image
  the interop scripts build.

The alternatives refused:
- colibri's own pools inside the client, sized at compile time. Every connection or channel
  would carry the windows, which decision 91's shared pools avoid, and the owner ruled that
  the caller manages them.
- One pool whose slots hold any coding: each slot would cost 16 MiB, 512 times what a `gzip`
  decoder needs.
- A `br` window of 4 MiB, the default of Google's encoder. A server that codes with a larger
  window would have its responses refused.
