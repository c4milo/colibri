# RFCs

These are the plain-text RFCs colibri is written from, copied unmodified from
`https://www.rfc-editor.org/rfc/rfcNNNN.txt` on 2026-09-16. CLAUDE.md non-negotiable 10 says to
read the RFCs themselves rather than a summary or another implementation's source; these copies
are what that sentence points at, so every reader works from the same bytes.

`SHA256SUMS` records each file's checksum. Check that nothing was edited with:

```bash
cd docs/rfcs && shasum -a 256 -c SHA256SUMS
```

RFC 7540 is deliberately absent. RFC 9113 obsoletes it, and colibri never reads or cites it.

RFC 8446 is absent for the same reason. RFC 9846, the July 2026 revision of TLS 1.3, obsoletes
it. The wire format and the version codepoint are unchanged, but the sections are renumbered and
some requirements are tightened, so a section number copied from RFC 8446 may name a different
rule or none at all.

## HTTP

| RFC | Title | What colibri uses it for |
|---|---|---|
| [9110](rfc9110.txt) | HTTP Semantics | The semantics core h2 and h3 share (decision 15) |
| [5234](rfc5234.txt) | Augmented BNF for Syntax Specifications: ABNF | The core rules RFC 9110 §2.1 includes, and case-insensitive quoted strings (decision 15) |
| [9111](rfc9111.txt) | HTTP Caching | Not implemented; its conformance bar is zero (decision 16) |
| [9112](rfc9112.txt) | HTTP/1.1 | Not implemented; read to state why (decision 2) |
| [9113](rfc9113.txt) | HTTP/2 | `h2` |
| [7541](rfc7541.txt) | HPACK: Header Compression for HTTP/2 | `hpack`, and the Huffman code and prefixed integer in `wire` (decision 11) |
| [9114](rfc9114.txt) | HTTP/3 | `h3` |
| [9204](rfc9204.txt) | QPACK: Field Compression for HTTP/3 | `qpack` |

## QUIC

| RFC | Title | What colibri uses it for |
|---|---|---|
| [8999](rfc8999.txt) | Version-Independent Properties of QUIC | The version-independent packet reader (invariant 22) |
| [9000](rfc9000.txt) | QUIC: A UDP-Based Multiplexed and Secure Transport | `quic`, and the variable-length integer in `wire` |
| [9001](rfc9001.txt) | Using TLS to Secure QUIC | The TLS provider's QUIC mode and `crypto.Suite` (decisions 8 and 9) |
| [9002](rfc9002.txt) | QUIC Loss Detection and Congestion Control | Loss recovery, design §8 step 10 |

## TLS

| RFC | Title | What colibri uses it for |
|---|---|---|
| [9846](rfc9846.txt) | The Transport Layer Security (TLS) Protocol Version 1.3 | The semantics of the TLS provider (decision 8); obsoletes RFC 8446 |
| [7301](rfc7301.txt) | Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension | Negotiating `h2` and `h3`; the ask to chapulin (decision 10) |

## Compression

These three are in `compression/`, copied unmodified on 2026-09-25 from the same address. RFC 9112
§7.2 defines the `deflate` and `gzip` transfer codings through RFC 9110 §8.4.1, and each coding
names one of these formats. h11 decodes both, as the owner ruled in
https://github.com/c4milo/colibri/issues/60.

| RFC | Title | What colibri uses it for |
|---|---|---|
| [1951](compression/rfc1951.txt) | DEFLATE Compressed Data Format Specification version 1.3 | The compressed stream inside both codings |
| [1950](compression/rfc1950.txt) | ZLIB Compressed Data Format Specification version 3.3 | The wrapper of the `deflate` coding, with its Adler-32 check |
| [1952](compression/rfc1952.txt) | GZIP file format specification version 4.3 | The wrapper of the `gzip` coding, with its CRC-32 check |

## Extensions colibri declines

Each is read so that saying no is done correctly on the wire.

| RFC | Title | What colibri uses it for |
|---|---|---|
| [9218](rfc9218.txt) | Extensible Prioritization Scheme for HTTP | Ignored, beyond the parsing RFC 9113 still requires (decision 18) |
| [8441](rfc8441.txt) | Bootstrapping WebSockets with HTTP/2 | Not implemented (decision 19) |
| [9221](rfc9221.txt) | An Unreliable Datagram Extension to QUIC | Not implemented (decision 22) |
