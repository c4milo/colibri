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
| [5234](rfc5234.txt) | Augmented BNF for Syntax Specifications: ABNF | The core rules RFC 9110 §2.1 includes |
| [7405](rfc7405.txt) | Case-Sensitive String Support in ABNF | The `%s` prefix RFC 9110 §2.1 and RFC 9112 §1.2 add to RFC 5234: `%s"HTTP"` matches only as written, and a quoted string with no prefix matches in any case (decision 15), copied on 2026-09-29 |
| [9111](rfc9111.txt) | HTTP Caching | Not implemented; its conformance bar is zero (decision 16) |
| [9112](rfc9112.txt) | HTTP/1.1 | `h11` (decisions 88 and 91) |
| [9931](rfc9931.txt) | Security Considerations for Optimistic Protocol Transitions in HTTP/1.1 | What h11 does with the octets that follow a CONNECT or an Upgrade request before its answer (decision 109), copied on 2026-09-29 |
| [6585](rfc6585.txt) | Additional HTTP Status Codes | The 431 an h11 server answers a field section too large with (decision 92), copied on 2026-09-25 |
| [3986](rfc3986.txt) | Uniform Resource Identifier (URI): Generic Syntax | The grammar of Host and of the request-target that RFC 9110 §4 and RFC 9112 §3.2 cite, copied on 2026-09-25 |
| [9113](rfc9113.txt) | HTTP/2 | `h2` |
| [7541](rfc7541.txt) | HPACK: Header Compression for HTTP/2 | `hpack`, and the Huffman code and prefixed integer in `wire` (decision 11) |
| [9114](rfc9114.txt) | HTTP/3 | `h3` |
| [9204](rfc9204.txt) | QPACK: Field Compression for HTTP/3 | `qpack` |
| [7838](rfc7838.txt) | HTTP Alternative Services | The client learns h3 from a TCP response's Alt-Svc (decision 100), copied on 2026-09-28 |
| [9460](rfc9460.txt) | Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records) | The HTTPS record's `alpn` and `port`, which the client takes as values (decision 100), copied on 2026-09-28 |

## QUIC

| RFC | Title | What colibri uses it for |
|---|---|---|
| [8999](rfc8999.txt) | Version-Independent Properties of QUIC | The version-independent packet reader (invariant 22) |
| [9000](rfc9000.txt) | QUIC: A UDP-Based Multiplexed and Secure Transport | `quic`, and the variable-length integer in `wire` |
| [9001](rfc9001.txt) | Using TLS to Secure QUIC | The TLS provider's QUIC mode and `crypto.Suite` (decisions 8 and 9) |
| [9002](rfc9002.txt) | QUIC Loss Detection and Congestion Control | Loss recovery, design §8 step 10 |
| [9369](rfc9369.txt) | QUIC Version 2 | Version 2 beside version 1, for [#54](https://github.com/c4milo/colibri/issues/54), copied on 2026-09-29 |
| [9368](rfc9368.txt) | Compatible Version Negotiation for QUIC | The version_information transport parameter RFC 9369 §4 requires, copied on 2026-09-29 |

## TLS

| RFC | Title | What colibri uses it for |
|---|---|---|
| [9846](rfc9846.txt) | The Transport Layer Security (TLS) Protocol Version 1.3 | The semantics of the TLS provider (decision 8); obsoletes RFC 8446 |
| [7301](rfc7301.txt) | Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension | Negotiating `h2` and `h3`; the ask to chapulin (decision 10) |

## Compression

These three are in `compression/`, copied unmodified on 2026-09-25 from the same address. RFC 9112
§7.2 defines the `deflate` and `gzip` transfer codings through RFC 9110 §8.4.1, and each coding
names one of these formats. h11 decodes both through stdx's decoders (decision 90), as the owner
ruled in https://github.com/c4milo/colibri/issues/60.

| RFC | Title | What colibri uses it for |
|---|---|---|
| [1951](compression/rfc1951.txt) | DEFLATE Compressed Data Format Specification version 1.3 | The compressed stream inside both codings |
| [1950](compression/rfc1950.txt) | ZLIB Compressed Data Format Specification version 3.3 | The wrapper of the `deflate` coding, with its Adler-32 check |
| [1952](compression/rfc1952.txt) | GZIP file format specification version 4.3 | The wrapper of the `gzip` coding, with its CRC-32 check |

## qlog

These three are Internet-Drafts, not RFCs, in `qlog/`, copied unmodified on 2026-09-27 from
`https://www.ietf.org/archive/id/<name>.txt`, which keeps each revision unchanged. The owner ruled
them in until the RFCs publish ([decision 102](../decisions.md)). Each events draft's §2.1 has an
implementation of a draft name its event schema with the draft number, so colibri writes
`urn:ietf:params:qlog:events:quic-13` and `urn:ietf:params:qlog:events:http3-13`.

| Draft | Title | What colibri uses it for |
|---|---|---|
| [main-schema-14](qlog/draft-ietf-quic-qlog-main-schema-14.txt) | qlog: Structured Logging for Network Protocols | The file header, the event envelope and the JSON Text Sequences serialization of `qlog` |
| [quic-events-13](qlog/draft-ietf-quic-qlog-quic-events-13.txt) | QUIC event definitions for qlog | The events `quic` logs |
| [h3-events-13](qlog/draft-ietf-quic-qlog-h3-events-13.txt) | HTTP/3 qlog event definitions | The events `h3` logs |

qvis, the viewer most qlog users open, reads the older qlog 0.3 alone. `tools/qlog_to_qvis.py`
rewrites a colibri log into that form (decision 102 as amended), from the three drafts that define
it, copied the same way on 2026-09-28. colibri itself follows none of them.

| Draft | Title | What colibri uses it for |
|---|---|---|
| [main-schema-02](qlog/draft-ietf-quic-qlog-main-schema-02.txt) | Main logging schema for qlog | The qlog 0.3 header `tools/qlog_to_qvis.py` writes |
| [quic-events-02](qlog/draft-ietf-quic-qlog-quic-events-02.txt) | QUIC event definitions for qlog | The QUIC event names and members it writes |
| [h3-events-02](qlog/draft-ietf-quic-qlog-h3-events-02.txt) | HTTP/3 and QPACK qlog event definitions | The HTTP/3 event names and members it writes |

The main schema's §11.2 writes a log as JSON Text Sequences, so the two RFCs that define them are
here too, copied from rfc-editor.org on the same day.

| RFC | Title | What colibri uses it for |
|---|---|---|
| [7464](qlog/rfc7464.txt) | JavaScript Object Notation (JSON) Text Sequences | The record separator and line feed around each record |
| [8259](qlog/rfc8259.txt) | The JavaScript Object Notation (JSON) Data Interchange Format | The objects, strings and numbers inside a record |

## Extensions colibri declines

Each is read so that saying no is done correctly on the wire.

| RFC | Title | What colibri uses it for |
|---|---|---|
| [9218](rfc9218.txt) | Extensible Prioritization Scheme for HTTP | Ignored, beyond the parsing RFC 9113 still requires (decision 18) |
| [8441](rfc8441.txt) | Bootstrapping WebSockets with HTTP/2 | Not implemented (decision 19) |
| [9221](rfc9221.txt) | An Unreliable Datagram Extension to QUIC | Not implemented (decision 22) |
