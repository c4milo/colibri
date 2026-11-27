# Decision 53: colibri reads RFC 9846, not RFC 8446, and re-cited all 158 citations against the revision rather than renumbering them by hand

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-20.

RFC 9846 is the July 2026 revision of TLS 1.3. It obsoletes RFC 8446, keeps the same version
codepoint and the same wire format, and is backward compatible. It renumbers section 4 and
tightens a handful of requirements. `docs/rfcs/rfc8446.txt` is gone and non-negotiable 10
now names both obsoletions.

A find-and-replace of "8446" with "9846" would have been wrong. RFC 9846 §1.2 lists the
changes, and its section 4 moved a whole level: 8446's §4.1.x became §4.2.x, §4.2.x became
§4.3.x, §4.3.x became §4.4.x, §4.4.x became §4.5.x, §4.5 became §4.6 and §4.6.x became
§4.7.x, while "The Transcript Hash" moved up from §4.4.1 to §4.1. Sections 5, 6, 7 and 9
and appendices B.1, B.4 and E.5 held their numbers and their titles. Eighteen of colibri's
citations sat in the moved range, and each one was checked against the section title it
names before it moved. Two examples of what a blind renumber would have produced: the
certificate chain order in `src/testing/tls/chapulin_server.zig` cited §4.4.2, which in
RFC 9846 is "Certificate Request" and not "Certificate"; the KeyUpdate rules cited §4.6.3,
which in RFC 9846 is "Post-Handshake Authentication".

The audit read RFC 9846 §1.2's fifteen technical changes against colibri. Nine land inside a
TLS stack colibri does not own: KeyShare reuse, the PSK and HelloRetryRequest hash, the
NewSessionTicket rule, three corrected extension length bounds, KEM wording, the transcript
hash note and the RSA PSS removal are all the provider's. Three cost colibri nothing: it
refuses any version but TLS 1.3, so the TLS 1.0 and 1.1 prohibition is moot; it models no
alert level, so restoring "close_notify" to warning changes nothing; and it never enforces
the §5.5 limits on receive, which §5.5 now says receivers SHOULD NOT do. §5.5's upgrade to a
MUST reworded two comments in `src/tls/provider.zig` and moved no code, because the sender
that must act is the provider.

Three reached colibri's own code. The new "general_error" alert is named in
`src/tls/alert.zig` as part of this commit: the enum is not exhaustive, so 117 already
arrived as an unknown error alert and was treated as one, and naming it documents the value
without moving any behaviour. The other two are behaviour and wait on the owner:
https://github.com/c4milo/colibri/issues/18 for "user_canceled", which colibri treats as a
connection error although §6.1 now says to keep reading until the "close_notify" that must
follow it, and https://github.com/c4milo/colibri/issues/19 for §4.7.3's cap on the number of
key updates, which no member of `KeyUpdateError` lets a provider report.

`zig build test` passes 967 of 967 with both chapulin roles linked, and
`tools/tls_handshake.sh ../chapulin` still prints `complete alpn=h2 version=0x0304
suite=0x1303`.
