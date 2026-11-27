# Decision 15: The semantics core is shared; the verdicts are not

[All decisions](../decisions.md) · Section: [What is shared between h2 and h3](../decisions.md#what-is-shared-between-h2-and-h3)

RFC 9110 §2.5 says core semantics do not change between versions, only their expression on the wire,
and colibri draws the module boundary there. `src/http/` holds: method as an opaque case-sensitive
token (§9.1); status as a `u16` in 100..599 with class from the first digit and an unrecognised code
treated as the x00 of its class (§15; decision 158 ruling 17 amends the range a client reads); the
`field-name = token` and `tchar` grammar (§5.1, §5.6.2) and case-insensitive comparison; the
`field-value` grammar with `obs-text` at %x80-FF and the rule that CR, LF and NUL are invalid
(§5.5); the order-preserving field-section model, because §5.3 makes the order of same-name lines
significant; the connection-option denylist of §7.6.1, which RFC 9114 §4.2 delegates to rather than
restates; the "no content" table of §6.4.1, which both RFC 9113 §8.1.1 and RFC 9114 §4.1.2 carry;
`Content-Length` as a semantic field (§8.6); trailer policy (§6.5.1); and `HTTP-date` (§5.6.7). On
the "no content" table, RFC 9113 §8.1.1 points back to §6.4.1 by name and RFC 9114 §4.1.2 restates
the rule without a cross-reference.

What stays out, and why each would be a bug if it went in: **`obs-fold`**, which is RFC 9112
§5.2 and appears nowhere in 9110 — any unfolding code in a shared core is h1 code that does not
belong there. **The lowercase-on-the-wire rule**, which 9110 does not state; it is RFC 9113 §8.2
with its receive-side check in §8.2.1, and RFC 9114 §4.2, worded differently and producing
different errors. **The malformed verdict**: same predicate, different enum — h2 gives a stream
error of `PROTOCOL_ERROR` (RFC 9113 §8.1.1), h3 gives `H3_MESSAGE_ERROR` (RFC 9114 §4.1.2) — so
the core returns a *reason*, never a code. **Pseudo-headers**, which are RFC 9113 §8.3 and RFC
9114 §4.3, not 9110, and which differ: h2 says a recipient MUST NOT use `Host` when `:authority`
is present, h3 says if both are present they must be equal. Do not write one shared authority
resolver. **Message-body length determination**, which is h1's. **Field-section size
accounting**, whose name+value+32 formula is in RFC 9113 §6.5.2 and RFC 9114 §4.2.2 under
different setting names at the same identifier 0x06 — share the arithmetic, not the setting.

**TE is read as its grammar defines it.** Ruled by the owner on 2026-09-16. RFC 9113 §8.2.2 and
RFC 9114 §4.2 permit TE only in a request, and only when its value is "trailers". RFC 9110
§10.1.4 makes TE a list, and RFC 9110 §5.6.1.2 requires a recipient to accept empty members and
whitespace around the commas. "trailers" is an ABNF quoted string, which matches in any case
(RFC 7405 §2.1). So the core accepts "Trailers", "trailers," and "trailers, TRAILERS", and
nothing with another member. The rejected alternative was comparing the exact bytes. It refuses
values the grammar admits, and a refusal there reports the peer's request as malformed when the
fault is colibri's.

**h3 refuses a field value with leading or trailing whitespace, as h2 does, with one
exception.** Ruled by the owner on 2026-09-16. RFC 9113 §8.2.1 makes such a value malformed in
h2. RFC 9114 has no such rule: its §4.1.2 and §10.3 refuse invalid characters, and SP and HTAB
are valid inside a value. The ruling takes h2's rule for h3 because no conformant sender
generates such a value: RFC 9110 §5.5's field-value grammar has no whitespace at either end,
and RFC 9110 §2.2 forbids a sender to generate an element outside its grammar. Nor does
RFC 9110 §5.5's instruction to exclude that whitespace apply. It binds a version that lets
whitespace appear around a value, which is HTTP/1.1 (RFC 9112 §5), and h3 carries a value as a
length-delimited string.

The exception is RFC 9110 §5.6.1.2, which requires a recipient to accept a list whose first or
last member is empty, as in `, gzip` after leading OWS or `gzip, ` with trailing OWS. Senders
that merge values produce those. h2 still refuses them, because RFC 9113 §8.2.1 is the more
specific rule. h3 trims exactly that whitespace with `field.trim_empty_member_whitespace` and
refuses any that remains. Two alternatives lost. Refusing every such value in h3 would break
§5.6.1.2's MUST. Trimming all edge whitespace in h3 would give the two protocols different
verdicts for bytes no conformant sender produces. What remains is refused with
`H3_MESSAGE_ERROR`, the code RFC 9114 §8.1 defines for a malformed message, applied here by
colibri's classification rather than an RFC 9114 rule. A conformant intermediary that forwards
such a value unchanged is refused too, though only the value's first sender broke the grammar.
