# Decision 51: h2 and h3 share their message validation through `http`, and each names its own errors

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-20, answering design §12 question 6.

RFC 9114 §4.1 to §4.3 restates most of RFC 9113 §8. The checks are the same: the
pseudo-header rules, the field name and value rules, the ban on connection-specific fields,
the CONNECT rules. What differs is the RFC section each check cites and the error a violation
carries — PROTOCOL_ERROR for h2 (§8.1.1), H3_MESSAGE_ERROR for h3 (§4.1.2).

So the shared rules move into `http` and return a reason. Each protocol maps that reason to
its own error. This finishes the split [decision 15](../decisions.md#correctness) already describes, rather
than changing it: `http` already holds the field-level checks, and `content_length` already
works this way.

A shared check in `http` cites both RFCs on the line that does the checking. Both state the
rule, so both citations are true, and CLAUDE.md non-negotiable 9 is satisfied.

Four rules stay per protocol, because they differ in what they accept:

- `:authority` against `Host`. RFC 9114 §4.3.1 has four MUSTs. RFC 9113 §8.3.1 has one
  SHOULD that needs URI normalization, which colibri's h2 does not implement.
- A repeated pseudo-header name. RFC 9113 §8.3 states it for any pseudo-header. RFC 9114
  states only that a request carries exactly one `:method`, `:scheme` and `:path`, and says
  nothing about `:status`.
- An informational response with END_STREAM (RFC 9113 §8.1). h3 has no END_STREAM flag.
- `:protocol` from RFC 8441. It is defined for h2 alone. colibri's h2 does not implement
  extended CONNECT today, so both protocols refuse it, but the rule would part if it did.

**A fifth rule joined the four when RFC 9114 was read against them, 2026-09-20.** A field
value that starts or ends with SP or HTAB is malformed in h2, which RFC 9113 §8.2.1 states in
a MUST of its own. RFC 9114 states no such rule: the word HTAB does not appear in it, and the
nearest sentence, §10.3's "Any request or response that contains a character not permitted in
a field value MUST be treated as malformed", is about which bytes appear and not about where
they sit. SP and HTAB are permitted inside a value. The position rule reaches h3 only through
RFC 9110 §5.5, which states it and which §10.3 imports for its character set alone. So this
check stays per protocol under the same criterion as the other four, and `http` reports the
character rules and the position rule as separate reasons rather than one. h2 folds both back
into `FieldValueInvalid`, which is what it answers today.

Two more citations moved in the same read, without changing what runs. RFC 9114 states the
field-name token rule and the field-value character rule in §10.3, not in §4.2, and states
both as MUSTs where RFC 9113 §8.2.1 makes the full grammar a SHOULD. A shared line therefore
cites RFC 9113 §8.2.1 with RFC 9114 §10.3, and citing §4.2 there would name a section that
does not state the rule.

The alternatives lost. Duplicating the rules in `src/h3/message/` is what step 12's check
exists to refuse; the two copies would part the first time an erratum moved one. Having h3
call h2's code adds an `h3` to `h2` edge that design §3 does not have, and every check would
cite RFC 9113 while running for h3, which non-negotiable 9 forbids.
