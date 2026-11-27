# Decision 14: The stream *table* is not shared; a bounded slot pool is

[All decisions](../decisions.md) · Section: [What is shared between h2 and h3](../decisions.md#what-is-shared-between-h2-and-h3)

The candidate was the table and its id and half-close rules. The rules differ between the protocols:
h2 ids are 31-bit with client-odd and server-even parity and a closed set of seven states (RFC 9113
§5.1); QUIC ids are 62-bit with the two low bits encoding initiator and directionality, and separate
sending and receiving state machines (RFC 9000 §3.1, §3.2). h3 does not have a stream table at all —
RFC 9114 says stream concurrency is QUIC's, so h3 holds per-stream *frame decode* state and nothing
else.

What is shared is one data structure: a fixed slot pool with a per-parity watermark,
where "closed" is the implicit default for anything below the watermark rather than a stored
record. Both protocols need it for the same reason. In h2, ids cannot be reused and any stream
leaving idle implicitly closes every lower-numbered idle stream the peer could have opened
(RFC 9113 §5.1.1), so a map keyed by id can grow by 2^31 entries from one frame. In QUIC, a
single out-of-order STREAM frame implicitly opens every lower-numbered stream of its type
(RFC 9000 §3.2; §21.8 is the exhaustion hazard that rule creates). Same hazard, same structure,
different rules on top. `core` holds the structure; `h2` and `quic` hold the rules.
