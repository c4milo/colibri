# Decision 80: An application may copy a stream's received bytes without reading them, and take them later

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Adopted on 2026-09-24 for design §8 step 12; the owner may overrule it. It adds to entry 61.

h3 needs a HEADERS frame whole before QPACK decodes it. A field section blocked on the dynamic
table (RFC 9204 §2.2.1) must wait until the entries it needs arrive. Entry 74 hands a blocked
section back unread and leaves its bytes with the caller, "which §2.2.1 already asks it to
leave in the stream's flow-control window". But entry 61's `read` copies bytes out and
consumes them in one step, so h3 would need a buffer of its own for every blocked section.

So `connection_stream_read` gains two calls:
- `peek` copies what `read` would and leaves the bytes unread. They give the peer no credit
  (RFC 9000 §4.1) until they are taken.
- `consume` takes a count of them as `read` would, without copying them again.

h3 peeks a frame, decodes it from its copy, and consumes it once decoded. A blocked section
stays in the pool, and h3 peeks it again when it unblocks. The cost is a second copy of a
section that blocked.

The alternatives refused:
- h3 copies each blocked section into storage of its own. That needs room for
  `blocked_streams_max` sections per connection, which the pool already holds.
- A read that hands out the pool's blocks in place. It saves the copy, but a frame across two
  blocks needs one anyway, and the caller would hold pointers into colibri's pool across calls.
