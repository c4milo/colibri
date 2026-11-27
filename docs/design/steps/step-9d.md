# Design §8 step 9d: connection IDs, path validation and anti-amplification

[Design §8, the build plan](../../design.md#8-build-plan)

NEW_CONNECTION_ID and RETIRE_CONNECTION_ID (RFC 9000 §5.1), PATH_CHALLENGE and PATH_RESPONSE (§8.2),
the anti-amplification limit of §8, and the Stateless Reset of §10.3 — its §10.3.1 half here, with
§10.3's writer landing later, `9d902e1`. `disable_active_migration` per [decision
21](../../decisions/0021-connection-migration-no-to-initiating-it.md), which saves less than it sounds like. **Check:** [invariants 18 to
20](../../invariants.md#quic) asserted in the step 8 simulator after every step. *Medium.*

**Done, 2026-09-19.** Three files, one per rule set.

`src/quic/connection_id.zig` holds the two sets, which are not symmetric: the peer's, which
this endpoint writes into a Destination Connection ID field, and its own, which it accepts
there. §5.1.2's ordering is the part that is easy to get wrong and is written out — the
connection IDs below a frame's Retire Prior To are retired **before** the one it carries is
added, because the other order can push the count past `active_connection_id_limit` for an
instant, which §5.1.1 makes a CONNECTION_ID_LIMIT_ERROR. §19.15's tolerance is there too: the
same frame twice is ordinary, and the same sequence number carrying a different connection ID
is a PROTOCOL_VIOLATION.

`src/quic/path.zig` holds §8's anti-amplification limit and §8.2's validation, which are one
mechanism from two sides: an unvalidated path may take three times what it gave
([invariant 18](../../invariants.md#inv-18)), and validating it
is what lifts that. Whether a path is validated and whether a probe is outstanding are
separate fields, and the reported state is derived from both.

`src/quic/stateless_reset.zig` splits §10.3 where the entropy falls. Detecting a reset is
colibri's, because §10.3.1 fixes when the comparison happens and against what — the tokens of
connection IDs this endpoint has used and not retired, never the others — and the comparison
reads every byte of every token, which §10.3.1 requires so the value cannot leak through
timing. Sending one is the caller's: §10.3 wants the bytes before the token
indistinguishable from random and colibri draws no random number (invariant 5). What colibri
gives is the arithmetic, `permitted_len`, which holds both size rules at once — smaller than
the packet that triggered it (§10.3.3), so a loop dies out, and under three times it (§10.3),
so the answer cannot amplify.

Two defects surfaced while writing, both colibri's own. The repeat check for a
NEW_CONNECTION_ID swallowed §19.15's rule that a connection ID arriving below the current
Retire Prior To still owes a RETIRE_CONNECTION_ID; those are two questions and are now two
checks, with a bounded record so "unless it has already done so" survives the queue draining.
And path validation was modelled as one state, so challenging a path forced it out of
validated — which §8.2.1 permits at any time and §8.2.3 *requires* when the first datagram
was too small to test the MTU. A crashing test found it.

Mutations: 46 applied over the three, all **CAUGHT**. Five needed work first: three tests that
could not tell the mutant from the code — a retire mark with nothing active at it, a datagram
exactly at the amplification limit, and a sequence number at the top of what was issued — and
two more dead assignments, a cleared "already reported" mark and a cleared abandonment that
nothing reads while a probe is outstanding.

`zig build test` passes 809 of 809 and the lint is clean. What 9d still owes is its check,
which is the step 8 simulator asserting invariants 18 to 20 after every step; that needs a
connection to drive, so it lands with 9e.

**The TLA+ model, 2026-09-26** ([#50](https://github.com/c4milo/colibri/issues/50)).
- `spec/tla/quic_connection_ids` models the IDs a peer issues and colibri uses and retires:
  NEW_CONNECTION_ID with Retire Prior To, RETIRE_CONNECTION_ID, the limit of §5.1.1 and the
  order §5.1.2 puts retiring before adding, over a network that loses and reorders frames and
  sends lost ones again (§13.3). The properties: colibri holds no more active IDs than its limit;
  it sends no packet to an ID it retired; no RETIRE_CONNECTION_ID names its own packet's ID
  (§19.16); and every ID below a Retire Prior To the peer sent is retired in the end.
- It found three defects.
  - The peer's handshake ID, sequence number 0, was never in the set: only NEW_CONNECTION_ID
    filled it. A Retire Prior To above 0 therefore never retired it, and it did not count
    against the limit.
  - Every short header went to that handshake ID, whatever the set held, so colibri kept
    sending to an ID the peer had asked back, which §5.1.2 says the peer "MUST stop using".
  - A retirement past the queue of ones awaiting acknowledgment was dropped, where §5.1.2 says
    "An endpoint MUST NOT forget a connection ID without retiring it". It now closes with
    CONNECTION_ID_LIMIT_ERROR, which the same paragraph allows.

  The fix holds sequence number 0 from the peer's first Source Connection ID, addresses short
  headers to the set's active ID, and closes on a full queue. It also found a field,
  `Remote.highest_offered`, that is written and never read.
- What `zig build tla` printed, on macOS arm64:
  - holds, as expected: `colibri`, 109398 distinct states; `rotate_early`, a peer that raises
    Retire Prior To before its older IDs are retired, 30712;
  - violated, as expected: `pinned`, colibri before the fix, where sequence number 0 is never
    retired; `no_follow`, a packet sent to a retired ID; `forget`, a retirement dropped from a
    full queue, which the peer then never receives.
- The fix's mutations, against `zig build test-quic` alone: 9 applied, 8 **CAUGHT**. The header
  length mutant needed a test with a peer ID longer than the handshake's first. The one not
  caught set `highest_offered` for sequence number 0, which nothing reads, and the line is gone.
  `aebc502` then removed the field, its doc comment and its remaining two writes.
  `tools/quic_udp.sh` and `tools/quic_aioquic.sh` pass against the fix.
