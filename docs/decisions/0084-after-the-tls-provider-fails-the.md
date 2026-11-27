# Decision 84: After the TLS provider fails, the suite says where the CONNECTION_CLOSE can go

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24, for https://github.com/c4milo/colibri/issues/59. It amends
[invariant 21](../invariants.md#inv-21).

RFC 9001 §4.8 owes the peer a CONNECTION_CLOSE when TLS fails. A TLS stack that failed keeps
only the write keys the close needs, and wipes every read key. chapulin keeps one close per
level, and drops that level's write keys once it has sealed it. colibri's own record still
counted those levels as available, so the send failed with `NoSpaceLeft`, no close went out,
and the peer waited for its idle timeout.
- The connection records the failure (`tls_failed`).
- From then on, every `send` and `receive` asks the suite's `keys_available` about each level
  colibri still counts as available. It marks `lost` each one the suite no longer holds
  (`take_lost`).
- A lost level seals and opens nothing, as a discarded one does. The difference is that
  colibri told the suite to forget nothing.
- Before a failure, a level the suite drops is still the suite's defect, which invariant 21's
  assertions at `seal` and `open` catch.
- `crypto.Suite` is unchanged. The adapter in `src/testing/` seals through chapulin's
  `ch_quic_seal_close` once chapulin's session has failed.

With the close sent, a failed connection ends alone, and the UDP server serves the next one.
`tools/quic_aioquic.sh` checks that with two refused handshakes in a row.

The alternative refused: a thirteenth `crypto.Suite` member, `seal_close`, which colibri would
call for close packets after a failure. It grows entry 48's vtable, and colibri would still
need to learn which levels the suite no longer holds.
