# Decision 99: colibri's runs of the QUIC Interop Runner count the client's connection attempts as handshakes

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-27, for [#72](https://github.com/c4milo/colibri/issues/72).

The runner counts a handshake for each distinct Source Connection ID of the server's Initial
packets. quic-go's server drops a connection it has heard nothing from for 5 seconds, and it
starts a second one when the client's next Initial arrives. So `handshakeloss` counted 51
handshakes where colibri's client made 50 connections. Design §8 step 9e's runner notes hold
the evidence.
- `tools/quic_interop/count_handshakes.patch` has the runner's `_count_handshakes` count the
  distinct Destination Connection IDs of the client's Initial packets that have packet number
  0: one for each connection attempt (RFC 9000 §12.3, §7.2). `tools/interop.sh` applies it to
  the pinned clone.
- The same change is
  [quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509), for
  [quic-interop-runner#508](https://github.com/quic-interop/quic-interop-runner/issues/508).
  Once it is merged, the pin moves to the merge and the patch goes.

The alternatives refused:
- Leave the count as it is. `handshakeloss` with colibri as the client against quic-go then
  fails about one run in three, on handshakes that all completed.
- Lower `rtt_initial_ns` to 100 ms. A model of the case put the failures near 0.1% of runs.
  But RFC 9002 §6.2.2 recommends 333 ms, and the change would reach every user of the library
  for one test's sake.
- Count the client's Source Connection IDs, or the server's IDs that the client later used.
  quic-go's client uses zero-length connection IDs and switches to a NEW_CONNECTION_ID one
  during the handshake, so both counts are wrong for it.

Cost: until the upstream change is merged, colibri's runs check a count the public runner does
not.

Amended by the owner on 2026-09-27, the same day, after the runner job's first run against
ngtcp2, neqo and quinn (run 36359234791). The count above found no handshake with ngtcp2's or
neqo's client, so every case with either failed although each transfer completed. Their first
Initial packets carried packet numbers 671978432 and 31, which RFC 9000 §21.4 allows: an
endpoint may skip packet numbers. The patch now counts the Destination Connection IDs the
client chose for its Initial packets: every one it used, less the Source Connection IDs of the
server's Initial and Retry packets, which the client uses as its Destination Connection ID
from then on (RFC 9000 §7.2).
- On that run's captures, the new count gives the runner's expected number in all 36 pairings
  of `handshake`, `retry`, `resumption` and `handshakeloss` with five clients and four servers.
- On the twelve `handshakeloss` captures of [#72](https://github.com/c4milo/colibri/issues/72),
  it gives 50 in each. The runner's own count gives 51 in the two where quic-go's server
  dropped a connection.
- Mutations, both CAUGHT: without the subtraction, `handshake` counts 2 and `retry` 3; without
  the Retry packets, `retry` counts 2.
- `tools/interop.sh` resets the clone's `testcase.py` to the pinned commit before it applies
  the patch, so a clone that carries the earlier patch takes this one.
- [quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509)
  carries the same count, and the patch is its commit.

Amended again by the owner on 2026-09-27. The count above scored 2 for one quic-go handshake
against quic-go's own server, a pairing colibri's runs do not include. quic-go's server sends
NEW_CONNECTION_ID in the datagram of its Handshake flight, and quic-go's client sends its last
Initial packet, an ACK, to one of those IDs. The patch now counts only the Destination
Connection IDs of client Initial packets that carry CRYPTO data at offset 0, the start of the
ClientHello, less the Source Connection IDs of the server's Initial and Retry packets.
- quic-go against itself: `handshake` and `retry` count 1, where the count above gave 2;
  `resumption` and `zerortt` count 2, where it gave 4; `handshakeloss` counts 50, where it
  gave 66.
- All 151 captures of run 36359234791, and 16 more from this machine, give each test's
  expected number. That includes a colibri `handshakeloss` run the runner's own count
  scores 52.
- Mutations, all CAUGHT: without the offset test, quic-go's `handshake` counts 2; without the
  subtraction, every `retry` counts 2 or 3; without the Retry packets, every `retry` counts 2.
- [quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509)
  carries this count, and the patch is its commit.
