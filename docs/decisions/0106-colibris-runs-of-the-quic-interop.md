# Decision 106: colibri's runs of the QUIC Interop Runner pass a rebinding test's new path once the client answers any PATH_CHALLENGE sent on it

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-28, for [#78](https://github.com/c4milo/colibri/issues/78).

The runner's `rebind-port`, `rebind-addr` and `connectionmigration` cases take the
PATH_CHALLENGE in the server's first packet on each new path, and fail unless the client
answers that one. When that packet is lost, the server sends a new PATH_CHALLENGE with new
data (RFC 9000 §13.3), and the client answers it, but the case still fails. The weekly run
of 2026-09-28 failed `rebind-port` with colibri on both sides this way: the simulator's
25-packet queue dropped that packet. Design §8 step 9e's runner notes hold the evidence.
- `tools/quic_interop/rebind_challenges.patch` has the check record every PATH_CHALLENGE the
  server sends on each new path, and pass the path once the client answers any of them. The
  rule that the first packet on a new path carries a PATH_CHALLENGE stays.
  `tools/interop.sh` applies it to the pinned clone.
- The same change is
  [quic-interop-runner#511](https://github.com/quic-interop/quic-interop-runner/pull/511), for
  [quic-interop-runner#510](https://github.com/quic-interop/quic-interop-runner/issues/510).
  Once it is merged, the pin moves to the merge and the patch goes.

The alternatives refused:
- Leave the check as it is, and keep [#78](https://github.com/c4milo/colibri/issues/78) open as a known flake. The rebinding cases then fail
  now and then on paths the client did validate: 1 of the 18 colibri ran in on 2026-09-28,
  and 3 of 12 on 2026-09-27.
- Send the change upstream without the patch. colibri's runs keep failing until it is merged.

Cost: until the upstream change is merged, colibri's runs check a rule the public runner does
not.
