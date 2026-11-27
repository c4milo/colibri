# Decision 21: Connection migration: no to initiating it and no to accepting it — and this is the smallest saving of the seven

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

The mechanism is the `disable_active_migration` transport parameter, identifier 0x0c with a
zero-length value (RFC 9000 §18.2). It refuses exactly one thing: the peer using a *new local
address* when sending to the address colibri used during the handshake. Three consequences that are
routinely got wrong, recorded because the saving is smaller than the name suggests:

- **Refusing is not an error you may signal.** If a peer migrates anyway, RFC 9000 §9 permits
  exactly two responses: drop the packets silently without a Stateless Reset, or validate the
  path and allow it. Closing the connection is forbidden, because it would let a third party
  close connections by spoofing traffic. There is no `MIGRATION_REFUSED` code in §20.1.
  colibri's refusal path is a silent drop plus a counter.
- **It does not exempt colibri from path validation.** RFC 9000 §9 says not all changes of peer
  address are intentional migrations, and then requires path validation on *any* detected change
  to a peer's address unless already validated. NAT rebinding is not active migration and is not
  refusable. So colibri still implements the whole of §8.2 and the migration rules that depend
  on it: `PATH_CHALLENGE` and `PATH_RESPONSE` with the 8-byte echo (§19.17, §19.18), the
  one-response-per-challenge rule and the 1200-byte datagram expansion (§8.2.2), the
  anti-amplification limit (§8), the revert-to-last-validated-address rule on failure with a
  silent close when no such address is held (§9.3.2), the challenge to the previously active
  path on an apparent migration (§9.3.3), and the congestion and RTT reset on confirming a new
  address with the port-only exemption it may take (§9.4).
- **A connection-ID pool is still required.** `active_connection_id_limit` must be at least 2
  and defaults to 2 (RFC 9000 §18.2), so `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID` are
  implemented by an endpoint that never moves.

One consistency rule: colibri does not send `preferred_address` if it sends
`disable_active_migration`, because RFC 9000 §9 exempts migration following a preferred
address, so sending both permits the migration `disable_active_migration` refuses.
