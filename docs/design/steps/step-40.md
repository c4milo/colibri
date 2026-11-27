# Design §8 step 40: DPLPMTUD, proposed 2026-11-05

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 155](../../decisions/0155-quic-finds-each-paths-datagram-size.md), from RFC 9000 §14.3 and §14.4 and RFC 8899 §4 and §5. It
ships after v0.15.0. The owner ruled on 2026-11-05 that v0.14.0 tags once step 37d is on main, with
the `colibri` module, step 38a and the h3 status fix, and that steps 39 and 42 ship as v0.15.0. On
2026-11-06 the owner added steps 38b, 43 and 44 to v0.15.0. v0.15.0 waits for Rotor's tag `v0.10.0`,
which step 44 needs. Rotor's session reports that it carries Rotor's decisions 26 to 30 and 32
(decision 156, fifth amendment). On 2026-11-08 the owner ruled that v0.15.0 ships from main without
step 44, which moves to v0.16.0.
- **The public names.** A connection option `datagram_len_max`, 1,452 bytes by default and up
  to 65,527 (decision 155 ruling 6), which `server.Config` and `client.Config` carry, and the
  search's limits in `quic.constants.limits`. Each goes on its
  list in the commit that adds it.
- **The rules.** A path's search runs once the handshake is confirmed, from 1,200 bytes, by
  padded PING probes, up to the smallest ceiling. A lost probe changes no window. Repeated
  losses of full-size packets return the path to 1,200 bytes. The search starts again after
  PMTU_RAISE_TIMER.
- **The checks.** A simulator network of 9,000-byte frames, which a ceiling of 8,952 finds. A
  simulator network with a path size below the probes, and one whose size
  drops in the middle of a connection, each with every seed finishing. A TLA+ model of the
  search's states, with mutants. Mutations of each rule. A judge bulk run, beside step 34's
  numbers.
