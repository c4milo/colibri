# Decision 149: colibri's QUIC connections may resume congestion state, by RFC 9959's Careful Resume

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-04 (design §8 step 35). RFC 9959 lets a sender start a later
connection near an earlier one's rate, through its Reconnaissance, Unvalidated, Validating and Safe
Retreat phases. colibri holds no state between connections (non-negotiable 1), so the program keeps
it.

The rulings:
1. A provider. `server.Endpoint` and `client.ConnectionPool` take an optional resume
   provider, as they take a log provider (decision 102). Its `take` gives one saved set for
   a remote endpoint and claims it for one connection, as RFC 9959 §3.2 requires. Its `put`
   stores the set a connection observed (§3.1). `quic.Connection`'s options take a saved set
   directly, for a program that drives QUIC itself.

   Amended on 2026-11-14, after the Colibri Performance session's report of step 35e. The
   provider's calls name a host and no connection, and a server's `put` named the path's
   address at the end, another host after a migration. The engine now gives `put` and
   `drop` the address that `take` got, so each claim ends at its own host. A connection
   that moved to another host gives null, since its set is for the path to the host it
   moved to (§3.1). A provider counts each host's open connections and gives a set only to
   a host's one open connection (§3.2). The calls keep their names and types.
2. All three controllers: CUBIC and NewReno by §3, and BBRv3 by Appendix C.
3. Bounds in the configurations, with defaults: `max_jump`, 4 MiB, and the Lifetime, 1 hour
   (§3.3 and §4.3.1). A program may lower or raise either.
4. Both sides. RFC 9959 is about the sender, and the server and the client each send.
5. The saved set is a structure a program may write to disk, so it carries a version and a
   size (non-negotiable 6).

Alternatives that lost:
- `quic.Connection` alone, which leaves the server's and the client's programs without it.
- CUBIC and NewReno alone. BBRv3 is the default (decision 143), so few connections would
  resume.
- Bounds with no defaults, which every program would have to choose.
- The server alone. A client that uploads sends too.
- Calls that name the connection, in place of the address that `take` got, ruled on
  2026-11-14. Each call would change for every program, to fix what one address fixes.
