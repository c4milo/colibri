# Decision 55: The Retry token is the caller's to mint and to check, and the instant is a parameter

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-20, and amended on 2026-09-23: the token carries the two connection
IDs a server that sent a Retry needs again.

RFC 9000 §8.1.1 and §8.1.4 want a token that is authenticated, bound to the client's address
and expiring. Authenticating it needs a key, which non-negotiable 2 refuses colibri, and
expiring it needs the current instant, which non-negotiable 3 makes a parameter rather than
something read. So the token is the caller's: two members are added to `crypto.Suite`, one
that mints a token over an address the caller supplies and one that checks it, and both take
`now_ns` from colibri rather than reading a clock.

Taking the instant as a parameter is not a formality here. The deterministic simulator
supplies it (non-negotiable 5), so a token minted in a seeded run expires at a seeded instant
and one seed replays byte for byte. A token whose validity depended on a clock the suite read
would make every Retry check unreproducible, which is the one thing design §8's whole method
rests on.

The alternatives refused. colibri holding a key of its own is non-negotiable 2. A token that
is unauthenticated, which §8.1.4 warns lets an attacker replay one, would make Retry worse
than not offering it. And a plain parameter on the server's Retry entry point rather than a
vtable member was refused because the same key must mint and check across two connections,
which is state colibri does not hold (decision 35).

The amendment. A server that sent a Retry puts two connection IDs in its transport parameters
(RFC 9000 §7.3): `original_destination_connection_id`, the Destination Connection ID of the
client's first Initial, and `retry_source_connection_id`, the Source Connection ID of the
Retry. The client's next Initial carries the second as its Destination Connection ID and
never the first, and colibri keeps nothing between the Retry and that Initial (decision 35).
So the token carries both:
- `retry_token_write` takes both IDs, beside the address and the instant.
- `retry_token_check` replaces `retry_token_valid`. A Retry token that verifies gives both IDs
  back. A Retry token that fails is `invalid`, which §8.1.2 closes with INVALID_TOKEN. Any
  other token is `not_retry`, which §8.1.3 has the server treat as no token.
- colibri refuses a token that verifies but whose Retry Source Connection ID is not the
  Initial's Destination Connection ID: §17.2.5.2 has the client address exactly that ID, so
  the token came from another Retry.

The alternative the amendment refused: the caller keeping a table from each Retry's Source
Connection ID to the first Destination Connection ID. That puts per-Retry state and its expiry
in every caller, and the token would no longer bind the IDs it vouches for.
