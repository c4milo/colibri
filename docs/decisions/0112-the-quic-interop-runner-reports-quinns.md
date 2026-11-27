# Decision 112: The QUIC Interop Runner reports quinn's client in the `v2` case without failing the run

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-29, with design §8 step 19e. quinn's client runs the runner's `v2`
case, but its ClientHello carries no version_information. RFC 9369 §4 requires every endpoint that
supports version 2 to send it. RFC 9368 §2.3 has a server choose from the versions the client lists,
so colibri's server keeps quinn's client in version 1, and the runner, which expects version 2,
fails the case. A client that supports version 1 alone owes no version_information, but its endpoint
then answers the case as unsupported.
- `tools/interop.sh` has the runner write each run's results to a file, and
  `tools/quic_interop/known_failures.py` judges the file. A failed case the script lists is
  reported beside the tables and does not fail the run. Every other failed case fails it.
- The entry comes out once quinn's client sends version_information in the case, or its
  endpoint answers the case as unsupported. The script reports a listed case that did not
  fail, so the next run shows when.

The alternatives refused: skipping the pair, and leaving the weekly job red until quinn
changes.
