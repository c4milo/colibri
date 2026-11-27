# Decision 83: The h2 endpoints run on Rotor too

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24, for https://github.com/c4milo/colibri/issues/61. It amends entry
58, which kept the h2 endpoints on `poll` because moving them "buys nothing".
- `h2-server`, in cleartext and in its `--tls` mode, runs one Rotor loop per worker, each with
  its own listener bound with SO_REUSEPORT. `h2-client` runs one loop for the whole run.
- A worker keeps one accept in flight while it has a free slot. Each connection has at most
  one receive, one send and, at its end, one close in flight, and its slot is reused only
  after every one of them has its final event (Rotor's rule 1).
- A receive writes into a buffer of its own, and its bytes are appended to the session's
  input when its event arrives. The session moves what is left of its input as it consumes,
  and Rotor owns a receive's buffer until its final event (Rotor's rule 3), so a receive never
  targets the input.
- h11's endpoints are written on Rotor from their first commit
  (https://github.com/c4milo/colibri/issues/60).
- The one-connection checks `tls-handshake` and `tls-accept` still block. They serve one
  connection and exit, and entry 46 does not govern them.

The gain is one loop model for every endpoint of `src/testing/`, and io_uring for the h2
endpoints on Linux. Entry 46 holds unchanged: an endpoint waits only in the loop's tick.

The alternative refused: keep `poll` for h2, as entry 58 had it. The h2 endpoints passed
h2spec and interop on it. The owner chose one loop model over leaving the endpoints on two.
