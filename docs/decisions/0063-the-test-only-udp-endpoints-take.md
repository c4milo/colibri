# Decision 63: The test-only UDP endpoints take the instant from Rotor's loop

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23. It extends entry 58 and leaves entry 7 as it stands.

A QUIC endpoint on a real network needs the current instant for RTT estimates, loss recovery,
the PTO and the idle timeout, which colibri runs on the instants the caller passes. Entry 7
says no source file imports a clock, and `tools/lint/determinism.zig` holds `src/testing/` to
it too. Rotor already reads the monotonic clock in every backend's `tick`, for its own timers.

So Rotor's loop reports the instant its last `tick` read, and the endpoints of design §9 pass
that to colibri. No file under `src/` reads a clock. Rotor is the dependency that owns the
endpoints' socket already, and a loop that reports its own instant is what libuv's `uv_now`
and libxev's `now` do.

Two alternatives were refused. Exempting `src/testing/` from entry 7 would put the first
clock read in the tree and narrow the lint for it. Taking the instant from outside the process
through a file or a pipe keeps the rule but adds a read to every timer.

Randomness was never this entry's question, but the lint held `src/testing/` to it all the
same, so the endpoints read `/dev/urandom` as a file. The owner ruled on 2026-09-24 that this
was a defect: the endpoints are real network peers, and their connection IDs, keys and
PATH_CHALLENGE data must be unpredictable. So `determinism` no longer reads `src/testing/`,
and `testing-clock` holds it to this entry's clock rule alone.
