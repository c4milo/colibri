# Decision 52: I/O stays outside colibri, and the test endpoints keep their own loops for now

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-20, and amended on 2026-09-22 by entry 58, which adopts Rotor for the
UDP endpoints.

colibri's library owns no socket, no descriptor and no loop. That is non-negotiable 1 and it
does not change. The application that integrates colibri brings its own loop, and colibri
never learns which one. Rotor is one such loop and so is anything else.

The only place the question was open is `src/testing/`, which owns sockets by design (§9).
The answer there is not yet, for one reason: Rotor carries no datagrams today. It has no
`recvfrom`, no `sendto` and no `SOCK_DGRAM`. colibri's TCP endpoints already pass h2spec and
interop, so replacing them buys nothing, and the endpoints that would gain are the UDP ones
of steps 9, 12 and 13, which Rotor cannot carry.

Waiting costs nothing. Every endpoint is already a pure session and a thin socket file, so a
later swap touches the thin file alone. colibri does not invest in the hand-written loops:
no threads, no batching, and no io_uring of its own.

Decide again at step 9e, whose interop endpoint is the first UDP code in the tree. Adopting
Rotor then would make it a third test-only dependency after chapulin and pepegrillo, which
CLAUDE.md's "Ask before" covers.
