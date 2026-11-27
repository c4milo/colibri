# Decision 3: QUIC is a module inside colibri, not its own library

[All decisions](../decisions.md) · Section: [Scope and shape](../decisions.md#scope-and-shape)

Ruled by the owner on 2026-09-16. A module, `src/quic/`, that imports `core`, `wire`, `crypto` and
`tls` and nothing else, and that may never import `http`, `h2`, `h3`, `hpack` or `qpack`. Cost:
colibri's repository carries the larger half of the work, and somebody who wants QUIC alone takes an
HTTP library to get it. Gain: one CLAUDE.md, one simulator, one corpus format, one commit
discipline, and no version skew between two repositories that change together for a year. The
boundary that a separate repository would enforce socially is enforced here mechanically, by the
module graph in `build.zig`, and the check that proves it is that the QUIC simulator runs with no
HTTP module in the graph at all.

Extraction stays cheap on purpose: moving `src/quic/` to its own repository is a build-file
change plus a vendoring step, because no edge points out of it. Reopen trigger: a second consumer
wants QUIC without HTTP, or one person can no longer maintain QUIC and HTTP together.

Entry 102 amends this entry: `quic` also imports `qlog`, which imports stdx's `json` and
`platform` alone (entry 102 as amended), so moving `src/quic/` out takes `src/qlog/` with it.
