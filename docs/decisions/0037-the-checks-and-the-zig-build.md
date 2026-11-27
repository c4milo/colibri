# Decision 37: The checks and the `zig build sim` command line are a module of their own, `sim_run`, rooted at `src/sim/run.zig`

[All decisions](../decisions.md) · Section: [The simulator](../decisions.md#the-simulator)

Ruled by the owner on 2026-09-16. A check drives a protocol module through the harness, so some
module must import both `sim` and the module under test, and that is a new edge in the §3 graph.
`sim_run` takes it: `core`, `wire` and `sim` at step 2, and each protocol module as its check lands.
`sim` never imports `sim_run`, so the direction stays acyclic, and `sim` still imports no protocol
module. colibri follows the layout of stompy's `sim_run`.

Two alternatives lost. A `testing` module under `src/testing/` needs no lint exemption, since
that directory is already the one permitted to touch a socket, but it departs from stompy's
layout for no gain, and design §9's entry points are servers, not checks. `sim` importing
`wire` directly puts a codec in the harness, which §3 forbids, and still leaves the command
line with no home. Cost: `src/sim/run_main.zig` reads arguments and writes to the terminal, so
`tools/lint/io.zig` exempts that one file by path.
