# Decision 87: The simulator's h3 trace run logs every variable of `spec/tla/h3_connection`, and TLC checks each seed's log is a behavior of the model

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-25, for https://github.com/c4milo/colibri/issues/58.

Entry 67's models check a design, not the code that carries it out. A model and its code can
drift apart unseen. A trace check ties them: colibri runs, and the model must be able to
take the same path.
- The simulator's h3 check exchanges field sections of any size, so its state does not map to
  the model's frames. A run of its own, `src/sim/h3_trace_check.zig`, draws its plan to the
  model's rules. Each request is one HEADERS frame and a number of DATA frames of one size,
  and the plan draws the cancels and GOAWAYs.
- After each step, the run computes all 28 of the model's variables from both endpoints, in
  the model's units, and keeps each state that differs from the one before.
- One simulator step can take several of the model's steps. So `H3ConnectionTrace.tla` lets
  the model take up to 24 steps between two logged states, and a seed passes when TLC reaches
  the last one.
- The check runs through `tools/h3_trace.sh` and in `tools/ci.sh` where Java is installed. It
  is not part of `zig build test`, as `zig build tla` is not.

The alternatives refused, both offered in the issue:
- Log only the actions, such as an open, a send, a GOAWAY or a reset, and let TLC find the
  state between them. It needs less instrumentation, but the check is weaker: a variable
  colibri gets wrong goes unseen when some path of the model reaches the next action. TLC's
  time per trace also grows with the choices the model leaves open.
- Check only the flow scope, from the existing h3 check's QPACK counts. The GOAWAY and cancel
  rules would stay checked by the model alone.
