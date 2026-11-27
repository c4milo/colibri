# Decision 7: Time is a value the caller passes, never a clock read

[All decisions](../decisions.md) · Section: [What the caller supplies](../decisions.md#what-the-caller-supplies)

Every function that needs the current instant takes it as a parameter, typed as nanoseconds since an
origin the caller chooses. Cost: the parameter appears on functions at every depth — RFC 9002's
pseudocode reads `now()` at nine sites across five entry points, and the ninth is inside the
congestion controller, so the instant must be passed to it too. Gain: loss recovery, idle timeouts
and the PTO are testable and deterministic, and a failure found at one seed replays exactly. No
source file imports a clock, and `tools/lint/determinism.zig` enforces that.
