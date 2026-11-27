# Decision 6: colibri owns no I/O

[All decisions](../decisions.md) · Section: [What the caller supplies](../decisions.md#what-the-caller-supplies)

No socket, no descriptor, no `poll`, no thread. The caller reads bytes and passes them to colibri;
colibri writes bytes into storage the caller owns and tells it how many. Cost: the caller writes the
event loop, and colibri cannot hide a syscall optimization from it. Gain: the same code runs under
stompy's io_uring plane, under a test harness, and under the deterministic simulator, with nothing
conditionally compiled. chapulin's caller-supplied I/O callbacks are the precedent, and colibri
removes more than chapulin does: chapulin's callbacks block, and colibri has no callbacks at all.

The rejected alternative is an I/O abstraction with a simulated implementation in-tree. It fails
on the consumer side: stompy's rule is that every role's I/O extends `src/io/` so the simulator
can substitute it, and an abstraction colibri defines would be a second one for the caller to
adapt to.
