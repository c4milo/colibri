# Decision 24: Reading the RFC is not evidence

[All decisions](../decisions.md) · Section: [Correctness](../decisions.md#correctness)

Every step in the build plan names which of the five checks proves it, and a step with no check is
not a step. The five are the golden corpus, published test vectors, the conformance suites, interop
against real stacks, and the deterministic simulator — with fuzzing over every parser and mutation
over every test.
