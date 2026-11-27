# Decision 29: Fuzz every parser, and every check is seeded

[All decisions](../decisions.md) · Section: [Correctness](../decisions.md#correctness)

A parser is anything that reads peer bytes: the frame readers, the packet reader, HPACK, QPACK, the
varint and prefixed-integer decoders, the field validators, the transport-parameter reader. Every
property function lives in the file it tests, with the shared harness in `src/core/fuzz.zig`.
