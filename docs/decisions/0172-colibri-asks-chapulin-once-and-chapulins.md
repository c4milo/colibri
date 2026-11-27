# Decision 172: colibri asks chapulin once, and chapulin's module defines `ch_assert_fail`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-25: "Colibrí should only import chapulin once". Amends decision 94,
which left the hook to each program. A program that only wanted h11 had to define a C symbol of a
library it never called.
- colibri's build asks chapulin for `TRANSPORT=nonblocking` (chapulin's decision 245). The
  one module holds the TCP object as `chapulin.tcp` and the QUIC object as
  `chapulin.quic`, and it exports `ch_assert_fail` once. Zig refuses two exports of one
  name in one program, weak ones too, so one request is what lets the module define it.
- By default a failed chapulin assertion panics with the condition and chapulin's source
  line. A program that reports it its own way declares `pub fn chapulinAssertFail` in its
  root file, and the module calls it.
- The options of the request stay what colibri asked of each object before. chapulin's
  build gives the QUIC object the options a QUIC object takes.
- No test binary, example or consumer defines the hook. `tools/consumer_check.sh` requires
  a program that declares none to link with chapulin's `ch_assert_fail`.
- The alternatives refused: a weak export in each object, which Zig refuses; and a hook in
  chapulin's module of each transport, which two requests would export twice.
