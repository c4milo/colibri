# Decision 175: colibri takes the program's `stdx.crypto.Context` once, in the TLS values

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-26: "Take stdx.crypto.Context" and "One source everywhere". It amends
decisions 94 as amended on 2026-09-27, 97 as amended, 150 ruling 9 and 169, for v0.22.0. stdx at
`9dd95be8` owns chapulin's description of the CPU and its random source (stdx's decision 87 as
amended on 2026-11-26).
- stdx's `platform.CpuFeatures` and `CpuFeatures.detect()` are the one CPU API of a program.
  `platform.probe`, `platform.Cpu` and `platform.Answer` are gone. `CpuFeatures` holds AES,
  the SHA instructions, FEAT_DIT, SVE2, VAES and MIDR_EL1 beside the fields it held.
- A program makes one `stdx.crypto.Context` at start, with `stdx.crypto.init(features,
  random)`. `tls.Client` and `tls.Server` take it as `crypto`, with no default, in place of
  `cpu`. `tls.Cpu`, `tls.Timing` and `tls.Random` leave the root of `tls`.
- A configuration of `tls` keeps the context beside stdx's options, which hold no `cpu` and
  no `random`. Each session's `init` takes the context, and stdx fills chapulin's two fields
  from it. colibri maps no CPU, and passes the program's features unchanged, MIDR_EL1 too,
  so stdx's rule for a Neoverse N2 holds.
- stdx states the timing: on every x86-64 core, and on an arm64 thread whose PSTATE.DIT is
  set, where the core has FEAT_DIT. It states none on another architecture. A program sets
  PSTATE.DIT on each thread that runs TLS. A virtual machine that hides FEAT_DIT gets
  ChaCha20 alone.
- The session's `start` of `tls.record` and `tls.quic` takes no source, and
  `ServerConfig.check` takes no argument. `tls.pem.key` takes the context in place of the
  CPU.
- One source everywhere. `server.Engine.init` takes no source, and nor do
  `client.ConnectionPool.start_tcp` and `start_quic`. Each draw they made comes from the
  context in the TLS values of their configuration: connection IDs, a Retry's Source
  Connection ID, reset tokens, grease values, skipped packet numbers and BBRv3's probe
  waits. QUIC always has
  TLS values. An engine or a pool in cleartext draws nothing, and asserts a TLS value on each
  path that draws.
- `colibri.ServerConfig` loses `cpu` and `random`, and gains `crypto: ?stdx.crypto.Context =
  null`. With null, a `.private` server makes one of `engine.cpu_features` and the operating
  system's entropy, which keeps ruling 9. A `.hosted` server's `crypto` has no default, as
  its `random` had none (decision 159).
- `colibri.ClientConfig` and a hosted client's configuration lose `random`. A program puts
  its context in the pool's TLS value, and a client in cleartext needs none. So the entropy
  default is a `.private` server's alone.
- The module `colibri` imports stdx, for the type of `crypto` and for `stdx.crypto.init`. Its
  root names nothing of stdx (decision 170).
- A seed still replays. The engine passed its own source to each session before, so the
  engine and its sessions drew from one source then too.
- The simulator describes a CPU with no feature, and reads nothing of the host. Every
  session of its runs then holds ChaCha20 alone, so one seed replays byte for byte on every
  host (non-negotiable 5). Ruled by the owner on 2026-11-26: "They simulator shouldn't
  detect, its job is deterministic simulation testing". The simulator once stated the timing
  on every host, so every host ran AES-GCM. stdx states it on arm64 only where the core has
  FEAT_DIT, and GitHub's arm64 Linux machines report none, so they ran ChaCha20. The `tls`
  tests, `tools/h3spec.sh` and `tools/tls_openssl.sh` cover AES-GCM and the host's own
  code. The alternatives, each ruled and then replaced the same day:
  - The host's features, and one pinned value for each suite: a seed then replays only on a
    host that holds the same suite, so a failure on one host may not reproduce on another.
  - The host's features, with each client offering ChaCha20 alone: the bytes are the same
    on every host, but the run still reads the host, which a simulation must not.
- Each example over TLS, `tools/consumer/` and `tools/consumer_hosted/` draw from
  `io.randomSecure`, in the shape stdx documents, and halt when a draw fails. The owner
  ruled the same day to delete `examples/tls_program.zig`, which wrapped `getentropy`, so
  every example shows one source. No example and no consumer gives TLS a seeded generator.
- The tests describe their CPU as `CpuFeatures` values, with and without AES. A probe's
  `not_known` and a timing `not_stated` are no input now, so the tests of them are gone.
- The alternatives refused:
  - `CpuFeatures` in the TLS values, and the random source kept as a parameter of
    `Engine.init`, of the pool's two start calls and of each session's `start`.
  - The context in the TLS values, and the random source kept on `Engine.init` and on the
    pool's two start calls. A program could then give the engine one source and its
    sessions another.
  - colibri's own map of the features to chapulin's description of the CPU, as before.
    stdx owns that map, and two maps would drift.
