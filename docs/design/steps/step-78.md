# Design §8 step 78: colibri takes the program's `stdx.crypto.Context` once, 2026-11-26

[Design §8, the build plan](../../design.md#8-build-plan)

([decision 175](../../decisions/0175-colibri-takes-the-programs-stdxcryptocontext-once.md)). stdx is pinned at `9dd95be8`, whose `stdx.crypto` wraps
chapulin's sessions and options, and whose `platform` holds `CpuFeatures` alone. chapulin stays at
`f29c066a`.
- **Public names.** The root of `tls` loses `Random`, `Cpu` and `Timing`, and its list test
  holds the 14 names left. These fields and parameters change, which each dependent builds
  against:
  - `tls.Client.cpu` and `tls.Server.cpu` leave, and `crypto: stdx.crypto.Context` joins each,
    with no default.
  - `tls.record.ClientConfig`, `tls.record.ServerConfig`, `tls.quic.ClientConfig` and
    `tls.quic.ServerConfig` gain `crypto`, and their `values` are stdx's options, with no
    `cpu` and no `random`. `tls.quic.Client` and `tls.quic.Server` gain `crypto` too.
  - `start` of `tls.record.Client`, `tls.record.Server`, `tls.quic.Client` and
    `tls.quic.Server` loses `random`, and `check` of each `ServerConfig` loses its argument.
    `tls.pem.key` takes the context in place of the CPU.
  - `server.Engine.init(config, now)`, `client.ConnectionPool.start_tcp(connection,
    now_seconds, resumption)` and `start_quic(now_seconds, now_ns, resumption)` lose `random`.
  - `colibri.ServerConfig` loses `cpu` and `random`, and gains `crypto: ?stdx.crypto.Context =
    null`. A hosted server's configuration loses both and gains `crypto` with no default.
    `colibri.ClientConfig` and a hosted client's configuration lose `random`.
- **The code.** `src/tls/config.zig` keeps the context beside stdx's options, and each
  session's `init` takes it. colibri's own map of a probe to chapulin's description of the CPU
  is gone. The engine (`engine_connections.zig`), its QUIC connections
  (`quic_connection_internal.zig`), the pool (`pool_calls.zig`) and the client's QUIC
  connection draw from the context in their configuration's TLS values, and assert a TLS value
  on each path that draws. `colibri.Server` makes a context of `engine.cpu_features` and the
  system's entropy when its program passes none (`server_kinds.zig`). The module `colibri`
  imports stdx (`build/modules_colibri.zig`). The determinism lint exempts no file of `src/`
  now, since no file names `std.Random`.
- **The tests.** The tests of `tls` describe the build target's `CpuFeatures`, with and without
  AES, and an N2's MIDR_EL1, and check that a configuration keeps its context whole. The tests of
  a probe's `not_known` and of a timing `not_stated` are gone, since neither is an input now.
  `src/testing/cpu.zig` makes each test-only program's context, and sets PSTATE.DIT on each
  thread that runs TLS. The simulator's TLS values hold contexts over the streams each side drew
  from before, and its cleartext runs give no source.
- **The examples.** Each example over TLS, `tools/consumer/` and `tools/consumer_hosted/` draw
  from `io.randomSecure`, and halt when a draw fails. Each example draws its server's cookie
  key and ticket key from the context's source too. `examples/tls_program.zig`, which wrapped
  `getentropy`, is gone (decision 175). README.md and docs/usage.md show the lines.
- **Pinned values.** The engine passed its own source to each session before, so one source
  fed both already, and each run of the simulator keeps its order of draws. Under AES-GCM the
  censuses of `zig build test-sim-run` and their crc32 values were as before. CI's arm64 Linux
  job at `e9ffbac1` (run 89) ran ChaCha20, since its machine reports no FEAT_DIT, and three
  checks missed their wire pins there. The simulator now detects the host's features, and each
  client of its runs offers ChaCha20 alone (decision 175). Four pins moved to the values run 89
  found on arm64: `tcp_trace_check`'s `wire_crc32`, `endpoint_check`'s two, and
  `h3_deadline_check`'s `census_wire_crc32_expected`. The simulator's contexts now describe a
  CPU with no feature, and read nothing of the host (decision 175), so x86-64, which holds AES,
  gives the same values. The client trace run's census gained `wire_crc32`, over every byte its
  pool sends (`client_trace_world_send.zig`). Both build modes pass on x86-64. Mutations, each
  CAUGHT: the contexts over `CpuFeatures.detect()`, then over `.target()`; the pool's
  datagrams, then its TCP segments, left out of the client trace run's wire checksum.
- **Memory.** `zig build bench-memory`: `tls.quic.Client` and `tls.quic.Server` grow by 16
  bytes each, and `h11.Connection` by 16, since stdx's `CpuFeatures` grew. `server.Engine(.{})`
  grows by 112, and `client.ConnectionPool(.{})` by 136. docs/performance.md holds the table.
  With stdx v0.4.0 (`fdfbb709`), whose `Context` also holds the two descriptions of the CPU
  and the hash and JWS calls, each context grows by 176 bytes more: `tls.quic.Client` and
  `tls.quic.Server` by 176, and `server.Engine(.{ .tcp_connections = 1, .quic_connections = 0 })`
  by 528.
- **Names.** `qlog.Log`'s field `features` is `cpu_features`, as are the parameters and locals
  that hold a `CpuFeatures` in qlog, the `tls` tests and the examples. That finishes the owner's
  ruling of 2026-11-22 for colibri (https://github.com/c4milo/colibri/issues/144). stdx's
  `Context.features` is stdx's name, and keeps it.
- **Mutations: 10.** Eight were CAUGHT at once, and two were NOT CAUGHT until a test was written.
  - `zig build test-server`: the engine draws a connection's first ID from another source, and
    a QUIC connection its spare IDs. Each is CAUGHT by "decision 175: the engine and its
    connections draw each ID from the context in its TLS values".
  - `zig build test-tls`: a client configuration and a server configuration each keep a
    context of another source, a record client starts its session under one, and a client
    configuration drops the context's features. Each is CAUGHT.
  - `zig build test-colibri`: a `.private` server ignores its program's context. CAUGHT. A
    hosted server ignores it: NOT CAUGHT, and "decision 175: a hosted server draws its keys from
    the context its program gives" now catches it.
  - `zig build test-client`: the pool draws a QUIC connection's IDs from another source.
    CAUGHT. The client's QUIC connection draws its probe waits from another source: NOT CAUGHT
    there, though the client trace run of `zig build test-sim-run` caught it. "decision 175: the
    client draws its BBR probe waits from the context in its TLS values" now catches it.
- **Run on x86-64 Linux, in a container with no IPv6:** `zig build test`, 4,275 of 4,277, with
  1 skipped and the IPv6 test failed; `zig build examples`, 10 of 11, the IPv6 example failed;
  `zig build lint`; `tools/doc_snippets.sh`; and `tools/consumer_check.sh`, with stdx and
  chapulin from Zig's cache.
- **Not run:** the checks of `tools/ci.sh` that need Docker or a network peer, and every arm64
  host, where PSTATE.DIT decides the suite. CI runs them.
