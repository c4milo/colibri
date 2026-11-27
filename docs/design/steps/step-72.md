# Design §8 step 72: a configuration states the CPU features, and a pool none, 2026-11-24

[Design §8, the build plan](../../design.md#8-build-plan)

The owner ruled it for [#156](https://github.com/c4milo/colibri/issues/156).
- **The cost.** A program stated its CPU features to each codec pool it placed: three decoder
  pools in a client, an encoder pool and a decoder pool in a server. Each `init(features)` was a
  place to leave `CpuFeatures.target()` by mistake, and no test sees that, since stdx writes the
  same bytes on every path.
- **The change.** [Decision 169](../../decisions/0169-a-configuration-holds-the-programs-cpu.md): `client.Config`, `server.Config` and h11's
  `Options` hold `cpu_features`, with no default, and a pool's `init` takes no argument. A
  connection gives its configuration's features to a codec as the codec starts:
  `h11.coding.Decoding.start`, `begin` and `decode`, the client's `response_write.record_head`
  and `append_body`, and the server's `Encoders.take` through `coding_response.plan_head`.
- **Public names.** No name joins a root and none leaves. The lists of fields and parameters
  change, which each dependent builds against:
  - `h11.Connection.Options.cpu_features`, `client.Config.cpu_features` and
    `server.Config.cpu_features` join, each with no default. `colibri.ServerConfig.engine` and
    a hosted server's `engine` lose their default of `.{}` with it.
  - `init` of `h11.coding.Pool`, `client.DecoderPool`, `client.ZstdDecoderPool`,
    `client.BrotliDecoderPool`, `server.EncoderPool` and `server.DecoderPool` takes no
    features.
  - `h11.coding.Decoding.start`, `begin` and `decode`, and `server.Encoders.take`, take
    `cpu_features` as their last argument.
  - Each program needs the field: one that places no pool states it too, since the field has
    no default.
- **The examples.** Each program of `examples/`, `tools/consumer/` and
  `tools/consumer_hosted/` asks its CPU once, as it starts, and states the features in each
  configuration. A configuration that was a constant of the program's image is now built as
  the program starts, since `CpuFeatures.detect()` runs then. docs/usage.md and the README show
  the lines.
- **Memory.** `zig build bench-memory`: `h11.Connection` grows by 16 bytes, to 35,072, since
  it keeps its options' features. `server.Engine(.{})` grows by 64, to 49,714,864, and
  `client.ConnectionPool(.{})` by 32, to 843,472, each for the field in its configurations.
  `server.EncoderPool(.{})` loses 8, to 1,461,296, since it holds no features.
- **Tests.** stdx writes the same bytes on every path, so each test reads what a codec keeps
  of the features it started with: gzip's CRC-32 path, deflate's Adler-32 path, zstd's
  checksum path and its choice of assembly, and br's choice of assembly. Each one runs with no
  features and with the build target's, on a codec that held the other set before.
  - h11: `coding.zig` holds `start`, `begin` and `decode`, and `connection_coding_test.zig` a
    connection, on a body of one gzip member and of two.
  - client: `connection_coding_test.zig` over h11 and h2, `quic_coding_test.zig` over h3, and
    `connection_coding_zstd_br_test.zig` for zstd, of one frame and of two, and br.
    `pool_config_test.zig` holds what each connection's configuration takes of the pool's.
  - server: `coding_pool.zig` holds `take`, `connection_coding_h11_test.zig` a response over
    TCP, `quic_coding_test.zig` one over QUIC, `connection_records_test.zig` an h11 request's
    decoder, and `engine_config.zig` what each connection's configuration takes.
- **Check:** 28 mutations, each a place that gives a codec no features, or a configuration
  that takes none. Each is CAUGHT.
  - `zig build test-h11`, 6: a gzip decoder's start; a later member's; `start` to `begin`; a
    connection that keeps none of its options'; a connection's first start; its later
    member's.
  - `zig build test-client`, 14: the first start and a later member's, each over h11, h2 and
    h3; `coding.begin` for gzip, zstd and br; `coding.decode` for a later gzip member and a
    later zstd frame; the pool's held decoder on a later frame; a QUIC connection's
    configuration; a TCP connection's.
  - `zig build test-server`, 8: a gzip encoder's start and a deflate one's; `plan_head`; a
    TCP connection's response and a QUIC connection's; a server's h11 session; the engine's
    QUIC configuration and its TCP ones.
  - One was NOT CAUGHT at first: an h11 connection that started its decoder with no
    features. A body of two gzip members ends on the features its second member started
    with, so each test now decodes a body of one member too.
- **Not a mutation:** a client's h11 session takes the configuration's features and no
  decoder pool, since the client decodes content codings itself. Its features reach no codec,
  so no test tells them from another set.
- **Run on x86-64 Linux, in a container with no IPv6:** `zig build test`, `zig build
  examples` and `tools/doc_snippets.sh`. One test of `colibri` and the example
  `colibri_shared_rotor` open an IPv6 socket, and fail there for that reason alone.
- **CI, run 71 at 012b745, on GitHub's runners:** `zig build test` passed on arm64 Linux and
  on arm64 macOS. `tools/ci.sh` on x86-64 Linux passed each section but one, "A project that
  depends on colibri". `tools/consumer/main.zig` built a `server.Config` and a
  `client.Config` with no `cpu_features`, and its build stopped there. colibri's own build
  does not compile that project, and `tools/consumer_check.sh` fetches stdx from the
  network, which the container above does not reach. The commit after 012b745 states the
  field there. Each step of the script then passed in that container, with stdx and
  chapulin taken from Zig's cache.
- **Not run yet:** `bench/run.sh`, whose input `h2-coded-many` takes an encoder for each
  response. The `Bench` workflow runs it when a person starts it.
