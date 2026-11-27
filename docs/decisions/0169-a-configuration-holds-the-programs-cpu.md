# Decision 169: A configuration holds the program's CPU features, and a codec pool holds none

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-24, for [#156](https://github.com/c4milo/colibri/issues/156) (design
§8 step 72). It amends decisions 98, 101 and 158 ruling 10, which gave the features to each pool's
`init`.
- A program stated its CPU to colibri in up to five places: each TLS configuration, each of a
  client's three decoder pools, a server's encoder pool and its decoder pool, h11's own pool,
  and each qlog. Each one is a place where a program built for a generic CPU can leave
  `CpuFeatures.target()` by mistake. No test sees that mistake, since stdx writes the same
  bytes on every path.
- `client.Config`, `server.Config` and h11's `Options` each hold one field,
  `cpu_features: CpuFeatures`. The type is stdx's `platform.CpuFeatures`, under the names
  `client.CpuFeatures`, `server.CpuFeatures` and `h11.coding.CpuFeatures`, as before.
- The field has no default. A program that forgot it does not build, so none keeps the build
  target's features without a statement. `colibri.ServerConfig.engine` and a hosted
  server's `engine` lose their default of `.{}` with it.
- A pool's `init` takes no argument: `h11.coding.Pool`, `client.DecoderPool`,
  `client.ZstdDecoderPool`, `client.BrotliDecoderPool`, `server.EncoderPool` and
  `server.DecoderPool`. A pool is still placed once and shared by connections.
- A connection gives its configuration's features to a codec when the codec starts:
  `h11.coding.Decoding.start` and `begin`, a client's decoder as a response names its
  coding, and `server.Encoders.take`. A coding whose content holds more than one stream,
  gzip's members (RFC 1952 §2.2) and zstd's frames (RFC 8878 §3.1), starts each one with the
  same features, so `decode` takes them too.
- colibri still never asks the CPU itself (decision 98). The program calls
  `CpuFeatures.detect()` once and states the value.
- TLS keeps `cpu: tls.Cpu`, whose probe is another stdx type. It joins the field after
  [#144](https://github.com/c4milo/colibri/issues/144) and stdx's part of it.
- `qlog.Log.init` keeps its argument (decision 102 as amended). A log is a value the program
  places apart from any configuration.
- The alternatives refused:
  - The features at each pool's `init`, as before. A pool is whole by itself, but a program
    states its CPU once for each pool.
  - A default of `CpuFeatures.target()`, or of `.none()`. A program built for a generic CPU
    then runs the slow paths on every CPU, and nothing tells it.
  - The features kept in each message's decoding state, or in each pool slot, as the codec
    is taken. Each connection or each slot grows by the size of the features, where a
    parameter costs no memory.
  - The features read back from stdx's decoder for the next gzip member, as stdx's own
    `decode_all` reads them. It saves `decode` a parameter, and ties colibri to a field of
    another package's state.
  - A field `cpu_features` of `colibri.ServerConfig` beside `cpu`, which the server copies
    into its engine's configuration. It is a second place for one value.
