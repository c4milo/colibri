# Decision 98: h11 decodes a coded body into a buffer the caller passes to `receive`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-26, for design §8 step 15c. It settles how decision 91's decoded bytes
reach the application.
- `receive(input, decoded)` takes the buffer, and stdx's decoder writes straight into it. Each
  `data` event of a body carrying `gzip` or `deflate` is a slice of it, valid until the caller
  passes it again. A caller that places no decoder pool passes it empty.
- The pool holds decoders alone: `h11.coding.Pool(count)`, 43,216 bytes a decoder, which the
  caller places and gives each connection in `Options.decoders`. `DefaultPool` holds
  `decoders_default`, 16, in 691,472 bytes. The caller prepares it with
  `storage().reset(features)` and chooses the features, `Features.detect()` or
  `Features.target()`, so colibri never asks the CPU itself. Since 2026-11-24 the type is
  `h11.coding.CpuFeatures`, stdx's `platform.CpuFeatures` (decision 102 as amended that day).
  Amended by decision 169: the pool holds no features, and each connection gives its own,
  from `Options.cpu_features`, to the decoder a message takes.
- The reason is copies. stdx writes each decoded byte once, and at the end of each call copies
  the call's last 32,768 bytes into its window. Into the caller's own buffer that is about one
  write per byte, with no copy out, and a larger buffer means fewer calls.

The alternatives refused:
- A 16 KiB output block in each pool slot, with `receive` unchanged. Every caller's call stays
  as it was, but each decoded byte costs two or three writes: the decode, the window's copy of
  the whole block, and the caller's copy out. Each slot also grows by the block.
- A decoded buffer in each connection. Idle connections would hold buffers they rarely use,
  which is what decision 91's pool exists to avoid.

Cost: every h11 caller passes a second argument, an empty slice when it places no pool.
