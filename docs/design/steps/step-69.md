# Design §8 step 69: an h11 decoder starts in place, with no fill, 2026-11-19

[Design §8, the build plan](../../design.md#8-build-plan)

The owner asked for it on 2026-11-19, the last of the four findings that step 67's frame scan left.
- **The cost.** `begin_stream` made the slot's union hold the coding's decoder with
  `slot.decoder = .{ .gzip = undefined }`, as step 67's encoder did. In a ReleaseSafe
  aarch64-linux build of `8995a305`, it wrote 44,312 bytes of 0xAA for gzip and 44,296 for
  deflate, at each stream and each gzip member.
  - A server pays it for each h11 request body whose transfer coding is gzip or deflate.
  - A client pays it for each response coded in gzip or deflate, in any version.
- **The change.** A slot holds its decoder as bytes of the larger type's size and alignment.
  `gzip_decoder` and `zlib_decoder` give the decoder as its type, and each asserts the
  message's coding and its slot. `begin_stream` starts the decoder in place through them.
  `h11.coding.Slot` is a public name, so its field `decoder` changes type. No code outside
  `coding.zig` reads that field, and the client's pool has a `Slot` of its own.
- A test requires that a slot filled with 0 and then with 255 decodes the same text, in gzip and
  in deflate, in pieces of 7 bytes.
- **Check:** five mutations, each CAUGHT: no gzip decoder start; no deflate decoder start; a
  zlib decoder started for gzip; deflate decoded by the gzip decoder; and the gzip size check
  adding 4 bytes of the window's end, which `init` never writes. Only the new test catches the
  last.
- **No judge number.** The judge times colibri's servers under loads that send no coded body,
  and it times no client. The owner chose to admit the step on its disassembly: in the
  ReleaseSafe aarch64-linux builds of `http-client` and `http-server`, no coding function holds
  a 0xAA fill now.
- A filter on the laptop, never published: the ReleaseSafe test-only client, in blocks of 100
  runs of 16 GETs whose answers came coded in gzip, six blocks in turns in an ubuntu 24.04
  container. A block took 0.9545 s of user time before the step and 0.929 s with it, medians:
  about 16 µs for each answer. The test-only client exports no `memset` of its own, so
  compiler_rt's serves the fill, one byte at a time.
