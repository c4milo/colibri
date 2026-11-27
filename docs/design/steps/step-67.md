# Design §8 step 67: an encoder starts in place, with no fill, 2026-11-19

[Design §8, the build plan](../../design.md#8-build-plan)

The owner asked for it on 2026-11-19, after a scan of the x86-64 Debug test frames found a frame of
600 KB in `take`.
- **The cost.** `take` made the slot's union hold the coding's encoder with
  `slot.encoder = .{ .gzip = undefined }`. Zig writes the whole union to change its field, and
  ReleaseSafe writes 0xAA over an `undefined` payload. So each coded response wrote 299,768
  bytes for deflate and 299,776 for gzip, in a ReleaseSafe aarch64-linux build of `eb26cf67`.
  The encoder's `init` then wrote the state it reads.
- **The change.** A slot holds its encoder as bytes of the larger type's size and alignment,
  and `slot.coding` names the type they hold. `gzip_of` and `zlib_of` give the encoder as its
  type, and each asserts the slot taken and its coding. `take` starts the encoder in place
  through them. Each slot loses the union's hidden tag in a safe build, so
  `server.EncoderPool(.{})` takes 1,461,304 bytes, 32 fewer.
- No byte of the slot before `take` reaches the coded bytes, because stdx's `init` writes all
  the state its encoder reads. A test requires it: a slot filled with 0 and then with 255 codes
  the same bytes, at level 1 and at the default level 6, in gzip and in deflate.
- h11's decoder pool changes its union the same way, 44,312 bytes for each coded message
  (`begin_stream` in `src/h11/coding.zig`). This step leaves it, and step 69 removes it.
- **Check:** the test above and the two tests of `coding_pool.zig` that read the coded bytes
  back. Five mutations, each CAUGHT: `take` starts no gzip encoder; `take` starts no deflate
  encoder; `take` starts a zlib encoder for gzip; a deflate slot encodes with the gzip
  encoder; and the gzip trailer adds 4 bytes of the window's end, which `init` never writes.
  The last breaks the new test and eight tests of coded h11, h2 and h3 responses, and neither
  test that reads the coded bytes back: those decode a slot that held zeros.
- A filter on the laptop, never published: the ReleaseSafe server with `--coded` under h2-many's
  load in an ubuntu 24.04 container, seven rounds in turns. A coded response took 26,726 ns of
  the server's CPU at `7b06f5bd` and 7,073 ns with the change, medians. An uncoded response
  took 1,612 ns and 1,624 ns.
- **Checked, 2026-11-19,** on `627e8a97`:
  - The judge measured it against `7b06f5bd`
    ([run 44661604715](https://github.com/c4milo/colibri/actions/runs/44661604715)).
    h2-coded-many wins in both jobs, 0.4180 and 0.4182. A coded response took 112,910 and
    112,871 instructions, and 47,199 and 47,197 with the change. Its CPU time went from 17,462
    and 12,833 ns to 5,378 and 5,442 ns. Every other input is within the noise, and none loses.
  - `tools/ci.sh` passed 33 sections, with Zig 0.16.0 on an Apple M1 Pro with macOS. The server
    tests passed on x86-64 Debug in an amd64 container.
