# hpack-test-case, as vendored

The HPACK vectors of design §8 step 3 (decision 25), copied unmodified from
[github.com/http2jp/hpack-test-case](https://github.com/http2jp/hpack-test-case) at commit
`8a1406e7d14bfcb6c046021f13cc15cfb162726d` (2019-06-01), under the MIT license in `LICENSE`.
`util/` is left out: it computes compression ratios and reads nothing colibri needs.

`tools/hpack_vectors.zig` decodes every story of every encoder directory and round-trips
`raw-data/` through the encoder, and `zig build test` runs it. The JSON is read by that tool,
which may allocate; the library never reads it.
