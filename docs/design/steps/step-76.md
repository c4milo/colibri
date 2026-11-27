# Design §8 step 76: a server's UDP socket shares its port, 2026-11-25

[Design §8, the build plan](../../design.md#8-build-plan)

([decision 173](../../decisions/0173-a-servers-udp-socket-shares-its.md), [#155](https://github.com/c4milo/colibri/issues/155)).
No public name changes. Rotor is pinned at `af06860`, whose `DatagramOptions` takes `reuse_port`.
- `rotor_host_udp.zig` gives a server's UDP socket `server_socket_options`, which asks for
  `reuse_port`, and a client's socket keeps `socket_options`.
- The test "decision 173: a second server's UDP socket shares the port, and only one that asks"
  opens a second socket with the server's options on a running server's port, and one with a
  client's options, which the kernel refuses.
- Mutations, each CAUGHT by `zig build test-colibri`: the server's socket opened with a client's
  options, and `server_socket_options` without `reuse_port`.
- Run on x86-64 Linux: `zig build test`, 4,278 of 4,280, with 1 skipped and the IPv6 test
  failed; `zig build examples`, the IPv6 example failed; `tools/doc_snippets.sh`; and
  `tools/consumer_check.sh`, with the packages from Zig's cache. Rotor's half ran
  `zig build test` there too, where each failure was an IPv6 test.
