# Design §8 step 71: a server keeps 1-RTT packets that arrive early, 2026-11-23

[Design §8, the build plan](../../design.md#8-build-plan)

The QUIC Interop Runner's weekly job found it
([#153](https://github.com/c4milo/colibri/issues/153)).
- **The cost.** In `handshakeloss` with quinn's client, a client's Finished was lost and its
  request reached colibri's server first. The server dropped it with `key_unavailable`, because
  RFC 9001 §5.7 forbids it to process a 1-RTT packet before its handshake completes. quinn never
  sent the request again, and the case failed.
- **The change.** [Decision 168](../../decisions/0168-a-server-keeps-the-1-rtt.md): a server keeps such packets, at most 12 and
  14,720 bytes, and opens them once its handshake completes. `connection_early.zig` holds the
  store, and `connection_datagram.zig` keeps and opens the packets. `frames.process` takes the
  offset in `scratch.completed` where a packet's completed streams start, so several 1-RTT
  packets of one call keep each other's.
- **New public names:** `qlog.quic_event.PacketBuffered`, quic-events §5.8, which `quic`'s
  connection writes for a kept packet, and the member `handshake_pending` of
  `quic.connection_receive.Discarded`, which a server keeps and `no_keys` is not. No dependent
  used either enum. The golden case `quic_receive_short_before_complete` now names the verdict
  `HandshakePending`.
- **The simulator first.** The adversary `cut_client_finished` cuts the client's Initial and
  Handshake packets off the front of its first two datagrams after its handshake completes, and
  passes the 1-RTT packet behind them. Before the change, its 256 seeds finished in 67.84 s and
  3,328 datagrams, since colibri's own client sends its request again. After it, they finished
  in 38.40 s and 2,304 datagrams, and the servers opened 512 kept packets. The check requires
  at least one (`quic_connection_early_check.zig`).
- **The censuses moved.** The default schedule reorders, so a client's 1-RTT packets often
  arrived ahead of its Finished, and the server dropped them. The lossy check now takes 12,534
  datagrams instead of 14,391, the ACK-only check 4,032 instead of 4,598, the port and address
  rebinding checks 13,247 and 13,203 instead of 14,691 and 14,548, and the runner's network
  3,906 instead of 3,905. Under BBRv3 the lossy check takes 12,814 instead of 15,142, and under
  NewReno 11,836 instead of 13,316. The h3 checks run over the same network, so their digests
  move too, and their qlog grows from 8,025,390 to 8,033,685 bytes. Debug and ReleaseSafe agree
  on every census, and so do the runs with and without qlog.
- **Memory.** `quic.Connection` grows by 14,920 bytes, from 208,472 to 223,392, in clients too.
- **Tests.** `connection_early_test.zig` holds a packet kept and then opened, recorded at its
  arrival and with the idle timer at its opening, a full store, a client, a closing server, and
  an Initial packet with no keys that is not kept.
- **Check:** nine mutations, each CAUGHT by `zig build test-quic`: nothing kept; nothing
  opened; a client that keeps; a kept packet recorded at its opening; a store past its count;
  a store past its bytes; a store not emptied once opened; a packet with no keys kept; a
  packet that waits for the handshake named `no_keys`. `zig build test-sim-run-quic` also
  catches the first two.
- **Not run yet:** `tools/interop.sh quinn handshakeloss`, which needs Docker. The weekly job
  runs it.
