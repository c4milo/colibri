# Design §8 step 63: a TLS server session holds no trust anchors, 2026-11-18

[Design §8, the build plan](../../design.md#8-build-plan)

[#137](https://github.com/c4milo/colibri/issues/137). After step 62, `tls.record.Server` held 50,000
bytes, and every TCP slot of an engine holds one, in cleartext too. The owner ruled on 2026-11-18
for a server limit of no anchors. No public name changes.
- **Where the bytes were.** chapulin's session, `chapulin.tcp.Server(receive_len, limits)`, took
  49,688: its C session, 20,008; its receive buffer, 20,480; and the lists it copies from the
  configuration, 9,088. Of the lists, 8,192 were trust anchors: `anchors_max`, 256, of 32 bytes.
- **Why a server needs none.** Anchors check the peer's certificate. A colibri server requests
  no certificate from a client (RFC 9846 §4.4.2), and chapulin's `server_cfg` never fills the
  anchors. chapulin's `Limits.anchors_max` names the roots a client takes, and its own
  `Server.check` passes 0.
- **The change.** `server_anchors_max` is 0, a named limit, and `config.server_limits_of` gives
  it to the server sessions of `tls.record` and `tls.quic`. Clients keep `limits_of`, with
  `anchors_max`.
- **Memory.** `tls.record.Server` goes from 50,000 to 41,808 bytes, and `tls.quic.Server` from
  102,656 to 94,464. An engine's TCP slot goes from 242,448 to 234,256, and its QUIC slot from
  1,432,544 to 1,424,352. connect-zig's 528 TCP connections take about 4.3 MB less.
- **The rest of the TLS state** is not changed here. A cleartext slot still holds the TLS
  session and `plain_in`, which it never uses, and step 62 leaves them as they are. chapulin's
  receive buffer holds a copy of each record, which
  [c4milo/chapulin#227](https://github.com/c4milo/chapulin/issues/227) asks chapulin to remove.
- **The checks.**
  - A test of `tls.record` and one of `tls.quic` require each server session to take the
    server's limits, with no anchors, and each client session the client's.
  - 4 mutations, each **CAUGHT**: the TCP server session on the client's limits; the QUIC server
    session on the client's limits; the server's limits with the client's anchors; and a server
    limit of one anchor.
  - The tests of `tls` pass, 85 of 85, on arm64 and on x86-64 in Debug under Zig's own backend.
- **The judge**, [run 44447891565](https://github.com/c4milo/colibri/actions/runs/44447891565),
  measured the change against `89045d95` at 10 rounds. Every h2 input stays within the noise in
  both jobs, from 0.9984 to 1.0029 of the base, as a change of memory alone should.
