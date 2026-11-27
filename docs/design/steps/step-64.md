# Design §8 step 64: a TCP connection holds a TLS session only over TLS, 2026-11-19

[Design §8, the build plan](../../design.md#8-build-plan)

[#137](https://github.com/c4milo/colibri/issues/137), decision 167. After step 63 a TCP slot held
234,256 bytes, and 83,029 of them were the TLS session and `plain_in`, which a cleartext connection
never uses. The change breaks names, so it goes into v0.19.0.
- **The public names.** `server.Config` gains the field `tls_buffer` and the call
  `tls_buffer_len`. The server root exports no new name, and `colibri` adds none. A test of
  `Config` lists its one call with `core.public_names.expect`.
- **What a program writes.** It declares `var tls_buffer: [server.Config.tls_buffer_len(528)]u8`
  and passes `&tls_buffer` in `Config.tls_buffer`, or in `colibri.ServerConfig.engine`.
  `examples/colibri_server.zig`, `examples/server_exchange.zig`, docs/usage.md and the README
  show it.
- **The change.**
  - `TlsSession`, in `connection/tls_session.zig`, which the root does not export, holds
    `tls.record.Server` and `plain_in`. A TCP connection holds a pointer to one over TLS, and
    null in cleartext. `Connection.init` takes it, and asserts that it is there over TLS alone.
  - `tls_buffer_len(n)` counts `n` sessions and the bytes that align the first, so a buffer
    that starts anywhere holds `n`. `engine_tls_sessions.zig` cuts the buffer into sessions
    at `init`, at most `tcp_connections` of them, and keeps the free ones in a list.
  - `accept` over TLS takes a free session first, and returns null when none is free. A slot
    gives its session back when the engine releases it. `close_transport` ran by then, and its
    close wiped every secret.
  - `colibri.Server` asserts at `init` that an identity over TCP has room for one session at
    least. A test cannot reach an assertion, so no test checks this one.
  - The test-only endpoints of §9, the simulator and the examples pass a buffer. The
    simulator's censuses did not change.
- **Memory.** A TCP slot goes from 234,256 to 151,232 bytes, and `server.Engine(.{})` from
  50,804,336 to 49,476,080. `server.Config.tls_buffer_len(1)` is 83,039 bytes. connect-zig's
  528 cleartext connections hold about 43.8 MB less.
- **The checks.**
  - Tests of `tls_session.zig`, of `engine_tls_sessions.zig` and of
    `engine_tls_buffer_test.zig` require: `n` sessions at any alignment, and none in a short
    buffer; a session taken once until it is freed, and the one freed taken next; no session in
    cleartext; null from `accept` over TLS while each session is in use; a session that a full
    engine leaves free; a session given back wiped; and cleartext alone with no buffer.
  - 9 mutations, each **CAUGHT**: no session over TLS; a session kept at release; a session
    kept when no slot is free; a session in cleartext; no bytes to align; no cap at
    `tcp_connections`; the free list in the other order; the wrong number freed; and secrets
    kept at `close_transport`. Two were NOT CAUGHT at first, and the tests of a full engine
    and of the number freed were added for them.
  - The tests of `server`, 767 of 767, pass on arm64 and on x86-64 in Debug. `tools/ci.sh`
    passed all 32 sections on the step's code, `3b5e3e75`.
- **The judge**, [run 44462819065](https://github.com/c4milo/colibri/actions/runs/44462819065),
  measured the change against `c89178e1` at 5 rounds. No input loses in either job.
  h11-tls-many wins in both, at 0.9942 and 0.9879 of the base, and h2-tls-many wins in one, at
  0.9923. Every other input stays within the noise, from 0.9792 to 1.0046.
