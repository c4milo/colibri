# Decision 167: A TCP connection over TLS takes its TLS session from a buffer the program passes in `server.Config.tls_buffer`, from v0.19.0

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-18, for [#137](https://github.com/c4milo/colibri/issues/137) (design
§8 step 64).
- Every TCP slot of an engine holds a TLS session, `tls.record.Server` of 41,808 bytes, and
  `plain_in` of 41,221, in cleartext too. That is 35% of the slot.
- The owner ruled that colibri saves this memory, and that `server.Capacity` is the wrong
  place for the switch, because it counts connections.
- `Config.tls` keeps its type, `?tls.Server`. `Config.tls_buffer`, a `[]u8` that is empty by
  default, holds the TLS sessions of the TCP connections over TLS that the engine holds at
  once. `Config.tls_buffer_len(n)` gives the bytes that hold `n` sessions, with room to align
  them. So the program declares a plain `[N]u8`, as `std.crypto.tls.Client.Options` takes its
  `read_buffer`.
- `accept(.{ .tls = true })` takes a free session, and returns null when none is free, as when
  no slot is free. A cleartext program passes no buffer and holds no TLS state.
- A buffer with a null `tls` is a programmer error, and an assertion refuses it. With `tls`
  set and no buffer, the TCP connections serve cleartext alone, and QUIC still serves h3.
- `colibri.Server` adds no name: a program passes the buffer in `ServerConfig.engine`, which
  holds the engine's other fields. With an identity and TCP connections, `init` requires
  room for one session at least.
- The alternatives refused:
  - `Capacity.tls = false`. `Capacity` counts connections, and this is not a count.
  - A slice of `server.TlsSession` that the program declares. The program then names
    colibri's internal state.
  - `Config.tls` as a struct of the TLS values and the buffer. Its names stutter, as in
    `server.Tls.server`.
  - A build option, as `.rotor` is. A program that serves cleartext and TLS together cannot
    use it.
  - A second comptime parameter of `Engine`.
  - Bytes the program aligns, as `client.ConnectionPool.memory_bytes` asks. Zig's standard
    library never asks a caller to align a buffer.
  - A field of its own in `colibri.ServerConfig`. It then holds two fields for one buffer.
