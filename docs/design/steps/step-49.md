# Design §8 step 49: chapulin v0.6.0, and a server that changes its ticket key, ruled 2026-11-11

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 161](../../decisions/0161-colibris-servers-issue-session-tickets-and.md) as amended on 2026-11-11 and [decision
162](../../decisions/0162-colibri-exports-nothing-of-chapulin-and.md). [chapulin#220](https://github.com/c4milo/chapulin/issues/220). RFC
9846 §4.7.1.
- **Why.** A server that runs for weeks must change its ticket key: chapulin's `srv_ticket.h`
  asks for a change before one key seals 2^32 tickets. Before chapulin v0.6.0, a change ended
  every live ticket, so each client ran a full handshake again. chapulin v0.6.0 opens a ticket
  under the key before the current one. It also holds the JWS and SCRAM calls that Stompy's
  proxy and connect-zig call, and decision 162 puts them in colibri's object file.
- **The pin.** `build.zig.zon` pins chapulin v0.6.0, commit
  `17fd1f0ba108232403cbeff6c6e00a017294c857`. colibri's request for the object file for TLS
  over TCP adds `JWS` and `SCRAM`, `on` on a host target and `off` on another, as `DNSSEC`.
  The request for QUIC does not change. chapulin's `Cpu.bmi1` keeps its default, false: stdx's
  `platform.Cpu` reports no BMI1 yet.
- **The public names,** each listed in decision 115's form:
  - `colibri.ServerConfig.ticket_key_previous`, a `?[tls.constants.protocol.server_key_len]u8`,
    null by default. The server copies a key the program passes. With null, it draws a key
    after the ticket key, and that key opens no ticket.
  - `ticket_key_previous` in the `.hosted` configuration, a literal with no public name
    (decision 156 ruling 2), under the same rule.
  - `colibri.Server(...).set_ticket_key(self: *Self, key: *const
    [tls.constants.protocol.server_key_len]u8) void`, on both kinds. It joins the list in
    `src/colibri/colibri.zig`.
  - `tls.Server.ticket_key_previous`, a `?*const [tls.constants.protocol.server_key_len]u8`,
    null by default, which `tls.Config.init` passes to chapulin.
- **How a key changes.** `identity.change_ticket_key` copies the current key over the previous
  one, and the new key over the current one. Both stay at the addresses `load` gave to the TLS
  values. Each session reads the keys through those pointers at each open and each seal, so a
  session that started before a change uses the new bytes. A key equal to the current one
  changes nothing, and a key of zero bytes is a program's error, which an assertion refuses.
  `wipe_keys` writes zero over the previous key too.
- **Checks.**
  - `src/tls/record/record_ticket_test.zig`: a ticket sealed under one key resumes on a server
    that holds it as its previous key, and runs a full handshake after a second change.
  - `src/colibri/identity.zig`: the draw order is the cookie key, the ticket key, then the
    previous key, and a change keeps the current key as the previous one at the same address.
  - `src/colibri/server.zig`: `set_ticket_key` writes where the TLS values read, `deinit` wipes
    both keys, two equal keys stop a hosted `init` with `error.IdentityRefused`, and a cleartext
    server ignores the call.
  - `examples/colibri_hosted.zig` calls `set_ticket_key` between two calls, and docs/usage.md
    shows the excerpt. docs/usage.md, "Naming chapulin beside colibri", lists colibri's request
    to chapulin.
  - Mutations, 5 of 5 CAUGHT: `tls.Config.init` passes no previous key; `set_ticket_key`
    changes nothing; `deinit` keeps the previous key; a key change drops the current key
    instead of keeping it; `load` gives the TLS values no previous key.
