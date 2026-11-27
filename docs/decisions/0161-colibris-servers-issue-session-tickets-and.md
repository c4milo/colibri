# Decision 161: colibri's servers issue session tickets, and colibri.Client resumes with them

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-10, and for the client on 2026-11-11, for v0.16.0 (design §8 step 48).
Step 13j's profiles found that wrk resumes almost every session with hyper, and that colibri's TCP
servers issue no ticket. So each connection to colibri runs a full handshake with its signature. RFC
9846 §2.2 describes resumption, and §4.7.1 the NewSessionTicket message.
1. `colibri.ServerConfig.unix_seconds` is a `u64` with no default, as
   `ClientConfig.unix_seconds` (decision 150 ruling 9). It holds the seconds since 1970 when
   `run` starts. The program reads its clock, and colibri reads none (non-negotiable 3). A
   `.private` server passes it to `server.Engine.init` in place of 0. A `.hosted` server
   already takes the Unix seconds in `now`, a `server.Timestamp` (decision 159).
2. `ticket_key` is a `?[tls.constants.protocol.server_key_len]u8`, null by default, in
   `colibri.ServerConfig` and in the `.hosted` configuration. The owner ruled on 2026-11-10
   that both kinds follow one rule. The server copies a key the program passes (decision
   158). With null, it draws its own key at start from its random source, as it draws its
   cookie key. It writes zero over its copy at `deinit`.
3. The same key serves the server's TCP and QUIC connections. Decision 20 still refuses 0-RTT.
4. The test-only TCP server takes `--seconds <unix-seconds>`. With it, the server draws a ticket
   key from its entropy, as `quic-udp` does, and issues tickets. It starts its engine at its
   loop's first tick, because Rotor reads its clock at a tick (decision 63). Without the
   option it issues none. `bench/run.sh` passes `date +%s`.
5. chapulin chooses the lifetime and the count of the tickets. RFC 9846 §4.7.1 bounds the
   lifetime at 604,800 s, and colibri sets neither value.
6. `colibri.Client` keeps the newest ticket of each transport, TCP and QUIC, with the instant
   it arrived. The next connection of that transport offers it once, and the client then
   drops it, because RFC 9846 Appendix C.4 asks a client not to reuse a ticket. A ticket past
   its ticket_lifetime, or older than `tls.constants.protocol.ticket_lifetime_max_s`, is not
   offered, because the TLS stack would refuse it and fail the connection (RFC 9846 §4.7.1).
   `deinit` wipes the tickets. `pool.tls.takes_tickets`, true by default, stays the switch,
   so the client adds no public name.

The alternatives refused:
- `unix_seconds` as an optional field, with tickets only when the program passes it. A
  server would then resume no session unless its program asks.
- A key that each server always draws. Two servers then cannot resume each other's tickets.
- A pointer to the program's key. A type keeps no pointer to the caller's options after `init`
  returns (decision 158).
- Resumption turned off in hyper, nginx and h2o, so that the bench compares full handshakes.
  The bench would then measure a server that no client resumes.
- A request to chapulin for X25519 in assembly on arm64. X25519 takes 28% of hyper's samples
  and 31% of colibri's, at equal cycles a connection.
- A client that keeps several tickets of each transport, so that connections opened at once
  each resume. It needs a new named limit and the memory of several tickets. The owner chose
  one ticket of each transport.

This amends decision 159's list of the fields with no default: `ServerConfig.unix_seconds`
has none, because no instant is right to assume.

Cost: each program that builds a `colibri.ServerConfig` adds `unix_seconds`. v0.16.0 already
breaks programs, so they change once. A key change ends every live ticket until chapulin
opens tickets under the previous key too
([chapulin#220](https://github.com/c4milo/chapulin/issues/220)).

**Amended by the owner on 2026-11-11** for design §8 step 49
([chapulin#220](https://github.com/c4milo/chapulin/issues/220)). chapulin v0.6.0 opens a ticket
under the key before the current one, so a server changes its key and keeps its clients'
tickets.
1. `colibri.ServerConfig.ticket_key_previous` and the field of the same name in the `.hosted`
   configuration are a `?[tls.constants.protocol.server_key_len]u8`, null by default. The
   server copies a key the program passes. With null, it draws a key after the ticket key,
   and that key opens no ticket.
2. `colibri.Server(...).set_ticket_key(self, key)` takes the new key as `*const` and returns
   nothing. The current key becomes the previous one, and the key before it is gone. The same
   key again changes nothing. A server with no identity issues no ticket, so the call does
   nothing there. The program calls it on the server's thread: on `.hosted` between two
   calls, and on `.private` from a route or a middleware.
3. `tls.Server.ticket_key_previous` is the pointer colibri passes to chapulin's
   `ServerOptions.ticket_key_previous`.
4. colibri writes both keys in place, and never moves a pointer. Each session reads the keys
   through the pointers it took at its start, at each open and each seal (chapulin's
   `srv_cfg.h`). So the previous key is set from the start, and a session that started before
   a change opens and seals under the new bytes.
5. `deinit` wipes the previous key too.

The alternatives refused:
- Both keys in the configuration alone, with no call. A server that runs for weeks then keeps
  one key until the program starts it again.
- A null previous key until the first change. chapulin refuses a key of zero bytes, so the
  pointer must change at the first change, and a session that started before it keeps null.
- A call that swaps two pointers. A session that started before the swap keeps the old
  pointers, and can seal under the key that the program retired.

Cost: a ticket that the current key does not open costs a second open. Each server holds one
more key of 32 bytes. A server with the old key cannot open a ticket that a server with the
new key sealed, so a program that runs several servers gives each one the new key in one
pass.
