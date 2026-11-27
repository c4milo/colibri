# Decision 94: colibri links chapulin as its TLS stack and its packet protection

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-26. It amends non-negotiable 2 and entries 8, 9, 10 and 48.

**Status: amended by decisions 172, 174 and 175.** The rule that stands: colibri's library links
chapulin as its TLS stack and its packet protection, and holds no key. colibri pins no chapulin
of its own. It reads chapulin as `stdx.crypto`, from the stdx commit `build.zig.zon` pins, and
stdx asks chapulin for its one module (decisions 172 and 174). Each session draws from the
random source of the program's `stdx.crypto.Context` (decision 175). The text below records the
ruling of 2026-09-26: its pin, its build of chapulin's objects and `RAND=extern` are superseded.

Every user of colibri had to write the code between a TLS stack and colibri's two vtables, and
that code is where the choices that decide a connection's security are made: whether the
server name is checked, which trust anchors and pins apply and against which clock, which ALPN
is offered, where randomness comes from, and how QUIC's secrets pass from TLS to packet
protection. One adapter, kept here and run by colibri's interop checks, replaces a copy in
every consumer. cocuyo asked for it, after keeping its own QUIC adapter and starting a second.
- chapulin is pinned by commit and hash in `build.zig.zon`, and colibri's build compiles its C
  with the options each configuration needs, so no consumer runs `make` and no object can be
  built against other headers. chapulin has no Zig build yet, and is asked for one. colibri
  does not copy chapulin's Makefile.
- The adapters in `src/testing/` move into the library, and a user no longer fills
  `tls.Provider` or `crypto.Suite`. Both vtables stay inside colibri, filled by chapulin and by
  the simulator's null provider and null suite. Those null implementations are what let one
  seed replay byte for byte (non-negotiable 5), so they stay test-only and are never packaged.
- colibri still holds no private key, traffic secret or packet protection key: chapulin holds
  them (entry 48). colibri still reads no clock: the wall-clock time that certificate checks
  need is a value the caller passes (non-negotiable 3). colibri still does no I/O
  (non-negotiable 1).
- Randomness is the consumer's. chapulin is built with `RAND=extern`, and the program that
  links colibri defines `ch_rand_bytes` and `ch_assert_fail`, each of which an image may define
  once. `ch_rand_bytes` must be safe to call from several threads at once (chapulin's
  `docs/porting.md`). The library's configurations leave `KEYLOG` off, so those two are all a
  program defines; colibri's executables in `src/testing/` define them for themselves, and
  `ch_keylog` too for the test builds that turn `KEYLOG` on.

The alternatives refused:
- An optional module beside the library. It kept the library free of a TLS stack and left a
  user free to bring another, but a user who brought none still had nothing that worked.
- A separate package depending on both colibri and chapulin. It kept colibri's rules as they
  were, and made the supported way to use colibri live outside it.
- colibri defining `ch_rand_bytes` over a random-bytes callback. A consumer that defines its
  own, as cocuyo does, could then not link colibri at all.
- Each consumer's own chapulin checkout, as `src/testing/` used until now. Each consumer would
  have to pick chapulin's build options correctly, and `build.h` could only refuse a wrong one.

Cost: every build of colibri compiles chapulin, no other TLS stack can be used, and the
library gains its first dependency and its first C. Design §8 step 16 carries the work.

**Amended by the owner on 2026-09-26.** The part of the adapter that is plain TLS moves into
chapulin, as a Zig API over its C calls: step 16c's values (`Client`, `Server`, `Trust`,
`Ticket`), the session storage and its size, driving a handshake, and QUIC's key handover. Any
Zig program that uses chapulin needs it, HTTP or not, and cocuyo kept an adapter of its own for
want of one. colibri keeps the glue: its `tls` module fills `tls_provider.Provider` and
`crypto.Suite` from chapulin's sessions and makes colibri's own checks, such as the ALPN a
connection attaches with. The refused alternatives were the whole adapter in colibri, as ruled
above, which leaves every other Zig user of chapulin to write it again, and building it in
colibri first to move it later, which writes it twice.

**Amended by the owner on 2026-09-27.** A program passes each session the source its randomness
comes from, and every draw chapulin makes for that session comes from that source. cocuyo asked
for it, because its tests replay a connection only when every draw comes from a stream it
seeds.
- chapulin gives each session a randomness callback with a context, as `ch_keylog` has a
  context. The `start` of each `tls` session takes the source and passes it through.
- A session with no source does not start, and nothing falls back to another source.
- colibri's objects then call no `ch_rand_bytes`. A program defines that hook only for a
  chapulin object of its own, and still defines `ch_assert_fail`. It landed with chapulin
  `e4b9c6f`'s `RAND=session`, and non-negotiable 2 changed with it.
- `start` takes the source as a `tls.Random`, which `src/tls/values.zig` names. That file is
  the one under `src/` the determinism lint lets name `std.Random`, as the owner ruled the same
  day: colibri takes the source from its caller, and makes and draws from no generator.

The alternatives refused:
- colibri keeping the source in the session and making it the thread's current source around
  each call into chapulin, with a draw function the program's `ch_rand_bytes` calls. It needs no
  chapulin change, but every call into chapulin sets and restores a thread-local, and a call
  left unwrapped stops the program when it draws.
- The program's `ch_rand_bytes` as the only source. A caller that needs its draws per
  connection wraps the provider and must know which calls draw, which breaks with no error when
  chapulin moves a draw.

Cost: every caller passes a source to `start`, and chapulin changes how its objects draw.

**Amended by the owner on 2026-10-17: the pin moves to chapulin main 6f3bf952.** It is 174
commits after v0.2.0, and its push check passed. colibri needs its `takes_tickets`
([#104](https://github.com/c4milo/colibri/issues/104)).
- `tls.values.Client.takes_tickets`, true by default, passes to `chapulin.Client`. With false,
  a session keeps no ticket, and a web PKI session hashes its anchors only to check a ticket
  that it offers (chapulin's decision 132).
- chapulin no longer has `CH_WEBPKI_ANCHOR_MAX`, and takes any count of anchors. colibri names
  its own limit, `tls.constants.anchors_max`, and keeps it at 12, so no configuration grows.
  The PEM reader of [#97](https://github.com/c4milo/colibri/issues/97) sizes it again for a
  system bundle.
- chapulin's 1f4a9222 breaks a program with an RSA identity: in a host object, `ch_rsa_priv`
  also holds the CRT values p, q, dp, dq and qinv (chapulin's decision 95). colibri passes the
  key as an opaque pointer and changes no code. RSA-2048 signing goes from 37 ms to about 1 ms
  on an M1 Pro, by chapulin's measurement.
- Each QUIC session and each configuration grows by one or two words. The memory table of
  docs/performance.md moves by 8 to 144 bytes a row.

The alternatives refused:
- A chapulin tag first. `takes_tickets` then waits for chapulin's next release.
- An anchor limit of 256 now, for a system bundle. Each channel grows by 15,616 bytes
  before a program can read a bundle
  ([#97](https://github.com/c4milo/colibri/issues/97)).

**Amended by the owner on 2026-10-17, a second time: the pin moves to chapulin main
e6e3c1e7.** It is seven commits after 6f3bf952, and chapulin's `make check` passed on each.
They change the API that colibri calls.
- chapulin reads the clock through a function, `ch_cfg.now_seconds(clock_io)`, which each
  `init` calls once (chapulin's decision 135). colibri reads no clock (non-negotiable 3), so
  each `tls` session keeps the instant its `start` was given in `instant`, and
  `config.clock_at` answers it. `start` takes `now_seconds` as before.
- A kept ticket, a session's results, the send rule and the Key Phase bit change too
  (chapulin's decisions 134, 136 and 137). colibri calls these through forms of the Zig API
  that did not change, so no other code changes.
- Each `tls` session holds one more word, `instant`. With chapulin's own changes, the rows
  of the memory table in docs/performance.md move by 8 bytes down to 48 up.

**Amended by the owner on 2026-10-18 and 2026-10-19, a third time: the pin moves to chapulin
main 50d7d17b.** It is 20 commits after e6e3c1e7. chapulin's decision 138 moves the answer to
a peer's KeyUpdate from `read` to `write`.
- chapulin's `write` sends the answer in front of its first record of data, under the keys
  it replaces (RFC 9846 §4.7.3). One answer serves every request read since this side's last
  KeyUpdate, and `close` sends none.
- chapulin's `read` sends only the alert of a failure. It reads 16 KeyUpdates in a row,
  `CH_KEY_UPDATE_RUN_MAX`, and fails the read of the 17th with unexpected_message.
- The adapter keeps only that alert, so `tls.constants.key_update_replies_max` is removed.
  `State.owed` holds 24 bytes in place of 78.
- colibri drops the rule of 5368f5b that a second request ends the connection while an
  answer is owed. RFC 9846 §4.7.3 puts its rule on the sender of the request, and describes
  "a single update" for several requests.
- `tls_provider.Content` merges `new_session_ticket` and `key_update` into `without_data`.
  h2 and h11 now do the same thing with each, and with an empty record of application data.
- A run past chapulin's limit has a name, as `records_without_data` has: `OpenError.KeyUpdates`
  in `tls_provider`, `h2.Limit.key_updates` and h11's `error.KeyUpdates`. The server maps each
  by name to the close reason `server.Limit.key_updates`.

The alternatives refused:
- The rule of 5368f5b kept in colibri. chapulin's `Read` does not say that a record asked for
  an answer, so it needs a chapulin change first.
- The rule kept in the test providers alone. The tests would then hold a rule that no
  production provider holds.
- Both members of `Content` kept. chapulin's adapter then reports a KeyUpdate as
  `new_session_ticket`, and one name means three things.
- `KeyUpdates` in the `RecordError` of h2 and of h11, with the cause kept in the server. The
  switches of the server and the client then each need one more arm.

Cost: a program that names `new_session_ticket`, `key_update` or `key_update_replies_max`
changes. A program that switches over `server.Limit` or `h2.Limit` needs an arm for
`key_updates`. A peer that waits for the answer before it sends more data waits until colibri
sends data.

**Amended on 2026-11-08: the pin moves to chapulin v0.5.0 (15c37ef4).** chapulin's decision
190 renames its Zig API and passes each large argument through a pointer. The C library does
not change. colibri calls each function by its new name, and its own names do not change.
Design §8 step 16 records each move.
