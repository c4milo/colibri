# Design §8 step 16: chapulin in the library

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 94](../../decisions/0094-colibri-links-chapulin-as-its-tls.md) has colibri link chapulin as its TLS stack and its packet
protection. Five parts, in order:
- **16a**, the package. chapulin is pinned by commit and hash in `build.zig.zon` once it offers
  a Zig build that compiles each configuration colibri uses with `RAND=extern`, and colibri's
  build checks each object's build record against the headers it compiled. The pin moves past
  the API changes https://github.com/c4milo/colibri/issues/65 tracks.
- **16b**, the adapters. The record-mode provider and the QUIC provider and suite move from
  `src/testing/` into a library module, which design §3 gains. `tls.Provider` and
  `crypto.Suite` become internal, filled by that module and by the simulator's null
  implementations. Amended on 2026-09-26 (decision 94's amendment, decision 97): the plain-TLS
  part moves into chapulin as a Zig API, and colibri's `tls` module is the glue from it to
  `tls_provider.Provider` and `crypto.Suite`. 16b waits on that API.
- **16c**, what a user sets: the server name, trust anchors with the wall-clock time as a value,
  SPKI pins, ALPN, and session tickets offered and handed back, as the owner ruled below.
- **16d**, the checks. Every check that linked chapulin through `src/testing/` runs against the
  library's adapter, and the `-Dchapulin-*` options leave CLAUDE.md's commands.
- **16e**, the caller's CPU answer. On x86-64 and arm64 both objects are built `AES=runtime`,
  and `values.Client` and `values.Server` require the caller's `aes_instructions`
  ([decision 97](../../decisions/0097-the-librarys-tls-module-is-tls.md) as amended on 2026-09-29). The multiply's answer follows once
  chapulin offers it ([chapulin#186](https://github.com/c4milo/chapulin/issues/186)), which
  [#84](https://github.com/c4milo/colibri/issues/84) tracks, and colibri's programs take both
  from stdx's `platform` module once it exists
  ([stdx#15](https://github.com/c4milo/stdx/issues/15)).
  **Check:** the `tls` tests under both answers where the build target has the instructions,
  and under `absent` on a CPU model without them; a suite order that names AES-GCM refused
  under `absent`; every check of `tools/ci.sh`; and mutations.
- **16f**, chapulin 0.2.0 ([#84](https://github.com/c4milo/colibri/issues/84)), the one bump the
  owner ruled. On x86-64 and arm64 both objects are chapulin's host objects, which take no
  `AES`, `WIDEMUL` or `CHACHA` value, and each session picks its paths from the CPU its caller
  describes (chapulin's decision 89). Two of chapulin's claims state a timing: that the AES
  instructions, and the widening multiply, run in data-independent time in the mode the
  session's thread runs in. `values.Client` and `values.Server` carry them as the owner rules
  between the shapes the proposal shows in code. The owner ruled the shape that makes
  `tls.Cpu` the probe and a `tls.Timing`, a new public name every program that links `tls`
  needs, since it says what mode its thread runs in. avx2 and vaes wait on
  [stdx#16](https://github.com/c4milo/stdx/issues/16).
  **Check:** the `tls` tests under every description where the build target has the
  instructions, and on a CPU model without them; each claim chapulin receives, read from the
  converted values; a suite order that names AES-GCM refused without the AES claim; on arm64,
  PSTATE.DIT set on the test programs' thread; h3spec, which offers AES-GCM alone; every check
  of `tools/ci.sh`; and mutations.

**16c, ruled by the owner on 2026-09-26.** What a user sets is plain values, and chapulin's
`ch_cfg` (its `cfg.h`, `webpki_cfg.h` and `srv_cfg.h`) is what they become. Each rule below is
chapulin's, and colibri checks none of them twice.
- A client names one of two kinds of trust. Web PKI takes the trust anchors, each a root's
  subject and SubjectPublicKeyInfo as DER; the server name the leaf must carry, which is also
  sent as `server_name`; and the wall-clock time in seconds, as a value (non-negotiable 3). It
  may add SPKI pins, which then narrow the anchors. Pins alone take one to four SHA-256 pins
  of a SubjectPublicKeyInfo, as chapulin's `webpki_cfg.h` defines them, read no clock, and send
  a server name only when one is given. That is how cocuyo reaches a DNS server it knows by
  its key and address alone.
- Both roles set ALPN: a list, most preferred first. A client offers it, and a server picks
  from it in its own order (decision 88).
- A client may offer a session ticket it kept, with the ticket's age in milliseconds, and may
  refuse a handshake that is not post-quantum (`require_pq`). After the handshake the client
  says whether the ticket was taken. Each ticket the server sends is copied into a slot the
  session holds, and taking it empties the slot and hands back a `Ticket` value in fixed-size
  fields, which the caller keeps as long as it likes: the identity, the PSK, `age_add`, the
  binding, and `lifetime_s`, the ticket_lifetime of RFC 9846 §4.7.1. colibri calls no callback
  of the user's. The value and its lifetime were settled the same day, after cocuyo showed that
  slices into the session could not outlive the connection a ticket is kept for.
- A server sets its identities: one ECDSA P-256 and one RSA-PSS, each a certificate chain with
  the leaf first, a public key, and a pointer to a private key. It also sets the HelloRetry
  cookie key, an optional ticket key, the time in seconds as a value, whether a server name is
  required, and, in an AES build, its cipher suites in its order. After the handshake it
  reports the server name the client sent.
- Keys stay in the caller's memory. colibri passes chapulin a pointer to each private key and
  to each cookie and ticket key, and never reads or copies one (non-negotiable 2).
- The same values configure h11 and h2 over TCP and h3 over QUIC. The QUIC transport
  parameters and the key handover stay colibri's.
- The session's memory is the caller's, sized by a comptime constant from chapulin's receive
  floor (decision 35). 16b decides whether it sits inside each connection struct or beside it.
- Amended by the owner on 2026-09-26 (decision 97's amendment). chapulin's Zig API gives each
  object types of its own, so these values are colibri's, defined in `tls`. `tls` converts them
  once per object into that object's chapulin values, and a server identity types its keys.
- Amended in 16b. The clock and a ticket to offer change with each connection, and a value
  converted once per object would carry a stale one, so a session's `start` takes them:
  `Client.start(config, now_seconds, resumption)` and `Server.start(config, now_seconds)`.

```zig
pub const Anchor = struct { subject: []const u8, spki: []const u8 };
pub const Pin = [32]u8; // SHA-256 of a DER SubjectPublicKeyInfo

pub const Trust = union(enum) {
    web_pki: struct { anchors: []const Anchor, server_name: []const u8,
                      pins: []const Pin = &.{} },
    pins: struct { pins: []const Pin, server_name: ?[]const u8 = null },
};

// Sized from chapulin's CH_TICKET_ID_MAX, 320, and its largest hash, SHA-384's 48.
pub const Ticket = struct { identity: [ticket_identity_len_max]u8, identity_len: u16,
                            psk: [ticket_psk_len_max]u8, psk_len: u8, age_add: u32,
                            lifetime_s: u32, binding: [32]u8 };

pub const Client = struct { trust: Trust, alpn: []const []const u8, require_pq: bool = false };

// What one connection offers, which a client session's `start` takes with the clock.
pub const Resumption = struct { ticket: *const Ticket, age_ms: u64 };

pub const EcdsaP256Identity = struct { chain: []const []const u8, public_key: *const [64]u8,
                                       private_key: *const [32]u8 };
// chapulin's ch_rsa_priv is a type of each object, so this key stays opaque.
pub const RsaPssIdentity = struct { chain: []const []const u8, public_key: []const u8,
                                    private_key: *const anyopaque };

pub const Server = struct { ecdsa_p256: ?EcdsaP256Identity = null,
                            rsa_pss: ?RsaPssIdentity = null,
                            cookie_key: *const [32]u8, ticket_key: ?*const [32]u8 = null,
                            alpn: []const []const u8,
                            require_server_name: bool = false,
                            cipher_suites: []const u16 = &.{} };
```

**Check:** `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `h2spec -t -k`, the h2 and h11
interop over TLS, `tools/quic_loopback.sh`, `tools/quic_udp.sh`, `tools/quic_aioquic.sh`,
`tools/h3spec.sh` and the interop runner all pass with no chapulin option passed; and a program
that does not define `ch_rand_bytes` fails to link, naming it. *Large.*

**16a, 2026-09-26.** chapulin `64e2f25` is pinned in `build.zig.zon`, lazy, and colibri's build
compiles it from the package with `RAND=extern`
([#66](https://github.com/c4milo/colibri/issues/66)).
- Two objects serve `src/testing/`. The TCP one, `TRANSPORT=tcp-nonblocking ROLE=both
  TRUST=webpki EXPORTER=on`, serves the h11 and h2 endpoints and the TLS checks, both roles in
  one object. The QUIC one is `TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm
  AES=hw KEYLOG=on` with `CH_NATIVE_AES`. A third, the QUIC object built `TRUST=raw-ecdsa`, is
  compiled only for `zig build interop-endpoint`.
- `src/testing/` imports the module the package translates from chapulin's headers under the
  object's own defines, in place of `@cImport` under a define list colibri kept. That list had
  lost `HKDF_LABEL_MAX=32`, which `EXPORTER=on` adds. Each endpoint still calls
  `ch_build_matches`.
- Each image defines `ch_rand_bytes` from `getentropy` (`src/testing/entropy.zig`), and the tests
  that stage one ClientHello twice switch it to a fixed stream. `RAND=drbg` and its seeding are
  gone, and with them the API changes https://github.com/c4milo/colibri/issues/65 tracked.
- The `-Dchapulin-*` options are gone, which 16d had planned: no check takes a checkout, and
  `tools/ci.sh` runs the TLS and QUIC checks on every push.
- chapulin's module at `8a813e2` lacked `SRV_TICKET_KEY_LEN`, which its `srv_cfg.h` names but
  `srv_ticket.h` defined. chapulin `64e2f25` defines it and `SRV_COOKIE_KEY_LEN` in `srv_cfg.h`.
- The pin moved to chapulin `13f4692` on 2026-09-26, once its Zig API landed (`797fc73`). The
  module `chapulin` is now that API and carries the object, so `link_chapulin` no longer adds the
  object itself, and `src/testing/` imports the translated headers as `chapulin.c`. The key
  lengths are `CH_SRV_TICKET_KEY_LEN` and `CH_SRV_COOKIE_KEY_LEN` (chapulin `3ecd148`). The
  adapters still call the C API; 16b moves them onto the Zig one. On macOS arm64 at the new pin:
  `zig build test` passes; `tools/tls_handshake.sh`, `tools/tls_accept.sh`,
  `tools/quic_loopback.sh`, `tools/quic_udp.sh`, `tools/quic_aioquic.sh` and `tools/h3spec.sh`
  pass; `tools/h2spec.sh 18443 --tls` passes 144 of 146 both ways, the 2 skipped by name; and the
  h2 and h11 interop scripts pass in both directions over TLS.

What each check printed, on macOS arm64 with no chapulin option passed:
- `zig build test`: 1941 of 1941 tests, none skipped; before, 1823 of 1893 with 70 skipped for
  want of a checkout.
- `tools/tls_handshake.sh` and `tools/tls_accept.sh`: `tls_handshake: ok` and `tls_accept: ok`,
  each with `alpn=h2 version=0x0304 suite=0x1303`.
- `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, and the 2 skipped by
  name.
- The h2 and h11 interop over TLS, in both directions: every exchange and every request ended as
  planned, against Go, nghttpd, h2o, curl and nghttp.
- `tools/quic_loopback.sh`, `tools/quic_udp.sh` over h3 and hq-interop with resumption, and
  `tools/quic_aioquic.sh` against aioquic 1.3.0: ok.
- `tools/h3spec.sh`: 49 examples, 0 failures.
- `tools/interop.sh quic-go handshake,transfer,retry,resumption,keyupdate,http3`, its image now
  compiling chapulin from the package on Linux: every case passed in both roles against
  quic-go, and against colibri itself.
- With the export of `ch_rand_bytes` removed, the link fails with `undefined symbol:
  _ch_rand_bytes`.

**CI on Linux, 2026-09-26.** From 16a on, every CI check that starts a server failed on x86_64
Linux, and the examples had failed to compile there since their first commit. macOS showed
neither.
- Zig 0.16's own x86_64 backend, which builds Debug there, placed `udp_run.memory`, a global
  whose type is 64-aligned, 16 bytes past a multiple of 64. Rotor's io_uring loop then
  panicked on its first table. LLVM, which builds aarch64, places it right.
- A global that states `align(@alignOf(T))` is placed right by both backends. pepegrillo
  `6fcb273`'s `static-alignment` rule requires that of every container-level `var` under `src`,
  `examples` and `tools`, and `zig build lint` now runs it. It found 325, each now stating its
  alignment.
- `examples/link.zig` held both loops' memory in one array of byte arrays, which aligns only the
  first: a loop takes 1,456 bytes on Linux, not a multiple of 64. Each loop's memory is now a
  struct of its own.

What was checked, on macOS arm64:
- A `quic-udp` cross-built for x86_64 Linux places `udp_run.memory` at a multiple of 64.
- Both examples, built for arm64 Linux, run in Docker and print that every byte arrived as
  sent, and the h2 server keeps running.
- Mutations, each **CAUGHT**:
  - `udp_run.memory` without its stated alignment fails the lint, and the cross-built binary
    places it 48 bytes past a multiple of 64 again;
  - the rule left unregistered fails the lint's canary;
  - the examples' shared array fails `zig build examples -Dtarget=x86_64-linux-gnu`.

With that fixed, CI's h2spec over TLS still ended in EOF. CI installs h2spec 2.6.0's release
binary, built with Go 1.12, whose TLS client offers TLS 1.3 only with `GODEBUG=tls13=1`, and
chapulin speaks TLS 1.3 alone. Homebrew builds h2spec with a current Go, so macOS passed.
`tools/h2spec.sh` now sets the variable. Run in Docker against the server on macOS, that binary
passes 144 of 146 over TLS, the 2 skipped by name, and without the variable it ends in EOF:
**CAUGHT**.

**Global state, 2026-09-26.** The same pepegrillo commit has `global-state`, which refuses a
container-level `var` that is not `threadlocal`. Over the whole tree it found 510. `zig build
lint` now runs it over the library modules alone, where it found 70:
- `none_context`, the one byte `stream_provider.zig`'s `none()` points its context at, is now
  `threadlocal`;
- test fixtures that one file uses are `threadlocal` too;
- fixtures that several files' tests share move into `*_test_support.zig`, which the rule does
  not read. A test names such a fixture through a `const` holding its address, and a
  `threadlocal` has no address at compile time. `connection.zig`'s move to
  `connection_test_support.zig`, and `field_block.zig`'s to `field_block_test_support.zig`, made
  four `field_block` files, so they now sit in `src/h2/field_block/`.

The rule leaves out `src/testing/`, `src/sim/`, `src/golden/` and the test files. The servers in
`src/testing/` share arrays indexed by worker on purpose. Made `threadlocal`, each array would be
copied into every thread, and glibc places a thread's static TLS on its stack. Mutations, each
**CAUGHT** by `zig build lint`: `none_context` shared again, the rule unregistered (the
canary), and the rule reading `*_test_support.zig`.

**16b, the record side, 2026-09-26.** The library module `tls` (§3) holds step 16c's values and
chapulin's record-mode sessions, on chapulin's Zig API at `13f4692`.
- `tls.record.ClientConfig` and `ServerConfig` convert the values once per object. A conversion
  refuses only a list longer than the array it copies into. Every other rule is chapulin's, and
  a session's `start` or the server's `check` reports it.
- A caller places a `tls.record.Client` or `Server` beside each connection, and the h11 or h2
  connection holds the session's provider, which settles what 16c left to 16b. A client's
  `handshake` writes what it owes before it reads, because chapulin reads no record while the
  client owes the server bytes.
- The provider hands a KeyUpdate's reply over through `handshake_write`, under the keys it
  replaces, and holds at most `key_update_replies_max` replies.
- The TCP object is decision 97's: `SUITE=aesgcm`, `AES=hw` with `CH_NATIVE_AES` where the
  target has the AES instructions, and `TX_RECORD=16384`. `build.zig.zon` no longer marks
  chapulin lazy.
- `src/testing/`'s h11 and h2 endpoints and the TLS checks run on `tls.record`. The adapters
  `chapulin_client.zig`, `chapulin_server.zig` and `chapulin_record.zig` are gone, and so is
  `zero_key_records.zig`, which faked a connected session the API cannot make. The endpoints'
  record tests run over a provider that protects nothing (`records_test_support.zig`), and
  `src/tls/` tests chapulin's records with real sessions.
- `tls_keylog` runs the module's tests over a `KEYLOG=on` object. Its own tests seal a peer's
  KeyUpdate and an empty record under the logged secrets, because chapulin sends neither in
  record mode.

Two chapulin defects, reported to chapulin on 2026-09-26 and confirmed there:
- A record holding two KeyUpdates is answered twice. RFC 9846 §5.1 requires the connection to
  end with unexpected_message. colibri's test of it waits for chapulin's fix.
- After a failed read, chapulin keeps no description of the alert it sent or received, so
  `take_alert` reports the peer's close_notify alone. chapulin adds `alertSent()` and
  `alertReceived()`.

What each check printed, on macOS arm64:
- `zig build test`: 1919 of 1919 tests.
- `tools/tls_handshake.sh` and `tools/tls_accept.sh`: ok, each with `alpn=h2 version=0x0304
  suite=0x1303` and the two exporters equal.
- `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name.
- The h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned,
  against Go, nghttpd and h2o, and from curl, nghttp and Go.
- 41 mutations of `src/tls/`, each **CAUGHT** by `zig build test-tls test-tls-keylog`: the
  owed ClientHello four ways, the clock, the ticket's fields, age and wipe, the server's clock
  and short output, every provider check, every copy bound, the identity check, the build-record
  assertion and `key_update_replies_max`. Two first attempts said otherwise: a completion test
  on a state no failed call reaches was equivalent, and colibri's refusal of an empty exporter
  label duplicated chapulin's, so it was removed.

**16b, the QUIC side, 2026-09-27.** `tls.quic` holds chapulin's QUIC sessions: `Client` and
`Server` behind `tls_provider.QuicProvider` and `crypto.Suite`, and `Retry`, the suite a server
writes a Retry and checks its token with, under a key the caller draws once.
- `config.zig` converts the values once for either object, as a function of the object's module,
  and `ticket.zig` converts a ticket both ways.
- chapulin's session starts when colibri gives the provider its transport parameters (RFC 9001
  §8.2), so `start` prepares the connection's values alone. Every call that reads the session
  checks first that it started, so a struct reused for a new connection reports nothing of the
  last one.
- The library links the QUIC object, and `tls_keylog` its `KEYLOG=on` copy, which
  `src/testing/`'s QUIC endpoints now use. `chapulin_quic.zig`, `chapulin_quic_suite.zig` and
  `chapulin_quic_c.zig` are gone, and `protection_vectors.zig` is
  `src/tls/quic/quic_vectors_test.zig`.
- The owner ruled two things on 2026-09-26. `certificate_chain_len_max` is 16, for the runner's
  chain of nine. The interop endpoint is the UDP endpoint over the library's `TRUST=webpki`
  object, whose client pins the server's key with `pin`, in place of a `TRUST=raw-ecdsa` object;
  `qns_identity.py` writes the pin.
- chapulin refuses `SUITE=aesgcm` with `AES=soft` (its `ct.h`, INV-26), which decision 97 did not
  know. An object for a target without the AES instructions carries `SUITE=chacha`: a server's
  suite order is then refused with `SuitesUnavailable`, and a client, which records no suite,
  reports ChaCha20. `zig build test-tls test-tls-keylog -Dcpu=<model>`, on a model without the
  AES instructions, runs the tests over such objects, and `tools/ci.sh` runs it. Decision 97
  carries a note for the owner to confirm, which the owner confirmed on 2026-09-27.

A chapulin limit, reported on 2026-09-27: pins alone read the leaf alone, but chapulin refuses a
chain of more than `CH_WEBPKI_FLIGHT_ENTRIES`, four entries, with bad_certificate. The runner's
`amplificationlimit` case sends nine, so colibri as the client fails it, which it passed over
`TRUST=raw-ecdsa`. The case waits for chapulin's answer.

What each check printed, on macOS arm64:
- `zig build test`: 1938 of 1938 tests. `zig build test-tls test-tls-keylog -Dcpu=generic`: 68 of
  68.
- `tools/tls_handshake.sh` and `tools/tls_accept.sh`: ok.
- `tools/quic_loopback.sh`, `tools/quic_udp.sh` over h3 and hq-interop with resumption, and
  `tools/quic_aioquic.sh` against aioquic 1.3.0: ok.
- `tools/h3spec.sh`: 49 examples, 0 failures.
- `tools/interop.sh quic-go`, every case of its default list: colibri as the server passed every
  case against quic-go, whose client does not run `ecn`, and every case but `amplificationlimit`
  against colibri's client. As the client against quic-go, colibri passed every case but
  `amplificationlimit` and `handshakeloss`, and quic-go's server does not run `ecn`.
- `handshakeloss` with colibri as the client against quic-go failed 3 runs of 11 with "Expected
  50 handshakes. Got: 51", the failure recorded at `169c91d` above, and passed the other 8. The
  client's key log held 50 handshakes in the failed run. quic-go's server opened a second
  connection for one of the client's, and the runner counted both; step 9e's runner notes give
  the evidence ([#72](https://github.com/c4milo/colibri/issues/72)).
- 41 mutations of `src/tls/quic/`, each **CAUGHT** by `zig build test-tls test-tls-keylog`, and
  the two checks of an object without AES-GCM, each **CAUGHT** under `-Dcpu=generic`. The first
  run left eleven otherwise. The session struct the tests reuse still held the previous test's
  closed session, so nine checks before chapulin's session starts read harmless answers; a test
  now restarts a session that resumed and was not closed. Two more tests were missing: an open at
  a level with no keys, and a Retry token checked a second later. A mapping of a capacity error
  chapulin cannot return with `receive_len` is gone.

**16b at chapulin `e802399`, 2026-09-27.** The pin moved from `13f4692` to chapulin `e8023994`,
which carries two of the fixes 16b asked for.
- `9d604f7` ends the connection when a handshake message before a key change does not end its
  record (RFC 9846 §5.1). The test held back for it is in: two KeyUpdates sealed in one record
  fail the read, and neither is answered.
- `e802399` has pins alone take any number of certificates after the leaf. A pinned client
  completes in memory against a chain of 16.
- `7c18e3c` and `7d57fbc` change chapulin's Zig API and what its server refuses at init, and
  colibri needed no change for either.

The runner's `amplificationlimit` case still fails with colibri as the client, for a second
bound: pins alone read the leaf under `CH_WEBPKI_CERT_MAX`, 3,072 bytes, and the case's leaf
is 5,514 (`docs/chapulin.md`). Reported on 2026-09-27; the case waits for chapulin's answer.

What each check printed, on macOS arm64:
- `zig build test`: 1939 of 1939 tests. `zig build test-tls test-tls-keylog -Dcpu=generic`: 73 of
  73.
- `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`
  and `tools/quic_aioquic.sh`: ok. `tools/h3spec.sh`: 49 examples, 0 failures.
- `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
  h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
- `tools/interop.sh quic-go`, every case of its default list: colibri as the server passed every
  case against quic-go, whose client does not run `ecn`, and against colibri's client every case
  but `amplificationlimit` and `rebind-port`. `rebind-port` then passed 3 runs of 3. As the
  client against quic-go, colibri passed every case but `amplificationlimit`.

**CI on Linux, 2026-09-27.** CI failed on `ecb5924` and `94edca5` in its new section alone:
`-Dcpu=generic` names an Arm model, and clang knows no x86 model by that name. `tools/ci.sh` now
runs the section on `x86_64`, the x86-64 baseline, which has no AES instructions, and on
`generic` elsewhere. Built for x86_64 Linux with `-Dcpu=x86_64` and run in an amd64 container on
macOS arm64, the two test binaries passed 34 of 34 and 39 of 39.

**16d, 2026-09-27.** Every check that linked chapulin through `src/testing/` has run over the
library's `tls` since 16b, whose records hold what each printed, and the `-Dchapulin-*` options
left CLAUDE.md in 16a. 16d adds the rest of the step's check, in `tools/consumer_check.sh`:
- The consumer, a project that depends on colibri as a package, now links `tls`, defines the two
  hooks and starts a handshake. So a dependent links chapulin through colibri and runs it.
- A second program links `tls` and defines no `ch_rand_bytes`, and the check requires its link to
  fail naming the hook. On macOS arm64 the linker printed `undefined symbol: _ch_rand_bytes`. Zig
  links an executable only when its file is used, so the step installs it.
- Mutation: the second program given a `ch_rand_bytes` of its own links, and the check fails:
  **CAUGHT**.

One case of the step's check still fails: the runner's `amplificationlimit` with colibri as the
client, which waits for chapulin to read a pinned leaf longer than `CH_WEBPKI_CERT_MAX`. The owner
approved that change on 2026-09-27, and it has not landed.

**16b at chapulin `6fda41f`, 2026-09-27.** The pin moved to chapulin `6fda41f`, whose `df428cd`
adds `ch_alert_sent` and `ch_alert_received`: a failed read now names the alert it sent and the
fatal alert the peer sent. The record provider's `take_alert` reports the peer's close_notify
first, then the peer's fatal alert as `peer`, then this side's as `local`, each once. chapulin no
longer answers a peer's fatal alert. The same push refuses a KeyUpdate whose `request_update` is
neither 0 nor 1 with illegal_parameter (RFC 9846 §4.7.3). A new keylog test sends one and reads
that alert as `local`.

What each check printed, on macOS arm64:
- `zig build test`: 1940 of 1940 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 74
  of 74.
- `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`,
  `tools/quic_aioquic.sh` and `tools/consumer_check.sh`: ok. `tools/h3spec.sh`: 49 examples, 0
  failures.
- `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
  h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
- The QUIC Interop Runner, `tools/interop.sh quic-go`. colibri's server passed every case against
  colibri's client but `amplificationlimit` and `rebind-port`. Against quic-go's client it passed
  every case but `rebind-addr`, and `ecn` was unsupported. colibri's client passed every case
  against quic-go's server but `amplificationlimit`, and `ecn` was unsupported.
  `amplificationlimit` waits for the leaf-size change above.
- Two more rounds of `rebind-port` and `rebind-addr`, colibri as the server, against both
  clients: 7 of 8 passed, and `rebind-addr` against colibri's client failed once. Each rebinding
  failure printed a PATH_CHALLENGE with no PATH_RESPONSE. Only the last run's trace was kept. In
  it, the datagram that carried the server's first challenge on the new path never reached the
  client. The server's next challenge carried new data, as RFC 9000 §13.3 requires, and the
  client answered it. The runner checks only the first challenge on each new path, so losing that
  one datagram fails the case.
- 5 mutations of the new `take_alert`, each **CAUGHT**: reporting before the session failed, each
  report made twice, and each origin swapped.

**16d at chapulin `9bf41c9`, 2026-09-27.** The pin moved to chapulin `9bf41c9`, and step 16 is
done. Under pins alone, chapulin now reads the leaf and each entry after it up to
`CH_WEBPKI_LEAF_PIN_CERT_MAX`, 16,375 bytes, the most one entry holds in the 16 KiB body
chapulin allows a handshake message. The walk with anchors keeps `CH_WEBPKI_CERT_MAX`, 3,072. A session's buffer,
`receive_len`, is 20 KiB, above the 16,410 bytes chapulin's `docs/webpki.md` gives for the
largest Certificate message over TCP. `827b5d4`, in the same push, answers a KeyUpdate whose
body is not one byte, and a NewSessionTicket whose fields do not fill it, with decode_error in
place of unexpected_message.

What each check printed, on macOS arm64:
- `zig build test`: 1940 of 1940 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 74
  of 74.
- `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`,
  `tools/quic_aioquic.sh` and `tools/consumer_check.sh`: ok. `tools/h3spec.sh`: 49 examples, 0
  failures.
- `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
  h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
- The QUIC Interop Runner, `tools/interop.sh quic-go`: every case passed with colibri's server
  against colibri's client, with colibri's server against quic-go's client, and with colibri's
  client against quic-go's server. `ecn` was unsupported in the two pairings with quic-go.
  `amplificationlimit` now passes in all three.

**After 0.1.0: chapulin `157d2ac`, 2026-09-27.** The pin moved to chapulin `157d2ac`, in which
the call that fails a handshake writes its alert itself. The alert is in the clear before the
failing side's write key is installed and sealed after it, and none follows the peer's own fatal
alert. `ch_record_alert` is gone. Each record session's `failure_written` counts the bytes a
failed `handshake` wrote at the front of its output, the alert last, which the caller sends
before it closes. A client reads nothing while its output has no room for a whole alert record,
so the alert always fits the call that fails.

What each check printed, on macOS arm64:
- `zig build test`: 1948 of 1948 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 82
  of 82. `src/tls/record/record_failure_test.zig` adds four tests: a server's alert in the clear
  and sealed, a client's sealed, each read by the peer as its fatal alert, and a client's read
  waiting for room.
- `tools/tls_handshake.sh`, `tools/tls_accept.sh`, `tools/quic_loopback.sh`, `tools/quic_udp.sh`,
  `tools/quic_aioquic.sh` and `tools/consumer_check.sh`: ok. `tools/h3spec.sh`: 49 examples, 0
  failures.
- `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name. The
  h2 and h11 interop scripts with `--tls`: every exchange and request ended as planned.
- 6 mutations, each **CAUGHT**: the client's alert left out of its count, the server's count not
  kept, a client read with no room for the alert, an alert counted after the peer's own, and each
  `failure_written` answering 0.

**The endpoints send it, 2026-09-27.** `src/testing/`'s endpoints now send what a failed
handshake wrote before they close. The server's TLS layer ends the connection on it as on a
finished session, the client's loop closes once the socket has taken it, and the two TLS checks
write it before they exit. Four cases require Go to read colibri's alert:
- `tools/tls_accept.sh` and `tools/h2_server_interop.sh --tls`: a Go client that offers TLS 1.2
  alone reads "protocol version not supported" (RFC 9846 §4.3.1).
- `tools/tls_handshake.sh`: Go's server logs "bad certificate" from colibri's client, which asked
  for a name the certificate does not carry.
- `tools/h2_interop.sh --tls`: Go's server logs "unknown certificate authority" from colibri's
  client, which pins another root.

What each check printed, on macOS arm64:
- `zig build test`: 1948 of 1948 tests. The four scripts above, and the h11 interop scripts with
  `--tls`: ok, every exchange and request as planned.
- 4 mutations, each **CAUGHT**: each TLS check sending nothing, which Go read as an EOF; the server
  layer counting no bytes; and the client loop closing before its alert went out.

**The limits a caller sizes by, 2026-09-27.** A caller cannot reach `chapulin.c`, so `tls` names
the limits a caller sizes its buffers and lists by. cocuyo asked for them.
- `record.alert_record_len` is chapulin's sealed alert record, 24 bytes.
- `record.Client.handshake_output_len_min` is chapulin's `REC_HDR + CH_TX_HELLO`, 2,421 bytes on
  an object with AES-GCM: an output that long takes a whole ClientHello in one call.
- Each configuration's `anchors_max` and `protocols_max` are chapulin's `CH_WEBPKI_ANCHOR_MAX`
  and `CH_ALPN_MAX`.

`zig build test-tls test-tls-keylog`: 84 of 84, with and without `-Dcpu=generic`. A ClientHello
that offers a ticket took 1,568 bytes. 5 mutations, each **CAUGHT**: each list limit one above
chapulin's, a hello bound shorter than a ClientHello, and an alert record one byte short.

**Each session draws from its caller's source, chapulin `5ae9182`, 2026-09-27.** Decision 94 as
amended on 2026-09-27, https://github.com/c4milo/colibri/issues/71. The pin moved to chapulin
`5ae9182`, whose `e4b9c6f` adds `RAND=session`, and colibri's objects are built that way.
- Each `tls` session's `start` takes a `tls.Random` after its configuration, and
  `ServerConfig.check` takes one for an RSA-PSS salt. chapulin refuses a session with none, so no
  draw falls back to another source.
- No program defines `ch_rand_bytes`. `src/testing/entropy.zig` hands each endpoint session the
  bytes of `getentropy`, and the tests pass a seeded SplitMix64 (`random_test_support.zig`).
- `tools/lint/determinism.zig` lets `src/tls/values.zig`, which names the source's type, name
  `std.Random`. Every other file under `src/` still may not.
- `tools/consumer_check.sh` now requires a program without `ch_assert_fail`, chapulin's one hook,
  to fail to link, naming it.

What each check printed, on macOS arm64:
- `zig build test`: 1954 of 1954 tests; `zig build test-tls test-tls-keylog -Dcpu=generic`: 88
  of 88. Two tests replay a record and a QUIC handshake's first flights. One seed twice writes the
  same bytes, and another seed for one side changes what that side writes and leaves the other
  side's ClientHello as it was.
- The twelve scripts of the 157d2ac record, at `e4b9c6f`, whose C and Zig sources `5ae9182`
  keeps: ok, with h3spec's 49 examples and 0 failures and h2spec's 144 in cleartext and over TLS.
  `tools/consumer_check.sh` ran again at `5ae9182`: ok.
- 7 mutations, each **CAUGHT**: a record client that passes no source, each of the four session
  kinds drawing from a fixed source in place of its caller's, `check` passing no source, and the
  program without the hook defining it.

**A connection error ends the connection inside colibri, 2026-09-27.** cocuyo reported it in
https://github.com/c4milo/colibri/issues/68.
- h2 and h11: a record the provider refused, or an error alert, left the connection running,
  though RFC 9846 §5.2 says the receiver MUST terminate it. Now the connection fails at the
  record layer. It reads no record and writes no frame, `encrypt` writes only the alert the
  provider owes, and no close_notify follows (RFC 9846 §6). A seal the provider refuses ends it
  the same way, and an h11 server that owed an error response owes none after it.
- QUIC: `receive` and `send` owe the CONNECTION_CLOSE for the connection error they return (RFC
  9000 §10.2), so a caller no longer asks for its code.
- A TLS failure while `send` writes handshake bytes closed with no frame at all. It now closes
  with its alert's CRYPTO_ERROR code (RFC 9001 §4.8).
- A space out of packet numbers left the connection open, and the other spaces went on
  sending. Now it closes silently and sends nothing more (RFC 9000 §12.3).

What each check printed, on macOS arm64:
- `zig build test`: 1964 of 1964 tests.
- `tools/h3spec.sh`: 49 examples, 0 failures. `tools/h2spec.sh 18443 --tls`: 144 passed in
  cleartext and over TLS. The QUIC, TLS and interop scripts of the 157d2ac record: ok.
- 25 mutations, each **CAUGHT**: 10 in h2, 8 in h11 and 7 in QUIC. They include the failure
  not recorded, no alert owed, a record read, a frame written, a record sealed or a close_notify
  sent after the failure, each QUIC close not owed or carrying the wrong code, and packet-number
  exhaustion left open or owing a close.

**h2's field sections in their order, 2026-09-27.** cocuyo asked for it in
https://github.com/c4milo/colibri/issues/69.
- `write_trailers` writes a trailer section, a HEADERS frame carrying END_STREAM, after the
  final header section of either side's message (RFC 9113 §8.1). No call could send one before,
  so cocuyo's test server wrote the frame and its HPACK by hand.
- Each stream records whether colibri sent its final section, a request or a final response.
  Trailers before it are refused, and so is a response after it, which the peer would read as a
  trailer section carrying `:status`.
- `write_response` now holds the caller's field lines to RFC 9113 §8.2 as `write_request` does.
  An uppercase or connection-specific field went out before, which §8.2.1 makes the peer treat
  as malformed. Trailers are held to the same rules, which refuse a pseudo-header field (§8.1).
- `Event.ended_stream()` names the stream an event ended, where a caller checked a request, a
  response, DATA and trailers.

What each check printed, on macOS arm64:
- `zig build test`: 1970 of 1970 tests. `zig build examples`: every example ran.
- `tools/h2spec.sh 18443 --tls`: 144 passed in cleartext and over TLS, the 2 skipped by name.
  `tools/h2_interop.sh --tls` and `tools/h2_server_interop.sh --tls`: every exchange and request
  ended as planned.
- 13 mutations, each **CAUGHT**: each of the three order checks removed, an interim response
  counted as final, a final response or a request not recorded, either field-line check
  removed, trailers without END_STREAM, and each arm of `ended_stream` wrong.

**chapulin `0adcf33`, 2026-09-27.** The pin moved to chapulin `0adcf33`, whose `19d6a13` sends
a KeyUpdate before an AES-GCM write key reaches 2^24 records, under RFC 9846 §5.5's limit of
2^24.5. colibri changes nothing: `encrypt_record` sizes each write with `writableLen`, which
counts the 27-byte KeyUpdate, and `initiate_key_update` stays `Unsupported` over TCP.

What each check printed, on macOS arm64, at `b31bce6`, whose code `0adcf33` keeps: it changes one
proof floor. `zig build test`: 1970 of 1970 tests; `zig build test-tls test-tls-keylog
-Dcpu=generic`: 88 of 88. The two TLS checks, h2spec's 144 in cleartext
and over TLS, the h2 and h11 interop scripts with `--tls`, `tools/consumer_check.sh` and
`tools/quic_udp.sh`: ok.

**A record that fails, 2026-09-29.** https://github.com/c4milo/colibri/issues/74 asked the test
endpoints to send the alert a record that does not authenticate owes (RFC 9846 §5.2). Since
`ecffe73` and `16ddd3d` they run on the `server` and `client` modules, whose next `send` writes
that alert, and each loop closes once the socket has taken it. Two things were missing:
- A check. `tools/h2_interop/forged_record.go` completes a handshake and then writes a record no
  key sealed, as a client to colibri's server and as a server to colibri's client, offering one
  protocol. The four h2 and h11 interop scripts with `--tls` require Go to read colibri's
  `bad_record_mac`, and the two client scripts require the client to count the connection as
  failed.
- A fix. Each module's `should_close` said to close once the record layer failed, before `send`
  had written the alert, so a caller that asked before its next `send` closed without it. It now
  waits until the alert is out. A test in each module feeds a forged record over h2 and over h11
  and requires one alert record, `bad_record_mac`, before the close.

What each check printed, on macOS arm64:
- `zig build test`: 2331 of 2331 tests. The four scripts with `--tls go`: "a forged record ends
  with the server's alert: bad record MAC" from both server scripts and "the client's alert: bad
  record MAC" from both client scripts, with every exchange and request as planned.
- 8 mutations, each **CAUGHT**. `failure_sent` ignoring the owed alert, in each of its four arms,
  by the module tests. The server sealing nothing once stopped, by the server test and both server
  scripts. A failed record closing the client before its alert, by the client test and both client
  scripts. Each loop closing before its output drained, by the h11 scripts' forged record; in the
  h2 scripts the refused handshake fails first.

**chapulin `10a5bc8`, 2026-09-29.** The pin moved to chapulin `10a5bc8`, which closes
https://github.com/c4milo/chapulin/issues/180 for https://github.com/c4milo/colibri/issues/81.
- An object with AES-GCM now prefers TLS_AES_256_GCM_SHA384, then TLS_AES_128_GCM_SHA256, then
  TLS_CHACHA20_POLY1305_SHA256, as a client and as a server (chapulin's decision 80). The owner
  put AES-256-GCM first for CNSA 2.0. An object without AES-GCM holds ChaCha20 alone, as before.
- `tls.values.Client.cipher_suites` sets a client's order, as `tls.values.Server.cipher_suites`
  sets a server's, and the ClientHello offers exactly that list. An object without AES-GCM
  refuses any list with `SuitesUnavailable`, and chapulin refuses a suite named twice when the
  session starts.
- chapulin's QUIC calls now take a version (its `9680043`). colibri's `quic` speaks version 1
  alone (RFC 9000 §15), so `tls.quic.version` names it once: each session starts in it, and every
  seal, open and Retry call passes it.

What each check printed, on macOS arm64:
- `zig build test`: 2337 of 2337 tests. `zig build test-tls test-tls-keylog -Dcpu=generic`: 96
  of 96.
- `tools/tls_accept.sh`: `suite=0x1302` against Go's client. `tools/tls_handshake.sh`:
  `suite=0x1301` against Go's server, which takes its own order among the AES suites once the
  client lists one first. Before the pin, CI printed `suite=0x1303` for both.
- `tools/quic_loopback.sh`, `tools/quic_udp.sh`, `tools/quic_aioquic.sh` against aioquic 1.3.0,
  h3spec's 49 examples, h2spec's 144 in cleartext and over TLS, and `tools/consumer_check.sh`:
  ok.
- 11 mutations, each **CAUGHT**: the client's order not passed on, and its refusal in an object
  without AES-GCM; either role's version left unset; the version changed in the constant and in
  each of the five calls; and the shared length check. The close a failed session seals was
  caught only once a test opened it at the peer, which this change adds.

**16e, 2026-09-30.** Both objects are built `AES=runtime` on x86-64 and arm64, and each session
runs the AES instructions or ChaCha20 alone, as its caller answers (decision 97 as amended on
2026-09-29).
- `values.Client` and `values.Server` require `aes_instructions`, `present` or `absent`, with no
  default, and `config.zig` hands it to an object that takes it. An object built for another
  architecture fixes the choice when it is built, and there the answer changes nothing.
- The tests pass the build target's answer (`testdata.aes_instructions_present`), and run both
  answers where the target has the instructions. In record mode and in QUIC every pair of
  answers completes a handshake, and runs AES-256-GCM only when both sides hold it. Under
  `absent` a suite order that names AES-GCM is refused when a session starts.
- `src/testing/cpu.zig` answers for the test programs, and `tools/consumer` for itself, each for
  the target it was built for, until stdx's `platform` module answers
  ([stdx#15](https://github.com/c4milo/stdx/issues/15)). `tools/ci.sh`'s leg on a CPU model
  without the instructions runs the `tls` tests under `absent` alone.

What each check printed, on macOS arm64:
- `tools/ci.sh`: every section passed, with 2407 of 2407 tests in Debug and in ReleaseSafe.
- 8 mutations, each **CAUGHT**: the client's or the server's answer not handed on, either answer
  handed on as the other, no object taking the answer, the build keeping the target's choice on
  x86-64 and arm64, and no constant-time statement, which chapulin's build refuses. The test
  programs answering `absent` was caught by `tools/h3spec.sh`, whose client offers AES-GCM
  alone. The build mutation first failed to compile, which showed that `config.zig` named
  chapulin's `AesInstructions` for an object without it. The answer's condition is now decided
  at compile time, and a test pins the choice.

**16e with stdx `fa53aa4`, 2026-09-30.** The stdx pin moved from `342cb71` to `fa53aa4`, which
carries stdx's `platform` module ([stdx#15](https://github.com/c4milo/stdx/issues/15)). The test
programs and `tools/consumer` ask the CPU once through `platform.probe()` and pass `present` only
when `aes_clmul` is `yes`, and colibri's package exports `platform` (decision 97 as amended on
2026-09-30). The tests keep the build target's answer. The next record undoes the export.

What each check printed, on macOS arm64:
- `tools/ci.sh`: every section passed, with 2493 of 2493 tests in Debug and in ReleaseSafe.

**16e at chapulin `900ce67`, 2026-09-30.** The pin moved from chapulin `044a49c` to `900ce67`,
which carries the AES-GCM record path of [chapulin#184](https://github.com/c4milo/chapulin/issues/184).
chapulin's `docs/performance.md` times one 16 KiB AES-256-GCM seal on an Apple M1 Pro at 5.4,
5.7 and 5.6 µs, under macOS with Apple clang 21 and a Linux VM with clang 18 and gcc 13, where
it took 26.8, 27.6 and 36.3 µs at `044a49c`. chapulin calls these the filter's figures, and
colibri has none of its own. The pin also refuses a ClientHello too long to stage with nothing
sent, and records internal_error when the transport refuses a send. Its vector Poly1305 runs
only under `WIDEMUL=native`, which colibri does not build
([#84](https://github.com/c4milo/colibri/issues/84)).

What each check printed, on macOS arm64:
- `tools/ci.sh`: every section passed, with 2503 of 2503 tests in Debug and in ReleaseSafe.

**16e, the probe as input, 2026-09-30.** `values.Client` and `values.Server` take `cpu`, the
`platform.Cpu` the program's probe returned, in place of `aes_instructions`, and colibri's
package no longer exports `platform` (decision 97 as amended again on 2026-09-30).
- `tls` imports stdx's `platform` for the `Cpu` type alone. A session runs the AES instructions
  only when `aes_clmul` is `yes`.
- The tests pass a probe of the build target, and run every answer, `yes`, `no` and `not_known`,
  where the target has the instructions. Under `no` and `not_known` alike a session runs
  ChaCha20 alone, and a suite order that names AES-GCM is refused.
- `tools/consumer` depends on stdx itself, at the commit colibri pins and with the options
  colibri gives it, and compiles against the `platform.Cpu` that `tls` names.

What each check printed, on macOS arm64:
- `tools/ci.sh`, on the 0.7.0 release commit that carries it: every section passed, with 2505 of
  2505 tests in Debug and in ReleaseSafe.
- 6 mutations, each **CAUGHT**: `yes` running no AES instruction, `no` or `not_known` running
  them, and the client's or the server's probe not handed on; and, by `tools/h3spec.sh`, the test
  programs' probe saying `no`, since h3spec's client offers AES-GCM alone.

**16e at chapulin `c798fb8`, 2026-09-30.** The pin moved from chapulin `900ce67` to `c798fb8`,
as the owner approved. No API changed. chapulin's `docs/performance.md` times one 16 KiB record
on an Apple M1 Pro, under macOS with Apple clang 21 and a Linux VM with clang 18 and gcc 13:
- An AES-256-GCM seal takes 3.6, 4.0 and 4.1 µs, where it took 5.4, 5.7 and 5.6 at `900ce67`.
  Counter mode and GHASH run in one loop over each pass of eight blocks (`gcm_hw.c`).
- A ChaCha20-Poly1305 seal under `CHACHA=vector` takes 42.6, 37.3 and 55.4 µs, where it took
  47.5, 42.1 and 61.4. On NEON the ChaCha20 runs eight blocks a pass, two groups of four.
- colibri has no figures of its own. Under `WIDEMUL=native` the ChaCha20-Poly1305 seal takes
  11.8 µs, which waits on [chapulin#186](https://github.com/c4milo/chapulin/issues/186) and
  [#84](https://github.com/c4milo/colibri/issues/84).

What each check printed, on macOS arm64:
- `tools/ci.sh`: every section passed, with 2528 of 2528 tests in Debug and in ReleaseSafe.

**16f, 2026-10-09.** The pin moves from chapulin `c798fb8` to `v0.2.0` (`26fa782`). The proposal
carried one shape for the timing claims in code, and showed two more, and the owner ruled for the
one built, and for test programs that state the mode on x86-64, where no program can read DOITM
([decision 97](../../decisions/0097-the-librarys-tls-module-is-tls.md) as amended on 2026-10-09).
- `tls.Cpu` holds the probe and a `tls.Timing`, `not_stated` or `data_independent`. colibri
  claims constant-time AES under `data_independent` where the probe's `aes_clmul` is `yes`, and
  the constant-time multiply under `data_independent` alone. Without the AES claim a session
  holds ChaCha20 alone, and chapulin refuses a suite order that names AES-GCM.
- The test programs set PSTATE.DIT on their thread on arm64 where the core has FEAT_DIT, and
  state the mode on x86-64, so their sessions run the AES-GCM suites h3spec offers alone. The
  examples state nothing and run ChaCha20.
- On macOS arm64: the `tls` tests passed 58 of 58, and 122 of 122 with the `tls_keylog` tests on
  `-Dcpu=generic`; h3spec passed 49 of 49; `tools/quic_loopback.sh`, `tools/tls_handshake.sh` and
  `tools/tls_accept.sh` passed.
- 8 mutations, each **CAUGHT** by a test: the AES claim without the mode, or without the probe;
  the multiply claim never made, or always; the client's description never reaching chapulin;
  the host objects built with ChaCha20 alone; and the test programs stating the mode without
  setting PSTATE.DIT, or stating none on arm64.
- `zig build test`: 131 of 131 steps and 2662 of 2662 tests passed, the memory table unchanged.

**16f on the judge's runner, 2026-10-09.** The first judge run after the bump,
[38015272566](https://github.com/c4milo/colibri/actions/runs/38015272566), stopped in both jobs
at `h2-tls-many`: the test server answered none of h2load's 100 readiness requests. The same
server build answered them in an arm64 Linux container on an M1, whose kernel reports `dit`, with
epoll and with io_uring. The runner's VM most likely hides FEAT_DIT, so the server stated no mode
and held ChaCha20 alone, which h2load's AES-256-GCM offer cannot meet. At the owner's ruling the
test programs state the mode on every arm64 core, and the server names the CPU it described when
it starts in TLS mode ([decision 97](../../decisions/0097-the-librarys-tls-module-is-tls.md) as amended again on 2026-10-09).
- A test hands the mode's choice a probe with no FEAT_DIT, which an M1 never gives.
- 2 mutations, each **CAUGHT** by `src/testing/cpu.zig`'s tests: an arm64 core that states the
  mode without setting PSTATE.DIT, and one without FEAT_DIT that states no mode.
- `zig build test`: 131 of 131 steps and 2743 of 2743 tests passed.
- The rerun, [38021801946](https://github.com/c4milo/colibri/actions/runs/38021801946), on
  `89ecb36`, ran TLS_AES_256_GCM_SHA384 on both TLS inputs in both jobs. `89ecb36` changes only
  what the test programs state on a core whose probe does not answer `yes` for FEAT_DIT, so the
  runner's probe does not.
- That run is the first to count a tree with chapulin 0.2.0 on the judge. Its first job counted
  47,000 instructions per request on `h2-tls-many` and 7,596,003 per connection on
  `h2-tls-one`. Step 13c's table holds 85,507 and 55,569,416 for those inputs on `cf7bcd2`. The
  judge never compares two runs, so these are two counts and not a ratio, and no run has
  measured the competitors since.

**16f with stdx `f4c20dd`, 2026-10-25.** The stdx pin moves from `5da4397` to `f4c20dd`, whose
probe answers `sha256`, `sha512` and `sha3` ([stdx#19](https://github.com/c4milo/stdx/issues/19)).
On arm64 colibri makes chapulin's three SHA claims where the probe answers `yes` under
`data_independent`, and on x86-64 it makes none ([decision 97](../../decisions/0097-the-librarys-tls-module-is-tls.md) as amended on
2026-10-24).
- On macOS arm64 the `tls` tests passed 60 of 60, and on `-Dcpu=generic` too. Built for x86-64
  Linux and run in Docker, they passed 60 of 60.
- 5 mutations, each **CAUGHT** by the test of chapulin's claims: the SHA claims without the
  timing; the claims without the arm64 condition, on x86-64; the SHA-256 claim never made; and
  the SHA-3 claim read from `sha512`, and the SHA-512 claim from `sha256`. The SHA-3 mutation
  was **NOT CAUGHT** until the tests described one SHA answer at a time.
- Three judge runs stopped when a UDP server of the base or of the change met AddressInUse on
  the port, and no socket held the port moments later. A server on io_uring can hold its socket
  after it exits, so `bench/run.sh` now waits for the UDP port to be free after each server
  stops. The next run logged one such wait.

The judge, [run 40159041766](https://github.com/c4milo/colibri/actions/runs/40159041766),
measured the change against `6d783e6` with `--h11` and `--h3`. No input loses past the noise by
either count in either job, and each input that makes a handshake wins in both jobs:
- h2-tls-one at 0.7310 in both jobs: 1,928,164 instructions a connection fall to 1,409,582 in
  the first.
- h11-tls-one at 0.7267 in both jobs, and at 0.7057 and 0.7054 by its user instructions.
- h3-one at 0.7806 and 0.7815: 3,588,696 instructions a connection fall to 2,801,492 in the
  first.
- h2-tls-many at 0.9759 and 0.9767, and h3-many at 0.9936 in the first job, within the noise in
  the second.

**A fatal alert the program names, 2026-10-28.** cocuyo's DNS over TLS client must send
record_overflow before it closes on a record longer than RFC 9846 §5.2 allows
([#114](https://github.com/c4milo/colibri/issues/114)). colibri had no call that writes an alert
other than close_notify. chapulin a51898de adds `fail` ([chapulin#208](https://github.com/c4milo/chapulin/issues/208)), and colibri pins it. The
owner ruled where the call goes on 2026-10-28: on the session types, not in
`tls_provider.VTable`, which no provider then changes for.
- Public names: `tls.record.Client.fail`, `tls.record.Server.fail` and `tls.record.FailError`.
  A test beside the two types lists their calls, and the root's test lists `tls.record`.
- `fail(description, output)` takes the 26 error alerts of RFC 9846 §6.2 on a connected
  session. It writes at most `alert_record_len` bytes and fails the session. A refused call
  writes nothing and leaves the session as it was.
- tools/consumer and docs/usage.md show the call. No program of `examples/` drives a record
  session itself, so none shows it.
- 5 mutations **CAUGHT**: each refusal's error, the output's check, the count written, and the
  server's alert. 1 **NOT CAUGHT**: `KeyExhausted`, which no test can reach. chapulin keeps the
  write key's last sequence number for this alert (its `tls_write.c`).
- [Run 40799721045](https://github.com/c4milo/colibri/actions/runs/40799721045), against
  `b8cdbda` with `--h11` and `--h3`: no input loses in either job. The bump's handshakes win:
  h11-tls-one at 0.9833 and 0.9847, h2-tls-one at 0.9873 and 0.9880, and h3-one at 0.9905 and
  0.9879.

**The key-exchange group, 2026-10-31.** cocuyo reports which group protected each DNS
connection, beside the cipher suite. The owner ruled the form on 2026-10-31 (decision 140), and
chapulin's sessions already answer `group()` at colibri's pin.
- `tls_provider.Negotiated.group` holds the codepoint, and `tls_provider.constants.protocol`
  names X25519MLKEM768, x25519 and secp256r1.
- Public names: `tls.quic.Client.negotiated`. A test beside `tls.quic.Client` and
  `tls.quic.Server` now lists their calls, `is_client` among them, which the module's files read.
- tools/consumer and docs/usage.md show the read through a record session's provider.
- 4 mutations **CAUGHT**: the record group, the QUIC group, the QUIC version, and a QUIC report
  before the handshake completed, which a new test of a client that read only the ServerHello
  catches.

**chapulin's Zig types, 2026-10-31.** colibri pins chapulin c8cd8021, whose Zig API takes and
returns Zig slices for chains, anchors and ALPN names
(https://github.com/c4milo/chapulin/issues/213), which the owner asked for on 2026-10-31.
- `config.zig` passes a chain and an ALPN list as they are, and checks their lengths alone. An
  anchor is still copied, because each object has a `TrustAnchor` type of its own.
- Each session type takes chapulin's `Limits`, set from `certificate_chain_len_max` and
  `anchors_max`, so no limit of colibri's changes.
- chapulin holds the C arrays in each session now: each TLS session grows by 1,024 bytes, and
  colibri's configurations shrink by the copies they held. docs/performance.md's table is
  printed again.
- 3 mutations **CAUGHT**: each length check, and an anchor's name.

**The PEM reader, 2026-10-31** ([#97](https://github.com/c4milo/colibri/issues/97)). A program
hands `tls` the PEM files an operator holds, as decision 141 rules: `tls.pem.chain`,
`tls.pem.p256_key` and `tls.pem.anchors`, and the type `tls.P256Key`.
- Public names: `tls.pem` and `tls.P256Key` on the root's list, and a list of `tls.pem`'s four
  names beside it.
- The test identity gains its PEM files, made by the commands in `src/testing/testdata/`: the
  chain, the key under both labels, and a CA bundle with title lines.
- `examples/server_exchange.zig` reads its chain and key, and `examples/client_exchange.zig` its
  anchors, through `tls.pem`. docs/usage.md shows both.
- Each call skips the text lines around its blocks (RFC 7468 §2), which chapulin c8cd8021 does
  for chains and keys too (https://github.com/c4milo/chapulin/issues/214), at the owner's word.
- `anchors_max` rises from 12 to 256. Each TLS session grows by 7,808 bytes: the default
  `server.Endpoint`, which holds 32 sessions, by 249,856 bytes, and a pool by 23,424.
- 9 mutations **CAUGHT**: the chain's cap, each half of the key, the refused key, the anchors'
  two fields, an anchor dropped, and a room past the caller's. The cap was NOT CAUGHT until a
  test of a chain of 18 certificates was added. Wiping a copy of the key could not be tested,
  so chapulin now decodes into the caller's key and no copy is made.

**chapulin 0.3.0, 2026-11-05.** The pin moves from chapulin `965668d2` to `v0.3.0`
(`4da5b220`). Its decision 185 renames the TCP driver and makes each session opaque.
- `chapulin.record` is now `chapulin.tcp`, and `recordState` and `recordClose` are now
  `tcpState` and `tcpClose`. `record_provider.zig` calls `ch_tcp_whole_len`.
- colibri read no field of a chapulin session, so the opaque sessions change no code.
- colibri's own names do not change: `tls.record` stays on the root's list (decision 115).
- Each server session grows by 16 bytes: `tls.record.Server` to 49,480 and `tls.quic.Server`
  to 101,096. The default `server.Endpoint` grows by 512 bytes. docs/performance.md's table is
  printed again.
- **Check met, 2026-11-05,** on macOS 26 on arm64: `tools/ci.sh` passed on the tree of this
  commit. The rename adds no check, so it needs no mutation.

**chapulin 0.4.1, 2026-11-07.** The pin moves from `v0.3.0` (`4da5b220`) to `v0.4.1`
(`22a70c13`). chapulin 0.4.0 moved its C headers to `include/chapulin/`, and 0.4.1 carries the
same library from a commit whose CI passed.
- colibri takes chapulin through its Zig module alone, and that module did not change. So the
  bump changes no code.
- No session size changes: `zig build test` passed, and it fails when docs/performance.md's
  table differs.
- **Check met, 2026-11-07,** on macOS 26 on arm64: `tools/ci.sh` passed on the tree of this
  commit. The bump adds no check, so it needs no mutation.

**chapulin 0.5.0, 2026-11-08.** The pin moves from `v0.4.1` (`22a70c13`) to `v0.5.0`
(`15c37ef4`), and amends decision 94's pin. chapulin's decision 190 gives its Zig API the names
and forms of TigerStyle. The C library does not change.
- Each call colibri makes has its snake_case name, such as `record_in`, `crypto_out` and
  `alert_sent`. A tcp session's `end(output)` sends close_notify, `close()` ends the session,
  and `state()` reports it.
- `chapulin.Client` and `chapulin.Server` are now `ClientOptions` and `ServerOptions`. Each
  session's `init` takes them through a `*const` pointer.
- `tls.quic` writes its state into the options' `context` before `init`. It wrote
  `hook.context` after `init` before. An assertion holds that `init` stored the state.
- `write_parts` takes `[]const []const u8`, at most `tcp.parts_max` (16) parts. colibri passes
  two, a frame's header and its data (decision 139).
- chapulin reports an alert as `AlertDescription`, and colibri converts it to
  `tls_provider.Alert` through its byte.
- The Retry token calls take `quic.RetryConnectionIds`, and an RSA identity takes
  `*const RsaKey`. A ticket's `Fields` names `lifetime_seconds`, and `dnssec.Hash.init_digest`
  starts a digest.
- colibri's own names do not change.
- Each options struct gains `context`, one pointer. `tls.quic.Client` grows by 8 bytes to
  101,616 and `tls.quic.Server` to 101,104. The default `server.Engine` grows by 144 bytes and
  a pool's fixed part by 24. docs/performance.md's table is printed again.
- **Check met, 2026-11-08,** on macOS 26 on arm64. `zig fmt --check`, `zig build test`, `zig
  build examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh` passed. The TLS and QUIC
  scripts of `tools/ci.sh` passed too: `tools/tls_handshake.sh`, `tools/tls_accept.sh`,
  `tools/tls_openssl.sh`, `tools/quic_loopback.sh` and `tools/quic_udp.sh`.
- The bump adds one assertion, that `init` stored the state in the hook. Mutation, under `zig
  build test-tls`: remove the line that writes the options' `context`, and its assertion:
  CAUGHT, 2 tests crash.
