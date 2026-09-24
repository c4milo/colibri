# The request to chapulin

Status: written 2026-09-16 and refreshed against chapulin's tree on 2026-09-22, at its commit
`2ef6d52`. Every item below has since landed in chapulin, and each one says how; "What is left"
names the one contract note that remains. The h2 blocking-handshake item landed during the first
refresh that day, which is what [issue 20](https://github.com/c4milo/colibri/issues/20) turns on;
the exporter and the key log landed after it. Not sent yet;
sending it is the owner's (https://github.com/c4milo/colibri/issues/5). colibri never edits chapulin's repository, and
nothing here binds chapulin until chapulin's own decisions record it.

[Decision 10](decisions.md#what-the-caller-supplies) rules that chapulin provides all of colibri's
crypto. This document is the request that ruling needs: what colibri asks chapulin to add, why each
item is needed, and which of chapulin's recorded decisions each item reverses.

## How colibri would use chapulin

colibri defines two caller-supplied vtables and implements neither in its library
([decisions 8, 9 and 48](decisions.md#what-the-caller-supplies)):

- `tls.Provider` runs the TLS 1.3 handshake. Its record mode serves h2, and its QUIC mode serves
  h3.
- `crypto.Suite` holds every key of a QUIC connection and protects every packet: it installs the
  Initial keys, seals and opens whole packets at an encryption level, checks and writes the Retry
  tag, performs the key update, and discards a level's keys when colibri says so. colibri holds
  no key. This is the split chapulin's `docs/quic.md` ruled, "chapulin owns packet protection at
  every level", and colibri's decision 48 adopts it.

chapulin would fill both. colibri's library source never imports chapulin, so the packaged library
links no TLS stack. `src/testing/` links chapulin, because every check from design §8 step 5 onward
needs a TLS 1.3 server that signs its certificate. A consumer that wants chapulin links it the same
way.

## What chapulin has today

Verified against chapulin's tree on 2026-09-22, at its commit `8a32aeb`:

- Its API is one set of calls per build, and the set replaces rather than extends. A
  `TRANSPORT=tls` client exports `ch_connect`, `ch_write`, `ch_read` and `ch_close` (`tls.h`); a
  `TRANSPORT=record` client exports nine, the six `ch_record_*` calls beside those three; a
  `TRANSPORT=quic` client exports fifteen `ch_quic_*` calls. `RAND=drbg` adds `ch_drbg_seed`, and
  the two CA trust modes add `ch_pubkey_from_pem`. `make lib-check` diffs the object's exports
  against that list for exact equality.
- The handshake no longer has to block. `TRANSPORT=record` drives it bytes in, bytes out:
  `ch_record_init` stages the ClientHello, `ch_record_out` hands staged records to the caller, and
  `ch_record_in` takes the peer's. chapulin calls neither `cfg.send` nor `cfg.recv` while that
  handshake runs, which its INV-28 claims and `bin/rec_loop_test` measures by failing the run if
  either is called.
- The records after the handshake still go through the callbacks. `ch_read` and `ch_write` call
  `cfg.recv` and `cfg.send`, which are contracted to return 1..n bytes or -1 and to block
  (`cfg.h:371`). There is no "nothing yet" answer. `rec.h` states the assumption that closes the
  gap for some callers: by then "the caller holds the bytes and its send and recv are buffer
  copies". A caller reading a stream does not always hold a whole record.
- It has a working server role, in three transports. `ROLE=server` exports `ch_srv_accept` and
  `ch_srv_check` over TLS records, `ch_srv_record_init` and `ch_srv_record_in` under
  `TRANSPORT=record`, and `ch_srv_quic_init`, `ch_srv_quic_crypto_in` and `ch_srv_quic_retry_tag`
  under `TRANSPORT=quic`. No function in `srv*.c` is a stub: the `CH_SRV_STUB` marker matches
  nothing and the machinery that read it is gone. `ROLE=both` builds one object that answers and
  dials, which two objects cannot do because each carries the shared half.
- The server signs, and one signer is held to a branch count. `rsa_sign.c` signs
  `rsa_pss_rsae_sha256` and `p256_sign.c` signs `ecdsa_secp256r1_sha256`; a deployment provisions
  one identity per scheme and `ch_srv_check` verifies both at boot. `rsa_sign.c` sits in the
  Makefile's `BRANCH_SRCS`, so its conditional-branch count is held at a recorded ceiling per
  compiler and target. `p256_sign.c`, `p256_scalar.c` and `p256_point.c` do not, so the ECDSA
  signing path carries no such ceiling.
- Sessions share no global state under `RAND=extern`. Each connection has its own `ch_tls`, and
  the library's one global is `drbg.c`'s seeded flag, which `RAND=extern` leaves out: that build
  packages no generator and leaves `ch_rand_bytes` undefined, so an image that wires none fails to
  link.
- It offers ALPN at both ends. A client lists `cfg.alpn_protocols` and reads `alpn_selected`
  (RFC 7301 §3.1); a server selects from the client's list and ends the handshake with the fatal
  `no_application_protocol` alert when nothing overlaps (`srv_flight.h`). A `TRANSPORT=quic` build
  carries the ALPN fields whatever its trust mode (`cfg.h:232`), which is what RFC 9001 §8.1
  requires of clients too.
- It verifies certificates five ways, and one `TRUST` value now names both the trust and the
  algorithm: `raw-rsa` and `raw-ecdsa` pin the key itself, `ca-rsa` and `ca-ecdsa` pin a CA key
  the chain must reach, `webpki` verifies a public chain against the caller's anchors, and `none`
  is the server's value. The `TRUST=ca` this document named is now two values.
- Its QUIC mode has its API, not only its primitives. The fifteen `ch_quic_*` calls work: the
  `CH_QUIC_STUB` marker is retired, `make lib-check` counts fifteen exports on the client object
  and sixteen on the server's, and chapulin records both Initial directions checked against
  RFC 9001 Appendix A.3 byte for byte with header protection, and the Retry tag against A.4. The
  `AES` axis picks the implementation: `soft`, `hw` under the compiler's own intrinsics, or
  `extern` for a caller-supplied block.
- It has an exporter behind a build value. `EXPORTER=on` adds `ch_export` (RFC 9846 §7.5) to the
  API and 32 bytes to `ch_tls`; it is off by default, so a device pays nothing. It refuses
  `TRANSPORT=quic`, because the call sits in `tls.c`, which a QUIC object does not compile, and
  RFC 9001 uses no TLS exporter. chapulin's decision 43.
- It has a key log behind a build value. `KEYLOG=on` hands each of the four traffic secrets to
  `ch_keylog(io, label, client_random, secret)` as it derives them, in both roles and every
  transport, QUIC included. The image defines `ch_keylog`, the way it defines `ch_rand_bytes`, so
  a build that turned the axis on and wired nothing fails to link. The labels are the NSS key log
  format's. A client in a raw or ca trust mode refuses the axis; `TRUST=webpki`, the server's
  `TRUST=none` and `ROLE=both` admit it. chapulin's decision 44 and INV-29.

Two of these reshape the request. The blocking-callback item is now half answered: the handshake
takes bytes and returns bytes in both roles, and only the records after it still need a callback
that cannot say "nothing yet". And the two items this document last listed as missing, the
exporter and the key log, both exist, each as a build value colibri turns on in its own objects.

## What colibri asks for

### For h2: record mode

Design §8 step 5 waits for these five.

1. **ALPN at the server** (RFC 7301). chapulin offers the client half already. A server picks a
   name from the client's list, and one that shares no protocol ends the handshake with the fatal
   `no_application_protocol` alert, value 120 (RFC 7301 §3.2). **Landed**: `srv_flight.h`
   returns `CH_EPROTO` with that alert when nothing overlaps.
2. **A server role, with constant-time signing.** The server signs CertificateVerify
   (RFC 9846 §4.5.2) with a private key, and that path must not leak the key through timing.
   **Landed**, unevenly: `rsa_sign.c` carries a recorded branch-count ceiling and the three
   `p256_sign` sources do not, so ask chapulin whether the ECDSA path is meant to be held the
   same way.
3. **A record mode that takes bytes in and returns bytes, in both roles, for the handshake and
   for the records after it.** colibri owns no I/O, so it cannot call through a callback that
   blocks, and [decision 46](decisions.md) holds its test endpoints to the same rule. This is the
   shape `ch_quic_crypto_in` and `ch_quic_crypto_out` already give the QUIC mode. It is also why
   colibri's h2 client runs its interop in cleartext today: the client role works, and it cannot
   sit under a `poll` loop. The server role is stubs, so the cheapest time to give it this shape
   is before it is written. **Landed for the handshake, open for the records after it**:
   `TRANSPORT=record` gives both roles bytes in and bytes out, and the server role was written
   with that shape rather than retrofitted, so the handshake this item asked about no longer
   blocks in either role. `ch_read` and `ch_write` still call `cfg.recv` and `cfg.send`, which a
   caller satisfies by holding the bytes first — which colibri's adapter already does. See item 3
   of "What is left" for why that is a note rather than a gap.
4. **Many sessions with no global state.** One process runs many connections at once, each with
   its own session. **Landed**: `RAND=extern` packages no generator, so the DRBG's global is not
   in the object and each connection holds its own `ch_tls`.
5. **The exporter** (RFC 9846 §7.5). **Landed** behind `EXPORTER=on` as `ch_export(t, label,
   context, context_len, out, out_len)`. It refuses every state but connected, labels over 32
   bytes and outputs over 255. chapulin's `bin/rec_loop_test` runs a client and a server to
   completion and requires the two to export one value.

### For h3: QUIC mode (RFC 9001)

Design §8 steps 9, 10, 12 and 13 wait for these six. **All six have landed.** They are kept
because the reasoning in them is the reasoning, and because each one names the RFC clause colibri
will check chapulin's answer against.

1. **Handshake bytes per encryption level, with no record layer** (RFC 9001 §4.1.3). QUIC carries
   handshake messages in CRYPTO frames, so the provider takes and returns unframed handshake bytes
   tagged with their encryption level.
2. **Per-level keys that never leave** (RFC 9001 §4.1.4). When an encryption level becomes
   available, chapulin keeps that level's secrets and says the level is ready; colibri asks it to
   seal and open packets at the level. The first form of this request asked for the secrets
   themselves, and [decision 48](decisions.md#what-the-caller-supplies) withdrew that.
3. **The `quic_transport_parameters` extension, codepoint 0x39** (RFC 9001 §8.2). colibri
   supplies the extension's bytes and reads the peer's; the provider carries them in the handshake.
4. **ALPN** (RFC 9001 §8.1), which QUIC requires of clients as well as servers.
5. **Alerts returned as values.** colibri maps each alert to the QUIC error code 0x0100 plus the
   AlertDescription (RFC 9001 §4.8) and closes the connection itself.
6. **No TLS KeyUpdate message** (RFC 9001 §6), **no EndOfEarlyData message** (RFC 9001 §8.3), and
   **no middlebox compatibility mode** (RFC 9001 §8.4).

### For `crypto.Suite`

All four have landed.

Design §8 step 7's vectors wait for these, and every QUIC connection needs them. The first form
of this request asked for five primitives: AES-128-GCM, one AES-128-ECB block, raw ChaCha20,
ChaCha20-Poly1305 and HKDF-SHA256. chapulin has since built them and ruled that none is exported,
and [decision 48](decisions.md#what-the-caller-supplies) follows it. What colibri asks for now is
the API over them, which `quic.h` already declares.

1. **The fifteen `ch_quic_*` calls, working.** **Landed**: the `CH_QUIC_STUB` marker is retired
   and `make lib-check` counts fifteen exports on the client object. The sentence below described
   the tree at `3ff8517`, where each call carried `CH_QUIC_STUB` and failed closed.
   colibri's suite maps onto them one for one: `install_initial_keys` onto
   `ch_quic_initial_keys`, `seal` and `open` onto `ch_quic_seal` and `ch_quic_open`,
   `retry_tag_valid` onto `ch_quic_retry_ok`, `update_keys`, `key_phase` and
   `discard_previous_keys` onto `ch_quic_key_update`, `ch_quic_key_phase` and
   `ch_quic_drop_previous_keys`, and `discard_keys` onto `ch_quic_discard`.
2. **A server role in the QUIC mode.** **Landed**: `ch_srv_quic_init` and
   `ch_srv_quic_crypto_in`, sixteen exports on that object. `ch_quic_init` is a client's. colibri's h3 server, the
   server half of the interop endpoint and `secnetperf`'s peer need the other side: the server's
   Initial keys, which RFC 9001 §5.2 derives from the same connection ID under the other label,
   and the server's handshake.
3. **Writing the Retry Integrity Tag** (RFC 9001 §5.8). **Landed** as
   `ch_srv_quic_retry_tag`, over the one `gcm_seal` that `ch_quic_retry_ok` also uses, so minting
   and checking cannot disagree. `ch_quic_retry_ok` checks one, which is the client's half. A
   server that sends a Retry packet must compute it.
4. **A key log** for the interop runner (design §9), written by chapulin, because colibri holds
   nothing to log. **Landed** behind `KEYLOG=on`, and it took what this item expected: a
   decision record (chapulin's 44) and a build axis, with a link-time hook rather than a `ch_cfg`
   callback. It logs `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`,
   `CLIENT_TRAFFIC_SECRET_0` and `SERVER_TRAFFIC_SECRET_0`, each under the ClientHello's random,
   and chapulin's loopback test requires both ends to log the same random and secret per label.
   `src/testing/` defines the hook and writes the lines to `SSLKEYLOGFILE`.

RFC 9001 fixes Initial packets (§5), the header protection used before a suite is selected
(§5.4.1) and the Retry tag (§5.8) to AES whatever suite TLS negotiates, so no QUIC endpoint works
without AES ([decision 9](decisions.md#what-the-caller-supplies)). chapulin's `AES` build axis
answers that.

## What is left

Nothing chapulin owes, and one contract note that is smaller than a gap.

**A caller that buffers no whole record has no way to say so.** `ch_read` and `ch_write` call
`cfg.recv` and `cfg.send`, which return 1..n bytes or -1, so a caller must hold the bytes before
it calls. colibri already does: [issue 20](https://github.com/c4milo/colibri/issues/20) records
that after the handshake "the adapter's phase 2 is buffer in and buffer out — `ch_read` and
`ch_write` touch no descriptor at all". So this is a contract colibri meets, not a blocker. It is
written down because a result code meaning "call again, nothing consumed" would let a caller stop
pre-buffering, and because nothing in chapulin states that the contract is deliberate rather than
incidental.

**What colibri has done with the two new values.** Both are off in chapulin's default build. The
exporter is on: both TLS objects are built `EXPORTER=on`, `link_chapulin` passes `CH_EXPORTER`,
and `src/testing/tls/chapulin_record.zig` answers `export_keying_material` through `ch_export`.
`tools/tls_handshake.sh` and `tools/tls_accept.sh` require colibri's value to match the Go peer's.
The key log is on too. `src/testing/` links one chapulin QUIC object built `TRANSPORT=quic
ROLE=both KEYLOG=on`, in the loopback check and the UDP endpoint, and
`src/testing/quic/chapulin_quic.zig` defines `ch_keylog`. A QUIC object can carry `CH_KEYLOG` and
cannot carry `CH_EXPORTER`, so `export_keying_material` answers `Unsupported` there. The object is
`TRUST=webpki` on this machine and `TRUST=raw-ecdsa` in the interop runner's image, whose
certificates carry no extended key usage.

**chapulin's QUIC mode has met another implementation.** `tools/quic_aioquic.sh` runs the UDP
endpoint against aioquic 1.3.0 over chapulin `9c903d8`, as a client and as a server, and both
directions move their files intact. Two chapulin defects found on the way were fixed in that
commit: a `ROLE=both` client derived the server's Initial keys, and a QUIC server's
EncryptedExtensions had no room for its transport parameters.

**A server's Retry token is chapulin's too, from `cc88adb`.** `ch_srv_quic_token_mint` and
`ch_srv_quic_token_check` bind a token to the client's address and an instant, and carry the two
connection IDs decision 55, as amended, has a Retry token carry. The UDP endpoint's `retry` option
sends a Retry through them, under a key drawn once per run. The `TRUST=webpki` QUIC object did not
build from `756ad91` until `992043f`, which fixed it and added that build to chapulin's `make
check`. The loopback, UDP and aioquic checks pass over `992043f`.

**The handshake is no longer on this list, and that is new.** `ROLE=server` with
`TRANSPORT=record` drives the server handshake with no callback at all: `ch_srv_record_in` takes
the peer's bytes and pushes each record to `cfg.srv.on_record_out`. That is what option C of
[issue 20](https://github.com/c4milo/colibri/issues/20) waited for — "a handshake whose callbacks
can say 'nothing yet'" — and it arrived as no callbacks rather than as patient ones. That issue's
recommendation of option A, a separate serial endpoint, was written against a chapulin where
`ch_srv_accept` was the only server driver. Whether to adopt the new one instead of amending
decision 46 is colibri's call and issue 20's to record.

## What the request reverses in chapulin

chapulin has since made four of these five reversals. The table keeps them because the reasoning
is what a reader needs, and the third column records the answer.

| chapulin decision | What colibri's request changes | chapulin's answer at `8a32aeb` |
|---|---|---|
| 6, no AES | The suite needs AES-128-GCM and an AES-128-ECB block. | Reversed, narrowly: an `AES` axis with `soft`, `hw` and `extern`, admitted for the three public QUIC keys alone under chapulin's INV-26, and never as a cipher suite. |
| 8 and 9, one pinned algorithm and RSA verify-only | A server signs, and QUIC needs both AES and ChaCha20. | Reversed: `rsa_sign.c` and `p256_sign.c` sign, and a server object carries both verifiers because `ch_srv_check` checks both identities at boot. |
| 20, a single blocking connection and a global DRBG | The handshake stops blocking, and sessions share no global state. | Half reversed: `TRANSPORT=record` unblocks the handshake and `RAND=extern` removes the global. The records after the handshake still call a blocking callback. |
| 28, four exported symbols | Filling two vtables needs more than four entry points. | Reversed: nine, fifteen or sixteen calls depending on the build, with `make lib-check` holding each build's list to exact equality. |
| The server non-goal | colibri's checks need a server. | Reversed: `ROLE=server` in three transports, and `ROLE=both` for one object that answers and dials. |

## How chapulin could add these

chapulin's decision 36 set the precedent this request follows: "a mode, not a change". Each item
above can be a build mode that chapulin's existing builds leave out.

That precedent held. Every landed item above arrived as a build value rather than a change to the
default build: `ROLE`, `TRANSPORT` and the `AES` axis each leave chapulin's firmware builds where
they were, and `make lint-trust-separation` checks that each value packages its own sources and no
other's.

For AES, the request suggested a host-side mode using hardware instructions only. chapulin took a
wider answer: `AES=soft` carries a table and rests its case on the keys being public, `AES=hw` uses
the compiler's intrinsics, and `AES=extern` takes a caller-supplied block. The choice is the
compiler's at build time; chapulin probes no CPU and asks no operating system, so colibri picks the
value when it builds.

## What colibri keeps, whatever chapulin answers

- colibri's library never imports chapulin, and this tree carries no production implementation of
  either vtable ([decisions 8 and 9](decisions.md#what-the-caller-supplies)).
- If chapulin declines an item, colibri's source does not change. The checks that need the item
  wait, and naming a different provider for `src/testing/` is a new "Ask before" under CLAUDE.md.
- Design §8 steps 0 to 4, 6, 8 and 11 need none of this, and step 4 ships cleartext h2.
