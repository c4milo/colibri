# The request to chapulin

Status: written 2026-09-16 and refreshed against chapulin's tree on 2026-09-22, at its commit
`8a32aeb`. Twelve of the fifteen items below have since landed in chapulin; each one says so, and
"What is left" names the three that have not. Not sent yet;
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
- It has no exporter. Nothing in the tree implements RFC 9846 §7.5.
- It has no key log. Nothing in the tree writes one.

Two of these reshape the request. The blocking-callback item is now half answered: the handshake
takes bytes and returns bytes in both roles, and only the records after it still need a callback
that cannot say "nothing yet". And the server role is built rather than declared, so the items
that asked for a server ask instead for the two things a built server still lacks, the exporter
and the key log.

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
   with that shape rather than retrofitted. `ch_read` and `ch_write` still call `cfg.recv` and
   `cfg.send`, which return 1..n bytes or -1 and block, so colibri cannot drive application
   records without a callback that has the bytes already. This is now the whole of the ask.
4. **Many sessions with no global state.** One process runs many connections at once, each with
   its own session. **Landed**: `RAND=extern` packages no generator, so the DRBG's global is not
   in the object and each connection holds its own `ch_tls`.
5. **The exporter** (RFC 9846 §7.5). **Open**: nothing in chapulin's tree implements it.

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

Three of these four have landed; the key log has not.

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
   nothing to log. **Open**, and the one ask that cuts against chapulin's grain rather than
   extending it: every other item here keeps secrets inside chapulin, and this one exists to let
   them out. Expect it to need chapulin's own decision record and a build axis, not a callback
   added to `ch_cfg`.

RFC 9001 fixes Initial packets (§5), the header protection used before a suite is selected
(§5.4.1) and the Retry tag (§5.8) to AES whatever suite TLS negotiates, so no QUIC endpoint works
without AES ([decision 9](decisions.md#what-the-caller-supplies)). chapulin's `AES` build axis
answers that.

## What is left

Three items. Two are absences with nothing in the tree behind them, and the third is a contract
that has to change rather than code that has to be written.

1. **The exporter** (RFC 9846 §7.5), for h2. chapulin derives the key schedule `keysched.h`
   already holds, so this is one more secret off it and one call to read it.
2. **A key log**, for the interop runner. See the note on it above: it is the one ask that runs
   against chapulin's own rule that secrets stay inside, so it needs a decision there before it
   needs code.
3. **Application records without a blocking callback.** `ch_read` and `ch_write` are the last
   place colibri would have to supply a callback that cannot say "nothing yet". Two shapes would
   close it: a result code `ch_read` treats as "call again, nothing consumed", or a bytes-in,
   bytes-out pair for application data mirroring `ch_record_in` and `ch_record_out`. The second
   matches what `TRANSPORT=record` already does for the handshake.

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
