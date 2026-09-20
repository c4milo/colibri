# The request to chapulin

Status: written 2026-09-16 and refreshed against chapulin's tree on 2026-09-19, at its commit
`3ff8517`. Not sent yet;
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

Verified against chapulin's tree on 2026-09-19:

- Its client API is four calls, `ch_connect`, `ch_write`, `ch_read` and `ch_close` (`tls.h`), plus
  `ch_drbg_seed` and `ch_pubkey_from_pem`. It works: TLS 1.3 with
  `TLS_CHACHA20_POLY1305_SHA256`, which [decision 45](decisions.md) admits.
- Its I/O callbacks block, and they cannot do otherwise. `io.c` reads a record through
  `cfg.recv` and turns any result of 0 or less into `CH_EIO`, after which the session is dead.
  A callback has no way to say "nothing yet", so the client cannot run under a loop that never
  blocks ([decision 46](decisions.md)).
- It has a server role as an interface and no more. `srv.h` declares `ch_srv_accept` and
  `ch_srv_check` under `ROLE=server`, and every function in `srv*.c` carries `CH_SRV_STUB` and
  fails closed. `srv.h` describes `ch_srv_accept` as running the whole handshake over "the same
  blocking I/O callbacks" the client uses.
- Each connection has its own session, because `ch_connect` takes a `ch_tls` (`tls.h`), but the
  DRBG is global (`drbg.c`).
- It has no exporter: nothing in the tree implements RFC 9846 §7.5.
- It offers ALPN at the client: a caller lists `cfg.alpn_protocols` and reads which name the server
  chose from `session.alpn_selected` (RFC 7301 §3.1). The server's half is declared in
  `srv_parser.h` and `srv_message.h`, and stubbed.
- It verifies certificates three ways: a pinned key, `TRUST=ca` against a CA it runs, and
  `TRUST=webpki` against the caller's anchors, with the X.509, name, signature-algorithm and
  validity machinery that mode needs.
- Its QUIC mode has its primitives and not its API. AES-128 with a build axis for the
  implementation, AES-GCM, the packet protection keys, the key update, and Initial and Retry
  protection are implemented (`quic_aes*.c`, `quic_gcm.c`, `quic_keys.c`, `quic_packet.c`,
  `quic_initial.c`, `quic_retry.c`). All fifteen `ch_quic_*` calls of `quic.h` carry
  `CH_QUIC_STUB` and fail closed.
- Several internal pieces the request can build on already exist: `hkdf_extract` and
  `hkdf_expand_label` (`hkdf.h`), the `ks_*` key schedule (`keysched.h`), ChaCha20-Poly1305
  `aead_seal` and `aead_open` (`aead.h`), and `chacha20.c` with `chacha20.h`.

Three of these change what the request asks for. The AES and the packet protection the
`crypto.Suite` items name now exist as primitives, so what is left there is the `ch_quic_*` API
over them. The client half of ALPN is done, so the ask is the
server half: selecting from the client's list and sending the fatal alert when nothing overlaps.
And `TRUST=webpki` brings certificate parsing and signature verification into the tree, which is
the reading half of what a server does with a chain; the writing half, signing CertificateVerify,
is what is still missing.

## What colibri asks for

### For h2: record mode

Design §8 step 5 waits for these five.

1. **ALPN at the server** (RFC 7301). chapulin offers the client half already. A server picks a
   name from the client's list, and one that shares no protocol ends the handshake with the fatal
   `no_application_protocol` alert, value 120 (RFC 7301 §3.2).
2. **A server role, with constant-time signing.** The server signs CertificateVerify
   (RFC 9846 §4.5.2) with a private key, and that path must not leak the key through timing.
3. **A record mode that takes bytes in and returns bytes, in both roles, for the handshake and
   for the records after it.** colibri owns no I/O, so it cannot call through a callback that
   blocks, and [decision 46](decisions.md) holds its test endpoints to the same rule. This is the
   shape `ch_quic_crypto_in` and `ch_quic_crypto_out` already give the QUIC mode. It is also why
   colibri's h2 client runs its interop in cleartext today: the client role works, and it cannot
   sit under a `poll` loop. The server role is stubs, so the cheapest time to give it this shape
   is before it is written.
4. **Many sessions with no global state.** One process runs many connections at once, each with
   its own session.
5. **The exporter** (RFC 9846 §7.5).

### For h3: QUIC mode (RFC 9001)

Design §8 steps 9, 10, 12 and 13 wait for these six.

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

Design §8 step 7's vectors wait for these, and every QUIC connection needs them. The first form
of this request asked for five primitives: AES-128-GCM, one AES-128-ECB block, raw ChaCha20,
ChaCha20-Poly1305 and HKDF-SHA256. chapulin has since built them and ruled that none is exported,
and [decision 48](decisions.md#what-the-caller-supplies) follows it. What colibri asks for now is
the API over them, which `quic.h` already declares.

1. **The fifteen `ch_quic_*` calls, working.** Each carries `CH_QUIC_STUB` and fails closed today.
   colibri's suite maps onto them one for one: `install_initial_keys` onto
   `ch_quic_initial_keys`, `seal` and `open` onto `ch_quic_seal` and `ch_quic_open`,
   `retry_tag_valid` onto `ch_quic_retry_ok`, `update_keys`, `key_phase` and
   `discard_previous_keys` onto `ch_quic_key_update`, `ch_quic_key_phase` and
   `ch_quic_drop_previous_keys`, and `discard_keys` onto `ch_quic_discard`.
2. **A server role in the QUIC mode.** `ch_quic_init` is a client's. colibri's h3 server, the
   server half of the interop endpoint and `secnetperf`'s peer need the other side: the server's
   Initial keys, which RFC 9001 §5.2 derives from the same connection ID under the other label,
   and the server's handshake.
3. **Writing the Retry Integrity Tag** (RFC 9001 §5.8). `ch_quic_retry_ok` checks one, which is
   the client's half. A server that sends a Retry packet must compute it.
4. **A key log** for the interop runner (design §9), written by chapulin, because colibri holds
   nothing to log.

RFC 9001 fixes Initial packets (§5), the header protection used before a suite is selected
(§5.4.1) and the Retry tag (§5.8) to AES whatever suite TLS negotiates, so no QUIC endpoint works
without AES ([decision 9](decisions.md#what-the-caller-supplies)). chapulin's `AES` build axis
answers that.

## What the request reverses in chapulin

| chapulin decision | What colibri's request changes |
|---|---|
| 6, no AES | The suite needs AES-128-GCM and an AES-128-ECB block. |
| 8 and 9, one pinned algorithm and RSA verify-only | A server signs, and QUIC needs both AES and ChaCha20. |
| 20, a single blocking connection and a global DRBG | The handshake stops blocking, and sessions share no global state. |
| 28, four exported symbols | Filling two vtables needs more than four entry points. |
| The server non-goal | colibri's checks need a server. |

## How chapulin could add these

chapulin's decision 36 set the precedent this request follows: "a mode, not a change". Each item
above can be a build mode that chapulin's existing builds leave out.

For AES, the request suggests a host-side mode that uses hardware AES instructions only. AES in
software that is constant time without lookup tables is the cost decision 6 avoided. Hardware AES
instructions are constant time without that cost, and colibri needs AES on hosts, where servers
and test endpoints run.

## What colibri keeps, whatever chapulin answers

- colibri's library never imports chapulin, and this tree carries no production implementation of
  either vtable ([decisions 8 and 9](decisions.md#what-the-caller-supplies)).
- If chapulin declines an item, colibri's source does not change. The checks that need the item
  wait, and naming a different provider for `src/testing/` is a new "Ask before" under CLAUDE.md.
- Design §8 steps 0 to 4, 6, 8 and 11 need none of this, and step 4 ships cleartext h2.
