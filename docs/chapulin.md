# The request to chapulin

Status: written 2026-09-16 and refreshed against chapulin's tree on 2026-09-18. Not sent yet;
sending it is the owner's (https://github.com/c4milo/colibri/issues/5). colibri never edits chapulin's repository, and
nothing here binds chapulin until chapulin's own decisions record it.

[Decision 10](decisions.md#what-the-caller-supplies) rules that chapulin provides all of colibri's
crypto. This document is the request that ruling needs: what colibri asks chapulin to add, why each
item is needed, and which of chapulin's recorded decisions each item reverses.

## How colibri would use chapulin

colibri defines two caller-supplied vtables and implements neither in its library
([decisions 8 and 9](decisions.md#what-the-caller-supplies)):

- `tls.Provider` runs the TLS 1.3 handshake. Its record mode serves h2, and its QUIC mode serves
  h3.
- `crypto.Suite` protects QUIC packets through `aead_seal`, `aead_open`, `header_protection_mask`,
  `hkdf_extract` and `hkdf_expand_label`.

chapulin would fill both. colibri's library source never imports chapulin, so the packaged library
links no TLS stack. `src/testing/` links chapulin, because every check from design §8 step 5 onward
needs a TLS 1.3 server that signs its certificate. A consumer that wants chapulin links it the same
way.

## What chapulin has today

Verified against chapulin's tree on 2026-09-18:

- Its public API is four calls, `ch_connect`, `ch_write`, `ch_read` and `ch_close` (`tls.h`), plus
  `ch_drbg_seed` and `ch_pubkey_from_pem`.
- It has no server role. The README lists it among the non-goals, `cfg.h:5` says the whole file
  configures a client, and `docs/quic.md` repeats it for the transport mode.
- Its I/O callbacks block, and `io.h` reads and writes a record at a time through them.
- Each connection has its own session, because `ch_connect` takes a `ch_tls` (`tls.h:14`), but the
  DRBG is global (`drbg.c`).
- It has no exporter: nothing in the tree implements RFC 8446 §7.5.
- It offers ALPN at the client: a caller lists `cfg.alpn_protocols` and reads which name the server
  chose from `session.alpn_selected` (RFC 7301 §3.1).
- It verifies certificates three ways: a pinned key, `TRUST=ca` against a CA it runs, and
  `TRUST=webpki` against the caller's anchors, with the X.509, name, signature-algorithm and
  validity machinery that mode needs.
- Its QUIC transport mode is declared and linked as fail-closed stubs: `quic.h` and its headers
  state the interface, and nothing implements it yet.
- Several internal pieces the request can build on already exist: `hkdf_extract` and
  `hkdf_expand_label` (`hkdf.h`), the `ks_*` key schedule (`keysched.h`), ChaCha20-Poly1305
  `aead_seal` and `aead_open` (`aead.h`), and `chacha20.c` with `chacha20.h`.

Two of these change what the request asks for. The client half of ALPN is done, so the ask is the
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
   (RFC 8446 §4.4.3) with a private key, and that path must not leak the key through timing.
3. **A non-blocking handshake that takes bytes in and returns bytes.** colibri owns no I/O, so
   it cannot call through a callback that blocks.
4. **Many sessions with no global state.** One process runs many connections at once, each with
   its own session.
5. **The exporter** (RFC 8446 §7.5).

### For h3: QUIC mode (RFC 9001)

Design §8 steps 9, 10, 12 and 13 wait for these six.

1. **Handshake bytes per encryption level, with no record layer** (RFC 9001 §4.1.3). QUIC carries
   handshake messages in CRYPTO frames, so the provider takes and returns unframed handshake bytes
   tagged with their encryption level.
2. **Per-level secrets returned** (RFC 9001 §4.1.4). When an encryption level becomes
   available, the provider returns that level's secret, AEAD and KDF, and colibri derives the
   packet and header protection keys from them.
3. **The `quic_transport_parameters` extension, codepoint 0x39** (RFC 9001 §8.2). colibri
   supplies the extension's bytes and reads the peer's; the provider carries them in the handshake.
4. **ALPN** (RFC 9001 §8.1), which QUIC requires of clients as well as servers.
5. **Alerts returned as values.** colibri maps each alert to the QUIC error code 0x0100 plus the
   AlertDescription (RFC 9001 §4.8) and closes the connection itself.
6. **No TLS KeyUpdate message** (RFC 9001 §6), **no EndOfEarlyData message** (RFC 9001 §8.3), and
   **no middlebox compatibility mode** (RFC 9001 §8.4).

### For `crypto.Suite`

Design §8 step 7's vectors wait for these five, and every QUIC connection needs them.

1. **AES-128-GCM**, for Initial packets (RFC 9001 §5) and the Retry integrity tag (RFC 9001
   §5.8).
2. **A single AES-128-ECB block**, for AES-based header protection (RFC 9001 §5.4.3).
3. **Raw ChaCha20**, for ChaCha20-based header protection (RFC 9001 §5.4.4).
4. **ChaCha20-Poly1305**, for Handshake and 1-RTT packets when TLS negotiates
   `TLS_CHACHA20_POLY1305_SHA256` (RFC 9001 §5.3).
5. **HKDF-SHA256**: HKDF-Extract and HKDF-Expand-Label, as the TLS 1.3 key schedule uses them
   (RFC 8446 §7.1). The Initial secrets use SHA-256 whatever suite TLS negotiates (RFC 9001 §5.2).

The first two are not optional. RFC 9001 fixes Initial packets (§5), the header protection used
before a suite is selected (§5.4.1) and the Retry tag (§5.8) to AES whatever suite TLS negotiates,
so no QUIC endpoint works without them ([decision 9](decisions.md#what-the-caller-supplies)).

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
