# Decision 9: Packet protection is a *second* caller-supplied vtable, so the TLS provider never has to carry AES

[All decisions](../decisions.md) · Section: [What the caller supplies](../decisions.md#what-the-caller-supplies)

Ruled by the owner on 2026-09-16, and amended on 2026-09-19 by entry 48, which keeps the second
vtable and replaces its members. As first ruled, `crypto.Suite` supplied `aead_seal`, `aead_open`,
`header_protection_mask(hp_key, sample) -> [5]u8`, `hkdf_extract` and `hkdf_expand_label`, and
colibri derived every key and drove those five directly. Entry 48 makes the members whole-packet
operations and leaves every key with the suite. What follows is the reasoning of the first ruling.
Its account of what RFC 9001 fixes to AES still holds, and is now what a suite must carry rather
than what colibri must call.

The header-protection member is a mask function and not a block cipher on purpose. RFC 9001
§5.4.3 makes it AES in Electronic Codebook mode under a 128- or 256-bit key, and §5.4.4 makes
it the **raw ChaCha20 function** over a 4-byte counter and a 12-byte nonce taken from the
sample, encrypting five zero bytes. Those are not the same primitive and neither is an AEAD
call, so a vtable exposing one ECB block could not protect a ChaCha20 connection at all. The
mask function is the smallest member that covers both.

This is the answer to the AES problem. RFC 9001 requires AES
unconditionally, whatever suite TLS negotiates, in three places:
- Initial packets use `AEAD_AES_128_GCM` with keys derived from the client's Destination
  Connection ID (§5, and the Initial salt and labels in §5.2).
- Header protection before a suite is selected is AES-based, matching `AEAD_AES_128_GCM`
  (§5.4.1), and AES-based header protection is 128-bit AES in Electronic Codebook mode
  (§5.4.3).
- The Retry packet integrity tag is `AEAD_AES_128_GCM` under a hardcoded key and nonce (§5.8).

Beyond those three, the suite must also carry whatever TLS goes on to negotiate: RFC 9001 §5.3
makes the packet-protection AEAD the negotiated one and §5.4.1 makes the header-protection
algorithm follow it.

None of that is negotiated and none of it is optional, so a QUIC endpoint cannot be built
without AES-128-GCM, AES-128-ECB and HKDF-SHA256 — even one that negotiates
`TLS_CHACHA20_POLY1305_SHA256` for every packet after the Initial packets, which RFC 9001 §5.3
does permit. Two notes for the code: RFC 9001 never writes "MUST use AES-128-GCM", it states it
declaratively with no alternative offered, so cite §5 and §5.4.1 and do not write MUST; and
the header-protection key never changes across a key update (§5.4, §6.1), so it is installed
once per direction at 1-RTT and never touched again while `key` and `iv` rotate under
`"quic ku"`.

Splitting packet protection away from the TLS provider works because once QUIC takes over the
record layer (§3) the TLS stack does no bulk cipher work at all: the Initial keys, the AES header
protection and the Retry tag are all computed by the QUIC layer from a fixed salt, a hardcoded
key and the client's connection ID. A caller may therefore fill the TLS provider from a stack
with no AES and the suite from a separate AES source. Cost: two vtables where a smaller library
would have one, and a caller that must fill both. Rejected: one combined vtable, which would have
made every h3 consumer's TLS stack an AES stack.

The gain is narrower than it first looks, and entry 10 narrowed it again. h3 is not blocked on
the TLS provider **carrying** AES, but colibri's own tree does not use that freedom: entry 10 has
chapulin fill both vtables, so chapulin supplies the AES as well, and [the request](../chapulin.md)
reverses chapulin's decision 6 to get it. What the split still buys there is placement: the AES
is implemented behind `crypto.Suite`, where chapulin can hold it as a host-side mode of its own
rather than inside its TLS record layer. Nor is h3 independent of what the TLS stack
**negotiates**: RFC 9001 §5.3 and §5.4.1 make packet protection and header protection follow the
negotiated suite, so a TLS provider that offers only `TLS_CHACHA20_POLY1305_SHA256` obliges the
suite to carry ChaCha20-Poly1305 and raw ChaCha20 as well as the three mandatory members,
AES-128-GCM, AES-128-ECB and HKDF-SHA256. That is why the request asks chapulin's suite for all
five.

A caller that supplies a suite without AES-128-GCM, AES-128-ECB or HKDF-SHA256 is rejected at
init, not at the first Initial packet. A suite that lacks the AEAD or header-protection algorithm
TLS goes on to negotiate cannot be caught that early, because the suite is unknown until
EncryptedExtensions is decrypted; that case returns the same configuration error class at the
first Handshake packet, so the caller still sees a configuration error rather than a peer fault.
Since entry 48 colibri cannot see what a suite carries, so the rule is now about the one call
that shows it: a suite that refuses `install_initial_keys` is a configuration error
([invariant 25](../invariants.md#inv-25)).

Entry 94 amends this on 2026-09-26: colibri links chapulin, so a user no longer supplies this
vtable. It stays inside colibri, filled by chapulin and by the simulator's null suite. Since
decision 174, colibri reads chapulin as `stdx.crypto`.
