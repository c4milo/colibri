# Decision 48: The suite holds every key and protects every packet, and colibri holds none

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-19. It amends entries 8 and 9. `crypto.Suite` stays the second
caller-supplied vtable, and its members become whole-packet operations at one of the three
encryption levels colibri uses (RFC 9001 §4.1.4, less 0-RTT, which entry 20 rules out):
`install_initial_keys`, `keys_available`, `seal`, `open`, `retry_tag_valid`, `retry_tag_write`,
`update_keys`, `key_phase`, `discard_previous_keys` and `discard_keys`. Entry 55 adds
`retry_token_write` and `retry_token_valid` for the same reason, which makes twelve. No member takes
or returns a key, a secret or an IV. The secrets RFC 9001 §4.1.4 has TLS produce go from the
provider to the suite inside the caller's code, so entry 8's QUIC mode loses `on_secret` and
`hkdf_expand_label`.

`open` removes header protection, recovers the packet number and removes packet protection
in one call. RFC 9001 §9.5 requires the three applied together, with no timing or other side
channel between them, and only the code that holds the key can promise that. So the packet
number is an output of `open`, and colibri passes what RFC 9000 Appendix A.3 reads: the
largest packet number it has processed in that space. `seal` takes a packet colibri has
framed whole: the header with the packet number encoded, the Key Phase bit taken from
`key_phase`, and a payload long enough for the sample of §5.4.2.

What stays colibri's is every rule about *when*. It discards the Initial and Handshake keys
(§4.9), starts a key update only once the handshake is confirmed and the current phase has
been acknowledged (§6.1), answers a peer's update before it sends the acknowledgment (§6.2),
drops the previous receive keys about three PTOs later (§6.5), reads the Reserved Bits once
`open` returns (RFC 9000 §17.2), and sends KEY_UPDATE_ERROR and AEAD_LIMIT_REACHED, which a
suite reports as values and never as frames.

The ruling follows chapulin's, which its `docs/quic.md` records under "chapulin owns packet
protection at every level". Entry 10 has chapulin fill both vtables, and chapulin exports no
key: its `quic.h` offers `ch_quic_seal` and `ch_quic_open` and no primitive. Its reasons are
colibri's as well. §9.5's constant-time MUST lands in code with the tooling to prove it, and
colibri has none. No live traffic secret leaves the object that derived it. The six QUIC
labels are written once.

Cost. The null suite of design §10 must model keys, levels, phases and discards, because
colibri's connection logic will be checked against it. RFC 9001 Appendix A's sample packets
now check a provider through the vtable, so that half of step 7's check needs chapulin's
`ch_quic_*` calls, which fail closed today. A caller whose TLS stack hands out secrets
writes `seal` and `open` around its own AEAD, which is more work than five primitives were.
The interop runner's keylog (design §9) must come from the provider, because colibri has
nothing to log. Gain: colibri holds no secret in either mode
([invariant 23](../invariants.md#inv-23)).

Two alternatives lost. Entry 9's five primitives need the secrets out of the provider, which
chapulin refuses, and would put §9.5's obligation in a library with no way to check it. One
combined vtable lost again, for entry 9's reason and a new one: with protection apart from
the handshake, the QUIC simulator of step 8 runs over a null suite before any handshake
exists.

Entry 94 amends this on 2026-09-26: chapulin fills the suite inside the library. Every rule
above stands, and colibri still holds no key. Since decision 174, colibri reads chapulin as
`stdx.crypto`.
