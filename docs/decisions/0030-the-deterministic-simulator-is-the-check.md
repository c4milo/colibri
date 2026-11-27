# Decision 30: The deterministic simulator is the check that the others cannot be

[All decisions](../decisions.md) · Section: [Correctness](../decisions.md#correctness)

Seeded connection state, flow control, loss, reordering and recovery, with byte-identical replay
across hosts and build modes as the pass condition. It is built before the protocol it drives
(CLAUDE.md non-negotiable 7), which is possible only because entries 6, 7 and 8 made I/O, time and
crypto the caller's.

The null crypto suite buys less than it appears to. It is
**not** what makes a seed replay: AES-GCM and ChaCha20-Poly1305 are pure functions of key,
nonce and plaintext, so a real suite replays just as deterministically. What it buys is that
the simulator needs no crypto dependency and costs no cipher time. It must therefore be
**size-faithful, not an identity function** — it appends a 16-byte tag and returns a 5-byte
mask exactly as a real suite would — because RFC 9001 §5.3's expansion feeds §5.4.2's sample
offset, the Length varint, RFC 9000 §14.1's 1200-byte minimum and the anti-amplification
count. A null suite that shortened packets would produce packet sizes QUIC never produces.
