# Decision 85: The QUIC object is built `SUITE=aesgcm`, and every chapulin endpoint checks the object against the headers before it starts

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24, relayed by the chapulin session, for design §8 step 12's h3spec
check.

RFC 9846 §9.1 makes TLS_AES_128_GCM_SHA256 mandatory to implement, and h3spec's client offers
AES suites alone. chapulin's `SUITE=aesgcm` adds TLS_AES_128_GCM_SHA256 and
TLS_AES_256_GCM_SHA384 beside TLS_CHACHA20_POLY1305_SHA256, over QUIC as over TLS. It builds
only with `AES=hw` and `-DCH_NATIVE_AES`, the builder's statement that the part's AES
instructions run in constant time (chapulin's INV-26).
- `build/modules.zig` reads the QUIC headers under `CH_AES_HW` and `CH_SUITE_AES_GCM`, so the
  QUIC object must be the suite build. CLAUDE.md's QUIC check line names it.
- An object built with other defines exports the same calls and links, and then runs with the
  wrong struct sizes. So each endpoint calls chapulin's `ch_build_matches` before any other
  chapulin call and refuses a mismatch: `chapulin.check_build` for the TLS roles and
  `chapulin_quic_c.check_build` for QUIC.
- The suite adapter reports chapulin's `CH_EINVAL` at a level whose keys it holds as RFC 9001
  §6.6's confidentiality limit, at any level. An AES-GCM key set meets it at 2^23 packets, and
  the connection answers with a key update at 1-RTT, or with AEAD_LIMIT_REACHED where no
  update is possible.

The alternative refused: a build option naming the suite, so a ChaCha20-only object still
links. It keeps two object shapes alive, and only one of them can run h3spec.
