# Decision 10: chapulin provides all of colibri's crypto, through colibri's two vtables

[All decisions](../decisions.md) · Section: [What the caller supplies](../decisions.md#what-the-caller-supplies)

Ruled by the owner on 2026-09-16. chapulin fills both `tls.Provider` (entry 8) and `crypto.Suite`
(entry 9). colibri's library source never imports chapulin, so the packaged library still links no
TLS stack and this tree still carries no production implementation of either vtable. `src/testing/`
links chapulin. That answers the dependency question design §8 step 5 raised under CLAUDE.md's "Ask
before": the checks from step 5 onward get their TLS 1.3 server, and its certificate signing, from
chapulin.

The request is [docs/chapulin.md](../chapulin.md). The owner sends it, and this repository
never edits chapulin's. It asks for a server role, ALPN, a non-blocking handshake with no
global state, the exporter, a QUIC mode and host-side AES, and it names what each item
reverses: chapulin's decisions 6, 8, 9, 20 and 28, and its server non-goal. chapulin's decision
36, "a mode, not a change", is the shape it follows.

Cost: every colibri check that needs TLS or real packet protection now waits on work in another
repository, and that work reverses five of chapulin's recorded decisions. Gain: one crypto
source for colibri's whole tree, argued under one charter, with no third-party stack in
`src/testing/`. Two alternatives lost. The ask this entry used to make, ALPN and nothing else,
left every check from step 5 onward with no TLS server at all. A different test-only TLS stack
would have added a dependency whose charter nobody here argued, and its interop results would
measure that stack rather than chapulin.

If chapulin declines an item, colibri's source does not change. The vtables already have zero
implementations in this tree, and steps 0 to 4, 6, 8 and 11 need no crypto at all: step 4
ships prior-knowledge cleartext h2, so the whole h2 core is built and tested with no TLS. Only
the checks that need the declined item wait, and naming a different provider for
`src/testing/` would be a new "Ask before".

Entry 94 amends this on 2026-09-26: the library itself now links chapulin, pinned as a
package, and the adapters leave `src/testing/` for the library. Decision 174 moved the pin
into stdx: colibri reads chapulin as `stdx.crypto`.
