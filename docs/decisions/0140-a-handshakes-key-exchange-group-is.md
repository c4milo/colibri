# Decision 140: A handshake's key-exchange group is reported beside its cipher suite

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-31, for cocuyo, which reports how each DNS connection is protected.
- `tls_provider.Negotiated` gains `group: u16`, the NamedGroup codepoint of the server's
  KeyShareEntry (RFC 9846 §4.3.8): 0x11EC for X25519MLKEM768, 0x001D for x25519 and 0x0017
  for secp256r1. `tls_provider.constants.protocol` names the three.
- A record session reports it through `negotiated_parameters`, as it reports the suite.
- `tls.quic.Client.negotiated()` returns the same `Negotiated` once the handshake completed.
  A program read the suite before through chapulin's session inside the client.
- The pool's `connected` event does not change. cocuyo reads the TLS sessions themselves.

The alternatives refused:
- A group of its own type, such as an enum of the three. A program compares codepoints, and
  the registry grows.
- `negotiated_parameters` in the QUIC vtable. colibri's QUIC connection never asks for it,
  and a provider would implement it for a program alone.

Cost: a program that builds a `Negotiated`, such as a test provider, sets one more field.
