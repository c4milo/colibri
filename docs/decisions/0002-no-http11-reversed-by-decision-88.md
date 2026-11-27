# Decision 2: No HTTP/1.1. Reversed by decision 88 on 2026-09-24: colibri builds h11

[All decisions](../decisions.md) · Section: [Scope and shape](../decisions.md#scope-and-shape)

Cost: colibri cannot serve or speak to an h1 peer, and a consumer that needs one keeps whatever it
already has. Gain: the whole of RFC 9112 stays out — the eight-step message-body-length precedence
of §6.3, the chunked decoder of §7.1, `obs-fold` unfolding (§5.2), the whitespace-before-colon
rejection of §5.1, the connection-persistence state machine of §9.3, and the request-smuggling
surface that §11.2 exists to narrow. None of that machinery is reused by h2 or h3, where framing is
the transport's job and `Content-Length` degrades to a consistency check (RFC 9113 §8.1.1, RFC 9114
§4.1.2). It is a second, structurally unrelated parser for one version.

h2c *upgrade* is also out, and for a different reason: RFC 9113 §3.1 says the `h2c` token and the
Upgrade mechanism "was never widely deployed and is deprecated". Prior-knowledge cleartext h2
stays, and entry 8 explains why colibri depends on it rather than offering it as a convenience.

Entry 88 amends this entry: colibri builds HTTP/1.1 as h11, client and server. The h2c upgrade
stays out.
