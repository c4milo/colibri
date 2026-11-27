# Decision 71: Decision 65's second early resend waits until one PTO has passed since the first

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-24. It amends entry 65.

A client whose PTO fires sends two probes at once (RFC 9002 §6.2.4), and each is an Initial
packet that brings the server no new CRYPTO bytes. Under entry 65 the server answered each
with an early resend, so both resends went out 6 ms apart, and in the QUIC Interop Runner's
handshake loss case one loss took both. The simulator cannot show this, because it delivers
every datagram due at one instant before either endpoint sends.

The PTO is RFC 9002 §6.2.1's period without backoff and without `max_ack_delay`, which
§6.2.1 leaves out at the Initial level. A client's next PTO fires about that long later, so
its next probe can spend the second resend.

The alternatives refused:
- Resends as entry 65 had them: one burst of loss can take both.
- A limit of one resend: RFC 9002 §6.2.3's example, which entry 65 already refused.
