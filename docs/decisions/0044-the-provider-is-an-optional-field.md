# Decision 44: The provider is an optional field on `h2.Connection`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-18. A connection with no provider is the cleartext prior-knowledge
endpoint step 4 built and h2spec checks, so `init` keeps working unchanged and the simulator's
cleartext check keeps the census it committed. A connection with one runs h2 over TLS.

The alternative lost is a second h2 type above `Connection` holding the provider and the record
buffers. It would keep `Connection` free of TLS, at the cost of a second entry point for every
caller and for both endpoints of design §9. The documents settled that h2 calls the vtable
(entry 8, design §3 and §4) and left the type open; this entry closes it.

One consequence is recorded here so it is not rediscovered: an ALPN mismatch cannot go through
`Connection.fail`. That queues a GOAWAY, and RFC 9113 §3.2 sends the connection preface only
after TLS completes, so there is no HTTP/2 connection to send one on. RFC 7301 §3.2 makes it
the provider's fatal `no_application_protocol` alert, value 120.
