# Decision 28: Interop against real stacks, both directions, is the bar for h3

[All decisions](../decisions.md) · Section: [Correctness](../decisions.md#correctness)

The QUIC Interop Runner's matrix is the standard, and joining it is a design constraint rather than
a later chore: an endpoint implements a Docker contract reading `ROLE`, `TESTCASE` and `REQUESTS`,
serving `/www` on port 443, writing to `/downloads`, emitting a keylog and qlog — and **exiting 127
for any test case it does not support**, which is what lets colibri join with handshake, transfer
and http3 alone and add the rest later without recording failures. Most transfers run HTTP/0.9 over
ALPN `hq-interop`, so that ALPN is a test-only entry point too. For h2 the equivalent is nghttp2,
curl, Go's `net/http2` and h2o, in both directions.
