# Decision 22: HTTP datagrams: no, at the QUIC layer

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

`max_datagram_frame_size` is transport parameter 0x20 with default 0, and 0 means the endpoint does
not support DATAGRAM frames (RFC 9221 §3). Omit it and a conformant peer will not send one. The only
wire obligation is the error case, and it is easy to get wrong: receiving a DATAGRAM frame without
having advertised support must terminate the connection with `PROTOCOL_VIOLATION` (§3), and colibri
must recognise **both** codepoints, 0x30 and 0x31, because the low bit is the LEN flag (§4). A
dispatcher that knows only 0x30 lets 0x31 fall through as an unknown frame type and produces the
wrong error.

There is also a design-fit reason. RFC 9221 §5.3 says DATAGRAM frames carry no explicit flow
control signalling and do not contribute to any per-flow or connection-wide data limit. They
are the one data carrier in QUIC with no backpressure, so colibri would have to own a drop
policy, which is an application decision and not colibri's.

Scope note: this covers the QUIC extension only. The HTTP-layer datagram binding is a separate
document colibri has not read, and this entry makes no claim about it.
