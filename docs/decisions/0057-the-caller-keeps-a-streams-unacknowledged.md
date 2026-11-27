# Decision 57: The caller keeps a stream's unacknowledged bytes, and colibri reads them through a stream provider

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-22. It amends entry 56: one STREAM frame per packet and the flat range
on `Record` stand, and this entry replaces the rest.

Entry 56 said the bytes stay with the caller and that this needed no ruling, because `h2`'s
`write_data` already works that way. That precedent does not carry over. Under h2 the kernel
retransmits, so a byte colibri has consumed is no longer the caller's concern. Under QUIC
colibri retransmits (RFC 9000 §13.3), so the caller must keep each byte until the peer
acknowledges it, and colibri must be able to read it again. Entry 56 gave colibri no way to
read it and gave the caller no way to learn when it may let it go.

So the caller supplies a third vtable, the stream provider. Its one member,
`read(stream_id, offset, output)`, writes the stream's bytes from `offset` into `output` and
returns how many it wrote. colibri calls it only inside `send`, as it calls the suite's
`seal`, so it is not a callback at a time colibri chooses (design §4). New bytes and lost
bytes both arrive this way, straight into the packet scratch, so each byte is copied once
before sealing, as today. The caller tells colibri how far each stream's bytes reach and
whether the stream ends there, in a call that passes no bytes. The provider must answer the
same bytes for an offset every time (RFC 9000 §2.2: "The data at a given offset MUST NOT
change if it is sent multiple times"). colibri holds no copy to check this against, so it is
the provider's promise, as protecting a packet correctly is the suite's.

Loss resends exactly what was lost. Entry 56 rewound the stream to the lowest lost offset, as
the CRYPTO rule does. That is cheap for a handshake flight of a few kilobytes. For a stream it
resends every byte from the lost one to the send offset, up to 256 packets of them at
`sent_packets_max`, most of them already acknowledged. Instead, a lost packet's range goes
into a table of lost ranges that the stream table keeps, and `send` frames those before any
new bytes (§13.3: "Endpoints SHOULD prioritize retransmission of data over sending new
data"). New bytes wait while a lost range is owed, so the table needs `sent_packets_max`
ranges. A range split to fit a smaller packet (§13.3) is the exception, and the table joins
adjacent ranges of one stream to absorb it; a table that fills anyway closes the connection
with INTERNAL_ERROR.

Each range of a stream is then in exactly one place: in one packet in flight, in the lost
table, or acknowledged. So a count of acknowledged bytes per stream is exact in any order of
acknowledgment. The stream enters Data Recvd when the count reaches the final size and the
FIN is acknowledged (§3.1: "Once all stream data has been successfully acknowledged"), and
colibri reports it. From then on the caller may drop the stream's bytes. A reset ends the
obligation too (§13.3: "Once an endpoint sends a RESET_STREAM frame, no further STREAM frames
are needed"). Two rules keep the count exact. A probe (RFC 9002 §6.2.4) carries new bytes or
a PING, never a range already in flight. And recovery reports every acknowledged record,
where `recovery_sent.Removed` today reports only the largest.

Three things in entry 56 were wrong. `Record` must name a stream by its 62-bit identifier and
not by a slot index, because a slot is reused and a late acknowledgment would count toward
the next stream in it. A FIN sent alone is a range of length zero and is resent when lost
(§4.5: "A sender always communicates the final size of a stream to the receiver reliably").
And 56 priced the refused array of ranges over all three packet number spaces, but STREAM
frames travel in the application space alone (RFC 9000 §12.4, Table 3), so four ranges a
packet cost about 12 kilobytes a connection, not 72. One frame per packet still stands on
its other ground, that a cap on streams per packet is a limit invented for storage, and its
wire cost is still design §11's to measure.

The cost falls on the caller. It keeps each stream's bytes until Data Recvd or a reset. For
a small response that is the whole response, which a server holds anyway. For a file it is
nothing extra, because the provider reads the file. A caller that generates a long body it
cannot produce again must keep all of it until the stream ends, because colibri reports no
acknowledged prefix: that needs per-stream bookkeeping of acknowledged ranges, and it serves
bulk transfer, which decision 31 expects colibri to lose. When `h3` is the caller, it answers
for the bytes it writes itself, such as SETTINGS and frame headers; that is for `h3` to
settle when its send path is built. Design §4 gains a fifth item.

The alternatives refused. **colibri keeps the bytes** in a pool the caller places, copied in
at write. That keeps `h2`'s contract as it is, but it adds a copy per byte and 40 to 90
kilobytes a connection, and the pool's size caps the bytes in flight: 64 kilobytes is about
26 Mbit/s over a 20 ms round trip, the kind of cap decision 49 removed on the receive side.
**Keeping each packet's payload** until it is acknowledged, and reading lost frames back out
of it, is the queue of frames to replay that design §8 step 9e refused, and it holds 300
kilobytes a connection at the constants' worst case. **The caller keeps the bytes and learns
of a loss** by asking for each stream's send offset before every write. That is entry 56 made
explicit, and it puts resend logic in every caller, where colibri's simulator cannot test it.
