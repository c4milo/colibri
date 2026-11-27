# Decision 56: One STREAM frame per packet, so a lost packet's stream bytes are one range

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-22, and amended the same day by entry 57, which replaces its rewind on
loss and its last paragraph.

RFC 9000 §13.3 has application data "retransmitted in new STREAM frames", which means a lost
packet must be able to say which stream bytes it carried. CRYPTO needed no ruling for this:
one packet carries at most one CRYPTO frame, so `recovery_sent.Record` holds one offset and
one length. A packet may carry STREAM frames for several streams, and that is what this
entry settles: it carries one.

So `Record` gains a stream identifier, an offset and a length, flat, as it holds the CRYPTO
pair. Nothing else is stored and no second structure has to be kept in step with the sent
packets. Loss rewinds the stream's send offset to the lowest lost one, which is what the
CRYPTO rule already does, and §13.3 permits sending more than was lost: "a receiver MUST
accept packets containing an outdated frame".

The cost is on the wire and it is the reason this is a ruling rather than an obvious choice.
A packet that could have carried three small streams' data carries one, so a connection
multiplexing many small responses sends more packets and pays more header overhead. Design
§11's benchmarks are where that shows, and entry 56 is meant to be revisited against a
measured number rather than argued again.

The alternatives refused. **A fixed array of ranges on `Record`** costs 36 kilobytes a
connection at two ranges and 72 at four, against `Record`'s 32 bytes and the 768 of them a
connection holds; it also caps how many streams a packet may carry, which is a protocol limit
invented for storage rather than read from an RFC. **A side table keyed by packet number**
costs about the same without the cap, and is a second structure that must stay in step with
the first — two places to get a retransmission wrong instead of one. And **tracking only
acknowledged ranges per stream, with no packet mapping**, cannot work at all: an ACK frame
names packet numbers and not stream offsets, so the mapping has to exist somewhere.

What this does not settle. The bytes themselves stay with the caller, which is
non-negotiable 1 and decision 35 and needs no entry of its own: `h2`'s `write_data` already
takes the caller's payload and answers how much it consumed, and QUIC only strengthens that
contract from "hold until consumed" to "hold until acknowledged". Which stream sends next is
the frame scheduler's, not this entry's.
