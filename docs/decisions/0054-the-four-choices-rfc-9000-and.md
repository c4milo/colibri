# Decision 54: The four choices RFC 9000 and RFC 9001 leave to a sender, ruled together

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-20, before the send path was written, because each one changes what a
packet costs and all four would otherwise be settled by whoever typed first.

**RFC 9001 §5.4.2's four-byte floor is met by widening the packet number, not by PADDING.**
Header protection samples four bytes, so a packet's Packet Number field and payload together
must reach that; a packet carrying only PING or HANDSHAKE_DONE under a one-byte packet number
falls short. §17.1 permits any width that represents the range, so widening is always legal.
The alternative it beat is writing PADDING, which most implementations do and which is
simpler. It loses because RFC 9002 §2 counts a packet in flight when it is ack-eliciting "or
contains a PADDING frame": padding a bare probe or keep-alive spends congestion window on the
packets least able to afford it, and widening the number spends none.

**RFC 9000 §14.1's expansion to 1,200 bytes lands on the last packet of the datagram.** §14.1
permits "adding PADDING frames to the Initial packet or ... coalescing the Initial packet" and
does not say which. Padding the Initial is what §14.1 names first; it loses because the Initial
then counts about 1,200 bytes in flight, so a lost first flight costs the whole datagram
against the congestion window rather than the Initial's own contents. A trailing PADDING-only
packet was also refused: it accounts most cleanly and spends a packet number for nothing,
which invariant 17 makes irreversible.

**The frame scratch is a comptime parameter defaulting to 1,200 bytes.** `crypto.Sealing`
forbids the payload overlapping the output, so the frames cannot be framed at their final
offset and a separate buffer is forced. Decision 35 makes the caller place it, so its size is
storage the caller commits per connection. `datagram_len_max` was refused at 64 KiB each; a
flat `datagram_len_min` was refused because it would forgo a larger path MTU permanently. The
comptime parameter follows `recovery_sent`, which already takes its capacity that way.

**`token_len_max` is 256 bytes.** RFC 9000 bounds an Initial's Token field only by the packet
carrying it (§17.2.2, §19.7), so there is no number to derive. 256 comfortably holds the
authenticated, address-bound, expiring token §8.1.1 describes. It is a judgement and the
constant says so: 128 risks refusing a Retry from a server that mints something larger, and
512 buys headroom at the cost of a larger fixed header buffer on every connection.
