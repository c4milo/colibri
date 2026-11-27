# Decision 131: A packet carries up to 16 STREAM frames, and a ring holds the ranges after its first

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-29. Amends decision 56, which asked to be revisited against a measured
number. Decision 57 stands: the caller keeps the bytes, and loss resends exactly what was lost.

The number is design §8 step 13i's lossy run. On a path of 50 ms with 1% loss each way, at
4,000 requests a second over 8 connections, colibri sent 6,586 packets on one connection
for 5,003 STREAM frames, with a median packet of 64 bytes. quic-go sent 2,716 packets for
5,022 frames, and 3.4 frames a packet over its 8 connections. The congestion window counts
each packet's header and AEAD tag, so under loss colibri carried about half the responses
in each round trip, and its p99 was 221 ms against quic-go's 121 ms.

The rulings:
1. An application-level packet carries up to `stream_frames_per_packet_max` STREAM frames,
   16. For quic-go's frames in that run, a cap of 16 sends 30% of the packets one frame a
   packet sends, and no cap 29%.
2. A packet's record keeps its first stream range in place, as decision 56 put it. A ring
   of `stream_ranges_max` ranges, 512, holds the others, in the order the packets went out.
   Every application-level record names the ring position its extra ranges start at, and
   how many it has, which may be none.
3. The ring keeps no liveness of its own. Its tail is the start position of the oldest
   application-level record the sent table still holds, and every entry from the tail to
   the head is in use. So the sent table is the one place that says which ranges are live,
   which is the risk decision 56 named for a second structure. INV-33 states it.
4. A packet whose frames would not fit in the ring carries one STREAM frame, as before.
   The Initial and Handshake levels carry no STREAM frame, so their records never use the
   ring.
5. The lost table holds `sent_packets_max + stream_ranges_max` ranges, 768, because every
   range in flight may be lost at once, and a table that cannot take one closes the
   connection. Before, it held one range for each packet in flight.

The cost, for each QUIC connection: the ring is 512 ranges of 24 bytes, about 12 KB. The lost
table grows by 512 ranges of 32 bytes, about 16 KB. Each of the 1,280 records grows by 8
bytes for the position and the count, about 10 KB. That is about 38 KB in all. The owner
chose 512 over 1,024, which costs about 66 KB: a full ring falls back to one frame a packet,
and only many small frames in flight at once fill it.

Alternatives that lost:
- Two or four ranges in every `Record`: about 31 KB or 92 KB for each connection, every space
  paying, for 59% or 40% of the packets.
- Keep one frame a packet, and give CUBIC (RFC 9438) the gap. CUBIC halves the window less,
  but each response would still cost colibri a packet's header and tag.
