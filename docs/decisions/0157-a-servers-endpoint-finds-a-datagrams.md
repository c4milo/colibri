# Decision 157: A server's endpoint finds a datagram's connection from its Destination Connection ID in one table entry

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-06 (design §8 step 29d.17). One UDP socket carries every QUIC
connection of a `server.Endpoint`. RFC 9000 §5.2 matches a packet to its connection by its
Destination Connection ID (DCID), because the peer's address can change (§9). Before this decision,
`slot_for` asked each live connection whether it issued the DCID. A probe under h3-many on main
779f7df0 counted 8.5 connections checked for each lookup at 16 connections, and 32.3 at 64.
1. `server.Endpoint` holds a table of the connection IDs its connections issued. The table
   has `2 × quic_connections × connection_ids_max` entries, rounded up to a power of two.
   Each entry holds one ID and its slot, or nothing.
2. The low bits of an ID's first two bytes name its entry. The server makes this true when
   it issues the ID:
   1. It draws `quic_id_len` random bytes, as before (§5.1).
   2. When the entry those bits name is in use, it moves to the next free entry.
   3. It writes the index of that entry into the bits, and puts the ID in the entry.
3. The table is exact. The server frees a slot's entries when the slot is released. After
   each datagram a connection takes, the server compares the connection's count of active
   IDs, `local_ids.len`, with the count of its entries. A lower count means the peer retired
   an ID (§5.1.2), and the server frees each entry whose ID is no longer active. `quic` does
   not change, and no public name changes.
4. A short-header packet reads one entry. When the entry holds the DCID and its connection is
   not closed, the packet goes to that slot. Otherwise no connection takes it, with no scan:
   §7.2 has the client use the server's ID once the server's first Initial arrives, and a
   short header is sent only after that.
5. A long-header packet tries the table first. On a miss it scans as before, because the
   client chose its first DCID (§7.2), and the server drew a Retry's ID before a connection
   existed (§17.2.5.1).
6. The server issues IDs in two places, `Connections.start` and `issue_spare_ids`, and both
   go through the table.

Why it holds:
- A lookup reads one entry and compares one ID, whatever the number of connections.
- The table never fills, because it has twice as many entries as the IDs that the
  connections can hold.
- §5.1 forbids an ID that "can be used by an external observer to correlate" it with other
  IDs of the same connection. The index bits name an entry that the draw chose at random,
  and each ID of one connection names a different entry. The slot never appears in an ID.
- A short-header packet with an unknown DCID costs one entry, not a scan of every
  connection, so a flood of such packets is cheaper to drop.
- The draws come from the source that the program passes, so one seed still replays.

The alternatives it beat:
- The scan: its cost is linear in the number of connections.
- The last slot first, the owner's first choice of 2026-11-06. The probe counted 3,400
  lookups under h3-many, and the last slot matched 1.7% of them.
- A hash table from ID to slot: O(1) on average, with a chain to walk on a collision.
- The slot written into each ID: an observer reads the slot, which links a connection's IDs
  (§9.5). An encrypted slot needs a key, and colibri holds no key (non-negotiable 2).
- A table that confirms each hit with `addressed_by`, the first draft: about 120 more
  instructions a lookup, because the table did not learn of a retired ID.
- A call from `quic` that reports each retired ID, the owner's choice before the code: the
  count the server already reads tells it the same, with no new public name.
