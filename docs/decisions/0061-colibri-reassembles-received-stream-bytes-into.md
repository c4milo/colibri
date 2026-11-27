# Decision 61: colibri reassembles received stream bytes into a pool the caller places

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-23. It settles [#41](https://github.com/c4milo/colibri/issues/41) and
[#42](https://github.com/c4milo/colibri/issues/42).

colibri checked every STREAM frame against RFC 9000's flow control, final size and state
rules and kept none of the bytes, so no caller could read a stream. And decision 49's
window growth had no cap, so no window grew.

So colibri reassembles. A connection's received bytes go into one pool the caller places,
`stream_incoming.Pool(capacity)`, in fixed-size blocks any stream may take. The application
reads a stream's bytes in order, and what it reads is what gives the peer new credit (RFC
9000 §4.1). One pool is enough for every stream: the bytes waiting across all streams can
never pass the connection window, so the pool is sized by it plus two blocks per stream for
the ends of each stream's span. colibri never advertises more than it can hold, so the pool's
capacity is decision 49's cap, for the connection and for each stream alike. The default
capacity is 1 MiB, a named limit: about 80 Mbit/s per connection at a 100 ms round trip. A
caller that wants more places a larger pool. A connection given no pool reads no stream: it
checks STREAM frames and keeps nothing, and its windows stay where they start.

Three alternatives were refused. Handing each frame's bytes to the caller puts reassembly
in every caller, which is decision 60's reasoning again. A buffer per stream, sized to that
stream's largest window, commits 128 of them per connection. Handing in-order bytes out as
they arrive and keeping only what sits past a gap needs less pool, but makes the caller take
bytes whenever they come rather than when it reads.

Amended by the owner on 2026-10-17, after a review of the server's defences (design §8 step
20e): the pool finds a block through an index, not by a walk of its stream's list. Each
STREAM frame walked the list from the stream's first block. A peer that leaves the first
bytes out and sends one byte into each block of its window made each frame walk the whole
list: up to 1,026 blocks at the default pool of 1 MiB. RFC 9000 §21.7 asks for a mitigation
of this "large and inefficient data structure".
- The pool holds a bucket for each block. A block lies in the bucket its stream and number
  choose, chained through the field that links the free blocks.
- A stream's live blocks lie inside its window, which spans fewer numbers than there are
  buckets, so a chain holds at most one block of each stream. A lookup takes at most one
  probe for each stream that holds blocks.
- A stream keeps a count of its blocks in place of its first block. A stream reset with
  bytes unread gives them back by a walk of every bucket, which is rare.

The pool grows by two bytes a block, 2,560 bytes at the default capacity. The alternatives
refused: a pointer to each stream's last block, which speeds honest traffic but leaves a
write into the middle of a list at the full walk; a cap on the blocks past a gap, which an
honest peer with heavy loss and a large window could reach; and the cost left as it was.
