# Decision 132: h2 puts a response's field lines into HPACK's dynamic table, and empties both tables after a block it abandoned

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-29, for [#113](https://github.com/c4milo/colibri/issues/113). It
leaves decision 93 as it is, for requests.

colibri wrote every response line with `without_indexing`, so each response repeated its
lines whole. On a laptop's Linux VM a capture of h2 to colibri's test-only server and to axum
gave a field block of 26 bytes a response from colibri and 7 from axum, whose encoder indexes
`content-type` and `date` once and then sends each as one byte. The reason was decision 93's:
a line inserts into the encoder's table as the block is written, and into the peer's only as
the peer decodes the block. So a block the caller abandons after an insert leaves the two
tables apart, and `write_in_place` abandons one each time a block does not fit its room.

The rulings:
1. `write_response` writes `:status` and each field line with incremental indexing (RFC 7541
   §6.2.1). Trailers and requests keep `without_indexing`.
2. The encoder notes that the open block inserted. When the next block begins and no
   `commit_block` came between, that block opens with a size update to 0, which empties the
   peer's table, and one to the capacity, and the encoder's mirror empties with it (RFC 7541
   §4.2, §6.3).
3. A line both tables hold is an index and inserts nothing. So after a connection's first
   responses, an abandoned block rarely inserts, and the tables rarely empty.

The price, counted with callgrind on a laptop's Linux VM over h2 in cleartext: at most 325
fewer instructions a request, from 12,544 to 12,219, and 19 fewer bytes a response.

Alternatives that lost:
- Keep `without_indexing`. Each response then pays the 19 bytes and the Huffman coding of
  its lines.
- Copy the table before each block, to put it back after an abandoned one. Decision 93
  refused it for requests: the table is up to 16,384 bytes and 512 records.
- Hold a block's inserts until `commit_block`. Each later index in the block must then count
  the inserts still held, and an entry they would evict must count as absent: more code on
  each line, for a case that rarely comes.
