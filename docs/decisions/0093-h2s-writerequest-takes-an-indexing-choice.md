# Decision 93: h2's `write_request` takes an indexing choice for each field line

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-26, for a caller that sends a DNS query in `:path` (RFC 8484) and must
keep it out of every table on the path (RFC 7541 §7.1.3).
- `Request.indexing` holds a choice for each pseudo-header field, and `write_request` takes a
  list beside `fields`, one choice a line, or empty for none. h3's `write_request` takes QPACK's
  choices the same way (entry 76).
- A choice is `without_indexing` or `never_indexed` (RFC 7541 §6.2.2, §6.2.3), and the default
  is `without_indexing`, which every request used before. A request inserts nothing. RFC 7541
  §6.2.1 inserts a line into the dynamic table as the block that carries it is decoded, so a
  request refused after its block was encoded would leave the peer's table short of an entry
  the encoder holds, where `write_request` promises that a refused request changes nothing.
  QPACK's inserts travel on the encoder stream instead, which is why h3 offers `may_insert`.

The alternatives refused:
- A choice for `:path` alone. It serves the DNS query, but not `authorization` or `cookie`.
- Offering `incremental` too. The encoder would have to take back a refused block's inserts,
  which means copying the dynamic table before every request.
