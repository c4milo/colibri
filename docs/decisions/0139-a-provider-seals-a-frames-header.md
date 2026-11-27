# Decision 139: A provider seals a frame's header and its data from two slices

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-30, for https://github.com/c4milo/colibri/issues/105, after chapulin
added `writeParts` (chapulin's decision 167, https://github.com/c4milo/chapulin/issues/212). It
amends decision 8, which fixes the vtable's list, and decision 138.
- `tls_provider.VTable` gains `writable_len(output_len)`, the most plaintext one seal writes
  into that many bytes, and `encrypt_parts(head, data, output)`. The second seals `head`
  and then `data` in the records `encrypt_record` writes for the two joined, whole or not
  at all, and returns the bytes written.
- The client's h2 sizes each DATA frame by `writable_len`, at most one record's plaintext,
  so a frame and its header fill one record. h2 writes the header into its own nine bytes,
  and the provider seals it with the frame's data from the program's memory.
- Over TLS, h2 and h11 copy into the output the start of a request's content that fills
  the record of its head, so a small content goes out in one record with its head.
- The test-only providers seal the two the same way: the null provider in `src/sim/` across
  records, and the plain providers of the tests in one record.

The alternatives refused:
- A seal that takes a list of slices of any length. h2 needs two, and the vtable stays
  narrow.
- `encrypt_parts` sealing what fits, as `encrypt_record` does. The frame's header already
  names its length, so the data must go out whole.
- The header of each frame in a TLS record of its own (decision 138).

Cost: every provider implements two more calls, a change for any program that implements
the vtable. A request's content up to one record is still copied over TLS, so its head does
not go out alone.
