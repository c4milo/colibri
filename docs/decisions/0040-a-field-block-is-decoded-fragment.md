# Decision 40: A field block is decoded fragment by fragment, and the connection holds one partial representation, never a whole block

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

RFC 9113 §4.3 delivers a field block as a HEADERS or PUSH_PROMISE frame and any number of
CONTINUATION frames, contiguous on the connection. Each fragment is fed to the HPACK decoder as it
arrives, which reads every representation the fragment completes and leaves the cursor at the first
it does not (hpack's block reader is all-or-nothing per representation for this reason). The
connection keeps that tail, at most one representation long, and prepends it to the next fragment.
The decoded lines go into one field section slot on the connection, and on END_HEADERS the
connection returns the section to the caller.

The alternative lost is reassembling the whole block before decoding, which needs storage of
`continuation_count_max` times `frame_size_max` bytes per connection, 512 KiB at the limits,
for a block that decodes to at most `field_section_size_max`. Cost: a representation that
spans two fragments is read twice, once to find it cut and once whole. Gain: the slot is one
representation plus one frame, invariant 14's byte count is a counter rather than a buffer,
and a peer that never sends END_HEADERS holds no more memory than one that does; the count of
CONTINUATION frames is still bounded by `continuation_count_max` (§10.5's limits).

**Amended by the owner on 2026-11-18, for design §8 step 61a**
([#137](https://github.com/c4milo/colibri/issues/137)). Each fragment is decoded where the
connection holds it, and only the representation it cuts is copied, with the bytes of the
next fragment that finish it. So the slot is one representation, `representation_len_max`
bytes, and no longer one representation plus one frame: 16,384 bytes less a connection,
and no copy of a block that arrives whole. The design above stands: the block is still
decoded fragment by fragment, a cut representation is still read twice, and the reader is
still all-or-nothing per representation. A reader that resumes inside a representation would
remove the buffer too, but it would replace that reader, and it was not chosen.
