# Design §8 step 62: colibri sizes a TCP connection to what it uses, 2026-11-18

[Design §8, the build plan](../../design.md#8-build-plan)

[#137](https://github.com/c4milo/colibri/issues/137), its last item, and [decision
166](../../decisions/0166-a-program-sets-six-sizes-of.md) as amended.
- **The ruling, and its amendment the same day.** The owner first ruled six sizes a program
  sets through `server.Capacity`, at compile time. Its names, sub-step 62a, were proposed. Then
  the owner asked whether callers must size internal parts, and ruled that they need not:
  colibri sizes each part to what it uses, as long as performance is not affected. No name
  landed.
- **Where the bytes were.** After steps 60 and 61, an engine's TCP slot held 285,192 bytes,
  from `@sizeOf` on aarch64:

  | Part | Bytes | Sized by |
  | --- | ---: | --- |
  | h2's HPACK decoder | 31,032 | its table, 22,560, for `dynamic_table_capacity_max`; a scratch for one value, 8,192 |
  | h2's HPACK encoder | 23,752 | its table, 22,560 |
  | h2's field block | 49,200 | one representation, 31,721, for `field_value_len_max` in Huffman's worst case; the decoded section, 17,420 |
  | h2's streams | 10,744 | `concurrent_streams_max`, 128 |
  | chapulin's TLS session | 50,000 | chapulin's record state |
  | `plain_in` | 49,407 | h11's `head_len_max`, 32 KiB, which is longer than an h2 frame, and one TLS record |
  | `output` | 49,161 | h2's `send_block_len_max`, 32 KiB, and one frame |
  | bodies, sends and coding | 19,544 | 128 streams |

- **62b, HPACK's table, `f49faa4b`.** `dynamic_table_capacity_max` is 4,096, in place of
  16,384. colibri advertises a SETTINGS_HEADER_TABLE_SIZE of 4,096, and its encoder may use
  less than a peer allows (RFC 7541 §4.2), so the decoder never held more and the encoder
  compresses a response's fields with a smaller table. A TCP slot holds 34,560 bytes less.
  - `zig build hpack-vectors` skips `nghttp2-16384-4096`, the one directory whose encoder used
    a table of 16,384, and fails unless it skipped the directories its list names and decoded
    the others: 14 directories, 447 stories.
  - Mutations, 2 of 2 CAUGHT: the run skipping every directory, and skipping none.
  - The judge measured it against `89045d95` in two jobs, with the h11 inputs
    ([run 44442319011](https://github.com/c4milo/colibri/actions/runs/44442319011)). Every
    input was within the noise, and none lost.
- **62c, h11's request head, `69f12c06`.** A server reads a request head of
  `request_head_len_max`, 24,582 bytes: the leading empty line, the longest start line, the
  largest field section colibri accepts, and their CRLFs, so it refuses no request the section
  limit admits. A client reads a response head of `response_head_len_max`, 32,768, as before.
  `message_scan` takes each head's limit from its role. A server's TCP slot holds 8,184 bytes
  less, and `plaintext_in_len` is 41,221.
  - Mutations, 2 of 2 CAUGHT: each role reading the other's limit.
  - The judge measured it against `f49faa4b` in two jobs, with the h11 inputs
    ([run 44444946150](https://github.com/c4milo/colibri/actions/runs/44444946150)). Every
    input was within the noise, and none lost.
- **The sizes.** A TCP slot holds 242,448 bytes, against 285,192 before the step.
- **What stays.**
  - The 128 streams, because RFC 9113 §5.1.2 recommends at least 100 and fewer save little.
  - h2's frame size, whose floor is 16,384 (RFC 9113 §4.2), and one TLS record in `plain_in`.
  - The HPACK value scratch and the field block's representation: an 8 KiB value is
    colibri's limit, and a value past it ends the connection (RFC 7541 §7.4).
  - chapulin's session, which design §8 step 63 shrinks.
  - The TLS session and the plaintext buffer of a server that serves no TLS. The owner was not
    convinced by a `Capacity` field that drops them.
  - The response header block of two h2 frames, which sizes `output`, waits for the owner.
    One frame saves 16,384 bytes a connection, but colibri would then send no CONTINUATION,
    and each `send` would hold a third fewer bytes of a large body.
