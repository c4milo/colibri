# Decision 166: A program sets six sizes of a TCP connection through `server.Capacity`, at compile time, from v0.19.0, as ruled first; amended the same day to sizes colibri sets itself

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-18, for the last item of
[#137](https://github.com/c4milo/colibri/issues/137) (design §8 step 62).
- The sizes, each with today's value as its default:
  - HPACK's encoder table, from 16,384 bytes down to 0, which colibri chooses (RFC 7541
    §4.2).
  - HPACK's decoder table, from 16,384 down to 4,096, which a peer may use before it
    acknowledges a smaller SETTINGS_HEADER_TABLE_SIZE (RFC 9113 §6.5.2).
  - The longest header value, 8,192, and the header section, 16,384 (RFC 9110 §5.4 sets no
    limit).
  - The response header block, 32,768, which sizes `output`; the TLS flight keeps `output`
    at 20,480 bytes at least.
  - h11's head, 32,768; RFC 9112 §3 recommends request lines of 8,000 bytes at least.
- The types that hold them take them as type parameters: the server's TCP connection,
  `h2.Connection`, HPACK's decoder and encoder, and `h11.Connection`. A program that names
  one of those types directly changes its code.
- A peer past a size gets what it gets today past the fixed limit. Past the value size, h2
  ends the connection with COMPRESSION_ERROR, because HPACK refuses the string (RFC 7541
  §7.4).
- It goes into v0.19.0 beside 58b (decision 165), so names break once. The judge measures
  it at the default sizes, where no input may lose.

The alternatives refused:
- Buffers that the engine places and sizes from `server.Capacity`, as the slot tables are.
  Each read on the per-frame path then checks a length the compiler no longer knows.
- The stream count as a size. RFC 9113 §5.1.2 recommends at least 100 streams, and 100 in
  place of 128 saves about 6,600 bytes a connection.
- A release of its own before 58b, which breaks names twice.
- Fixed sizes, as before. connect-zig's OTLP sink then holds about 384 KB a connection
  after steps 60 and 61, where its counterpart on connect-rust holds about 100 KB.

**Amended by the owner on 2026-11-18, the same day.** The owner asked whether callers must
size colibri's internal parts, and ruled that they need not: colibri sizes each part to what
it uses, with no `Capacity` field and no type parameter, as long as performance is not
affected. The names of design §8 step 62a were withdrawn before any code landed.
- HPACK's dynamic table holds 4,096 bytes, the SETTINGS_HEADER_TABLE_SIZE colibri
  advertises and the most its encoder uses (RFC 7541 §4.2), in place of 16,384. This amends
  the ruling of 2026-09-16 that every directory of http2jp/hpack-test-case decodes: the run
  skips `nghttp2-16384-4096`, whose encoder used a table of 16,384.
- A server reads a request head of `request_head_len_max`, 24,582 bytes: the leading empty
  line, the longest start line, the largest field section colibri accepts, and their CRLFs.
  A client reads a response head of `response_head_len_max`, 32,768, as before.
- Each change landed only after the judge found no input losing.
- The alternatives refused:
  - The six fields of the first ruling: a program then sizes parts it does not see.
  - An h11 request head of 16,384. It refuses a request whose field section the section
    limit admits, such as a long target with large fields.
  - A `Capacity` field that drops the TLS session and the plaintext buffer from a server
    that serves no TLS, about 35% of a TCP slot. The owner was not convinced.
- The response header block of one h2 frame, in place of two, waits for the owner: it saves
  16,384 bytes a connection, colibri would then send no CONTINUATION, and each `send`
  holds a third fewer bytes of a large body.

**Amended by the owner on 2026-11-19, and refused by the judge.** The owner asked to try a
server output sized for one h2 frame of header block in place of two, and then, after the
trial, to floor a DATA frame that the room cuts short (design §8 step 65).
- The note above was wrong in part. The server bounds a response's header section by its
  count of lines and by the output alone, not by `field_section_size_max`, so a block can
  pass one frame, and colibri sends CONTINUATION for it.
- The trial held a HEADERS frame and a DATA frame in the output, 32,786 bytes in place of
  49,161, and cut no DATA frame at the room below `data_frame_len_min`. Without that floor,
  a full output went out in DATA frames of a few hundred bytes.
- The judge refused it, in run 44541453452: a response of 256 KiB, `h2-large-many` (design §8
  step 13n), lost in both jobs, at 1.1164 and 1.1129 of the base's instructions. Its user
  instructions went from 119,077 to 146,980 a request: each response took more passes.
- So the output stays 49,161 bytes, and no floor on the room lands. The branch
  `one-frame-65b` keeps the trial.
