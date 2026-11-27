# Design §8 step 15c: the `gzip` and `deflate` codings

[Design §8, the build plan](../../design.md#8-build-plan)

stdx's decoders from a pool the caller owns, under decision 91. It follows
https://github.com/c4milo/stdx/issues/1. **Check:** step 15b's simulator check with coded bodies,
the corrupt and refused verdicts each with a case, and mutations.

**The codings, 2026-09-26.** `src/h11/coding.zig` holds the pool and one message's decoding, and
the connection decodes a body carrying `gzip` or `deflate` into the buffer the caller passes to
`receive` ([decision 98](../../decisions/0098-h11-decodes-a-coded-body-into.md)).
- A server with no pool answers a coded request 501 (RFC 9112 §6.1). With one, it answers 503
  when every decoder is taken (RFC 9110 §15.6.4), 400 when the body is corrupt or when bytes
  follow a zlib stream inside the body, and 501 for a feature stdx refuses, such as a zlib preset
  dictionary. Every refusal gives the decoder back, and so does a server that answers before the
  body ends and closes (RFC 9112 §9.3).
- A client with a pool sends `TE: gzip, deflate` with `Connection: TE` (RFC 9112 §7.4). One
  without refuses a response that uses either coding, because with no TE only chunked is
  acceptable. A coded response that runs until the close ended only if its stream did.
- A chunked read that decoded only part of its data gives the rest back
  (`chunked.Decoder.give_back`), so the next call returns it again.
- stdx sorts its refusals into corrupt and unsupported, and h11 keeps them apart. A zlib window
  size RFC 1950 does not allow is corrupt in stdx, so it is a 400, not the 501 decision 91 first
  named for it.
- The test-only server gives its cleartext h11 connections a pool of
  `h11_decoders_per_worker` per worker and a decoded buffer of `h11_decoded_len`, so `--echo`
  returns a coded request decoded. Over TLS its sessions have none, and a coded request is a 501.

What was checked, on macOS arm64 with Zig 0.16.0:
- `zig build test` passes. `src/h11/coding.zig` and `connection_coding_test.zig` read gzip and
  deflate in any pieces, into rooms of 1, 7 and 11 bytes and one that holds the whole body,
  with two gzip members, and with each refusal above.
- `http-server --h11 --echo` returned, decoded, a two-member gzip body and a deflate body that
  Python's `gzip` and `zlib` modules coded, which are encoders other than stdx's. It answered a
  wrong CRC-32 with 400 and a preset dictionary with 501.
- Mutations, each against `zig build test-h11`, all **CAUGHT**: undecoded bytes not given back,
  every byte of a run counted as consumed, a body ending mid-stream not checked, bytes after a
  zlib stream starting another, a second gzip member refused, a refused feature called corrupt,
  a stream cut short accepted, the free list not advanced, the stream's end not noted, 503
  answered as 400, a refused feature answered 400, a server or a client taking no decoder, an
  early close keeping its decoder, TE left out of the head, a close-delimited body whole without
  its stream, a failure keeping its decoder, and a given-back chunk keeping its `data_end` state.
  The TE mutation first did not compile and was rewritten so it did.

**The check, 2026-09-26.** Step 15b's exchange runs a colibri client against a colibri server,
and no colibri writer codes a body (decision 91), so the exchange cannot carry a coded one.
`src/sim/h11_coding_check.zig` is the check instead:
- The plan (`h11_coding_plan.zig`) writes one to four requests to a colibri server, or responses
  to a colibri client, each with a body in `gzip`, `deflate` or no compression under `chunked`,
  coded by stdx's encoders and cut into chunks of seeded lengths. A third of the gzip bodies are
  two members.
- Half the seeds plant a defect in the last message: a checksum one bit off, the last coded byte
  left out, a byte after a zlib stream, a zlib preset dictionary, or the pool's one decoder
  taken. Each must meet decision 91's refusal: the server's 400, 501 or 503, or the client's
  matching failure.
- The connection reads the stream in seeded pieces, with a seeded room of 1 to 48 bytes for
  each call. Each seed runs twice in pieces and once whole with the most room, and the three
  traces must agree, every body must decode to the plan's bytes, and the decoder must be back
  in the pool.
- `zig build sim -- --h11-coding-check` printed, in Debug and in `-Drelease` alike:
  `h11-coding: seeds=256 messages=540 refused=127 two_members=72 stream_octets=116431
  pieces=13532 calls=27992 trace_octets=52145 crc32=0x4b48322b`. The test pins the digest.
- Mutations of the library, each against `zig build test-sim-run` alone, all **CAUGHT** by the
  check: undecoded bytes not given back, a stream cut short accepted, bytes after a zlib
  stream starting another, a second gzip member refused, 503 answered as 400, and a failure
  keeping its decoder.

The simulator's h11 commands moved to `src/sim/run_main_h11.zig` to keep `run_main.zig` under
500 lines, and the check's limits are in `src/sim/constants_h11.zig`, which `constants.zig`
exports as `h11_coding`.
