# Design §8 step 61: h2's field blocks where they lie, 2026-11-18

[Design §8, the build plan](../../design.md#8-build-plan)

[#137](https://github.com/c4milo/colibri/issues/137). After step 60, h2's field blocks held 98,352
bytes of each connection: 65,584 to receive a block and 32,768 to send one. The owner ruled on
2026-11-18 for two steps, each judged alone. No public name changes.
- **61a, a fragment decoded where it lies.** The slot copied each fragment after the bytes a
  cut representation left, then decoded the buffer, so it held one representation and one frame
  (decision 40). Now `decode_fragment` appends the next fragment's first bytes to a kept
  representation, at most up to `representation_len_max`, and decodes the buffer. It then
  decodes the rest of the fragment where the connection holds it, and `keep` copies only the
  representation the fragment cuts. `field_block_buffer_len` goes from 48,105 to 31,721 bytes,
  and a block that arrives whole is never copied. Decision 40 is amended.
- **One call of the decoding loop.** A first version called `decode_slice` once for the buffer
  and once for the fragment, and the judge counted h2-many at 1.0019 and 1.0023 of main (run
  44416678769). Both runs now go through one call. A probe of `feed` on one request block,
  under callgrind on arm64, counted 1,273 instructions on main, 1,354 with two calls, 1,322
  with one call, and 1,254 for a decoder in place that handles no cut line. The other ways to
  lay out the call that the probe counted were dearer: forced inline, 1,375, and the loop out
  of line, 1,352.
- **61b, a block cut into frames where it is encoded.** A response, trailer or request block
  was encoded into `send_block` when it did not fit one frame, then copied into its frames.
  `write_block` already needed the caller's buffer to hold every frame, so `block_space` now
  gives the block that buffer after the HEADERS frame's header. `frame_block` moves each later
  fragment after the headers before it, the last first, and writes the headers. A block that
  fits one frame does not move, and no block is encoded twice. `send_block` is gone.
- **Memory.** `h2.Connection` goes from 164,672 to 115,520 bytes, and an engine's TCP slot from
  334,344 to 285,192. A connection of connect-zig's sink, which step 60 brought to about
  432,960 bytes, goes to about 383,808, and its 528 connections take about 26 MB less.
- **The contract of a refusal.** A send or a request that the connection refuses changes nothing
  of the connection and counts no byte of the caller's buffer as written. A refused block may
  have been encoded into the buffer, so the bytes past what a call returns are scratch, as
  `core.Writer` says. The old path that encoded a block in its frame wrote there too.
- **The checks.**
  - Two tests of 61a feed one block of five lines: Huffman-coded and raw strings, a value of
    2,000 bytes, and a line that names the dynamic table. They cut it in two at each byte,
    and in three at each two places 53 bytes apart. Each cut must give the section, the line
    count and the table length of the block fed whole.
  - The test of 61b keeps the old `write_block` as its reference. For three frame sizes, and a
    block about the edges of one and two frames and the longest block, both must write the same
    frames, or both must refuse the block when the output is one byte short.
  - 61a: 10 mutations, each **CAUGHT**: the append past the buffer's room; a cut line that took
    the whole fragment refused; the rest found without the kept bytes; the buffer kept after the
    line is finished; the decoded bytes not counted; the cut line decoded without the appended
    bytes; the rest decoded while a line is still cut; the tail not kept; the counts not carried
    into the buffer's decode; and the rest decoded as if it were the buffer.
  - 61b: 9 mutations. 8 are **CAUGHT**: the frames past the output; a fragment moved one header
    short; END_HEADERS on the first frame too; END_STREAM on a CONTINUATION frame; each frame a
    HEADERS frame; a frame's length one byte short; a block past the limit; and no room before
    the first header. The first fragment moved first is **NOT CAUGHT**, and no test can catch
    it: a block holds at most `send_block_len_max`, two frames of the smallest
    `max_frame_size`, so only one fragment moves.
  - The tests of `h2` pass, 414 of 414, on arm64 and on x86-64 in Debug under Zig's own backend.
- **The judge** measured each step against `a9bbe33b` at 10 rounds, and every h2 input stays
  within the noise in both jobs of each run.
  [Run 44427802334](https://github.com/c4milo/colibri/actions/runs/44427802334) measured 61a:
  h2-many is 0.9974 and 0.9976 of the base, from 10,459 to 10,427 user instructions a request.
  [Run 44427805722](https://github.com/c4milo/colibri/actions/runs/44427805722) measured 61a
  and 61b: h2-many is 0.9981 and 0.9986, from 10,462 to 10,439.
