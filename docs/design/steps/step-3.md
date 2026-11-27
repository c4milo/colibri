# Design §8 step 3: HPACK

[Design §8, the build plan](../../design.md#8-build-plan)

Static table, dynamic table with the shared size arithmetic, all five representations, the
size-update instruction. **Check:** `http2jp/hpack-test-case` decoded across
**every** encoder directory, not only nghttp2's — the naive, static and linear strategies crossed
with Huffman and plain are what exercise the dynamic table; round-trip of `raw-data`; the three
interop breaks of §6.2 each with a named error and a corpus case; fuzzing; mutations. *Medium.*

**Check passed, 2026-09-16.** `zig build test` exits 0 on Zig 0.16.0, macOS 25.6, arm64: 256 tests
pass, the lint scores 556 functions with a highest score of 15 against the limit of 15, the
eleven `tools/lint` rules run clean, `static_table --check` confirms `src/hpack/static_table.zig`
is what RFC 7541 Appendix A yields, and `hpack-vectors` prints
`directories=15 stories=478 cases=47142 fields=548382 round_trips=10152` in 2.9 s.

- **Module.** `hpack.Decoder` reads a block one representation at a time and returns each field
  line to the caller, which is §3.1's minimal transitory memory; `hpack.Encoder` writes a block
  with the strategy Appendix C's examples follow, and the tests hold both to C.3 through C.6
  byte for byte. `DynamicTable` is shared by the two, with the size formula in
  `wire/table_size.zig` (decision 11) and invariant 11's sum recomputed after every insert and
  eviction. The size-update rules of §4.2 and §6.3, and RFC 9113 §4.3.1's rule that a block
  after a lowered limit opens with a conformant update, are decoder errors with their sections
  on the checks. The static table is generated from Appendix A by `tools/static_table.zig`,
  as the Huffman table is from Appendix B.
- **Vectors.** Every directory of `http2jp/hpack-test-case` decodes, `nghttp2-change-table-size`
  and `nghttp2-16384-4096` included, and `raw-data` round-trips through the encoder in each of
  its three Huffman settings (decision 38 on how the corpus is held). Since step 62b the run
  skips `nghttp2-16384-4096`, whose table is larger than colibri keeps (decision 166 as
  amended).
- **Corpus.** `src/golden/hpack/` holds the three interop breaks of §6.2 beside their legal
  twins, six cases with five mutations, and `golden` now imports `hpack` to check them.
- **Not built.** Nothing of the step. `Decoder` and `Encoder` are 30 KiB and 22 KiB, sized by
  `dynamic_table_capacity_max`; the h2 connection of step 4 places one of each.

Forty-three source mutations were applied over the table, the decoder, the encoder, the
constants, the golden decode and the vectors tool, run against the narrowest step that can
catch them, and reverted: 42 **CAUGHT**, eight of them only after a test was added (an exact-fit
insert, a duplicate entry in `find`, the `never_indexed` flag, a name referenced from the entry
its own insert evicts and then compacts over, a size update held to a case's
`header_table_size`), and one equivalent: preferring the dynamic table's exact match over the
static table's cannot be observed, because a line the static table holds is indexed and never
inserted, so the mirror never holds one. The code now says so and prefers the static index.

**The static table's index, 2026-10-10.** For
[#57](https://github.com/c4milo/colibri/issues/57), `3c07e53` has the encoder find a static
entry through a map built at compile time. The map takes each name of RFC 7541 Appendix A to the
run of entries that carry it. A name is compared only with the table's names of its length, and
its value only within that run. Before it, the encoder compared each field line the table does
not hold whole with all 61 entries. The build refuses a table that does not keep one name's
entries together.

What each check printed:
- The scan stays in the encoder's tests as the reference. Two tests require the index to find
  what the scan finds: for every name of the table with every value of the table, and for each
  name one byte shorter, one byte longer, and with each of its bytes changed.
- 7 mutations, each **CAUGHT**: the index never read; a run that starts one entry late; a run
  without its last entry; an exact match without its name index; an exact index that counts
  from 0; a name match that reports no name; and, by the build's own check, entries of one name
  that each start a run.
- `tools/ci.sh` on macOS arm64: 33 of 33 sections passed, with 2745 of 2745 tests.

The judge, [run 38021801946](https://github.com/c4milo/colibri/actions/runs/38021801946),
measured it against `89ecb36`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 39,175 | 36,916 | 0.9423 | 0.9423 | wins in both |
| h2-tls-many | 47,000 | 44,746 | 0.9520 | 0.9519 | wins in both |
| h2-one | 305,317 | 302,511 | 0.9908 | 0.9912 | within the noise, then wins |
| h2-tls-one | 7,596,003 | 7,596,708 | 1.0001 | 0.9984 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 2,257 in the
first job and by 2,256 in the second.

**An indexed field line is read before the other representations, 2026-10-13.** `Block.next`
was one function the compiler kept out of line for every representation, called once a line:
a frame, a stack canary and a result returned through memory. `next` now reads an indexed line
itself, with `indexed` inline, and calls `next_other`, the old loop, for every other
representation and for a size update. In the server `bench/run.sh` builds, `next` is inlined
into h2's `feed_fragment`. Every block decodes to the lines, the refusals, the consumed bytes
and the table it did.

What each check printed:
- `next_other` is the old `next` and the tests' reference. On two decoders that start alike,
  `next` and `next_other` must return the same line or refusal, consume the same bytes and
  leave the same table, counts and lowered limit: for every block of up to two bytes, with
  and without a lowered limit, and for each cut of blocks that mix every representation.
- `zig build hpack-vectors` and `zig build golden-check` passed, and the four traces wrote the
  same bytes before and after the change.
- 6 mutations, each **CAUGHT**: the fast path reading a block with no byte left, taking a
  literal with incremental indexing, or taking every representation but an indexed line; a
  block with no indexed line ahead ending; an indexed line after a lowered limit needing no size
  update; and an index of 0 accepted.

The judge, [run 38342558304](https://github.com/c4milo/colibri/actions/runs/38342558304),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 15,898 | 15,691 | 0.9870 | 0.9871 | wins in both |
| h2-tls-many | 23,839 | 23,636 | 0.9915 | 0.9929 | wins in both |
| h2-one | 181,267 | 180,978 | 0.9984 | 0.9986 | within the noise |
| h2-tls-one | 7,279,084 | 7,280,172 | 1.0001 | 0.9998 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 207 in the first
job and by 206 in the second, where the disassembly gave about 210.

**HPACK measures a Huffman code once when it is shorter, 2026-10-13.** An encoder that
Huffman-codes a string only where the code is shorter measured the code twice: once in
`write_string` to choose the coding, and once more in `string_literal.encode` for the
literal's length. `encoder_string.write_shorter` now writes the literal (RFC 7541 §5.2) from
the one measurement, with `prefixed_integer.encode` and `huffman.encode`, names `wire` already
exports. It asserts that the code is shorter and that the literal holds the code. QPACK's
encoder still measures twice.

What each check printed:
- The old path stays in `encoder_string.zig`'s tests as the reference. `write_shorter` must
  return what it returns and leave the same bytes written, in every room from none to past the
  literal: for every string of up to two bytes, strings that mix code lengths up to 40 bytes,
  the strings a response carries, and runs of three 5-bit codes up to 220 bytes, whose codes
  pass the 127 bytes a one-byte length holds.
- `zig build hpack-vectors` and `zig build golden-check` passed, and the four traces wrote the
  same bytes before and after the change.
- 8 mutations, each **CAUGHT**: a code as long as the string written; the H flag one bit low;
  the flag left out; the string's length written for the code's; the cursor not given back; the
  literal written in place, so that a short room keeps its length; and the length given a
  6-bit or a 5-bit prefix.

The judge, [run 38427721946](https://github.com/c4milo/colibri/actions/runs/38427721946),
measured it against `0228d20`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 15,072 | 14,923 | 0.9901 | 0.9909 | wins in both |
| h2-tls-many | 23,006 | 22,858 | 0.9936 | 0.9937 | wins in both |
| h2-one | 180,439 | 180,484 | 1.0003 | 1.0005 | within the noise |
| h2-tls-one | 7,273,153 | 7,273,448 | 1.0000 | 0.9999 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 143 in the first
job and by 142 in the second, where the disassembly gave about 185.

**The encoder finds a response line in the chain of its name, 2026-11-15.** Decision 132 puts a
response's lines into the dynamic table, so the encoder searched its mirror for each line, and
compared the name of every entry it held. It searched even for a line the static table holds
whole, such as `:status: 200`, whose index it then sends. `name_chains.zig` now keeps, for
each name of the static table and for every other name together, the mirror's entries of it,
newest first. A line is searched in its own chain alone, and not at all when the static table
holds it whole ([#57](https://github.com/c4milo/colibri/issues/57)).
- An entry is named by its insert number, so an insert or an eviction changes no link, and a
  link past the table's length ends the walk. Each entry a walk finds is compared with the line,
  name and value, so a link that a wrapped number makes look live costs a compare, and never a
  wrong index.
- A table may hold many lines of one name: a server's `date` line inserts a new value each
  second. A line then reads its own chain, newest first, and no other name's entries.
- Each encoder grows by 1,152 bytes, and so does each h2 connection.

What each check printed:
- The scan of `DynamicTable.find` stays as the reference. A test requires the chains to find
  what the scan finds, over three times the 65,536 numbers a chain's insert number holds.
- `zig build hpack-vectors` and `zig build golden-check` passed. A new test of the encoder
  requires a repeated line to be one index, for the static table's first and last names.
- 12 mutations, each **CAUGHT**: every line inserted into chain 0; the static table's last
  name taken as another name; every line searched in chain 0; an insert not noted; an evicted
  entry read; the name not compared; the value not compared; the oldest name index kept; a head
  one number off; no older link kept; the heads not emptied at `init`; and a walk that stops at
  the head.
- Callgrind on a laptop's Linux VM, which publishes no number, gave h2-many 11,026 instructions
  a request before and 10,812 after.

The judge, [run 43726635141](https://github.com/c4milo/colibri/actions/runs/43726635141),
measured it against `f3e9bc09`, in instructions per request, or per connection for the two
`one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 13,480 | 13,275 | 0.9847 | 0.9847 | wins in both |
| h2-routes-many | 16,294 | 16,084 | 0.9871 | 0.9870 | wins in both |
| h2-routes-post-many | 20,345 | 20,163 | 0.9910 | 0.9900 | wins in both |
| h2-tls-many | 15,731 | 15,529 | 0.9872 | 0.9867 | within the noise |
| h2-routes-post-late-many | 37,871 | 37,675 | 0.9948 | 0.9969 | within the noise |
| h2-one | 150,526 | 150,971 | 1.0030 | 0.9974 | within the noise |
| h2-tls-one | 1,035,316 | 1,035,729 | 1.0004 | 0.9998 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 214 in the first
job and by 215 in the second.
