# Design §8 step 1: `wire` and `http`

[Design §8, the build plan](../../design.md#8-build-plan)

The varint (RFC 9000 §16), the prefixed integer generic over N in 1..8 and sized for 62 bits, the
Huffman coder over RFC 7541 Appendix B, the string literal including QPACK's mid-byte prefix form,
the `tchar` and field-value validators, the connection-option denylist, the status and method
models. **Check:** a golden corpus with a manifest, valid and invalid, including one case per
Huffman decode error (padding over 7 bits, padding that is not EOS's high bits, EOS inside the data)
and one per varint length; RFC 9000 Appendix A's sample varint decodings; fuzzing of every decoder;
and a mutation per check reported `CAUGHT`. *Small to medium.*

**Check passed, 2026-09-16.** `zig build test` exits 0 on Zig 0.16.0, macOS 25.6, arm64:
262 tests pass, the lint scores 583 functions with a highest score of 12 against the limit of
15, the eight `tools/lint` rules run clean, and `huffman_table --check` confirms that
`src/wire/huffman_table.zig` is what RFC 7541 Appendix B yields.

- **Reader and writer.** `core.Reader` and `core.Writer` work over caller-owned slices and hold
  no memory ([decision 35](../../decisions/0035-colibri-is-zero-heap.md)). A read or write that does not fit returns an
  error and moves no cursor, and each entry point asserts that the cursor is inside the slice
  ([invariant 3](../../invariants.md#inv-3)). Every decoder
  built on them consumes a whole structure or nothing.
- **Huffman table.** `tools/huffman_table.zig` generates the table from the RFC text. It reads
  both code columns of every row and refuses a row where they disagree. Comptime asserts in
  `src/wire/huffman.zig` pin Kraft equality, EOS as thirty set bits, and the canonical order the
  decoder depends on. The bytes 204 and 22 encode to `ff ff fb ff ff ff ff 7f`, whose run of
  thirty-four ones decodes with no EOS
  ([decision 11](../../decisions/0011-the-huffman-coder-and-the-prefixed.md)).
- **Corpus.** `src/golden/` holds 32 cases in four formats, 14 of them invalid, each format with
  a version 1 manifest: 10 varint, 9 prefixed integer, 7 Huffman and 6 string literal. They cover
  one valid case and one truncation per varint length, RFC 9000 Appendix A.1's five sample
  decodings, RFC 7541 Appendix C.1's three integers, the Appendix C strings, one case per Huffman
  decode error, and QPACK's mid-byte string literal at 4-bit and 2-bit prefixes.
  `zig build golden-check` compares every committed file and manifest with the case table, and
  runs the 15 corpus mutations of `src/golden/mutations.zig`, each of which produces the verdict
  it names.
- **Fuzzing.** Every decoder and validator has a `std.testing.fuzz` property function.
  `zig build test` runs each one over its corpus and over every input of up to two bytes, at
  every prefix size where the decoder takes one (`core.fuzz.sweep`). Zig 0.16.0's fuzz-mode
  test runner does not compile, because `lib/compiler/test_runner.zig:566` passes a
  `builtin.StackTrace` where `std.debug.writeStackTrace` takes a `debug.StackTrace`. Since
  decision 144, `zig build test-<module> -Dfuzz --fuzz=<runs>` runs the fuzzer over a runner
  with that one line fixed. A corpus entry is not raw bytes: outside `--fuzz`, `Smith` reads a
  4-byte length before each slice, which `core.fuzz.input` writes.
- **Built after the step passed.** Invariant 3's lint rule, no slicing with a peer-derived
  index outside the reader and writer, was not written when the step passed; its assertions
  and fuzzing were. `tools/lint/peer_index.zig` added it on 2026-09-16, and the tree was clean
  under it.

Seventy-two source mutations were applied, run against the narrowest test step that can catch
them, and reverted. The first run found one `NOT CAUGHT`: an encoder that ended the prefixed
integer one value early wrote `ff 00` for a remainder of 127, which decodes to the same value, so
no test saw it. The test "continuation octets follow only while the remainder is 128 or more" now
pins RFC 7541 §5.1's loop condition. Five mutations failed only to compile, because they left a
local unused, which proves nothing about the rule. Each was replaced with a mutation that
compiles. Every row below is the final result.

| Mutation | Result | Caught by |
|---|---|---|
| reader: take accepts one byte past the end | **CAUGHT** | test panicked (null unwrap or bounds check) |
| reader: peek_byte skips the empty check | **CAUGHT** | test panicked (null unwrap or bounds check) |
| reader: read_byte does not advance | **CAUGHT** | test `reader`: "a read inside the slice returns the octets and moves the cursor" |
| reader: read_int shifts seven bits | **CAUGHT** | test `reader`: "integers read in network byte order" |
| writer: write_bytes accepts one byte past the end | **CAUGHT** | test panicked (null unwrap or bounds check) |
| writer: write_byte skips the full check | **CAUGHT** | test panicked (null unwrap or bounds check) |
| writer: write_int writes little-endian | **CAUGHT** | test `writer`: "a write inside the buffer lands and moves the cursor" |
| writer: print advances at most one byte | **CAUGHT** | test `writer`: "formatted text lands whole or not at all" |
| varint: length read from the top bit alone | **CAUGHT** | test `varint`: "a non-minimal encoding decodes and re-encodes at its own length" |
| varint: length bits left in the value | **CAUGHT** | test panicked (null unwrap or bounds check) |
| varint: encoder writes the length bits one place low | **CAUGHT** | test `varint`: "a non-minimal encoding decodes and re-encodes at its own length" |
| varint: one-byte range includes 64 | **CAUGHT** | test `varint`: "each length's largest value round-trips and one more needs the next length" |
| prefixed integer: a full prefix read as the value | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
| prefixed integer: continuation flag read from bit 6 | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
| prefixed integer: value limit one past 62 bits | **CAUGHT** | test `prefixed_integer`: "a value one past the ceiling is IntegerTooLarge" |
| prefixed integer: byte limit one longer | **CAUGHT** | test `prefixed_integer`: "an eleventh octet is IntegerTooLong even when every group is zero" |
| prefixed integer: groups shifted by eight | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
| prefixed integer: caller high bits kept in the prefix | **CAUGHT** | test `prefixed_integer`: "the high bits belong to the caller and never change the value" |
| prefixed integer: encoder ends one value early | **CAUGHT** | test `prefixed_integer`: "continuation octets follow only while the remainder is 128 or more" |
| prefixed integer: failed decode still consumes | **CAUGHT** | test `prefixed_integer`: "a value one past the ceiling is IntegerTooLarge" |
| wire constants: integer_len_max nine | **CAUGHT** | comptime assert |
| huffman: EOS compared with symbol 255 | **CAUGHT** | test `huffman`: "every octet round-trips, and the empty string is empty" |
| huffman: EOS found by scanning for thirty ones (invariant 12) | **CAUGHT** | test `huffman`: "octets 204 and 22 decode through a run of thirty-four ones with no EOS" |
| huffman: padding of eight bits allowed | **CAUGHT** | test `huffman`: "padding longer than seven bits is HuffmanPaddingTooLong" |
| huffman: padding not checked against EOS | **CAUGHT** | test `huffman`: "padding that is not a prefix of EOS is HuffmanPaddingNotEos" |
| huffman: canonical range admits one code too many | **CAUGHT** | test `huffman`: "octets 204 and 22 decode through a run of thirty-four ones with no EOS" |
| huffman: encoder pads with zeros | **CAUGHT** | test `huffman`: "octets 204 and 22 decode through a run of thirty-four ones with no EOS" |
| huffman: failed decode commits partial output | **CAUGHT** | test `huffman`: "a complete EOS inside the data is HuffmanEosInData, even before a valid symbol" |
| huffman table: one code changed | **CAUGHT** | comptime assert |
| huffman table: one length changed | **CAUGHT** | comptime assert |
| huffman table: generated comment edited by hand | **CAUGHT** | `huffman_table --check` in `zig build test` |
| string literal: H flag one bit low | **CAUGHT** | test `string_literal`: "a Huffman error inside the data fails the literal and consumes nothing" |
| string literal: length read at N bits | **CAUGHT** | test `string_literal`: "a Huffman error inside the data fails the literal and consumes nothing" |
| string literal: declared length clamped to the data present | **CAUGHT** | test `string_literal`: "a length longer than the data present is Truncated and consumes nothing" |
| string literal: Huffman data copied raw | **CAUGHT** | test `string_literal`: "a Huffman error inside the data fails the literal and consumes nothing" |
| string literal: decode never commits the reader | **CAUGHT** | test `string_literal`: "fuzz: a literal consumes its whole length or nothing" |
| field: bar dropped from tchar | **CAUGHT** | test `field`: "every tchar RFC 9110 §5.6.2 lists is a tchar, and nothing else is" |
| field: empty name accepted | **CAUGHT** | test `field`: "a field name is a non-empty token within the limit" |
| field: name limit refuses the limit itself | **CAUGHT** | test `field`: "a field name is a non-empty token within the limit" |
| field: name bytes above 0x7f accepted | **CAUGHT** | test `field`: "a field name is a non-empty token within the limit" |
| field: CR not refused as CR | **CAUGHT** | test `field`: "a field value is refused in check order" |
| field: HTAB reported as control | **CAUGHT** | test `field`: "a field value admits VCHAR, obs-text and inner whitespace" |
| field: DEL not a control | **CAUGHT** | test `field`: "a field value is refused in check order" |
| field: control bytes accepted | **CAUGHT** | test `field`: "a field value is refused in check order" |
| field: leading whitespace accepted | **CAUGHT** | test `field`: "a field value is refused in check order" |
| field: trailing whitespace read from the first byte | **CAUGHT** | test `field`: "a field value is refused in check order" |
| field: value limit refuses the limit itself | **CAUGHT** | test `field`: "a field value admits VCHAR, obs-text and inner whitespace" |
| field: names compared case-sensitively | **CAUGHT** | test `field`: "field names compare case-insensitively" |
| connection-specific: Connection dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
| connection-specific: Proxy-Connection dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
| connection-specific: Keep-Alive dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
| connection-specific: TE dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
| connection-specific: Transfer-Encoding dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
| connection-specific: Upgrade dropped | **CAUGHT** | test panicked (null unwrap or bounds check) |
| connection-specific: TE trailers matched by prefix | **CAUGHT** | test `connection_specific`: "TE is trailers only when it says exactly that" |
| method: empty method accepted | **CAUGHT** | test `method`: "a method that is not a token is refused" |
| method: space accepted in a method | **CAUGHT** | test `method`: "a method that is not a token is refused" |
| method: standard methods matched case-insensitively | **CAUGHT** | test `method`: "a method is case-sensitive, and an unknown token is still a method" |
| status: 99 in range | **CAUGHT** | test `status`: "the range ends are 100 and 599" |
| status: 600 in range | **CAUGHT** | test `status`: "the range ends are 100 and 599" |
| status: four digits accepted | **CAUGHT** | test `status`: "three digits parse, and anything else is refused in check order" |
| status: digits not checked | **CAUGHT** | test `status`: "three digits parse, and anything else is refused in check order" |
| status: recognised codes not kept | **CAUGHT** | test `status`: "an unrecognised code is understood as the x00 of its class" |
| status: 426 dropped from the recognised codes | **CAUGHT** | test `status`: "the recognised codes are exactly those RFC 9110 §15.2 to §15.6 define" |
| golden: constructor value changed | **CAUGHT** | test `golden`: "golden-check: every committed case file is what its constructor builds" |
| golden: rejection named wrongly | **CAUGHT** | test `golden`: "golden-check: every committed manifest is what the table renders" |
| golden: manifest checksum edited | **CAUGHT** | test `golden`: "golden-check: every committed manifest is what the table renders" |
| golden: corpus mutation names the wrong verdict | **CAUGHT** | test `golden`: "golden-check: every corpus mutation produces the verdict it names" |
| golden tool: frozen marker ignored | **CAUGHT** | test `golden`: "a frozen directory is refused and a writable one is written in full" |
| golden tool: stale cases kept | **CAUGHT** | test `golden`: "a frozen directory is refused and a writable one is written in full" |
| huffman tool: only a larger hex column refused | **CAUGHT** | test `huffman_table`: "a row whose bits and hex disagree is refused" |
| huffman tool: symbol order not checked | **CAUGHT** | test `huffman_table`: "a missing, reordered or short appendix is refused" |

**The varint proved, 2026-09-26.** `spec/lean/Colibri/Wire/Varint.lean` states RFC 9000 §16's
codec over natural numbers, as `varint.zig` computes it, and proves four things
([#52](https://github.com/c4milo/colibri/issues/52)):
- `decode_encode`: an encoding decodes to its value and its length, whatever bytes follow it;
- `encode_octets`: in the four lengths, every byte of an encoding is below 256;
- `decode_bound`: whatever bytes are decoded, the value fits the length the first byte names;
- `minimal_fits` and `minimal_shortest`: the minimal length carries the value, and no shorter
  one does.

The proof of the first used no bound on the length. The four lengths are what keep the first
byte a byte, which `u8` enforces in `varint.zig` and the model had left unstated, so that
fact became `encode_octets`. `spec/lean/Vectors.lean` writes `src/wire/varint_vectors.txt`:
60 encodings, among them RFC 9000 Appendix A.1's, 484 decodings of every one-byte input and
every cut encoding, and 23 minimal lengths. A test in `varint.zig` requires the Zig codec to
give each. Mutations: 3 in `varint.zig`, each **CAUGHT** by that test; 2 in the Lean
definitions, each stopping the proofs; and 1 edit to the vector file, which `zig build lean`
refuses.

**The prefixed integer proved, 2026-09-26.** `spec/lean/Colibri/Wire/PrefixedInteger.lean`
states RFC 7541 §5.1's integer as `prefixed_integer.zig` computes it, at every prefix size 1 to 8,
and proves:
- `decode_encode`: an encoding decodes to its value and its length, whatever high bits the
  caller set above the prefix and whatever bytes follow;
- `encode_octets`: every byte is below 256;
- `encode_length`: every value up to 2^62 - 1 takes at most `integer_len_max` bytes at every
  prefix size;
- `decodeLimited_encode`: with colibri's byte and value limits, every such encoding still reads
  back, so the limits refuse nothing RFC 9204 §4.1.1 requires.

`src/wire/prefixed_integer_vectors.txt` holds 191 encodings, RFC 7541 Appendix C.1's three
among them, and 355 decodings: every cut encoding, and the inputs only colibri's limits refuse.
A test in `prefixed_integer.zig` requires the Zig codec to give each. Mutations: 5 in
`prefixed_integer.zig`, each **CAUGHT** by that test. One, reading a tenth continuation byte,
was caught only after the vectors gained an input whose tenth byte ends the integer. 1 in the
Lean definitions stops the proofs, and 1 edit to the vector file is refused by `zig build lean`.

**The Huffman code proved, 2026-09-26.** `spec/lean/Colibri/Wire/Huffman.lean` states RFC 7541
Appendix B's code and §5.2's padding as `huffman.zig` encodes them. Its decoder reads one bit at
a time and looks the bits read so far up in the table. It proves:
- `prefix_free`: no symbol's code is a prefix of another's. The kernel checks this over the
  codes as numbers in 9 seconds, where a check over the codes as bits took 100, and a lemma
  carries it to the bits;
- `eos_ones`: EOS is thirty ones;
- `decode_encode`: every string of bytes decodes back from its encoding, padding included;
- `decode_octets`: whatever a decoding accepts is bytes below 256, so EOS never reaches the
  output.

`spec/lean/Colibri/Wire/HuffmanTable.lean` copies the 257 rows of `huffman_table.zig`.
`src/wire/huffman_vectors.txt` names each row, and holds 271 encodings and 1,288 decodings, 796
of them refused. The encodings cover every byte, RFC 7541 Appendix C.4's and C.6's strings, and
all 256 bytes in one string. A test in `huffman.zig` requires the Zig table and coder to give
each line. `huffman.zig` decodes through the table's canonical ranges, so these vectors are what
tie it to the decoder the proofs are about.

Mutations:
- 8 in `huffman.zig` and `huffman_table.zig`, each **CAUGHT** by that test. Two first failed to
  compile and were rewritten to compile: zero padding, which left a constant unused, and a table
  row, which the comptime Kraft check refused and which became two 5-bit codes swapped.
- 4 in the Lean definitions. Three make a theorem false: EOS reaching the output, zero padding,
  and two rows sharing a code. The fourth, eight bits of padding accepted, first broke only a
  proof script that named the constant 7. That script now uses `split`, so the mutant builds,
  and `zig build lean` refuses it for the vectors it changes.
- 1 edit to the vector file, which `zig build lean` refuses.

**The encoder writes a word at a time, 2026-10-11.** For
[#57](https://github.com/c4milo/colibri/issues/57), `huffman.encode` gathers code in a 64-bit
value and writes its oldest thirty-two bits at one call. Before it, the encoder measured the
string and then wrote one byte at a time, with up to four writes for a symbol. A string that
does not fit now leaves the output cursor where it was, as a failed decode does, and the bytes
past the cursor are scratch. No name changed.

What each check printed:
- The encoder it replaced stays in `huffman_test.zig` as the reference. Three tests require
  `encode` to return what the reference returns and to leave the same bytes written: for
  strings of every length up to 40, in every room from none to one byte past the code; for
  every pair of bytes; and for the strings the judge's exchange carries. The first also
  requires its strings to leave each count of waiting bits, 0 to 31.
- The vectors `spec/lean/Colibri/Wire/Huffman.lean` gives, `zig build hpack-vectors`,
  `zig build qpack-vectors` and `zig build golden-check` passed with the new encoder. Zig 0.16
  cannot run the fuzzer ([#53](https://github.com/c4milo/colibri/issues/53)).
- 13 mutations, each **CAUGHT**: a word taken one bit too high, or from the newest bits; a word
  or a tail byte that does not fit, dropped; the count keeping a written word's bits; padding
  of zeros, or a byte of padding after a code that ends on a byte; a tail of three bytes at
  most; a tail byte taken before the count moves; the cursor moved before the tail is written,
  or never; a shift one bit short; and a full word that waits for one more symbol, which the
  encoder's own assertion stops.

The judge, [run 38144224156](https://github.com/c4milo/colibri/actions/runs/38144224156),
measured it against `e880e60`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 36,934 | 36,349 | 0.9841 | 0.9841 | wins in both |
| h2-tls-many | 44,755 | 44,170 | 0.9869 | 0.9871 | wins in both |
| h2-one | 301,639 | 301,666 | 1.0001 | 0.9978 | within the noise |
| h2-tls-one | 7,564,746 | 7,560,839 | 0.9995 | 0.9985 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 586 in the first
job and by 587 in the second. The server then still measured a string twice before it coded it:
once to choose Huffman, in the HPACK encoder's `write_string`, and once for the literal's length,
in `string_literal.encode`. HPACK measures once since the change recorded in step 3; QPACK's
encoder still measures twice.

**`validate_value` reads one table, 2026-10-12.** The loop tested each byte of a field value
with compares and returned from inside itself at NUL, CR or LF, which kept the compiler to one
byte a pass: 14 instructions a byte, over the 70 bytes of field values the judge's request
and response carry. A table now gives each byte its class: NUL, CR or LF; another control
byte; or neither. The loop ORs the classes and no byte ends it, and the two reasons are
tested after it, NUL, CR or LF first. Every value gets the verdict it got. A value that holds a
NUL is now read to its end, which `field_value_len_max` bounds.

What each check printed:
- The old loop stays in `field.zig`'s tests as the reference. `validate_value` must give its
  verdict for every value of up to two bytes; with every byte value at every position of
  every length up to 40, over three backgrounds; with every pair of nine kinds of byte at
  every pair of positions up to 20; at the longest value and one byte past it; and with each
  kind at each power of two inside the longest value.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change.
- 14 mutations, each **CAUGHT**. Of the table: NUL, CR or LF admitted; a control byte reported
  as one of those three, or admitted; and HTAB reported as a control byte. Of the loop: the
  last byte's class kept alone; the first byte left out, or the last, or those past the
  fortieth. Of the reasons: the two in the other order, either one left out, and both classes
  on one bit.

The judge, [run 38201626617](https://github.com/c4milo/colibri/actions/runs/38201626617),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians. The judge measured the
commit before its review, which differs from this one in tests alone.

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 17,555 | 16,888 | 0.9620 | 0.9618 | wins in both |
| h2-tls-many | 25,404 | 24,748 | 0.9742 | 0.9759 | wins in both |
| h2-one | 222,749 | 222,232 | 0.9977 | 0.9966 | within the noise |
| h2-tls-one | 7,327,325 | 7,326,680 | 0.9999 | 0.9998 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 668 in both
jobs, where the disassembly gave about 620: the new loop runs 9 instructions for each 2 bytes.

**A pseudo-header name is compared with each definition at once, 2026-10-13.** `slot_of`
compared each pseudo-header name of a request with the five definitions through
`std.mem.eql`, which the compiler did not inline: ten calls for a request of four
pseudo-headers. The loop is unrolled with `inline for`, and `is_name` reads the name as one
integer, in an order it states, against the definition's name as a constant. A definition then
costs a length test and one compare. `slot_of` returns the slot it returned for every name.

What each check printed:
- The loop with `std.mem.eql` stays in `message_lines.zig`'s tests as the reference. `slot_of`
  must name its slot, or null, in a request and in a response, for every pseudo-header name of
  up to three bytes and for each defined name with any one byte changed, one byte short, or
  one byte longer.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change.
- 5 mutations, each **CAUGHT**: a name of another length compared, a name taken when it
  differs, the expected name read in the other order, the last byte not compared, and a name
  defined in either kind. 1 mutation **NOT CAUGHT**: the colon left out of the compare, which
  `slot_of` asserts before it compares.

The judge, [run 38342552581](https://github.com/c4milo/colibri/actions/runs/38342552581),
measured it against `25e1c93`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 16,857 | 16,504 | 0.9790 | 0.9790 | wins in both |
| h2-tls-many | 24,698 | 24,396 | 0.9878 | 0.9882 | wins in both |
| h2-one | 184,513 | 184,336 | 0.9990 | 0.9987 | within the noise |
| h2-tls-one | 7,283,578 | 7,282,422 | 0.9998 | 0.9999 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 354 in the first
job and by 355 in the second, where the disassembly gave about 370.

**A one-byte or two-byte prefixed integer is written directly, 2026-10-13.** `encode` built
every integer in a zeroed array of ten bytes and wrote it with one `write_bytes` of a length
known only at run time, which calls `memcpy`. A value under the prefix's maximum is now one
`write_byte`, and a remainder of seven bits or fewer one `write_bytes` of two bytes. Longer
integers take the old array in `encode_continued`, which takes no prefix size and is compiled
once. Each call still writes all of its bytes or none.

What each check printed:
- The old encoder stays in `prefixed_integer.zig`'s tests as the reference. `encode` must
  return what it returns and leave the same bytes written, at every prefix size, with the
  caller's bits clear and set, for every value of up to 15 bits and the values at and beside
  each length boundary above them, in every room from none to one byte past the longest
  encoding.
- `zig build hpack-vectors`, `zig build qpack-vectors` and `zig build golden-check` passed, and
  the four traces wrote the same bytes before and after the change.
- 8 mutations, each **CAUGHT**: a value equal to the prefix's maximum written in the prefix;
  the caller's bits dropped from the one-byte case; a remainder of 128 written in one byte;
  the continuation flag on the last of two bytes; the two bytes in the other order; the
  first of two written when the second does not fit; and the prefix's ones dropped in the
  two-byte and the longer case.

The judge, [run 38342556593](https://github.com/c4milo/colibri/actions/runs/38342556593),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 16,028 | 15,905 | 0.9923 | 0.9922 | wins in both |
| h2-tls-many | 23,978 | 23,860 | 0.9951 | 0.9941 | within the noise in job 1, wins in job 2 |
| h2-one | 181,698 | 181,693 | 1.0000 | 0.9991 | within the noise |
| h2-tls-one | 7,277,535 | 7,277,189 | 1.0000 | 1.0000 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 122 in the first
job and by 121 in the second. The disassembly gave about 290, because it took the one-byte
case to compile to about 15 instructions. In the server `encode` stays out of line with a stack
canary, because the two-byte case keeps its pair on the stack and writes it through
`write_bytes`, which calls `memcpy`; the one-byte case runs about 40.

**A field name is checked for case and token in one pass, 2026-10-13.** h2 and h3 read each
regular field name twice: once for uppercase letters (RFC 9113 §8.2.1, RFC 9114 §4.2), then
through `field.validate_name` for bytes outside a token (RFC 9110 §5.1). A table of the bytes
that are tchars and not uppercase letters now checks both rules in one read a byte, in
`message_lines.check_name` for what h2 and h3 receive and in h2's `validate_field_line` for
what it sends. Each module builds the table from `http.field.is_tchar`, since sharing one would
add a public name. `validate_name` serves h11.

What each check printed:
- The two passes stay in the tests as the reference, h2's in `connection_request_test.zig`,
  split off `connection_request.zig` for length. Each check must give its verdict for every
  name of up to two bytes, with every byte value at every position of every length up to 40
  and of the longest name, and at one byte past the longest.
- The four traces wrote the same bytes before and after the change.
- 10 mutations, each **CAUGHT**. Of each table: an uppercase letter admitted, and on receive any
  byte but an uppercase letter, and on send a colon. An empty name accepted, on each side; a
  name past the limit accepted on send; the last byte left unread on receive; and the bytes
  past the fortieth left unread, on each side.

The judge, [run 38342559987](https://github.com/c4milo/colibri/actions/runs/38342559987),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 15,691 | 15,454 | 0.9849 | 0.9847 | wins in both |
| h2-tls-many | 23,645 | 23,489 | 0.9934 | 0.9909 | wins in both |
| h2-one | 181,661 | 181,551 | 0.9994 | 0.9982 | within the noise |
| h2-tls-one | 7,278,673 | 7,278,190 | 0.9999 | 1.0000 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 244 in both jobs,
where the disassembly gave about 250.

**A field line of another name length is skipped without reading it, 2026-10-13.**
`FieldSection.find` and `content_length.from_section` read every line's bytes to compare its
name, through `get`, which builds both slices. RFC 9110 §5.1 makes names case-insensitive, and
`names_equal` folds ASCII case one byte to one byte, so a name of another length never
matches. Both now compare the line's recorded name length first and skip a line of another
length. Neither returns anything it did not.

What each check printed:
- The two old loops stay in the tests as references. `find` must return the line the scan
  returns, for nine names that share a length, differ in case, differ by one byte, or are
  empty, in every section of up to three lines of them. `from_section` must give the
  reference's length or refusal for every section of up to three lines mixing four names with
  five values.
- The four traces wrote the same bytes before and after the change.
- 5 mutations, each **CAUGHT**: `find` skipping the lines of the same length, or stopping at
  the first of another; `from_section` skipping the lines of the same length, stopping at the
  first of another, or reading the line after the record. 2 mutations **NOT CAUGHT**, which skip
  fewer lines: `names_equal` refuses those lines anyway.

The judge, [run 38342563842](https://github.com/c4milo/colibri/actions/runs/38342563842),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 15,236 | 15,049 | 0.9877 | 0.9875 | wins in both |
| h2-tls-many | 23,201 | 23,013 | 0.9919 | 0.9904 | wins in both |
| h2-one | 180,671 | 181,213 | 1.0030 | 0.9979 | within the noise |
| h2-tls-one | 7,275,145 | 7,274,168 | 0.9999 | 0.9999 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 189 in both jobs,
where the disassembly gave about 200.

**A fixed-size integer is stored without `memcpy`, 2026-10-13.** `Writer.write_int` built its
bytes in an array and wrote them through `write_bytes`, which the compiler keeps out of line
and which calls `memcpy` for a length it learns at run time. It now checks the room and stores
the array, whose size the compiler knows. Huffman's 32-bit words already used it; an h2 frame
header now writes its 24-bit length and its type as one `u32`, and `wire`'s prefixed integer
writes its two-byte case as one `u16`, for HPACK and QPACK. `@sizeOf(u24)` is four bytes, so
`write_int` still writes four for it, and its comment says so.

What each check printed:
- The old `write_int` and the old frame header stay in the tests as references, and the
  prefixed integer's reference from step 1 covers its two-byte case. `write_int` must write
  what the old one writes at every width, offset and room; the frame header must return what
  the old one returns and leave the writer the same bytes, for each length, type, flags and
  stream in every room. A failed frame header no longer leaves its three length bytes in the
  buffer past the writer's offset, which no caller reads.
- `zig build hpack-vectors`, `zig build qpack-vectors` and `zig build golden-check` passed, and
  the four traces wrote the same bytes before and after the change.
- 7 mutations, each **CAUGHT**: an integer that fits exactly refused; no room checked; the
  cursor not moved; the low byte written first; the frame type left out of the header, or the
  length shifted a byte too far; and the prefixed pair written in the other order.

The judge, [run 38427727383](https://github.com/c4milo/colibri/actions/runs/38427727383),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 14,962 | 14,671 | 0.9806 | 0.9824 | wins in both |
| h2-tls-many | 22,942 | 22,702 | 0.9895 | 0.9869 | wins in both |
| h2-one | 181,310 | 180,711 | 0.9967 | 0.9971 | within the noise |
| h2-tls-one | 7,279,202 | 7,278,778 | 0.9999 | 1.0000 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 282 in the first
job and by 280 in the second, where the disassembly gave about 300.

**A field value is checked for control bytes eight at a time, 2026-10-13.**
`field.validate_value` read each byte's class from the table step 1 gave it. A value of eight
bytes or more is now read a 64-bit word at a time by `field_value.has_control`: a few
operations on each word mark every byte below SP or equal to DEL (RFC 5234 Appendix B.1's
CTL), with no carry from one byte into the next, and the last word overlaps the steps before
it. A value with none holds no class, and the table is skipped; a value with one, HTAB
included, is read a byte at a time as before, which names the reason. Every value gets the
verdict it got.

What each check printed:
- `field_value.zig`'s tests require the word operations to mark each control byte in every
  lane, beside four kinds of neighbour, and `has_control` to find a control byte at every
  position of every length from 8 to 40. `field.zig`'s reference tests from step 1 now also put
  a control byte at every offset of the longest value.
- The four traces wrote the same bytes before and after the change.
- 9 mutations, each **CAUGHT**: the last word not read; one step fewer; DEL not wrapped; SP
  counted as a control byte; obs-text counted as one; a clean value of seven bytes skipping
  the table; a value with a control byte skipping it; the steps past the thousandth not read;
  and the sixth step's word not read.

The judge, [run 38427737018](https://github.com/c4milo/colibri/actions/runs/38427737018),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 14,548 | 14,461 | 0.9940 | 0.9936 | wins in both |
| h2-tls-many | 22,475 | 22,351 | 0.9945 | 0.9956 | wins in job 1, within the noise in job 2 |
| h2-one | 179,222 | 179,368 | 1.0008 | 1.0002 | within the noise |
| h2-tls-one | 7,275,292 | 7,276,176 | 1.0001 | 1.0000 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 91 in both jobs,
where the disassembly gave about 160.

**The Huffman decoder reads twelve bits at a time, 2026-11-16.** For
[#57](https://github.com/c4milo/colibri/issues/57), `huffman.decode` holds the next bits of its
input in a 64-bit buffer, and moves up to eight bytes into it at a time. A comptime table of
4,096 entries, read by the buffer's top twelve bits, gives the codes those bits hold whole and the
bits they take. The shortest code is five bits, so twelve bits hold two codes at most. One read
of 11 instructions writes up to two symbols, where the machine of four bits a step took about 19
instructions a symbol. The table is 16 KB, the size of the machine's.
- A code longer than twelve bits is read one bit at a time through `huffman.Partial`. EOS is
  thirty bits, so this read finds it when its last bit is read (invariants 7 and 12).
- A read writes two bytes, and the second is scratch when one code is whole. When the output
  has room for `decoded_len_max` bytes and one more, the reads write into that room after one
  check for the string. Otherwise each symbol goes through `write_byte`, as before.
- `core.Writer` gains `writable_slice_greedy` and `advance`, the names `std.Io.Writer` gives the
  two calls. `wire.huffman.decode` is the program that needs them. The owner chose them on
  2026-11-16 over a decoder that slices the writer's buffer itself.
- Step 29d.14 records why main kept the machine on 2026-11-05. The other decoder measured then,
  a machine of eight bits a step, needed a table of 256 KB and a build of three minutes. This
  table is 16 KB, and the probe's build took no longer.

What each check printed:
- The tests compare `decode` with `decode_by_bits` on every input of one and two bytes, and on
  4,096 longer inputs. The encoding of each longer input is decoded in every room from none to
  one byte past what `decode` asks for. No byte past the writer's buffer changes. A test
  requires the table to hold both codes of every pair whose codes fit in twelve bits, and none
  for a longer first code.
- A probe compared the decoder with main's on two million random inputs, raw and coded. Some
  were cut short, and some had a padding bit changed. Each gave the same bytes or the same error.
- The tests of `wire`, `core`, `hpack` and `qpack` pass in Debug on x86-64, under Zig's own
  backend, which GitHub's `checks` job uses.
- Zig's fuzzer, `zig build test-wire -Dfuzz --fuzz=1000000`, exited 0 three times.
- 21 mutations, each **CAUGHT**:
  - the room: no byte for the scratch, a read that counts one symbol, the count not advanced,
    and a write one byte off;
  - the checked path: a second symbol that it never writes;
  - the reads: a long code read as a short one, one bit short or without a refill, and a last
    code that fills the bits refused;
  - the refill: one after the input ends, one past the input, one a bit low, and the last word
    or a short word a byte off;
  - the end: seven bits of padding refused, padding of zeros taken, and EOS taken;
  - the table's second symbol dropped. It gives the same bytes, and it was **NOT CAUGHT**
    until the table's test;
  - `Writer`: an exact fit refused, a slice from the buffer's start, and an advance one byte
    past.
- Callgrind on a laptop's Linux VM, never published (decision 32), counted the three strings of
  an h2load request over h3. They are 35 coded bytes and 48 symbols. The count fell from 1,151
  instructions to 718. In the probe, windows of 10, 11, 12 and 13 bits took 818, 653, 627 and
  627. Of the 91 from 627 to 718, the two calls of `Writer` with their assertions cost about 30,
  and the bound on the loop's slow passes about 34.
- `tools/ci.sh` passed on the tree of this record.

The judge, [run 43994485300](https://github.com/c4milo/colibri/actions/runs/43994485300),
measured it against `f8db00c4` with the h3 inputs, at 10 rounds. It counts instructions per
request, or per connection for the `one` inputs. The base and the change are the first job's
medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-routes-many | 15,879 | 15,698 | 0.9886 | 0.9884 | wins in both |
| h3-many | 28,077 | 27,879 | 0.9930 | 0.9863 | within the noise |
| h3-bbr-many | 28,314 | 27,923 | 0.9862 | 0.9962 | within the noise |
| h3-one | 1,314,510 | 1,313,596 | 0.9993 | 0.9983 | within the noise |
| h3-bbr-one | 1,317,118 | 1,318,015 | 1.0007 | 0.9991 | within the noise |
| h2-many | 13,088 | 13,083 | 0.9996 | 1.0003 | within the noise |
| h2-one | 149,694 | 149,771 | 1.0005 | 0.9964 | within the noise |

The other four h2 inputs stay within the noise in both jobs, and no input loses. Each request of
h2-routes-many names a new path, which h2load codes in Huffman. On it the server's user
instructions fell by about 181 a request in both jobs. On h3-many they fell by 279 and 375,
inside the h3 inputs' spread of 1.8% to 3.3%. The probe on the laptop gave 433.
