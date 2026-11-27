# Design §8 step 15a: the message parsers and writers

[Design §8, the build plan](../../design.md#8-build-plan)

What RFC 9112 §2 to §7 put on the wire:
- the request line (§3) and the status line (§4), with each element separated by one SP, and
  HTTP-version case-sensitive (§2.3);
- the request-target in its four forms (§3.2), and the Host rules a server holds a request to
  (§3.2): 400 for none, for more than one, or for an invalid value;
- field lines (§5): a field name and a colon with no whitespace between, which a server refuses
  with 400 (§5.1), and OWS trimmed from the value;
- obs-fold (§5.2): a server refuses it with 400, and a client replaces each one with SP, which
  §5.2 makes a user agent's MUST;
- a bare CR is invalid (§2.2), and so is whitespace between the start line and the first field
  line (§2.2);
- §6.3's eight rules for the length of a body, with `http.content_length` for the list rule
  of item 5, and §6.1's rules for Transfer-Encoding with Content-Length and in HTTP/1.0;
- the chunked coding (§7.1): the chunk size with no overflow, chunk extensions skipped within a
  named limit, the last chunk, and the trailer section.

A parser reads a start line and field section only when the whole of it is in the caller's
slice, up to a named limit, as h2 reads a whole frame (§4.1). Where RFC 9112 leaves a choice,
such as a lone LF as a line end (§2.2) or whitespace other than SP between elements (§3, §4),
colibri takes the strict side and refuses, because §11.2 traces request smuggling to parsers
that differ in what they forgive. **Check:** a golden corpus with a manifest, valid and invalid,
carrying one case per refusal and the smuggling shapes: Content-Length with Transfer-Encoding,
`Transfer-Encoding: chunked` hidden behind whitespace or repeated, a chunk size that overflows,
and obs-fold in a request. The step 2 byte pipe feeds every parser at seeded splits, and each
split must give what the whole input gives. Fuzzing and mutations.

**Check passed, 2026-09-25**, `91316b0` to `df09b96`, on macOS arm64 with Zig 0.16.0.
- `91316b0`: the head. A resumable scanner finds a head's end, scanning each byte once however
  the head arrives, and refuses a bare CR and a lone LF. The start line and the field lines are
  read into `http.FieldSection`, and a client joins obs-fold with SP (RFC 9112 §5.2).
- `c6257c2` and `6b8e1ca`: RFC 3986 in `docs/rfcs/`, and its grammar for host, port, authority,
  origin-form and absolute-URI in `http.uri`.
- `694f1c8`: the request-target's form and the Host rules of RFC 9112 §3.2.
- `1be3578`: §6.3's eight rules for the length of a body, and decision 91's codings.
- `043d357`: the chunked decoder, which returns data as slices of the caller's bytes.
- `f55aa0b`: the request, response and chunk writers, which refuse what colibri would refuse
  to read.
- `d42b181`: the golden corpus, 32 request and 12 response cases. The owner raised
  `case_len_max` to 256 and `manifest_len_max` to 32,768, and `decoded_len_max` doubled with them.
- `bdeb891`: the split check, below.
- `df09b96`: fuzz properties for the head and chunked parsers.

What each check printed:
- `zig build test`: 1730 of 1794 tests passed, 64 skipped. That run includes `golden-check`,
  which decodes every h11 case to its verdict.
- `zig build sim -- --h11-split-check`, in Debug and in ReleaseSafe: `h11-split: seeds=256
  passed=170 rejected=86 messages=522 chunks=7161 trace_octets=69565 crc32=0x793d2f38`. Every
  seed read in seeded chunks what it read in one piece, every body matched the plan's, and each
  of the 86 planted defects was refused with its error.
- `zig build test-h11 --fuzz=1M` does not build: Zig 0.16.0's own test runner fails to compile
  in fuzz mode, as it does for every module
  ([#53](https://github.com/c4milo/colibri/issues/53)). The fuzz properties run over their corpus
  and every input of up to two bytes.
- Mutations: 121 CAUGHT and 1 equivalent. By commit: 19 in the head, 17 of 18 in the URI
  grammar, 16 in the target and Host rules, 23 in the body rules, 18 in the chunked decoder, 17
  in the writers, 6 caught by the corpus alone, 3 caught by the split check alone, and 2 in the
  fuzz properties. The equivalent mutant lets userinfo hold "@", which the first "@" always
  ends.

**RFC 7405, 2026-09-29.** RFC 9110 §2.1 and RFC 9112 §1.2 write their grammar in RFC 5234's
ABNF with RFC 7405's `%s` prefix, and `docs/rfcs/` now holds RFC 7405. Its §2.1 replaced the
note in RFC 5234 §2.3 that made every quoted string match in any case, and keeps that rule for a
string with no prefix, so the four citations of the rule now name RFC 7405 §2.1. `http.uri`
names RFC 3986 §3.2.2 instead, which says itself that IPvFuture's "v" is case-insensitive.
- colibri reads three `%s` strings, and compares each byte for byte: HTTP-name in h11 (RFC 9112
  §2.3), the weak prefix `W/` in the server's ETag (RFC 9110 §8.8.3), and `clear` in the
  client's Alt-Svc (RFC 7838 §3). RFC 9110 §5.6.7's HTTP-date uses `%s` too, and colibri parses
  no HTTP-date.
- Mutations, on macOS arm64 with Zig 0.16.0: HTTP-name compared in any case, `clear` compared in
  any case, and TE's "trailers" compared exactly, each **CAUGHT**. Two were **NOT CAUGHT**: the
  weak prefix compared in any case, and an IPvFuture that starts with "V" refused. A test for
  each now catches it.
