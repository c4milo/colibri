# The client's zstd and br fixtures

The client's tests decode these files (decision 101 as amended, design §8 step 17h,
https://github.com/c4milo/colibri/issues/80). stdx writes no `zstd` or `br` encoder yet, so the
files come from the reference programs. They were written once, on 2026-09-30, with Zstandard's
`zstd` 1.5.7 and Google's `brotli` 1.2.0, and nothing writes them again.

```sh
python3 -c "import sys; sys.stdout.write(''.join(f'{i:04} colibri decodes zstd and br content codings\n' for i in range(160)))" > plain.txt
zstd -19 -q -c plain.txt > plain.zst
head -c 3000 plain.txt | zstd -3 -q -c > part1.zst
tail -c +3001 plain.txt | zstd -3 -q -c > part2.zst
cat part1.zst part2.zst > two_frames.zst
{ printf '\x5a\x2a\x4d\x18\x05\x00\x00\x00skip!'; cat plain.zst; } > skippable.zst
cat plain.txt | zstd -3 -q --zstd=wlog=24 -c > window_16mb.zst
brotli -q 11 -w 24 -c plain.txt > plain.br
brotli -q 5 --large_window=25 -c plain.txt > large_window.br
```

| File | What it is | What the client does with it |
|---|---|---|
| `plain.txt` | 160 numbered lines, 7,840 octets | The content every other file codes |
| `plain.zst` | One Zstandard frame with its XXH64 check (RFC 8878 §3.1.1) | Decodes it |
| `two_frames.zst` | Two frames, the text's first 3,000 octets and the rest (§3.1) | Decodes both, one after the other |
| `skippable.zst` | A skippable frame of five octets, then `plain.zst` (§3.1.2) | Skips the first, decodes the second |
| `window_16mb.zst` | A frame whose Window_Size is 16 MiB, since `zstd` read an input of no known size | Refuses it: RFC 9659 §3 holds the `zstd` coding to 8 MB |
| `plain.br` | A brotli stream with WBITS 24, a window of 16 MiB less 16 octets (RFC 7932 §9.1) | Decodes it |
| `large_window.br` | A stream `brotli --large_window` wrote, whose first seven bits are the pattern RFC 7932 §9.1 calls invalid | Refuses it |

| SHA-256 | File |
|---|---|
| `6e40960e99f24a346c24c227cf609f1aa39014b3ba99fc7cd2e3685441269ddb` | `plain.txt` |
| `4c3f3b23373d5adc7eaef70cd512959cd0c25f14dc4728a47107cae1b9e6245f` | `plain.zst` |
| `65e3a608d38bf4278e5072322c2af71a7133016b50e9550b0be6064ed8b9ec11` | `two_frames.zst` |
| `db348d6cf139fc44650c716130fb37725667cdb3b03841bb5ff1642bb926d959` | `skippable.zst` |
| `b6eb62d8825e2ceb56f10f1802de355e7862b42cca7445b09aa206564d6934b6` | `window_16mb.zst` |
| `74a618f39b09376ca0d95e35bb315b8e9cb733e2df508cb4d093d6e796100623` | `plain.br` |
| `738dde43c5a0a6fdaeae56d67a71aa18881d90c801e591b427b050c4c3d15403` | `large_window.br` |
