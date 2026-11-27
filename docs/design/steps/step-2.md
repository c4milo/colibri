# Design §8 step 2: the deterministic driver

[Design §8, the build plan](../../design.md#8-build-plan)

A seeded harness that feeds bytes in arbitrary chunks, supplies instants, and substitutes null TLS
and crypto providers. This is the simulator for the h2 half, and it exists before there is a
connection to drive, which is possible only because §4 put I/O, time and crypto in the caller's
hands. **Check:** the step 1 decoders driven through the harness at seeded chunk boundaries over a
seed range, with the §6.6 trace records compared byte for byte across macOS and Linux and across
Debug and ReleaseSafe. What this does and does not prove: at step 2 nothing but the harness can
differ, so it shows the harness is self-consistent. The same check re-run over a connection at step
4 is the first point at which it can fail for any other reason. *Small.*

**Check passed on macOS, 2026-09-16.** `zig build test` exits 0 on Zig 0.16.0, macOS 25.6,
arm64, in Debug and with `-Drelease`, and the lint scores 460 functions with a highest score
of 12. `zig build sim -- --chunk-check` prints the same census in both modes:
`seeds=256 passed=193 rejected=63 chunks=2551 trace_octets=278839 crc32=0x11c9c07a`. That digest
is `chunk_check.census_crc32_expected` and the check's test requires it.

**Check passed on Linux, 2026-09-18, on two architectures**
([issue 1](https://github.com/c4milo/colibri/issues/1)). Debian bookworm with glibc, Zig 0.16.0,
under OrbStack on the development Mac, once on aarch64 and once on x86-64. `zig build test`
passes 622 tests on x86-64, and all three checks print what macOS prints, in Debug and with
`-Drelease`:

| Check | Census |
|---|---|
| chunk | `seeds=256 passed=193 rejected=63 chunks=2551 trace_octets=278839 crc32=0x11c9c07a` |
| connection | `seeds=256 passed=195 rejected=61 frames=4670 chunks=9636 trace_octets=588870 crc32=0xe8f7c0b4` |
| tls | `seeds=256 events=512 crc32=0x795236bd` |

Two qualifications, so the claim is read for what it is. The x86-64 run is Zig's own x86-64 code
generation, which is the part determinism depends on, executed under Rosetta rather than on
x86-64 hardware. And every run so far is little-endian; a big-endian host would test the
byte-order rules of §2.2 harder than any of these do.

- **Harness.** `src/sim/` holds `Random`, SplitMix64 written out so a Zig upgrade cannot change
  what a seed replays; `Clock`, which moves only when the pipe advances it; `Trace`, the §6.6
  format over a `core.Writer`; and `pipe.run`, which feeds a stream to any subject with `step`
  and `describe` in chunks of 1 to `chunk_len_max` bytes after delays of up to
  `chunk_delay_ns_max`, writing a `feed` record per chunk and an `accept` or `reject` per value.
- **Check.** `src/sim/chunk_check.zig`, in the `sim_run` module. Each seed draws 1 to 16 values
  across the varint, the prefixed integer at every prefix size, and the string literal at every
  prefix size in both codings, and one seed in four appends an encoding a decoder refuses. The
  seed runs chunked twice and in one piece once: the two chunked traces must match byte for
  byte with the same draw count, the chunked run's accept and reject records must be the
  one-piece run's, the outcome must be what the plan says, and the run in one piece must feed
  exactly once, without which the comparison is vacuous.
- **Driver.** `zig build sim -- --chunk-seed <hex>` prints one seed's chunked trace and its
  outcome; `--chunk-check [seeds]` prints the census or the seed that failed.
  `src/sim/run_main.zig` is the one file under `src/sim/` the `io` rule exempts, by path.
- **Not built.** The null TLS provider and the null crypto suite. `tls.Provider` and
  `crypto.Suite` do not exist yet, and no step 2 subject calls a provider, so each null
  implementation lands with the step that shapes its vtable: the provider with step 5
  ([issue 3](https://github.com/c4milo/colibri/issues/3)), the suite with step 7
  ([issue 4](https://github.com/c4milo/colibri/issues/4); design §10 fixes its sizes: a
  16-byte tag and a 5-byte mask).

Twenty-nine mutations over the generator, the clock, the trace, the pipe, the stream, the check
and the command line were applied, run against `zig build test-sim` or `test-sim-run`, and
reverted, plus three over the `wire` decoders, which the check must see: every one **CAUGHT**,
eight after a new test. The three that mattered most: a chunked run replaced by a run in one
piece, the reverse, and a replay restarted from the seed rather than from the generator as it
stood after the stream was drawn.
