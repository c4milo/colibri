# Design §8 step 28: HyStart++

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 135](../../decisions/0135-cubics-first-slow-start-is-hystart.md) runs RFC 9406's HyStart++ in CUBIC's first slow start, in
`recovery_hystart.zig`, as RFC 9438 §4.10 asks. It adds one public name, `quic.constants.hystart`,
which holds RFC 9406 §4.3's constants.
- **Check.** Tests drive each move of RFC 9406 §4.2: the exit to CSS when a round's minimum
  round trip grows by the threshold, the return to slow start when it falls below the
  baseline, the entry to congestion avoidance after CSS_ROUNDS rounds, the end at a congestion
  event, and no HyStart++ after the first slow start. `spec/lean/Colibri/Quic/HyStart.lean`
  proves the threshold's bounds and that CSS ends within CSS_ROUNDS rounds, and its vectors
  hold the Zig to the proved steps. `spec/tla/hystart` checks the moves in every order. In the
  Linux container of step 13i, colibri's p99 under each profile comes no worse than with step
  27. The judge's `network` run then measures it.

  **Check met, 2026-10-30.** The full `zig build test` passed 3,388 of 3,388, in Debug and in
  ReleaseSafe; the endpoint check's two censuses moved, and `quic.Connection` grew by 72
  bytes. `zig build lean` proves the five theorems of `HyStart.lean`, and its 613 vector lines
  match the Zig. TLC holds `spec/tla/hystart` over 6,367 states and finds each of its five
  mutants. `tools/ci.sh` passed 37 of 37 on `b35a12b0`. In the container, eight rounds of
  `far` at 4,000 req/s gave p99s from 63 to 111 ms before this step and from 66 to 140 ms
  after it; `lossy` and `mobile` moved less than the rounds differ.

  **The judge, 2026-10-30.** [Run 40995852953](https://github.com/c4milo/colibri/actions/runs/40995852953)
  measured `b35a12b0` against main `1014dd32` with `h3`: every h2 and h3 input is within the
  noise. [Run 40995845275](https://github.com/c4milo/colibri/actions/runs/40995845275), the
  `network` input on `b35a12b0`, gives colibri's p99 over h3 at 4,000 req/s, job 1 and then
  job 2, beside step 27's:
  - `far`: 61.64 and 61.66 ms, where step 27 gave 61.46 ms in job 2.
  - `lossy`: 109.94 and 107.92 ms, where step 27 gave 106.68 and 109.48 ms.
  - `mobile`: 3,232 and 3,246 req/s, and 1,988 and 1,991 ms, where step 27 gave 3,223 and
    3,211 req/s, and 1,973 and 2,054 ms.
  - Every round of every rate answered 200 to every request. With step 27, one round of
    `mobile` at 4,000 did not: a client's first key update came before the server opened any
    1-RTT packet, and `cd131e39` fixed it (RFC 9001 §6.1, §6.2).

  The loads above are application-limited, so the window rarely grows and HyStart++ has little
  to act on. It costs nothing measurable there.
