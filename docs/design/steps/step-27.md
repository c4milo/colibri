# Design §8 step 27: CUBIC

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 133](../../decisions/0133-the-congestion-controller-is-cubic-in.md) replaces RFC 9002 §7's NewReno with CUBIC (RFC 9438) in
`recovery_congestion.zig`, with RFC 9438's arithmetic in integers in `recovery_cubic.zig`.
`Congestion.on_ack` takes the instant and the smoothed round trip.
`quic.constants.congestion_loss_reduction_divisor` goes, and `quic.constants.cubic` holds the new
constants; no other public name changes.
- **Check.** Tests drive each region of RFC 9438 §4: the Reno-friendly estimate after a
  decrease, the climb back to W_max by K, the decrease to 0.7, fast convergence, the time the
  sender was limited left out of `t`, and K = 0 after persistent congestion. In the Linux
  container of step 13i, colibri's p99 under `lossy` and `mobile` comes no worse than with
  NewReno, and nearer quinn's with CUBIC. The judge's `network` run then measures it.

  **Check met in the container, 2026-10-29.** The container of step 26 ran the tree before and
  after this step, two runs each. Under `mobile` at 4,000 req/s colibri reached 2,931 and 2,919
  req/s where it reached 2,680 and 2,597, with p99 from 3,150 and 3,468 ms to 2,734 and 2,763
  ms. The other rows moved less than the runs differ. The full `zig build test` passed 3,377 of
  3,377. Nine pinned censuses moved, the same in Debug and ReleaseSafe. `zig build lean` proves
  the cube root exact and the target between the window and 1.5 times it. TLC holds
  `spec/tla/cubic_congestion` over 1,958,541 states, and finds each of its six mutants.

  **The judge, 2026-10-29.** [Run 40976209928](https://github.com/c4milo/colibri/actions/runs/40976209928)
  measured `cfded975` against main `087939dc` with `h3`: every h2 and h3 input is within the
  noise. [Run 40976195250](https://github.com/c4milo/colibri/actions/runs/40976195250), the
  `network` input on `cfded975`, gives colibri's p99 over h3 at 4,000 req/s, job 1 and then job 2:
  - `lossy`: 106.68 and 109.48 ms, where step 26 gave 116 ms. chi gave 106.64 and 106.95 ms.
  - `mobile`: colibri reaches 3,223 and 3,211 req/s, where step 26 reached 3,082. chi reaches
    3,284 and 3,274, and axum 3,102. colibri's p99 is 1,973 and 2,054 ms, and chi's 1,856 and
    1,885 ms.
- **Next.** HyStart++ (RFC 9406), which RFC 9438 §4.10 says CUBIC SHOULD use, and BBRv3
  beside CUBIC ([decision 134](../../decisions/0134-colibri-may-read-the-bbr-draft.md)).
