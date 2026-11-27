# Design §8 step 26: several STREAM frames in a packet

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 131](../../decisions/0131-a-packet-carries-up-to-16.md) amends decision 56: an application-level packet carries up
to 16 STREAM frames, and a ring holds each record's ranges after its first (INV-33). It adds no
public name.
- **Check.** In the Linux container of step 13i's lossy run, colibri sends fewer packets for
  the same requests, and its p99 at 4,000 requests a second comes within 1.2 times quic-go's.
  The judge's `network` run then compares colibri's h3 against h2-tls again. Every stream range
  a record names reads back after the ring wraps, a lost packet resends each of its ranges,
  and an acknowledged one counts each of them once (INV-29). The owner restated the check on
  2026-10-29: it first asked for half the packets, and the run below sent 59%.

  **Check met in the container, 2026-10-29.** An Ubuntu 24.04 container on OrbStack's Linux 7.2
  kernel ran colibri's UDP server in its `h3 routes=github no-gso` mode, under oha with 8
  connections of 64 streams, two runs each, against the tree before and after this step:
  - `lossy`, 4,000 req/s: p50 from 96 and 99 ms to 56 and 57 ms, and p99 from 231 and 258 ms to
    133 and 143 ms. quic-go's chi gave 54 ms and 121 ms. One connection sent 3,882 packets where
    it sent 6,594, 59%, and its median packet grew from 64 bytes to 118. Its ACK-only packets
    fell less, because they carry no STREAM frame.
  - `mobile`, 2,000 req/s: colibri reached 2,001 req/s where it reached 1,699, with p50 from
    837 ms to 126 ms and p99 from 1,729 ms to 415 ms. chi reached 2,010, with 112 ms and 257 ms.
    The gap that is left fits the congestion controller: NewReno halves the window on a loss,
    where quic-go's CUBIC keeps 0.7 of it.
  - The full `zig build test` passed 3,361 of 3,361. Nine pinned censuses moved with the
    packets, the same in Debug and ReleaseSafe: the h3 check's qlog holds 31,894 events where
    it held 50,487. `quic.Connection` grew by 34,824 bytes, and a server's QUIC slot by 38,920.

  **The judge, 2026-10-29.** [Run 40950828136](https://github.com/c4milo/colibri/actions/runs/40950828136)
  measured `b5f74c3d` against main `2afba28b` with `h3`. h3-many takes 0.684 and 0.686 of main's
  instructions a request, and h3-one 0.969 and 0.969: fewer packets, so fewer seals and sends.
  Every h2 input is within the noise. [Run 40950751199](https://github.com/c4milo/colibri/actions/runs/40950751199),
  the `network` input on `b5f74c3d`, gives colibri's p99 over h3 divided by its p99 over h2-tls,
  job 1 and then job 2:
  - `lossy`: 0.69 and 0.73 at 2,000 req/s, and 0.78 and 0.78 at 4,000, where they were 1.34 and
    1.32. At 4,000 colibri's p99 over h3 is 116 ms, chi's 107 ms and axum's 108 ms.
  - `mobile`: 0.75 and 0.80 at 2,000 req/s, where they were 5.02 and 4.46. At 4,000 no server
    reaches the rate: colibri reaches 3,082 req/s, chi 3,273 and axum 3,014.
