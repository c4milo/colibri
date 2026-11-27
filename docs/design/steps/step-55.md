# Design §8 step 55: no byte-loop copy in the library, 2026-11-17

[Design §8, the build plan](../../design.md#8-build-plan)

A cost that connect-zig found with its benchmark of a full stack, for v0.18.1. The owner ruled the
scope: every copy of the library.
- **The cost.** connect-zig's sink reads a gRPC export of 192,397 bytes through a stream route
  that keeps every byte unread until the body's last piece. After each piece, `keep_unread` in
  `server/router/router_body.zig` copied the held bytes onto themselves at offset 0, with
  `std.mem.copyForwards`. In Zig 0.16 that function is a loop of one byte a step, and its doc
  comment says to use `@memmove`. callgrind counted about 27 instructions a byte, and 43% of
  the instructions of 200 calls. The copy of each piece grows with the bytes held, so a body's
  cost grew with its square. `drop_read_plaintext` and `take_output` in the server's
  `connection_internal.zig` cost another 7.8% in the same loop.
- **The change.**
  - `keep_unread` copies nothing when the unread bytes already start `held`, which they do
    when the route read none of them.
  - Each of the library's 21 calls of `std.mem.copyForwards` becomes `@memmove`, with the two
    slices of equal length that it requires. The tests and the simulator keep theirs.
- **What no test catches.** The skip of the copy changes no byte, so no test fails without it.
  Its proof is the measurement below.
- **The measurement, by connect-zig, 2026-11-17.** Its OTLP sink reads each export through a
  stream route on `colibri.Server`, in ReleaseSafe, over h2 with TLS, and h2load sends the
  exports. The median of 5 rounds, the three builds in turns:

  | Export | Build | Calls a second | CPU µs a call |
  | --- | --- | ---: | ---: |
  | 16 spans, 6,271 bytes | v0.17.3 | 35,857 | 28 |
  | 16 spans, 6,271 bytes | `d9f3dd34`, v0.18.0's tree | 36,152 | 27 |
  | 16 spans, 6,271 bytes | `ed40807b`, this step | 62,102 | 16 |
  | 512 spans, 192,397 bytes | v0.17.3 | 817 | 1,222 |
  | 512 spans, 192,397 bytes | `d9f3dd34` | 819 | 1,220 |
  | 512 spans, 192,397 bytes | `ed40807b` | 1,997 | 495 |

  - The machine: an Apple M1 Pro, in an OrbStack Linux VM, kernel 7.2.12, aarch64. Other
    builds ran on the host, so the builds ran in turns. Decision 32 publishes no number of a
    laptop, so these numbers order the builds and are not a published claim.
  - The command: the sink `taskset -c 1 otlp-sink 14317`, built from connect-zig `8cf269e` with
    `zig build otlp-sink -Drelease -Dtarget=aarch64-linux`. A warm run of a tenth of the calls,
    then `taskset -c 2,3 h2load -n <40000 or 4000> -c 16 -m 4 -t 2
    --tls13-ciphers=TLS_AES_128_GCM_SHA256 -d <export>` to its gRPC method. The CPU time is the
    server's utime and stime from `/proc/<pid>/stat` over the measured calls.
  - Every call of every round succeeded.
- **Checked, 2026-11-17,** on `ed40807b`:
  - The judge measured it against `d9f3dd34` in two jobs, with the h11 inputs
    ([run 44026995045](https://github.com/c4milo/colibri/actions/runs/44026995045)). h2-tls-many
    wins in both jobs, 0.9819 and 0.9825, from the shift of the TLS plaintext buffer, and
    h11-tls-many in one, 0.9899. Each other input is within the noise, and none loses.
  - `tools/ci.sh` passed 31 sections, with Zig 0.16.0 on an Apple M1 Pro with macOS.
  - `zig build test` passed. The step adds no test, so no run on x86-64 Debug preceded the
    push; GitHub's `tools/ci.sh (x86-64 Linux)` job runs every test there.
- **The published numbers, by connect-zig's CI, 2026-11-17.** Run 169 pins v0.18.1, on an Intel
  Xeon Platinum 8370C with 4 vCPUs and Linux 7.0.0-1017-azure, and runs the OpenTelemetry
  Collector on the same load as a control. The median of 3 rounds:

  | Export | connect-zig on colibri | The Collector |
  | --- | ---: | ---: |
  | 16 spans, 6,271 bytes | 40,753 calls a second, 24.5 µs a call | 13,042, 76.5 µs |
  | 512 spans, 192,397 bytes | 1,271 calls a second, 782.5 µs a call | 706, 1,412.5 µs |

  - Run 168 pinned v0.17.3 on an AMD EPYC 9V45, so the two runs' times do not compare. Their
    ratio to the Collector does: from 2.23 to 3.12 times at 16 spans, and from 1.26 to 1.80
    times at 512 spans.
  - [Run 169](https://github.com/c4milo/connect-zig/actions/runs/44076765191) and
    [run 168](https://github.com/c4milo/connect-zig/actions/runs/44024752259).
  - connect-zig's own judge counts 13 instructions more for each routed call on v0.18.1 than on
    v0.17.3, 0.3%, under callgrind on x86-64-v3, and 23 more for its medium call. Its engine
    there runs no TLS and no h2 framing. Nobody traced the 13 yet. colibri's judge found no
    input that lost.
- **The tests, the simulator and the examples,** commit `ef53f2af`: their 40 calls of
  `std.mem.copyForwards` and `std.mem.copyBackwards` became `@memmove` too, so the tree holds
  none. `tools/ci.sh` passed 31 sections.
- **The rule, 2026-11-19.** The owner asked pepegrillo for a lint rule that refuses the standard
  library's calls known to be slow where a better call exists. pepegrillo's `slow_std` landed in
  its commit `b618bb4`, with `std.mem.copyForwards` and `std.mem.copyBackwards` as its entries.
  colibri pins pepegrillo at `a90cc29`, whose guide states the rule's evidence, and runs the rule
  as `slow-std` over every Zig file the other rules read (`tools/lint/slow_std.zig`). The tree
  holds no such call, so the rule found nothing. The canary of `build/lint.zig` holds one, and
  the lint reports it. pepegrillo's pre-push hook did not change.
  - The same pin raised pepegrillo's default limits of a commit's body from 3 paragraphs and 100
    words to 4 and 150, which its commit `60b03e2` made at the owner's word of 2026-11-16. On
    2026-11-19 the owner ruled that colibri follows them. CLAUDE.md (Commits) states 4 and 150,
    and `tools/commit_lint.zig` takes pepegrillo's defaults.
  - Five mutations, each CAUGHT: the canary without its slow-std line, `build/` out of the
    rule's scope, the rule not registered, and colibri's old limit of 100 words or of 3
    paragraphs put back.
