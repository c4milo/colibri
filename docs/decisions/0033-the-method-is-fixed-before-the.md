# Decision 33: The method is fixed before the first measurement, so the numbers cannot be shaped later

[All decisions](../decisions.md) · Section: [Performance](../decisions.md#performance)

Pinned cores and a fixed governor; warmup discarded; at least five runs reported as median with
spread, never a best-of; the A/B against the competitor in the same session on the same kernel; and
the machine, the kernel, the certificate type, the cipher suite and the socket buffer sizes
published with the result. Instructions per connection is the primary metric because it is the most
reproducible counter across machines and frequencies, with cycles, IPC, cache misses, context
switches and syscall counts beside it.

Best-of-N is rejected because it reports the favourable tail of the noise distribution rather
than what a user sees. Anything under about 5% is treated as noise until shown otherwise: link
order and environment size alone move results by percent-scale amounts, and core assignment can
be worth far more. Loopback is not a network — its MTU and its absent driver path make every
result look better than it would on a real link — so a published number names the path it was
measured over.

Amended by the owner on 2026-09-30, for design §8 step 13: the judge is GitHub's hosted
`ubuntu-24.04-arm` runner, a Neoverse N2, which `.github/workflows/bench.yml` runs when a person
starts it, as stdx's judge runs. The method is pepegrillo's `docs/performance/performance.md`,
which `zig build guide` installs. A hosted runner fixes no governor, so the rule rests on the
count and on pairing, not on the machine:

- Instructions retired per unit, from `perf stat`, stay the primary metric: they survive the
  runner's other tenants and its clock. Cycles, task-clock and system calls per unit stand
  beside them.
- A comparison stays inside one job. The job builds a base and the change and measures them in
  turns on one runner, and a change stays only when it wins past the noise in every one of at
  least two such jobs. A number from one job is never compared with a number from another.
- The job pins the server and the load generator to cores of their own with `taskset`, and
  writes the CPU model, the kernel and the core count beside the numbers. It claims nothing
  about the governor.
- The x86-64 runner refuses `perf_event_open` and draws a different CPU from run to run, so it
  judges nothing.

The alternatives offered: a self-hosted runner on a dedicated machine, which meets this entry
as first written and costs a machine to keep; and both, the N2 runner now and a dedicated
machine for published numbers later.
