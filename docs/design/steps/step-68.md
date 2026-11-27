# Design §8 step 68: stdx v0.2.0, 2026-11-19

[Design §8, the build plan](../../design.md#8-build-plan)

The owner asked stdx for the core and SVE2 that chapulin v0.9.1 and v0.10.0 read, and stdx v0.2.0
(`12b8c8d7`) answers them: `platform.Cpu` gains `sve2` and `midr`.
- **The change.** colibri pins stdx v0.2.0. Each `platform.Cpu` literal of colibri's tests and
  of `tools/consumer/` names the two fields. A program that writes such a literal names them
  too, and one that calls `platform.probe()` changes nothing. The memory table grows by 16
  bytes for an engine of one TCP connection and by 8 for a client's pool, since a
  `tls.Cpu` holds the probe.
- **The N2 rule waits.** chapulin's decision 240 asks a program to leave
  `constant_time_sha3` clear on a Neoverse N2, where Keccak runs 1.8 times slower on the SHA-3
  instructions. A trial of the rule, `cpu_of` reading `midr`, lost on the judge against
  `7b06f5bd` ([run 44663625651](https://github.com/c4milo/colibri/actions/runs/44663625651)):
  h2-tls-large-many took 1,057,624 user instructions a request where it took 1,016,688,
  +4.0%, in both jobs, with cycles +0.5% and +1.3%. The same bit gives AES-GCM its EOR3 passes
  (chapulin's decision 158), and the judge's h2load offers no ML-KEM, so it shows the cost and
  not the gain. The owner ruled on 2026-11-19 to ask chapulin to split the bit, and to apply
  the rule once a chapulin release does. Until then colibri keeps the SHA-3 claim on an N2.
- **Checked, 2026-11-20,** on `88ed25e6`: the judge against `27c6e5f0`, with the h11 and h3
  inputs, found every input within the noise in both jobs
  ([run 44668386611](https://github.com/c4milo/colibri/actions/runs/44668386611)).
  h2-tls-large-many was at 1.0017 and 1.0000. `tools/ci.sh` passed 33 sections, with Zig 0.16.0
  on an Apple M1 Pro with macOS.
