# Decision 47: Every check runs on each push to main, and the run leaves a report

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-19, to spot regressions in interoperability and performance. This
amends the premise of entry 34, "there is no CI here"; its two layers stay.
`.github/workflows/ci.yml` installs Zig, h2spec and h2load, each pinned by checksum, and runs
`tools/ci.sh`, which a person can run by hand for the same answer. The script runs the format check,
`zig build test`, the three simulator checks in Debug and ReleaseSafe, `tools/h2spec.sh` and
`tools/h2_interop.sh`, and it runs every section even after one fails, so the report is whole. The
report is Markdown on the run's summary page and an artifact named for the commit.

The report keeps two kinds of number apart. The test count, the simulator's checksums and the
counted costs of entry 34's cheap layer are exact: a change in one is a change in the code, and
`zig build test` already fails on it. The h2load throughput is indicative. A hosted runner pins
no core and fixes no governor, which entry 33 requires of a published number, so the figure
shows a large regression and proves nothing about a small one. It carries no threshold, and
entry 32 holds: it comes from Linux with the machine written beside it.

Two alternatives lost. A self-hosted Linux runner would meet entry 33 and make the throughput
a baseline with a threshold; it costs a machine to keep, and the same script runs there the day
one exists. Committing each report to a branch would keep the history past the 90 days an
artifact lives, and it would give the workflow write access to the repository, which a job
that runs on every push should not hold.

Amended by the owner on 2026-09-25, for design §8 step 15d: the HTTP Garden runs in a job of
its own, started by hand and every Monday, and not in `tools/ci.sh`. It builds every origin
the Garden carries from source, which takes hours and tens of GB, past the 45 minutes of the
push job. Its work is still one script, `tools/http_garden.sh`, which a person on Linux runs
for the same answer; the job adds only what a hosted runner lacks: uv, and room on the disk.
The alternatives offered: a manual job alone, which lets the comparison go stale while colibri
changes; and a person running it on Linux with no job, which leaves no record between runs.

Amended by the owner on 2026-09-27, for design §8 steps 9e and 12: `tools/h3spec.sh` joins
`tools/ci.sh`, and the QUIC Interop Runner, `tools/interop.sh`, runs in a job of its own,
started by hand and every Monday. Until then neither ran in CI, although CLAUDE.md said both
did. h3spec has passed all 49 of its cases in every run design §8 records since 2026-09-25, and
it tests the endpoint that h2spec's section has already built. The runner stays out of the
push job for three reasons:

- It takes about 30 minutes against quic-go in both roles, and the push job took about 25 of
  its 45 minutes on `13b7dbd`.
- It needs tshark from Wireshark 4.5.0 or newer. Ubuntu 24.04 packages 4.2 and Ubuntu 26.04
  packages 4.6, so its job runs on Ubuntu 26.04.
- Its `handshakeloss` case with colibri as the client failed some runs against quic-go's
  server, because the runner counted one client connection twice
  ([#72](https://github.com/c4milo/colibri/issues/72)). A push should not fail on that.
  Decision 99, ruled the same day, patches the count, so this reason no longer holds.

Its work is still one script, which a person runs for the same answer; the job adds only what
a hosted runner lacks: Zig and the directory in its global cache that its fetch of a zip
package needs, tshark, and the kernel module the simulator's IPv6 needs. The
alternatives offered: both checks in the push job, which needs a longer limit and fails a push
whenever `handshakeloss` fails; h3spec in the push job and the runner by hand alone, which
leaves no record between runs; and CLAUDE.md corrected to say both run by hand, with nothing
added to CI.

Amended again by the owner on 2026-09-27, after those jobs first ran, so that CI runs four
checks it did not:

- The push job runs the tests in ReleaseSafe as well as in Debug. ReleaseSafe is the mode
  colibri ships in, and until then only the simulator ran in both.
- The push job builds the Lean proofs. It installs the Lean release that
  `spec/lean/lean-toolchain` pins, checked against its SHA-256, and fails when the workflow and
  that file name different releases. Until then `tools/ci.sh` skipped the proofs, because no
  hosted runner has lake.
- A job of its own runs `zig build test` on Linux arm64 on each push. Every simulator check
  pins its census in its test, so a pass shows that a seed replays byte-identically on a second
  architecture, and the tests run over chapulin's objects built with the Arm AES instructions.
  The job is the third exception to the rule that a new check joins `tools/ci.sh`: its work is
  one `zig build` step, which a person on an arm64 machine runs as it is.
- The runner job runs against ngtcp2, neqo and quinn as well as quic-go. Each pairing of a
  server and a client takes about 7 minutes, so that job's limit rises from 90 minutes to 150,
  and the push job's from 45 to 60 for the two sections it gains.

The alternatives offered and not taken: commit messages linted in CI, as the pre-push hook
lints them; more simulator seeds and coverage-guided fuzzing every Monday; and
`tools/h3load.sh` in CI, which stays a check a person runs.

Amended a third time by the owner on 2026-09-27: the arm64 job runs on macOS 26 as well as on
Linux, on GitHub's standard macOS runners, which cost a public repository nothing. macOS on
arm64 is the development host, where until then a person ran every check by hand; the job runs
`zig build test` there on each push, with the test endpoints on Rotor's kqueue backend. The
checks that need Docker stay on Linux, because GitHub's Apple Silicon runners have no Docker.

Amended by the owner on 2026-09-30, for design §8 step 13: `bench/run.sh` runs in a workflow
of its own, `.github/workflows/bench.yml`, which a person starts with a base to compare
against, and in no push job. Entry 33 as amended makes its `ubuntu-24.04-arm` runner the judge,
and an A/B builds two trees and measures each over many rounds, which the push job's hour does
not hold. The work is still one script, which a person on Linux runs for the same answer; the
workflow adds the base's checkout and `perf`, which the script runs as root, so that it counts
the kernel's instructions and reads the system call tracepoint with no kernel setting changed.

Amended by the owner on 2026-11-02, for https://github.com/c4milo/colibri/issues/115: the push
job runs on Ubuntu 26.04 and not on Ubuntu 24.04. `tools/tls_openssl.sh` needs an OpenSSL that
offers ML-KEM-1024 and speaks QUIC, 3.5 or newer. Ubuntu 26.04 packages 3.5, and Ubuntu 24.04
packages 3.0. The alternatives offered: OpenSSL from a Docker image pinned by digest, which the
job pulls on each push; and the openssl on the path, with the check skipped where it offers no
ML-KEM-1024, so that no hosted runner ran it.
The same day the owner asked that every job run on the latest Ubuntu LTS. The arm64 job moves
to `ubuntu-26.04-arm`, and the HTTP Garden's job to `ubuntu-26.04`. The judge of
`.github/workflows/bench.yml` stays on `ubuntu-24.04-arm` until the owner rules, because a new
runner changes every baseline (decision 33).

Amended by the owner on 2026-11-05, with entry 67 as amended the same day. The TLA+ models
took 51 of the push job's 100 minutes. These rulings apply:

- The models at their full bounds, and every seed of each trace run, run in a job of their
  own, `tla`, every night and when a person starts the workflow.
- The `tla` job is the fourth exception to the rule that a new check joins `tools/ci.sh`. Its
  work is `zig build tla` and the seven trace scripts, which a person runs for the same answer.
- The report of `tools/ci.sh` gives the wall time of each section and of the whole run, so a
  later change to a job's limit starts from a measured number.

A scheduled run starts every job whose condition holds. So each scheduled job's condition names
its own cron line, and the Monday jobs do not run every night.

The first ruling of that day also kept a quick tier of the models in the push job, for the
paths that changed since the newest push run that passed. The second ruling below replaces
that part.

Amended a second time by the owner on 2026-11-05. The push job runs no TLC:

- `tools/ci.sh` skips the TLA+ models and the seven trace checks by default. Its report has a
  row that says so and names the nightly job.
- `CI_TLA=all` makes `tools/ci.sh` check every model and run the seven trace checks over every
  seed. It refuses any other value, so a mistyped value does not skip the checks unseen.
- The push job has no Java step and does not read the earlier runs of the workflow. The `tla`
  job is the one job that runs TLC.

The alternatives offered and not taken: the full set on each push, which took 51 minutes; and
the quick tier on each push, which the first ruling chose. Entry 67 as amended a second time
gives the cost.

Amended by the owner on 2026-11-22: the two jobs that run on each push to main, `tools/ci.sh
(x86-64 Linux)` and `zig build test (arm64 ...)`, run on each pull request to main too.

- A change is checked before it merges. Until then CI ran only once a change was on main, so
  [#145](https://github.com/c4milo/colibri/pull/145) merged with no run of CI.
- Each job has a queue for each ref. Main keeps one run at a time, as before. A pull request
  never waits for main's run, and a new push to it ends its older run.
- The weekly jobs and the nightly job do not run on a pull request.
- A rule of the repository, and not this workflow, makes the two jobs required for a merge.
