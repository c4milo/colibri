# Design §8 step 52: line coverage, ruled 2026-11-15

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 164](../../decisions/0164-line-coverage-comes-from-pepegrillos-tool.md).
- `zig build line-coverage` (`build/line_coverage.zig`, `tools/line_coverage.zig`) runs the
  tests of the 17 library modules and of `tls-keylog` under kcov 43, through pepegrillo's
  `coverage` tool. `tools/line_coverage_check.sh` runs it on Linux, and `tools/ci.sh` holds it.
- pepegrillo moves from `9ae244b` to `97e7cfd`. `580a9d1` added the tool, and `97e7cfd` raised
  its branch quota for 17 directories, with a test that names them.
- **The first count**, on an Apple M1 Pro in an ubuntu:26.04 container (arm64, kcov 43), took
  190 s: 98.2% of 69,142 lines. Each module was between 96.8% (`core`) and 100% (`crypto` and
  `tls_provider`), with `quic` at 98.2% of 18,178 lines and `server` at 98.0% of 15,400. The
  README's badge takes its number from GitHub's first run of the check on main.
- **GitHub's first count.** The `checks` job of
  [run 43727822114](https://github.com/c4milo/colibri/actions/runs/43727822114) ran the check on
  `91673c6d`, x86-64 Linux, in an ubuntu:26.04 container, in 3 minutes 29 seconds: 98.7% of
  69,583 lines. Each module was between 97.3% (`core`) and 100% (`tls_provider`, `crypto` and
  `qlog`). The x86-64 build compiles a few more lines than the arm64 one, which counted 98.2%.
  The README's badge shows 98.7% and links to the run.
