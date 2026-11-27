# Decision 164: Line coverage comes from pepegrillo's tool under kcov, and the badge from a named CI run

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-15, as connect-zig's decision 43.
- Zig 0.16 has no line coverage of its own for tests. pepegrillo's `coverage` tool, pinned at
  `97e7cfd`, runs each library module's test binary under kcov 43. It prints each module's
  share of lines and a total. At `580a9d1` the tool's comptime check passed Zig's default
  branch quota with colibri's 17 directories, and `97e7cfd` raises that quota.
- `zig build line-coverage` builds the tests of the 17 modules that the package exports
  (decision 86), and of `tls-keylog`, in Debug with LLVM. Zig's own x86-64 backend writes an
  incomplete line table. `tools/line_coverage_check.sh` runs the step on Linux, in an
  ubuntu:26.04 container when the host has no kcov 43. `tools/ci.sh` runs it on Linux and
  skips it on another host.
- Zig compiles only the functions that code references, so the share is of the lines that
  the tests compile. The test blocks in the counted directories count too.
- The README's badge is a static shields.io badge. A commit takes its number from a named CI
  run of the check.

The alternatives refused:
- Codecov, which needs an account and a token in the repository's secrets.
- A JSON file that the workflow pushes to a branch, for a shields.io endpoint badge. It needs
  a step in the workflow file that writes to the repository.
