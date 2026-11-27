# Decision 144: `-Dfuzz` builds the unit tests with Zig 0.16.0's test runner, one line fixed

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-01, for decision 29
([#53](https://github.com/c4milo/colibri/issues/53)). Zig 0.16.0's runner does not compile with
`-ffuzz`. At test_runner.zig:566 it passes a `std.builtin.StackTrace` to
`std.debug.writeStackTrace`, which takes a `std.debug.StackTrace`. Zig 0.17.0 fixes the line.

The rulings:
1. `build/fuzz.zig` reads the runner from the Zig in use, replaces that one line, and gives
   the result to each unit test. The repository holds no copy of the runner.
2. `-Dfuzz` is off by default, so `zig build test` keeps Zig's own runner. A person runs
   `zig build test-<module> -Dfuzz --fuzz=<runs>`. `tools/ci.sh` does not run it.
3. When the runner no longer holds the line, the build stops and says to remove `-Dfuzz`.
   The move to Zig 0.17 removes the option and this file.

Alternatives that lost:
- A patched copy of the runner in `tools/`. It is 607 lines of Zig's code, past the file
  length limit and the heap rule, and it would not follow a Zig patch release.
- A fuzzer run in `tools/ci.sh` on each push. It adds minutes to each run, and the fuzz
  properties already run over their corpus and every input of up to two bytes.
- A wait for Zig 0.17. colibri stays at 0.16, and the fuzzer finds what the corpus does not.

Cost: the build depends on one line of Zig's runner, so another 0.16 release can stop
`-Dfuzz`. The build then says so, and `zig build test` is not affected.
