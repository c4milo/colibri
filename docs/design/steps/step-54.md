# Design §8 step 54: the router's branch quota on a table of many routes, 2026-11-17

[Design §8, the build plan](../../design.md#8-build-plan)

A fault that connect-zig found with its benchmark of a routed call, for the release after v0.17.3.
- **The fault.** Five functions of `server/router/router_pool.zig` switch over every route with
  `inline else`, which makes one prong for each route. `start`, `on_finished` and `finish` raise
  Zig's default quota of 1,000 backwards branches to `branch_quota`, which grows with the routes.
  `on_body` and `on_writable` raised none. A table of 256 struct routes, 16 services of 16
  methods each, then did not compile: "evaluation exceeded 1000 backwards branches" in
  `on_body`. connect-zig's table of 225 routes compiled.
- **The fix.** `on_body` and `on_writable` raise the quota to `branch_quota`, as the other three
  do. The quota is a compile-time bound, so no machine code changes.
- **The test.** `router_pool_quota_test.zig` builds a table of 256 struct routes, each with
  `next`, and sends each event that reaches a switch. Whether a table passes the default quota
  depends on more than its count of routes: tables of 256 and of 512 routes in other shapes
  compiled without the fix, so they would not find the fault. The test's table is one that
  failed, and its comment says to keep it as it is.
- **Mutations, 2 of 2 CAUGHT:** `on_body` raises no quota, and `on_writable` raises no quota.
  Each fails the compile of the `server` tests with "evaluation exceeded 1000 backwards
  branches". Without `next` in the test's routes, the second was NOT CAUGHT.
- **Checked, 2026-11-17,** on `d922736c`:
  - The judge measured it against `c6ff7c94` in two jobs, with the h11 inputs. Each of the 15
    inputs was within the noise
    ([run 44015514012](https://github.com/c4milo/colibri/actions/runs/44015514012)).
  - `tools/ci.sh` passed 31 sections, with Zig 0.16.0 on an Apple M1 Pro with macOS.
  - The server tests, 755 of 755, passed on x86-64 Debug in an amd64 container, the new test
    among them.
