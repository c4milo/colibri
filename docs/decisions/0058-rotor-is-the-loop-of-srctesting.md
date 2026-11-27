# Decision 58: Rotor is the loop of `src/testing/`'s UDP endpoints, a third test-only dependency

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-22. It amends entry 52, which deferred the question to step 9e, and
entry 63 extends it: the loop reports the instant the endpoints pass to colibri.

Entry 52 had one reason to wait: Rotor carried no datagrams. Its version one does. It runs
the same conformance suite over kqueue on macOS and io_uring on Linux, UDP included, and it
allocates nothing: the caller hands each loop its memory. Step 9e's interop endpoint is the
first UDP code in the tree, so the question entry 52 left open is now due.

Rotor is a lazy package in `build.zig.zon`, pinned by commit. Only colibri's own build
requests it, after the point where a dependent project's build stops, as pepegrillo is
requested (decision 36). One module imports it: `testing_udp`, rooted at
`src/testing/udp.zig`, the thin socket file around a QUIC session that entry 52 asked for.
The library never imports it, and non-negotiable 1 does not change: colibri owns no socket
and no loop, and a consumer brings its own.

Decision 46 still holds in substance. An endpoint on Rotor waits only in the loop's one
system call per tick, and makes no other call that waits. The h2 endpoints keep their `poll`
loops: they pass h2spec and interop, and moving them buys nothing (entry 52's reasoning).

The alternatives refused. **Another hand-written `poll` loop for UDP** is what entry 52
asked colibri not to invest in, and it would be a second loop to keep correct beside one the
owner maintains. **libuv or libxev** would be a dependency no one here maintains, and Rotor
already measures itself against both, the rows it loses included.
**`std.Io`'s evented implementations** take an allocator, which decision 46 already refused.
