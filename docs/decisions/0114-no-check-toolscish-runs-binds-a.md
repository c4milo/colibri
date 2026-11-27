# Decision 114: No check `tools/ci.sh` runs binds a fixed port: the kernel chooses each one

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-03, for [#94](https://github.com/c4milo/colibri/issues/94). The check
scripts listened on fixed ports and gave their containers the same names in every run, so two runs
on one machine collided. Sessions that share a machine held each other for the length of a run,
about 35 minutes.
- Each peer a script starts binds port 0 and prints `listening on port <port>` once its
  socket is bound. `tools/listening_port.sh` waits for the line and prints the port, so it is
  the script's wait for the peer too. The scripts take no port.
- The workers of the test-only server share one port. The first binds port 0, and the others
  bind the port it got, with SO_REUSEPORT as before.
- A container peer is published on a host port Docker chooses, under a name the run alone
  has. Its script waits for the peer's own socket inside the container, and then for the
  host port. Docker Desktop's host port refused the first connection in 17 of 30 starts, for
  up to 0.15 s, and accepts before the peer listens when the peer is the slower one.
- `tools/h3load.sh` and `bench/run.sh` keep a fixed port. `tools/ci.sh` runs neither.
- Two runs still share TLC's state directory, which pepegrillo names
  (https://github.com/c4milo/pepegrillo/issues/2).

The alternatives refused:
- Sessions taking turns on the fixed ports, as before. A run holds every other session for
  its length.
- A script that binds port 0 itself, reads the port, releases it, and passes the number to
  its peer. Another process can bind the port in between.
- A range of ports for each worktree. It needs a rule that hands the ranges out, and two
  runs in one worktree still collide.
