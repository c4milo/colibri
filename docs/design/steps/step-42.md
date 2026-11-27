# Design §8 step 42: `colibri.Client`, proposed 2026-11-05

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 153](../../decisions/0153-a-client-that-runs-on-a.md) ruling 8. It runs on Rotor's own API. The owner ruled on
2026-11-06 that it lands before step 39, so that a program fetches over h11, h2 and h3 before
streamed bodies exist. Streamed bodies come to `colibri.Client` with step 39, in the pool
underneath. Step 44 amends the loop rules below ([decision 156](../../decisions/0156-colibriclient-and-colibriserver-run-on-a.md)): the
client runs on a loop the program may share, and owns the loop when its type names `.private`.
- **The public names:** `colibri.Client`, `colibri.ClientOf`, `colibri.ClientCapacity` and
  `colibri.ClientConfig`, with `init`, `deinit`, `request`, `shutdown` and `run`, beside
  `colibri.Server`'s, listed in the root's test first. `Client` is `ClientOf(.{})`: QUIC, one
  TCP connection and `client.constants.limits.requests_max` requests. A program that needs
  another size names a `ClientCapacity` (decision 153 ruling 9). Decision 156 renames
  `ClientOf` to `Client`, a type function, in step 44. `client.Timeouts` gains the field
  `connect_ns`.
- **The rules.** It owns the TCP sockets, the UDP socket for h3, the loop, the clock and a
  `client.ConnectionPool`. After step 44 it owns the loop only when its type names `.private`. `socket.zig`, `datagram_socket.zig` and `datagram_batch.zig` serve the
  server and the client alike. `colibri` imports `client`, as decision 150 ruling 1 puts it above
  both.
  - `ClientConfig` holds `host`, an IP literal, `port`, `pool`, the `client.Config` whose counts
    and `ecn` `init` sets, `random`, which defaults to the system's entropy, and `unix_seconds`.
    `unix_seconds` is the program's instant at the start of `run`, and it has no default. A web
    PKI trust judges each chain at it, plus the time the loop has run. A trust in pins judges no
    date.
  - `init` sets the pool's `ecn`, as `colibri.Server` sets its endpoint's (decision 68). The
    loop reads and sets each datagram's codepoint, and a pool that does not read ECN halts on
    a datagram marked ECT(0).
  - Each TCP connect goes to Rotor with the deadline `pool.timeouts.connect_ns`, 10 s by
    default. A connect past it ends the attempt as a refused connect does. Rotor takes no
    deadline past `rotor.constants.timeout_ns_max`, one day, so a longer limit becomes one day.
  - `run(handler)` runs one loop on the calling thread. Step 44 moves the handler to `init`,
    and `run` takes no argument. The handler declares `on_finished` and
    may declare `on_connected`. Each runs on the loop's thread and may call `request` and
    `shutdown`. `shutdown` is the one call another thread may make. A program calls `run` once
    for each `init`.
  - After `shutdown`, `request` returns `error.ShutDown`, which `client.RequestError` does not
    hold. The pool asserts that no request comes after its own shutdown.
  - `init` returns an inferred error set, and `run` returns `colibri.RunError`.
  - A shutdown steps each running TCP socket. This works around a bug of the pool: after
    `shutdown`, an idle h2 connection never sends its GOAWAY, because `send_blocked` stays set
    and the pool reports no `send` event. Step 39 changes the pool's files, so the fix goes
    there.
- **The checks.** `examples/colibri_server.zig` fetches through it over h11, h2 and h3 on
  loopback, over TLS with the test identity. Its unit tests bind loopback.
- **The record, 2026-11-05.** Each mutation below was **CAUGHT** by `zig build test-colibri`,
  or by `zig build example-colibri_server` for 42f, unless it says otherwise. A watchdog of 8 s
  halts a test whose run does not return, so a hang fails before the server's deadlines of 10 s.
  - 42b moved the server's UDP socket into `datagram_socket.zig` with no change of behaviour.
    42e's tests check its paths.
  - 42c: no default source; the UDP socket not opened, not closed, or bound in IPv4 alone; either
    count not taken from the capacity; the host ignored.
  - 42d, some of them as a hang: the connect event ignored; `start_tcp` not called;
    `transport_closed` not called for a failed connect, or for a running socket that fails; the
    `send` event not stepped; a closed connection's socket kept open; an open not held for the
    slot's last close; the held open never started; shutdown ignored; no step of the running
    sockets at shutdown; the deadline not passed to the tick; `on_finished` not called;
    `unix_seconds` ignored; the run's first instant not read; a request left undrained.
  - 42d: the drop of unread input at a close was removed, because `Socket.open` starts each
    socket with no input. The first mutations of it were **NOT CAUGHT**.
  - 42e: a datagram not given to the pool, or to the server's endpoint; no flush, in the client
    or in the server; `start_quic` not called; a batch not released; the multishot receive not
    restarted; `stop` that does not cancel; the received or the sent ECN codepoints swapped;
    `on_instant` not called. These checks cover the UDP paths that 37c left with no check.
  - 42e: a drain after each flush was removed. Its mutation was **NOT CAUGHT**, and the next
    turn's drain reads the same events.
  - 42f, by `zig build example-colibri_server`, two of them as a hang: the server's shutdown
    ignored; port 0 kept; the client's shutdown ignored; the client's datagrams not flushed.
  - 42f: a closing server socket kept open was **NOT CAUGHT** by the example, because the client
    now closes its own side. `zig build test-colibri` still catches it, as a hang, as in 37b.
- **The review, 2026-11-06.** Two reviews found the defects below. Each fix has a test, and each
  mutation was **CAUGHT** by `zig build test-colibri` unless it says otherwise.
  - A connect the pool closed in flight kept its slot and `run` until the system's connect
    timeout, about 75 s on macOS and 127 s on Linux. Its close now goes at once, and Rotor's
    close cancels the connect. Caught: the close held back; the slot freed before the connect's
    final event; a connect that succeeds after the close starts its connection.
  - A request from a handler after `shutdown` halted on the pool's assertion. Caught: no
    refusal.
  - A second `run` after one `init` waited without end. `run` now asserts that it runs once for
    each `init`. Its mutation is **NOT CAUGHT**, because a test cannot survive the assertion.
  - A run that failed left its TCP sockets open. Its end now closes each socket whose close was
    never submitted. Caught: no close; no call at the end; `init` leaves an earlier run's
    sockets live.
  - New tests guard the close of a stale handle, the drop of an open that waits, the loop's time
    in `unix_seconds`, no wait while a socket is pending, and one pass of a shutdown.
  - No test could see three checks, so they were removed: the generation in `owed`, the UDP
    socket's `stop` at `closed`, and the `continue` after the pool took a datagram.
  - No test reaches four paths: `start_tcp` refused by the TLS stack, `open_socket` refused by
    the system, and the bounds of 1,024 events and 1,024 passes, which 4 requests cannot fill.
    The second review below reaches `open_socket` refused.
- **The rulings, 2026-11-06.** The branch moved onto v0.14.1, and the owner's rulings of decision
  153 ruling 9 were applied. Each mutation below was **CAUGHT** by `zig build test-colibri`.
  - v0.14.1's ECN fix and its tests moved with the UDP code into `datagram_socket.zig`. Caught:
    the server's `ecn` not set; the sent ECT(0) and ECT(1) swapped; a codepoint read with no
    flag.
  - `colibri.Client` had the server's ECN defect: the pool halted on the server's first
    datagram marked ECT(0). `init` now sets the pool's `ecn`, and the h3 tests leave it false
    in the program's configuration. Caught: the `ecn` not set.
  - A connect to a listener whose backlog is full ends the exchange refused within a deadline
    of 200 ms, under a watchdog of 3 s. Caught: the deadline not passed to Rotor; Rotor's
    `timeout` not taken as a failed connect; a limit of 0 passed as Rotor's none.
  - `Server.run` left its accepted sockets open when it failed. `server_loop.end` now closes
    them with the client's `socket.close_left`. Caught: no close at the end; `init` leaves an
    earlier run's sockets live.
  - `unix_seconds` with no default is a compile error where a program leaves it out, so it has
    no mutation.
- **The second review, 2026-11-06.** Two reviews read the branch after the rulings. Each fix has
  a test, and each mutation was **CAUGHT** by `zig build test-colibri`.
  - A `connect_ns` past one day, such as `std.math.maxInt(u64)`, halted the program on Rotor's
    assertion at the connect's submit. `colibri.Client` now passes one day at most. Caught: no
    bound on the deadline.
  - A socket the system refused, in an open that waited for the slot, left the pool's events
    until the next tick ended, 50 ms at most. The refusal now marks the pool undrained. A test
    sets the process's descriptor limit to 0 to make the system refuse the socket. Caught: no
    mark.
- **The third review, 2026-11-06.** A review of the branch on v0.14.1 found the items below.
  - Rotor splits what the kernel coalesced, so `datagram_socket.take_delivery` now hands a
    delivery to the server or the client whole, as v0.14.1 did in `server_udp.zig`.
  - No test required `finished` to wait for live sockets. An h2 peer now records the client's
    GOAWAY, which the socket sends after the pool reports `closed`. Caught: `finished` ignores
    live sockets.
  - Two client checks were **NOT CAUGHT**, and were removed: the `started` guard before
    `transport_closed`, and the clear of `started` in `close`. `pool_calls.zig` shows why. After
    the pool's `close`, `resolve` names no connection, so `receive` drops the bytes and
    `send_stream` writes 0. A second `transport_closed` of a running connection calls the
    connection's again, which changes nothing (`pool_links.close_over`).
- **The close at a run's end, 2026-11-06.** A run that failed after a socket's close was
  submitted could leave the socket open on io_uring.
  - `end` called `cancel_all` and then Rotor's `drain`, which discards the final events. On
    io_uring a submitted close is in flight, so `cancel_all` can cancel it before it runs. Its
    final event is then `canceled` (Rotor's decision 5, rule 2), and `close_left` skipped the
    socket because its close was submitted. kqueue and epoll close at submit, so macOS does not
    show it.
  - `socket.end_loop` now serves the server's `end` and the client's. It ticks
    `rotor.constants.drain_rounds_max` times at most, as Rotor's `drain` does, and reads each
    event. A close that ended `canceled` or `timeout` did not run, so `close_left` closes its
    socket with `rotor.sync.close_now`. A close that failed otherwise ran, and the system
    released the descriptor, so a second close could close another descriptor.
  - Each mutation below was **CAUGHT** by `zig build test-colibri` on macOS arm64, and by the
    same command on Linux arm64 under io_uring, in an Ubuntu 26.04 container with no seccomp
    filter: a canceled close treated as done; `close_now` dropped; a failed close treated as
    not run; a receive's event read as a close. The final events discarded, as before the fix,
    was **CAUGHT** on Linux alone, where a test cancels a close that io_uring holds.
- **An accept at a run's end, 2026-11-06.** A server's accept that succeeded during the end
  left its new descriptor open, on each backend.
  - `socket.end_loop` read the final event of a close alone. An accept that a peer's connection
    completes before `cancel_all` reaches it ends with success, and no entry holds its socket.
  - `socket.on_last_event` now closes the descriptor of a successful accept with
    `rotor.sync.close_now`. `socket.accept_user_data` names the accept, and `server_loop.zig`
    reads it from there.
  - A client's connect that succeeds during the end needs no change. Its socket is live with no
    close submitted, so `close_left` closes it. A test of `socket.zig` holds this.
  - The test of the server's end connects a peer, then submits a send of the peer and the
    accept. The tick reads one event, the send's, so the accept's success stays for the end.
  - Each mutation below was **CAUGHT** by `zig build test-colibri` on macOS arm64, and on Linux
    arm64 under io_uring as above: the accept's descriptor not closed; the accept's event not
    read; the same with the test of `socket.zig` removed, so the server's test alone reads it; a
    connect that succeeded read as a close that ran.
