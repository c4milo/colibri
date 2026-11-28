# Design §8 step 79: a TCP socket sends from its connection's output, 2026-11-26

[Design §8, the build plan](../../design.md#8-build-plan)

([decision 176](../../decisions/0176-a-tcp-socket-sends-from-its.md), [#137](https://github.com/c4milo/colibri/issues/137)).
The owner ruled "Build it now" on the draft of this entry.
- **Where the bytes were.** A TCP connection of `colibri.Server`, from `zig build
  bench-memory` at v0.22.0:

  | Part | Bytes | Holds |
  | --- | ---: | --- |
  | engine slot | 151,232 | the connection, with its `output` of 49,161 |
  | socket input | 41,221 | received bytes, which the protocol reads in place in cleartext |
  | socket output | 49,161 | bytes to send |
  | TLS session, over TLS alone | 83,039 | chapulin's session, 41,808, and `plain_in`, 41,221 |

  In cleartext, `send_stream` copied the slot's `output` into the socket's output, so the two
  held the same bytes. Over TLS the socket held the records that `send_stream` sealed.
- **The names.** `server.Engine` gains two calls, beside `send_stream`:
  - `output_stream(connection, now_ns) []const u8`: the bytes the TCP connection owes its
    socket, sealed over TLS, where the engine holds them. Empty for a handle that names no
    connection, and for a connection whose socket closed.
  - `sent_stream(connection, sent, now_ns) void`: the send took the first `sent` of them.
  No other root changes. `colibri.Server` is the program that needs them, and
  `examples/server_exchange.zig` shows them. `examples/server_stream.zig` keeps `send_stream`,
  for a program that sends from a buffer of its own.
- **The contract.**
  - The engine keeps the bytes an `output_stream` returned in place until its `sent_stream`.
    The connection writes after them, and moves what is left to the front only at
    `sent_stream`.
  - A program calls `output_stream` once a turn, for a socket with no send in flight, so the
    turn's one send carries every byte its writes made (decision 119 as amended). A call
    before the send starts returns the same bytes from the same front, and those written
    since. The engine reports a `send` for bytes no call returned yet, as it did after a
    `send_stream` that left room. A `sent_stream` past what the calls returned halts.
  - The engine reports `ended` only after the `sent_stream` of each `output_stream` that
    returned bytes, whatever ended the connection: its `close`, `transport_closed` or
    `shutdown`.
  - `send_stream` copies, as before. Over TLS it first copies records that an `output_stream`
    sealed and no send took.
- **Over TLS.** Each TLS session holds the sealed records, `output_len` bytes, so
  `Config.tls_buffer_len(1)` grows by that much and the socket holds none. A connection over
  TLS holds as many bytes as before.
- **Memory.** A cleartext connection of `colibri.Server` goes from about 241.6 KB to about
  192.4 KB, and its sends copy no byte.
- **The send meter.** An h2 stream's meter ran only while the output held nothing, and lent
  bytes stay in the output until their send ends. So each lend paused the meter,
  `sent_stream` started it again with a new grace period, and a peer that opens its window an
  byte a second was never cut. Two changes keep decision 110's rule:
  - A stream's meter waits only on bytes that no lend gave the socket. The connection's
    meter still counts the lent ones, so a peer that reads slowly is still judged.
  - A stream's meter stopped and started at one instant keeps its window (decision 110 as
    amended a ninth time). A body's meter still starts again with a grace period once its
    WINDOW_UPDATE is out, as the fourth amendment rules. The pumps read again after a response's write and before the turn's lend,
    and that read paused the meter. `main` has the same gap: its pumps copy at the end of a
    step, after more reads. The owner ruled "Resume the meter" over a lend at each `send`,
    which over TLS seals a record for each response.
- **The programs.** `colibri.Server`, in both kinds, and the test-only server hold no output in
  a socket. A socket takes the lend when its driver arms it, while no send is in flight, and
  hands back each send's count with `sent_stream`. A socket of `colibri.Server` that stops with
  a lend it never sent hands it back with 0, so the engine can end the connection. A client's
  socket keeps its output, in `src/colibri/socket_output.zig`, since `client.ConnectionPool` has
  no such calls.
- **The sizes**, from `zig build bench-memory` on x86-64: an engine's TCP slot holds 151,240
  bytes, 8 more for `lent_len`, and `Config.tls_buffer_len(1)` is 132,207, against 83,039. A
  socket of `colibri.Server` holds its input and no output.
- **The checks.**
  - `src/server/engine/engine_tcp_output_test.zig`: a lend in place, a partial send's rest, a
    copy and a lend that send the same bytes, an `ended` that waits for a lent send, a close and
    a staged close that wait for the sealed records, a re-lend in cleartext and over TLS, and a
    session that ended with sealed records left. `connection_output_test.zig`: a lent send feeds
    the send meter. `rate.zig`: a pause that lasts no time keeps its window.
  - The attack of decision 110 as amended, a window that opens a byte a second, is cut under
    the engine with a copy, a lend at each `send` and a late lend
    (`engine_tcp_writable_test.zig`), under the test-only session
    (`server_session_meter_test.zig`) and under a hosted server (`fake_host_meter_test.zig`).
  - `fake_host_send_test.zig`: a hosted server sends from the engine, a partial send's rest goes
    next, a socket that fails with a lend it never sent frees for the next connection, and the
    part of a stream that a send's room lets the route write leaves in the same turn.
  - The endpoint check of step 21b.5 lets no connection outlast its horizon. Six of its 128
    seeds hold an h2 peer that keeps a stream's window closed and pings: 0x4, 0x7, 0x1c, 0x4b,
    0x5d and 0x63. The stream's meter now cuts the stream, and the idle deadline then ends the
    connection. On main three of them ran to the horizon, and three ended only at the drain
    after `shutdown`. Its census moved: `seeds=128 connections=768 reused=256 requests=1583 done=506
    cancelled_peer_reset=14 cancelled_deadline=910 cancelled_closed=116 cancelled_program=37
    writable=444 sends=1242 closes=376 stale_calls=17133 waiting_probes=34925 accept_waits=95
    shutdowns=15 unserved=0 failed=0 trace_octets=143256 crc32=0x45eff0da
    wire_crc32=0x7746945e`, the same in Debug and ReleaseSafe. On main the same seeds made 1,910
    sends.
  - Mutations on the code as it landed, each CAUGHT: 21 of the engine and the meter against
    `zig build test-server`, 9 of `colibri.Server` against `zig build test-colibri`, and 5 of
    the test-only server against `zig build test-testing`. Five were NOT CAUGHT until a test
    was written: the half-close wait, a lend after a close, a lent send fed to the send meter,
    a meter's stop in place of its pause, and sealed records a full lend leaves owed. One was
    NOT CAUGHT because its line was redundant, a lend for an entry whose connection ended,
    and the line went. A send's completion that hands back nothing hangs the tests of
    `colibri`, which counts as CAUGHT.
  - One more of the meter, the other meters paused in place of a stop: CAUGHT by the deadline
    check of `zig build test-sim-run`, and NOT CAUGHT by `zig build test-server`.
- **Run on x86-64 Linux, in a container with no IPv6:** `zig build test`, 4,298 of 4,300, with
  1 skipped and the IPv6 test failed; `zig build examples` but the IPv6 example;
  `zig build lint-commits`; and `tools/doc_snippets.sh`. Each commit's own targets passed too:
  the meter's fix under `test-server` and `test-sim-run`, and the second lend under
  `test-server`.
- **Not run:** `tools/consumer_check.sh`, whose fetch this container's network refuses, the
  checks of `tools/ci.sh` that need Docker or a network peer, and every arm64 host. CI runs
  them.
- **CI:** [45996575425](https://github.com/c4milo/colibri/actions/runs/45996575425) passed on
  8140451a: `tools/ci.sh` on x86-64 Linux, and `zig build test` on arm64 Linux and arm64 macOS.
- **The judge:** [45996610799](https://github.com/c4milo/colibri/actions/runs/45996610799)
  measured 8140451a against 210c5e08 with `--h11`, five rounds on each of two Neoverse-N2
  runners. The run fails: 13 of the 15 inputs lose past the noise by instructions in both jobs.
  Each figure below is the change against the base, job 1 and then job 2.
  - **Wins:** h2-large-many, by 8.2% and 10.2% of the instructions a request. Job 2's noise is
    12.1%, so there it is within the noise. Its user instructions fall by 27% in both jobs, from
    118,860 to 86,727 a request, and its CPU time by 16% and 14%.
  - **Within the noise:** h2-tls-large-many in both jobs, and h2-routes-post-late-many in job 1.
  - **Losses over h2:** h2-many by 2.95% and 2.82%, about 370 instructions a request;
    h2-tls-many by 2.31% and 2.77%; h2-one by 2.49% and 2.71%; h2-routes-post-many by 1.32%
    and 1.18%; h2-tls-one by 0.94% in both; h2-routes-post-late-many by 1.43% in job 2; and
    h2-routes-many, h2-k8s-routes-many and h2-coded-many by 0.54% to 0.62%.
  - **Losses over h11:** h11-many by 3.00% and 3.31%, about 1,000 instructions a request;
    h11-tls-many by 4.96% and 4.85%; h11-one by 9.71% and 11.92%; and h11-tls-one by 1.42% and
    1.34%. Their user instructions lose by 1.05% to 19.85%. h11-one completes 46,692 and
    44,543 connections a second on the base, and 41,520 and 40,353 on the change.
  - So the lend costs more instructions than the copy it removes, except where a response is
    large. Step 79 does not meet the admission rule of docs/performance.md as it stands.
- **The cost, found on 2026-11-28** ([#137](https://github.com/c4milo/colibri/issues/137)). The
  owner ruled to find the cost, cut it, and run the judge again.
  - **The instrument.** Valgrind 3.22 does not follow io_uring's completions, so a server on
    io_uring answers nothing under it. A seccomp filter that refuses `io_uring_setup` makes Rotor
    take epoll (Rotor's decision 20), and callgrind then counts the server's instructions by
    function. The server is the test-only one, built by `zig build http-server -Drelease
    -Dcpu=x86_64_v3`, on one core of an x86-64 Linux container: an Intel Xeon at 2.10 GHz, with
    kernel 6.18. It runs under `valgrind --tool=callgrind --instr-atstart=no`. After a warm-up,
    `callgrind_control -i on` starts the count, the load runs, and `callgrind_control -i off`
    ends it. Each count is the instructions in user mode while the load ran.
  - **The loads.** h2load 1.59.0 sends h2 with `-c 1 -m 10`, and one request on each of 64
    connections. A paced client sends h11: each request follows the response before it and a
    pause of 3 ms. So a send's completion and the next request never share a turn, as on
    io_uring, and two runs of one load differ by less than 0.01%. Over TLS the server holds the
    test identity. The 256 KiB load is `--body 262144`.
  - **What the counts showed.** Three costs, and 210c5e08 has the second one too:
    - The loops called `output_stream` for each socket that a turn touched. A call with nothing
      owed fires the connection's deadlines, observes them and touches the slot. The next read
      of the engine's events then polls the connection again.
    - Each pass of a step, and the step after each send, passed the engine a read of no bytes.
      The engine ran the connection's `receive` to learn that it read nothing.
    - `observe` asks `finished` for the linger while the output holds bytes. Lent bytes stay in
      the output until their send ends, so `finished` ran 5 times for a request, against 3.
- **The fixes of 2026-11-28**, each a commit of its own:
  - `finished` returns at once for a connection that nothing stopped, that nothing asked to
    end, and whose protocol is open.
  - A step of both loops passes its socket's unread bytes alone, and its read of the engine's
    events reports what the connection owes. Over TLS the engine may hold a request of a record
    after it consumed the record's bytes, and reports it with its events. So a step of the
    test-only server takes one more pass after a read that reported an event, and answers it.
  - An entry of both loops keeps `send_owed`, which the engine's `send` sets and a lend clears,
    as `send_stream` had before this step. A lend asks the engine only then.
  - Two variants lost. A lend inside the step, where `send_stream` was, removes the `send`
    event. Over TLS it seals the first response of a record apart from the others, and h2 over
    TLS then lost 1.3% against 210c5e08. A read of no bytes that stays over TLS kept the record
    whole, and h11 over TLS then gained only 0.7%.
- **The counts**, in instructions a request, or a connection where each request has its own:

  | Load | 210c5e08 | 8140451a | With the fixes |
  | --- | ---: | ---: | ---: |
  | h2, 10 streams | 11,075 | 11,235 (+1.5%) | 10,946 (-1.2%) |
  | h11 | 17,264 | 18,010 (+4.3%) | 16,484 (-4.5%) |
  | h2 over TLS, 10 streams | 12,993 | 13,154 (+1.2%) | 12,928 (-0.5%) |
  | h11 over TLS | 27,663 | 28,603 (+3.4%) | 26,188 (-5.3%) |
  | h2, a connection | 37,874 | 39,031 (+3.1%) | 35,873 (-5.3%) |
  | h11, a connection | 25,841 | 26,786 (+3.7%) | 24,786 (-4.1%) |
  | h2 over TLS, a connection | 1,480,732 | 1,479,634 (-0.1%) | 1,474,803 (-0.4%) |
  | h2, 256 KiB responses | 105,433 | 86,800 (-17.7%) | 74,651 (-29.2%) |

  These are x86-64 instructions in user mode, on epoll. The judge counts arm64 instructions in
  user and kernel mode, on io_uring, so the judge's run decides.
- **What the lend still costs.** 210c5e08 passed the read of no bytes too. A copy of 210c5e08
  with the first two fixes counts 10,788 for h2, 15,068 for h11, 13,005 for h2 over TLS, 23,928
  for h11 over TLS, 34,164 and 23,367 for a connection, and 97,234 for 256 KiB responses.
  Against that copy the lend costs 1.5% over h2, 9.4% over h11 in cleartext and over TLS, and
  5.0% and 6.1% a connection. It saves 0.6% over h2 over TLS, and 23.2% on 256 KiB responses.
  The cost is `sent_stream`. When a send ends it counts the bytes, fires and observes the
  deadlines, starts the idle deadline, and touches the slot for a poll. Before this step the
  engine had no call then. [#169](https://github.com/c4milo/colibri/issues/169) holds it. The
  owner ruled on 2026-11-28 to keep this step with its fixes.
- **The checks of the fixes.**
  - `server_session_meter_test.zig`: a step with no unread bytes and a lend with nothing owed
    leave the instant of the connection's last deadline check as it was. A session over a
    stand-in engine that counts its calls passes its unread bytes once, and answers a request
    that its read of the engine's events reports.
  - `src/colibri/server_pump_test.zig` runs `colibri.Server`'s loop over a stand-in engine: no
    read with no unread bytes, one lend for one `send`, none with a send in flight, and none for
    a new connection whose entry owed before.
  - `connection_close.zig`: an h2 connection whose protocol failed has finished once its GOAWAY
    is out, with nothing else that ended it.
  - Mutations, each CAUGHT: 9 of `finished` against `zig build test-server`; 4 of the read and
    4 of the lend in the test-only loop against `zig build test-testing`; and 1 of the read and
    5 of the lend in `colibri.Server`'s loop against `zig build test-colibri`. Three were NOT
    CAUGHT until a test was written: a failed h2 protocol that `finished` counted as open, and
    in each loop a new connection that starts owing.
- **Run on 2026-11-28, on x86-64 Linux in a container with no IPv6:** `zig build test` on the
  last of the three commits, 4,309 of 4,311 tests, with 1 skipped and the IPv6 test failed;
  `zig build examples` but the IPv6 example; `zig build lint`; `zig build lint-commits`; and
  `zig fmt --check`. The tree of the second commit passed `test-server`, `test-testing` and
  `test-colibri`, the IPv6 test apart.
- **Not run:** the checks of `tools/ci.sh` that need Docker, a network peer or an arm64 host.
- **The judge of the fixes:**
  [46163421175](https://github.com/c4milo/colibri/actions/runs/46163421175) measured 461895d
  against 210c5e08 with `--h11`, five rounds on each of two Neoverse-N2 runners. The run fails
  on one input, where 13 failed before. Each figure is the change against the base, job 1 and
  then job 2.
  - **Loses:** h11-one by its user instructions, 6.85% and 6.91%: 19,955 a connection against
    18,675. Its total moves by 6.27% in both jobs, inside noise of 6.79% and 6.55%. It
    completes 43,391 and 44,343 connections a second, against 46,286 and 47,966.
  - **Wins:** h2-large-many by 9.2% and 10.5%, with user instructions down 25.8%; h2-one by
    1.5% and 1.2%; h2-many by 0.61% and 0.64%; h2-routes-many and h2-k8s-routes-many by 1.0% to
    1.1%; h2-routes-post-late-many by 0.7% and 0.8%; h2-routes-post-many by 0.5% in job 1; and
    h11-tls-many by 2.3% and 2.1%, with user instructions down 4.7% and 4.6%.
  - **Within the noise:** h11-many, h11-tls-one, h2-tls-many, h2-tls-one, h2-coded-many and
    h2-tls-large-many in both jobs, and h2-routes-post-many in job 2.
- **Why h11-one still loses.** wrk sends `Connection: close` on that input, so the server
  closes each connection after its response. The counts above had missed it: their paced
  client closed first. With a paced client whose request asks for the close, callgrind counts
  21,063 instructions a connection at 210c5e08, 24,484 at 8140451a and 22,819 with the fixes.
  - The engine reports `close` once the output holds nothing. A copy emptied the output in
    the turn that wrote the response, so the socket learned of the close before it armed its
    next receive. Lent bytes leave the output only at `sent_stream`, one turn later. So the
    socket arms one more receive, and its close then cancels it. On epoll, Rotor's part of
    that receive is about 1,000 of the 1,756 instructions.
  - The rest is `sent_stream`, which
    [#169](https://github.com/c4milo/colibri/issues/169) holds.
  - By the admission rule, this step does not pass while h11-one loses. The owner's ruling on
    it is owed.
