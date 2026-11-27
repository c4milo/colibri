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
