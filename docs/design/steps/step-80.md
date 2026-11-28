# Design §8 step 80: a lend gives the socket its bytes, as a copy did, 2026-11-28

[Design §8, the build plan](../../design.md#8-build-plan)

([decision 176](../../decisions/0176-a-tcp-socket-sends-from-its.md) as amended,
[decision 110](../../decisions/0110-the-servers-defences-against-denial-of.md) as amended a
tenth time, [#169](https://github.com/c4milo/colibri/issues/169),
[#137](https://github.com/c4milo/colibri/issues/137)). The judge failed
[step 79](step-79.md) on h11-one. The owner ruled on 2026-11-28 "Do the redesign now", approved
the rule of the proposal in the issue, and chose the exact heap first.
- **The rule.** Bytes are out once a lend or a copy gave them to the socket. Step 79 made
  "out" mean that the socket's send had ended. So each send's end moved deadlines, and a
  connection's `close` came one turn after its last bytes left the engine.
- **No name changes.** No root gains or loses a name. `server.Engine` keeps `output_stream`,
  `sent_stream` and `send_stream`, and their comments say the rule. docs/usage.md says what a
  program does.
- **The engine.**
  - `connection_output.owes_socket` says whether a connection holds bytes that no lend gave
    the socket: the output's bytes after the lent ones, and over TLS the output's bytes and
    the records that a send left. The idle deadline, the linger, `should_close` and
    `should_half_close` read it. A request body's meter reads `unlent_within` for its
    WINDOW_UPDATE.
  - So the engine reports `half_close` and `close` once the last bytes are lent. `ended` still
    waits for `sent_stream`.
  - `sent_stream` of a whole lend, on an open socket, runs `connection_output.took_whole`. It
    drops the bytes, counts them, and stops the connection's send meter when the output holds
    nothing. It fires and observes no deadline. The call marks the slot's deadline for the
    next `deadline_ns` (INV-31, the exact heap). It asks for a poll only when room in the
    output can bring an event: the connection reads with no bytes, as h2 and TLS do, or a
    response waits to write.
  - A send that took part of a lend, and a send that ends after the socket closed, do what
    they did.
  - `output_stream` asks for the slot's poll, as before, and the poll reports what the lend
    brought. It moves the slot's count of room only when the lend freed room: it wrote a coded
    response's bytes out, or sealed the output into records. Only then does it let a `receive`
    with no bytes read the connection again at the same instant. A lend of the output in
    place frees no room, and changes nothing that such a `receive` reads. Before, each lend
    did both, so the poll after a lend asked each response that waits whether it could write,
    and passed an h2 connection a read of no bytes.
  - The poll of a connection whose transport closed, and whose table holds no request, asks
    the connection nothing more. Before, it passed the connection a read of no bytes, which
    fired and observed its deadlines, once after its `close` and once before its `ended`.
- **A send that takes part of a lend after a `close`.** The proposal did not name this case.
  The engine lends a connection it closed nothing more. So the program's socket sends the rest
  of what it was lent, from the same bytes, and the program calls `sent_stream` once they are
  all out or the socket failed. `end_send` does it in both loops. Before a `close`, a count of
  part of a lend goes back at once, as before. The rule follows from the proposal's "the
  program lets the send end, and then closes".
- **The loops**, of `colibri.Server` (`server_pump.zig`, `server_loop.zig`) and of the
  test-only server (`server_session.zig`, `server_worker.zig`):
  - In cleartext a step lends before it reads the engine's events, where `send_stream` was
    before step 79. The engine then reports no `send` for a response that the step wrote, and
    the step reads the `close` that the lend brought. So a socket whose connection closes arms
    no receive.
  - An entry's `send_owed` says that its connection may owe bytes: the engine took bytes of a
    response, the router took the event that ends a request or a `writable`, or the engine
    reported a `send`. An entry that owes nothing asks the engine for nothing. A route that
    answers before its request ends is lent at the engine's `send`.
  - Over TLS a step lends once, after its last pass, as step 79's fixes lent when the socket
    was armed. A lend seals a record, so the responses to the requests of one read leave in
    one record. Its `close` is read in the entry's next step, as before this step. So this
    step changes no count over TLS but what the engine's own changes move.
  - No loop lends when it arms a socket. A socket with a send in flight keeps its entry owing,
    and the step after the send's end lends.
- **The counts**, in instructions a request, or a connection where each request has its own,
  with the change against 210c5e08:

  | Load | 210c5e08 | Step 79 with its fixes | This step |
  | --- | ---: | ---: | ---: |
  | h2, 10 streams | 11,075 | 10,946 (-1.2%) | 10,921 (-1.4%) |
  | h11 | 17,264 | 16,484 (-4.5%) | 15,672 (-9.2%) |
  | h2 over TLS, 10 streams | 12,993 | 12,928 (-0.5%) | 12,951 (-0.3%) |
  | h11 over TLS | 27,663 | 26,188 (-5.3%) | 26,315 (-4.9%) |
  | h2, a connection | 37,874 | 35,873 (-5.3%) | 35,744 (-5.6%) |
  | h11, a connection that the client closes | 25,841 | 24,786 (-4.1%) | 23,932 (-7.4%) |
  | h11, a connection that the server closes | 21,063 | 22,819 (+8.3%) | 20,693 (-1.8%) |
  | h2 over TLS, a connection | 1,480,732 | 1,474,803 (-0.4%) | 1,476,168 (-0.3%) |
  | h2, 256 KiB responses | 105,433 | 74,651 (-29.2%) | 67,834 (-35.7%) |
  | h2, routed GET | 13,492 | 13,304 (-1.4%) | 13,355 (-1.0%) |
  | h2, routed POST of 128 bytes | 18,133 | 17,986 (-0.8%) | 18,060 (-0.4%) |
  | h2, routed POST of 8,192 bytes | 22,144 | 21,708 (-2.0%) | 22,056 (-0.4%) |
  | h2, coded responses | 42,470 | 42,272 (-0.5%) | 42,265 (-0.5%) |

  These are x86-64 instructions in user mode, under callgrind on epoll, with step 79's
  instrument. Its loads gain the judge's three routed inputs and its coded one, each on one
  connection. The judge counts arm64 instructions in user and kernel mode, on io_uring, so the
  judge's run decides.
- **What this step gives back.** The routed loads keep less of step 79's gain. In h2 the engine
  reports the requests of one read, after the first, with its events. So a step lends after
  its read, and again after those events, where step 79's fixes lent once a turn. The second
  lend holds the first and more, so the turn still sends once.
- **What the lend still costs.** A copy of 210c5e08 with step 79's two fixes that do not need
  the lend counts 15,068 for h11, and 20,031 for an h11 connection that the server closes.
  This step counts 4.0% and 3.3% more. That is `sent_stream`: the call itself, and the slot's
  deadline, which the exact heap computes again after each send. The early wake of the
  proposal would remove the second part, at the price of INV-31.
- **Variants that lost.**
  - A TLS entry that reads the engine's events before it lends, to lend in its pass as
    cleartext does. The read of the events costs a read of no bytes over TLS, and h11 over TLS
    counted 27,452, 4.8% over step 79 with its fixes.
  - A lend that asks for a poll only when it can bring an event, as `sent_stream` does. The
    test called `should_send` and `should_close` from a second place, LLVM stopped placing
    them inline in the poll, and h2 counted 0.2% more. The lend asks for its poll as it did.
  - A lend only for a response that the engine took whole. With 256 KiB responses each part
    then waited for the engine's `send`, 77,064 a response.
  - A lend after each event that the router took. A route reads a body before it answers, so
    a POST of 8,192 bytes asked for a lend at each part of its body: 22,410, over 210c5e08.
- **The checks.**
  - `engine_tcp_output_test.zig`: a connection that finished closes once its last byte is
    lent, and ends after the send's count, in cleartext and over TLS with its close_notify. A
    staged close's `half_close` comes with the lend. A send that took a whole lend reports
    nothing and asks for no poll, and over TLS drops its records. A lend in place moves no
    room, and one that sealed the output or wrote a coded ring out does. The poll that ends a
    closed connection leaves the instant of its last deadline check as it was, and no linger
    runs over lent bytes. A coded h2 response past the output owes a `send` once a send freed
    its room. Over TLS a pipelined request that a record held is read once no request is
    open. INV-31 holds straight after a lend.
  - `connection_output_test.zig` and `connection_bodies_test.zig`: a send that took a whole
    lend counts its bytes, the meter runs while bytes are left and stops with the last, the
    idle deadline runs from the lend, and a body's rate starts again once its WINDOW_UPDATE
    is lent.
  - `server_session_meter_test.zig`, over a stand-in engine that notes the order of its calls:
    a step lends the response it wrote before it reads the events; each part of a response is
    lent in its step; a socket with a send in flight takes no lend; over TLS a step lends
    once, after its last pass; a later lend that gives nothing leaves the socket the earlier
    one's bytes; and the router may write at the end of a request and at a `writable`. Over
    the real engine, a step reads the `close` that its lend brought, and the slot waits for
    the send.
  - `server_worker_test.zig`: a socket learns of its close with the lend; a closed
    connection's socket sends the rest of a send that took ten bytes, and its slot frees only
    then; one whose send fails frees its slot; and an open connection's socket hands back a
    part of a lend, which the engine lends no byte of again.
  - `src/colibri/server_pump_test.zig` and `fake_host_send_test.zig`: the same order of calls
    in `colibri.Server`'s loop; what the router wrote to an event of the engine's is lent in
    the same step, and the events are read again after it; and a closed connection's socket
    arms no receive, sends the rest of its lend from the same bytes, closes only then, and
    frees when its send fails.
  - Mutations, each CAUGHT: 42 of the engine and the connection against `zig build
    test-server`, 31 of the test-only loop against `zig build test-testing`, and 23 of
    `colibri.Server`'s loop against `zig build test-colibri`. Fourteen were NOT CAUGHT until
    a test was written: an open connection with no request that is asked nothing; the room
    after a coded lend; sealed records kept after a whole send; the bytes of a whole send not
    counted, and its meter left as it was; the idle deadline, a body's rate and the linger
    under step 79's rule; no poll of h2 after a whole send; a lend that leaves the heap as it
    was; a later lend that drops the earlier one's bytes; and no read of the events after a
    lend in `colibri.Server`'s loop. One mutant changed no result, in a condition that the
    code then lost: the lend after a step's passes read whether its entry runs TLS.
- **Run on 2026-11-28, on x86-64 Linux in a container with no IPv6 and no Docker:** `zig build
  test`, 4,341 of 4,343 tests with 2 skipped; `zig build examples` but the IPv6 example; `zig
  build lint`; `zig fmt --check`; `tools/doc_snippets.sh`; `tools/deadlines.sh`, each of its
  four peers cut at its deadline; and `tools/h11_server_interop.sh --tls go` and
  `tools/h2_server_interop.sh --tls go`, 65 requests in cleartext, over TLS and coded, with
  none failed. TLC found each trace a behavior of its model: 32 of `tools/deadline_trace.sh`,
  64 of `tools/tcp_trace.sh` and 64 of `tools/h2_trace.sh`. curl against the test-only server
  on io_uring read 200 closes in a row, 256 KiB responses over h11 and h2, in cleartext and
  over TLS, at a limited rate too, and the 405 of a staged close before a body of 2 MiB.
- **Not run:** the checks of `tools/ci.sh` that need Docker, a peer from an image or an arm64
  host.
