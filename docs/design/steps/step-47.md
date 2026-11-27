# Design §8 step 47: the h11 server reads the rest of a body, or closes in stages, ruled 2026-11-09

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 160](../../decisions/0160-the-h11-server-reads-the-rest.md), for v0.16.0. RFC 9112 §9.3 and §9.6.
- **The public names,** each listed in decision 115's form:
  - `h11.Connection.Options.discard_len_max`, a field with the default 0. A program that drives
    h11 itself keeps its behaviour, and the server passes its limit.
  - `server.Event.half_close`, a field of the union. A program needs it to close the write side
    of a socket (RFC 9112 §9.6).
    - The field breaks a program whose `switch` names every field of `server.Event` and has no
      `else`. That program does not compile until its `switch` names `half_close`.
    - The owner ruled on 2026-11-10 that the step ships in v0.16.0 for that reason, and not in
      v0.15.2.
  - `server.constants.limits.discard_len_max`, 262,144 bytes, and
    `server.constants.limits.half_close_ns`, 1 s, each pinned by the test of the limits.
- **The commits.**
  1. `docs`: decision 160 and this entry.
  2. `fix(h11)`: the `discard` phase, and the server's limit and deadlines on it.
  3. `fix(server)`: the staged close and `half_close`.
  4. `fix(server)`: the half-close and the read in the `colibri` module and `src/testing`.
  5. `fix(h11)`: the close option in a response that ends at its head, when the server knows
     that it closes (RFC 9110 §10.1.1, decision 160 ruling 5).
  6. `test(server)`: each loop receives after the half-close, at one instant for every turn.
  7. `test(server)`: a failure in the `discard` phase closes at once. The check of the failure
     in `staged` was dead code, because each failure stops the connection first. It became an
     assertion.
  8. `test(server)`: the host client of `tools/h11_server_interop.sh` checks the half-close by
     an acknowledgement, and not by a clock.
  9. `docs`: this list.
- **The checks.** A 405 to a POST with a 10 KiB body keeps the connection, which serves a
  second request, with a Content-Length and chunked. A body past the bound gets the staged
  close, and the client reads the whole 405 before the close. A client that never closes is
  closed 1 s after the half-close, at a simulated instant. A peer that drips the body is cut by
  decision 110's body deadline. A malformed chunk in the `discard` phase closes at once.
  `tools/h11_server_interop.sh` runs curl against the router's 405, with a body under the bound
  and one past it. A python3 client on the host then keeps writing past the bound:
  1. It reads the whole 405 and the end of the data, with no reset.
  2. A write after that is acknowledged. A full close answers it with a reset.
  3. A later write fails, at the server's close.

  No step reads a clock to decide. Step 2 must end within the server's bound of 1 s after its
  half-close, and on an idle host it takes some milliseconds.
- **Checked on macOS 26.6.2 arm64 on 2026-11-10:** 20 runs of `tools/h11_server_interop.sh curl`
  passed, and 10 more passed with two busy processes on each of the 10 cores. With the test
  server's half-close made a full close, the script failed in 3 runs of 3.
- **The close in the head, 2026-11-16.** Decision 160 ruling 5 as amended, for v0.17.2.
  connectrpc's conformance suite v1.0.7 reuses its connections, and 1 to 4 of its 2,852 server
  cases over h11 failed in each of connect-zig's runs with "unexpected EOF". The server
  answered a message past its limit before the body ended, with a response that has a body.
  The head said nothing, the server closed, and Go's client sent its next request on that
  connection.
  - `leaves_body` in `h11/connection/connection_server.zig` no longer excuses a response
    whose body is open, and `discard_fits` is false for a chunked rest. So the head carries
    `Connection: close` for a rest past the bound and for a chunked rest.
  - The `discard` phase reads a fixed rest alone. `discard_left` goes, and `start_discard`
    asserts that a rest that does not fit had its close said at the head. Each h11 connection
    shrinks by 8 bytes.
  - A chunked body answered early now gets the staged close at once. The engine reads none of
    what follows the response, so a malformed chunk there fails nothing, and the test of that
    failure goes.
  - A client test used colibri's h11 server as the peer that answers a chunked upload early
    with no close option. That peer now says the close, so the test writes the head itself.
  - **Mutations, 6 of 6 CAUGHT:** a response whose body is open says no close; a chunked rest
    fits when the bound is above 0; a fixed rest at the bound does not fit; a request with no
    open body says the close; the `discard` phase never starts; and a discarded body's end
    starts no next request.
  - **Checked, 2026-11-16,** on `c1b59ce0`, which v0.17.2 names:
    - `tools/ci.sh` passed 31 sections, with Zig 0.16.0 on an Apple M1 Pro with macOS. It ran
      no TLA+ model and no line coverage, which GitHub's jobs run.
    - The judge measured it against `967bd100` in two jobs, with the h11 inputs. Each of the 15
      inputs was within the noise
      ([run 43888582882](https://github.com/c4milo/colibri/actions/runs/43888582882)). h11-one
      took 20,204 and 20,188 user instructions a connection, against 20,179 and 20,206.
    - The h11 tests, 178 of 178, and the server tests, 740 of 740, passed on x86-64 Debug in an
      amd64 container.
    - GitHub's run passed: the `checks` job on x86-64 Linux, with the line coverage check, and
      the `arm64` jobs on Linux and macOS
      ([run 43909610813](https://github.com/c4milo/colibri/actions/runs/43909610813)). GitHub
      gave the macOS job a runner only in its second attempt.
- **The program that reads on, 2026-11-16.** Decision 160 ruling 5 as amended again, for
  v0.17.3. connect-zig built against v0.17.2, and its `streaming` example failed. Each stream
  route that answered a chunked request before its end got the close option. So a round of
  three calls over one connection ended its third call `refused` (decision 124).
  - **The public name** is the field `server.ResponseHeader.request_body`: `.discard`, the
    default, or `.keep_reading`. The owner ruled the field and its two values. connect-zig's
    stream routes need it, through `server.Router`, which sets it. A program that calls
    `server.Engine.respond` sets it itself.
  - `push_head` in `server/response/response_internal.zig` gives `.keep_reading` when the
    response is open and its route asked for no end, and `.discard` otherwise.
  - `write_head` in `server/connection/connection_coding.zig` copies the field into
    `h11.Connection.request_body` before each h11 head. h2 and h3 read it nowhere, because a
    stream ends alone (RFC 9113 §8.1).
  - In `h11/connection/connection_server.zig`, `leaves_body` returns false for
    `.keep_reading`.
    `start_discard` starts the phase for a chunked rest again, and `discard_left` bounds its
    read, as before v0.17.2. `rest_fits` judges a head, and `rest_may_fit` judges the end of a
    response. Each h11 connection is 35,056 bytes again.
  - **The tests:**
    - Six in `h11/connection/connection_discard_test.zig`: a program that reads on, and each
      rest that it can leave.
    - Two in `server/connection/connection_discard_test.zig`, and two restored in
      `server/engine/engine_staged_close_test.zig`.
    - One of `push_head` in `server/response/response_test.zig`.
    - One in `server/router/router_duplex_test.zig`: a struct route answers a chunked body
      before its end, and the connection serves the next request.
  - **Mutations, 7 of 7 CAUGHT:** `leaves_body` gives the close to a program that keeps
    reading; a chunked rest never starts the `discard` phase; the `discard` phase reads past
    the bound; a request keeps the `.keep_reading` of the request before it; the server does
    not copy the field to h11; `push_head` gives each head `.discard`; and `push_head` gives
    each head `.keep_reading`.
  - **Checked, 2026-11-16,** on `2c2144db`, which v0.17.3 names with step 53 and stdx v0.1.2:
    - The h11 tests, 183 of 183, and the server tests, 754 of 754, passed on x86-64 Debug in an
      amd64 container.
    - The judge measured it against `f8db00c4` in two jobs, with the h11 inputs. Each of the 15
      inputs was within the noise
      ([run 43982890851](https://github.com/c4milo/colibri/actions/runs/43982890851)).
    - `tools/ci.sh` passed 31 sections, with Zig 0.16.0 on an Apple M1 Pro with macOS. The first
      run on that commit failed its section "Lint and tests". Its report named no test and no
      compile error, and `tools/ci.sh` deletes the section's whole output at its end, so the
      cause is not known. `zig build test` then passed twice on the same tree, and so did a
      whole run, which kept each section's output.
    - GitHub's run passed: the `checks` job on x86-64 Linux, with the line coverage check, and
      the `arm64` jobs on Linux and macOS
      ([run 43993121130](https://github.com/c4milo/colibri/actions/runs/43993121130)).
- **The close after the shutdown, 2026-11-22.** A fix of decision 160's staged close, after
  connect-zig's conformance suite read "unexpected EOF" over h11.
  - **The fault.** A socket that failed while its shutdown was in flight wrote its close at
    once. Rotor's close first cancels each operation on the descriptor, and then closes it.
    That cancel does not find a shutdown that has not started. io_uring runs a shutdown on a
    worker thread, and the worker looks up the descriptor only when it starts: Linux 6.18's
    `io_shutdown_prep` sets `REQ_F_FORCE_ASYNC`, and a cancel by descriptor matches a request
    by its file. So the close freed the descriptor's number first. The next accept could take
    the number, and the shutdown then ended the write side of that new connection. Its client
    read a FIN and no response.
  - **How it showed.** connectrpc's conformance suite v1.0.7 failed one h11 case in about one
    run of three, on connect-zig's server over v0.19.0. A capture showed the server read a
    whole request and then sent a FIN with no byte of a response. Prints in `colibri.Server`
    then showed socket 9 shut down descriptor 14, failed, and closed it. Socket 10 accepted a
    connection on descriptor 14, and socket 9's shutdown completed after that. Socket 10's
    first send then failed with a reset.
  - **The change.** `socket.zig`'s `arm` writes no close while `shutting_down`. The shutdown's
    completion steps the socket, and the close follows. `src/testing`'s server socket does the
    same through `close_due`, and its `arm` takes any loop, so a test records what it submits.
  - **The tests:** two in `server_socket.zig`. One in `server_half_close_test.zig` takes the
    place of the test that wrote the close while the shutdown was in flight.
  - **Mutations, 4 of 4 CAUGHT:** the library's close ignores the shutdown in flight;
    `close_due` ignores it; the test server's `arm` submits a receive while the socket ends;
    and the test server ends before its bytes are out.
  - **Checked, 2026-11-22,** with Zig 0.16.0 on x86-64 Linux 6.18, in a container with no IPv6:
    - `zig build test-colibri` passed 149 of 150. The one that fails, decision 156 ruling 13's
      test of a UDP socket of each family, fails on main too, for want of IPv6.
    - `zig build test-testing` passed 64 of 64, and `zig build lint` passed.
    - connect-zig's conformance server, built on v0.19.0 with this change through `zig build
      --fork`, ran the suite's h11 cases in zstd and br 30 times, and none failed. On v0.19.0
      alone, 4 of the first 11 runs failed. The whole server half then passed 5 runs of 5.
