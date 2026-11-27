# Design §8 step 48: session tickets in colibri's servers and client, ruled 2026-11-10 and 2026-11-11

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 161](../../decisions/0161-colibris-servers-issue-session-tickets-and.md), for v0.16.0. RFC 9846 §2.2, §4.7.1 and Appendix C.4.
- **Why.** Step 13j's profiles found that wrk resumes almost every session with hyper. A
  resumed handshake skips the certificate and its signature. colibri's TCP servers issue no
  ticket, so each connection to them runs a full handshake, and the P-256 signature takes 11% of
  the server's samples on h11-tls-one. A client of a real colibri server cannot resume either.
- **What stops a ticket today.** `tls.values.Server.ticket_key` is null unless a program sets
  it, and chapulin issues no ticket under a null key. A `.private` `colibri.Server` also passes
  0 as the Unix time to `server.Engine.init`. The engine dates each connection's tickets from
  that value, and 0 means none (`engine_connections.seconds_at`).
- **The public names,** each listed in decision 115's form:
  - `colibri.ServerConfig.unix_seconds`, a `u64` with no default, as
    `colibri.ClientConfig.unix_seconds` (decision 150 ruling 9). It holds the seconds since 1970
    when `run` starts. The program reads its clock, and colibri reads none (non-negotiable 3).
    - The field breaks each program that builds a `ServerConfig`. That program does not compile
      until it passes the field. The owner ruled on 2026-11-10 that the step ships in v0.16.0
      for that reason, beside v0.16.0's other breaking changes.
  - `colibri.ServerConfig.ticket_key`, a `?[tls.constants.protocol.server_key_len]u8`, null by
    default. The server copies a key the program passes (decision 158). With null, it draws its
    own key at start from its random source, as it draws its cookie key. Either way it writes
    zero over its copy at `deinit`. A program that runs several servers passes one key to each,
    so each server resumes the tickets of the others.
  - `ticket_key` in the `.hosted` configuration, a literal with no public name (decision 156
    ruling 2), under the same rule. A `.hosted` server takes the Unix seconds in `now`.
  - `tls.constants.protocol.ticket_lifetime_max_s`, 604,800 s: RFC 9846 §4.7.1's bound on a
    ticket's lifetime, which `colibri.Client` checks before it offers a ticket.
  - `core.constants.nanoseconds_per_millisecond`, the unit RFC 9846 §4.3.11.1 counts a
    ticket's age in.
  - No name of a library module's root changes. `colibri.Client` keeps tickets with no new name:
    `pool.tls.takes_tickets` stays its switch (decision 161 ruling 6).
- **The test-only TCP server.** `http-server` takes `--seconds <unix-seconds>`. With it, the
  server draws a ticket key from its entropy at start, as `quic-udp` does, and issues tickets.
  Without it, the server issues none, as before. Rotor's instant is 0 until a loop's first
  tick, so the worker ticks once with no wait and then starts its engine at that instant, as
  `udp_run.zig` does (decision 63). An assertion refuses a Unix time with an instant of 0.
  `bench/run.sh` passes `date +%s` to each colibri server whose usage names the option, so a
  base tree from before this step still runs.
- **What does not change.** chapulin chooses the lifetime and the count of the tickets, and RFC
  9846 §4.7.1 bounds the lifetime at 604,800 s. A resumed session still runs X25519, as hyper's
  does. Decision 20 still refuses 0-RTT.
- **The commits.**
  1. `docs(bench)`: the h11 profiles of step 13j, which found that wrk resumes with hyper alone.
  2. `docs`: decision 161 and this entry.
  3. `feat(server)`: the test-only TCP server's `--seconds` and its ticket key.
  4. `test(server)`: the server interop scripts require Go's client to resume over TLS.
  5. `feat(bench)`: `bench/run.sh` passes `--seconds`. The commands that start each server
     move to `bench/run_servers.sh`, because `bench/run.sh` reached 500 lines.
  6. `feat(colibri)!`: `ServerConfig.unix_seconds` and `ServerConfig.ticket_key`, the `.hosted`
     configuration's `ticket_key`, the example, README.md, docs/usage.md and `tools/consumer/`.
  7. `feat(colibri)`: `colibri.Client` keeps the newest ticket of each transport and offers it
     once (`client_tickets.zig`).
  8. `docs`: this list, the checks and docs/usage.md's paragraph on the client's tickets.
- **The checks.**
  - Go's client resumes its new connection to the test-only server over TLS, in
    `tools/h11_server_interop.sh --tls` and `tools/h2_server_interop.sh --tls`. Against a server
    started without `--seconds` it runs a full handshake. The client sends its last request
    through a copy of its transport: after `CloseIdleConnections`, the transport could still
    reuse a plan connection that was not idle yet, and the check then failed in 7 runs of 10.
  - `--seconds` takes Unix seconds above 0, and only with `--tls`.
  - `colibri.Server`: the TLS values hold the server's copy of the program's ticket key, or a
    key drawn after the cookie key. `deinit` wipes the copy. `run` starts the engine at
    `ServerConfig.unix_seconds`. A `.hosted` server takes its key and the Unix seconds of
    `now`.
  - `colibri.Client` against `colibri.Server` over TLS: the server closes each of three
    connections after its response, and the second and the third resume with the ticket of the
    one before. On a fake host with h3 alone, a QUIC connection ends at its idle timeout, and the
    next one, in QUIC version 2, resumes. `deinit` leaves no ticket. With h3 and h2 both
    allowed, the pool opened h2 after the QUIC connection ended, so the test allows h3 alone.
  - The client offers a ticket once, keeps the newest, keeps each to its transport, and offers
    none past its lifetime or seven days.
  - Mutations, 23 of 23 CAUGHT. The client: no ticket kept, none offered over TCP or over QUIC,
    a ticket offered twice, no lifetime check, no seven-day bound, the caller's copy not wiped,
    every ticket taken as TCP's, and `deinit` not wiping. The test-only server: no key drawn,
    the time not passed, the first tick removed, `--seconds 0` accepted, `--seconds` without
    `--tls`, the value dropped, and tickets issued without `--seconds`. `colibri.Server`: the
    program's key not copied, no key in the values, the key not wiped, `run` passing 0, the time
    not kept at `init`, and the key not passed by either kind.
- **The judge.** Run [42972694487](https://github.com/c4milo/colibri/actions/runs/42972694487), on
  `32dd6257`, ran `competitors` with `h11`. On h11-tls-one wrk now resumes with colibri too,
  as it does with hyper. For each connection, job 1 and then job 2:

  | For each connection | colibri before | colibri | hyper |
  | --- | --- | --- | --- |
  | instructions | 940,303 and 940,369 | 790,233 and 791,028 | 809,891 and 810,107 |
  | cycles | 535,615 and 528,049 | 450,235 and 454,882 | 542,217 and 541,129 |
  | CPU time, µs | 173.0 and 170.9 | 143.3 and 145.4 | 167.4 and 167.3 |

  "Before" is run [42967637728](https://github.com/c4milo/colibri/actions/runs/42967637728), on
  `83d58c09`, where `bench/run.sh` passed no `--seconds`: `takes_seconds` piped the server's
  usage into grep, and under pipefail the server's exit status 2 failed the pipe. colibri now
  takes 0.976 of hyper's instructions on h11-tls-one in both jobs, where it took 1.161 and
  1.163. h11-tls-many does not change, at 1.21 of hyper's, because its connections live for
  the whole load.
- **Checked on macOS 26.6.2 arm64 (Apple M1 Pro) on 2026-11-11:** `tools/ci.sh` passed 31 of
  31 sections on `b0ef2269`, with the TLA+ models skipped, as decision 67 as amended rules. An
  earlier run found `src/colibri/loop_check_test.zig`, which only `colibri-loop-check` compiles,
  with no `unix_seconds`.
- **A test that read undefined memory, 2026-11-11.** GitHub's `checks` job failed on `98278278`
  in Debug on x86_64 Linux alone, with 4,056 of 4,057 tests passed
  ([run 43031437569](https://github.com/c4milo/colibri/actions/runs/43031437569)). The test of
  `Kept.wipe` read a ticket's bytes after its optional became null. The payload of a null
  optional is undefined: Zig 0.16's x86_64 backend fills it with 0xaa in Debug, and LLVM leaves
  the zero bytes. So the ticket was wiped on each backend, and only the test was wrong.
  - Each kept ticket is now in plain memory with a flag, `Room`, in place of an optional. Its
    bytes stay defined after a wipe, and the tests read them. A new test checks that a ticket
    which is taken, or which is past its lifetime, leaves no byte in its room.
  - `tools/ci.sh` ran on arm64, which compiles Debug with LLVM, so it did not see the failure.
    The Debug tests of `client_tickets.zig`, built for x86_64-linux, pass in an amd64 container.
  - Mutations, 6 of 6 CAUGHT: the wipe not zeroing, a taken ticket left in its room with its
    flag or without it, the caller's copy not wiped, the QUIC room not wiped, and `deinit` not
    wiping.
- **What tickets cost a client that never resumes, 2026-11-11.** The record "Main against
  v0.15.0" of step 13 holds the run. On h2-tls-one, where h2load resumes no session, a
  connection takes 2.5% more instructions and 1.5 more system calls. On h11-tls-one, where wrk
  resumes, it takes 16% fewer. The owner ruled to accept the cost.
