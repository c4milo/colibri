# Design §8 step 35: Careful Resume (RFC 9959), proposed 2026-11-04

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 149](../../decisions/0149-colibris-quic-connections-may-resume-congestion.md).
- **The public names,** each listed in a test beside its root before the code (decision 115):
  - `quic.ResumeState`: `version`, `size`, `window_len` (§3.1's saved_cwnd), `rtt_ns`
    (saved_rtt) and `saved_at_ns`. A program stores it as it stores a ticket.
  - `quic.ResumeBounds`: `jump_len_max` (§3.3's max_jump) and `lifetime_ns` (§4.3.1).
  - `quic.Connection`'s options gain `resumed_from: ?ResumeState` and `resume_bounds`. Zig
    reserves `resume`, so no name is that word.
  - `quic.connection_resume.observe(connection, now_ns) ?ResumeState`: the set to save, or
    null when the window is below four initial windows (§3.1).
  - `server.ResumeProvider` and `client.ResumeProvider`, each with `take` and `put`, and
    `server.Config.resumes` and `client.Config.resumes`, null by default, beside `logs`.
  - `quic.constants.policy.resume_jump_len_max_default`, 4 MiB, and
    `resume_lifetime_ns_default`, 1 hour.
- **The rules,** each cited to RFC 9959 in the code (non-negotiable 9):
  - Reconnaissance: the initial window, and the normal controller. Congestion, a saved set
    past its Lifetime, or a minimum RTT at or below half of `rtt_ns` ends Careful Resume (§3.2).
  - Unvalidated: the window is at most `min(jump_len_max, window_len / 2)`, paced over the
    current RTT. The phase ends on congestion, on the first acknowledgment of an unvalidated
    packet, once the window is full, or after one RTT (§3.3).
  - Validating and Safe Retreat as §3.4 and §3.5, with Beta at the controller's own β.
  - BBRv3 by Appendix C.
- **The checks.**
  - Unit tests of each phase's entry and exit, for each controller.
  - A simulator check: a connection that observes, then a second one that resumes on the same
    path and finishes sooner, and one whose path lost capacity and retreats.
  - A TLA+ model of the phases, whose mutants break §3.2's RTT check, §3.3's half of the
    saved window and §3.5's halving.
  - A Lean proof of the jump and the retreat arithmetic.
  - The judge's bulk run, with a second download that resumes.
- **What it costs.** A `quic.Connection` grows by the phase state, 56 bytes in 35a. The
  provider is the program's, so colibri holds no table.
- It lands in five parts: 35a, the saved set, the bounds, `observe` and the option; 35b, the
  phases under CUBIC and NewReno; 35c, BBRv3 by Appendix C; 35d, the providers of
  `server.Endpoint` and `client.ConnectionPool`; and 35e, the simulator check, the model, the
  proof and the judge run.
- **35a, the saved set, 2026-11-04.**
  - `quic.ResumeState` is an extern struct of 32 bytes: `version`, `size`, `window_len`,
    `rtt_ns` and `saved_at_ns`. `usable` refuses another version or size, an empty window or
    round trip, a set from after now, and one past its Lifetime (§3.2, §4.3.1).
  - `quic.connection_resume.observe` saves the window in congestion avoidance, half of it in
    slow start (§4.1), BBRv3's BDP under BBRv3, and nothing below four initial windows (§3.1).
  - The option `resumed_from` starts the Reconnaissance Phase, and a new path ends it (§3.2).
    The window does not change yet: 35b changes it.
  - The example in `examples/` and the section of docs/usage.md come with 35d, where a program
    reaches Careful Resume through `server.Config.resumes` and `client.Config.resumes`.
- **35b, the phases under CUBIC and NewReno, 2026-11-04.** `recovery_resume_phases.zig`
  takes three calls from `Recovery`: an application packet recorded, an ACK frame, and a new
  congestion event. An ACK frame's bytes join PipeSize before loss detection, so a retreat the
  same frame starts halves a PipeSize that holds them.
  - Reconnaissance: an acknowledged initial window, with a minimum round trip above half the
    saved one and at most ten times it, enters the Unvalidated Phase (§3.2, §4.2.1).
    Congestion first ends Careful Resume.
  - Unvalidated: the window jumps to `min(jump_len_max, window_len / 2)`, and PipeSize starts at
    the flight size (§3.3). A jump no larger than the window ends Careful Resume. A full
    window, the first unvalidated packet acknowledged, or one round trip ends the phase. The
    window then falls to PipeSize, held at the initial window, or takes the flight size and
    the Validating Phase starts.
  - Validating ends once the last unvalidated packet is acknowledged (§3.4). Congestion in
    either phase retreats: the window falls to half of PipeSize, held at the minimum, and
    `retreated` says to delete the saved set (§3.5). The window holds until the last
    unvalidated packet is acknowledged, and ssthresh is then at most PipeSize times the
    controller's β.
  - Persistent congestion ends Careful Resume (§3.6). BBRv3 stays in Reconnaissance, which
    changes nothing, until 35c.
  - 22 mutations, each **CAUGHT**: the path confirmed early; the half and the ten-times checks
    of the round trip; a jump of the whole saved window; max_jump ignored; a jump below the
    window; a full window, or the first unvalidated acknowledgment, not ending the phase; an
    unused jump kept; the Validating Phase on the jump window, or never ending; congestion in
    Reconnaissance kept; no retreat; a retreat that does not halve; the saved set kept; growth
    in Safe Retreat, NOT CAUGHT until its test was added; no ssthresh after it; persistent
    congestion kept; PipeSize, congestion events or sent packets never reported; and BBRv3
    under the window rules.
- **35c, BBRv3 by Appendix C, 2026-11-04.** `recovery_bbr/recovery_bbr_resume.zig` holds
  Appendix C's "carefully-resuming" flag in BBRv3's state. Reconnaissance is §3.2's, the same
  for the three controllers.
  - A confirmed path in Startup waits for the next round, then sets the flag for
    `resume_rounds`, 2 (C.1). The probing rate is the jump over the saved round trip. While the
    flag holds in Startup, the pacing rate is at least the probing rate, and the window covers
    the larger of `BBR.bw` and the probing rate over `BBR.min_rtt` at the cwnd gain.
  - A path confirmed after Startup does not resume (C.1). Congestion with the flag set leaves
    Startup for Drain, the Safe Retreat Phase, and the saved set goes (C.3). Drain discards its
    delivery rates while the flag holds, and leaving Drain clears it (C.3). BBRv3's own rules
    exit Startup, which is the Validating Phase (C.2).
  - 14 mutations, each **CAUGHT**: a flag outside Startup; the flag never set; set before a
    round starts, NOT CAUGHT until its test was added; never cleared; Drain keeping its rates;
    no raised pacing rate; no raised window; congestion kept in Startup; the flag kept after
    Drain; the probing rate doubled; the rounds never run; a refused start left Unvalidated;
    the saved set kept after a retreat; and persistent congestion keeping the flag.
- **35d, the providers, 2026-11-04.** `quic.ResumeProvider` has three calls: `take`, which
  claims a set for one connection; `put`, once when that connection ends, with what it
  observed or null; and `drop`, before `put`, when the connection retreated (§3.5). `server`
  and `client` re-export it beside `ResumeState` and `ResumeBounds` (decision 126), and each
  `Config` takes `resumes` and `resume_bounds`.
  - The plan named `take` and `put`. `drop` joins them because `put`'s null keeps a held set,
    so a retreat needs a call of its own.
  - A server's connection, and a client's, takes its set only once its start succeeded, so no
    failed start leaves a set claimed. The server puts when the connection ends; the client
    puts in `transport_closed`, once, stamped with the latest instant its controller was given.
  - `examples/server_resume.zig` is the server example's provider: a table of four addresses
    with no allocator, which gives a set to one connection at a time. `server_exchange.zig`
    requires one `take` and one `put`, and docs/usage.md shows `take`.
  - 10 mutations, each **CAUGHT**: on each side, no set taken, the set ignored, nothing put
    back and nothing dropped after a retreat; on the server, a drop after the put; on the
    client, a second close that puts twice.
- **35e, the simulator, 2026-11-04.** `quic_connection_resume_check.zig` runs the QUIC
  connection check with the client resuming from a saved set, under each controller, over a new
  network, `light_loss`: at most 5 drops in 1,000, the default duplicates, no ECN-CE mark, and
  one delay of 15 ms. The client sends 256 KiB.
  - The lossy network of the other checks ends every resume in Reconnaissance, rightly: its marks
    and its random delays, which reorder packets past RFC 9002's threshold, are congestion events
    before the initial window is acknowledged. `light_loss` lets most seeds jump.
  - The saved window is 120,000 bytes under CUBIC and NewReno, whose slow start has reached
    about 35,000 when the path is confirmed, and 60,000 under BBRv3, whose window is twice the
    probing rate's BDP. `network_in_flight_max` grows from 64 to 128 for BBRv3's window and the
    acknowledgments.
  - Of 256 seeds each, CUBIC and NewReno jumped on 239 and retreated on 14, and BBRv3 jumped on 233
    and retreated on 32. The censuses are pinned, and Debug and `-Drelease` give the same ones.
    The existing checks' censuses did not change.
  - 2 mutations against the check, each **CAUGHT**: a jump that never widens the window, and a
    retreat that does not halve PipeSize.
- **35e, the model and the proof, 2026-11-04.** `spec/tla/careful_resume` models the phases under
  CUBIC and NewReno in datagrams. It holds over 57,285 states: the jump stays at or below half
  the saved window and max_jump, the window jumps only after the initial window is acknowledged,
  a retreat leaves at most half of PipeSize and deletes the set, the window does not grow in Safe
  Retreat, and Careful Resume never starts again once it ends. Each of its 5 mutants is violated.
  `spec/lean/Colibri/Quic/CarefulResume.lean` proves the jump's two bounds, the retreat's bounds
  and that it never raises the window, and that the threshold after it is at most PipeSize.
  - `quic.Connection` grows by 56 bytes, to 208,376, and `server.Endpoint` at its default
    capacity to 52,447,248 on main f5649a00. docs/performance.md lists each size.
  - 14 mutations, each **CAUGHT**: another version, another size, an empty window, a set from
    after now and one past its Lifetime each used; `init` taking an unusable set; a new path
    that keeps Careful Resume, in `Resume` and in `Recovery`; slow start saving the whole
    window; a small window saved; the smoothed round trip saved; a set saved with no sample;
    BBRv3's BDP in the wrong unit; and the option ignored.
- **35e, the judge run, 2026-11-14.** The bulk run of step 13k gains `h3-resume`: 5 downloads
  of the file of 2 MiB from colibri under each of its three controllers, each download alone
  and on a connection of its own. Each server runs as the other loads run it, and then with
  `careful-resume`.
  - The UDP server's word `careful-resume` gives `server.Config.resumes` a table of 16 hosts,
    `src/testing/quic/udp/udp_resume.zig`. A client opens each connection from another port,
    so the table compares hosts and no ports (RFC 9959 §2.2).
  - The provider's calls name a host and no connection. So the table counts each host's open
    connections, and gives a set only to a connection that is its host's one open connection
    (§3.2). A table that follows §3.2 exactly needs a call that names the connection.
  - oha sends no close after one download, and holds the connection for the idle timeout of
    30 s. The word `idle=<milliseconds>` makes the server advertise another one, and these
    loads advertise 2 s.
  - A server with `careful-resume` serves one download more first, which saves the set. Its
    log gives its counts after each connection's end, and each download waits for that line.
    The report gives the median time of a download from each server, the ratio, and how many
    connections took a set and how many retreated.
  - `tools/quic_udp.sh` requires a client's second connection to take what its first one
    saved, and the client's qlog to hold the idle timeout of `idle=1500`.
  - The bench job's limit goes from 180 to 210 minutes, because the loads add about 7 minutes
    a round.
  - The new tests pass on x86-64 Debug in an amd64 container.
  - 25 mutations, each **CAUGHT**. Of the table: ports compared; a second open connection, or
    one that `take` did not count, given the set; `put` that leaves its connection open or
    deletes the set for a null; `drop` that keeps the set or deletes every host's; a full
    table that gives a new host an entry; a count below zero; and each of the three counts
    wrong. Of the words: `careful-resume` or `idle` taken without `h3`, a number of 0 taken,
    `careful-resume` that sets nothing, and `idle` that sets the clock. Of the server: no
    provider given to the engine, and `idle` ignored. Of the report: download 0 or round 0
    counted, the idle wait counted in the time, the ratio inverted, the sets taken not
    summed, and the retreats read from the sets taken.
  - [Run 43627411197](https://github.com/c4milo/colibri/actions/runs/43627411197), 3 rounds,
    measured `712936c1`, a branch whose bench code is the code above. The median time of one
    download on a connection of its own, over 15 downloads, in job 1 and job 2:

    | Path | Server | New (ms) | Resumed (ms) | Resumed / new | Took a set | Retreated |
    | --- | --- | --- | --- | --- | --- | --- |
    | 20 Mbit/s, 25 ms | colibri (CUBIC) | 1078 and 1078 | 1032 and 1032 | 0.96 and 0.96 | 15 and 15 | 0 and 0 |
    | 20 Mbit/s, 25 ms | colibri-bbr | 1083 and 1083 | 1066 and 1066 | 0.98 and 0.98 | 15 and 15 | 0 and 0 |
    | 20 Mbit/s, 25 ms | colibri-newreno | 1078 and 1078 | 1051 and 1051 | 0.98 and 0.98 | 15 and 15 | 0 and 0 |
    | the same, 1% loss | colibri (CUBIC) | 5863 and 5904 | 6673 and 6692 | 1.14 and 1.13 | 1 and 0 | 1 and 0 |
    | the same, 1% loss | colibri-bbr | 1118 and 1114 | 1105 and 1135 | 0.99 and 1.02 | 15 and 15 | 4 and 5 |
    | the same, 1% loss | colibri-newreno | 7116 and 6952 | 6208 and 6910 | 0.87 and 0.99 | 0 and 0 | 0 and 0 |

  - With no loss, each connection took a set, and a resumed download took 17 ms to 46 ms less.
    A download on a connection that is already open takes 946 ms in the same run. So under
    CUBIC, Careful Resume removes 46 ms of the 132 ms that a new connection adds.
  - With 1% loss, CUBIC and NewReno end each connection with a window below four initial
    windows, so they save no set (RFC 9959 §3.1). One connection of CUBIC in job 1 took a set,
    and retreated. Their ratios are the noise of one download under loss, which
    [#123](https://github.com/c4milo/colibri/issues/123) tracks for CUBIC.
  - BBRv3 saves its BDP under loss too, so each connection took a set. 4 and 5 of 15
    retreated (§3.5), and the time did not change.
  - Each job took 157 and 158 minutes, against 132 for the last bulk run.
- **The address of `put` and `drop`, 2026-11-14.** The owner ruled on the report of the 35e
  judge run (decision 149 as amended). A server's `put` and `drop` named the path's address
  at the connection's end. So a connection that moved ended no claim at the host of its
  `take`.
  - The server's QUIC connection keeps `started_from`, the address of `Start.peer`, and
    `close_resume` gives it to `put` and `drop`. The engine asserts that `take` gets the same
    address.
  - A connection that moved to another host gives `put` null. Its set is for the path to the
    host it moved to (RFC 9959 §3.1).
  - `examples/server_resume.zig` counts each host's open connections, as `udp_resume.zig`
    does, and gives a set only to a host's one open connection (§3.2). Its check requires a
    second open connection to get no set. docs/usage.md shows the new `take`.
  - A client's `take` and `put` each name `server_address`, which does not change, so the
    client is as it was.
  - Each QUIC slot of an engine grows by 24 bytes, the size of a `PeerAddress`.
  - The new tests pass on x86-64 Debug in an amd64 container, 687 of 687.
  - `tools/ci.sh` on `08ccc6a4`, on an Apple M1 Pro with macOS 26.6.2: 31 of 31 checks
    passed. [Run 43668695539](https://github.com/c4milo/colibri/actions/runs/43668695539)
    passed the `checks` job on x86-64 Linux and both `arm64` jobs.
  - 7 mutations, each **CAUGHT**: `put` and `drop` that name the path's address; `drop` alone
    that names it; a moved host that saves its set; a connection on the same host that saves
    none; a start that keeps no address; and in the example, a second open connection that
    gets the set, and a `put` that leaves its connection open.
