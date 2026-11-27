# Design §8 step 29: BBRv3

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 134](../../decisions/0134-colibri-may-read-the-bbr-draft.md) builds BBRv3 from draft-ietf-ccwg-bbr-06 beside CUBIC, and
[decision 136](../../decisions/0136-bbrv3-draws-its-probe-waits-from.md) rules its random draws, its configuration and its
measurement. It adds one public name, `quic.CongestionController`. Each part brings its Lean proofs
and its TLA+ model, and the owner rules each part before it starts.
- **29a, delivery rate samples.** §4.1: each sent packet records the bytes delivered and the
  instant of the last delivery when it went out, and each ACK frame gives one rate sample, held
  at the send rate (§4.1.1.2.4), and marked when the application limited it (§4.1.2.4). CUBIC
  reads none of it, so the step changes no census except the endpoint check's.
  - **Check.** Tests drive each rule of §4.1.2: a sample from the newest acknowledged packet, a
    sample held at the send rate, no sample for an interval shorter than min_rtt, and the mark of
    an application limit. Lean proves the sample never above the send rate or the ACK rate.
    `spec/tla/rate_sample` checks, in every order of ACKs, losses and writes, that the mark of
    an application limit clears once its packets are delivered, and that a sample comes from
    the newest acknowledged packet.
  - The owner ruled on 2026-10-30:
    - Every record in each packet number space holds the four fields of §4.1.2.1.2 that 29a
      reads: `delivered`, `delivered_time`, `first_send_time` and `is_app_limited`. They add
      about 24 bytes a record, so about 18 KB to each connection.
    - `tx_in_flight` and `lost` come with 29b, the first part that reads them.
    - 29a brings the TLA+ model above beside its Lean proof.
  - **29a, 2026-10-30.** `recovery_delivery.zig` holds the state of §4.1.2.1.1, and
    `Recovery.on_packet_sent` writes each record's snapshot. Each ACK frame's sample comes from
    the largest packet it took, which went out last, and `recovery_ack.Outcome.rate` returns it.
    - colibri holds no send buffer, so `send` notes `ran_out_of_data` when it plans no packet
      and no limit held it. The window, the pacer, a full table, the peer's connection credit
      and RFC 9000 §8's limit each hold it (§4.1.1.3.1). The mark is checked at the start of
      `send`, of each ACK frame and of the loss timer (§4.1.2.4).
    - §4.1.2.2 reads `C.inflight` after the packet counts, which is never 0. colibri reads it
      before, as the sentence above the pseudocode means.
    - `window_of` moved to `connection_recovery.zig`, since `connection_send.zig` was at 500
      lines.
    - The record grew from 48 to 72 bytes, and `quic.Connection` from 176,888 to 195,360
      bytes. docs/performance.md lists each size.
    - `spec/lean/Colibri/Quic/DeliveryRate.lean` proves a sample never above the send rate or the
      ACK rate, its interval never shorter than min_rtt, and when the mark clears.
      `src/quic/recovery/delivery_vectors.txt` holds 903 of its answers, and a Zig test reads them.
    - `zig build tla` on `spec/tla/rate_sample` with 5 packets and a window of 3: the properties
      hold over 232,913 distinct states. Its three mutants are violated: a sample from the oldest
      packet, a mark without the bytes in flight, and a mark never cleared.
    - Mutations, against `zig build test-quic`, each CAUGHT: no reset on an empty path, the send
      interval alone, no min_rtt test, a clear at `>=`, no window test, a mark without the
      bytes in flight, no snapshot, nothing delivered, `first_sent_at_ns` kept, no check at
      `send`, at an ACK frame or at the timer, `ran_out_of_data` kept after a packet went out,
      and the window, the credit, a full table or §8's limit not counted as a limit.
- **29b, the model and the states.** §5: BBR.max_bw over a window of 2 bandwidth probe cycles,
  BBR.min_rtt over 10 s, and Startup, Drain, ProbeBW's four phases and ProbeRTT, with their
  pacing and window gains. `recovery_bbr.zig` holds them, and `recovery_congestion` calls BBRv3
  or CUBIC by the connection's `congestion_controller`.
  - **Check.** Tests drive each move of §5.3. Lean proves the filters' bounds, each probe wait
    between 2 and 3 s, and each round bound 62 or 63. `spec/tla/bbr` checks the moves in every
    order: ProbeRTT comes at most each 5 s and ends, and the state never stops in Drain.
  - The owner ruled on 2026-10-30:
    - 29b comes in four parts, each with its own commit, record and rulings: 29b.1 the model
      of the path (§5.5.1 to §5.5.9), 29b.2 the states (§5.3, §5.4), 29b.3 the model upon loss
      (§5.5.10, §5.5.11), and 29b.4 the pacing rate, the send quantum and the window (§5.6).
    - Each gain and factor of the draft is a numerator and a denominator, as for CUBIC.
    - §5.5.11 comes too. RFC 9002 does not detect a spurious loss, so 29b.3 first does, from a
      list of lost packets that the owner rules on before it is written.
    - The offload budget is the send quantum alone (§5.5.8.2). colibri owns no socket, so it
      cannot know whether the caller's sends offload pacing.
  - The owner ruled on 2026-10-31:
    - 29b.2 builds the states with what they read: `BBR.inflight_longterm`, its headroom and the
      2% loss check of §5.5.10, and `BBR.bdp` with `Inflight()` of §5.6.4.2. 29b.3 keeps the
      short-term model, the loss of each packet, Startup's exit on high loss and §5.5.11. 29b.4
      keeps the pacing rate, the send quantum and the window.
    - Each probe wait mixes `bandwidth_probe_waits` with the count of waits so far through the
      SplitMix64 finalizer (decision 136).
    - 29b.3 detects a spurious loss episode from a list of the packet numbers the episode
      declared lost, at most 32 of them, a new limit in `constants_limits.zig`. An episode that
      declares more is never undone, and the next episode replaces the list.
    - The undo of §5.5.11 is BBRv3's alone. CUBIC's, which RFC 9438 §4.9.2 permits, is not
      part of step 29.
  - The owner ruled on 2026-10-31, for 29b.3:
    - §5.3.1.3's loss rate is the bytes lost in a round over the bytes delivered and lost
      in it.
    - §5.3.1.3's lost range is a run of consecutive lost packet numbers.
    - The list of lost packet numbers holds the application space's alone. A loss in the
      Initial or Handshake space makes its episode one that is never undone.
    - BBR saves its undo state as the draft's pseudocode does: when a loss episode starts
      (§5.6.4.4) and at the first loss of each round (§5.5.10.2's `NoteLoss`).
  - The owner ruled on 2026-10-31, for 29b.4:
    - `Congestion` keeps RFC 9002's shared state, and a tagged union holds CUBIC's or BBRv3's
      own, so a connection pays for one controller.
    - On persistent congestion BBRv3's window falls to `kMinimumWindow`, as RFC 9002 §7.6.2's
      MUST says, after BBR saves its state as §5.6.4.4's `OnEnterRTO` does. QUIC has no RTO.
    - `quic.CongestionController` and the `congestion_controller` and `bandwidth_probe_waits`
      options of `quic.Connection` come in 29b.4, so the simulator's QUIC checks run once
      with each controller before the step is done. 29c keeps `server.Config`,
      `client.Config`, the examples and the judge.
  - **29b.1, the model of the path, 2026-10-30.** `recovery_bbr_model.zig` keeps §5.5.1's round
    count, §5.5.5's BBR.max_bw, §5.3.4.3's BBR.min_rtt and §5.5.9's BBR.extra_acked. Nothing
    calls it before 29b.4, so no census moves.
    - `recovery_bbr_filter.zig` keeps the largest value of each time in a slot of its own, so
      its answer is exact. The draft names Kathleen Nichols' filter, which keeps three samples
      and gives an estimate. The windows are 2 and 10 times long, so the slots are few.
    - Each record also holds `tx_in_flight` and `lost` (§4.1.2.1.2), so it grew from 72 to 88
      bytes. `C.lost` counts what RFC 9002 §6.1 declares lost. Decisions 64 and 66 declare
      packets lost only to send their frames again, so those do not count.
    - Each ACK frame that takes a packet out of flight gives a sample. Its rate is 0 when the
      interval is not reliable, as in the draft, because §5.5.1 reads the sample's other fields.
      Losses that a frame reveals count in later samples, because the sample comes first.
    - `RS.rtt` runs from the newest packet's send to the frame, ACK delay included (§5.5.7.1).
      BBR.min_rtt starts at the draft's "Infinity", the largest `u64`, since a connection starts
      with no round trip sample.
    - `spec/lean/Colibri/Quic/BbrModel.lean` proves the filter's answer the largest value of its
      window, the round count rising by at most 1, BBR.min_rtt never above
      BBR.probe_rtt_min_delay, and the extra bytes never above the window.
      `src/quic/recovery/recovery_bbr/bbr_model_vectors.txt` holds 738 lines of its answers, and a Zig test
      reads them.
    - The record's two fields grew `quic.Connection` from 195,360 to 207,656 bytes.
      docs/performance.md lists each size.
    - Mutations, against `zig build test-quic`, each CAUGHT: no slot cleared, a window one time
      wider, a round at `>`, a round that ends at `RS.prior_delivered`, an application-limited
      sample always or never counted, no cycle advance, the probe's expiry at `>=`, a probe or a
      BBR.min_rtt that never expires, BBR.min_rtt's instant taken as now, no new interval, extra
      bytes not held at the window, a window of 10 in Startup, `expected_delivered` in
      milliseconds, `tx_in_flight` without its packet, `RS.lost` as `C.lost`, no loss counted,
      `P.lost` not kept, `RS.rtt` from the first send, `RS.prior_delivered` as `C.delivered`, and
      a rate from an interval below min_rtt. The application-limited sample counted was NOT
      CAUGHT at first; a test that drops the larger sample two cycles later now catches it.
  - **29b.2, the states, 2026-10-31.** `recovery_bbr/recovery_bbr.zig` holds `Bbr`, which
    moves through Startup, Drain, ProbeBW's four phases and ProbeRTT on each ACK frame, and
    handles the restart after an idle period before a send (§5.3, §5.4). One file holds each
    state's moves, `recovery_bbr_inflight.zig` the volumes they compare with, and
    `recovery_bbr_wait.zig` the draws. Nothing calls `Bbr` before 29b.4, so no census moves.
    - The BBR files moved into `src/quic/recovery/recovery_bbr/`, as CLAUDE.md asks of four or
      more files with one prefix.
    - Every gain is a count of hundredths: 2.77 is 277 (§5.6.1's table).
    - §5.3.3.8.2's Reno bound compares round trips with `TargetInflight`, which is a volume. A
      Reno flow grows by one datagram a round trip, so colibri divides the volume by the maximum
      datagram size before it takes the smaller of it and 63.
    - Each wait draws from `mix(bandwidth_probe_waits + count × 0x9e3779b97f4a7c15)`, the
      SplitMix64 finalizer: bit 0 is the round trip start, and the rest give the wait.
    - `C.cwnd` is `Bbr.window_len`, which ProbeRTT saves and restores and 29b.4 sets. Until then
      it holds the initial window.
    - §5.4 also paces at the estimate after an idle period in ProbeBW. That is pacing, so 29b.4
      adds it.
    - `spec/lean/Colibri/Quic/BbrStates.lean` proves each wall clock wait at least 2 s and below
      3 s, each round trip start 0 or 1, so a wait lasts 63 or 62 rounds once the Reno bound is
      63, the volume with headroom never below `BBR.MinPipeCwnd` nor above
      `BBR.inflight_longterm`, and no compared volume below the floor.
      `src/quic/recovery/recovery_bbr/bbr_states_vectors.txt` holds 142 lines of its answers, the
      draws among them, and a Zig test reads them.
    - `zig build tla` on `spec/tla/bbr`: the properties hold over 9,437 distinct states. They are
      ProbeRTT at most once each `BBR.ProbeRTTInterval`, its 200 ms and a round, its end in CRUISE
      or Startup, Drain bounded, and ProbeBW only after a full pipe. Each state must also end at
      the first ACK frame its rules allow. A liveness property cost TLC about a thousand times
      the time, so these safety properties stand in for it. Its six mutants are violated.
    - Mutations, against `zig build test-quic`, 42 of 42 CAUGHT. They cover each move of each
      state, each gain, each volume, each draw, and the idle restart. Twelve were NOT CAUGHT at
      first, and `recovery_bbr_probe_test.zig` now guards each of them:
      - a full pipe at exactly 1.25 times;
      - the cap of 63 Reno rounds;
      - the headroom before CRUISE;
      - REFILL's round;
      - UP held by a full window;
      - ProbeRTT's round and its 200 ms boundary;
      - the larger saved window and its restore;
      - the doubled slope and the growth of `BBR.inflight_longterm`;
      - ProbeRTT's pacing gain.
  - **29b.3, the model upon loss, 2026-10-31.** `recovery_bbr/recovery_bbr_loss.zig` holds
    §5.5.10's short-term model and its response to each lost packet, §5.3.1.3's end of
    Startup on high loss, and §5.5.11's undo. `recovery_spurious.zig` finds a spurious loss
    episode, and `recovery_ack.Outcome.spurious` reports it. Nothing calls `Bbr` before 29b.4.
    - An episode is RFC 9002's recovery period. `recovery_spurious.on_congestion_event` starts
      one for both of `Recovery`'s congestion events, a loss and a rise in the ECN-CE count.
    - A frame that acknowledges only lost packets takes nothing out of the sent table, so the
      frame's ranges are read for the list before RFC 9002's early return.
    - Once an episode is found spurious, it is over. TLC found that the first version emptied
      the list, so a later loss in the same recovery period could make the episode spurious
      twice.
    - §5.5.11 defines a spurious episode over the whole episode, but a sender judges it while the
      episode runs, so a verdict can come before a later loss that is real. The draft and RFC
      9002 do not say what then. colibri keeps the first verdict: a later loss in the same
      recovery period lowers the model as any loss does, and undoes nothing again.
    - §5.3.1.3 says "at least one full packet-timed round trip" of recovery. Recovery that
      starts in round R has a full round once round R + 2 starts, so the check waits for it.
    - §5.5.10.2's `lost_prefix` is negative when the losses before the lost packet already
      crossed 2%. `inflight_at_loss` takes it in signed arithmetic and holds the answer at 0.
    - `spec/lean/Colibri/Quic/BbrLoss.lean` proves that the crossing `InflightAtLoss` finds is
      never past the lost packet and never below 0. It also proves that a round with loss lowers
      each short-term bound to at least the round's delivery and 0.7 of the bound, and never
      above the larger of the two.
      `src/quic/recovery/recovery_bbr/bbr_loss_vectors.txt` holds 74 lines of its answers, and
      a Zig test reads them.
    - `zig build tla` on `spec/tla/spurious_loss`, 4 packets and a list of 2: an episode is found
      spurious only when every packet it declared lost was delivered and acknowledged, and at
      most once. The properties hold over 38,994 distinct states, and its four mutants are
      violated.
    - The list grew `quic.Connection` from 207,656 to 207,920 bytes.
    - Mutations, against `zig build test-quic`, 43 of 43 CAUGHT. They cover each rule of the
      short-term model, of each lost packet, of Startup's exit on high loss and of the undo, and
      each rule of the detector. Seven were NOT CAUGHT at first, and a test now guards each of
      them:
      - the latest rate started again each round;
      - `RS.lost` counted from the lost packet's send;
      - Startup's exit only inside recovery;
      - the bound after high loss at least the round's delivery;
      - ProbeRTT's end resetting the short-term model;
      - losses the caller's slice could not hold;
      - a frame's second range read for lost packets.
  - **29b.4, the controls, 2026-10-31.** `recovery_bbr/recovery_bbr_control.zig` sets §5.6.2's
    pacing rate, §5.6.3's send quantum and §5.6.4's window, and `recovery_congestion_bbr.zig`
    gives `Bbr` each event of `Recovery`. A connection whose options name `.bbr` runs BBRv3.
    - The public names: `quic.CongestionController`, `enum { cubic, bbr }`, and the
      `congestion_controller` and `bandwidth_probe_waits` options of `quic.Connection`. The
      simulator's QUIC connection check needs them, and 29c's `server.Config` and
      `client.Config` will set them.
    - `recovery_congestion.zig` keeps RFC 9002's shared state, and `State`, a tagged union,
      holds `recovery_congestion_cubic.Cubic` or `Bbr`. `Congestion.window` is what the sender
      reads, and BBRv3's `window_len` is a copy that `set_window` keeps equal.
    - The pacer's `Rate` is now bytes over a period times a factor. Under CUBIC it is RFC 9002
      §7.7's window over the smoothed round trip times 5/4, so no census moved. Under BBRv3 it is
      the pacing rate over a second, with the send quantum as the burst.
    - §5.6.2 starts the pacing rate from "the initial C.srtt after the first non-zero RTT
      sample". BBR starts it over 1 ms at init, and once more at the first round trip sample.
    - BBRv3 does not cut the window on loss. A new recovery period runs §5.6.4.4's
      `OnEnterFastRecovery`, and each lost packet runs `HandleLostPacket`. Persistent
      congestion comes after them, because it ends the recovery period that they save state in.
      A test found that the other order saved the minimum window as the one to restore.
    - RFC 9000 §9.4's reset of the path starts the chosen controller again. It comes with no
      instant, so BBRv3 starts from the latest instant it was given.
    - The simulator's zeroed storage holds a tagged union now, so `zeroes_around_suites` zeroes
      a union's first field.
    - `spec/lean/Colibri/Quic/BbrControl.lean` proves the window never below `BBR.MinPipeCwnd`
      nor above ProbeRTT's cap or the model's, and at most `BBR.max_inflight` once the pipe is
      full. It also proves the send quantum between 2 datagrams and 64 KB, and the pacing rate
      never above the estimate at its gain. `src/quic/recovery/recovery_bbr/bbr_control_vectors.txt`
      holds 254 lines of its answers, and a Zig test reads them.
    - `quic_connection_bbr_check.zig` runs the QUIC connection check with both endpoints on
      BBRv3: the lossy network, the dropped ACK frames, the runner's handshakeloss network and
      both NAT rebindings. Every seed finishes with invariants 17 to 21 holding, and each census
      is pinned, the same in Debug and in ReleaseSafe. Every census under CUBIC is unchanged.
    - BBRv3's state grew `quic.Connection` from 207,920 to 208,288 bytes.
    - Mutations, against `zig build test-quic`, and `zig build test-sim-run-quic` for the option
      the connection reads, 31 of 31 CAUGHT. They cover each control, each event `Recovery`
      gives BBRv3, the copy of the window, the reset of the path, the option, and the pacer's
      factor. Five were NOT CAUGHT at first, and a test now guards each of them:
      - `extra_acked` in `BBR.max_inflight`;
      - each lost packet given to BBRv3;
      - the start of a recovery period given to it;
      - an ACK frame inside a recovery period, which only Startup's end on loss reads;
      - `C.is_cwnd_limited` from RFC 9002 §7.8's judgement.
- **29c, the configuration and the measurement.** `congestion_controller` in `server.Config`
  and `client.Config`, and `bandwidth_probe_waits`, which the server and the client draw.
  `examples/` and docs/usage.md show the option. 29b.4 brought `quic.CongestionController` and
  `quic.Connection`'s two options (the owner's ruling of 2026-10-31).
  - **Check.** The simulator runs its QUIC checks with each controller. The judge's `bulk` and
    `network` inputs measure BBRv3 against CUBIC, chi and axum, and the fairness run of 13k.
    The owner then rules on the default.
  - **29c.1, the option and the inputs, 2026-10-31.** `server.Config` and `client.Config` take
    `congestion_controller`, which reaches each QUIC connection. Under BBRv3 each connection
    draws its `bandwidth_probe_waits` from the program's source, after its
    `packet_number_skips`. Under CUBIC it draws nothing, so no census of the server's or the
    client's checks moved.
    - `examples/server_exchange.zig` runs its QUIC connections under BBRv3, and docs/usage.md
      shows the option for the server and the client.
    - The test-only UDP server takes `bbr` with `h3`, and its summary names the controller.
      `tools/quic_udp.sh` downloads the three files from the `h3` mode under BBRv3 too.
    - `bench/run_bulk.sh` adds `colibri-bbr`, and `h3-shared` runs, where colibri under CUBIC
      and under BBRv3 load the one bottleneck at once. `bench/report_bulk.py` gives each one's
      share. `bench/run_latency.sh --network` adds `colibri-bbr` over h3.
    - A client test found that §5.6.2's `C.srtt ? C.srtt : 1ms` was read as "any sample". A
      smoothed round trip of 0, which a test whose ACK comes at the instant of the send gives,
      crashed on an assertion. The pacing rate now starts again only from a sample above 0.
    - Mutations, each CAUGHT: the option dropped by the server's configuration, by its
      connection, by the client's configuration and by its connection, either side's probe
      waits fixed at 0, the `bbr` word ignored or taken without `h3`, and the `h3` mode run
      under CUBIC whatever the word, which `tools/quic_udp.sh` catches. The client's two were
      NOT CAUGHT at first: the test read a connection the pool had not started, whose fill of
      1s reads as `.bbr`. It now reads the connection after its exchange.
  - **29c.2, the judge and the default, 2026-11-01.** The judge ran `bulk` (run 41267075258)
    and `network` (run 41267079569) on ef04f32b, two jobs of 2 rounds each, and every answer
    was a 200. [Decision 143](../../decisions/0143-bbrv3-is-the-default-congestion-controller.md) then made BBRv3 the default of `quic.Connection`,
    `server.Config` and `client.Config`.
    - `bulk`, over h3 at 20 Mbit/s and 25 ms with a queue of 1,000 packets, the two jobs'
      values:

      | Case | CUBIC | BBRv3 |
      |---|---|---|
      | No loss, 1 connection: goodput (Mbit/s) | 17.34, 17.34 | 17.06, 17.06 |
      | No loss, 4 connections: GET p99 (ms) | 509.1, 717.5 | 185.6, 185.5 |
      | 1% loss, 1 connection: goodput (Mbit/s) | 1.68, 1.68 | 14.54, 14.82 |
      | 1% loss, 4 connections: goodput (Mbit/s) | 8.11, 8.11 | 17.06, 17.06 |
      | Shared, no loss, 4 connections each: share | 0.82, 0.83 | 0.18, 0.17 |
      | Shared, 1% loss, 4 connections each: share | 0.24, 0.23 | 0.76, 0.77 |

    - At 1% loss, chi (quic-go) got 3.36 Mbit/s from 1 connection, and axum (quinn) 2.52.
      [#123](https://github.com/c4milo/colibri/issues/123) asks why colibri's CUBIC gets half
      of quic-go's.
    - `network`, colibri's p99 over h3 at 4,000 req/s, the two jobs' values: on `far`, 50.76
      and 62.23 ms under CUBIC and 59.28 and 69.54 ms under BBRv3. On `mobile`, 2,066 and
      2,037 ms under CUBIC and 1,823 and 1,795 ms under BBRv3. On `lossy` the two were within
      2%, and on `clean` both stayed under 0.4 ms.
    - Under BBRv3 the server and the client draw their probe waits by default, so three
      censuses moved: `h3_deadline_check` and `endpoint_check`, each in its two CRC-32s, and
      the client trace run, whose seeds still reach each path its comment names. Each passes in
      Debug and with `-Drelease`.
    - Two quic tests read RFC 9002's window rules, which BBRv3 does not follow, so their
      fixtures name CUBIC. Two server tests pump `rounds_paced`, 32 rounds: the fixture steps
      30 ms and sends once a round, and BBRv3's pacer lets one send quantum out each time. A
      program wakes at `deadline_ns`, which names the pacer's next send.
    - The test-only UDP server keeps CUBIC unless its command names `bbr`, so the judge's
      `colibri` input measures the same server as before.
    - Mutations, each default set back to `.cubic`: `server.Config`'s and `client.Config`'s
      were CAUGHT. `quic.Connection`'s and the two QUIC connections' own were NOT CAUGHT at
      first, because the endpoint and the pool pass the controller. A test of each now starts
      a connection with its defaults, and all five are CAUGHT.
  - **29c.3, CUBIC at 1% loss, 2026-11-04.** [#123](https://github.com/c4milo/colibri/issues/123)
    asked why colibri's CUBIC got half of quic-go's goodput. CUBIC follows RFC 9438, and most of
    the difference is in how the report counts.
    - A scratch copy of the simulator, which was not kept, held the bulk path: a queue of
      1,000 packets at 20 Mbit/s, 25 ms each way, and 1% loss each way. Over 4 seeds a 2 MiB
      download took 6.49 s under CUBIC, 2.58 Mbit/s, and 1.14 s under BBRv3, 14.76 Mbit/s.
    - The bulk run's qlog option (`BENCH_BULK_QLOG`, the workflow's `qlog` input) kept the
      server's qlog in run 41830884812, job 2, on a39c8d1f. Each CUBIC connection at 1% loss
      had a smoothed RTT of 51 to 55 ms and a mean window of 14 to 18 KB. Each sent 2.0 to
      2.6 Mbit/s.
    - Between two cuts the window grew 0.49 to 0.52 packets a round trip, where RFC 9438 §4.3
      gives α_cubic = 0.53. Each cut left 0.7 of the window (§4.6). At 1% loss and 50 ms,
      CUBIC stays in the Reno-friendly region, where that growth gives about 2.3 Mbit/s.
    - The report's goodput counts whole 2 MiB downloads in a load of 30 s. 1.68 Mbit/s is 3
      downloads, 2.24 is 4 and 3.36 is 6, so the report shows the differences in steps of
      one download.
    - The median download still took 9.1 s from colibri, 6.4 s from axum (quinn) and 5.2 s
      from chi (quic-go). Both send faster than RFC 9438's CUBIC on this path. colibri reads
      neither one's source (non-negotiable 10), and BBRv3 is the default for a lossy path.
    - BBRv3 loses about 8.5% at 1% loss in the simulator, over 16 MiB: 16.45 Mbit/s against
      17.97. Most of it is draft-ietf-ccwg-bbr-06 §5.5.10.3, which cuts the short-term model
      in each round that loses a packet. The owner ruled on 2026-11-04 to keep the draft.
- **29d, BBRv3 against itself and its cost.** The judge measured BBRv3 only beside CUBIC, and
  neither chi (quic-go) nor axum (quinn) runs BBRv3. The owner asked on 2026-11-01 for two
  measurements before any change to the controller.
  - `bench/run.sh --h3` adds `h3-bbr-many` and `h3-bbr-one`, which the UDP server answers under
    BBRv3. Each one's instructions a request, or a connection, beside `h3-many` and `h3-one`
    give the cost of BBRv3's work on each ACK. quic-go serves neither.
  - The `bulk` input adds ngtcp2's server, under its own BBR with no GSO, from its QUIC Interop
    Runner image, pinned by digest. ngtcp2's release notes say its BBR follows the current draft.
    It is measured and never read (non-negotiable 10), and shows whether colibri's queue and
    goodput are BBRv3's own on that path.
  - **Check.** One judge run of `--h3` gives the four h3 inputs, and one `bulk` run gives the
    other BBRv3 beside colibri's.
  - **29d.1, the cost, 2026-11-01.** The judge ran `--h3` on 98939d73 (run 41348385244), two
    jobs of 5 rounds each. BBRv3's instructions are CUBIC's within the noise:

    | Input | Unit | CUBIC | BBRv3 | System calls, CUBIC and BBRv3 |
    |---|---|---|---|---|
    | many, job 1 | request | 114,145.6 | 114,246.7 | 5.022, 5.023 |
    | many, job 2 | request | 115,143.0 | 115,222.4 | 5.022, 5.023 |
    | one, job 1 | connection | 1,561,166.6 | 1,559,076.9 | 15.938, 16.881 |
    | one, job 2 | connection | 1,531,236.8 | 1,535,484.1 | 15.589, 16.578 |

    - The difference is at most 0.28%, and each value varies by 0.4% to 0.8% across rounds.
      The work on each ACK costs no instruction the judge can see.
    - On `h3-one` BBRv3 makes about one system call more a connection in both jobs. Its pacer
      may let a connection's first flight out in two sends, but no run has measured the cause.
  - **29d.2, the h3 server's files, 2026-11-01.** The owner asked why h3 does not match h11 and
    h2. The judge's `--profile --h3` on 956454b2 (run 41355278358) put 44.5% and 42.2% of
    h3-many's samples in the h3 server's file reads, and h3-one's 7.6% and 7.5%. Each request
    opened its file, mapped it, closed it and unmapped it at its end. That is four of its 5.02
    system calls, and the TLB flush of the unmap took 12% alone. The h2 server answers from
    memory.
    - `udp_h3_files.Mapped` keeps each file mapped from its first request until the run ends,
      for `h3_mapped_files_max` (64) files. A file past those is mapped for its request alone,
      as before.
    - quic-go's server reads its file on each request, so colibri's h3 ratio to quic-go also
      moves for this reason, not for QUIC alone.
    - Mutations, by `zig build test-testing-udp`: `content_of` without the mapping kept,
      `content_of` that keeps nothing, `find` that finds nothing, `keep` past a full table, and
      `keep` without its count: each CAUGHT. `tools/quic_udp.sh` passes.
    - The judge's `--h3` on 1f981e2a (run 41357653325), two jobs of 5 rounds, a request on
      h3-many and a connection on h3-one, against 98939d73 (run 41348385244):

      | Input | Instructions | System calls | CPU (ns) |
      |---|---|---|---|
      | h3-many | 114,146 to 67,130; 115,143 to 67,940 | 5.022 to 0.021, both jobs | 16,801 to 7,517; 20,627 to 7,700 |
      | h3-one | 1,561,167 to 1,538,974; 1,531,237 to 1,543,498 | 15.94 to 11.19; 15.59 to 11.13 | 281,813 to 276,531; 314,297 to 291,078 |
      | h2-many, for scale | 13,488 | 0.023, 0.024 | 1,523; 1,555 |

      h3-many now makes as few system calls a request as h2-many, so the loop already batches
      its sends and receives. What is left is about 5 times h2-many's instructions, almost all
      in user space.
  - **29d.3, a second BBRv3, 2026-11-01.** The judge ran `bulk` on 4f274b5f (run 41351081101),
    two jobs of 2 rounds each, with ngtcp2 a08611c0 under `--cc bbr`. Every answer was a 200.
    The two jobs' values:

    | Case | colibri, BBRv3 | ngtcp2, BBR |
    |---|---|---|
    | No loss, 1 connection: goodput (Mbit/s) | 17.34, 16.78 | 17.06, 16.78 |
    | No loss, 4 connections: GET p99 (ms) | 167.0, 154.8 | 305.0, 305.2 |
    | 1% loss, 1 connection: goodput (Mbit/s) | 14.26, 14.26 | 12.02, 12.58 |
    | 1% loss, 4 connections: goodput (Mbit/s) | 17.34, 17.06 | 17.06, 17.62 |
    | 1% loss, 4 connections: GET p99 (ms) | 263.0, 612.6 | 471.5, 280.4 |

    - colibri's queue with 4 connections and its goodput at 1% loss from one connection are
      BBR's own on this path: ngtcp2's are the same or worse. Neither is a defect of colibri.
    - The GET p99 at 1% loss from 4 connections varies between the jobs for both, so one run
      does not order them.
  - **29d.4, the request records apart from their flags, 2026-11-01.** The judge's
    `--profile --h3` on e1ff6119 (run 41358976530) put 46% of h3-many's samples under
    `server.Endpoint`'s poll and 10.8% in `quic_connection_h3.settle` itself, the largest of any
    function. `settle` runs after each datagram and read `in_use` in each of the 100 records,
    each more than 8 KiB with its response's kept frames, to find the few in use. AES-GCM took
    0.5%.
    - `quic_request.Requests` holds `held`, a bit set of the records in use, and their stream
      ids apart from the records. `settle`, `of`, `idle`, `any_open` and the encoders' give-back
      read the bit set and the records in use alone. A QUIC slot grows by 16 bytes.
    - Mutations, by `zig build test-server`: a walk that visits one record, a `free` that keeps
      the record held, a `take` that writes no stream id, an `any_open` that finds none, an
      `idle` with one record held, and a `take` that never uses the last record: each CAUGHT.
    - The judge's `--h3 --base e1ff6119` on ea7878f9 (run 41365866317), two jobs of 5 rounds,
      the change's instructions over the base's:

      | Input | Job 1 | Job 2 |
      |---|---|---|
      | h3-many | 0.8936, wins | 0.8995, wins |
      | h3-one | 0.9697, wins | 0.9727, wins |
      | h3-bbr-many | 0.8929, wins | 0.9143, within the noise of 9.39% |
      | h3-bbr-one | 0.9696, wins | 0.9744, wins |
      | h2 inputs | 0.9987 to 1.0007 | 0.9983 to 1.0033 |

      h3-many fell from 67,680 to 60,477 instructions a request in job 1, and its CPU time
      from 7,488 to 6,738 ns. Each h2 input is within the noise, as a change to h3 alone gives.
  - **29d.5, the meters of the records in use, 2026-11-01.** Each call to a QUIC connection's
    `receive` fires and observes the deadlines, and the send and body meters walked all 100
    entries for each, whichever records were in use. They now walk `Requests.held`. An entry
    whose record is free never runs: `quic_sends.forget` empties it when the record is freed,
    and a record is freed only once the wait for its body ended.
    - Mutations, by `zig build test-server`, each walk made to visit no record: the send
      meters' `observe`, `soonest` and `fire`, and the body meters' `observe`, `soonest` and
      `fire`: each CAUGHT.
    - The judge's `--h3 --base f177f5ec` on e279444e (run 41385734311), two jobs of 5 rounds,
      the change's instructions over the base's: h3-many 0.8455 and 0.8888, h3-bbr-many 0.8859
      and 0.8691, each a win. h3-one, h3-bbr-one and every h2 input stayed within the noise.
      h3-many fell from 60,560 to 51,200 instructions a request in job 1.
    - A cache of `quic.connection_flow.data_credit_owed`'s answer, forgotten at each call that
      can change credit, was tried next and dropped: 12 of its 13 places that forget the answer
      survived their mutation, so no test held them. Step 29d.6 removes the repeated walks
      another way.
  - **29d.6, one settle for each change, proposed 2026-11-02.** On h3-many a datagram brings
    about 3 events, so the endpoint calls `receive` 4 times for it. `take` already fired the
    deadlines and settled each request at that instant (`after_change`). Each `receive` does both
    again, though nothing that they read changed. After 29d.5 the judge's profile of h3-many gave
    `settle` 7.4% to 8.1% of the server's samples and `fire` 3.3%.
    - The change:
      1. A new field, `settled_ns: ?u64`, holds the instant of the last `fire` and `settle`
         that saw every change. `after_change` sets it, and so does `receive` when it runs the
         two.
      2. `receive` runs `fire` and `settle` only when `settled_ns` is not `now_ns`. Otherwise
         it runs `settle` only while `continue_owed` is set, because a head that `read_event`
         read can owe a 100 (Continue) (RFC 9110 §10.1.1).
      3. Each call that changes what the two read sets `settled_ns` to null: `respond`,
         `write_body`, `write_trailers`, `cancel` and `set_timeouts`. `shutdown` and `send`
         were in the plan too, and each one's mutation survived, so neither clears it:
         - `shutdown` ends the requests itself (`finish_if_drained`), and the drain that it
           starts starts at `now_ns`.
         - `send` moves a stream only to `send` or `data_sent`, which `settle` ignores, and
           it settles first while a 100 (Continue) is owed (`write_before_send`).
      4. `observe` still runs after each event, because each event can open a request or owe
         credit. It is the next cost, and this step does not change it.
    - Why a `receive` at the same instant can skip `fire`. Between two calls to `receive`, only
      `read_event` and `observe` ran. Each deadline that they start starts at `now_ns`, and
      `deadline.Timeouts.validate` refuses a limit of 0, so none passes at `now_ns`. A wait
      that `observe` resumes moves by the time it waited (`moved`), so it does not pass either.
      Content that `read_event` reads only makes a body less late.
    - Why it can skip `settle`. `settle` reads the streams' states, what the peer acknowledged
      and what each response supplied. Only a datagram changes the first two, and only the
      caller's calls change the third. A stream that `read_event` reads to its end can close,
      and its record then frees at the next change, not at once. No request needs that record
      first: QUIC grants a new stream only in a datagram that `send` writes (RFC 9000 §4.6).
    - The checks:
      - A test for each call of item 3 fails when that call does not clear `settled_ns`. A
        call that no test can show in this way needs no clear: its entry here says why, and
        the clear goes.
      - Mutations, by `zig build test-server`: each clear of item 3, the instant compared in
        item 2, and the `continue_owed` test of item 2.
    - **29d.6, the tests, 2026-11-02.** `quic_settle_test.zig` holds one test for each clear.
      Mutations, by `zig build test-server`: the clears of `respond`, `write_body`,
      `write_trailers`, `cancel` and `set_timeouts`, each CAUGHT. The clears of `shutdown` and
      `send`, each NOT CAUGHT, and removed for the reasons of item 3. `receive` that settles
      only when the instant differs, with no `continue_owed` test: CAUGHT. `settled_at` that is
      always true: CAUGHT. `settled_at` that is always false is the code before this step, so
      only the judge can show it.
    - The judge's `--h3 --base 07b742ee` on fe2da81b, the change's instructions over the
      base's:
      - Run 41440875630, two jobs of 5 rounds: h3-many 0.9440 and 0.9416, h3-bbr-many 0.9272,
        a win, and 0.9544. The base's noise was up to 7.5%, so three of the four stayed within
        it.
      - Run 41448365201, two jobs of 10 rounds: h3-many 0.9002, a win, and 0.9176, within its
        noise of 8.3%; h3-bbr-many 0.9200 and 0.9267, each a win. h3-many fell from 53,738 to
        48,374 instructions a request in job 1.
      - h3-one, h3-bbr-one and every h2 input stayed within the noise in both runs.
  - **29d.7, one credit walk and the requests the caller changed, proposed 2026-11-02.** The
    judge's `profile` on 3e815faa (run 41458676089) gave two costs on h3-many, in both jobs:
    - `quic_deadline.observe` took 6.8% of the samples, and
      `quic.connection_flow.data_credit_owed` 5.4% of them. `observe_credit` calls
      `data_credit_owed`, and then `credit_owed`, which calls it again. Each call walks every
      stream of the connection.
    - `settle` took 5.4%: 2.5% from `after_change`, once for each datagram, and 3.0% from
      `receive`. A call of the caller's clears `settled_ns`, so the next `receive` settles every
      request again, though the call changed one.
    - The change:
      1. A new name in `quic`, `connection_flow.count_credit_owed`, says whether a MAX_STREAMS
         frame is owed, and `credit_owed` calls it. `observe_credit` calls `data_credit_owed`
         once and `count_credit_owed`, so it walks the streams once. The server's `observe`
         needs the name, which goes on `quic`'s list.
      2. A bit set beside `Requests.held`, `changed`, holds a bit for each record. `respond`,
         `write_body`, `write_trailers` and `cancel` set the bit of the request they name, in
         place of a clear of `settled_ns`. A `receive` at the instant the connection settled at
         settles only the records whose bit is set (`settle_changed`), and clears the bits.
         `settle` clears them all. `set_timeouts` still clears `settled_ns`, because it changes
         the deadlines and no request.
    - Why item 2 is the same as a whole `settle`. `settle_one` of a record reads its stream and
      its response, and only a datagram or a call that names the record changes either. A
      datagram settles every record in `after_change`. `finish_if_drained` runs after the walk
      in both cases.
    - The checks:
      - `quic_settle_test.zig` keeps its five tests, with item 2's flags in place of the clears.
        One more test changes two requests' responses and requires each to settle.
      - Mutations, by `zig build test-server`: each flag that a call sets, the clear of the flag,
        and `observe_credit` with `count_credit_owed` left out.
      - `tools/h3_deadline_trace.sh` and the QUIC simulator give what they gave before.
      - The judge's `--h3 --base 3e815faa`, at 10 rounds. The step lands when h3-many and
        h3-bbr-many win and no input loses.
  - **29d.7, the tests, 2026-11-02.** `quic_settle_test.zig` holds a test of two requests
    changed at one instant, and `quic_deadline_credit_test.zig` a MAX_STREAMS frame owed that
    holds the idle deadline. `settle` moved to `quic_connection_h3_settle.zig`, for the file
    length. Mutations, by `zig build test-server` and, for `count_credit_owed`, `zig build
    test-quic`:
    - The bit that `respond`, `write_body`, `write_trailers` and `cancel` each set: each CAUGHT.
    - `settle_changed` that settles the first record alone: CAUGHT.
    - `settle_changed` and `settle` that clear no bit: each NOT CAUGHT at first. The test of two
      requests now reads `Requests.changed`, and `settle_changed` asserts that each bit names a
      record in use. Each is now CAUGHT.
    - `free` that also cleared the bit of the record: NOT CAUGHT, because `settle` clears every
      bit before it frees a record. The clear was removed.
    - `observe_credit` with no `count_credit_owed`: NOT CAUGHT at first, and CAUGHT by the test of
      the MAX_STREAMS frame.
    - `count_credit_owed` that is always false: CAUGHT.
  - **29d.7, the judge, 2026-11-02.** The judge's `--h3 --base 3e815faa` at 10 rounds, the
    change's instructions over the base's:
    - Run 41469433388 on d146989b: every h3 input won in both jobs, and h3-many fell from
      48,434 to 44,894 instructions a request. h2-many lost, 1.0065 and 1.0069, past its
      noise of 0.5%: 97 more user instructions a request in both jobs, in code that h2 does
      not change.
    - Runs 41478348806 and 41478368393 measured each part alone. The credit walk left h2-many
      at 1.0001 and 0.9998, and h3-one won, 0.950. The records' bits made h2-many lose, 1.0063
      and 1.0068.
    - A size of each function of the two servers showed why. `State.poll` holds the TCP poll and
      the QUIC poll, and LLVM inlines both. With the bits it laid out the endpoint's functions in
      another way, and `State.receive`, where h2-many spends 37% of its samples, was split.
    - `State.poll` now calls `endpoint_state_quic.poll` with `.never_inline`. Run 41491105165 on
      4d046092: h2-many 0.9976 and 0.9963, h2-tls-many 0.9964 and 0.9963, each within the
      noise; h3-many 0.9215 and 0.9158, h3-bbr-many 0.9130 and 0.9193, h3-one 0.9559 and
      0.9473, h3-bbr-one 0.9532 and 0.9512, each a win. h3-many fell from 48,602 to 44,788
      instructions a request in job 1.
      - `tools/h3_deadline_trace.sh`, `zig build test-sim-run-quic` and the simulator's h3
        censuses give what they gave before.
      - The judge's `--h3 --base 07b742ee`. The step lands only when h3-many and h3-bbr-many
        win and no input loses.
    - When the mutations leave a clear that is needed but that no test holds, the step stops,
      as the cache of 29d.5 stopped.
  - **29d.8, a build-time index of the QPACK static table, proposed 2026-11-03.** The judge's
    `profile` on 5c238041 (run 41651029947) gave h3-many no cost above 6.2% of the samples. The
    largest, in both jobs, was the h3 `connection_send.write_headers`: 5.3% and 6.2% of the
    samples in the function itself, each one under `respond`.
    - `write_headers` encodes the response's field section. The QPACK encoder's `find_static`
      compares each field line with the 99 entries of RFC 9204 Appendix A, in order. The test
      server's response has two lines. `:status: 200` is entry 25, and `content-length` is
      entry 4 with no entry for its value, so that line compares all 99 entries.
    - HPACK had the same scan, and 3c07e53e replaced it with a build-time map from each name to
      its entries (h2-many 0.942). HPACK's map needs the entries of a name to be adjacent.
      Appendix A of RFC 9204 does not keep them adjacent: `content-type` is entries 44 to 54,
      and `access-control-allow-headers` is entries 33, 34 and 75.
    - The change: `encoder_plan.zig` builds, at compile time, a `std.StaticStringMap` from each
      name of Appendix A to the list of its entries, in order. `find_static` reads the name's
      list, takes its first entry as `name`, and compares the value with the list alone. The
      result is the same as the scan's: the lowest entry with the name, and the lowest with the
      line. No public name changes.
    - The checks:
      - A test compares `find_static` with the scan for each entry of Appendix A, for each name
        with a value it does not hold, and for a name it does not hold.
      - Mutations, by `zig build test-qpack`: a list that leaves out its last entry, a first
        entry that is not the lowest, and a value compared with the first entry alone.
      - `zig build qpack-vectors`, `tools/qif_interop.sh` and the golden corpus give what they
        gave before.
      - The judge's `--h3 --base 5c238041`, at 10 rounds. The step lands when h3-many wins and
        no input loses.
  - **29d.8, the checks, 2026-11-03.** The test compares `find_static` with the scan. Mutations,
    by `zig build test-qpack`: the list without its last entry, a first entry that is not the
    lowest, and a value compared with the first entry alone: each CAUGHT. `zig build
    qpack-vectors` gives the round-trip bytes it gave on 5c238041, and `tools/qif_interop.sh`
    passes its 45 runs.
  - **29d.8, the judge, 2026-11-03.** Run 41656458658, `--h3 --base 5c238041` at 10 rounds, the
    change's instructions over the base's:
    - h3-many 0.9398 and 0.9380, and h3-bbr-many 0.9366 and 0.9385, each a win. h3-many fell
      from 44,704 to 42,011 instructions a request in job 1.
    - h3-one, h3-bbr-one and each h2 input are within the noise in both jobs.
  - **29d.9, a peek of a stream where nothing arrived, proposed 2026-11-03.** The profile of
    h3-many on 5c238041 (run 41651029947) gave `stream_incoming.Storage.find` 4.9% and 4.6%
    of the samples, in the function itself. A third of them came from h3's `peek_critical`,
    which peeks the peer's control, encoder and decoder streams on each `step`. Those streams
    are idle once the SETTINGS frame is read, and each peek walks a chain of the pool's buckets
    to find that no block holds the next byte.
    - The change, in `quic`'s `connection_stream_read.peek`: when the stream's
      `receive_flow.used` equals its `receive_flow.consumed`, no byte past the read offset has
      arrived, so the peek copies none and does not call `Incoming.peek`. `fin` is computed as
      before, so a FIN that carries no byte is still reported. The same peek serves h3's
      request streams. No public name changes.
    - The checks:
      - A test peeks a stream with nothing new, then with an empty STREAM frame that carries a
        FIN, and requires `len` 0 and `fin` false, then true.
      - Mutations, by `zig build test-quic`: the fast path when `used` is above `consumed`,
        and a fast path that reports no FIN.
      - The QUIC simulator's censuses and `tools/h3_deadline_trace.sh` give what they gave
        before.
      - The judge's `--h3 --base 96ed6ef5`, at 10 rounds. The step lands when h3-many wins and
        no input loses.
  - **29d.9, the checks and the judge, 2026-11-03.** The test and both mutations ran as the
    entry says: each mutation CAUGHT. `zig build test-sim-run-quic` and
    `tools/h3_deadline_trace.sh` (32 of 32) passed. The judge, `--h3 --base 96ed6ef5`:
    - Run 41730768549, 10 rounds: h3-many 0.9786, within its noise of 2.84%, and 0.9706, a
      win. h3-bbr-many 0.9804 and 0.9740, within the noise.
    - Run 41738836664, 20 rounds: h3-many 0.9787 and 0.9709, within noises of 3.87% and
      3.62%. h3-bbr-many 0.9809 and 0.9735, within the noise.
    - No input lost in either run. h3-many fell 2% to 3% in each of the four jobs, about 900 to
      1,240 instructions a request, which is less than its noise.
    - The owner's ruling of 2026-11-03: the step stays on its branch, and the judge measures it
      again together with the next h3 change.
  - **29d.10, a credit walk over the streams that receive, 2026-11-03.** The same profile gave
    `quic_deadline.observe_credit` 4.9% and 4.3% of h3-many's samples, in the function itself,
    where `quic.connection_flow.data_credit_owed` is inlined. It walks every live stream of
    the connection, about twice a datagram, and reads each stream's receiving state. In
    h3-many each GET carries its FIN, so nearly every stream it reads has left "Recv".
    - The change, the owner's choice of three on 2026-11-03: `quic`'s `Streams` keeps
      `may_owe_credit`, a bit for each slot. `open_local` and `open_peer` set the bit of each
      stream this endpoint receives on, and `close` clears it. `data_credit_owed` walks the set
      bits alone, and clears the bit of a stream it finds out of "Recv" (RFC 9000 §13.3). No
      answer is kept from one call to the next, so no answer goes stale. No public name
      changes.
    - The two alternatives it beat: one walk a datagram, which halves the walks and keeps
      their length, and a count of the streams that owe credit, which is the cache that 29d.5
      dropped.
    - The checks:
      - A test in `stream_table.zig` opens streams of each type and closes one, and counts the
        bits. The credit test of decision 110 requires the walk to clear the bit of a stream
        whose size is known.
      - Mutations, by `zig build test-quic`: `open_local` and `open_peer` that mark nothing, a
        stream that only sends marked too, `close` that keeps the bit, a walk that keeps the
        bit of a stream out of "Recv", and a walk that clears the bit of a stream in "Recv":
        each CAUGHT.
      - Each QUIC connection grows by 16 bytes, the 128 bits, in docs/performance.md.
      - The judge's `--h3 --base 96ed6ef5`, at 10 rounds, measures 29d.9 and 29d.10 together.
        They land when h3-many wins and no input loses.
  - **29d.9 and 29d.10, the judge, 2026-11-04.** Run 41749723586, `--h3 --base 96ed6ef5` at 10
    rounds, the change's instructions over the base's:
    - h3-many 0.9097 and 0.9098, h3-bbr-many 0.9147 and 0.9094, h3-one 0.9575 and 0.9586, and
      h3-bbr-one 0.9591 and 0.9607: each a win. h3-many fell from 42,280 to 38,461 instructions
      a request in job 1.
    - Each h2 input is within the noise in both jobs.
  - **29d.11, no scan for a stream that closed, 2026-11-04.** The judge's `profile` on 5036ba0c
    (run 41824399460) gave `core.Pool.get` of the QUIC stream table 4.0% and 4.1% of h3-many's
    samples, the largest cost in the function itself. A lookup of an identifier that is not
    live scans every slot, and each stream that closes costs three:
    - `Pool.close` asserts that its identifier is found no more.
    - `close_if_finished` asserts that `lookup` calls it `closed`.
    - `settle_one` looks up the stream after the acknowledgment that closed it.
    - The change, the owner's choice of 2026-11-04, which allowed the two assertions to change:
      1. `core.Pool` gets `holds(index, id)`: whether a slot holds the live entry of an
         identifier.
      2. `Pool.close` asserts that the slot it freed holds the identifier no more. `open`
         takes only an identifier above its watermark (invariant 13), so no other slot holds
         it, and the check proves what the scan proved.
      3. `close_if_finished` asserts the same of the stream's slot, and that the identifier is
         at or below its watermark, which together are what `lookup` calls `closed`.
      4. Each server `Request` keeps `stream_slot` once `settle_one` finds its stream live,
         and each later settle reads that slot alone. A slot that holds the identifier no more
         says the stream closed, because an identifier never returns to a pool.
    - The alternative it beat, run first as 29d.11 on the branch `pool-buckets`: buckets by
      `id / class_count` and a count of each bucket's live entries in `core.Pool`. Run
      41835439979 lost h2-many by 0.65% for 2% on h3-many, and the owner dropped it.
    - The checks:
      - The test of two requests in `quic_settle_test.zig` requires each record to keep its
        stream's slot.
      - Mutations, by `zig build test-core` and `zig build test-server`: `holds` that ignores
        the identifier or the live flag, a settle that keeps no slot, a kept slot read as live
        after its stream closed, and `make_record` that keeps an old slot: each CAUGHT.
      - Each QUIC slot of a server grows by 800 bytes, 8 for each record, in
        docs/performance.md.
      - The judge's `--h3 --base 5036ba0c`, at 10 rounds. The step lands when h3-many wins and
        no input loses.
  - **29d.11, the judge, 2026-11-04.** Run 41852315591, `--h3 --base 5036ba0c` at 10 rounds:
    h3-many 0.9452 and 0.9476, and h3-bbr-many 0.9447 and 0.9381, each a win. h3-many fell
    from 38,313 to 36,215 instructions a request in job 1. Every other input is within the
    noise in both jobs, and h2-many runs the base's instructions.
  - **29d.12, no walk of the receive pool to assert a discard, 2026-11-05.** The judge's
    `profile` on f5649a00 (run 41958253605) gave `stream_incoming.Storage.find` 3.1% and 4.1%
    of h3-many's samples. About half came from one assertion in `Incoming.discard`, which
    called `contiguous_end` to walk the blocks and prove that each byte it drops arrived.
    - The change, the owner's ruling of 2026-11-05, which allowed the assertion to change:
      `discard` no longer walks the blocks. Its one caller, `connection_stream_read.consume`,
      then calls `flow.Receiver.consume`, which asserts that the bytes lie below the highest
      one that arrived, and `discard` still requires each whole block it drops to be found.
      What the assertion no longer proves is that no gap lies below that byte. The caller
      drops only bytes that `peek` copied, and `peek` stops at the first gap.
    - The checks: the step adds no check, so it has no mutation. `zig build test-quic`,
      `test-h3`, `test-server` and `test-sim-run-quic` pass (1,611 tests).
    - The judge's `--h3 --base f5649a00`, at 10 rounds. The step lands when h3-many wins and
      no input loses.
  - **29d.12, the judge, 2026-11-05.** Run 41961450679, `--h3 --base f5649a00` at 10 rounds:
    h3-many 0.9822 and 0.9799, each a win, and h3-bbr-many 0.9788, a win, and 0.9871, within
    its noise. h3-many fell from 36,194 to 35,552 instructions a request in job 1. Every other
    input is within the noise in both jobs.
  - **29d.13, no encoder stream for a section that inserts nothing, 2026-11-05.** The judge's
    `profile` on cbd11528 (run 42076270070) gave h3's `write_headers` 3.1% and 3.5% of
    h3-many's own samples. Callgrind on a laptop counted 1,619 instructions a request in it.
    About 820 came from `connection_local.encoder_room`, which asks
    `quic.connection_stream_credit.send_credit` for the encoder stream's credit. That call
    walks every live stream of the connection.
    - Only a line that may be inserted writes an encoder instruction (RFC 9204 §4.3). The
      server writes each response line `no_insert`. The change: `write_headers` takes room on
      the encoder stream only when a line of the section may be inserted.
    - A peer that stops the encoder stream breaks RFC 9204 §4.2. colibri now finds it on the
      next section that may insert a line, and not on a section that inserts none.
    - The checks: a test writes a section of `no_insert` and `never_indexed` lines after the
      peer stopped the encoder stream, and requires no failure. Four mutations, each CAUGHT:
      the encoder stream always taken, never taken, an empty `indexing` read as no insert, and
      a test for `no_insert` in place of `may_insert`. `zig build test-h3`, `test-server`,
      `test-sim-run-quic` and `lint` pass.
    - The judge's `--h3 --base cbd11528`, at 10 rounds. The step lands when h3-many wins and
      no input loses.
  - **29d.13, the judge, 2026-11-05.** Run 42087359788, `--h3 --base cbd11528` at 10 rounds:
    h3-many 0.9702 and 0.9691, and h3-bbr-many 0.9721 and 0.9685, each a win. h3-many fell from
    35,569 to 34,508 instructions a request in job 1. Every other input is within the noise in
    both jobs.
  - **29d.14, a faster Huffman decoder, not built, 2026-11-05.** The same profile gave
    `huffman_decode.decode` 3.1% and 3.7% of h3-many's own samples. Callgrind on a laptop counted
    1,165 instructions a request for three strings of 47 bytes. The checked `write_byte` took
    about 330 of them.
    - The owner asked for a decoder from the published methods. The code of RFC 7541 Appendix B
      is canonical, so the Moffat and Turpin decoder applies (A. Moffat, "Huffman Coding", ACM
      Computing Surveys 52(4), 2019, §3.2). It reads a window of the next bits, and a table of
      its first eight bits gives each code of eight bits or fewer.
    - A probe decoded the three strings under callgrind. Main's machine of four bits a step
      took 928 instructions. Two forms of the canonical decoder took 1,784 and 1,557: each
      symbol took about 23 instructions, against about 13 for the machine. A machine of eight
      bits a step, which completes up to two symbols, took 694.
    - The survey's full machine is the fastest form, and main already has one. The machine of
      eight bits a step saves about 230 instructions a request, 0.7% of h3-many, but its table
      is 256 KB against 4 KB, and its build at comptime took about 3 minutes. The owner ruled
      on 2026-11-05 to keep main's decoder.
  - **29d.15, one event for a request whose head ended its stream, 2026-11-05.** The same
    profile gave the QUIC poll's own code 4.4% and 4.5% of h3-many's samples. Callgrind on a
    laptop counted about 1,070 instructions a request in it, and a probe counted 3.1 polls a
    GET: its `request`, an empty `body` that ends it, and its `finished`.
    - Each poll pays about 340 instructions to set up the connection's `receive`. A split of
      the poll's rare paths into functions of their own saved 13 instructions a request, and
      was dropped. Decision 145's draft keeps three calls a GET, since a stream gives one
      event a call.
    - The change, decision 116 as amended at the owner's ruling of 2026-11-05: when the FIN
      arrives with the head, `h3.connection.Request` reports `end`, and the server sets
      `request.end`. No `end` event and no empty `body` follow. A FIN in a later packet keeps
      the old order.
    - `h3.connection.Request` gains the field `end`, which programs of `h3` read. The head
      handlers move to `connection_request_head.zig` for the length of `connection_request.zig`.
    - The simulator's h3 deadline program and the test-only UDP server answered an h3 request
      only at its `body` end. Each reads `request.end` now, as `server.router` already did.
      The first judge run found the server's gap: it answered no h3-many request. Three pinned census values change: h3's long check, and the endpoint check's
      trace and wire values. Each run passes, and Debug and ReleaseSafe agree on each value.
    - The checks: tests for a FIN with the head, a FIN in a later packet, and a content-length
      above zero with the FIN, which h3 refuses before the program reads the request. Seven
      mutations, each CAUGHT: h3 never folds, folds with `end` false, ignores a refusal, or
      skips the end's checks; the server waits for a body, drops `end`, or leaves the record
      unended. `zig build lint`, `test-h3`, `test-server`, `test-client`, `test-sim`,
      `test-sim-run`, `test-sim-run-quic`, `test-testing-quic` and `test-golden` pass.
    - The judge's `--h3 --base` 29d.13's tree, at 10 rounds. The step lands when h3-many wins
      and no input loses.
  - **29d.15, the judge, 2026-11-05.** Run 42135404302, `--h3 --base bde26625` at 10 rounds:
    h3-many 0.9117 and 0.9155, and h3-bbr-many 0.9096 and 0.9153, each a win. h3-many fell from
    34,598 to 31,543 instructions a request in job 1. Every other input is within the noise in
    both jobs. The saving is larger than one poll's setup: a request that ends at its head also
    starts no body deadline, and no empty `body` passes through the server.
  - **29d.16, a walk over the streams that may send, 2026-11-06.** Callgrind on a laptop, on
    29d.15's tree, counted about 2,340 instructions a request of h3-many in
    `connection_stream_send.write`. Most of them are `choose`, which `write_new` calls for each
    STREAM frame. `choose` walks every live stream, and the scan of the pool's live flags alone
    took about 980. Most streams it reads have sent their FIN and wait for an acknowledgment.
    - The change, the owner's choice of 2026-11-06: `quic`'s `Streams` keeps `may_send_new`,
      a bit for each slot. `open_local` and `open_peer` set the bit of each stream this
      endpoint sends on, and `close` clears it. `choose` walks the set bits alone, and clears
      the bit of a stream it finds out of "Ready" and "Send" (RFC 9000 §3.1). No stream goes
      back to those states, so a cleared bit stays correct. No public name changes.
    - `write_new` copies the bits and clears each stream it tries in the copy, in place of
      an array of 128 flags it filled for each frame.
    - The order of the frames does not change, because the walk skips only streams that
      `owed_new` refuses. So each pinned census stays as it is.
    - The tests of `stream_table.zig` move to `stream_table_test.zig` for the file's length.
    - The checks: a test in `stream_table_test.zig` counts the bits as streams of each type
      open and close. A send test requires `choose` to clear the bit of a stream that sent
      its FIN. Mutations, by `zig build test-quic`, each reported CAUGHT or NOT CAUGHT.
    - Each QUIC connection grows by 16 bytes, the 128 bits, in docs/performance.md.
    - The judge's `--h3 --base` 29d.15's tree, at 10 rounds. The step lands when h3-many wins
      and no input loses.
  - **29d.16, the judge, 2026-11-06.** Run 42309659935, `--h3 --base 4fa8d78a` at 10 rounds:
    h3-many 0.9718 and 0.9710, and h3-bbr-many 0.9708 and 0.9649, each a win. h3-many fell
    from 31,692 to 30,799 instructions a request in job 1. Every other input is within the
    noise in both jobs. Callgrind on a laptop counted `connection_stream_send.write` at about
    750 instructions a request, from 2,330.
  - **29d.17, one table entry for a datagram's connection, 2026-11-06.** The judge's profile of
    main 779f7df0 (run 42327497518) gave `udp_run_h3.take` 2.2% and 3.6% of h3-many's samples,
    in the function itself. Callgrind on a laptop showed that cost to be `slot_for` of
    `server.Endpoint`, inlined. A probe of 20,000 GETs counted:
    - at 16 connections, 0.11 lookups a request, 8.5 connections checked for each, and about
      120 instructions a request in the lines of the scan;
    - at 64 connections, 0.17 lookups a request, 32.3 checked for each, and about 570.
    - The change: decision 157. `quic` does not change, and no public name changes.
    - The checks:
      - Tests in `endpoint_routes.zig`: an ID's bits name its entry; an entry in use moves the
        next ID to a free one; a retired ID, a refused ID and a released slot free their
        entries. Tests in `endpoint_routes_test.zig`, through the endpoint: a short header with
        the client's first DCID reaches no connection; a closed connection takes no datagram;
        an ID the peer retired frees its entry after the connection's next datagram.
      - The IDs change, so three pinned values change: the endpoint check's trace and wire
        values, and the h3 deadline check's wire value. Debug and ReleaseSafe agree on each.
      - Nine mutations, by `zig build test-server`, or `test-sim-run` where named, each
        CAUGHT: the index not written into the ID; an entry in use taken over; `sync` that
        frees nothing; an endpoint that never calls `sync`; a released slot that keeps its
        entries (`test-sim-run`); a hit on a closed connection routed; a short-header miss
        that scans; a long-header miss that does not scan; spare IDs drawn outside the table.
        The first run left three NOT CAUGHT, and the tests through the endpoint catch them.
      - `server.Endpoint` grows by 5,088 bytes at its default capacity, the table's 256
        entries and the record of each slot's IDs, in docs/performance.md.
    - The judge's `--h3 --base` main, at 10 rounds. The step lands when h3-many wins and no
      input loses. The judge's 16 connections may put the gain within the noise, and then the
      owner rules.
  - **29d.17, the judge, 2026-11-06.** Run 42337266301, `--h3 --base ccbcdc66` at 10 rounds:
    h3-many 0.9921 and 0.9905, within the noise in both jobs, and 30,621 to 30,378
    instructions a request in job 1. h3-one 0.9954 and 0.9926, and h3-bbr-one 0.9937 and 0.9939,
    each a win in job 2 and within the noise in job 1. No input loses. The owner admitted the
    step on 2026-11-06: each h3 input moves the right way, and the gain grows with the number
    of connections.
  - **29d.18, the length of a varint by compares, 2026-11-07.** The judge's profile of main
    779f7df0 (run 42327497518) gave `wire.varint`'s length functions about 1.2% of h3-many's
    samples. Callgrind on a laptop, on main e365df44, over 4,000 GETs on 16 connections,
    counted about 2,610 instructions a request in `encoded_len_minimal`, `encode_with_len` and
    the `std.mem.indexOfScalar` that `is_length` calls. `encoded_len_minimal` called
    `value_max` for each length, and each call asserted `is_length`, a search of
    `varint_lens`.
    - The change: `value_maxes` holds the largest value of each length, computed at build
      time. `encoded_len_minimal` unrolls into three compares with those constants.
      `is_length` tests for a power of two up to `varint_len_max`, in place of the search. The
      assertions stay. No public name changes, and no byte on the wire changes.
    - The checks: the test of `is_length` runs over every byte value, in place of 0 to 9.
      Six mutations, by `zig build test-wire`, each CAUGHT: `is_length` admits 0; it admits a
      power of two past 8; it admits any length up to 8; each maximum is one less; a value at
      a maximum takes the next length; the maximums are those of the next length.
    - Callgrind on the laptop counted 36,801 to 34,723 instructions a request, and
      `std.mem.indexOfScalar` fell from about 1,530 to 380.
    - The judge's `--h3 --base` main, at 10 rounds. The step lands when h3-many wins and no
      input loses.
  - **29d.18, the judge, 2026-11-07.** Run 42436889568, `--h3 --base e365df44` at 10 rounds:
    h3-many 0.9377 and 0.9417, h3-bbr-many 0.9440 and 0.9479, h3-one 0.9847 and 0.9869, and
    h3-bbr-one 0.9857 and 0.9866, each a win. h3-many fell from 30,667 to 28,758 instructions a
    request in job 1. Each h2 input is within the noise in both jobs, and no input loses.
  - **29d.19, a walk over the responses whose meter may run, 2026-11-07.** The judge's profile
    of main f12bfa99 (run 42442344863) gave `quic_deadline.observe_credit` 1.7% of h3-many's
    samples and 3.4% of h3-one's. Callgrind on a laptop, over 4,000 GETs on 16 connections,
    counted about 1,660 instructions a request in `quic_deadline.observe` and what it calls,
    about 2.5 calls a request. `quic_sends.observe` walked every held request record to start
    or stop its meter, about 380 of them, with the iterator. A response's own meter runs only
    while its stream's credit does not cover it, which is rare.
    - The change, the owner's choice of 2026-11-07: `quic_sends.Sends` keeps `may_meter`, a
      bit for each entry. `look` sets the bit of each entry it finds bound. The walks of
      `observe`, `soonest` and `fire` visit the set bits alone, and `observe` clears the bit of
      each entry whose meter it stopped. `forget` asserts that the bit is clear: a stream
      closes only after a `look` found its response holding nothing. No public name changes,
      and no deadline changes.
    - The checks: a test requires a response its stream's credit holds to be marked, and its
      mark to be clear once the credit covers it, while its record is held. A second requires
      a `look` to leave a response that is not bound unmarked. Seven mutations, by `zig build
      test-server`, each CAUGHT: a bound entry never marked; every entry marked; a walk that
      clears no mark; a walk that clears the mark of a meter that runs; `soonest`, `fire` and
      `observe` each walking no entry. The first run left four NOT CAUGHT. Two were
      equivalent, and the clear and the assertion in `forget` now remove them; the tests above
      catch the other two.
    - Callgrind on the laptop counted 34,723 to 34,205 instructions a request, and the lines
      of the send walk and its iterator fell from about 622 to 135.
    - Each QUIC connection grows by 16 bytes, the 100 bits, and `server.Engine(.{})` by 256, in
      docs/performance.md.
    - The judge's `--h3 --base` main, at 10 rounds. The step lands when h3-many wins and no
      input loses.
  - **29d.19, the judge, 2026-11-08.** Run 42451184832, `--h3 --base 7de688e3` at 10 rounds:
    h3-many 0.9981 and 0.9913, within the noise in both jobs, and 28,631 to 28,576
    instructions a request in job 1. Every other input is within the noise, and no input
    loses. A probe that counted the held records at each `observe` call explains the gap:
    - without valgrind, over 20,000 GETs, 2.0 calls a request, a walk in 44% of them, and 3.0
      records held a call;
    - under valgrind, over 4,000 GETs, a server that falls behind: 2.5 calls a request, a walk
      in 94% of them, and 11.7 records held a call.
    - The owner admitted the step on 2026-11-08: no input loses, and the gain grows with the
      requests a connection holds, when a server falls behind.
  - **29d.20, a stream's last block before the index, dropped, 2026-11-08.** The judge's
    profile of main f12bfa99 (run 42442344863) gave `stream_incoming.Storage.find` 2.5% of
    h3-many's samples. Callgrind on a laptop, over 4,000 GETs on 16 connections, counted about
    320 instructions a request in it, in about five calls a request.
    - The change tried: each `Incoming` kept the block it last found or took, and a lookup
      checked it before the index, as an amendment of decision 61. Six mutations were each
      CAUGHT, and `tools/ci.sh` passed.
    - Callgrind on the laptop counted 34,161 to 34,092 instructions a request. The judge, run
      42519278238, `--h3 --base 130b9e69` at 10 rounds: h3-many 0.9977 and 1.0038, and h3-one
      0.9982 and 1.0001, each within the noise.
    - The owner dropped the step on 2026-11-08: the gain is too small to measure, so decision
      61 stays as it is. Do not try the last block again without a new measure.
