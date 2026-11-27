# Design §8 step 66: MAX_STREAMS rides in a packet that goes anyway, 2026-11-19

[Design §8, the build plan](../../design.md#8-build-plan)

[#139](https://github.com/c4milo/colibri/issues/139). The owner ruled decision 130's amendment.
- **The cost.** Under the latency run's 32 requests in flight, colibri's h3 server took 15.5 µs
  a request at 40,000 a second, against 4.0 µs with 160 in flight (step 13s). An h3 request
  took 3.9 datagrams at 2,000 requests a second with colibri, and 2.6 with axum on quinn. A
  qlog of 500 requests showed why: 199 of the server's 405 packets held a MAX_STREAMS frame
  alone, about 1.5 ms after a packet of responses, and the client acknowledged them in 260
  packets of their own.
- **The change.**
  - `flow.Receiver.count_credit_low` says when an owed MAX_STREAMS goes out at once: the peer
    holds half its stream count unused, or less.
  - `write_limits` writes only those, and a lost frame owed again (RFC 9000 §13.3).
    `count_credit_owed`, which says whether the connection must send, judges the same way.
  - `write_count_credit` writes every owed MAX_STREAMS after the STREAM frames of a packet
    that elicits an acknowledgment for another reason. Each STREAM frame carries its length
    (§19.8), so a frame can follow it.
- **The simulator.** Every check passes, in Debug and ReleaseSafe. The census of the h3 check,
  its long and qlog runs, the h3 deadline check and the endpoint check pin new values, since
  each digest holds the datagrams or the traces. 4 of the 256 h3 deadline seeds changed, each
  by 1 ms to 4 ms in a finish or a close on a lossy link, with the same verdicts. 123 of the
  128 endpoint seeds changed, since TCP and QUIC peers share one endpoint there, and fewer QUIC
  packets move when each connection runs. Every property holds.
- **Check:** `src/quic/connection/connection_flow_count_test.zig` and a test of `flow.zig`.
  Seven mutations, each CAUGHT: `count_credit_owed` by the old rule; `write_limits` writing
  every owed frame; no frame after the STREAM frames; a frame after them in a packet that
  elicits nothing; half the count taken as above half; a lost frame left to wait; a lost frame
  not owed.
- **Checked, 2026-11-19,** on `3c43557d`:
  - The judge measured it against `eb26cf67`, with the h11 and h3 inputs
    ([run 44643486991](https://github.com/c4milo/colibri/actions/runs/44643486991)).
    h3-bbr-many wins in both jobs, 0.9756 and 0.9834. Every other input is within the noise,
    and none loses.
  - The latency run ([44643499229](https://github.com/c4milo/colibri/actions/runs/44643499229))
    against the one before the step ([44619128899](https://github.com/c4milo/colibri/actions/runs/44619128899)),
    both jobs. At 2,000 requests a second an h3 request took 2.48 and 2.49 datagrams with
    colibri, where it took 3.88 and 3.93, and 2.60 with axum. At 40,000, it took 2.05 and 2.08,
    where it took 2.29 and 2.39, and 2.13 with axum. colibri's core was busy 0.53 and 0.56 at
    40,000, where it was 0.67 and 0.61. The p99 stayed within the rounds' spread.
  - `tools/ci.sh` passed 33 sections, with Zig 0.16.0 on an Apple M1 Pro with macOS. The quic
    tests passed on x86-64 Debug in an amd64 container.
