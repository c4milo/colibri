# Decision 136: BBRv3 draws its probe waits from one value the caller draws, a connection takes its controller from one enum, and a bulk download measures it first

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-30, for decision 134 and design §8 steps 13k and 29.

BBRv3 picks two random values each time it waits to probe for bandwidth (draft-ietf-ccwg-bbr-06
§5.3.3.8.2): a wait of 2 to 3 s, and a bound of 62 or 63 round trips. colibri holds no
generator (invariant 5). The loads of step 13i keep the window at its first value, so they
cannot tell two controllers apart.

The rulings:
1. The caller draws one u64 from its source at start, the option `bandwidth_probe_waits` of
   `quic.Connection`, as for `packet_number_skips` (decision 123). The server's and the
   client's QUIC connections draw it. Each wait mixes the value with the count of waits so
   far, through a fixed function of integers, so no pattern repeats and one seed replays.
2. `quic.CongestionController` is `enum { cubic, bbr }`. `quic.Connection`'s options,
   `server.Config` and `client.Config` each take `congestion_controller`, with `.cubic` the
   default. It is the one new public name.
3. Step 13k measures bulk downloads at a bottleneck before step 29 builds BBRv3. netem
   holds a rate and a deep queue, and the report gives the download time, the goodput and
   the queue delay. Step 29 then adds a run where CUBIC and BBRv3 share the bottleneck.
4. Each part of step 29 comes with Lean proofs of its arithmetic and a TLA+ model of its
   states, as for decisions 133 and 135.

Alternatives that lost:
- A call that asks the program for each draw. Each wait would add a step to the receive
  path, and the program would answer a question it cannot judge.
- The eight bytes of the value taken in turn, as decision 123 does. The waits would repeat
  after eight probes, and two connections with one value would probe together.
- One bool for BBRv3. An enum takes a third controller without a new name.
- A controller for each connection that the server picks. A server has no way to tell which
  peer gains from which controller.
- The `network` input of step 13i alone. Its loads are limited by the application, and BBRv3
  differs from CUBIC only when the window fills.
