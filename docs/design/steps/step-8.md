# Design §8 step 8: the QUIC simulator

[Design §8, the build plan](../../design.md#8-build-plan)

A datagram network with delay, drop, reorder, duplication and ECN marking, over the step 2 clock,
with a null crypto suite. **Check:** one seed replays byte-identically across hosts and build modes
— and the harness **builds and runs with no HTTP module in the graph**, which is the check for
[decision 5](../../decisions/0005-quic-knows-nothing-about-http.md).
*Medium.*

**Check passed, 2026-09-19.** `src/sim/network.zig` carries datagrams between two endpoints over
the clock of step 2. A `Schedule` fixed before a run gives the rates of three events as counts
out of a thousand — dropped, duplicated, and marked ECN-CE — and a delay range; every draw for a
datagram is made when it is sent, so its fate does not depend on when it is collected.

Reordering is not a draw. Each datagram takes its own delay, so one sent later and delayed less
overtakes one sent earlier, which is what a network does. Two that arrive at one instant are
delivered in the order they were sent: without that tie-break the delivery order would follow
the array's layout, and a run would replay only on the host that laid it out. RFC 9000 §13.4
puts one rule on the marking, and the network keeps it: a node answers congestion by marking a
datagram the sender sent ECT, and never one sent Not-ECT. The codepoints carry RFC 9000 §13.4's
names and no bit values, because the two bits are RFC 3168's, which is not in `docs/rfcs/` and
which colibri never writes: the field belongs to the IP header its caller owns.

What the network does not model is recorded with it. There is no bandwidth, no queue length and
no path MTU, so a datagram is never dropped for being too large or too frequent. RFC 9002's
congestion control is step 10's, and a network that modelled a bottleneck would decide the
answers step 10 must compute.

`src/sim/network_check.zig` is the check, and it is the first run in which both halves meet:
colibri frames a packet, the null suite seals it, the network carries it, and the peer reads the
datagram, opens the packet and compares it. Each packet carries the number its header encodes
inside its sealed payload, so the peer compares what it rebuilt against what was sent and not
against what is plausible. An endpoint learns what its peer has acknowledged only when a
datagram comes back, which is the narrowest Packet Number field RFC 9000 Appendix A.2 permits
and so the strict case for recovery.

Over 256 seeds on macOS 25.6 arm64: 16,384 packets sent, 16,398 delivered, 809 dropped, 823
duplicated, 9,294 reordered, 982 marked ECN-CE, and **6,611 packet numbers rebuilt against a
history that had already moved past them, every one exactly right**. Digest `0x1f31d87e` in
Debug and in `-Drelease`. A run in which any of those events never happened fails as
`ScheduleUnexercised`, so the check cannot pass while proving less than it claims.

The second half of the check is the module graph. `src/sim/run_quic.zig` receives `sim` and
`quic` and no HTTP module, so this harness builds and runs with `h2`, `h3`, `hpack`, `qpack`
and `http` absent — held by the build, not by a lint. `zig build test-sim-run-quic` runs it,
and CI runs it in both modes.

`zig build test` passes 716 of 716.

Mutations: 22 applied over the network and the check, 21 **CAUGHT** and one equivalent. The
first pass caught 14, and the seven it missed were worth more than the fourteen.

One did not fail the run, it **hung** it. Removing the line that frees a delivered datagram's
slot left `receive` returning the same datagram for ever, and a test helper looped on it with
`while (network.receive(...)) |_| {}`. That is an unbounded loop, which non-negotiable 4
forbids and which `tools/lint/unbounded_loop.zig` does not catch: its own header records the
blind spot, that a `while` over an optional is outside both of its checks. The helper is now
bounded by the network's slots, and what found it was a mutation harness that times a step out
and reports the hang rather than waiting.

Three were missing tests of the network's bookkeeping, each written: the tie-break between two
datagrams arriving at one instant, which the old test could not tell from the array's layout
because its slots happened to be in order; the highest sequence delivered being assigned
instead of raised; and the two endpoints sharing one record of it.

Three were a check whose assertions never fire on a healthy run, so deleting one changed no
output. `Fault` is the answer, in the shape the null suite's refusal flags already use: a test
turns one on and requires the violation it should produce — a corrupted byte, a packet number
misreported as an earlier one of the sender's own, a scrambled payload, a run left undrained,
and a network with nothing to report. Two of those faults were themselves wrong at first, and
the mutations said so: one returned its violation directly instead of leaving datagrams in
flight, and one misreported a number out of range, where a neighbouring check caught it first
and hid the comparison the fault existed to prove.

The equivalent one is sizing the Packet Number field as if nothing were acknowledged. Every
number in this run is small enough that both sizings give one byte, so the mutant's output is
identical — which is also why no field here exceeds one byte. Fields of two, three and four
bytes are drawn by step 7's packet check, which sets the distance directly.
