# Design §8 step 9: QUIC transport, cut into five

[Design §8, the build plan](../../design.md#8-build-plan)

The owner ruled on 2026-09-19 that this step is five (§12 question 5), after the first part of it
showed where the dependencies already cut. Only the last waits on chapulin. **Check:** the step 8
simulator checking [invariants 17 to 21](../../invariants.md#quic) after every step; the QUIC Interop
Runner's `handshake`, `transfer`, `retry`, `resumption`, `keyupdate`, `multiplexing`, `ipv6`,
`amplificationlimit`, `rebind-port` and `rebind-addr` cases against the endpoint of §9, with
**exit 127** for everything not yet supported — `connectionmigration` and `zerortt` are
permanent 127s by decisions 21 and 20. That check belongs to step 9e, because nothing before
it completes a connection.
