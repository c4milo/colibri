# Decision 32: Real numbers come from Linux, and the machine is written down beside them

[All decisions](../decisions.md) · Section: [Performance](../decisions.md#performance)

io_uring, UDP_SEGMENT, UDP_GRO, `sendmmsg`, SO_REUSEPORT and ECN handling are Linux mechanisms, and
a number measured on the development Mac predicts nothing about them. Cost: the bench does not run
in the inner loop. Gain: colibri never publishes a number that is an artifact of the wrong kernel.
macOS runs the simulator, the corpus and the unit tests, which need no kernel at all.
