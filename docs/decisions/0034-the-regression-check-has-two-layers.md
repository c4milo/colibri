# Decision 34: The regression check has two layers

[All decisions](../decisions.md) · Section: [Performance](../decisions.md#performance)

It was ruled when there was no CI here; entry 47 adds one and keeps both layers. The cheap layer
runs inside the deterministic simulator and does not vary between runs: counted syscalls, copies and
bytes per request, committed as exact numbers that a diff has to change on purpose. Allocations are
not counted, because entry 35 makes that number zero by construction. That layer runs in `zig build
test` on every change. The expensive layer is `bench/` with committed baselines and a threshold that
fails, run by a person before a step is called done — stompy's full crash tier is the precedent.
Static memory per connection is a comptime number and is measured the way chapulin's `bench/sram.sh`
measures its SRAM rows, never estimated, and the README's table is generated from the measurement
rather than written beside it.
