# Decision 35: colibri is zero heap

[All decisions](../decisions.md) · Section: [Memory](../decisions.md#memory)

Ruled by the owner on 2026-09-16. There is no `Allocator` anywhere in `src/`: no parameter, no
field, no `std.heap`, and no test that allocates. The caller owns every connection struct and every
buffer, and places each one where it chooses: static storage, its own arena, or memory it mapped.
colibri exposes their sizes as comptime constants, so `@sizeOf` and the named limits of design §7
account for all of colibri's memory. chapulin's decision 18 is the precedent.

The rejected alternative is the rule this repository started with: allocate at init, through
one constructor per connection type that takes an `Allocator`, and never after. Three things
beat it. An allocating constructor puts `error.OutOfMemory` into colibri's API, and a failure
path into every caller that no protocol requires. The lint could enforce that rule only by
function name, so any function named `init` could take an allocator. And a connection pool
that colibri allocated would have made colibri decide how many connections a process holds and
where their memory lives, which is the caller's decision.

Cost: the caller places every struct and cannot ask colibri to grow one, so a peer that exceeds
a limit colibri sized for is refused, never accommodated. Gain: nothing to allocate, fail or
leak; no signature that obtains memory; and an embedding runtime that places memory as it
chooses, such as on huge pages or in buffers registered with the kernel, without colibri
knowing. `tools/lint/heap.zig` enforces the rule with no exception by name, and invariant 1
asserts it at runtime.

**Amended by the owner on 2026-10-19, for design §8 step 22 (decision 125).** A type may
size part of its memory from a count that the caller sets at run time. `client.Pool` is the
first such type: the caller sets its count of TCP connections in the options that `init`
takes. The owner ruled the count at run time on 2026-10-17.
- The type has a pure function `memory_bytes(options)`, which returns the bytes that those
  options need. A caller can call it at comptime to size a static array, or at run time to
  size memory that it maps.
- `init` takes that memory and asserts its length and its alignment. The memory belongs to
  the type until the caller stops using it. colibri never asks for more.
- The struct itself keeps a comptime size. `@sizeOf` plus `memory_bytes(options)` is all the
  memory of the type, and docs/performance.md gives both terms.
- A named maximum in the module's `constants.zig` bounds each count, so every loop over the
  counted part stays bounded and `memory_bytes` cannot overflow.
- A new type that uses this form is a design change. Its step in design §8 names the type and
  the count. Every other type keeps its sizes as comptime constants.

The rule against the heap does not change: no `Allocator`, no `std.heap`, and no
`error.OutOfMemory`. `tools/lint/heap.zig` needs no change.

The alternatives refused:
- A comptime count, `client.PoolOf(.{ .tcp_connections = 16 })`, as `server.EndpointOf`
  does. A program then fixes the count when it builds. A program that reads its counts from
  its configuration must reserve the largest count for each pool, or build again to change
  one.
- A slice of connections that the caller builds. The connection type would become public
  again, which step 21d removed from each root (decision 121).
- An `Allocator` that `init` takes, which this decision refused for the reasons above.

Cost: the caller makes one call more, and `@sizeOf` alone no longer gives a pool's memory.
The comptime assert pins the size of one counted connection and the struct, not the total.
