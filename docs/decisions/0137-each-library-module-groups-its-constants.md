# Decision 137: Each library module groups its constants by who sets them: the protocol, the limits, the policy, and each algorithm's parameters, one file each

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-30, for design §8 step 30.

`src/quic/constants.zig` reached the 500-line limit (CLAUDE.md), and step 29a had to place
a unit in `core` to make room. The file mixed values an RFC fixes with limits colibri
chose, so a reader could not see which values CLAUDE.md says to ask before changing.

The rulings:
1. Every library module sorts each constant by the question a reader asks of it:
   - `protocol`: a value the RFC fixes, which no one may change: a frame type, a bit, a
     length. The name is not `wire`, because `wire` is a module most of the others import.
   - `limits`: a bound colibri chose that sizes memory or bounds a loop or a queue.
     CLAUDE.md's "Ask before changing a named limit" covers exactly this file.
   - `policy`: a value colibri chose within what the RFCs allow, which sizes nothing: a
     count of probe timeouts, a default deadline, or a value an RFC recommends outside an
     algorithm's file.
   - One file for each algorithm whose parameters an RFC or a draft recommends. In `quic`
     it is `recovery`, which holds the values of RFC 9002's loss detection, congestion
     control and pacing, and nests `cubic`, `hystart` and `bbr`.
   - Units stay in `constants.zig`, beside one import for each file. A value another
     module defines goes into the group it has there, such as `streams_per_connection_max`
     from `core`, which is a limit in both.
2. A module has a file only for the groups it holds. `constants.zig` exports each file as a
   namespace, so `constants.frame_ack` becomes `constants.protocol.frame_ack`.
3. Every library module moves at once, before step 29b, so BBRv3's constants go into
   `recovery` from the start. The renames are a breaking change in the next release.
4. `constants_limits.zig` holds a test that pins each limit's value. A changed limit fails
   that test, and the owner rules on it before the test changes.
5. The test-only trees, `sim`, `testing` and `golden`, keep their files by check. Their
   constants set a check's workload, which none of the groups describes.

Alternatives that lost:
- New constants alone in files by group, as `cubic` and `hystart` were added. No name
  changes, but the old file stays at its limit and its groups stay mixed.
- quic alone, or quic first and the rest when each grows. Two layouts would stand side by
  side, and each module would break its dependents in a release of its own.
- The file by itself as the guard of the limits. A changed value would pass every check,
  and the ruling would rest on a reader who noticed it.
