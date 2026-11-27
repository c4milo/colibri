# Decision 102: colibri writes qlog when its caller asks, from the pinned drafts

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-27. The QUIC Interop Runner asks each endpoint for a qlog (entry 28),
and colibri's had none (design §8 step 9e).
- `src/qlog/` is a library module that imports `core` alone. `quic` and `h3` import it and
  fill its event records from their own state. It imports no protocol module, so `quic`
  still imports no HTTP module (decision 5), and moving it out later changes only the build.
- It is written from three Internet-Drafts, pinned in `docs/rfcs/qlog/` with their SHA-256:
  draft-ietf-quic-qlog-main-schema-14, draft-ietf-quic-qlog-quic-events-13 and
  draft-ietf-quic-qlog-h3-events-13. Non-negotiable 10 names RFCs; these three are the
  exception until the RFCs publish. Each events draft's §2.1 has an implementation name its
  event schema with the draft number, so colibri writes
  `urn:ietf:params:qlog:events:quic-13` and `urn:ietf:params:qlog:events:http3-13`.
- A connection logs only when its caller gives it a log in its options, which is null by
  default. With none, each place that would log costs one branch and writes nothing. This is
  the one exception to CLAUDE.md's rule that nothing logs on the per-frame path, and it is
  off unless the caller turns it on.
- colibri still owns no I/O. A log is a buffer the caller owns, and colibri appends JSON Text
  Sequences records to it (RFC 7464). The caller writes the records wherever it wants, for
  example to a file under `QLOGDIR` (main schema §12.1). An event that does not fit is
  dropped whole and counted, and never fails the connection.
- A log never changes what a connection sends. The same seed gives the same datagrams with
  and without one.
- colibri writes a peer's bytes, such as a close reason or an ALPN value, as hexstrings and
  never as text, so every string it writes is its own ASCII and needs no UTF-8 check.

The alternatives offered:
- Its own repository, recommended first and withdrawn: decision 3's reason to move code out
  is another project that wants it without colibri, and the only producer of QUIC and HTTP/3
  events among the owner's projects is colibri. The two would change together across two
  pins, and a package cannot import colibri's types.
- stdx, whose codecs carry no protocol knowledge. Decision 90 kept protocol limits out of it.
- The test endpoints alone, which would leave a caller of the library with no qlog.
- A build option, which costs nothing when off but needs a rebuild to turn on, and a
  provider the connection calls for each event. The owner chose a runtime setting.
- Waiting for the RFCs.

Cost: a module and two edges in design §3, `quic` → `qlog` and `h3` → `qlog`, and a branch
at each place a connection logs.

Amended by the owner on 2026-09-27: a JSON encoder and decoder belong in stdx, beside its
other codecs, which carry no protocol knowledge (decision 90). `src/qlog/json.zig` stays
until stdx has them and is deleted then, and `qlog` then imports stdx's `json` in place of
`core`. The simulator's check that each record parses waits for stdx's decoder, rather than a
decoder written in colibri.

Amended by the owner on 2026-09-28, for design §8 step 18d:
- Each h3 call that writes or reads a frame takes the instant, `now_ns`, as `quic`'s calls do
  (non-negotiable 3), and `write_data_header` becomes a method of the connection that names
  its stream. Refused: logging each h3 event at the instant of `quic`'s last call, which
  would give a frame the caller writes long after that call an earlier time than it had.
- A HEADERS frame's field name is logged as text when every byte of it is printable ASCII,
  0x20 to 0x7e, and as `name_bytes` otherwise; its value likewise, as `value_bytes`. That is
  h3-events §4.2.2's rule, and text of ASCII alone needs no UTF-8 check, the reason this entry
  gave for hexstrings. Refused: hexstrings for every line, which a viewer shows as hex, and an
  empty list of field lines.

Amended by the owner on 2026-09-28: qvis, the qlog viewer most people open, reads qlog 0.3
alone, which draft-ietf-quic-qlog-main-schema-02 and its two events drafts define, so
`tools/qlog_to_qvis.py` rewrites a colibri log into that form. colibri itself still writes the
drafts this entry pins. Refused: writing qlog 0.3 from colibri, which would trade the pinned
drafts for a viewer's, and leaving the logs unreadable in qvis until it catches up.

Amended by the owner on 2026-09-28: when stdx's JSON module takes the CPU features its vector
paths may use (stdx's decision 30), `qlog.Log.init` takes them from its caller, who passes
`Features.detect()` or `Features.target()`, as decision 98 has h11's decoder pool do, so
colibri never asks the CPU itself. `qlog` then imports stdx's `codec` too. The records are the
same bytes for every value (stdx's invariant 5). Refused: `qlog` calling `Features.target()`
itself, which keeps `Log.init` as it is but leaves the caller no choice, and gives a build for
a baseline CPU the scalar paths.

Amended by the owner on 2026-09-28: `server.Endpoint`, which starts its QUIC connections
itself (decision 103), gets their logs from a log provider in its config, a vtable the caller
fills. Once a connection has started, the endpoint calls `open` with the original destination
connection ID, which main schema §12.1 names the file after, and gets a log whose header the
caller wrote, or null for a connection the caller does not log. The connection writes its
QUIC and h3 events into it. When `ended` hands the connection back, the endpoint calls `close`
with the log, and the caller takes its last records. Refused: one log per connection slot,
given at init beside the receive pools, which holds a buffer per slot whether or not it logs.

Amended by the owner on 2026-09-29: `qlog` hands each record's tokens to stdx's `write_items`
many at a call (stdx's decision 33), with stdx pinned at c134f2c. `batch.zig` gathers them,
and copies each name's, string's and hex string's bytes into its own buffer as it takes
them, so no writer's bytes need to outlive the call that passed them. Bytes longer than
that buffer go to `write_items` at once. The records are the same bytes as before. The QUIC
simulator tests took 2.61 s in ReleaseSafe on an Apple M1 Pro, against 2.68 s writing one
token a call, about 2 ns less for each byte the logged runs write. Refused: one token a
call, which is simpler and 2.7% slower there; and gathering without copies, which has each
writer that formats a string on its stack write the gathered tokens before it returns, a rule
a later writer could break without any test failing.

Amended on 2026-11-24, after stdx's decision 40 as amended that day: stdx moved the type of
CPU features from its `codec` module to `platform`, as `platform.CpuFeatures`, and `codec`
no longer holds it. `qlog` imports `platform` in place of `codec`, for the type alone, and
never calls `probe` or `detect`. h11 and `server` import `platform` beside `codec` for the
same type (decisions 98 and 101). The names `qlog.Features`, `h11.coding.Features`,
`server.Features` and `client.Features` stay, each an alias of `platform.CpuFeatures`, so a
program that names one builds as before. Refused: a name `CpuFeatures` in each module in
their place, which renames four public names (decision 115) for no change in what a program
can do.

Amended by the owner later on 2026-11-24: the four names become `qlog.CpuFeatures`,
`h11.coding.CpuFeatures`, `server.CpuFeatures` and `client.CpuFeatures`. Each is the name of
the type it aliases, so the type has one name in stdx and in colibri. A program that named
`Features` names `CpuFeatures`, which is the change the previous amendment refused.
