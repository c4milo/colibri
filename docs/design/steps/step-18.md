# Design §8 step 18: qlog

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 102](../../decisions/0102-colibri-writes-qlog-when-its-caller.md) has colibri log a connection as qlog when its caller asks,
from the drafts pinned in `docs/rfcs/qlog/`. Four parts, in order:
- **18a**, the `qlog` module. A `Log` over a buffer the caller owns, the QlogFileSeq header of
  main schema §5, and the event envelope of §7, with each time in milliseconds after the
  connection's first instant. Each record is a JSON text between RS and LF (RFC 7464) with
  RFC 8259's escaping. An event that does not fit is dropped whole and counted.
  **Check:** byte-exact tests of the header and of each record, and a test that fills a buffer
  until an event is dropped.
- **18b**, QUIC events. `Options.qlog`, null by default, and the Core events of quic-events §3:
  `version_information`, `alpn_information`, `parameters_set`, `packet_sent` and
  `packet_received` with their frames, `recovery_metrics_updated` and `packet_lost`. Also
  `connection_closed`, `connection_state_updated` and `packet_dropped`.
  **Check:** each QUIC check of the simulator gives the same census with a log as without one,
  and each record of those logs parses as JSON and carries the fields its event requires.
- **18c**, the endpoints. §9's UDP endpoint writes each connection's log under `QLOGDIR`, named
  for its original destination connection ID and its vantage point (main schema §12.1), and
  the interop image passes on the runner's `QLOGDIR`.
  **Check:** a runner run leaves one file per connection, and each file parses.
- **18d**, HTTP/3 events. h3-events' `parameters_set`, `stream_type_set`, `frame_created` and
  `frame_parsed`.
  **Check:** the simulator's h3 checks give the same census with a log as without one, and each
  record parses.

**18a, 2026-09-27.** `src/qlog/` is the `qlog` module, exported by name, which imports `core`.
- `Json` writes a JSON text through `core.Writer`: objects and arrays with a comma between
  members, strings of colibri's ASCII with RFC 8259 §7's escapes, hexstrings, unsigned integers,
  booleans, and milliseconds with a three-digit fraction from nanoseconds.
- `Log` holds the records in a buffer the caller owns. `start` writes the QlogFileSeq header
  with the trace's group ID and vantage point, a monotonic clock whose epoch is "unknown", and
  the event schemas. `event` writes one record, whose time runs from the header's instant, or
  drops it whole and counts it. `bytes` and `clear` hand the records to the caller.
- The drafts and RFCs 7464 and 8259 are in `docs/rfcs/qlog/`, with their SHA-256 in
  `docs/rfcs/SHA256SUMS`.
- 9 tests, byte-exact, and 8 mutations, each CAUGHT: the record separator, the closing line
  feed, both escapes, the comma, an event committed in part, the fraction's unit, and the
  epoch.

**18b, 2026-09-27.** `quic` imports `qlog`, and `Options.qlog`, null by default, is the log a
connection writes into. The caller writes the log's header with `Log.start`, because the event
schemas it names depend on whether h3 events go into the same log.
- `connection_qlog.zig` writes the events. `Connection.init` logs `version_information` and the
  connection's own `parameters_set`. `seal_all` logs each packet it seals as `packet_sent`. The
  receive walk logs each packet as `packet_received` or `packet_dropped`, with the bytes the
  walk stepped over as its length. A packet's frames are read a second time from its
  plaintext, and an ACK Delay is scaled by the exponent of the endpoint that sent it (RFC 9000
  §19.3).
- `send`, `receive` and `on_instant` end in `log_changes`, which logs what changed since the
  last events: the peer's `parameters_set` and the `alpn_information` once the peer's
  parameters arrive, the state of quic-events §4.6, `connection_closed` when the connection
  stops being active, and each recovery metric whose value changed. A peer's close is logged
  where its frame is read, which is where its code is known.
- `quic_event.zig` writes `version_information` and `alpn_information`, and `packet_lost`'s
  trigger is optional, for a loss either threshold of RFC 9002 §6.1 could have declared.
- 10 tests in `connection_qlog_test.zig` and one in `quic_event.zig`. 20 mutations, each CAUGHT
  by `zig build test-quic`, broke: the PADDING of a sent packet; the length of a coalesced
  packet; one close per side; a close logged only once the connection stops being active; one
  event per state; the three rules of a metric logged on change; the peer's parameters and the
  protocol, once each and in that order; the two rules of the Handshake state; each side's ACK
  Delay exponent; two drop triggers; the version's byte order; the initiator of a connection's
  own parameters; a sent close's code; and a frame that does not parse, which was NOT CAUGHT
  until its test was written.
- Each packet recovery declares lost is logged as `packet_lost`: with `time_threshold` from the
  loss timer, with `pto_expired` from a probe timeout (RFC 9002 §6.2.4), and with no trigger
  from an ACK, where either threshold of §6.1 could have declared it. 2 tests, and 5 mutations,
  each CAUGHT by `zig build test-quic`: each of the three triggers, the ACK's losses logged at
  all, and the lost packet's number.
- The simulator check, 2026-09-28. The QUIC connection check runs its five networks again
  with a qlog on each endpoint, and each gives the digest it gives without one, which folds in
  every datagram's bytes. The run takes each endpoint's records after every step, as a caller
  that writes them to a file would, and fails when an event was dropped. The logs replay too:
  Debug and ReleaseSafe wrote the same bytes with the same digest on each network, 9,786,196
  bytes over the lossy network's 256 seeds, and the test pins each network's length and
  digest.
- 5 mutations, each CAUGHT by `zig build test-sim-run-quic`: the endpoints given no log, a
  dropped event left unreported, the records not taken after a step, and two changes a logger
  could make to what a connection sends: the count a PING waits for, and the congestion window.
  The third was NOT CAUGHT until the digest was pinned.
- Not built yet: the check that each record parses as JSON and carries the fields its event
  requires. It waits for stdx's JSON decoder (decision 102 as amended).

**18c, 2026-09-28.** The UDP endpoint takes `qlogdir=<directory>` in both roles, and each
connection writes its qlog there, named as main schema §12.1 recommends:
`<ODCID>_<vantage point>.sqlog` (`udp_qlog.zig`). A connection's buffer of `quic_qlog_len`
bytes holds one turn's events. The loop writes them to the file after each turn, through libc as
`hq_file.zig` writes a download, and closes the file when the connection ends or the run fails.
`run_endpoint.sh` passes the runner's `QLOGDIR` to both roles.
- `tools/qlog_check.py` checks a directory of these files. Each record must be a JSON text
  between RS and LF (RFC 7464), the header's group ID and vantage point must be the file
  name's, and each event must carry the members main schema §7 and quic-events §3 require, at a
  time that never goes back. The packets sent in each space must be numbered without a gap,
  since colibri skips no number. With `complete` it also requires a client file and a server
  file per connection, each logging the connection's close.
- `tools/quic_udp.sh` runs its hq-interop and h3 connections with `qlogdir`, requires that no
  event was dropped, and checks the four files with `complete`: 17,283 events, on an Apple M1
  Pro. `tools/interop.sh` checks every qlog directory colibri's side of a runner test case
  leaves. A local run against quic-go, handshake and transfer in both roles, left 8, and each
  passed.
- 7 mutations, each CAUGHT. `zig build test-testing-udp` caught three: the file named for the
  other vantage point, the connection ID left out of its name, and an empty directory taken.
  `tools/quic_udp.sh` caught four: the records not written each turn, `qlogdir` refused by the
  server and by the client, and a connection given no log. The first and last of those four were
  NOT CAUGHT until `complete` required each file to log its connection's close.

**18d, 2026-09-28.** `h3` imports `qlog`, and `Options.qlog`, null by default, is the log an h3
connection writes its HTTP/3 events into. A caller that passes its QUIC connection's log keeps
both in one trace (h3-events §1.1). Each call that writes or reads a frame takes the instant,
`now_ns`, and `write_data_header` is a method that names its stream (decision 102 as amended).
- `connection_qlog.zig` logs `stream_type_set` for each stream colibri or the peer opens, the
  SETTINGS frame each side sends with `parameters_set` for each, and `frame_created` and
  `frame_parsed` for HEADERS with their field lines, DATA, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH and
  reserved or unknown frames. A field line is text when printable ASCII and bytes otherwise
  (h3-events §4.2.2). The UDP endpoint's h3 connections write into their QUIC connection's
  file, which names both event schemas.
- 7 tests in `connection_qlog_test.zig` and 4 in `qlog/h3_event.zig`. 21 mutations, each CAUGHT
  by `zig build test-h3`, removed each hook, kept a stale instant on two calls, and swapped the
  reserved and unknown names and the field section size setting's. The stale instant on a DATA
  frame was NOT CAUGHT until its test gave the frame an instant of its own.
- The simulator runs the h3 check's first 32 seeds twice, without logs and with one on each
  endpoint, and both give the same datagram digest. The logs' length and digest are pinned, and
  Debug and ReleaseSafe agree. A log too small for a step's events is reported. With logs, the
  whole h3 check wrote 91 MB and the long check 354 MB, and they made `zig build test-sim-run`
  43 and 122 seconds longer on an Apple M1 Pro, so the test runs 32 seeds, which cost 5.
- 5 mutations, each CAUGHT by `zig build test-sim-run`: the endpoints given no log, the h3
  connection given none, a dropped event unreported, the records not taken after a step, and a
  logger that changes how field sections are encoded. A logger that changed the grease value
  after SETTINGS had gone out changed nothing sent, and was rightly NOT CAUGHT.
- Not built yet: parsing each record as JSON in the simulator, which waits for stdx's decoder.

**18b and 18d, the record check, 2026-09-28.** stdx's `json` module is pinned at eb0f0c7, so
`qlog` writes each record with its `TextWriter`, `src/qlog/json.zig` is gone, and `qlog` imports
stdx's `json` in place of `core` (decision 102 as amended). `member.zig` writes one member of an
object, its name and its value. Every byte-exact test passes unchanged, and so do the
simulator's pinned logs.
- `src/sim/qlog_records.zig` reads back, with stdx's `TextReader`, each record a logged run
  takes. A log's first record must be the header, with the members main schema §3 and §5
  require. Every other record must be an event with a time, a name and data (§7), no earlier
  than the event before it (§7.1), and with the members its event requires: a packet's header
  and its type, each frame's type, a state's `new`, and a stream's ID and type. The QUIC
  connection check and the h3 check call it after each step and pin the events it read: 49,865
  on the lossy network's 256 seeds, and 47,715 on the h3 check's 32. Debug and ReleaseSafe
  agree.
- 7 tests, and 12 mutations, each CAUGHT. `zig build test-sim-run-quic` caught the check not
  called, packet events without their header, and seven breaks of the check itself: the
  header's members, the event's members, a member `packet_sent` requires, a member an object
  must hold, a packet's frames skipped, a time that goes back, and a time without three digits
  of fraction. `zig build test-sim-run` caught the check not called, h3 frames without their
  type, and frames read at the instant of the call before. A DATA frame header written at the
  instant of the call before was NOT CAUGHT by the simulator, which writes each at the same
  instant as that call; `zig build test-h3` catches it (18d).
- Cost, as user CPU time on an Apple M1 Pro. `zig build test-sim-run-quic` took 2.41 s in
  ReleaseSafe at a5a97d2, 2.57 s with stdx's writer, and 2.79 s with the check; in Debug, 15.3,
  16.7 and 18.8 s. The logged runs write 36.7 MB, so stdx's writer costs about 4 ns more per
  byte in ReleaseSafe. The check added 1.2 s to the 71.5 s of `zig build test-sim-run` in
  Debug.

**18b and 18d, stdx's features, 2026-09-28.** stdx is pinned at f647da1, whose JSON writer and
reader take the CPU features their vector paths may use (stdx's decision 30). As decision 102
as amended rules, `qlog.Log.init(buffer, features)` takes them from its caller, and `qlog`
imports stdx's `codec` for the type, which it exports as `qlog.Features`. The simulator and the
unit tests pass `Features.none()`, and the UDP endpoint passes `Features.detect()`.
- The records are the same bytes for every value (stdx's invariant 5). Every byte-exact test
  and the simulator's pinned logs and event counts hold, and `zig build test` passed 2,244 of
  2,244. `tools/quic_udp.sh`: 4 files, 17,335 events, each record a JSON text.
  `tools/consumer_check.sh` passed.
- `zig build test-sim-run-quic` in ReleaseSafe on an Apple M1 Pro, as user CPU time with both
  pins run side by side: 2.88 s at eb0f0c7 and 2.77 s at f647da1. The machine's load average
  was 77 during the run.

**18b, tuples, 2026-09-28.** Each packet event names the tuple its datagram went to or came
from (main schema §7.2), so a log shows which of the peer's addresses each packet used, which
diagnosing [#78](https://github.com/c4milo/colibri/issues/78) took captures for. The first
address a connection's log meets is tuple 0, which quic-events §4.7 makes the default, and its
events name none. Each new address takes the next number, and `quic:tuple_assigned` names it,
with the address's bytes and port when it is IPv4 or IPv6 (§4.7, §8.4, §8.5). colibri knows
the peer's half of a tuple alone (`connection_qlog_tuple.zig`).
- 7 tests: 4 in `connection_qlog_tuple.zig`, one in `connection_migration_test.zig`, where a
  server follows its client to a new port and its challenge to the previous path names tuple 0,
  and one each in `qlog/log.zig` and `qlog/quic_event.zig`.
- 7 mutations, each CAUGHT: sent packets and received packets naming no tuple, tuple 0 named,
  a known address numbered again, the newest address let go, IPv4 and IPv6 swapped, and tuple 0
  written as "0".
- The simulator's logs gained one `tuple_assigned` for each endpoint of each seed, and one for
  each move on the rebinding networks. Their datagrams are the same, and Debug and ReleaseSafe
  agree. `tools/qlog_check.py` and the simulator's record check require `tuple_id`, and
  `tools/qlog_to_qvis.py` leaves the event out, since qlog 0.3 has none.
- `tools/quic_udp.sh`: 4 files, 17,346 events, each record a JSON text.

**18c and 18d, the server's connections, 2026-09-28.** `server.Endpoint` takes a log provider in
its config (decision 102 as amended). Once a connection starts, the endpoint asks the provider
for a log with the original destination connection ID, gives it to the QUIC connection and to
h3 through `QuicConnection.attach_log`, and hands it back through `close` when `ended` returns
the connection. The UDP endpoint's `h3` mode fills the provider from a pool of its logs, so the
runner's `http3` cases and `tools/quic_udp.sh`'s h3 mode now leave a server qlog as well.
- 2 tests in `endpoint_test.zig`: a connection's log carries its QUIC and h3 events and comes
  back once the connection is over, and a connection the provider gives no log writes none.
- 5 mutations, each CAUGHT by `zig build test-server`: the provider never asked, the provider
  asked with the client's connection ID, the QUIC connection given no log, h3 given none, and
  the log never handed back.
- `tools/quic_udp.sh`: the h3 mode's connection left 2 files, 8,692 events, each whole.
  `tools/interop.sh` no longer skips the `http3` server's qlog directory: `tools/interop.sh
  quic-go http3` on an Apple M1 Pro passed every pairing, and the 4 qlog directories colibri
  left, its server's two among them, passed `tools/qlog_check.py`.

**18b and 18d, many tokens a call, 2026-09-29.** stdx is pinned at c134f2c, and `qlog` hands
each record's tokens to stdx's `write_items` in lists (decision 102 as amended). `batch.zig`'s
`Batch` has `TextWriter`'s calls, so the event writers changed only the type they name. It
copies each name's, string's and hex string's bytes as it takes them, and writes bytes longer
than its buffer at once.
- Every byte-exact test and the simulator's pinned logs hold, so the records are the same bytes.
  `zig build test` passed 2,327 of 2,327, and so did `tools/quic_udp.sh` and
  `tools/consumer_check.sh`.
- 4 tests in `batch.zig`, and 4 mutations, each CAUGHT by `zig build test-qlog`: bytes not
  copied, a long string written before what came earlier, the copies never freed, and items
  written past their array.
- `zig build test-sim-run-quic` in ReleaseSafe on an Apple M1 Pro, as user CPU time over five
  rounds run side by side: 2.700 s at f647da1, 2.684 s at c134f2c writing one token a call, and
  2.612 s with `write_items`. c134f2c's own speed work was for text outside ASCII, which qlog
  does not write.
