# Design §8 step 4: h2 connection and streams, cleartext, prior knowledge

[Design §8, the build plan](../../design.md#8-build-plan)

Frame reader and writer, the two prefaces, settings with the ACK discipline, the stream state
machine, the signed send window and the retroactive settings sweep, GOAWAY, `RST_STREAM`, the
field-block reassembly slot, request and response validation. Push refused per [decision
17](../../decisions/0017-server-push-no.md), priority parsed but never scheduled per [decision
18](../../decisions/0018-priorities-no-to-scheduling-yes-to.md). **Check:** `h2spec` green at the pinned version against the test-only
prior-knowledge cleartext h2 server of §9 — h2spec connects in cleartext unless `-t` is given — with
every skipped case named and justified; `http2jp/http2-frame-test-case`; the step 2 driver checking
[invariants 13 to 16](../../invariants.md#http2) after every step of every seed; fuzzing; mutations.
**This is the largest single step and the first shippable thing.** *Large.*

**Check passed, 2026-09-17.** `zig build test` exits 0 on Zig 0.16.0, macOS 26.6, arm64: 587 tests
pass, the lint scores 1,324 functions with a highest score of 13 against the limit of 15, and
the eleven `tools/lint` rules run clean. `tools/h2spec.sh` prints `146 tests, 144 passed,
0 skipped, 2 failed` against h2spec 2.6.0, and the script names the two: both test RFC 7540
§5.3.1's rule that a stream cannot depend on itself, which RFC 9113 §5.3.2 dropped with the rest
of the priority scheme, leaving §6.3 two rules that colibri does enforce
([decision 41](../../decisions/0041-h2specs-two-self-dependency-cases-are.md)). `h2-frames` prints
`cases=34 normal=12 errors=22 round_trips=12`. The simulator check prints
`connection: seeds=256 passed=195 rejected=61 frames=4670 chunks=9636 trace_octets=588870
crc32=0xe8f7c0b4`, the same number in Debug and `-Drelease`.

- **Connection.** `receive` consumes one frame and returns at most one event, and the frames
  colibri owes are queued in fixed slots that a short buffer never truncates (decision 39). The
  send path writes a response, its DATA under both windows, a RST_STREAM and a graceful GOAWAY
  into the caller's buffer. A connection error queues the GOAWAY and stops the reading; a stream
  error queues a RST_STREAM and the connection goes on (invariant 27).
- **Streams.** The table keeps every closed record until an open needs its slot, which is what
  tells a stream the peer opened and closed from an identifier it never opened: h2spec
  `http2/5.1/12` wants `STREAM_CLOSED` for the first and `http2/5.1.1/2` `PROTOCOL_ERROR` for
  the second, and §5.1 permits both only if the two are distinguished.
- **Field blocks.** Every fragment is passed to the decoder whatever colibri thinks of its stream,
  or the dynamic table would stop matching the peer's (invariant 10, decision 40).
  `representation_len_max` is the longest line the decoder's own limits admit, so it refuses none
  of them.
- **Simulator.** `src/sim/connection_check.zig` drives one connection through the step 2 pipe and
  reads invariants 13 to 16 after every frame it accepts. A seed replays byte for byte and
  chunking changes no verdict, which at this step can fail for the connection's own reasons and
  not only the harness's.
- **Endpoint.** `src/testing/` holds the cleartext server of §9, in two halves: a session with no
  socket in it, which the unit tests drive, and the socket around it. Nothing imports the module
  back, so the library cannot reach that socket.
- **Not built.** TLS, which is step 5, and with it h2spec's `-t` mode. Push stays refused
  (decision 17) and priority parsed and never scheduled (decision 18).

Two hundred and nineteen source mutations were applied over the field-block slot, the message
validators, the stream table, the connection's two paths, the Huffman bound and the simulator
check, each run against the narrowest step that can catch it, and reverted: 215 **CAUGHT** and
four equivalent. The four: two in the stream table that change no answer it gives, one weakening
the check's replay comparison, which two runs of a seed cannot tell apart, and one that makes the
highest identifier the peer opened lag without ever decreasing, which invariant 13 does not
forbid and `zig build test-h2` catches on h2spec's `http2/5.1.1/2` case.

**The client send path, 2026-09-18.** Step 4's check proved the server. The stream table was
written for both roles at the time, but `open_local` was never called from connection code, so a
client could parse a response and had no way to ask for one. `connection/connection_request.zig`
adds `write_request`: it refuses a request §8.3.1 or §8.5 would make malformed before anything
changes, then opens the stream, encodes the section with the pseudo-header fields before the
regular field lines (§8.3), and cuts it into HEADERS and CONTINUATION. This order matters:
§5.1.1 forbids reusing an identifier, so a request refused for its own contents costs no stream.

Two receive-side rules came with it, both on the client path that nothing could reach before. A
client now reads any number of interim responses before the final one (§8.1), which the
`sections_received` marker on the stream record decides; until now the second field section on a
stream was always a trailer section, so a response after a 1xx was refused as malformed. And an
interim response no longer sets the content-length §8.1.1 compares the DATA bytes against.

`zig build test` passes 598 tests on Zig 0.16.0, macOS 26.6, arm64, the lint scores 1,354
functions with a highest score of 13 against the limit of 15, and the simulator check prints the
census the step recorded, unchanged: `crc32=0xe8f7c0b4`. What this does not have is a conformance
suite: h2spec connects to a server, so no suite drives a colibri client, and §9 lists no client
endpoint. Interop in the client direction is step 5's check, which waits on a TLS server.

Thirteen mutations were applied over the new checks, each run against `zig build test-h2` and
reverted. Every one was **CAUGHT**.

| Mutation | Caught by |
|---|---|
| an interim response is marked final | test: "an interim response is not a trailer section, and the final response follows it" |
| any second field section is trailers | same test |
| an interim response sets the content-length | test: "an interim response does not set the content-length the DATA is compared with" |
| the request is validated after the stream opens | test: "each request opens the next odd identifier, and a refused one opens none" |
| a CONNECT request may carry `:path` | test: "a CONNECT request carries :authority alone" |
| an uppercase field name is sent | test: "an uppercase name and a connection-specific line are refused" |
| TE carries any value | same test |
| an empty `:path` is sent | test: "a request without :scheme or :path, or with an empty one, is refused" |
| `:authority` is left out of the block | test: "the block carries the pseudo-header fields, then the regular field lines" |
| `:path` is written before `:method` | same test |
| the regular field lines are left out | same test |
| CONNECT writes a `:scheme` anyway | test: "a CONNECT block carries :method and :authority alone" |
| no stream opens after a GOAWAY the peer sent | test: "no stream opens after a GOAWAY the peer sent" |

**Still not built.** Neither role sends a trailer section. A server may send an interim response
by calling `write_response` twice, and nothing stops it setting END_STREAM on one, which §8.1
forbids.

**The TLA+ model, 2026-09-26** ([#48](https://github.com/c4milo/colibri/issues/48)).
- `347f8e7`: `spec/tla/h2_flow_control` models a colibri client and a colibri server over one
  connection: RFC 9113 §5.1's stream states, §6.9's connection and stream windows, colibri's
  WINDOW_UPDATE threshold and its queue of owed replies, and a peer that changes its
  SETTINGS_INITIAL_WINDOW_SIZE, which may drive a send window negative (§6.9.2). The
  properties: no frame goes out that its stream's state forbids, no window passes its maximum,
  no sender sends on a window that is not positive, and every exchange finishes.
- It found a defect. colibri queued a stream's WINDOW_UPDATE when DATA arrived and wrote it
  later, so it could follow the frame that closed the stream, which §5.1 forbids ("An endpoint
  MUST NOT send frames other than PRIORITY on a closed stream"). `3653d52` drops a stream's owed
  credit once the peer ends its side or either side resets it, since no more DATA comes.
- What `zig build tla` printed, on macOS arm64:
  - holds, as expected: `colibri`, 6463 distinct states; `two_streams`, 572165; `settings`,
    432411;
  - violated, as expected: `update_after_end`, the path the fix closes; `settings_negative`, a
    send window does go negative, so the rule is exercised; `ignore_negative`, a sender that
    sends on a window that is not positive; `threshold_above_window`, a WINDOW_UPDATE threshold
    above the window, which stalls the exchange and is why `window.Receiver` requires the
    window to be at least the threshold.
- The fix's mutations, against `zig build test-h2` alone: 7 **CAUGHT**. h2spec still prints 144
  of 146 in cleartext and over TLS, and the server interop against Go passes.

**The input check, 2026-09-26.** `src/sim/h2_input_check.zig` gives the frame reader inputs
longer than two bytes, as the QPACK and QUIC input checks do
([#53](https://github.com/c4milo/colibri/issues/53)).
- Each input is a stream of frames of all ten types and one of an unknown type, written by
  `h2.frame`'s writers, with values drawn at their bounds or a few inside them half the time.
  What the writers produced must be read whole before it takes up to eight edits.
- The edited stream is read as the connection reads it: the header, the Length against
  SETTINGS_MAX_FRAME_SIZE, then `parse`.
- A refusal must get a verdict of PROTOCOL_ERROR or FRAME_SIZE_ERROR, and a stream error only on
  a stream other than 0 (§5.4.2). An accepted frame must keep every rule its writer asserts.
  Written again, it must keep its type, its stream and its defined flags, and read back the
  same.

`zig build test-sim-run` runs 256 seeds of 128 inputs and pins the census, which Debug and
ReleaseSafe agree on. `zig build sim -- --h2-input-check` prints `seeds=256 taken=6698
incomplete=16496 refused=9574 frames=157943 crc32=0x0d547a5d`. 200,000 seeds, 25.6 million
inputs, ran in ReleaseSafe with no input halted. 20 mutations of the reader, its writers and
`verdict`, all **CAUGHT** by the check alone.

**The connection model and its trace check, 2026-09-27**
([#75](https://github.com/c4milo/colibri/issues/75), [decision 104](../../decisions/0104-an-h2-connection-model-and-a.md)).
- `spec/tla/h2_connection` models a colibri client and server over one connection. It holds each
  stream's state at both endpoints (RFC 9113 §5.1), each message's order in each direction
  (§8.1), RST_STREAM crossing frames in flight (§6.4) and GOAWAY (§6.8). Each rule colibri keeps
  is a constant: `SendInState`, `DataAfterHead`, `OneFinalHead`, `DiscardAfterReset`,
  `IgnoreAboveGoaway` and `NoStreamAfterGoaway`. A configuration that turns one off must find a
  violation.
- `src/sim/h2_trace_check.zig`: a colibri client and server act out a seed's plan over one queue
  of bytes in each direction. The plan draws write calls colibri must refuse as well as ones it
  takes: DATA before a response's head, a head after the final one, a frame after END_STREAM or a
  reset, and a stream after a GOAWAY. After each action, `h2_trace_state.zig` computes the
  model's variables from both endpoints, and the run keeps each state that differs from the one
  before. The run fails a seed on a connection error, a stream error or a stream opened after a
  GOAWAY, so it finds those without TLC.
- `zig build sim -- --h2-trace-write <directory>` writes 64 seeds' states as TLA+ modules and
  TLC configurations. `tools/h2_trace.sh` runs TLC over them with `H2ConnectionTrace.tla`.
  Between two logged states the model takes up to 40 steps, `steps_between_max`. A seed passes
  when TLC reaches its last logged state.
- `c32cabe` fixed the defect that led to the model: `write_data` sent DATA before the response's
  head. The run then found two more:
  - `3fa6e78`: `write_response` set END_STREAM on an interim response. The note "Still not
    built" above names this, and it no longer holds.
  - `9acb1dc`: after a GOAWAY colibri sent, DATA, RST_STREAM or WINDOW_UPDATE on a stream the
    peer initiated above its last stream identifier failed the connection. §6.8 lets the
    GOAWAY's sender ignore those frames, and colibri now does.

What each check printed on macOS arm64:
- `zig build sim -- --h2-trace-check`, in Debug and in ReleaseSafe: `h2-trace: seeds=256
  opened=405 responses=123 resets=169 goaways=196 refused=5422`.
- `tools/h2_trace.sh`: `64 of 64 traces are behaviors of the model`, in 59 seconds. The 64 logs
  hold 570 states. Of the logs, 22 hold an answered request, 4 an interim response, 24 a reset
  and 38 a GOAWAY, 8 of them two. 26 seeds open three streams.
- `zig build tla -- spec/tla/h2_connection/*.cfg`: the three scopes hold, `messages` in 626993
  distinct states, `resets` in 3264 and `goaway` in 1633432. The six configurations that turn a
  rule off are violated.
- 4 mutations of colibri, 4 **CAUGHT**. For each, the run's own checks fail a seed. With those
  checks removed, TLC finds traces that are not behaviors of the model:
  - DATA before the final head: 47 of 64 traces pass;
  - an interim response that ends the stream: 61 of 64 pass;
  - frames above a GOAWAY colibri sent not ignored: 60 of 64 pass;
  - the client opens a stream after a GOAWAY it read: 52 of 64 pass.

**The caller's resets, 2026-09-30** ([decision 113](../../decisions/0113-a-rststream-the-caller-asks-for.md)).
- `reset_stream` pushed its RST_STREAM into the reply queue with no room check, and the push
  asserted a free slot among `stream_replies_max`. Before the fix, six tests stopped on that
  assertion. At a server: 128 resets between two writes, 128 before an open, and 127 before an
  open that must drop the one record it may. Then one reset after the peer's DATA filled the
  queue with WINDOW_UPDATE frames, 128 resets at a client, and 33 cancels through
  `server.Connection.cancel`.
- The reading could not overflow the queue. A DATA frame that owes a WINDOW_UPDATE and then
  breaks its content-length drops that frame before its RST_STREAM is queued, so it takes one
  slot. A test pins the case with one slot left, and `receive` now asserts after each frame that
  it owes at most one reply about one stream. No other frame pushes two.
- `spec/tla/h2_flow_control` models the resets of one endpoint's caller, `Resetter`, and the
  reading's stop for a full queue, `QueueMax`. `resets` checks safety with a one-slot queue,
  `QueueBounded` among it, and `resets_finish` checks that every exchange finishes. With one slot
  and two frames in flight each way, both endpoints can stop reading while both channels are
  full, with resets or without ([#85](https://github.com/c4milo/colibri/issues/85)), so `resets`
  checks no liveness. Three configurations turn a rule off: `reset_in_queue` queues the resets
  with no room checked, `reset_keeps_update` keeps the credit owed on a reset stream, and
  `reset_uncharged` leaves DATA after a reset out of the connection window.
- 18 mutations of colibri, 17 **CAUGHT** and 1 **NOT CAUGHT**:
  - **CAUGHT**: the reset owes nothing; an open drops a record that owes a reset; a HEADERS
    frame never waits for a slot; every frame waits, or a client's HEADERS waits too; an open
    waits with no reset owed, with a free slot, at the peer limit, or while a closed record
    owes nothing; a written reset keeps its mark, or its count; `owe_reset` counts nothing; the
    owed resets go before the queued replies; `has_pending` leaves them out; either reset keeps
    the stream's credit; a reset the reading decides queues its RST_STREAM before it drops the
    credit.
  - **NOT CAUGHT**: the write walks the records when none owes a reset. The walk then writes
    nothing, so no test can tell.

What each check printed on macOS arm64:
- `zig build test`: `128/128 steps succeeded; 2492/2492 tests passed`.
- `tools/h2spec.sh 28443 --tls`: 144 passed and the 2 cases decision 41 names, in cleartext and
  over TLS.
- `tools/h2_trace.sh`: `64 of 64 traces are behaviors of the model`. `tools/client_trace.sh`:
  `67 of 67 traces are behaviors of the model`. `zig build sim -- --h2-trace-check`: the census
  above, unchanged.
- `zig build tla -- spec/tla/h2_flow_control/*.cfg`: `colibri` holds in 6463 distinct states,
  `settings` in 432411 and `two_streams` in 572165, as before, `resets` in 1384220 and
  `resets_finish` in 176219. The seven configurations expected to be violated are.

**The stall check, 2026-09-30** ([#85](https://github.com/c4milo/colibri/issues/85)).
- `src/sim/h2_stall_check.zig` runs a colibri client and a colibri server over a transport that
  holds 1 to 256 KiB each way. Each endpoint is driven as a caller drives h2 (decision 39): it
  reads while `receive` takes frames, writes what it owes when `receive` takes none, and reads on
  only if that fits. It writes what its connection owes before its own frames, as
  `client.Connection` does, or after them, as `server.Connection`'s `respond` and `write_body`
  do. A round in which nothing moves ends a run, and one whose messages did not all arrive is a
  stall.
- Random seeds send bodies of up to 128 KiB on up to 48 streams, and seldom fill a reply queue.
  While an endpoint cannot write, its peer can send it at most the connection window, 65,535
  bytes, which gathers two thresholds' worth of stream credit. Only streams whose credit already
  sits just below the threshold owe more. Aligned seeds make that happen: 40 to 48 streams each
  send one byte short of the threshold first, so the next byte on each owes a WINDOW_UPDATE.
- What `zig build sim -Drelease -- --h2-stall-check 8192` printed, on macOS arm64 in 538
  seconds: 30.9 GB of bodies and 4 stalls. All four are aligned seeds over a transport of 1 KiB
  (two) or 4 KiB (two), with both endpoints writing their own frames first and both reply
  queues full. None of the 6074 runs in which an endpoint writes what it owes first stalled.
  Random seeds filled a queue three times, and each of those runs finished.
- The test runs seeds `[0, 16)`, which finish, and pins seed `0x12c`, which stalls. A stall in
  a run whose endpoints both write what they owe first is a violation, `StalledOwedFirst`.
- 4 mutations of h2, 4 **CAUGHT**. With no stream WINDOW_UPDATE written, no connection
  WINDOW_UPDATE written, or a reading that does not stop for a full queue, both tests fail. A
  queue of 64 fails the check's build, because its aligned seeds open more streams than the
  queue holds.

**The server writes what h2 owes first, 2026-10-01**
([#85](https://github.com/c4milo/colibri/issues/85)). The owner ruled on the stall above in
decision 39 as amended: the transport holds at least 16 KiB each way, and `server.Connection`
writes what h2 owes before its own frames, as `client.Connection` already did.
- h2's `write_replies` writes the queued replies once the preface is out, and `write_pending`
  writes the preface and then calls it, so no reply goes ahead of the preface (RFC 9113 §3.4).
- `server.Connection` calls it before a response's head, DATA, a trailer section and a 100
  (Continue). A WINDOW_UPDATE written there holds a body's rate deadline, as one written in
  `send` does (decision 110 as amended).
- Three tests have the server read a PING and a request in one call, which returns the request
  while the PING's acknowledgment is owed. The acknowledgment must go out before each frame. A
  fourth, in h2, has a connection fail before its preface is out: `write_replies` writes
  nothing, and `write_pending` writes the SETTINGS before the GOAWAY.
- `zig build test`: 131 of 131 steps and 2536 of 2536 tests passed.
- 6 mutations, each **CAUGHT**. Each of the four calls removed fails its test. `write_replies`
  without its preface check fails h2's test. `take_owed` without its note of a WINDOW_UPDATE
  fails decision 110's test of the send deadline.

**The write order in the flow-control model, 2026-10-01**
([#85](https://github.com/c4milo/colibri/issues/85)). The stall check found no stall when an
endpoint writes what it owes first. `spec/tla/h2_flow_control` now checks that order.
- `OwedFirst` names the endpoints that write what they owe before a frame of their own: their
  HEADERS and DATA wait while they owe anything. Every earlier configuration leaves it empty,
  which keeps the order free, and explores the states it did before.
- With every frame one of `ChannelMax` slots, the order changes nothing. Over channels of 2 to
  6 frames and queues of 1 or 2, both orders stall or both finish. A reply then takes as much
  room as a DATA frame, and with both endpoints writing what they owe first, their replies fill
  a channel of two frames (`queue_stall_owed_first_slots`, violated).
- `Weighted` makes the channel count DATA units. A reply takes one unit, a DATA frame its units
  and one for its header, and a DATA frame is cut to the room left, as `sendable` cuts it. Over
  2, 3 and 4 units the free order stalls (`queue_stall_weighted`, violated), and both endpoints
  writing what they owe first finish (`queue_stall_owed_first`, 68,777 states). With the client
  alone doing so, as colibri did before the server's change above, it stalls over 2 and 3 units
  (`queue_stall_client_first`, violated) and finishes over 4. Over 5 units every order
  finishes.
- `ChannelBounded` says the frames in flight never take more room than the channel has.
- `zig build tla -- spec/tla/h2_flow_control/*.cfg`: the 23 configurations give their verdicts,
  the earlier ones over the states they explored before.
- 5 mutations of the model, 4 **CAUGHT** by `queue_stall_owed_first`: no order, an order that
  waits for no stream reply, every frame one unit, and a DATA frame not cut to the room. The
  fifth, an order that waits for no connection increment, is **NOT CAUGHT**, and no
  configuration can catch it: only the queue of stream replies stops the reading, so a
  connection increment written late never stalls.

**The prefaces in the connection model, 2026-09-30**
([#79](https://github.com/c4milo/colibri/issues/79)). `e3126a9` fixed a server that answered a
request read with the client's preface before writing its own SETTINGS, which RFC 9113 §3.4
requires to be the first frame a server sends. The model had no prefaces, so it could not see
that.
- `spec/tla/h2_connection` now starts each endpoint with its preface: the client's 24 bytes and
  its SETTINGS, carried as one frame, and the server's SETTINGS. Each endpoint reads its peer's
  first, and any other frame first is a connection error (§3.4). `PrefaceFirst` is colibri's
  rule: an endpoint writes its preface before any other frame, and before it reads one.
  `NothingBeforePreface` says no frame goes ahead of its sender's preface.
- Two configurations turn the rule off, and each must be violated. In `preface_first` the
  server's response goes ahead of its SETTINGS, and in `preface_read` the client reads that
  response first, a connection error.
- The h2 trace run logs a state before either preface, and shows each preface in flight as the
  model's frame.
- `zig build tla -- spec/tla/h2_connection/*.cfg`: the three scopes hold, `messages` in 821,759
  distinct states, `resets` in 3,970 and `goaway` in 2,193,274. The eight configurations that
  turn a rule off are violated.
- `tools/h2_trace.sh`: 64 of 64 traces are behaviors of the model. `zig build sim --
  --h2-trace-check`: the census above, unchanged.
- `zig build test`: 131 of 131 steps and 2513 of 2513 tests passed.
- 6 mutations, each **CAUGHT**. In the model: the server, or the client, sending before its
  preface; no `NothingBeforePreface`; and no error for a frame read before the peer's preface.
  In the trace run, no preface shown in flight. In h2, the SETTINGS written before the client's
  24 bytes. The fourth was **NOT CAUGHT** while the model dropped a frame read before the
  preface. It now reads it as colibri would without the check.
- A trace through `server.Connection` and `client.Connection`, where e3126a9's defect was, is
  the rest of [#79](https://github.com/c4milo/colibri/issues/79).

**The TCP trace, 2026-09-30** ([#79](https://github.com/c4milo/colibri/issues/79)). The h2
trace drives `h2.Connection` directly and writes each preface first, as h2's contract asks, so
it could not see e3126a9's defect, which was in `server.Connection`.
- `src/sim/tcp_trace_check.zig` has a `client.Connection` and a `server.Connection` act out a
  seed's plan over h2 in cleartext. Each side writes into its own output until its caller calls
  `send`, and a delivery gives the reader every byte in flight at once, as one read from a
  socket does.
- The client's first flight carries its preface, its SETTINGS and one to three requests, and
  the server reads it in one delivery. The server's caller answers some requests the moment the
  server reports them, inside that delivery, which is where e3126a9's server wrote a response
  ahead of its SETTINGS.
- After each action the run computes `spec/tla/h2_connection`'s state from both connections, in
  the h2 trace's `State`, and TLC checks each seed's log as it checks the h2 trace's. A
  connection error, a malformed message, a stream opened after a GOAWAY or a replay that
  differs fails the run without TLC.
- A cancel or a shutdown decides a RST_STREAM or a GOAWAY that h2 writes at the caller's next
  `send`. The model sends either in the step that decides it, so the run has the connection
  write it at once with `write_owed`.
- The client sends its own GOAWAY when it closes after the server's (RFC 9113 §6.8). It names
  stream 0, because colibri's server opens no stream (decision 17), so the log leaves it out as
  it leaves out SETTINGS and PING.
- `zig build sim -- --tcp-trace-check 64`: `seeds=64 states=508 requests=123 responses=76
  refused=5 shut_down=26`. `tools/tcp_trace.sh`: 64 of 64 traces are behaviors of the model.
- 6 mutations, each **CAUGHT**. Three undo e3126a9 a layer at a time. With the server reading
  before it writes its SETTINGS, h2's assertion that nothing goes out before the preface halts
  the run. With that assertion gone too, the client reads the response first and fails the
  connection: `ConnectionFailed` on seed 0. With the client's §3.4 check gone as well, TLC finds
  22 of the 64 traces to be behaviors of the model. Before the server's caller answered on the
  event, the deadline check alone caught the first two, and nothing caught the third.
- The other three: the client and h2 opening a stream after a GOAWAY, `OpenedAfterGoaway` on
  seed 0x1b; the client reading a 103 as its final head, the client's assertion in
  `record_head`; and h2 refusing every response head that ends its stream, `Malformed` on seed
  0.
- TLS, where cocuyo found the defect with the request in the flight of the client's Finished, is
  the rest of [#79](https://github.com/c4milo/colibri/issues/79).

**The TCP trace over TLS, 2026-09-30** ([#79](https://github.com/c4milo/colibri/issues/79)).
cocuyo found e3126a9's defect over TLS, where the client's first flight goes out with its
Finished, and the server reads the request in the call that completes its handshake.
- One seed in two runs over TLS, with the test identity of `src/testing/testdata/` judged at
  its fixed instant and h2 chosen by ALPN. The handshake runs before the first flight: the
  ClientHello one way, the server's flight the other. The first flight then goes out with the
  client's Finished, and the server reads both in one delivery.
- A side's records carry the protocol's bytes sealed, so the run calls `send` twice. The first
  call has no room, so it writes what the connection owes and seals nothing. The run copies the
  plaintext the connection then holds, and the second call seals it.
  `src/sim/tcp_trace_direction.zig` notes where each send ended, in bytes handed out and in
  plaintext. A reader that consumed the records of whole sends has read their plaintext, less
  what it holds unread. A reader stopped inside one send's records fails the run, since the
  run cannot place it.
- Until a side's handshake completes it has no h2 connection, and the model's state for it is
  the initial one.
- `zig build sim -- --tcp-trace-check 64`: `seeds=64 tls=38 states=564 requests=129
  responses=83 refused=3 shut_down=25`. `tools/tcp_trace.sh`: 64 of 64 traces are behaviors of
  the model.
- With every seed over TLS, the three mutations that undo e3126a9 are each **CAUGHT**: by h2's
  assertion, by `ConnectionFailed` on seed 0x4, and by TLC, which finds 25 of the 64 traces to
  be behaviors.
- The six mutations above, again over the mixed seeds, each **CAUGHT**: h2's assertion;
  `ConnectionFailed` on seed 0x4; TLC with 24 of 64; `OpenedAfterGoaway` on seed 0x18; the
  client's assertion in `record_head`; and `Malformed` on seed 0.

**The TCP trace without `write_owed`, 2026-10-04.** After a cancel or a shutdown the run called
each connection's `write_owed`, the one caller that kept those two functions public. It now
calls `send` with no room, which writes what the connection owes and hands out nothing.
- The client's `send` also writes the requests that wait, so a cancel's action can write them
  too, and the census has one state fewer: `seeds=64 tls=38 states=563 requests=129
  responses=83 refused=3 shut_down=25`.
- `tools/tcp_trace.sh`: 64 of 64 traces are behaviors of the model.
- The six mutations are each still **CAUGHT**, the third by TLC with 25 of 64.

**A lookup reads the watermark first, 2026-10-11.** The table keeps closed streams' records, so
once a connection has carried `concurrent_streams_max` streams all 128 slots of its pool are
live. `lookup` scanned them for a record before it read the watermark, for every stream a peer
opened, and a new stream's identifier is above its parity's watermark, where the pool holds no
record (invariant 13). `lookup` reads the watermark first now. It moved to `streams_slot.zig`,
because `streams.zig` was at the file limit.

What each check printed:
- The lookup it replaced stays in the tests as the reference. Two tests require `lookup` to
  find what the reference finds for each identifier of either parity, as a server's table
  fills, refuses a stream, closes and drops records, and in a client's table with a promised
  stream.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write` and `--deadline-trace-write` wrote
  the same bytes before and after the change: 128, 128 and 64 files.
- 4 mutations, each **CAUGHT**: the identifier at its watermark read as idle; an idle
  identifier that names the wrong initiator; an identifier with no record read as idle
  whatever its watermark; and a record at or below the watermark not looked for. A fifth, the
  scan first again, changes no answer, and only the judge sees it.

The judge, [run 38167448104](https://github.com/c4milo/colibri/actions/runs/38167448104),
measured it against `5954c39`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 25,701 | 24,783 | 0.9643 | 0.9643 | wins in both |
| h2-tls-many | 33,456 | 32,530 | 0.9723 | 0.9731 | wins in both |
| h2-one | 212,851 | 213,322 | 1.0022 | 0.9981 | within the noise |
| h2-tls-one | 7,336,367 | 7,338,780 | 1.0003 | 1.0000 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 917 in each job.
The run's base is the commit before design §8 step 21b.6, which moved the test-only server onto
`server.Endpoint` and changed nothing under `src/h2`.

**The pool reads the slot it found last, 2026-10-11.** A frame and its answer look one stream
up several times in a row: `finish`, `sendable` twice, and `transition`'s own assertion three
times. Each `get` scanned the pool from its first slot, and with every slot live a record is
64 slots in on average. The pool of decision 14 now keeps the slot `get` last found or `open`
last wrote, and reads it before it scans. No two live entries hold one identifier, so the slot
is the one the scan would find. QUIC's stream pool is the same type and reads the same way.
No struct grew: the field fits where the pool had padding. The pool's tests moved to
`src/core/slots_test.zig`, because the field took `slots.zig` past the file limit.

What each check printed:
- Two tests hold `get` to a scan from the first slot, for every identifier the test uses and
  with the slot read first on each entry in turn, as entries open and close; and they pin
  which slot is read first after a `get`, an `open`, a `get` that finds nothing and an `init`.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change: 128, 128, 64 and 128
  files.
- 5 mutations, each **CAUGHT**: the slot read first answering for any identifier; a dead slot
  read first still answering; `get`, and `open`, not moving the slot read first; and `init`
  leaving it where the entries before left it.

The judge, [run 38180215123](https://github.com/c4milo/colibri/actions/runs/38180215123),
measured it against `1c80d6b`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 27,727 | 25,371 | 0.9150 | 0.9149 | wins in both |
| h2-tls-many | 35,548 | 33,190 | 0.9337 | 0.9337 | wins in both |
| h2-one | 223,176 | 224,262 | 1.0049 | 1.0039 | within the noise |
| h2-tls-one | 7,325,644 | 7,325,198 | 0.9999 | 1.0000 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 2,355 in each
job. This run's base counts 27,727 instructions a request where run 38167448104 counted 24,783
for the same h2 code: between them step 21b.6 moved the test-only server onto
`server.Endpoint`. The two counts are from different runs, so the difference is not a judged
ratio, and no run has measured that step.

**The closed records wait in close order, 2026-10-11.** The owner ruled for it on 2026-10-11.
An open into a full pool dropped the oldest closed record by sweeping all 128 for the lowest
`closed_at`, and the pool then scanned for that record to close it and scanned again to assert
it gone. A connection that has carried `concurrent_streams_max` streams has a full pool, so
each new stream paid for the three. The table now keeps the slots of its closed records in a
ring, in the order `sequence` gives their closes. `Streams.close` adds a record's slot after
the rest, and `drop_oldest_closed` takes the first record that owes no RST_STREAM (decision
113) and has the pool close it at its slot. The record it drops is the one the sweep chose.
- `core.Pool` gains three calls for h2's table: `index_of`, the slot of an entry; `at`, the
  entry in a slot; and `close_at`, which closes the entry in a slot and asserts on that slot
  alone. `close` keeps its scan and its assertion: QUIC's table still calls it, and the judge
  has no h3 input to measure a change there.
- `assert_counts` now also requires as many closed records in the ring as the pool holds
  records that are neither open nor half-closed.
- `h2.Connection` holds 136 bytes more, the ring's 128 and its two counts, and
  `docs/performance.md` has the six rows that follow from it.

What each check printed:
- The sweep stays in the tests as the reference. One test requires the ring to hold every
  closed record of the pool in close order, and its first record that owes nothing to be the
  one the sweep would drop, through 320 closes: streams closed from the highest identifier
  down, two that owe a RST_STREAM and are passed over, and more closes than the ring has
  places.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change.
- 12 mutations, each **CAUGHT**. Of the ring: a close not added; places that do not go around
  its end; an open that drops the newest; a record that owes a RST_STREAM dropped; the oldest
  forgotten in place of a later one; a dropped record left in the ring; a dropped reset not
  remembered; the first place not moved on; and a table that starts again with the closed
  records it had. Of the pool: `close_at` leaving the slot live, or not counting the entry
  out, and `index_of` naming the next slot.

The judge, [run 38186227224](https://github.com/c4milo/colibri/actions/runs/38186227224),
measured it against `bf3096a`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 25,367 | 19,471 | 0.7675 | 0.7676 | wins in both |
| h2-tls-many | 33,187 | 27,295 | 0.8225 | 0.8225 | wins in both |
| h2-one | 223,129 | 223,296 | 1.0007 | 1.0045 | within the noise |
| h2-tls-one | 7,327,870 | 7,328,398 | 1.0001 | 1.0001 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 5,890 in the
first job and by 5,888 in the second. On h2-one they rose by 107 and by 117 a connection: the
ring is emptied when a connection starts, and each close adds to it.

**`open` scans for a free slot from a lower bound, 2026-10-12.** `Pool.open` looked for the
lowest free slot from the first slot. h2's pool is full once a connection has carried
`concurrent_streams_max` streams, so each new stream passed the live flag of every slot below
the one the table had just freed, 62 of the 128 on average in the judge's exchange. The pool
now keeps `free_from`, a slot no free slot is below. `open` scans from it and leaves it one
past the slot it took, and `close` and `close_at` lower it to the slot they free when that slot
is below it. An open takes the lowest free slot, as before, so the order `iterator` visits is
unchanged (invariant 15). `last_slot` and `free_from` are the narrowest integer that holds
`capacity`, and no struct grew.

What each check printed:
- The scan from the first slot stays in `slots_test.zig` as the reference. Each open of a
  written walk must take the slot the scan names, after closes of the lowest slot, the highest,
  and slots below and above `free_from`, by identifier and by slot. Two tests pin `free_from`
  itself, because one left too low changes no slot.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change.
- 11 mutations, each **CAUGHT**. Of `open`: `free_from` left on the slot it took, moved two
  past it, not moved, moved by one whichever slot it took, or moved only when it took the slot
  there. Of `close` and of `close_at`: `free_from` not lowered, or moved to the freed slot when
  that slot is higher. And `init` leaving it, and the scan starting one past it.
- 1 mutation **NOT CAUGHT**: the scan from the first slot, which is the code before the change.
  It takes the same slots, and nothing a test reads tells the two apart.

The judge, [run 38201625077](https://github.com/c4milo/colibri/actions/runs/38201625077),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians. The judge measured the
commit before its review, which differs from this one in tests and comments alone.

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 17,805 | 17,561 | 0.9863 | 0.9862 | wins in both |
| h2-tls-many | 25,691 | 25,416 | 0.9893 | 0.9906 | wins in both |
| h2-one | 222,457 | 222,434 | 0.9999 | 0.9985 | within the noise |
| h2-tls-one | 7,330,709 | 7,330,565 | 1.0000 | 1.0001 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 243 in both
jobs. The estimate from the disassembly was 790: it counted 13 instructions for each flag
passed, and the judge's count is about 4. `free_from` stays one past the slot last taken while
the pool is full, so a table whose streams close out of slot order still passes the live flags
between that slot and the one freed. The judge's exchange closes streams in slot order and
does not measure that.

**`init` leaves the send block's bytes, 2026-10-12.** `Connection.init` zeroed `send_block`,
32,768 bytes, for each connection. The block is scratch: `encode_response`, `encode_trailers`
and `encode_request` each start a writer at its first byte and read only what that writer
wrote. `init` no longer writes it.

What each check printed:
- The disassembly of the server `bench/run.sh` builds no longer calls `memset` over the block
  where an h2 connection starts.
- `zig build sim -- --h2-trace-write`, `--tcp-trace-write`, `--deadline-trace-write` and
  `--h3-trace-write` wrote the same bytes before and after the change.
- The change removes a store and alters no check, so no mutation applies to it.

The judge, [run 38201630221](https://github.com/c4milo/colibri/actions/runs/38201630221),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians.

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-one | 192,411 | 185,401 | 0.9636 | 0.9604 | wins in both |
| h2-tls-one | 7,293,475 | 7,286,634 | 0.9991 | 0.9990 | within the noise |
| h2-many | 16,863 | 16,853 | 0.9994 | 0.9997 | within the noise |
| h2-tls-many | 24,754 | 24,774 | 1.0008 | 1.0003 | within the noise |

No input loses. On h2-one the server's user instructions per connection fell by 7,165 in the
first job and by 7,220 in the second, where the disassembly gave 7,193.
