# Design §8 step 20: denial of service at the server

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 110](../../decisions/0110-the-servers-defences-against-denial-of.md) rules the defences that
[#82](https://github.com/c4milo/colibri/issues/82) planned, in three parts.
- **20a**, Rapid Reset (CVE-2023-44487). h2 counts the streams the peer opens and then resets,
  and ends the connection past `peer_reset_rate_max` in one `peer_reset_rate_period_ns`.
  **Check:** unit tests at the limit and across a period, a client whose streams its server
  refuses never ending the connection, and mutations.
- **20b**, the deadlines of decision 110 in `server.Connection`. **Check:** unit tests at each
  deadline's instant, a simulator check with seeded slow and flooding peers and an honest slow
  peer that is never cut, and mutations. It lands in three parts:
  - the first-request, idle and head deadlines, and the calls that run them;
  - the body and send rates, the cap per request, h2's floor on a DATA frame, the linger of a
    close, and 100 concurrent h2 streams;
  - the SETTINGS acknowledgment and drain deadlines, the close reasons, and the test-only server
    taking its instants from Rotor's loop.
- **20c**, the same defences over h3 ([#95](https://github.com/c4milo/colibri/issues/95),
  decision 110 as amended). **Check:** unit tests at the reset limit and at each deadline's
  instant, a simulator check with seeded slow and flooding peers over QUIC and an honest slow
  peer that is never cut, a check over real sockets with aioquic as the slow peer, and
  mutations. It lands in four parts:
  - the reset limit in h3;
  - the first-request, idle and head deadlines in `server.QuicConnection`, and `Deadlines` in
    `server.QuicConfig`;
  - the body and send rates, and the cap per request;
  - drain, the close reasons, `set_deadlines`, and the calls in `docs/usage.md` and an example.

  It adds two public functions to `server.QuicConnection`, which a TCP connection has already:
  `set_deadlines`, for a server short of connections that shortens the deadlines of the ones
  it holds, and `close_reason`, for an operator's log that tells an attack from a limit set
  too tight. `examples/h3_exchange.zig` calls both.
- **20d**, a TLA+ model of the h3 deadlines, `spec/tla/h3_deadlines`, which the owner asked for
  on 2026-10-08. It models one `server.QuicConnection`, an honest client and the application,
  with QUIC's flow control and congestion window, and checks two things:
  - what the server tells the client when it ends the connection on its own: at the close,
    the client knows which requests below the GOAWAY's identifier the server did not take,
    the close waits for the GOAWAY's acknowledgment until the drain deadline passes, and the
    server never counts a reset it asked for;
  - decision 110's rule 2 over QUIC, as `spec/tla/server_deadlines` states it for h2: each
    deadline runs only while the client holds the connection up, checked in the states where
    colibri has no step of its own left.

  **Check:** TLC finds colibri's rules holding, and each earlier rule, and each rule turned
  off, violated. It lands in two parts:
  - the model and its configurations;
  - the simulator's h3 deadline run written as traces of the model, which TLC checks are
    behaviors of it, as `tools/deadline_trace.sh` does for h2.

  The second part logs only what maps one to one, at the owner's ruling of 2026-10-09. colibri
  counts bytes and the model units and packets, its congestion window grows with each
  acknowledgment while the model's is fixed, and its receive windows grow too (decision 49),
  so no run can match the model state for state.
  - A run, `h3_deadline_trace_*.zig`, acts out a seed's plan with the h3 deadline run's peer
    and a `server.Endpoint`, one queue of datagrams each way that loses and reorders nothing.
    The peer sends each request in the model's units: its head in `HeadUnits` pieces and its
    content in `Content`, each in a datagram of its own. The application writes each response
    in `ResponseUnits` calls. The program's shutdown and time are actions too. Time moves only
    while no datagram is in flight, to the instant the endpoint or the client next names, and
    never as far as QUIC's own idle timeout, which the model leaves out.
  - A seed may stop the client inside a head or a body, or the application inside an answer,
    so the head, body and drain deadlines pass. The client does not cancel: after a cancel its
    h3 stops reading the stream, where the model's client still learns the response.
  - After each action the run logs the client's side (what it opened, what it learned of each
    request, the GOAWAY and the close), colibri's (each request's phase, whether the
    application heard of it and waits for its content, what it wrote and reset, the GOAWAY's
    identifier, the shutdown, the close and its reason), and whether each of colibri's clocks
    runs. TLC finds the units, windows and packets in flight that fit, and each clock must run
    exactly when the model's rule says. colibri reads and writes all it can in the action that
    brings it, so each logged state is one where the model's colibri has no step left.
  - The run's windows are wide enough that flow control never binds, as the h3 trace run's
    are, so the credit rules are checked by TLC on the model and by the unit tests. The run
    turns the body rate off, because the meter of all bodies together, which the model leaves
    out, would close the connection; the body cap is the body clock.
  - `zig build sim -- --h3-deadline-trace-check [seeds]` runs it, `--h3-deadline-trace-write
    <directory>` writes each seed's trace as TLA+, and `tools/h3_deadline_trace.sh` has TLC
    check each one against `spec/tla/h3_deadlines/H3DeadlinesTrace.tla`. `tools/ci.sh` runs
    the script.
- **20e**, five changes the owner ruled on 2026-10-17 (decisions 110 and 61 as amended, and
  decision 123). Each lands in a commit of its own:
  - the reset limits as `server.Limits.peer_resets_max` and `resets_sent_max`, which h2 and h3
    read in place of the constants;
  - h3's count of the request streams it refuses, under `resets_sent_max`;
  - `server.Config.retry_from_percent`, the share of QUIC slots in use from which the endpoint
    sends Retry;
  - an index in QUIC's receive pool, so a STREAM frame finds its block in a bounded number of
    probes (RFC 9000 §21.7);
  - skipped packet numbers in QUIC's 1-RTT space, so an ACK of a packet never sent shows an
    optimistic ACK (RFC 9000 §21.4).

  The new fields are for an operator's program. A server behind a proxy that carries many
  users on one connection may need higher reset limits, and a server under attack lower ones
  or Retry. **Check:** unit tests at each limit and one past it, through `Limits` and through
  the endpoint, and mutations.

**Rapid Reset, 2026-09-29.** h2 counts a RST_STREAM that closes a stream the peer opened, in the
period its instant falls in, beside the count of the resets colibri sends. What was checked, on
macOS arm64 with Zig 0.16.0:
- `zig build test`: 128 of 128 steps and 2388 of 2388 tests passed, the simulator's h2 censuses
  unchanged.
- `tools/h2spec.sh 18443 --tls` passed 144 of 146 cases in cleartext and over TLS, skipping
  decision 41's two.
- Mutations, each **CAUGHT**: the peer's resets not counted, every reset counted, the reset at
  the limit refused, one past the limit allowed, the period never starting again, a period
  starting one nanosecond late, and the wrong error code.

**The first-request, idle and head deadlines, 2026-09-29.** The first part of 20b.
- `server.Connection.init` takes the instant the listener accepted the connection, and
  `Config.deadlines` holds each deadline's limit, or null to turn it off. `set_deadlines`
  changes one connection's limits. Both refuse 0, and a limit past `timeout_ns_max`, a day.
- `deadline_ns` reports the soonest instant a deadline passes, and `on_instant` ends the
  connection then. `receive` and `send` end it first when their instant is past a deadline, so
  bytes that arrive late are not read. `timed_out` names the deadline that ended it.
- A silent or idle h11 connection closes with nothing sent, and a head that began and did not
  end gets a 408 with `Connection: close`. h2 sends GOAWAY with NO_ERROR, or with
  ENHANCE_YOUR_CALM for a field block left unfinished.
- Only a request head starts or ends a deadline. An h2 PING does not, and no deadline runs
  while the application holds a request.
- The deadline check (`zig build sim -- --deadline-check`) came first, in a commit of its own.
  Before the deadlines, every hostile peer held the server open until the end of the run. With
  them it also runs a peer that makes one exchange and then sends nothing but PINGs, over 256
  seeds.

What each check printed, on macOS arm64 with Zig 0.16.0:
- `zig build test`: 128 of 128 steps and 2408 of 2408 tests passed.
- The deadline check over 256 seeds: 130 exchanges; 104 connections ended at the first-request
  deadline, 107 at idle and 45 at head, and none held open. Debug and ReleaseSafe print the
  same census.
- 39 mutations, each **CAUGHT** by `zig build test-server` but one: the idle limit raised to
  31 s, which the unit tests read from its constant and the deadline check's census catches.
  - The calls: `receive`, `send` or `on_instant` not ending a connection past its deadline, or
    not noting a wait that began; a deadline passing a nanosecond late; and `deadline_ns`
    reporting the later deadline, or leaving out the head's or the first request's.
  - The limits: `init` or `set_deadlines` not validating them; `init` ignoring
    `Config.deadlines`; the clock starting at 0 rather than at `init`'s instant;
    `set_deadlines` keeping the old limits; and `validate` accepting 0 or a limit past a day,
    or refusing a day.
  - The waits: a request not ending the first-request deadline, or that deadline passing after
    the first request; a head's deadline outliving the head, or restarting at each call; idle
    running before the first request, never starting, or restarting at each call; the idle or
    head deadline never passing; and an unfinished h2 block, a begun h11 head, an h2 connection
    with open streams, or an h11 request being read taken for idle.
  - The actions: a begun h11 head ending without a 408, or an idle h11 connection with one; the
    408 without its reason phrase; an unfinished h2 block ending with NO_ERROR; an idle h2
    connection ending without a GOAWAY; a handshake deadline leaving the connection open; and a
    deadline not stopping the connection.
- The deadline check caught 22 of the 39 by itself. It calls `receive`, `send` and `on_instant`
  at every instant, runs in cleartext, and leaves every limit at its default. So it cannot tell
  which call ended a connection, and it misses the handshake deadline, the checks on limits,
  the reason phrase, and idle running before a first request, which the first-request deadline
  always ends first.

**The body deadlines, 2026-09-29.** The second part of 20b, after the deadline check's new peers.
- From the end of a request's head, or from the 100 (Continue) the request is owed, its body
  must bring `body_rate_min` bytes a second over each window of `rate_window_ns`, the first
  window taking `rate_grace_ns` more, and must end within `body_timeout_ns`. `server.rate.Meter`
  keeps the windows: one that brings its quota ends where the next starts, so a peer cannot bank
  bytes from one window for the next.
- Only a body's own bytes count: in h11 what h11 reads of the body, its framing included, and
  in h2 the data of its DATA frames, without their padding.
- In h11 a body that falls short ends the connection, with a 408 unless its response began. In
  h2 it ends its stream, with a 408 and RST_STREAM with NO_ERROR, or with CANCEL once the
  response began, and the caller reads `cancelled`, whose new `reason` names the deadline. h2
  also meters the bodies together, from the first body that waits until none does, and ends
  the connection with ENHANCE_YOUR_CALM when they fall short.
- The cost: each h2 stream's body keeps the rate on its own. A client that uploads on several
  streams over a slow link, and starves one of them, loses that one. The check's honest uploads
  go one at a time.
- The check gains an honest upload at two to four times the rate, a slow body under it, and a
  long body that keeps twice a shortened rate past a shortened cap. Each run starts at a drawn
  instant, and one plan in four shortens the server's limits.

What each check printed, on macOS arm64 with Zig 0.16.0:
- `zig build test`: 128 of 128 steps and 2428 of 2428 tests passed.
- The deadline check over 256 seeds: 145 exchanges; 67 connections ended at the first-request
  deadline, 137 at idle, 26 at head, 14 for a body's rate and 12 for its cap; 28 h2 streams cut,
  and none held open. Debug and ReleaseSafe print the same census.
- 41 mutations, each **CAUGHT** by `zig build test-server`. Two were **NOT CAUGHT** at first,
  the deadlines running on after h11 closes and a stopped meter counting, and a test now
  catches each.
  - The waits: a body's wait never starting, starting before its 100 (Continue), or starting
    again at each call; h11 or h2 counting no body bytes; a body's end, its trailers, the
    peer's reset or the caller's cancel leaving its deadlines running; and the count of bodies
    that wait left as it was.
  - The bodies together: their meter running with no body, starting again with each body,
    never falling short, or left out of `deadline_ns`, and ending the connection with NO_ERROR.
  - The cap: never passing, passing a nanosecond late, or left out of `deadline_ns`.
  - The rate: never falling short, or its meter left out of `deadline_ns`; a window at its
    quota taken for short, in `check_ns` or in `short`; the next window keeping the last one's
    bytes; two ended windows not short; the meter starting without its grace period; the quota
    rounding down; and `validate` accepting a rate or a grace period of 0.
  - The actions: h2 writing no 408 before a response, or resetting with CANCEL after one; an h2
    stream's deadline owing no `cancelled`, naming the cap for every body deadline, or ending
    the connection; and an h11 body deadline writing no 408.
  - The reasons: an h2 or h3 peer's reset read as a refusal, a refusal read as the peer's
    reset, and a STOP_SENDING read as a refusal.
- The deadline check caught 21 of the 41 by itself. None of its peers sends trailers, cancels,
  holds two bodies at once or waits for a 100, and it leaves the limits valid and reads no
  reason but a deadline's.
- The check's own commit reports three mutations, each **CAUGHT**: `init` ignoring
  `Config.deadlines`, the clock starting at 0, and h2 never crediting its connection window.

**The send deadlines, 2026-09-29.** More of the second part of 20b, after the check's slow
readers and a fix: the idle deadline had started when a response's last bytes went into the
output, not when the peer took them, and cut a peer that read a long response slowly.
- While the connection holds bytes its peer has not taken, the peer must take `send_rate_min`
  bytes a second over each window, as a body brings them. The meter counts what `send` hands
  out and stops when the output is empty. A peer that takes too little ends the connection: h11
  sends nothing more, and h2 queues a GOAWAY with ENHANCE_YOUR_CALM.
- In h2 a stream whose response waits on a flow-control window has a meter of its own, which
  counts what the window lets through. It runs only while the output is empty: a client that
  opens its window once it has read what fills it would otherwise be cut, and while the output
  holds bytes the connection's meter judges the peer. When the stream's meter falls short, the
  stream is reset with CANCEL and the caller reads `cancelled`. When the connection's window is
  the one that holds it, the connection ends with ENHANCE_YOUR_CALM, a code decision 110 left
  open.
- h2 sends no DATA frame shorter than `data_frame_len_min`, 1,024 bytes, unless the window
  holds the whole payload (RFC 9113 §10.5). `server.Config` carries it, the h2 connection takes
  it as a field that is 0 for none, and `DataWritten` now says what held a frame short.
- A connection that has ended with bytes still to send closes once they are out or
  `close_linger_ns` after it ended, whichever comes first.
- A body arrives a unit at a time, an h2 DATA frame or a TLS record of up to 16,384 bytes. A
  peer at twice the minimum rate brings one each window only when the window's quota is half a
  unit or more, as the defaults' 10,240 bytes are. `Deadlines` says so, and the check's stricter
  plans keep to it; an earlier plan whose windows held no whole frame cut an honest upload.

What each check printed, on macOS arm64 with Zig 0.16.0:
- `zig build test`: 128 of 128 steps and 2455 of 2455 tests passed.
- The deadline check over 256 seeds: 141 exchanges; 45 connections ended at the first-request
  deadline, 114 at idle, 14 at head, 5 for a body's rate, 12 for its cap and 66 for the send
  rate; 33 h2 streams cut, and none held open. Debug and ReleaseSafe print the same census.
- 34 mutations, each **CAUGHT** by `zig build test-h2` and `zig build test-server`. Three were
  **NOT CAUGHT** at first, and a test now catches each: a stream held after its window let a
  write through, a stream's meter running while the output holds bytes, and a stream's bytes
  left uncounted.
  - h2's floor: never holding a frame, holding a payload the window holds whole, or holding a
    window at the floor; the connection's window read as the stream's; room read as nothing
    held; and the server setting no floor.
  - The meters: a write a window held not noted; the connection's window noted as the stream's;
    the connection's meter running with an empty output; a running meter starting again at each
    call; `send`'s bytes not counted; the connection's meter never falling short; and
    `deadline_ns` leaving out either meter.
  - The actions: a stream the connection's window holds cancelled rather than ending the
    connection; a held stream never cancelled; a cancelled one owing no `cancelled`, or reset
    with NO_ERROR; and h2 ending a send deadline with NO_ERROR.
  - The linger: never ending, ending a nanosecond late, never starting, ignored by
    `should_close`, or left out of `deadline_ns` once the connection has stopped.
  - The limits and the ends: `validate` accepting a send rate or a linger of 0; and trailers, a
    peer's reset, the caller's cancel or the other deadline leaving a stream's send meter, or its
    body's meter, behind.
- The deadline check caught 23 of the 34 by itself. None of its peers sends trailers, cancels, or
  opens a window a floor at a time, and it leaves the limits valid.
- The check's own commit reports one mutation, **CAUGHT**: idle starting with the output held.

**The SETTINGS deadline, 2026-09-29.** The first piece of 20b's last part. An h2 peer that does
not acknowledge the server's SETTINGS within `settings_timeout_ns`, 10 s, ends its connection
with SETTINGS_TIMEOUT (RFC 9113 §6.5.3): h2 reports the instant with
`Connection.settings_deadline_ns`, and the server's deadlines honour it. The deadline check
found it cutting an honest upload whose acknowledgment arrived behind its own DATA, and the
owner amended decision 110: the SETTINGS clock stops while a request body arrives.
- `zig build test`: 128 of 128 steps and 2458 of 2458 tests passed. The deadline check's census
  did not change, and no connection in it ended at the SETTINGS deadline.
- 8 mutations, each **CAUGHT** by `zig build test-server`: the deadline never passing, passing
  a nanosecond late, or left out of `deadline_ns`; the connection ending with another code; the
  clock not pausing while a body arrives, the pause adding nothing, or the deadline running
  while paused; and h2 reporting no SETTINGS deadline.

**The drain deadline, 2026-09-29.** After the caller's `shutdown`, the requests the connection
holds have `drain_timeout_ns`, 30 s, before it closes. `shutdown` takes no instant, so the drain
runs from the first call after it. When it passes the connection stops: h2's GOAWAY went out
with the shutdown (RFC 9113 §6.8), and h11 says nothing more.
- `zig build test`: 128 of 128 steps and 2460 of 2460 tests passed. The deadline check's census
  did not change, since none of its runs shuts down.
- 6 mutations, each **CAUGHT** by `zig build test-server`: the drain never starting, starting
  again at each call, never passing, or left out of `deadline_ns`; a drain ending as the other
  deadlines do, with a second GOAWAY; and `validate` accepting a drain of 0.

**The floor, as amended, 2026-09-29.** h2spec failed six flow-control cases once the floor was
in: each sets a window of one byte and waits for a DATA frame of one byte. The owner amended
decision 110: the floor applies only while the peer's SETTINGS_INITIAL_WINDOW_SIZE is at least
the floor.
- `tools/h2spec.sh 18443 --tls`: 144 of 146 cases in cleartext and over TLS, the two decision
  41 skips.
- 2 mutations, each **CAUGHT** by `zig build test-h2` or `zig build test-server`: the floor
  ignoring the peer's initial window, and a peer whose initial window is the floor counting as
  small.

**The test-only server's clock, 2026-09-29.** Design §9's server ran each connection on a counter
of a millisecond a step, so no deadline ever passed on a real socket. It now takes the instant
its Rotor loop read at the last tick, as the UDP endpoints do (decision 63), and a tick waits no
longer than the soonest deadline of its connections. `tools/deadlines.sh` runs it in h11 and h2,
and `tools/ci.sh` runs that.
- `tools/deadlines.sh`: half a head cut at 10.00 s, a silent peer at 10.00 s while another
  connection opens halfway, a body too slow at 20.00 s, and an h2 preface alone at 10.00 s.
- `tools/h2spec.sh 18443 --tls`: 144 of 146 cases in each mode. `tools/h2_server_interop.sh
  --tls` and `tools/h11_server_interop.sh --tls`: every request answered.
- 2 mutations, each **CAUGHT** by `tools/deadlines.sh`: the loop never waking a connection at
  its deadline, and a tick waiting Rotor's longest. The default deadlines are multiples of that
  wait, 10 s, so the second is caught only because another connection opens halfway.

**100 concurrent h2 streams, 2026-09-30.** The last piece of 20b's second part. The server
advertises a SETTINGS_MAX_CONCURRENT_STREAMS of `h2_streams_max`, 100, down from h2's 128, and
refuses a stream past it with REFUSED_STREAM (RFC 9113 §5.1.2); `server.Config` lowers it. h2's
`Connection.limit_peer_streams` sets what it advertises and enforces, before its preface.
- `zig build test`: 128 of 128 steps and 2463 of 2463 tests passed. `tools/h2spec.sh 18443
  --tls`: 144 of 146 cases in each mode.
- 5 mutations, each **CAUGHT** by `zig build test-h2` and `zig build test-server`: h2 refusing
  at its table's size rather than the limit, the limit not advertised or not enforced, the
  server setting no limit, and one stream past the limit allowed.
- A peer that opens 110 streams at once joins the deadline check once h2's queue of replies can
  hold a reset for each stream a deadline cuts in one call: 32 fit today.

**The close reasons, 2026-09-30.** The last piece of 20b. An operator cannot tell an attack from
a limit set too tight unless the connection says what ended it
([#82](https://github.com/c4milo/colibri/issues/82)). `server.Connection.close_reason` replaces
`timed_out`: it names the deadline that passed, or the limit the peer passed, and is null after
any other end. h2 records which of its four limits ended a connection with ENHANCE_YOUR_CALM,
and h11 names its one limit, on a run of records that carry no data.
- `zig build test`: 128 of 128 steps and 2479 of 2479 tests passed. The deadline check's
  census did not change.
- 15 mutations, each **CAUGHT** by `zig build test-h2`, `zig build test-server`, `zig build
  test-sim-run` or the deadline check: h2 naming no limit, naming one after an earlier failure,
  keeping the last connection's limit, or naming any of its four limits as another; the server
  naming no limit or no deadline, not reading h2's limits or h11's, or naming every h2 or h11
  failure a limit; and the simulator recording no close reason, or reading a limit as a
  deadline.

**The peer that opens 110 streams, 2026-09-30.** It joins the deadline check now that decision
113 lets a caller reset every stream it holds between two writes. The peer opens 110 streams at
once, each a request whose body never comes. The server refuses the 10 past its 100 with
REFUSED_STREAM. At the end of the first window it cuts the other 100 in one call, each with a
408 and RST_STREAM with NO_ERROR, and the connection closes at the idle deadline.
- `zig build sim -- --deadline-check`, in Debug and in ReleaseSafe: every seed passed, with
  `streams_refused=60` over six runs of the peer and the census CRC-32 `0xa02e1727`.
- `zig build test`: 131 of 131 steps and 2493 of 2493 tests passed.
- 3 mutations, each **CAUGHT** by the deadline check: the server leaving h2's limit at 128, h2
  refusing one stream past the limit too late, and a caller's RST_STREAM put back in the queue of
  `stream_replies_max` slots, which stops on the queue's assertion as before decision 113.

**The deadline model, 2026-09-30** ([#86](https://github.com/c4milo/colibri/issues/86)). The
simulator and h2spec found three rules that broke decision 110's rule 2, a deadline runs only
while colibri waits on the peer, and no model had deadlines to find them.
`spec/tla/server_deadlines` models one h2 server connection, an honest client and an
application. It states rule 2 as four invariants and checks them in the states where colibri has
no step of its own left to take, since its own steps take no time.
- `zig build tla -- spec/tla/server_deadlines/*.cfg`, in about a minute: colibri's rules hold the
  idle, SETTINGS and send invariants over 6,380,329 states. Each rule this step replaced breaks
  one of them: the idle deadline starting once the response is written, the SETTINGS deadline
  running while a body waits, and the floor applied whatever the peer's window.
- Two findings, each kept as a configuration TLC must find violated until it is ruled on:
  - `body_update_held`: a body's deadline runs while the client's window is spent and the
    WINDOW_UPDATE that reopens it waits in colibri's output
    ([#89](https://github.com/c4milo/colibri/issues/89)).
  - `floor_late_update`: the amended floor stalls a client that sends a WINDOW_UPDATE only for
    more credit than its window minus the floor
    ([#90](https://github.com/c4milo/colibri/issues/90)).
- Checking the deadline check's runs against the model is the rest of
  [#86](https://github.com/c4milo/colibri/issues/86).

**The floor after a small increment, 2026-09-30**
([#90](https://github.com/c4milo/colibri/issues/90)). Decision 110's third amendment. h2 notes
a WINDOW_UPDATE whose increment is below `data_frame_len_min`, on the connection or on a stream,
and the floor applies only from then.
- `zig build test`: 131 of 131 steps and 2496 of 2496 tests passed. The deadline check's
  census moved to `0x6d3f1273`, the same in Debug and ReleaseSafe, with every count unchanged:
  one honest slow reader, seed `0x1b`, drains its last response 60 ms later, since colibri now
  sends a short frame the floor held before.
- `zig build tla -- spec/tla/server_deadlines/*.cfg`: `late_update` holds. The first
  amendment's rule is violated, kept as `floor_any_update`, which the model named
  `floor_late_update` before.
- `tools/h2spec.sh 28443 --tls`: 144 of 146 cases in each mode, the two decision 41 skips.
- 7 mutations, each **CAUGHT** by `zig build test-h2` or `zig build test-server`: no increment
  turning the floor on, an increment of the floor turning it on, the floor applied before a small
  increment or whatever the peer's initial window, either reader of WINDOW_UPDATE noting nothing,
  and `init` keeping the last connection's note.

**A body's rate and a held WINDOW_UPDATE, 2026-09-30**
([#89](https://github.com/c4milo/colibri/issues/89)). Decision 110's fourth amendment. h2 says
whether it owes a WINDOW_UPDATE, and the server counts down the bytes its output holds ahead of
the last one it wrote. While either holds one, every body's rate meter and the bodies' shared
meter stop, and they start again with a grace period once the update is out. The cap on a body
keeps running. The count makes a `server.Connection` 8 bytes larger, 306,280 in all, as
`docs/performance.md`'s table says, and the reply queue is read only while a body waits.
- `zig build test`: 131 of 131 steps and 2499 of 2499 tests passed. The deadline check's census
  did not change: none of its runs holds a WINDOW_UPDATE while a body's rate matters.
- `zig build tla -- spec/tla/server_deadlines/*.cfg`: colibri's rules now hold all four
  invariants, and `upload_update_held` holds. The rule before the amendment is violated, kept as
  `body_update_held`.
- 8 mutations, each **CAUGHT** by `zig build test-h2` or `zig build test-server`: an owed
  WINDOW_UPDATE on a stream, or on the connection, not counted; the rate ignoring h2's queue or
  the output; a written WINDOW_UPDATE not tracked, or never counted out; and the shared meter or
  a body's own meter not waiting. The first run found two NOT CAUGHT: the rate ignoring the
  output, and a written WINDOW_UPDATE not tracked. The test checked that the connection ended on
  the send deadline, and not that the body deadline had cut the stream first. It checks both now.

**The deadline model in bytes, 2026-09-30.** A run of colibri's h2 client and server can be
checked against the model only if the model sends what they send
([#86](https://github.com/c4milo/colibri/issues/86)). It now counts bytes as colibri does:
- a frame is a header and its payload, colibri's output holds `OutputLen` bytes and each
  direction `ChannelLen`;
- a DATA frame from colibri is as long as the windows, the floor, the frame size and the room
  allow, as `sendable` has it;
- both endpoints owe their replies as `connection_reply.zig` queues them: SETTINGS
  acknowledgments, one increment for the connection, then the streams' in order;
- the client's preface and both acknowledgments of SETTINGS are frames of their own, and the
  client sends DATA frames of any length its windows allow, or with `MaximalUploads` only the
  longest, as colibri's h2 does.

`zig build tla -- spec/tla/server_deadlines/*.cfg`, in about a minute and a half: colibri's
rules hold the four invariants in two configurations, `colibri`, with two streams at once and
small buffers (7,310,332 states), and `colibri_one_at_a_time`, with larger buffers (1,377,905
states). The five earlier rules are each violated, as before.

**The deadline model against colibri's runs, 2026-09-30**
([#86](https://github.com/c4milo/colibri/issues/86)). The model proves decision 110's rules
only if colibri does what the model says. The simulator's deadline trace run acts out a seed's
plan with colibri's h2 client and a `server.Connection` in cleartext. The client opens up to
three streams, pipelined or one at a time, and the application answers each request with a body
it offers a step at a time. Each action is one step of one side: the client writes or reads a
frame, colibri reads one or hands one out, or the application answers or offers content. After
each action the run offers `write_body` the rest of each response until colibri takes no more,
since one call writes one DATA frame. It then logs the model's variables, read from the two
endpoints and the bytes between them, and whether colibri's SETTINGS, body and send clocks
run. TLC checks that each seed's log is a behavior of the model, that each clock runs as the
model's rules say, and that the model's colibri has no content left to take. A log that stops
early is still a behavior, so the run also requires each seed to end with every exchange
finished and nothing in flight or owed. No run lasts long enough for a deadline to pass, so the
check covers when each clock runs, not when one expires.
- The first run found the model adding a WINDOW_UPDATE's increment on a stream colibri had
  closed. colibri's h2 discards it, which RFC 9113 §6.9 says is no error, and notes no small
  increment from it. The model now does the same at both endpoints.
- TLC evaluated the operator bound to the `Trace` constant again at each reference, so its cost
  per state grew with the log's length. The trace module reads the log through `Logged`, a
  definition TLC evaluates once. On macOS arm64, seed 0's 311 states took 5.6 s, not 90 s.
- `tools/deadline_trace.sh`: 32 of 32 traces are behaviors of the model, in under a minute.
- `zig build tla -- spec/tla/server_deadlines/*.cfg`: the nine configurations give their
  verdicts as before, `colibri` over 7,525,308 states and `colibri_one_at_a_time` over 1,413,735.
- `zig build test`: 131 of 131 steps and 2505 of 2505 tests passed.
- 9 mutations of colibri, each **CAUGHT** by `tools/deadline_trace.sh`. Five break a clock rule,
  and TLC found the rest of the traces behaviors: the SETTINGS clock never pausing (23 of 32), a
  body's rate running while a WINDOW_UPDATE is held (13), the floor applied before a small
  increment (22), the idle clock starting before the output empties (1), and a held stream's
  send meter running while the output holds bytes (17).
- Four more stop or slow colibri:
  - `write_body` taking nothing while the output holds bytes: 1 of 32. Without the check that
    no content is left, **NOT CAUGHT**: 32 of 32.
  - The server writing no reply it owes: the run fails on seed 0, unfinished. Without the check
    that each seed finishes, **NOT CAUGHT**: 32 of 32.
  - h2 writing no SETTINGS acknowledgment: the run fails, unfinished.
  - `sendable` writing nothing when the room is short of a whole frame: the run fails, with more
    frames in flight than `frames_max`.

**The rate meter proved, 2026-09-30** ([#87](https://github.com/c4milo/colibri/issues/87)).
`spec/lean/Colibri/Server/RateMeter.lean` states `rate.zig`'s `Meter` and `deadline.zig`'s
`quota` as colibri computes them. It also states a peer that sends a body in whole units at a
steady rate, each unit arriving at the first nanosecond its last byte is sent. It proves:
- the meter's windows: the first ends a grace period and a window after the start, each later
  one follows the one before, and a window that brought its quota gives way at its end with
  nothing counted, so bytes that arrive at a window's end count in the next one;
- `arrival_lt_iff` and `arrives_in_iff`: `brought`, the bytes a window receives, counts exactly
  the units that arrive in it;
- `never_short_iff`: a peer that sends whole units at twice the rate or more, and starts before
  the grace period ends, brings every window its quota exactly when twice the rate over one
  window is a whole unit or more;
- `half_unit_quota_short` and `half_unit_and_one_enough`: the bound is on the rate times the
  window before the quota rounds it up. At 8,192 bytes a second over windows of 999,999,999
  ns, a window owes half of 16,384 bytes, and a peer at twice the rate can bring the first
  window nothing. A quota of half a unit and one byte always suffices.

The note on `Deadlines` said a quota of half a unit was enough, and now states the proved bound.
The defaults, 10,240 bytes over 10 s, and the simulator's `window_quota_min` of 9,216 bytes are
past it. `src/server/rate_vectors.txt` holds 90 quotas and 404 honest peers. For each peer it
names the first window the proved model leaves short: none for 374, and window 1, 2, 4 or 6 for
30. A test in `deadline.zig` requires `quota` to give each quota. A test in `rate.zig` drives
the meter as the server does, `short` at each arrival and at each instant `check_ns` names, and
requires it to name the same window.
- `zig build lean`: the proofs build, and every vector file is what the definitions give.
- `zig build test`: 131 of 131 steps and 2507 of 2507 tests passed.
- 5 mutations of `rate.zig` and `deadline.zig`, each **CAUGHT** by `zig build test-server`:
  bytes at a window's end counted in that window, the next window starting where `short` is
  called, no grace period, a window after a full one never short, and the quota rounding down.
  Only the new meter test caught the second, because every earlier test called `short` at a
  window's exact end.
- 2 mutations of the Lean definitions stop the proofs, and 1 edit to the vector file is refused
  by `zig build lean`.

**Body rates an honest peer can meet, 2026-09-30.** Decision 110's fifth amendment.
`server.Connection` refuses a `body_rate_min` under the bound that
`spec/lean/Colibri/Server/RateMeter.lean` proves, at `init` and at `set_deadlines`, when its
configuration has TLS or speaks h2 in cleartext (`Config.whole_units`). Twice the rate over one
`rate_window_ns` must be a whole unit or more, where a unit, `body_unit_len`, is a record's or a
DATA frame's 16,384 bytes. `fits_unit` in `deadline.zig` computes the bound. The Lean
`fitsUnit`, which `fitsUnit_iff` proves equal to `never_short_iff`'s condition, gives the same
answer over 110 vectors. In h2 the deadline check's slow-body server now has windows of 32 s,
over which twice its 256 bytes a second is a unit. Every count of its census is unchanged, and
its CRC-32 moved to `0x280860ff` in Debug and ReleaseSafe.
- `zig build test`: 131 of 131 steps and 2513 of 2513 tests passed.
- 7 mutations, each **CAUGHT** by `zig build test-server` or `zig build test-sim-run`: the bound
  itself refused, a peer at the minimum rate rather than twice it, TLS or h2 in cleartext not
  held to units, `init` or `set_deadlines` checking no unit, and the simulator's h2 slow-body
  server keeping its short window. 1 mutation of the Lean `fitsUnit` stops the proofs.

**The floor and the server's timeout in the flow-control model, 2026-09-30**
([#88](https://github.com/c4milo/colibri/issues/88)). `spec/tla/h2_flow_control` sent each DATA
frame as one unit and had no time, so two of decision 110's rules were outside it.
- DATA frames carry lengths. A sender's caller offers `Chunk` units at a time, and a frame
  carries what both windows take of the offer, up to `FrameMax`, as `sendable` has it. The
  server holds a frame while the windows are below `Floor` and do not take the whole offer. It
  holds it only once the peer's initial window is at least the floor and the peer has sent an
  increment below it. The client has no floor. With `FrameMax` of 1 and no floor, every earlier
  configuration that holds explores the states it did before.
- With `ServerTimeout`, the server ends the connection while the channel toward the client stays
  full: its send deadline passes, then its linger. `Finishes` now reads: every exchange
  finishes, or the server ends the connection.
- `zig build tla -- spec/tla/h2_flow_control/*.cfg`: colibri's floor holds with the peer's window
  below it (`floor_small_peer_window`, 504 states) and above it (`floor`, 813 states, and
  `floor_two_streams`, 7,117). The rule before each amendment is violated: the floor whatever the
  peer's window (`floor_small_window`), and the floor after any increment (`floor_any_update`).
  The stall of [#85](https://github.com/c4milo/colibri/issues/85) is violated with no timeout
  (`queue_stall`) and holds with the server's (`queue_stall_timeout`, 137,068 states): the
  server's send deadline ends it. The client has no deadline, so the stall stays open on its side,
  which [#85](https://github.com/c4milo/colibri/issues/85) rules on.
- 144 small configurations of one stream under colibri's floor found no stall: the peer's
  window from 2 to 4 units, the floor 2 or 3, its threshold 1 to 3, offers of 1 to 4 units and
  bodies of 4 or 6.
- 6 mutations of the model, each **CAUGHT** by the new configurations: the floor with no small
  increment, or whatever the peer's window; every increment counted as small; no floor; and the
  server's timeout never enabled, or not fair. The third was **NOT CAUGHT** until `floor` sent a
  body of 7 units rather than 4, long enough for a second round of the window after the floor
  turns on.

**One `write_body` call writes every frame it can, 2026-10-01**
([#91](https://github.com/c4milo/colibri/issues/91)). The deadline trace above found that
`server.Connection.write_body` wrote one DATA frame per call over h2, though its comment says it
writes as much as the room and h2's windows allow. h11's call fills the room, and h3's takes
every byte.
- Over h2 it now calls `write_data` again while the last frame stopped at the peer's
  SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2), and stops at the windows, the room or the content's
  end. `data_frames_per_write_max` bounds the calls: every frame but the last carries 16,384
  bytes at least, and all of them fit the output.
- A test offers content of two whole frames and a byte, and one call takes it as three
  frames, the last with END_STREAM. Another writes an empty last piece, which goes out as an
  empty DATA frame with END_STREAM.
- Three tests assumed one frame per call. Two coded responses now fill the output in one call,
  so each test sends before the next stream's head, as a caller must when `respond` returns
  `NoSpaceLeft`. A send-deadline test now offers one frame's bytes, as its comment says.
- The deadline check's census digest changed: in 2 of its 256 seeds the server's output drains
  226 ms and 69 ms later, and the idle deadline that ends each moves with it. The bytes sent
  and every other count stay the same, and the Debug and ReleaseSafe builds print the same
  census, so `census_crc32_expected` is now `0x9369abbc`.
- `zig build test`: 131 of 131 steps and 2538 of 2538 tests passed.
- 4 mutations, each **CAUGHT**: one frame per call again; each frame offering the content from
  its start; a bound of one frame; and an empty last piece reported as `Blocked`, which was
  **NOT CAUGHT** until the empty-piece test above.

**The reset limit over h3, 2026-10-04** ([#95](https://github.com/c4milo/colibri/issues/95)).
The first part of 20c. QUIC's stream limit bounds how many request streams are open at once,
and nothing bounded how fast a client opens and cancels them.
- `server.QuicConnection` counts a request stream the client opened and then cancelled, in the
  period its latest instant falls in. A client cancels with a RESET_STREAM, which h3 reports
  even before the request's head is whole, or with a STOP_SENDING that stops its response,
  which the connection sees when it settles each response.
- A request cancelled with both frames counts once. One the server cancelled or refused does
  not count: the RESET_STREAM a client owes a STOP_SENDING (RFC 9000 §3.5) is no cancel of
  its own.
- Past `quic_peer_reset_rate_max` in one `quic_peer_reset_rate_period_ns`, which are h2's 100
  and one second, the connection closes with H3_EXCESSIVE_LOAD (RFC 9114 §10.5).
- The connection grows by 16 bytes, to 717,536 (`docs/performance.md`).
- `zig build test`, on 590b3d8: 131 of 131 steps and 2543 of 2543 tests passed.
- 8 mutations, each **CAUGHT**: a RESET_STREAM not counted; a STOP_SENDING not counted; a
  request cancelled with both frames counted twice; one cancel past the limit allowed; the
  cancel at the limit refused; the period never starting again; the period starting one
  nanosecond late; and another error code.

**The first-request, idle and head deadlines over h3, 2026-10-04**
([#95](https://github.com/c4milo/colibri/issues/95)). The second part of 20c.
- `server.QuicConfig` carries `deadlines`, the `Deadlines` a TCP connection takes. A
  connection refuses to start with limits `Deadlines.validate` refuses, and `Endpoint`
  asserts they are valid when it starts: `Endpoint.init` returns no error, and an endpoint
  whose every connection refused to start would answer no client. Whether `init` returns
  `DeadlineInvalid`, as `server.Connection.init` does, changes a public call and is the
  owner's to rule.
- A connection's deadline is the sooner of QUIC's next timer and its own deadlines, and it
  fires each one that passed at `on_instant` and at `receive`. A program that runs QUIC's
  timers through `server.Endpoint`, with its `deadline_ns` and `on_instant`, runs these with
  no new call.
- The first-request deadline counts from the client's first datagram until a whole request
  head arrives, so it covers the handshake. The idle deadline counts from the instant no
  request is open, after the first one. Each closes the connection with H3_NO_ERROR (RFC 9114
  §8.1), and `receive` reports no failure. Before the handshake completes, `quic` sends the
  close as RFC 9000 §10.2.3 has it.
- A request is open from its whole head until its `done` or `cancelled` event. A request
  stream that waits for its head does not stop the idle deadline (decision 110 as amended).
- h3 keeps the instant it first saw each request stream, and `oldest_head_wait` names the
  stream that has waited longest for its head. A look that finds none is not repeated until
  another request stream opens, so a connection whose heads arrive whole walks its request
  streams once for each stream, and not at each call. Past the head deadline the server asks the
  client to stop sending with H3_NO_ERROR, answers 408 (RFC 9110 §15.5.9, RFC 9114 §4.1), and
  the connection goes on. The caller never hears of the request, and the RESET_STREAM the
  client owes the STOP_SENDING (RFC 9000 §3.5) does not count toward the reset limit. With no
  record free for a response, the server resets the stream with H3_REQUEST_REJECTED (RFC
  9114 §4.1.1).
- **Not done: the GOAWAY.** Decision 110 has these deadlines close the connection after a
  GOAWAY, and RFC 9114 §5.2 says a server SHOULD send one when it knows of the close in
  advance. `quic` writes a CONNECTION_CLOSE alone once it owes one (RFC 9000 §10.2.1), so a
  GOAWAY written at the deadline's instant is never sent. `shutdown` on a connection with no
  request open has the same fault. The last part of 20c owns both, with the drain deadline.
- `h3.Connection` grows by 800 bytes, 8 for each of its 100 request streams, to 146,312, and
  `server.QuicConnection` by 960, to 718,496 (`docs/performance.md`).
- `zig build test`, on 590b3d8: 131 of 131 steps and 2555 of 2555 tests passed.
- 34 mutations. 33 were **CAUGHT**: a deadline passing one nanosecond late; the first-request
  deadline never firing, waiting for the handshake, or not ending at a whole head; the idle
  deadline running before the first request, running with a request open, stopped by a
  partial head, restarting at each call, or never firing; a late head with no response, still
  read, reported to the caller, left open with no record free, cancelled where it must be
  rejected, or answered 400; the caller not woken for a late head or for the idle deadline;
  `deadline_ns`, `on_instant` and `receive` each ignoring the connection's deadlines; the
  deadlines running on a stopped connection; a late head's deadline never firing; the close
  carrying H3_INTERNAL_ERROR or sent as a transport close; and nine in h3, a stream's first
  instant not kept, the newest stream named, a stream whose head arrived still waiting, no
  STOP_SENDING sent, a stopped stream still waiting for its head, a stream that opens asking
  for no look, a look that found none repeated at each call, a look that found a stream not
  repeated, and every call walking the streams.
  The STOP_SENDING carrying H3_REQUEST_REJECTED was **NOT CAUGHT** until the late-head test
  read the code the server's stream holds.

**The body and send rates over h3, 2026-10-04**
([#95](https://github.com/c4milo/colibri/issues/95)). The third part of 20c.
- A request's body waits from the call that reads its head until its content or its stream
  ends (`quic_body.zig`). Each body keeps the minimum rate over each window and ends within
  the cap, and the bodies of a connection keep the rate together. Only the data of DATA
  frames counts.
- A body that falls short ends its request alone. With no final response begun, the request
  gets a 408 and the server asks the client to stop with H3_NO_ERROR. With one begun, the
  server resets the stream with H3_REQUEST_CANCELLED. With one ended, the server asks the
  client to stop and the response arrives whole. The caller reads `cancelled`, naming the
  deadline, unless the response had ended. Bodies that together fall short close the
  connection with H3_EXCESSIVE_LOAD.
- A connection refuses to start with a body rate `Deadlines.validate_units` refuses, and
  `Endpoint` asserts its configuration holds none.
- The send meters count the bytes the peer acknowledged (`quic_sends.zig`). The connection
  reads them from each response's stream when it settles its requests, after each datagram.
  A response is busy while it holds bytes its stream's credit covers and the peer has not
  acknowledged, its FIN among them. It is bound while it holds bytes the credit does not
  cover.
- While any response is busy, the peer acknowledges the minimum send rate across the
  responses, or the connection closes with H3_EXCESSIVE_LOAD. That ends a peer that
  acknowledges too little and one that withholds the connection's credit.
- A bound response has a meter of its own, which runs while no other response is busy. Under
  the rate, the server resets its stream with H3_REQUEST_CANCELLED and the caller reads
  `cancelled`. The meter keeps its window while the stream's own credit grows.
- A connection fires the deadlines that passed before it takes a datagram, as it does at
  `receive` and at `on_instant`, so bytes acknowledged after a window's end count in the
  next window.
- Not done: the QUIC server owes no 100 (Continue) of its own (RFC 9110 §10.1.1), so a
  body's wait starts at its head. Over TCP it starts once the 100 is written.
- `server.QuicConnection` grows by 2,632 bytes, to 721,128 (`docs/performance.md`).
- `zig build test`, with the three parts replayed on ecd57e1: 131 of 131 steps and 2592 of
  2592 tests passed.
- `tools/quic_udp.sh`, `tools/h3spec.sh` and `tools/quic_aioquic.sh`, on macOS arm64 before
  the replay: each passed with the default deadlines on.
- 32 mutations of the body deadlines. 29 were **CAUGHT**: a wait never starting; content not
  counted for a body or for the bodies together; the bodies never judged; the cap not kept,
  or one nanosecond late; a body's own rate not judged; the wait not ended by the content's
  end, a reset, the caller's cancel, a refusal, or the end of a request the caller hears of
  no more; a reset in place of the 408; a response that ended reset, or one acknowledged
  cancelled; either STOP_SENDING carrying H3_REQUEST_CANCELLED; the server reading on after
  a 408; no `cancelled` event, or a `done` after it; a coded response keeping its encoder; a
  rate under the unit bound accepted; the caller not woken; no deadline fired; the bodies'
  meter never starting, or running on after the last body; another close code; the cap not
  reported; and the deadline that closed the connection not kept.
  Three were **NOT CAUGHT** until tests were added: a trailer section that arrives before
  its stream's end not ending the wait, and a body's window and the bodies' window each not
  reported to the caller's loop, which the first tests hid because both fell at one instant.
  A 33rd found a line with no effect, which is gone.
- 24 mutations of the send rate. 23 were **CAUGHT**: acknowledged bytes not counted for the
  connection, or for the stream; a response never busy, or never bound; a stream's own bytes
  stopping its meter; a stream's meter running while another response is busy; the
  connection's meter, or a stream's, never judged; another reset code; no `cancelled` event;
  the caller not woken; no deadline fired; the meters never started; the server never looking
  at a response; a record keeping the last response's count; a datagram taken with no window
  judged before it counts; a stream's window, or the connection's, not reported; meters that
  ran not stopped; a FIN alone not making a response busy; bytes past the stream's credit
  making one busy; a stream a send deadline ends still waiting for its body; and another
  close code.
  A reset stream keeping its state was **NOT CAUGHT** until the cancel test kept the stream
  open.
- The mutations of the three parts ran on 590b3d8. The replay on ecd57e1 moved the calls the
  endpoint makes into `quic_connection_internal.zig` and changed no rule.

**The calls of the fourth part, 2026-10-04** ([#95](https://github.com/c4milo/colibri/issues/95)).
- `QuicConnection.set_deadlines` replaces one connection's limits, and refuses what a
  connection refuses at its start. `QuicConnection.close_reason` names the deadline that
  closed a connection, or `Limit.peer_resets` for the reset limit, and is null after any other
  end. Both are on the list in the test of `quic_connection.zig` (decision 115).
- `examples/h3_exchange.zig` sets `QuicConfig.deadlines`, shortens one connection's idle
  deadline with `set_deadlines`, and reads `close_reason` from each connection `ended` hands
  back. docs/usage.md quotes each, and no longer says that nothing bounds a slow h3 peer.
- Decision 110's amendment records the owner's rulings of 2026-10-04: a GOAWAY before a
  close, an error from `Endpoint.init`, and the body and send rates over QUIC as built. The
  first two are not built yet.
- `zig build test`, on 93ced64: 131 of 131 steps and 2593 of 2593 tests passed, and `zig build
  examples` ran all four.
- 7 mutations, each **CAUGHT**: `set_deadlines` keeping the old limits, taking a limit of 0,
  or taking a rate under the unit bound; `close_reason` naming no deadline, or no limit; the
  reset limit not kept as the reason; and a public function added and not listed.

**A GOAWAY before the close, and the drain deadline, 2026-10-04**
([#95](https://github.com/c4milo/colibri/issues/95)). The owner's ruling, in decision 110 as
amended.
- At its first-request or idle deadline a connection whose h3 runs sends a GOAWAY and takes
  no new request. It closes with H3_NO_ERROR once its requests are over and the client has
  acknowledged the GOAWAY. h3's `goaway_acknowledged` says whether the client acknowledged
  every byte of the control stream. `server` calls it, so it is a method of
  `h3.Connection`, the sixteenth on the list in its test (decision 115).
- `shutdown` ends a connection the same way, so a shutdown with no request open now sends
  its GOAWAY before it closes.
- The drain runs from the first call that sees the connection shutting down. When it passes,
  the connection closes with the requests it still holds. `close_reason` names the deadline
  that began the shutdown, or `drain` after the program's own `shutdown`. With `drain_ns`
  null nothing of colibri's bounds the wait for the acknowledgment, and the comment on
  `Deadlines.drain_ns` says so.
- A connection that is shutting down runs no first-request and no idle deadline. One whose
  h3 never started has no stream to send a GOAWAY on, and closes at once (RFC 9000 §10.2.3).
- `server.QuicConnection` grows by 16 bytes, to 721,400 (`docs/performance.md`).
- `zig build test`, on 93ced64: 131 of 131 steps and 2600 of 2600 tests passed.
- `tools/quic_udp.sh`, `tools/h3spec.sh`, `tools/quic_aioquic.sh` and
  `tools/channel_interop.sh`, on macOS arm64: each passed.
- 12 mutations, each **CAUGHT**: the close not waiting for the GOAWAY's acknowledgment; a
  deadline closing at once with no GOAWAY; the drain never firing, not reported, starting
  again at each call, or never starting; a drain a deadline began reported as the reason;
  the idle deadline firing again on a connection shutting down; a connection whose h3 never
  started waiting for a GOAWAY; a shutdown sending no GOAWAY; and in h3, a GOAWAY that
  never went out read as acknowledged, and one read as acknowledged before the peer
  acknowledged it.

**The h3 deadlines over real sockets, 2026-10-04**
([#95](https://github.com/c4milo/colibri/issues/95)).
- `tools/h3_deadlines.sh` runs the test-only h3 server on its loop's clock, and four aioquic
  peers at the default limits (`tools/quic_interop/slow_peer.py`). The server must end each
  within a second after its instant, and not before it. `tools/ci.sh` runs it after
  `tools/deadlines.sh`.
- What it printed on macOS arm64, with a load average over 100:
  - a peer that sends a PING every second and no request: a GOAWAY, then H3_NO_ERROR, after
    10.21 s;
  - half a request's head, after one whole fetch: 408 after 10.01 s, and the connection
    served a later fetch;
  - a head and three bytes of content: 408 after 20.02 s;
  - a peer that acknowledges nothing of a response: H3_EXCESSIVE_LOAD after 20.02 s.
- aioquic reports a close only when its draining period ends, three PTOs after the close
  arrived, and a peer whose datagrams are dropped has a PTO that has grown past a second. So
  the peer reads the close from aioquic's `_close_event`, at the datagram that carried it.
- 5 mutations of the server, each **CAUGHT** by the peer that covers it: the first-request
  deadline never firing; the close not waiting for the GOAWAY's acknowledgment, which the
  silent peer reports as a close with no GOAWAY before it; a late head never answered; a
  body's rate not judged; and the connection's send meter not judged.

**A body's wait and the 100 (Continue), 2026-10-04**
([#95](https://github.com/c4milo/colibri/issues/95)). The owner ruled on 2026-10-04 that h3
adds no code for it.
- Over TCP a body's wait starts once the 100 (Continue) its request is owed is written. Over
  h3 it starts at the request's head, also when a 100 is owed (decision 116, step 17i).
- The connection writes the 100 at its next call after the head, before the next datagram it
  sends, so the two instants are most often one.
- The wait starts before the 100 in two cases. The caller filled the response's 16 runs with
  interim responses before its next call, so the 100 waits for the client to acknowledge one.
  Or the caller made its next call late. The grace period covers both while the caller's
  loop keeps turning.

**A request whose head is unread at a shutdown, 2026-10-04**
([#95](https://github.com/c4milo/colibri/issues/95)). The h3 deadline check, below, found it.
- A connection that shut down while a request stream still waited for its head closed with
  nothing said of that request. The GOAWAY names the first stream the server has not seen,
  so that stream was below it, and its client could not tell whether the server took the
  request.
- When the server sends the GOAWAY, at a deadline or at `shutdown`, it now resets each such
  stream with H3_REQUEST_REJECTED (RFC 9114 §4.1.1), and the client may send the request
  again (decision 110 as amended). The owner has not ruled on it.
- A connection answers each head that is late before its own deadline shuts it down. So a
  head that is late at that instant gets its 408, and only a head that is not late is
  rejected.
- `zig build test-server`, on ae1f066 with the commits before this one: 298 of 298 tests
  passed.
- 5 mutations, each **CAUGHT**: no stream rejected; H3_REQUEST_CANCELLED in place of
  H3_REQUEST_REJECTED; the connection's deadline fired before a late head is answered; the
  oldest unread head rejected alone; and a stream asked to stop but not reset.

**The h3 deadline check, 2026-10-04** ([#95](https://github.com/c4milo/colibri/issues/95)).
- `zig build sim -- --h3-deadline-check [seeds]` runs each seed's plan between a server
  `Endpoint` and a scripted client over QUIC in simulated time, through the calls a program
  makes. `--h3-deadline-seed <hex>` prints one seed's trace. Each seed runs twice and must
  write one trace. `zig build test` runs 256 seeds and pins the CRC-32 of their traces, and
  `tools/ci.sh` runs them in Debug and in ReleaseSafe and compares the two.
- A plan draws one of eighteen peers, decision 110's default limits or stricter ones in one
  plan of four, and how long the application holds each request before it answers, up to
  25 s. The application writes half of its answers to honest peers in two halves, up to 25 s
  apart.
- Five peers are honest, and each must read every response whole:
  - one that makes up to three exchanges at once;
  - one whose request heads arrive in two parts, up to 2 s apart;
  - one that uploads content at two to four times the minimum body rate;
  - one that reads long responses at two to four times the minimum send rate, from streams
    whose credit starts at 8,192 bytes;
  - one behind a link that carries four to eight times the minimum send rate and drops the
    datagrams its queue of eight cannot hold. Its responses stay unacknowledged for whole
    windows, so the connection's send meter judges it at each one.
- Thirteen are slow or flooding, and the server must end each at the instant decision 110
  names:
  - a peer that sends nothing after the handshake, and one that sends only PINGs: a GOAWAY
    at the first-request deadline;
  - a peer that sends only PINGs after one exchange: a GOAWAY at the idle deadline, counted
    from the instant the server reported the response done;
  - a head short of its last byte, the connection's first or one after an exchange: a 408
    at the head deadline, or a reset with H3_REQUEST_REJECTED when the connection's own
    deadline comes first. The connection ends at its own deadline either way;
  - a body under the rate: a 408 at the end of its first window. A body that keeps the rate
    for longer than the cap: a 408 at the cap. The application reads `cancelled` for each,
    naming the deadline;
  - a long response to a peer that reads none of it, or reads far under the rate: a reset
    with H3_REQUEST_CANCELLED at the end of the first window, and `cancelled`;
  - a peer that acknowledges nothing, one that holds an open response with its connection's
    credit, two bodies that bring nothing, and a peer that cancels requests past the reset
    limit: a close with H3_EXCESSIVE_LOAD, whose `close_reason` names the deadline or the
    limit. The flood is closed with the batch that carries its 101st cancelled request.
- A connection that ended one request runs on to its idle deadline, counted from that end.
- The peer must read each GOAWAY at the deadline's instant, and the close must follow with
  H3_NO_ERROR within the 25 ms the peer takes to acknowledge the GOAWAY. A slow link adds the
  time it takes to carry a datagram to each.
- What it printed on macOS arm64, in Debug and in ReleaseSafe: `h3-deadline: seeds=256
  exchanges=129 first_request=34 idle=151 body_rate=15 send_rate=38 peer_resets=18
  requests_cut=78 trace_octets=116332 crc32=0xd51694dc`.
- The slow link dropped 13 to 19 datagrams in each of its 13 seeds, and the server cut none
  of them.
- The check found one fault in the server: the request whose head is unread at a shutdown,
  above.
- Not covered: the application answers only after a request's content has ended, so a
  body's deadline always finds no response begun. The unit tests cover the reset of a
  response that began and the response that ended.
- `zig build test`, on faa6575 with the commits of the fourth part: 131 of 131 steps and
  2644 of 2644 tests passed.
- 31 mutations of the server, each **CAUGHT**:
  - a deadline passing one nanosecond late; the first-request deadline never closing a
    connection; the idle deadline running with a request open, or stopped by an unfinished
    head;
  - a late head never answered, its deadline counted from the connection's start, or the
    caller not woken for it;
  - the close not waiting for the GOAWAY's acknowledgment, or never reading it as
    acknowledged; a shutdown keeping no deadline as its reason;
  - a body's wait never starting, or going on after its content ended; its bytes not
    counted; its own window, or the bodies' together, never judged; the cap one nanosecond
    late, or reported as the rate; a late body's request reset in place of its 408; the
    caller not told of it;
  - the connection's send meter, or a stream's, counting nothing; the connection's meter
    never judged; a stream its credit holds never reset; a response its connection's credit
    holds not waiting on its peer; a response whose end is not written waiting on its peer;
  - the reset limit never closing the connection, letting one more cancelled request
    through, or keeping no reason;
  - no unread head rejected at a shutdown, another code for it, and the connection's
    deadline fired before a late head is answered.
- One of them was **NOT CAUGHT** at first, by the check and by the unit tests: a response
  its connection's credit holds not waiting on its peer. Every answer ended as it was
  written, and the unacknowledged end alone kept the response waiting. `quic_sends_test.zig`
  has the test now, and the check's application leaves that peer's answer open.
- Three parts of the check came from reading the mutations before running them. No honest
  peer kept the connection's send meter running for a whole window, so one is behind the
  slow link. A flood in batches of four could not find the limit's last request, so a plan
  draws the batch, and a batch of one finds it. And the peer says when it read the GOAWAY,
  where the run first read the server's clock.
- The mutations ran in copies of this tree with `zig build sim -- --h3-deadline-check`. One
  is caught when the command fails or prints another CRC, which is what the module's test
  compares.

**The h3 deadline model, 2026-10-08.** The first part of 20d. `spec/tla/h3_deadlines` models
one `server.QuicConnection`, an honest client and the application, with QUIC's credit and
congestion window. Its header says what it leaves out.
- `zig build tla -- spec/tla/h3_deadlines/*.cfg`, on macOS arm64: the fourteen configurations
  give their verdicts in two to three and a half minutes. colibri's rules hold GoawayBeforeClose,
  RejectedUnprocessed and OnlyChosenCounted over 3,304,818 states with two streams and over
  372,018 with bodies and the client's cancels, and SendWaitsOnPeer over 370,167.
- Each earlier rule, and each rule turned off, is violated: a shutdown that leaves an unread
  head unanswered, as before 4b4749c (NothingUnsaid); a close that does not wait for the
  GOAWAY's acknowledgment, as before 76545f7 (GoawayBeforeClose); and a reset on a stream
  colibri abandoned counted toward the limit (OnlyChosenCounted).
- Two findings, each kept as configurations TLC must find violated until it is ruled on:
  - `rejection_lost`: colibri closes once the client acknowledged the GOAWAY, while the
    rejection of a request whose head it had not read is still owed. Once a close is owed,
    colibri's QUIC sends nothing else, so the client never learns that it may send that
    request again. One datagram most often carries the GOAWAY and the rejections together,
    and a datagram that fills, or a lost packet, splits them. With the close also waiting
    for the client's acknowledgment of every RESET_STREAM colibri sent, NothingUnsaid holds
    (`close_after_resets` over 3,125,954 states, and `close_after_resets_cancels`).
  - `credit_held_body`, `credit_held_head` and `credit_held_idle`: a body's clock, a head's
    and the idle clock run while the credit the client needs waits in colibri behind its
    congestion window, which the client's next acknowledgment frees. It is the QUIC form of
    what `spec/tla/server_deadlines` found for h2
    ([#89](https://github.com/c4milo/colibri/issues/89)). With the head, body and idle clocks
    waiting while colibri holds credit, every rule-2 invariant holds (`pause_for_credit`, and
    `pause_for_credit_three` over 2,183,812 states with three streams).
- The first runs let colibri's packets reach the client in any order: 80 million states in
  ten minutes, and still growing. In order, with the close free to pass every packet sent
  before it, each scope finishes in seconds and keeps every case the invariants need.
- Three counterexamples were the model's own, and are fixed. A credit packet carried one
  limit, so the connection's credit took the window from the stream's, where colibri writes
  every limit in one packet. And the head and idle invariants judged a head already on its
  way to colibri.
- Each invariant constrains states the model reaches. A module that extends the model named
  one such state for each, and TLC reached every one. An idle client whose next request
  needs held connection credit is reached only with three streams, which `credit_held_idle`
  runs.
- Next: the simulator's h3 deadline run written as traces of the model, the second part of
  20d.

**The close waits for every reset, 2026-10-08.** Decision 110's seventh amendment, the owner's
ruling on `rejection_lost`.
- `finish_if_drained` also waits until no stream of the connection is in "Reset Sent", which
  `quic.connection_stream_acknowledged.resets_acknowledged` answers from QUIC's stream table.
  It is a new public name of `quic`, and the server calls it.
- The model now parts a datagram's arrival from h3's read of it, as colibri does: `take` hands
  the datagram to QUIC, and h3 reads it at the caller's next `receive`. `settle`, which
  decides the close, runs at both. A server test first found a close coming before h3 read a
  request stream the closing datagram opened, and TLC finds it harmless: that stream is at or
  above the GOAWAY's identifier, which tells the client the server did not take it.
- `zig build tla -- spec/tla/h3_deadlines/*.cfg`: the twelve configurations give their
  verdicts in 3 minutes 37 seconds. colibri's rules hold NothingUnsaid with the other three
  over 8,133,722 states with two streams, and over 774,510 with bodies and the client's
  cancels. `rejection_lost` keeps the rule before this change, violated.
- A test splits the rejection from the GOAWAY with datagrams of 36 bytes and loses the one
  that carries the rejection (`quic_drain_test.zig`). The events the harness keeps moved to
  `quic_seen_test_support.zig`, which leaves room for the two settings the test needs.
- 3 mutations, each **CAUGHT**: the close not waiting for the resets, by the drain test; and a
  reset read as waiting only once acknowledged, and every reset read as acknowledged, by
  `zig build test-quic` and the drain test.
- `zig build test`: 131 of 131 steps and 2646 of 2646 tests passed, the h3 deadline check's
  census unchanged.

**The clocks wait for held credit, 2026-10-09.** Decision 110's seventh amendment, the owner's
ruling on `credit_held_body`, `credit_held_head` and `credit_held_idle`.
- colibri holds credit while QUIC owes a MAX_DATA, MAX_STREAMS or MAX_STREAM_DATA frame it has
  not sent: a new limit worth a frame, or one lost and owed again.
  `quic.connection_flow.credit_owed` answers it, and `flow.Receiver.owes_credit` is the test
  `credit_frame_limit` already made. The server calls it at each `take`, `receive` and
  `on_instant`, and after a `send` while credit is held, so the hold ends at the send that
  carries the credit.
- While credit is held, the body meters stop and the head and idle deadlines do not run. Once
  the credit is out, the meters start again with a grace period, as h2's do, and the head and
  idle deadlines move by the time it was held: one that began during the hold starts at its
  end. h3 moves the instants of the heads it waits for, through `h3.Connection`'s new
  `delay_head_waits`. Both new public names are the server's. The body cap and the
  first-request deadline run on, as the ruling names neither.
- `server.QuicConnection` grows by 16 bytes, to 721,416, for the instant the hold began
  (`docs/performance.md`).
- `zig build tla -- spec/tla/h3_deadlines/*.cfg`: the eleven configurations give their
  verdicts in 2 minutes 55 seconds. colibri's rules hold every rule-2 invariant over 754,135
  states with two streams (`colibri_flow`) and over 4,789,077 with three
  (`colibri_flow_three`). The three `credit_held_*` configurations keep the clocks before this
  change, violated.
- Four tests hold the credit by leaving the server's congestion window no room
  (`quic_deadline_credit_test.zig`): a head whose deadline moves, an idle deadline that moves,
  one that starts once the credit is out, and a body whose meters start again.
- Mutations, by `zig build test-quic`, `test-h3` and `test-server`:
  - 9 of the credit query, each **CAUGHT**: each limit, fresh or lost, not counted; a stream
    past "Recv" counted; the fraction off by one; and a limit that does not rise offered.
  - 15 of the server and of h3, each **CAUGHT**: the credit never observed, or not at a send;
    a wait moved wrongly whether it began before the hold or inside it; the idle or head
    instants not moved; the idle or head deadline reported or fired during a hold; either
    meter running during a hold; the hold restarted at each call; and the first-request
    deadline not reported.
  - 3 **NOT CAUGHT**, which change no behaviour: two skip a fast path, and one moves the
    instant of a request whose head arrived, which nothing reads again.
- `zig build test`: 131 of 131 steps and 2652 of 2652 tests passed, the h3 deadline check's
  census unchanged.

**The h3 deadline trace check, 2026-10-09.** The second part of 20d, which logs only what maps
one to one, at the owner's ruling.
- `zig build sim -- --h3-deadline-trace-check`, on macOS arm64: `seeds=32 states=418 opened=61
  responses=24 timeouts=2 rejected=26 cancelled=0 drained=21 drain_passed=11`. Each seed runs
  twice and goes through the same states.
- `tools/h3_deadline_trace.sh`: 32 of 32 traces are behaviors of the model, in 96 seconds of
  TLC. The largest seed takes 2,744,823 states.
- What the first runs found was the run's mapping, not colibri:
  - h3 forgets a request stream in the call that reads its end, so the run takes a request's
    end from the server's events;
  - colibri frees its records when the connection stops, so the trace compares `bodyWaits`
    only while the connection is open;
  - with nothing of colibri's due, a wait reached QUIC's own idle timeout, so one wait moves
    time 30 seconds at most.
- Matching only states where the model's colibri has no step left cut one seed from 5,781,839
  states to 513,029.
- Clients and applications that stop short are what make deadlines pass: before them, 256
  seeds reached 4 timeouts and 4 drains, and after them 18 and 88.
- 6 mutations of colibri, each **CAUGHT** by `tools/h3_deadline_trace.sh`. TLC finds a trace
  the model cannot reach for a shutdown that leaves unread heads unrejected (10 seeds), a close
  that does not wait for the GOAWAY's acknowledgment (8), an idle clock that runs while a
  request is open (20), and a late head rejected rather than answered with a 408 (1). The run
  fails before TLC for a drain that never starts, whose client never reads the close, and an
  assertion in colibri for a body's wait that goes on after its content ended.
- `zig build test`: 131 of 131 steps and 2654 of 2654 tests passed, the trace run's test among
  them.

**The deadline tables of 20b, read only while in use, 2026-10-11.**
`server.Connection.receive` reads one event a call, and fires the deadlines before it and
observes them after it. Each of the two swept the send table and the body table, 128 entries
each, and each write and each end of a request searched them. A request with no body, whose
response no window holds, has an entry in neither. `Sends` and `Bodies` now count their entries
in use, and a lookup or a sweep that finds none reads no entry. No name or behaviour changed,
and `server.Connection` holds 8 bytes more.

What each check printed:
- The deadline tests read and send through two helpers, and each now requires both tables'
  counts to be what a scan of the entries gives.
- `zig build sim -- --deadline-trace-write` and `--tcp-trace-write` wrote the same bytes
  before and after the change: 64 and 128 files.
- 12 mutations, each **CAUGHT**. In each table: an entry taken but not counted; an entry freed
  but still counted, which only the scan in the tests' helpers sees; and a lookup that reads no
  entry while one is in use. For the bodies: no wait started, no soonest instant named and no
  deadline passed while one body alone waits. For the sends: no meter started, no soonest
  instant named and no deadline passed while one stream alone is held.

The judge, [run 38148866370](https://github.com/c4milo/colibri/actions/runs/38148866370),
measured it against `58e1c20`, in instructions per request, or per connection for the two `one`
inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 36,336 | 25,697 | 0.7072 | 0.7071 | wins in both |
| h2-tls-many | 44,163 | 33,434 | 0.7571 | 0.7570 | wins in both |
| h2-one | 301,430 | 213,404 | 0.7080 | 0.7046 | wins in both |
| h2-tls-one | 7,580,207 | 7,336,792 | 0.9679 | 0.9687 | wins in both |

The server's user instructions fell by 10,629 a request on h2-many and by 89,328 a connection on
h2-one, in the first job. Its system calls rose on the inputs that open many connections: from
16.8 to 21.4 a connection on h2-tls-one in the first job and from 16.4 to 21.6 in the second,
and from 4.5 to 4.7 on h2-one. The simulator's traces did not change, so colibri asks for the
same I/O. The likely cause is a server that ends each tick sooner and so takes more ticks for
the same bytes. No run has checked that.

**The deadline check past its pinned seeds, 2026-10-11.** The check pins seeds `[0, 256)`. Run
over 8,192 seeds it failed at seed `0xffe`, and two more seeds failed after that one was
answered. Each showed the check wrong and colibri right:
- Seed `0xffe`: a slow h2 body brought the bytes that make colibri owe a WINDOW_UPDATE, and
  colibri started the body's rate again with a grace period, as decision 110 says since its
  amendment for a held WINDOW_UPDATE. The check's oracle now does the same.
- Seed `0x1f4c`: a slow reader left the server's output full when a second answer was due.
  `respond` returned `NoSpaceLeft`, which `SendError` answers with "`send`, then call again",
  and the run's application took it for a refusal. It now writes the head once the peer has
  read.
- Seed `0x3be9`: the idle deadline closed the connection while the peer still had bytes of its
  last response to read from the socket, and the run counted the exchange lost. An honest peer
  now reads what the server wrote before it closed.

What each check printed, on macOS arm64:
- `zig build sim -Drelease -- --deadline-check 65536`: every seed passed, with `exchanges=33054
  first_request=11683 idle=28620 head=4650 body_rate=4105 body=2111 send_rate=14367
  streams_cut=8033 streams_refused=20690 held=0` and `crc32=0x4878c63a`. The pinned CRC-32 of
  seeds `[0, 256)` did not change.
- Seven tests pin what no pinned seed reaches: the three seeds; seed `0x16ec`, an h11 body that
  brings as many bytes, whose rate runs on; a window that ends as the update's piece arrives,
  which colibri judges first; a piece due as the body stops, which is never sent; and a peer
  that reads nothing, which has read nothing when the server closes.
- 11 mutations, each **CAUGHT** by a test. Of the oracle: a rate that never starts again, that
  starts again without its grace period, that counts the piece that brought the update, that
  takes the update a piece early, that takes one from a piece due as the body stops, that
  starts again before a window ending at the update is judged, and that starts again in h11.
  Of the application: a head with no room taken for a refusal, and an answer that waits for
  room and still names its due instant, which the run's own assertion stops. Of the run: an
  honest peer that reads nothing after the close, and a hostile peer that reads the rest.

**The deadlines are checked once at each instant, 2026-10-13.** The endpoint calls `receive`
several times at the instant it read, and each call ran `fire` first, which found nothing on
every call but the first. A deadline that starts at an instant passes after it, since every
limit is above 0, and the first call at that instant checked each deadline that started before.
`Clock.checked_ns` holds the instant `fire` last checked, `fire` returns at once at that
instant, and `set_deadlines` forgets it, since a shorter limit can pass at it.
`server.Connection` holds 16 bytes more, and `docs/performance.md` has the three rows that
follow from it.

What each check printed:
- `zig build sim -Drelease -- --deadline-check 65536` printed crc32=0x4878c63a, as main does.
- A new test shortens a limit after a call so that it has passed at that call's instant, and
  requires the next call at that instant to end the connection.
- The four traces wrote the same bytes before and after the change.
- 4 mutations, each **CAUGHT**: `fire` returning at any instant once it has checked one,
  `set_deadlines` keeping the instant, `fire` recording the instant after this one, and `init`
  keeping the instant of the slot's last connection. 2 mutations **NOT CAUGHT**: the instant
  never recorded, which is the old code, and the instant `init` is given recorded, at which no
  deadline passes.

The judge, [run 38342554675](https://github.com/c4milo/colibri/actions/runs/38342554675),
measured it against the commit before it, in instructions per request, or per connection for
the two `one` inputs. The base and the change are the first job's medians:

| Input | Base | Change | Ratio, job 1 | Ratio, job 2 | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| h2-many | 16,497 | 16,019 | 0.9710 | 0.9713 | wins in both |
| h2-tls-many | 24,416 | 24,028 | 0.9841 | 0.9821 | wins in both |
| h2-one | 184,383 | 181,885 | 0.9865 | 0.9836 | wins in both |
| h2-tls-one | 7,280,627 | 7,275,389 | 0.9993 | 0.9992 | within the noise |

No input loses. On h2-many the server's user instructions per request fell by 474 in both jobs,
where the disassembly gave about 480. h2-one wins as well: its user instructions per connection
fell by 2,791 and 2,799, because the endpoint calls a new connection several times at one
instant too.

**20e, part 1: the reset limits in `Limits`, 2026-10-17.** `server.Limits` gained
`peer_resets_max` and `resets_sent_max`, 100 each by default. `h2.Connection` holds both as
fields. Its `init` sets `peer_reset_rate_max` and `rst_stream_rate_max` in them, and a
server's TCP connection sets its `Limits` in them after `init`. A QUIC connection's
configuration carries `peer_resets_max`, which the endpoint copies from its `Limits`.
`h2.Connection` and the connection of each TCP slot hold 8 bytes more, and
`docs/performance.md` has the seven rows that follow from it. Nothing read
`server.constants.quic_peer_reset_rate_max` any more, and the owner ruled on 2026-10-17 to
remove it.

What was checked:
- New tests:
  - h2 ends a connection past limits set after `init`, and not before.
  - A server's h2 connection ends at `Limits.peer_resets_max` and at `Limits.resets_sent_max`,
    and the default `Limits` leave h2's constants in place.
  - An h3 connection ends at its configuration's limit, and an endpoint gives each QUIC
    connection its `Limits.peer_resets_max`.
- `zig build test-h2` passed 385 of 385 tests, and `zig build test-server` 472 of 472.
- 13 mutations, each **CAUGHT**:
  - h2 compares either count with its constant, or lets one reset past the limit;
  - h2's `init` sets another sent limit;
  - the server leaves either h2 limit unset, or sets the peer limit as the sent limit;
  - the endpoint gives QUIC no limit;
  - h3 compares with the default, or lets one cancel past the limit;
  - either default is one lower.

**20e, part 2: h3 counts the request streams it refuses, 2026-10-17.** h3 reports each request
stream it refuses to the server's QUIC connection. The connection now counts each one against
`Limits.resets_sent_max` in one second, whether the caller heard of the request or not. Past
the limit, the connection closes with H3_EXCESSIVE_LOAD, and its close reason names
`resets_sent`. h3 rejects a stream at or above the GOAWAY's identifier without a refusal, so
that stream does not count. The two counters moved into `quic_connection_resets.zig`, because
`quic_connection_h3.zig` would pass 500 lines. The connection of each QUIC slot holds 8 bytes
more, and `docs/performance.md` has the two rows that follow from it.

What was checked:
- New tests:
  - h3 counts each request it refuses after the caller heard of it, and past a limit of 4 it
    closes the connection with H3_EXCESSIVE_LOAD;
  - the same past the default limit of 100;
  - a request stream that ends before a whole head counts too;
  - the count starts again each period, apart from the client's cancels;
  - an endpoint gives each QUIC connection its `Limits.resets_sent_max`.
- `zig build test-server` passed 476 of 476 tests.
- 12 mutations, each **CAUGHT**:
  - no count, or a count of only the refusals the caller heard of;
  - one refusal past the limit, the peer limit in its place, or the count kept with the
    cancels;
  - a period that never starts again, or one that ends one nanosecond late;
  - a close that names no reason, or a flag that is never set;
  - an `init` that keeps a count;
  - an endpoint that gives QUIC no limit, and a default that is one lower.

**20e, part 3: Retry past a share of the QUIC slots, 2026-10-17.** `server.Config` gained
`retry_from_percent`, 0 by default, at most `server.constants.retry_from_percent_max`, which
is 100. With `retry` set, a client that brings no Retry token gets a Retry while at least that
percent of the endpoint's QUIC slots hold a connection. Below the share, its Initial starts a
connection. The endpoint checks a token that a client returns with, whatever the share. The
share counts QUIC slots alone, so TCP connections never send a QUIC client a Retry. No struct
grew.

What was checked:
- New tests:
  - with two QUIC slots, one connection reaches 50 percent and gets the next client a Retry,
    and does not reach 51;
  - at the default of 0, every client gets a Retry, as before;
  - under the share, a client that returns with a Retry token starts from it;
  - TCP connections do not count toward the share, and the share is of the QUIC slots alone.
- `zig build test-server` passed 480 of 480 tests.
- 8 mutations, each **CAUGHT**:
  - a Retry for every client, or for none;
  - a share that must be passed, not reached;
  - TCP slots counted toward the share, or the share taken of every slot;
  - held QUIC slots counted as free ones;
  - a returned token not checked under the share;
  - a default of 50.

**20e, part 4: an index in QUIC's receive pool, 2026-10-17.** Each stream kept its blocks of
the pool in a list in offset order, and each STREAM frame walked the list from its first
block. A peer that leaves the first bytes out and sends one byte into each block of its
window made each frame walk the whole list: up to 1,026 blocks once the window grew to the
default pool of 1 MiB. The pool now holds a bucket for each block, and a block lies in the
bucket its stream and number choose, chained through the field that links free blocks. A
chain holds at most one block of each stream, so a lookup takes at most one probe for each
stream that holds blocks. A stream keeps a count of its blocks, and `release` walks the
buckets for a stream reset with bytes unread. The pool holds 2,560 bytes more at the default
capacity, and `quic.Connection` 16 more for the slice of buckets. `docs/performance.md` has
the seven rows that follow from it.

What was checked:
- New tests:
  - the list, kept in the test as the reference, against the index over 64 seeds of 400
    random writes, reads, peeks, discards and releases on three streams: the same bytes,
    the same ends and the same free blocks after each, and no chain longer than the streams
    that hold blocks;
  - one byte in each block of a window leaves every chain one block long;
  - the first blocks of three streams fall in different buckets;
  - three streams whose first blocks share a bucket each read their own bytes, while the
    middle of the chain goes back first, then its head, then the last block by a release.
- `zig build test-quic` passed 740 of 740 tests, `test-h3` 118 of 118, `test-client` 193 of
  193 and `test-server` 481 of 481.
- 16 mutations, each **CAUGHT**:
  - every stream in the same buckets;
  - a lookup that ignores the stream or the number;
  - a block never linked into its bucket;
  - a removal that drops the rest of its chain, or that empties its bucket at the head;
  - a removed block not given back, or a new block not counted;
  - a read that keeps a block it read to the end, or a discard that gives back one block
    more;
  - a release that keeps the head of a chain, drops the rest of one, removes another
    stream's blocks, or walks the first bucket alone;
  - buckets not emptied at a reset of the pool, and a reset stream's blocks kept.

  A peek that goes on past a gap inside a block is equivalent: its next pass finds the same
  block and copies nothing.

**20e, part 5: skipped packet numbers in QUIC, 2026-10-17.** The 1-RTT space skips one number
after each interval, and an ACK frame that covers the number skipped last closes the connection
with PROTOCOL_VIOLATION (decision 123). The intervals come from one value that the server's or
the client's QUIC connection draws from the program's source at start, the new option
`packet_number_skips` of `quic.Connection`. `quic.Connection` holds 120 bytes more, and
`docs/performance.md` has the six rows that follow from it.

What was checked:
- New tests:
  - a space skips one number after each interval, and takes the intervals in turn from the
    draw's bytes;
  - an ACK frame that covers the skipped number, in its first range or a lower one, at a
    range's start or its end, is refused, and one that leaves it out is not;
  - a space given no draw skips none;
  - the client draws at start, and only its 1-RTT space skips;
  - over h3, a response of about 200 packets passes a skip and reaches colibri's client whole,
    with no PROTOCOL_VIOLATION.
- `zig build test-quic` passed 743 of 743 tests, `test-server` 482 of 482 and `test-client`
  194 of 194.
- Two censuses moved, each the same in Debug and ReleaseSafe:
  - the h3 deadline check's trace CRC-32 stayed 0x9050e8bf, and its wire CRC-32 moved from
    0x942c7916 to 0x99c38067, since the packet numbers changed;
  - the endpoint check's draw at each start moves every later draw. Its counts moved by a few
    (509 done to 508, 476 writable to 469), every property holds and none failed. Its CRC-32s
    moved from 0x560d5625 and 0x5ec49f44 to 0xb14b502f and 0x137ae3c8.
- 14 mutations, each **CAUGHT**:
  - no number skipped, or the skipped number not recorded;
  - an ACK of the skipped number accepted;
  - a range that ends or starts at the number taken as not covering it, or the first range
    checked alone;
  - one byte for every interval, an interval without its floor, the first skip one packet
    late, or each later skip one packet early;
  - a connection that ignores its draw, or that skips in the Handshake space too;
  - a server or a client that passes no draw.
- `tools/ci.sh` found the gap in `tools/quic_udp.sh`: `tools/qlog_check.py` refused a server's
  qlog, whose 1-RTT space skipped packet 177. The owner ruled on 2026-10-17 that the check
  allows a gap of one number in the 1-RTT space, at least `packet_number_skip_interval_min`
  packets after the last one, and no other gap. The check gained a `--test` mode with 7 tests,
  which `tools/quic_udp.sh` runs first. 6 mutations, each **CAUGHT**: any gap of one number
  whatever the interval, a gap in any space, a gap of any size, a count that never starts
  again, an interval that must be passed rather than reached, and packets of every space
  counted toward it.

**`observe`, `fire` and `continue.write` test their fields first, 2026-10-21.** The endpoint calls
`Connection.receive` several times a request, and the program calls `send` once. Each call ran
three pieces of code whose result one or two fields decide. Each piece did work before its test:
- `connection_deadline.observe` called `connection_close.finished`, which reads the protocol,
  before it tested the output. A linger starts only while the output holds bytes (decision
  110). `observe` now tests `output_len` and `linger_since_ns` first, and its new `ended` reads
  the protocol after them.
- `connection_deadline.fire` saved its registers and loaded the stack canary before it returned
  at an instant it had checked. Its test of `checked_ns` is now inline, and
  `fire_at_new_instant` keeps the rest.
- `connection_continue.write` did the same before it returned with no 100 (Continue) owed. Its
  test of `continue_owed` is now inline, and `write_owed_continue` keeps the rest.

`finished` and the functions it calls write nothing, so each linger starts at the same instant
as before. The `unreachable` arms of `finished` run on fewer calls, and on no new one. No name,
struct or byte changed. The owner ruled on 2026-10-20 that the three changes stay on one
branch, in three commits, and that the judge measures them together. Each alone saves less than
the noise.

The estimate comes from a static count of the server's disassembly. `zig build install -Drelease
-Dtarget=aarch64-linux-gnu -Dcpu=neoverse_n2` built `http-server` on `9e9d70e` and on the
change. The count follows one call of `receive` in h11 cleartext at an instant `fire` checked.
The call owes no 100, reads the protocol, reports nothing and leaves the output empty. The count
leaves out `read_protocol`, which differs between the builds only in the values of its errors.

| Part of one call of `receive` | Before | After |
| --- | ---: | ---: |
| `fire`, with its call | 37 | 5 |
| `continue.write`, with its call | 30 | 4 |
| The rest of `receive` | 168 | 181 |
| The end of `observe`, from its drain test, with `finished` | 58 or 66 | 11 |
| All that the count follows | 293 or 301 | 201 |

The two values before are the two h11 paths of `finished`: 39 instructions while the connection
reads or answers a request, and 47 while it is idle. LLVM now inlines
`connection_cleartext.choose` and `connection_tls.handshake` into `receive`. So the rest of
`receive` keeps more values on the stack, and that costs 13 instructions on this path.

So a call of `receive` saves 92 to 100 instructions. In the test server's path of `send`, the
code from the lookup of the slot to `connection_internal.write_owed` fell from 80 instructions
to 25. With `observe`, a call of `send` saves 102 to 110. A call at a new instant saves 38
fewer: the inline test of `fire` runs first, and the assertion of `fire_at_new_instant` tests
the instant again.

A keep-alive request on h11-many makes at least three calls:
- a `receive` that reads the request;
- a `receive` that reports its `done` (decision 103);
- a `send`.

The endpoint makes more calls of `receive` that read nothing, and each of them saves about 100. At three calls, the first at a
new instant, the three changes save about 250 to 280 instructions a request. That is about 0.7%
of the 36,638 instructions a request that step 13d's run measured for h11-many. It is 1.5% to
1.6% of the 17,223 user instructions of that run's first job. Each further call adds about 0.3%
and 0.6%.

On the h2 inputs, `fire` and `continue.write` save the same in each call. The h2 paths of
`finished` for an open connection that owes nothing are about 60 to 70 instructions, so
`observe` saves more there. No count of the calls of an h2 request exists, so this record gives
no estimate a request for h2.

What each check printed, on macOS arm64 unless a line names another machine:
- `zig build test-server` passed 494 of 494 tests. One test and one check are new:
  - in `connection_sends_test.zig`, the peer takes nothing of an h11 response to a request with
    `Connection: close`. `deadline_ns()` names the end of the linger, and the connection closes
    at that instant and not a nanosecond before. `close_reason()` stays null.
  - in `connection_deadline_test.zig`, a shutdown whose requests finish in time runs no
    deadline once the response is out.
- x86_64 Debug: `zig build test-server -Dtarget=x86_64-linux-gnu` built the tests, and an
  `ubuntu:24.04` container for `linux/amd64` ran them. All 494 passed.
- `zig build test-sim-run` passed 87 of 87 tests in Debug and 87 of 87 in ReleaseSafe. So the
  deadline check, the deadline trace run and the TCP trace run kept their pinned censuses.
- `zig build sim -- --deadline-check 4096` printed the same census on `9e9d70e` and on the
  change: 2,037 requests, `crc32=0xd03a1f7e` and `wire_crc32=0x6f330cca`.
- `zig build test` passed.
- 9 mutations of the three changes:
  - `ended` without `finished`: **NOT CAUGHT** before the new test, and **CAUGHT** by it after.
  - `observe` without the test of `output_len`: **CAUGHT** by three tests that existed and by
    the new check.
  - `observe` without the test of `linger_since_ns`: **CAUGHT** by two tests, one of them new.
  - `finished` read first again, the old order: equivalent. It changes the count of
    instructions alone, and every test passed.
  - `set_deadlines` keeps `checked_ns`: **CAUGHT** by the test of a limit shortened after a
    call.
  - The assertion of `fire_at_new_instant` removed: **NOT CAUGHT**. The inline test runs
    first, so no call can make the assertion fail.
  - `fire_at_new_instant` stores no `checked_ns`: **NOT CAUGHT**. It is equivalent, because
    each call then runs the whole check, which adds cost alone.
  - `continue.write` returns false with no 100 owed: **CAUGHT** by 200 tests.
  - `write_owed_continue` called with no 100 owed: **CAUGHT** by 17 tests.

The judge, [run 39631973284](https://github.com/c4milo/colibri/actions/runs/39631973284),
measured `cf421c6` against `9e9d70e` with `--h11`. No input loses past the noise by either count
in either job:
- h2-many wins on the total in both jobs, at 0.9815 and 0.9829, and h2-tls-many at 0.9842 and
  0.9848. Each saves about 280 user instructions a request.
- By the rule docs/performance.md states for the h11 inputs, h11-one wins by its user
  instructions in both jobs, at 0.9694 and 0.9697. It saves 649 and 642 a connection.
- h11-tls-many also wins by its user instructions in both jobs, at 0.9804 and 0.9737.

**A URI byte's class is one table load, 2026-10-25.** Each request checks its target, and its
Host or `:authority`, against RFC 3986's classes. `uri.matches` read each byte through the
reader and tested it against a chain of comparisons. A comptime table for each class now holds
every byte value's answer, and the common case, bytes of the class alone, is one pass over the
slice. A "%" or a refused byte takes the reader's path as before.
- `zig build test-http` passed, with a test that compares each table with the class's rule for
  every byte value.
- 3 mutations, each **CAUGHT**: the fast path accepts a byte outside the class, every class
  built as reg-name, and the reader's path accepts a byte outside the class.

The judge, [run 40228870787](https://github.com/c4milo/colibri/actions/runs/40228870787),
measured `367d432` against `534f297` with `--h11` and `--h3`. No input loses past the noise by
either count in either job:
- h2-many wins on the total in both jobs, at 0.9889 and 0.9895, and h2-tls-many at 0.9894 and
  0.9922. Each saves about 165 user instructions a request.
- By the rule docs/performance.md states for the h11 inputs, h11-one wins by its user
  instructions in both jobs, at 0.9862 and 0.9850. It saves 283 and 308 a connection.

A second change, a 64-bit division for the rate quotas in `deadline.quota`, won no input in
either job of [run 40229115862](https://github.com/c4milo/colibri/actions/runs/40229115862),
and did not land.

**h3's stream lookups and response fills, 2026-10-26.** Three changes, each judged alone against
`9968e85` with `--h3`:
1. `core.slots.Pool` keeps `slot_by_bucket`, the slot each identifier modulo the capacity was
   last written or found in, and `get` checks it before it scans. QUIC's `Streams.lookup` reads
   the watermark before the pool, as h2's does, so a new stream's lookup scans nothing. Each pool
   grows by its capacity in bytes, and the memory table follows.
   - 7 mutations: 5 **CAUGHT**, and 2 **NOT CAUGHT** that are equivalent: `get` with no bucket
     check, and QUIC's old order, which invariant 13 makes give the same answers.
   - [Run 40343779763](https://github.com/c4milo/colibri/actions/runs/40343779763): h3-many wins
     at 0.9618 and 0.9584, about 5,700 and 6,150 user instructions a request. h2-many wins at
     0.9709 and 0.9692, 455 a request, and h2-tls-many at 0.9785 and 0.9756.
2. h3 `respond` declares the 12,288 bytes of rewritten field lines only in `respond_planned`,
   which a coded final response alone calls: the branch of 2026-09-30, held until this judge
   existed, ported. 4 mutations of `quic_coding.plans`, each **CAUGHT**.
   - [Run 40344315015](https://github.com/c4milo/colibri/actions/runs/40344315015): h3-many wins
     at 0.9853 and 0.9794, about 2,250 and 3,050 user instructions a request.
3. `Requests.take` writes a new record through `make_record`, with runtime safety off at the
   owner's ruling of 2026-10-26, so the response pieces' 8 KiB of kept frames and their run table
   stay unfilled. A test runs the pieces over three storage fills and requires the same reads. 3
   mutations of `Pieces.init`, each **CAUGHT**.
   - [Run 40346185767](https://github.com/c4milo/colibri/actions/runs/40346185767): h3-many wins
     at 0.9826 and 0.9837, about 2,350 and 2,150 user instructions a request.

No input loses past the noise in any of the three runs. A fourth change, a QPACK dynamic table of
4,096 bytes that the server advertises with 0 blocked streams, lost on h3-many at 1.1013 and
1.1054 in [run 40346835608](https://github.com/c4milo/colibri/actions/runs/40346835608), and did
not land.

**A closing stream's received blocks, and Huffman decoding, 2026-10-26.** Two changes, each
judged alone against `377a614` with `--h3`:
1. `Incoming.release` gives a closing stream's received blocks back by probing its own block
   numbers, from the block of its read offset up, until it holds none. It walked every bucket of
   the receive pool before. A peer that holds one block at each end of its window still costs
   about as many probes as the pool has buckets, which is what the walk cost.
   - 3 mutations: 1 **CAUGHT**; 1 **NOT CAUGHT** until a test released a stream that had read
     past the pool's size, then **CAUGHT**; and 1 **NOT CAUGHT** that is equivalent: no stop
     once none is held.
   - [Run 40425024722](https://github.com/c4milo/colibri/actions/runs/40425024722): h3-many wins
     at 0.9701 and 0.9726, about 4,000 user instructions a request.
2. `wire.huffman.decode` reads four bits a step through a machine built at comptime from RFC 7541
   Appendix B's table, in `huffman_decode.zig`. The bit decoder stays as `decode_by_bits`, the
   reference: the tests compare the two on every input of one and two bytes, on longer ones,
   and with EOS starting at every bit of a byte.
   - 5 mutations, each **CAUGHT**.
   - [Run 40425796746](https://github.com/c4milo/colibri/actions/runs/40425796746): h3-many wins
     at 0.9759 and 0.9782, about 3,300 and 3,000 user instructions a request, and h2-one at
     0.9796 and 0.9764, about 2,500 a connection. Cycles on h3-many fell 0.3% and 0.5%, inside
     the noise.

No input loses past the noise in either run. A third change, the pool's live flags kept as bits
in 64-bit words, lost on h3-many at 1.0162 and 1.0201 and on h2-many at 1.0128 and 1.0108 in
[run 40425392749](https://github.com/c4milo/colibri/actions/runs/40425392749), and did not land.

**An h3 response's acknowledged end, and a field section's accounting, 2026-10-27.** Two changes,
each judged alone against `069366b` with `--h3`:
1. `settle` reads `acknowledged_end` only when `Pieces.may_release` says a run can go: the first
   run ends within the stream's `acknowledged_len`. The end is never above that count, so no
   other read releases a run. Each read scans every packet in flight, and `settle` runs after
   each datagram.
   - 5 mutations, each **CAUGHT**.
   - [Run 40446126816](https://github.com/c4milo/colibri/actions/runs/40446126816): h3-many wins
     at 0.9438 and 0.9445, about 7,400 and 7,200 user instructions a request.
2. `FieldSection.check_accounting` reads the last line and the limits, not every line. Only
   `init`, `append` and `extend_last` change the sums, each by the bytes it adds, so the sums
   hold by induction. A check of the sums once a section is complete needs a new public name.
   - 4 mutations, each **CAUGHT**.
   - [Run 40446261122](https://github.com/c4milo/colibri/actions/runs/40446261122): h2-many wins
     at 0.9872 in both jobs, about 190 user instructions a request, and h2-tls-many at 0.9890 in
     one job.

No input loses past the noise in either run. A third candidate, a count of the streams that owe
flow-control credit in place of `credit_owed`'s walk, was dropped at the owner's ruling: about
six sites change what the count reads.

**chapulin bbfd316, 2026-10-27.** chapulin keeps each AES traffic key's schedule in its host
objects ([chapulin#205](https://github.com/c4milo/chapulin/issues/205)), so a record does not expand its key again. Its daf336e stores a schedule
only under the session's AES bit, which keeps INV-26. The bump was judged against `eaa59ea`
with `--h3`.
- [Run 40561211242](https://github.com/c4milo/colibri/actions/runs/40561211242): h3-many at
  0.9755 and 0.9906, inside its noise of 5.02% and 4.18%. Every h2 input stays within 0.3%.
- No input wins or loses past the noise. The bump landed for chapulin's fixes, at the owner's
  ruling, and claims no saving.
- The schedules add 480 bytes to a TLS session over TCP and 2,464 to one inside QUIC.
  `server.Endpoint` grows from 40,940,448 to 40,987,552 bytes, as docs/performance.md lists.

**An h11 head scanned in runs, 2026-10-28.** The judge's profile of h11 on e8987edb has no
function that stands out. `message_scan` read a head one byte at a time, though past a
request's method only CR and LF need a check. It now compares `scan_vector_len` bytes at once
to find the next CR or LF, and counts the bytes before it. It was judged against `e8987ed`
with `--h11`, by user instructions (docs/performance.md).
- 6 mutations, each **CAUGHT**.
- [Run 40769901627](https://github.com/c4milo/colibri/actions/runs/40769901627): h11-one wins
  at 0.9799 and 0.9808, about 400 user instructions a connection. h11-many, with a noise of
  5.6% and 5.9%, stays inside it. No input loses.

**A rate's quota in 64 bits, 2026-10-28.** The owner asked for fewer calls on each h11 request.
A request takes about six calls to `receive`, because each call reports one event (decision
119), so fewer calls would change the API. What repeats is `deadline.quota`: about three times a
request, each a 128-bit division through compiler-rt. It now divides in 64 bits, a multiply,
when the product and its rounding fit. Judged against `a61f2d6` with `--h11`:
- 4 mutations, each **CAUGHT**. A fifth, a bound one short, is equivalent: the 128-bit form
  gives the same quota.
- [Run 40782029564](https://github.com/c4milo/colibri/actions/runs/40782029564): h11-one wins
  at 0.9931 and 0.9921, about 140 and 160 user instructions a connection. No input loses.
