# Decision 110: The server's defences against denial of service: Rapid Reset first, then deadlines

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-29 for [#82](https://github.com/c4milo/colibri/issues/82), on the
proposal in that issue. colibri reads no clock, so it closed no connection on time, and h2 counted
no stream the peer reset.
- **Rapid Reset first.** h2 counts the streams the peer opened and then reset in each
  `peer_reset_rate_period_ns`. Past `peer_reset_rate_max`, 100 a second, it ends the
  connection with GOAWAY and ENHANCE_YOUR_CALM (RFC 9113 §10.5). Only a stream the peer
  opened counts: a server that refuses a client's streams costs the client no work it did not
  ask for.
- **Seven deadlines in `server.Connection`**, reported by `deadline_ns()` and fired by
  `on_instant(now_ns)`, as `server.Endpoint` does for QUIC. They are the first request (the
  TLS handshake and the first whole request head), idle (between requests), head (fixed from
  a head's first byte), body and send (a minimum rate over a window after a grace period,
  with a total cap per request), h2's SETTINGS acknowledgment, and drain (after
  `shutdown()`). Only request bytes count as progress, and a deadline pauses while colibri
  waits on the application. h2 keeps them per stream and checks a minimum rate across the
  connection.
- **What each does.** An idle or silent connection closes without a response, and h2 sends
  GOAWAY with NO_ERROR first (RFC 9112 §9.5, RFC 9113 §9.1). A slow head or body before a
  response gets 408 (RFC 9110 §15.5.9). An unfinished h2 field block ends the connection with
  ENHANCE_YOUR_CALM. A stall after a response started closes, and h2 resets the stream with
  CANCEL. The SETTINGS deadline is a connection error of SETTINGS_TIMEOUT. `close_linger_ns`
  bounds every close.
- **The defaults**, each a named limit `server.Config` carries: first request 10 s, idle
  30 s, head 10 s, grace and window 10 s each, 1,024 bytes a second for body and send, a
  300 s cap per request, a floor of 1,024 bytes on a DATA frame, drain 30 s, linger 2 s, and
  100 concurrent h2 streams, down from 128.
- **One control.** A caller may change one connection's limits at any time. Null turns a
  deadline off, and 0 is refused.

The idle default stays at 30 s, ruled by the owner on 2026-11-16, and docs/usage.md tells a
program to set `idle_ns` above its h11 clients' idle time. connect-zig's conformance server
set 1 s, and Go's client, which keeps an idle connection for 90 s, sent a request on a
connection at the instant the server closed it and read end-of-file. With 50 ms each run
failed about 200 cases, and with 120 s none failed. The alternative refused: a default of
120 s, above Go's 90 s, which holds each idle connection's slot up to four times longer.

The alternatives refused:
- For Rapid Reset: a limit on the share of its opened streams the peer resets, and building
  it together with the deadlines.
- For the deadlines: a recipe of timeouts for each caller to write, and per-stream deadlines
  without the check across a connection.
- For what each does: closing silently at every deadline.
- For the defaults: a gentler set (idle 60 s, 512 bytes a second, 128 streams) and a
  stricter one (idle 15 s, 2,048 bytes a second, 64 streams).
- For the controls: `idle_since_ns()`, which would let a full server close its longest-idle
  connection, and raising one request's cap after its head.

Cost: a deadline bounds how long an attacker holds a connection, not how many connections it
holds, so per-source limits stay the caller's. The deadlines land in design §8 step 20b.

Amended by the owner on 2026-09-29: the SETTINGS deadline waits while a request body arrives.
The deadline check found an honest h2 upload at 2.5 KB/s cut at 10 s: the client had queued
64 KB of DATA before it read the server's SETTINGS, and its acknowledgment arrived behind
them. The SETTINGS clock stops while any body waits and resumes when none does, so a peer
that never acknowledges is still cut, later by the time it spent uploading. The owner ruled
for waiting; a pause, rather than an overdue acknowledgment passing the moment the last body
ends, keeps the acknowledgment one piece behind that body from being cut. Refused: a longer
timeout, which a slower upload still outlasts; dropping the deadline, which RFC 9113 §6.5.3
leaves to the server; and keeping 10 s as ruled.

Amended again by the owner on 2026-09-29: the floor on a DATA frame applies only while the
peer's SETTINGS_INITIAL_WINDOW_SIZE is at least the floor. h2spec's flow-control cases set a
window of one byte and wait for a DATA frame of one byte, which the floor never sent, and a
client whose windows stay under the floor would stall the same way and be cut. A peer that
asks for small windows gets frames that fit them, and the send-rate deadline bounds one that
opens its window a few bytes at a time. Refused: dropping the floor, keeping it and skipping
the six cases, and turning it off for h2spec alone.

Amended a third time by the owner on 2026-09-30: the floor applies only once the peer has
sent a WINDOW_UPDATE whose increment is below it. `spec/tla/server_deadlines` found a client
the floor still stalled: one that sends a WINDOW_UPDATE only once it has more credit than its
window less the floor, which RFC 9113 allows. colibri held the last bytes of the window, the
client never reached its threshold, and the send deadline cut it
([#90](https://github.com/c4milo/colibri/issues/90)). The floor defends against the tiny
increments RFC 9113 §10.5 warns of, so one of them now turns it on, and a peer that gives
credit back in pieces of the floor or more never meets it. Refused: keeping the rule and
documenting the clients it stalls, and removing the floor, which leaves the send deadline
alone against many tiny frames.

Amended a fourth time by the owner on 2026-09-30: a request body's rate waits while colibri
holds a WINDOW_UPDATE its peer has not been handed, owed or in the output, and starts again
with a grace period once the update is out. `spec/tla/server_deadlines` found the overlap the
first amendment removed for SETTINGS: a client whose window is spent waits for that
WINDOW_UPDATE behind whatever the output holds, so its upload waits on its reading, which the
send deadline already judges. A client that uploads while it reads a large response at the
minimum rate could have its body cut ([#89](https://github.com/c4milo/colibri/issues/89)).
The cap on a body does not wait. Refused: writing owed WINDOW_UPDATE frames ahead of the DATA
the output holds, which shortens the wait but leaves the kernel's buffers ahead of the update,
and keeping the rule with a note that a client must read to go on uploading.

Amended a fifth time by the owner on 2026-09-30: a server whose bodies arrive in units refuses
a body rate an honest peer can fall short of. `spec/lean/Colibri/Server/RateMeter.lean` proves
the exact bound ([#87](https://github.com/c4milo/colibri/issues/87)). Take a peer that sends
whole units at twice the minimum rate or more and starts before the grace period ends. It never
falls short in a window exactly when twice the rate over one window is a whole unit or more.
Over TLS a body arrives a record at a time, and in h2 a DATA frame at a time, each of up to
16,384 bytes (RFC 9846 §5.1, RFC 9113 §4.2). So `server.Connection` refuses a `body_rate_min`
under the bound, at `init` and at `set_deadlines`, when its configuration has TLS or speaks h2
in cleartext. An h11 connection in cleartext reads a body byte by byte and keeps any rate.
The defaults, 1,024 bytes a second over 10 s windows, pass. The send rate is unchanged: the
proof is about a peer that sends, not one that reads. Refused: refusing in
`Deadlines.validate`, which cannot see the protocol and would refuse h11 in cleartext too; and
accepting such limits with the bound in a note.

Amended a sixth time by the owner on 2026-10-04, for
[#95](https://github.com/c4milo/colibri/issues/95): h3 gets the defences too. The QUIC
server ran QUIC's loss, idle and closing timers alone. A peer keeps a QUIC connection alive
with a PING, so it held request streams with no limit in time, and RFC 9000 §21.6 names a
minimum transfer speed among the mitigations a deployment SHOULD provide. A caller now has
the same limits whichever protocol carries a request.
- **The reset limit first.** The QUIC server counts the request streams the client opens
  and then cancels in each period, with h2's limit of 100 a second. Past it, the connection
  closes with H3_EXCESSIVE_LOAD (RFC 9114 §10.5). A client cancels with a RESET_STREAM or
  with a STOP_SENDING that stops its response (RFC 9114 §4.1.1), and a request cancelled
  with both counts once. A request the server cancels or refuses does not count.
- **The deadlines in `server.QuicConnection`**, from the `Deadlines` that `server.QuicConfig`
  carries, reported and fired by the calls that already run QUIC's timers. First request,
  idle and drain close the connection with H3_NO_ERROR after a GOAWAY (RFC 9114 §5.2). Head,
  body rate and the cap answer one request with a 408 and stop reading it with H3_NO_ERROR
  (RFC 9114 §4.1), or reset its stream with H3_REQUEST_CANCELLED once a response started
  (§4.1.1). The connection goes on, because h3's streams are independent. The send rate
  resets a stream held by its own credit, and closes a connection held as a whole with
  H3_EXCESSIVE_LOAD. A program changes one connection's limits with `set_deadlines` and
  reads why colibri closed one with `close_reason`, as on a TCP connection, and the reset
  limit reads as `Limit.peer_resets`.
- **The GOAWAY before a close.** At the first-request, idle and drain deadlines the server
  sends a GOAWAY first, and closes with H3_NO_ERROR once the client acknowledged it or the
  drain deadline passed, as the owner ruled on 2026-10-04. RFC 9114 §5.2 says a server
  SHOULD send one when it knows of the close in advance, so that a client learns which
  requests the server did not take. `quic` writes a CONNECTION_CLOSE alone once it owes one
  (RFC 9000 §10.2.1), so a GOAWAY written with the close would never be sent. `shutdown`
  with no request open sends its GOAWAY the same way. A close before the handshake
  completes sends none, because h3 has not started. A program that sets `drain_ns` to
  null leaves the wait for that acknowledgment to QUIC's own idle timeout, which a
  client's PING keeps away, as `linger_ns` of null leaves a TCP connection's last bytes
  to its peer.
- **An endpoint given limits a connection refuses** returns `DeadlineInvalid` from
  `Endpoint.init`, as `server.Connection.init` does, as the owner ruled on 2026-10-04. The
  endpoint starts each connection itself and drops one that refuses to start, so without
  the error it would answer no client and tell its program nothing.
- **What stops the idle deadline.** Only a request whose head arrived whole, as the owner
  ruled on 2026-10-04. A request stream that still waits for its head does not stop it.
  Each such stream gets its 408 at the head deadline, and the connection closes at the idle
  deadline unless a whole request arrives. The first-request deadline counts from the
  client's first datagram, so it covers the handshake, and a close before the handshake
  completes leaves as RFC 9000 §10.2.3 has it.
- **A request whose head is unread when the connection shuts down** is rejected. The
  GOAWAY names the first request stream the server has not seen, so a stream that still
  waits for its head is below that identifier, and the connection closes without waiting
  for it. When the server sends the GOAWAY, at a deadline or at the program's `shutdown`,
  it resets each such stream with H3_REQUEST_REJECTED. RFC 9114 §4.1.1 says a server
  SHOULD do so for a request it cancels with no application processing, and the client
  may then send the request again. §5.2 allows it below the GOAWAY's identifier. A head
  whose own deadline passes at that instant gets its 408 first.
- **A request body over h3.** Its wait starts at the call that reads its request's head,
  also when the request is owed a 100 (Continue) (decision 116), and ends with its content
  or its stream. Only the data of its DATA frames counts (RFC 9114 §7.2.1), and only while
  the caller still hears of the request. A body under the rate or past the cap ends its
  request alone:
  - with no final response begun, a 408 and a STOP_SENDING with H3_NO_ERROR;
  - with a final response begun and not ended, a reset with H3_REQUEST_CANCELLED;
  - with a response ended, a STOP_SENDING with H3_NO_ERROR, and the response goes on.

  The caller reads `cancelled`, naming the deadline, unless the response had ended. h3
  checks the rate across the connection's bodies too, as h2 does, and closes with
  H3_EXCESSIVE_LOAD where h2 sends ENHANCE_YOUR_CALM.
- **Where a body over h3 differs from h2.** Its rate does not wait on flow control. QUIC
  writes a MAX_STREAM_DATA frame ahead of stream data in its next packet, so the frame
  never waits behind a response, as an h2 WINDOW_UPDATE does in a TCP connection's output.
  A body arrives a QUIC packet at a time, and a QUIC connection refuses to start with a rate
  `validate_units` refuses: the bound for a unit of 16,384 bytes covers every packet up
  to that length, and one `Deadlines` then suits a server's TCP and QUIC connections. A
  longer packet crosses only a path with such an MTU, as loopback has, and the bound is
  not proved for it.
- **The send rate over h3.** A QUIC peer takes a response's bytes by acknowledging them,
  and lets them leave by the credit it gives the stream and the connection (RFC 9000 §4.1,
  §13.2). So the meters count the bytes the peer acknowledged, which the server reads
  when it settles its requests after each datagram, and not for each frame.
  - While any response holds bytes the peer may take and has not acknowledged, the peer
    must acknowledge the minimum send rate over each window, across the responses. A peer
    that falls short acknowledges too little, or holds the responses with the connection's
    credit, and the connection closes with H3_EXCESSIVE_LOAD.
  - A response its stream's credit does not cover has a meter of its own, which counts
    what the peer acknowledges of it. It waits while any other response holds bytes the
    peer may take, as an h2 stream's waits while the connection's output holds bytes. A
    stream under the rate is reset with H3_REQUEST_CANCELLED, and the caller reads
    `cancelled`.
  - A stream's meter keeps its window while its own credit grows, so credit that grows a
    few bytes at a time is judged by what it lets through. h2 needs a floor on a DATA
    frame for that, and h3 needs none.
- **What does not apply.** h3 defines no SETTINGS acknowledgment (RFC 9114 Appendix A.4),
  and QUIC's closing period bounds a close (RFC 9000 §10.2), so h3 has no SETTINGS deadline
  and no linger.

The owner ruled the reset limit, the deadlines and what each does, and what stops the idle
deadline. The three points on a request body and on the send rate apply those rulings to
QUIC. They were settled while building step 20c, and the owner confirmed them on
2026-10-04. The rejection of an unread head was settled on 2026-10-04 too, after the
simulator's check of step 20c showed a connection that closed with such a stream
unanswered. It follows RFC 9114 §4.1.1, and the owner has not ruled on it.

The alternatives refused:
- Leaving h3 to QUIC's idle timeout, which counts silence alone.
- Resetting a slow request's stream with no response. It is cheaper to write, but an honest
  slow client learns less, and RFC 9114 §4.1.1 recommends a response with a status code.
- Deadlines with no reset limit. QUIC's stream limit bounds how many streams are open at
  once, and nothing would bound how fast they are opened and reset.
- Letting a request stream with a partial head stop the idle deadline, and closing the
  connection after some number of late heads. It needs a second limit and a count, and a
  client that stays under the count holds the connection for as long as it likes.
- Leaving a connection that brings partial heads alone to the caller. The caller never
  hears of a request whose head is not whole, so it has nothing to decide with.
- Resetting a response that ended when its request's body falls short. Over TCP the
  response's bytes are ahead of the RST_STREAM and arrive. A QUIC stream that is reset
  sends its bytes no more (RFC 9000 §3.1), so the client would lose a whole response.
- Body deadlines for each stream alone. A client that opens slow bodies one after another
  would then hold the connection with no end, each body taking a grace period and a
  window.
- Counting the datagrams `send` writes, as a TCP connection counts what its socket takes.
  A UDP socket takes every datagram, and a peer that sends PING frames draws
  acknowledgments from the server at no cost to itself.
- Counting the bytes QUIC frames for the first time. The server keeps a response until
  the peer acknowledges it, so a peer that acknowledges nothing of a response framed whole
  would hold its record with no meter running.
- The GOAWAY in the close's packet, which RFC 9114 §5.3 names. `quic` would write a stream
  frame beside a CONNECTION_CLOSE, against a property spec/tla/quic_close checks, and a
  GOAWAY lost with its packet is not sent again.
- Closing at once with no GOAWAY, which the first three parts of step 20c did. A client
  that sent a request as the server closed could not tell whether the server took it.
- Closing with a request stream's head unread and nothing said of it, which the GOAWAY
  did at first. That stream is below the GOAWAY's identifier, so its client could not
  tell whether the server took the request either.
- Waiting for each unread head until its own deadline before the close. A connection
  would outlive its first-request or idle deadline by up to the head deadline, for a
  client that sent part of a head.
- A GOAWAY that names the unread stream. A request stream above it that the server did
  take would then read as rejected.
- An assertion in `Endpoint.init` in place of the error, which the third part of step 20c
  had. A program that reads its limits from outside would stop on a value it could have
  reported.

Cost: a few branches for each datagram and each event of an h3 connection, and 8 bytes
for each request stream h3 holds, the instant it first saw the stream. The work is design
§8 step 20c.

Amended a seventh time by the owner on 2026-10-08, after `spec/tla/h3_deadlines` (design §8
step 20d) found two faults in the sixth amendment:
- **The close waits for every reset's acknowledgment.** A shutdown rejects each request
  whose head h3 has not read, and the close waited for the GOAWAY's acknowledgment alone.
  Once QUIC owes a close it sends nothing else. So a rejection still owed, or lost in a
  packet of its own, never reached the client, which could not tell that it may send the
  request again (RFC 9114 §4.1.1). colibri writes resets ahead of stream data, so a
  datagram that fills, or one that is lost, parts a rejection from the GOAWAY. The close
  now also waits until no stream of the connection is in "Reset Sent" (RFC 9000 §3.1), and
  the drain deadline bounds the wait. It does not wait for h3 to read a request stream the
  closing datagram opened: that stream is at or above the GOAWAY's identifier, which
  already tells the client the server did not take it (RFC 9114 §5.2).
- **The head, body and idle clocks wait while colibri holds credit.** RFC 9002 §7 bounds
  every ack-eliciting packet by the congestion window, MAX_DATA and MAX_STREAM_DATA among
  them. While the window is full of packets the client has not acknowledged, the credit
  the client needs waits in colibri, and these clocks judged the client for it, as h2's
  body rate did before the fourth amendment. The body meters stop while colibri owes
  credit it has not sent, and start again with a grace period once it is out, as h2's do.
  The head and idle deadlines move by the time the credit was held.

The alternatives refused:
- Recording both and changing no code. A rejection lost to the close leaves a client
  unable to retry a request the server never processed, and judging a client for credit
  colibri holds breaks rule 2.
- Also waiting, before the close, for h3 to read every request stream QUIC opened. TLC
  finds it changes nothing the client learns.
- Sending credit past the congestion window. RFC 9002 §7 forbids it for an ack-eliciting
  packet.

Amended an eighth time by the owner on 2026-10-17, after a review of the server's defences.
Design §8 step 20e carries three rulings:
- **The reset limits are settings.** `server.Limits` holds `peer_resets_max`, the requests a
  client may cancel in one second, and `resets_sent_max`, the streams the server may reset
  in one second. Each is 100 by default, the value of h2's two constants. `init` sets them,
  and they stay fixed after it. An assertion refuses 0, which is a programmer error. The
  period stays one second, a constant. `h2.Connection` holds the two limits as fields.
  `init` sets h2's constants in them, and a server sets its own after `init`, as it does
  for `data_frame_len_min`.
- **h3 counts the streams it resets.** h2 counted each RST_STREAM it sent, but h3 counted
  only the client's cancels. A client could send a whole request head, which the
  application starts to work on, and then break the request, for example with content past
  its Content-Length. h3 then reset the stream, and nothing limited how often. This is the
  cost of Rapid Reset, with a reset that the server sends. h3 now counts each request stream
  it refuses under `resets_sent_max`. Past it, the connection closes with H3_EXCESSIVE_LOAD
  (RFC 9114 §10.5).
- **Retry past a share of the slots.** `Config.retry` sent a Retry to every client or to
  none. Without one, each spoofed Initial holds a QUIC slot until the first-request
  deadline, and it starts a TLS handshake. RFC 9000 §8.1.2 names Retry as the way to defer
  that state and that work. With `retry` set, the endpoint sends Retry while at least
  `Config.retry_from_percent` of its QUIC slots hold a connection. Its default of 0 keeps
  the old behavior: every client gets a Retry. The endpoint checks a Retry token that a
  client returns with, whatever the share.

The names are the owner's. `peer_resets_max` and `resets_sent_max` match the values
`peer_resets` and `resets_sent` of a close reason's limit, so an operator reads one name for
a limit and for the close it caused.

The alternatives refused:
- For the settings: the constants as they were, and settings that a call changes for one
  connection while it runs, as `set_deadlines` does.
- For h3: one counter for the client's cancels and the server's resets together, and no
  limit.
- For Retry: a call that turns Retry on and off while the server runs; a default of 50
  percent, which changes what a program that sets `retry` does today; and a count of free
  slots, which a program must size against its `Capacity`.
- For the names: `cancels_max` and `refusals_max`, and names that end in `_per_second_max`.

Amended a ninth time by the owner on 2026-11-27, as "Resume the meter", while design §8 step
79 was built (decision 176):
- **A pause that lasts no time keeps its window.** An h2 stream's send meter that stops and
  starts again at one instant takes back the window it stopped in, with its bytes, and gets
  no new grace period. A start at a later instant starts a window again with a grace period,
  as before.
- **The other meters stop as before.** A request body's meter starts again with a grace
  period once its WINDOW_UPDATE is out, as the fourth amendment rules, though colibri sends
  the update at the instant it stopped: the peer still waits a round trip for it. The
  connection's send meter and QUIC's meters keep their rule too.
- **Why.** An h2 stream's meter runs only while the connection's output holds nothing that no
  socket took. The pumps of `colibri.Server` and of the test-only server read again after a
  response's write and before they take its bytes, and that read stopped the meter. Taking
  the bytes at the same instant started it again with a new grace period. So a peer that
  opens its window a byte a second was never cut. The engine's own test took the bytes at
  each `send`, and so never showed it. A pump now takes them once a turn, which keeps one
  send and one TLS record a turn.
- **The gap design §8 step 21b.5 left to the owner closes too.** Its endpoint check read
  after each PING's acknowledgment and copied it at the same instant. So an h2 peer that keeps
  a stream's window closed and pings every few seconds was never cut, and the check let that
  peer alone outlast its horizon. The stream's meter now cuts it, and the check lets no
  connection outlast the horizon.
- **Cost.** No byte: the meter keeps the instant it stopped at in the field that said whether
  it runs, so `rate.Meter` stays 24 bytes.
- The alternatives refused:
  - Taking the bytes at each `send`, with no change to the meter. Over TLS each take seals a
    record of its own, so h2 pays an AEAD call and 22 bytes for each response of a turn.
  - Keeping the gap, and filing an issue.
  - Every meter keeping its window across a pause that lasts no time. A body's meter would
    then judge a peer for the round trip in which it waits for its WINDOW_UPDATE, which the
    fourth amendment refused.
