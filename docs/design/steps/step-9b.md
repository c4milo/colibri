# Design §8 step 9b: packet number spaces, acknowledgments, and how a connection ends

[Design §8, the build plan](../../design.md#8-build-plan)

The three spaces of RFC 9000 §12.3, duplicate suppression, ACK generation and processing (§13.1,
§13.2), the ECN counts (§13.4.1), the idle timeout (§10.1) and the closing and draining states
(§10.2). **Check:** an ACK frame written from a space reads back through step 9a as the ranges the
space holds, and both state machines are checked by enumerating every state and event pair.
*Medium.*

**The packet number spaces, 2026-09-19.** `src/quic/space/` holds the three spaces of RFC 9000
§12.3 — Initial, Handshake and Application data — each with its own numbers, its own record of
what it received, its own ECN counts and its own acknowledgment state. Sharing nothing is the
point: §12.3 gives the spaces cryptographic separation, and a number means nothing outside the
one it was used in.

One structure does two jobs, because both ask which numbers have been processed. §12.3 has a
receiver discard a packet unless it is certain it has not processed that number before, and
§19.3.1's ACK ranges are exactly the runs such a record holds. `Received` keeps them
descending and merges a number that closes a gap, so the ranges are always the fewest that
describe what arrived, in any order it arrived in.

Its storage is fixed, which §13.2.3 asks for, and the cost is stated rather than hidden. Past
the limit the oldest range is dropped — §13.2.3's own remedy — and below what is left §12.3's
certainty is gone, so a packet there is discarded. A number one below the floor is refused
too, though it would merely extend the lowest range: the range that held it could have been
dropped before its neighbour arrived, and extending downward would then take a number this
endpoint had already processed. That refuses some packets a larger record would accept; it
never accepts one twice.

`Space` writes the ACK frame from that record (§19.3), with the ACK Delay measured from the
instant the largest number arrived and shifted by the endpoint's `ack_delay_exponent` (§19.3,
§13.2.5, §18.2), and the three ECN counts when the endpoint reports them (§13.4.1, §19.3.2).
It owes an ACK after two ack-eliciting packets (§13.2.2), and at once when one arrives out of
order or marked ECN-CE (§13.2.1). `on_ack` reads what a peer's frame said: §13.1 makes an
acknowledgment for a packet never sent a connection error of PROTOCOL_VIOLATION, and §13.2
makes acknowledgments irrevocable, so the largest never moves backward. What it does not do is
loss recovery — nothing here remembers what was sent, so nothing here can call a packet lost;
RFC 9002 is step 10's, and the report exists for that step to act on.

Every ACK frame the tests write is read back through the frame layer, so the writer and the
reader agree about §19.3.1's arithmetic rather than each agreeing with itself.

`zig build test` passes 750 of 750 and the lint is clean. Mutations: 32 applied, 31 **CAUGHT**.
The one that was not removed a guard against a space that owes an acknowledgment while having
received nothing, which no reachable state produces: both counters move only on a packet the
space processed. It is now an assertion stating that invariant rather than a branch defending
against it, so a later change that empties a space without clearing them fails at the
assertion instead of writing an ACK frame with no ranges. Removing the assertion is not caught
either, and cannot be: no input violates it, which is what makes it an invariant.

A test of mine was wrong before the code was. It expected a number just below the remembered
floor to be accepted, and the reasoning in the paragraph above is why it must not be.

**How a connection ends, 2026-09-19.** `src/quic/termination.zig` holds RFC 9000 §10's idle
timeout and its closing and draining states. The effective idle timeout is the smaller of the
two advertised values, or the sole non-zero one, and never below three Probe Timeouts (§10.1).
Receiving a packet restarts the timer; sending restarts it only when nothing ack-eliciting has
gone out since a packet last arrived, which is what stops an endpoint that only talks from
holding a dead connection open. A timeout closes silently, so nothing goes on the wire.

The two states differ in what may be sent. A closing endpoint answers an arriving packet with
a CONNECTION_CLOSE frame and nothing else, each answer waiting for twice as many packets as
the last, which is the rate limit §10.2.1 asks for. A draining endpoint sends nothing at all
(§10.2.2), and a closing one that hears a close moves to draining, which ends the endless
exchange of close frames that section warns about — keeping its own reason and the instant its
period began, because changing state is not a second close. Both periods last three Probe
Timeouts, which the caller supplies: §10.1 and §10.2 size themselves on it and RFC 9002
computes it in step 10.

**How the state machine is checked, and why by no tool.** The transitions are verified by
enumerating every one: four states by five events, each pair asserted, with a check that the
table holds each pair exactly once. For a finite machine that is the whole function rather
than a sample, so a model in a second language would restate the same twenty facts and add a
source of truth that can drift. The owner asked on 2026-09-19 whether Lean or TLA+ belonged
here; the answer recorded then was that neither earns its place at this size, that the same
enumeration covers step 9's stream machines (§3.1, §3.2), and that the case for TLA+ — not
Lean, which suits pure functions, as chapulin's use of it shows — arises only for properties
that quantify over interleavings of two endpoints, which the step 8 network check samples
rather than covers. Adding one is a new dependency and so the owner's call, to be made against
a specific property that resists both an enumeration and a simulator invariant.

Mutations: 22 applied, all **CAUGHT**. Two needed tests first: nothing called the
instant-passing entry point on an active connection, and the check that a draining endpoint
stays silent was masked, because the counter it reads stops moving once draining begins.

**The TLA+ model, 2026-09-26** ([#51](https://github.com/c4milo/colibri/issues/51)).
- `spec/tla/quic_close` models two endpoints ending a connection as colibri does: the idle
  timeout (§10.1) with its rule for restarting on a send, the immediate close, and the closing
  and draining states (§10.2), over a network that loses packets and delivers some a tick late.
  Time moves in ticks of one PTO, so the idle timeout, the PTO and its doubling, and the three
  PTOs of each period are checked against each other. Either endpoint may close first, both may
  close at once, and any CONNECTION_CLOSE may be lost. The properties: a closing endpoint sends
  CONNECTION_CLOSE alone and a draining or closed one sends nothing; a closing endpoint's
  answers back off, so after n answers it has received at least 2^(n-1) packets; and once
  either endpoint leaves "active", both reach "closed".
- It found no defect, and one sentence above that no longer holds. `Termination` moves a closing
  endpoint that hears a close to draining, but the connection never asks it to:
  `connection_datagram.receive` takes no frame while closing, as §10.2.1 allows. The rate limit
  is what ends an exchange of closes, and the model checks that it does.
- What `zig build tla` printed, on macOS arm64:
  - holds, as expected: `colibri`, both endpoints may close and neither sends data, 3996
    distinct states; `talker`, one closes while the other sends a packet every tick, 127762;
  - violated, as expected: `no_idle`, with no idle timeout a peer whose CONNECTION_CLOSE was
    lost and that has nothing to send never ends; `restart_every_send`, restarting the idle
    timer on every ack-eliciting send keeps a peer that talks into a closed connection alive
    for good, which is why §10.1 restarts it only on the first; `no_rate_limit`, two endpoints
    closing at once answer each other without backing off.
  - Run once and not kept, because it takes seven minutes: both endpoints closing while one
    talks, with one loss, holds over 2242541 distinct states.

**The ACK ranges proved, 2026-09-26.** `spec/lean/Colibri/Quic/AckRanges.lean` states RFC 9000
§19.3.1's ranges as `frame_ack.zig` reads them and as `write_ack_at` in `space.zig` writes them,
and proves:
- `decode_encode`: ranges that descend with an unacknowledged number between each two, as
  `space_received.zig` keeps them, read back from what the writer writes;
- `encode_decode` and `decode_wellFormed`: whatever the reader accepts is such ranges, and the
  writer writes them back as the same fields;
- `decode_none_iff`: the reader refuses a frame exactly when a packet number §19.3.1 computes
  over the integers is below zero, which is that section's FRAME_ENCODING_ERROR.

`src/quic/frame/frame_ack_vectors.txt` holds 205 frames, 32 ranges long at most, and what the
reader gives each. `src/quic/space/space_ack_vectors.txt` holds the 74 distinct sets of ranges
the reader accepts, and the fields the writer writes for each. A test beside each requires the
Zig code to give them. Mutations: 14 over the reader, its iterator, `smallest_acknowledged` and
the writer, each **CAUGHT** by those tests. One, a writer that counts the next gap down from a
range's largest, was caught only after the vectors gained ranges of two numbers between two
others. 3 mutations in the Lean definitions stop the proofs, and 1 edit to a vector file is
refused by `zig build lean`.
