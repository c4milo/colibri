---------------------------- MODULE QuicClose ----------------------------
(***************************************************************************)
(* How a QUIC connection ends (RFC 9000 §10): the idle timeout (§10.1),    *)
(* the immediate close, and the closing and draining states (§10.2), as    *)
(* colibri keeps them (src/quic/termination.zig and, in                    *)
(* src/quic/connection/, connection_datagram.zig and connection_send.zig). *)
(*                                                                         *)
(* Two endpoints exchange packets over a network that may lose them and    *)
(* may deliver one a tick late, so packets can arrive out of order. Time   *)
(* moves in ticks: one tick is the PTO, and every timer counts down in     *)
(* whole ticks. Nothing is left undone when a tick passes: every packet    *)
(* due is delivered or lost, every timer at zero fires, and everything     *)
(* owed is sent.                                                           *)
(*                                                                         *)
(* colibri's rules, as this model has them:                                *)
(*   - an endpoint that closes sends one CONNECTION_CLOSE and enters       *)
(*     "closing" (§10.2.1). It processes no frame from then on, and        *)
(*     answers the packets it receives with CONNECTION_CLOSE at the 1st,   *)
(*     2nd, 4th and 8th of them, and so on (close_answer_backoff);         *)
(*   - an endpoint that receives CONNECTION_CLOSE while active enters      *)
(*     "draining" and sends nothing (§10.2.2). colibri declines the        *)
(*     single close §10.2.2 allows before draining;                        *)
(*   - both states last three PTOs (§10.2, close_probe_timeouts), and the  *)
(*     connection is closed after;                                         *)
(*   - the idle timer restarts when a packet is received, and when an      *)
(*     ack-eliciting packet is sent if none was sent since the last        *)
(*     receipt (§10.1). When it runs out the endpoint closes silently;     *)
(*   - an ack-eliciting packet in flight arms the PTO, which sends a probe *)
(*     and doubles (RFC 9002 §6.2). A closing or draining endpoint sets    *)
(*     no PTO.                                                             *)
(*                                                                         *)
(* A CONNECTION_CLOSE is not ack-eliciting (RFC 9002 §2), so nothing       *)
(* sends it again when it is lost: a closing endpoint answers what arrives *)
(* instead. Without the idle timeout, a peer whose closes were all lost    *)
(* and that has nothing to send never ends: configuration no_idle keeps    *)
(* that path. Without §10.1's rule for restarting on a send, a peer that   *)
(* keeps sending into a closed connection never ends: configuration        *)
(* restart_every_send keeps that one.                                      *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    Closers,            \* the endpoints whose application may close the connection
    Talkers,            \* the endpoints whose application may send a packet every tick
    Idle,               \* the idle timeout, in ticks; at least three PTOs (§10.1)
    Period,             \* the closing and draining period, in ticks (§10.2)
    BackoffMax,         \* how many times the PTO may double
    CountMax,           \* where the counts of received packets and answers stop
    NetMax,             \* packets of one kind one endpoint may have on their way
    LossMax,            \* packets the network may lose in one behavior
    IdleEnabled,        \* whether either endpoint advertised a max_idle_timeout
    RateLimit,          \* whether a closing endpoint's answers back off (§10.2.1)
    RestartEverySend    \* whether every ack-eliciting send restarts the idle timer

Endpoints == {"a", "b"}
Peer(e) == IF e = "a" THEN "b" ELSE "a"
Kinds == {"data", "ack", "close"}
States == {"active", "closing", "draining", "closed"}

ASSUME /\ Closers \subseteq Endpoints /\ Talkers \subseteq Endpoints
       /\ {Idle, Period, BackoffMax, CountMax, NetMax, LossMax} \subseteq Nat
       /\ Idle >= 3 /\ Period >= 3 /\ NetMax >= 1
       /\ {IdleEnabled, RateLimit, RestartEverySend} \subseteq BOOLEAN

Min(x, y) == IF x < y THEN x ELSE y
Pow2(n) == 2^n
PtoTicks(n) == Pow2(n)
NoPackets == [k \in Kinds |-> 0]

VARIABLES
    state,          \* state[e]: §10.2's state
    closeOwed,      \* closeOwed[e]: the application closed and the CONNECTION_CLOSE is not yet sent
    closed,         \* closed[e]: the application may close only once
    idleLeft,       \* idleLeft[e]: ticks until the idle timeout
    sentSinceReceive, \* sentSinceReceive[e]: an ack-eliciting packet went out since
                      \* the last receipt
    periodLeft,     \* periodLeft[e]: ticks until the closing or draining period ends
    inflight,       \* inflight[e]: an ack-eliciting packet is unacknowledged
    ptoLeft,        \* ptoLeft[e]: ticks until the PTO
    backoff,        \* backoff[e]: how many times the PTO doubled
    ackOwed,        \* ackOwed[e]: an ack-eliciting packet arrived and is not yet acknowledged
    received,       \* received[e]: packets received while closing
    answerAt,       \* answerAt[e]: the count at which the next answer goes out
    answers,        \* answers[e]: answers sent while closing
    talked,         \* talked[e]: the application sent a packet this tick
    now,            \* now[e]: packets from e to be delivered or lost before the next tick
    later,          \* later[e]: packets from e that arrive after the next tick
    losses,         \* packets lost so far
    wrongSend       \* whether a packet went out that its sender's state forbids

vars == <<state, closeOwed, closed, idleLeft, sentSinceReceive, periodLeft, inflight, ptoLeft,
          backoff, ackOwed, received, answerAt, answers, talked, now, later, losses, wrongSend>>

TypeOK ==
    /\ state \in [Endpoints -> States]
    /\ closeOwed \in [Endpoints -> BOOLEAN] /\ closed \in [Endpoints -> BOOLEAN]
    /\ idleLeft \in [Endpoints -> 0..Idle]
    /\ sentSinceReceive \in [Endpoints -> BOOLEAN]
    /\ periodLeft \in [Endpoints -> 0..Period]
    /\ inflight \in [Endpoints -> BOOLEAN]
    /\ ptoLeft \in [Endpoints -> 0..PtoTicks(BackoffMax)]
    /\ backoff \in [Endpoints -> 0..BackoffMax]
    /\ ackOwed \in [Endpoints -> BOOLEAN]
    /\ received \in [Endpoints -> 0..CountMax]
    /\ answerAt \in [Endpoints -> 1..2 * CountMax]
    /\ answers \in [Endpoints -> 0..CountMax]
    /\ talked \in [Endpoints -> BOOLEAN]
    /\ now \in [Endpoints -> [Kinds -> 0..NetMax]]
    /\ later \in [Endpoints -> [Kinds -> 0..NetMax]]
    /\ losses \in 0..LossMax
    /\ wrongSend \in BOOLEAN

Init ==
    /\ state = [e \in Endpoints |-> "active"]
    /\ closeOwed = [e \in Endpoints |-> FALSE]
    /\ closed = [e \in Endpoints |-> FALSE]
    /\ idleLeft = [e \in Endpoints |-> Idle]
    /\ sentSinceReceive = [e \in Endpoints |-> FALSE]
    /\ periodLeft = [e \in Endpoints |-> 0]
    /\ inflight = [e \in Endpoints |-> FALSE]
    /\ ptoLeft = [e \in Endpoints |-> 0]
    /\ backoff = [e \in Endpoints |-> 0]
    /\ ackOwed = [e \in Endpoints |-> FALSE]
    /\ received = [e \in Endpoints |-> 0]
    /\ answerAt = [e \in Endpoints |-> 1]
    /\ answers = [e \in Endpoints |-> 0]
    /\ talked = [e \in Endpoints |-> FALSE]
    /\ now = [e \in Endpoints |-> NoPackets]
    /\ later = [e \in Endpoints |-> NoPackets]
    /\ losses = 0
    /\ wrongSend = FALSE

---------------------------------------------------------------------------
(* Sending.                                                                *)

(* A packet of `kind` from e, due now or after the next tick. §10.2.1: a   *)
(* closing endpoint sends CONNECTION_CLOSE alone; §10.2.2: a draining one  *)
(* sends nothing, and neither does a closed one. An ACK frame acknowledges *)
(* every packet received (RFC 9000 §19.3), so a second one on its way says *)
(* what the first does, and one stands for both.                           *)
Added(count, kind) == IF kind = "ack" THEN 1 ELSE Min(count + 1, NetMax)

Put(e, kind) ==
    /\ \E slot \in {"now", "later"} :
          IF slot = "now"
          THEN /\ now' = [now EXCEPT ![e][kind] = Added(@, kind)]
               /\ UNCHANGED later
          ELSE /\ later' = [later EXCEPT ![e][kind] = Added(@, kind)]
               /\ UNCHANGED now
    /\ wrongSend' = \/ wrongSend
                    \/ state[e] \in {"draining", "closed"}
                    \/ state[e] = "closing" /\ kind # "close"

(* §10.1's restart on an ack-eliciting send, and RFC 9002's PTO armed.     *)
AckElicitingSent(e) ==
    /\ IF RestartEverySend \/ ~sentSinceReceive[e]
       THEN idleLeft' = [idleLeft EXCEPT ![e] = Idle]
       ELSE UNCHANGED idleLeft
    /\ sentSinceReceive' = [sentSinceReceive EXCEPT ![e] = TRUE]
    /\ inflight' = [inflight EXCEPT ![e] = TRUE]

(* The application sends a packet, at most one a tick.                     *)
Talk(e) ==
    /\ e \in Talkers /\ state[e] = "active" /\ ~closeOwed[e] /\ ~talked[e]
    /\ talked' = [talked EXCEPT ![e] = TRUE]
    /\ Put(e, "data")
    /\ AckElicitingSent(e)
    /\ ptoLeft' = [ptoLeft EXCEPT ![e] = PtoTicks(backoff[e])]
    /\ UNCHANGED <<state, closeOwed, closed, periodLeft, backoff, ackOwed, received, answerAt,
                   answers, losses>>

(* The application closes the connection (§10.2).                          *)
AppClose(e) ==
    /\ e \in Closers /\ state[e] = "active" /\ ~closed[e]
    /\ closed' = [closed EXCEPT ![e] = TRUE]
    /\ closeOwed' = [closeOwed EXCEPT ![e] = TRUE]
    /\ UNCHANGED <<state, idleLeft, sentSinceReceive, periodLeft, inflight, ptoLeft, backoff,
                   ackOwed, received, answerAt, answers, talked, now, later, losses, wrongSend>>

(* connection_send.note_close_sent: the close goes out and the endpoint    *)
(* enters "closing" for three PTOs (§10.2, §10.2.1).                       *)
SendClose(e) ==
    /\ state[e] = "active" /\ closeOwed[e]
    /\ Put(e, "close")
    /\ state' = [state EXCEPT ![e] = "closing"]
    /\ closeOwed' = [closeOwed EXCEPT ![e] = FALSE]
    /\ periodLeft' = [periodLeft EXCEPT ![e] = Period]
    /\ UNCHANGED <<closed, idleLeft, sentSinceReceive, inflight, ptoLeft, backoff, ackOwed,
                   received, answerAt, answers, talked, losses>>

SendAck(e) ==
    /\ state[e] = "active" /\ ackOwed[e]
    /\ Put(e, "ack")
    /\ ackOwed' = [ackOwed EXCEPT ![e] = FALSE]
    /\ UNCHANGED <<state, closeOwed, closed, idleLeft, sentSinceReceive, periodLeft, inflight,
                   ptoLeft, backoff, received, answerAt, answers, talked, losses>>

(* RFC 9002 §6.2: the PTO sends a probe and doubles.                       *)
Probe(e) ==
    /\ state[e] = "active" /\ inflight[e] /\ ptoLeft[e] = 0
    /\ Put(e, "data")
    /\ AckElicitingSent(e)
    /\ backoff' = [backoff EXCEPT ![e] = Min(@ + 1, BackoffMax)]
    /\ ptoLeft' = [ptoLeft EXCEPT ![e] = PtoTicks(Min(backoff[e] + 1, BackoffMax))]
    /\ UNCHANGED <<state, closeOwed, closed, periodLeft, ackOwed, received, answerAt, answers,
                   talked, losses>>

(* Termination.permission: a closing endpoint answers once the packets it  *)
(* received reach answerAt, which then doubles (§10.2.1).                  *)
AnswerDue(e) == state[e] = "closing" /\ received[e] >= answerAt[e]

Answer(e) ==
    /\ AnswerDue(e)
    /\ Put(e, "close")
    /\ answerAt' = [answerAt EXCEPT ![e] =
                       Min(IF RateLimit THEN 2 * @ ELSE @ + 1, 2 * CountMax)]
    /\ answers' = [answers EXCEPT ![e] = Min(@ + 1, CountMax)]
    /\ UNCHANGED <<state, closeOwed, closed, idleLeft, sentSinceReceive, periodLeft, inflight,
                   ptoLeft, backoff, ackOwed, received, talked, losses>>

---------------------------------------------------------------------------
(* Receiving.                                                              *)

(* connection_datagram.receive, for a packet that opened while active.     *)
TakeActive(e, kind) ==
    /\ idleLeft' = [idleLeft EXCEPT ![e] = Idle]
    /\ sentSinceReceive' = [sentSinceReceive EXCEPT ![e] = FALSE]
    /\ CASE kind = "data" ->
              /\ ackOwed' = [ackOwed EXCEPT ![e] = TRUE]
              /\ UNCHANGED <<state, periodLeft, inflight, backoff>>
         [] kind = "ack" ->
              /\ inflight' = [inflight EXCEPT ![e] = FALSE]
              /\ backoff' = [backoff EXCEPT ![e] = 0]
              /\ UNCHANGED <<state, periodLeft, ackOwed>>
         [] kind = "close" ->
              \* §10.2.2: draining, for three PTOs, sending nothing.
              /\ state' = [state EXCEPT ![e] = "draining"]
              /\ periodLeft' = [periodLeft EXCEPT ![e] = Period]
              /\ UNCHANGED <<inflight, backoff, ackOwed>>
    /\ UNCHANGED <<received>>

(* A packet from e's peer arrives at e.                                    *)
Receive(e, kind) ==
    LET from == Peer(e) IN
    /\ now[from][kind] > 0
    /\ now' = [now EXCEPT ![from][kind] = @ - 1]
    /\ CASE state[e] = "active" -> TakeActive(e, kind)
         \* §10.2.1: a closing endpoint processes no frame and counts what arrives.
         [] state[e] = "closing" ->
              /\ received' = [received EXCEPT ![e] = Min(@ + 1, CountMax)]
              /\ UNCHANGED <<state, idleLeft, sentSinceReceive, periodLeft, inflight, backoff,
                             ackOwed>>
         \* §10.2.2: a draining endpoint sends nothing, so nothing that arrives matters.
         [] OTHER -> UNCHANGED <<state, idleLeft, sentSinceReceive, periodLeft, inflight, backoff,
                                 ackOwed, received>>
    /\ UNCHANGED <<closeOwed, closed, ptoLeft, answerAt, answers, talked, later, losses, wrongSend>>

Lose(e, kind) ==
    /\ now[e][kind] > 0 /\ losses < LossMax
    /\ now' = [now EXCEPT ![e][kind] = @ - 1]
    /\ losses' = losses + 1
    /\ UNCHANGED <<state, closeOwed, closed, idleLeft, sentSinceReceive, periodLeft, inflight,
                   ptoLeft, backoff, ackOwed, received, answerAt, answers, talked, later,
                   wrongSend>>

---------------------------------------------------------------------------
(* Timers and time.                                                        *)

(* §10.1: idle past the timeout, and closed silently.                      *)
IdleOut(e) ==
    /\ IdleEnabled /\ state[e] = "active" /\ idleLeft[e] = 0
    /\ state' = [state EXCEPT ![e] = "closed"]
    /\ UNCHANGED <<closeOwed, closed, idleLeft, sentSinceReceive, periodLeft, inflight, ptoLeft,
                   backoff, ackOwed, received, answerAt, answers, talked, now, later, losses,
                   wrongSend>>

(* §10.2: the closing or draining period is over.                          *)
PeriodEnd(e) ==
    /\ state[e] \in {"closing", "draining"} /\ periodLeft[e] = 0
    /\ state' = [state EXCEPT ![e] = "closed"]
    /\ UNCHANGED <<closeOwed, closed, idleLeft, sentSinceReceive, periodLeft, inflight, ptoLeft,
                   backoff, ackOwed, received, answerAt, answers, talked, now, later, losses,
                   wrongSend>>

(* Something must happen before time moves on.                             *)
Due(e) ==
    \/ \E k \in Kinds : now[e][k] > 0
    \/ /\ state[e] = "active"
       /\ \/ closeOwed[e] \/ ackOwed[e]
          \/ inflight[e] /\ ptoLeft[e] = 0
          \/ IdleEnabled /\ idleLeft[e] = 0
    \/ AnswerDue(e)
    \/ state[e] \in {"closing", "draining"} /\ periodLeft[e] = 0

Down(n) == IF n > 0 THEN n - 1 ELSE 0

Tick ==
    /\ \A e \in Endpoints : ~Due(e)
    /\ \E e \in Endpoints : state[e] # "closed"
    /\ idleLeft' = [e \in Endpoints |->
                       IF state[e] = "active" THEN Down(idleLeft[e]) ELSE idleLeft[e]]
    /\ ptoLeft' = [e \in Endpoints |-> IF inflight[e] THEN Down(ptoLeft[e]) ELSE ptoLeft[e]]
    /\ periodLeft' = [e \in Endpoints |-> Down(periodLeft[e])]
    /\ now' = later
    /\ later' = [e \in Endpoints |-> NoPackets]
    /\ talked' = [e \in Endpoints |-> FALSE]
    /\ UNCHANGED <<state, closeOwed, closed, sentSinceReceive, inflight, backoff, ackOwed,
                   received, answerAt, answers, losses, wrongSend>>

---------------------------------------------------------------------------

Next ==
    \/ \E e \in Endpoints :
          \/ Talk(e) \/ AppClose(e) \/ SendClose(e) \/ SendAck(e) \/ Probe(e) \/ Answer(e)
          \/ IdleOut(e) \/ PeriodEnd(e)
          \/ \E k \in Kinds : Receive(e, k) \/ Lose(e, k)
    \/ Tick

(* Every endpoint does what it owes and takes what arrives, and time       *)
(* moves on. The applications need do nothing.                             *)
Fairness ==
    /\ \A e \in Endpoints :
          /\ WF_vars(SendClose(e)) /\ WF_vars(SendAck(e)) /\ WF_vars(Probe(e))
          /\ WF_vars(Answer(e)) /\ WF_vars(IdleOut(e)) /\ WF_vars(PeriodEnd(e))
          /\ \A k \in Kinds : WF_vars(Receive(e, k))
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

---------------------------------------------------------------------------
(* Properties.                                                             *)

(* §10.2.1, §10.2.2: a closing endpoint sends CONNECTION_CLOSE alone, and  *)
(* a draining or closed one sends nothing.                                 *)
NoWrongSend == ~wrongSend

(* §10.2.1: a closing endpoint's answers back off. After n answers it has  *)
(* received at least 2^(n-1) packets.                                      *)
RateLimited == \A e \in Endpoints : answers[e] > 0 => Pow2(answers[e] - 1) <= received[e]

(* No count stopped at its cap, so none of them lost a packet or an        *)
(* answer the model did not mean to lose.                                  *)
Uncapped ==
    /\ \A e \in Endpoints : \A k \in Kinds : now[e][k] < NetMax /\ later[e][k] < NetMax
    /\ \A e \in Endpoints : received[e] < CountMax

(* Once either endpoint leaves "active", both reach "closed".              *)
BothEnd ==
    (\E e \in Endpoints : state[e] # "active") ~> (\A e \in Endpoints : state[e] = "closed")
=============================================================================
