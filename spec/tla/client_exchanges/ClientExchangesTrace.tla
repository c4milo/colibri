------------------------ MODULE ClientExchangesTrace ------------------------
(***************************************************************************)
(* Trace validation of ClientExchanges against colibri (decision 105).     *)
(* The simulator's client trace run logs every variable of ClientExchanges *)
(* but goaways after each instant, and a seed's module gives that log as   *)
(* Trace: a sequence of records whose functions over Exchanges are         *)
(* sequences, exchange 1 first, and whose functions over the transports    *)
(* are records.                                                            *)
(*                                                                         *)
(* One instant of the run can take several of the model's steps: a         *)
(* datagram can end two exchanges and carry a GOAWAY. So between two       *)
(* logged states the model moves freely, up to StepsMax steps, and the     *)
(* trace advances when the model's state equals the next logged one. The   *)
(* log is a behavior of the model when TLC reaches its last state, so a    *)
(* seed's configuration expects the invariant Unfinished to be violated. A *)
(* log with a state the model cannot reach leaves it holding.              *)
(*                                                                         *)
(* The log leaves out quiet: the run keeps KeepAlive, so the model never   *)
(* sets it.                                                                *)
(*                                                                         *)
(* The log leaves out goaways. A server sends its GOAWAY before the client *)
(* reads it, and the model counts it when the client does, so the run      *)
(* bounds it through GoawaysMax instead: the GOAWAY frames its servers     *)
(* sent.                                                                   *)
(***************************************************************************)
EXTENDS ClientExchanges, Sequences

CONSTANTS
    Trace,      \* the logged states, in order
    StepsMax,   \* the model's steps between two logged states, at most
    Goal        \* the logged state TLC must reach: Len(Trace), or less to find where one stops

VARIABLES
    index,      \* the logged state the model last matched
    since       \* the model's steps since then

\* A function over Exchanges from the sequence the log writes, exchange 1 first.
AsFunction(s) == [e \in Exchanges |-> s[e]]

Matches(i) ==
    LET t == Trace[i] IN
    /\ stage = AsFunction(t.stage) /\ carrier = AsFunction(t.carrier)
    /\ holds = AsFunction(t.holds) /\ outcome = AsFunction(t.outcome)
    /\ moved = AsFunction(t.moved) /\ seen = AsFunction(t.seen)
    /\ processed = AsFunction(t.processed)
    /\ phase = t.phase /\ opens = t.opens /\ tried = t.tried
    /\ fallback = t.fallback /\ learned = t.learned /\ shut = t.shut
    /\ stale = t.stale

TraceInit == Init /\ Matches(1) /\ index = 1 /\ since = 0

(* The model's state is the next logged one, so the trace moves on.        *)
Advance ==
    /\ index < Len(Trace) /\ Matches(index + 1)
    /\ index' = index + 1 /\ since' = 0
    /\ UNCHANGED vars

(* One of the model's steps toward the next logged state.                  *)
Move ==
    /\ index < Len(Trace) /\ Next
    /\ since' = since + 1
    /\ UNCHANGED index

TraceSpec == TraceInit /\ [][Advance \/ Move]_<<vars, index, since>>

StageRank(s) ==
    CASE s = "unmade" -> 0 [] s = "waiting" -> 1 [] s = "queued" -> 2 [] s = "sent" -> 3
      [] s = "ended" -> 4 [] s = "reported" -> 5 [] s = "cancelled" -> 5

PhaseRank(p) ==
    CASE p = "none" -> 0 [] p = "handshake" -> 1 [] p = "open" -> 2 [] p = "draining" -> 3
      [] p = "failed" -> 4 [] p = "closed" -> 5

(* No variable the model only moves one way has passed the logged state i: *)
(* a path that did can never match it, so TLC stops extending it. An       *)
(* exchange's stage goes back only when it moves, and a transport's phase  *)
(* only when it opens again.                                               *)
Toward(i) ==
    LET t == Trace[i] IN
    /\ (shut => t.shut) /\ (learned => t.learned)
    /\ \A e \in Exchanges :
        /\ processed[e] <= t.processed[e]
        /\ \/ moved[e] < t.moved[e]
           \/ moved[e] = t.moved[e] /\ StageRank(stage[e]) <= StageRank(t.stage[e])
    /\ \A tr \in Transports :
        \/ opens[tr] < t.opens[tr]
        \/ opens[tr] = t.opens[tr] /\ PhaseRank(phase[tr]) <= PhaseRank(t.phase[tr])

(* The CONSTRAINT: a path that has not matched the next logged state in    *)
(* StepsMax steps, or has passed it, is one TLC stops extending.           *)
Within == since <= StepsMax /\ (index < Len(Trace) => Toward(index + 1))

(* The INVARIANT each seed expects violated: the model reached the goal.   *)
Unfinished == index < Goal

=============================================================================
