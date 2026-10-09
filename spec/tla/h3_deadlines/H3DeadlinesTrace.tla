------------------------- MODULE H3DeadlinesTrace -------------------------
(***************************************************************************)
(* Trace validation of H3Deadlines against colibri (design §8 step 20d).   *)
(* The simulator's h3 deadline trace run logs, after each of its actions,  *)
(* the variables of H3Deadlines that map one to one onto colibri and its   *)
(* client, and whether each of colibri's clocks runs. A seed's module      *)
(* gives that log as Trace, a sequence of records whose functions over     *)
(* Requests are sequences, request 0 first.                                *)
(*                                                                         *)
(* colibri counts octets where the model counts units and packets, so the  *)
(* run logs nothing of the client's units, colibri's QUIC, the network or  *)
(* the credit, and TLC finds values for them that fit. One of the run's    *)
(* actions can take several of the model's steps, so between two logged    *)
(* states the model moves freely, up to StepsMax steps, and the trace      *)
(* advances when the logged variables equal the next logged state, the     *)
(* model's colibri has no step left, and each clock runs as the model's    *)
(* rule for it says. The log is a behavior of the model when TLC reaches   *)
(* its last state, so a seed's configuration expects the invariant         *)
(* Unfinished to be violated. A log with a state the model cannot reach,   *)
(* or a clock the rules do not run, leaves it holding.                     *)
(***************************************************************************)
EXTENDS H3Deadlines

CONSTANTS
    Trace,      \* the logged states, in order
    StepsMax,   \* the model's steps between two logged states, at most
    Goal        \* the logged state TLC must reach: Len(Trace), or less to find where one stops

VARIABLES
    index,      \* the logged state the model last matched
    since       \* the model's steps since then

(* The logged states as one value. TLC evaluates the operator a CONSTANT   *)
(* is bound to at each reference, but a definition without arguments once, *)
(* before it starts.                                                       *)
Logged == Trace

(* A function over Requests from a sequence the log writes.                *)
AsFunction(sequence) == [r \in Requests |-> sequence[r + 1]]

Matches(i) ==
    LET t == Logged[i] IN
    /\ opened = t.opened /\ outcome = AsFunction(t.outcome)
    /\ goawayRead = t.goawayRead /\ closeRead = t.closeRead
    /\ taken = t.taken /\ phase = AsFunction(t.phase) /\ processed = AsFunction(t.processed)
    \* colibri frees its records when the connection stops, and the model keeps bodyWaits, which
    \* no clock reads once it has.
    /\ t.closed = "open" => bodyWaits = AsFunction(t.bodyWaits)
    /\ written = AsFunction(t.written)
    /\ aborted = AsFunction(t.aborted) /\ goawayId = t.goawayId
    /\ firstRequestRead = t.firstRequestRead /\ shuttingDown = t.shuttingDown
    /\ timedOut = t.timedOut /\ closed = t.closed
    \* colibri reads what arrived and writes what it owes in the action that brings it, and a
    \* client's action leaves colibri as it was, so the model's colibri has no step left.
    /\ Quiescent
    \* colibri's clocks run exactly when the model's rules say they do.
    /\ FirstRequestRuns = t.firstRequestRuns /\ IdleRuns = t.idleRuns
    /\ SendRuns = t.sendRuns /\ DrainRuns = t.drainRuns
    /\ \A r \in Requests : HeadRuns(r) = t.headRuns[r + 1] /\ BodyRuns(r) = t.bodyRuns[r + 1]

TraceInit == Init /\ Matches(1) /\ index = 1 /\ since = 0

(* The model's state matches the next logged one, so the trace moves on.   *)
Advance ==
    /\ index < Len(Logged) /\ Matches(index + 1)
    /\ index' = index + 1 /\ since' = 0
    /\ UNCHANGED vars

(* One of the model's steps toward the next logged state.                  *)
Move ==
    /\ index < Len(Logged) /\ Next
    /\ since' = since + 1
    /\ UNCHANGED index

TraceSpec == TraceInit /\ [][Advance \/ Move]_<<vars, index, since>>

PhaseRank(p) ==
    CASE p = "unseen" -> 0 [] p = "head" -> 1 [] p = "content" -> 2
      [] p \in {"ended", "abandoned"} -> 3

(* No logged variable the model only moves one way has passed the logged   *)
(* state i: a path that did can never match it, so TLC stops extending it. *)
Toward(i) ==
    LET t == Logged[i] IN
    /\ opened <= t.opened /\ taken <= t.taken
    /\ goawayRead => t.goawayRead
    /\ closeRead => t.closeRead
    /\ shuttingDown => t.shuttingDown
    /\ firstRequestRead => t.firstRequestRead
    /\ closed # "open" => closed = t.closed
    /\ \A r \in Requests :
        /\ processed[r] => t.processed[r + 1]
        /\ aborted[r] => t.aborted[r + 1]
        /\ outcome[r] # "none" => outcome[r] = t.outcome[r + 1]
        /\ written[r] <= t.written[r + 1]
        /\ PhaseRank(phase[r]) <= PhaseRank(t.phase[r + 1])
        /\ PhaseRank(phase[r]) = 3 => phase[r] = t.phase[r + 1]

(* The CONSTRAINT: a path that has not matched the next logged state in    *)
(* StepsMax steps, or has passed it, is one TLC stops extending.           *)
Within == since <= StepsMax /\ (index < Len(Logged) => Toward(index + 1))

(* The INVARIANT each seed expects violated: the model reached the goal.   *)
Unfinished == index < Goal

=============================================================================
