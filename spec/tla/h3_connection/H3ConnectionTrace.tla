------------------------- MODULE H3ConnectionTrace -------------------------
(***************************************************************************)
(* Trace validation of H3Connection against colibri                       *)
(* (https://github.com/c4milo/colibri/issues/58). The simulator's h3 trace *)
(* run logs every variable of H3Connection after each of its steps, and a  *)
(* seed's module gives that log as Trace, a sequence of records whose      *)
(* functions over Requests are sequences, request 0 first.                 *)
(*                                                                         *)
(* One simulator step can take several of the model's steps, so between    *)
(* two logged states the model moves freely, up to StepsMax steps, and the *)
(* trace advances when the model's state equals the next logged one. The   *)
(* log is a behavior of the model when TLC reaches its last state, so a    *)
(* seed's configuration expects the invariant Unfinished to be violated.   *)
(* A log with a state the model cannot reach leaves it holding.            *)
(***************************************************************************)
EXTENDS H3Connection

CONSTANTS
    Trace,      \* the logged states, in order
    StepsMax,   \* the model's steps between two logged states, at most
    Goal        \* the logged state TLC must reach: Len(Trace), or less to find where one stops

VARIABLES
    index,      \* the logged state the model last matched
    since       \* the model's steps since then

\* A function over Requests from the sequence the log writes, request 0 first.
AsFunction(s) == [r \in Requests |-> s[r + 1]]

Matches(i) ==
    LET t == Trace[i] IN
    /\ opened = t.opened /\ inserted = t.inserted /\ known = t.known
    /\ ric = AsFunction(t.ric) /\ outstanding = AsFunction(t.outstanding)
    /\ encoderQueued = t.encoderQueued /\ requestQueued = AsFunction(t.requestQueued)
    /\ encoderSent = t.encoderSent /\ requestSent = AsFunction(t.requestSent)
    /\ connectionLimit = t.connectionLimit /\ encoderLimit = t.encoderLimit
    /\ settingsReceived = t.settingsReceived /\ goawayReceived = t.goawayReceived
    /\ outcome = AsFunction(t.outcome) /\ reset = AsFunction(t.reset)
    /\ taken = t.taken /\ phase = AsFunction(t.phase)
    /\ processed = AsFunction(t.processed) /\ consumed = AsFunction(t.consumed)
    /\ encoderConsumed = t.encoderConsumed /\ decoderKnown = t.decoderKnown
    /\ decoderStream = t.decoderStream /\ toClient = AsFunction(t.toClient)
    /\ goawaySent = t.goawaySent /\ goawayCount = t.goawayCount
    /\ control = t.control /\ controlEnded = t.controlEnded /\ broken = t.broken

TraceInit == Init /\ Matches(1) /\ index = 1 /\ since = 0

(* The model's state is the next logged one, so the trace moves on.       *)
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

ResetRank(value) == CASE value = "none" -> 0 [] value = "sent" -> 1
                      [] value = "arrived" -> 2 [] value = "read" -> 3

(* No variable the model only moves one way has passed the logged state   *)
(* i: a path that did can never match it, so TLC stops extending it.       *)
Toward(i) ==
    LET t == Trace[i] IN
    /\ opened <= t.opened /\ inserted <= t.inserted /\ known <= t.known
    /\ encoderSent <= t.encoderSent /\ taken <= t.taken
    /\ encoderConsumed <= t.encoderConsumed /\ decoderKnown <= t.decoderKnown
    /\ connectionLimit <= t.connectionLimit /\ encoderLimit <= t.encoderLimit
    /\ goawayCount <= t.goawayCount /\ goawaySent >= t.goawaySent
    /\ goawayReceived >= t.goawayReceived /\ (settingsReceived => t.settingsReceived)
    /\ \A r \in Requests :
        /\ requestSent[r] <= t.requestSent[r + 1] /\ consumed[r] <= t.consumed[r + 1]
        /\ (processed[r] => t.processed[r + 1])
        /\ outcome[r] \in {"none", t.outcome[r + 1]}
        /\ ResetRank(reset[r]) <= ResetRank(t.reset[r + 1])

(* The CONSTRAINT: a path that has not matched the next logged state in    *)
(* StepsMax steps, or has passed it, is one TLC stops extending.           *)
Within == since <= StepsMax /\ (index < Len(Trace) => Toward(index + 1))

(* The INVARIANT each seed expects violated: the model reached the goal.   *)
Unfinished == index < Goal

=============================================================================
