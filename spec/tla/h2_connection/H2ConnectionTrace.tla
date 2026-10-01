------------------------- MODULE H2ConnectionTrace -------------------------
(***************************************************************************)
(* Trace validation of H2Connection against colibri                       *)
(* (https://github.com/c4milo/colibri/issues/75, decision 104). The        *)
(* simulator's h2 trace run logs every variable of H2Connection after each *)
(* of its steps, and a seed's module gives that log as Trace, a sequence   *)
(* of records whose functions over Streams are sequences, stream 1 first.  *)
(*                                                                         *)
(* One of the run's steps can take several of the model's steps: a         *)
(* delivery reads every frame in flight. So between two logged states the  *)
(* model moves freely, up to StepsMax steps, and the trace advances when    *)
(* the model's state equals the next logged one. The log is a behavior of  *)
(* the model when TLC reaches its last state, so a seed's configuration    *)
(* expects the invariant Unfinished to be violated. A log with a state the *)
(* model cannot reach leaves it holding.                                   *)
(***************************************************************************)
EXTENDS H2Connection

CONSTANTS
    Trace,      \* the logged states, in order
    StepsMax,   \* the model's steps between two logged states, at most
    Goal        \* the logged state TLC must reach: Len(Trace), or less to find where one stops

VARIABLES
    index,      \* the logged state the model last matched
    since       \* the model's steps since then

\* A function over Streams from the sequence the log writes, stream 1 first.
AsFunction(s) == [i \in Streams |-> s[i]]

Matches(i) ==
    LET t == Trace[i] IN
    /\ clientState = AsFunction(t.clientState) /\ clientClosed = AsFunction(t.clientClosed)
    /\ serverState = AsFunction(t.serverState) /\ serverClosed = AsFunction(t.serverClosed)
    /\ request = AsFunction(t.request) /\ requestData = AsFunction(t.requestData)
    /\ response = AsFunction(t.response) /\ responseInterims = AsFunction(t.responseInterims)
    /\ responseData = AsFunction(t.responseData)
    /\ requestRead = AsFunction(t.requestRead) /\ responseRead = AsFunction(t.responseRead)
    /\ toServer = t.toServer /\ toClient = t.toClient
    /\ goawaySent = t.goawaySent /\ goawayCount = t.goawayCount /\ goawayRead = t.goawayRead
    /\ malformed = t.malformed /\ broken = t.broken /\ lateOpen = t.lateOpen
    /\ clientPreface = t.clientPreface /\ serverPreface = t.serverPreface
    /\ clientReadPreface = t.clientReadPreface /\ serverReadPreface = t.serverReadPreface

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

StateRank(s) == CASE s = "idle" -> 0 [] s = "open" -> 1 [] s = "half_closed_local" -> 2
                  [] s = "half_closed_remote" -> 2 [] s = "closed" -> 3
RequestRank(p) == CASE p = "none" -> 0 [] p = "head" -> 1 [] p = "ended" -> 2
ResponseRank(p) == CASE p = "none" -> 0 [] p = "interim" -> 1 [] p = "final" -> 2 [] p = "ended" -> 3

(* No variable the model only moves one way has passed the logged state   *)
(* i: a path that did can never match it, so TLC stops extending it.       *)
Toward(i) ==
    LET t == Trace[i] IN
    /\ goawayCount <= t.goawayCount
    /\ (malformed => t.malformed) /\ (broken => t.broken) /\ (lateOpen => t.lateOpen)
    /\ (clientPreface => t.clientPreface) /\ (serverPreface => t.serverPreface)
    /\ (clientReadPreface => t.clientReadPreface) /\ (serverReadPreface => t.serverReadPreface)
    /\ \A s \in Streams :
        /\ StateRank(clientState[s]) <= StateRank(t.clientState[s])
        /\ StateRank(serverState[s]) <= StateRank(t.serverState[s])
        /\ RequestRank(request[s]) <= RequestRank(t.request[s])
        /\ RequestRank(requestRead[s]) <= RequestRank(t.requestRead[s])
        /\ ResponseRank(response[s]) <= ResponseRank(t.response[s])
        /\ ResponseRank(responseRead[s]) <= ResponseRank(t.responseRead[s])
        /\ requestData[s] <= t.requestData[s] /\ responseData[s] <= t.responseData[s]
        /\ responseInterims[s] <= t.responseInterims[s]

(* The CONSTRAINT: a path that has not matched the next logged state in    *)
(* StepsMax steps, or has passed it, is one TLC stops extending.           *)
Within == since <= StepsMax /\ (index < Len(Trace) => Toward(index + 1))

(* The INVARIANT each seed expects violated: the model reached the goal.   *)
Unfinished == index < Goal

=============================================================================
