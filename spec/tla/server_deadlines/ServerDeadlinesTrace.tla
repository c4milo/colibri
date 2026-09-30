------------------------ MODULE ServerDeadlinesTrace ------------------------
(***************************************************************************)
(* Trace validation of ServerDeadlines against colibri                     *)
(* (https://github.com/c4milo/colibri/issues/86). The simulator's deadline *)
(* trace run logs every variable of ServerDeadlines after each of its      *)
(* actions, and three of colibri's clocks: whether the SETTINGS            *)
(* acknowledgment's runs, and each body's rate and each stream's send. A   *)
(* seed's module gives that log as Trace, a sequence of records whose      *)
(* functions over the streams are sequences, stream 1 first.               *)
(*                                                                         *)
(* One of the run's actions can take several of the model's steps: colibri *)
(* writes what it owes and takes content in the call an action makes. So   *)
(* between two logged states the model moves freely, up to StepsMax steps, *)
(* and the trace advances when the model's state equals the next logged    *)
(* one, each clock runs as the model's rule for it says, and colibri has   *)
(* taken all the content the model lets it take. The log is a behavior of  *)
(* the model when TLC reaches its last state, so a seed's configuration    *)
(* expects the invariant Unfinished to be violated. A log with a state the *)
(* model cannot reach, a clock the rules do not run, or content colibri    *)
(* could have taken leaves it holding.                                     *)
(***************************************************************************)
EXTENDS ServerDeadlines

CONSTANTS
    Trace,      \* the logged states, in order
    StepsMax,   \* the model's steps between two logged states, at most
    Goal        \* the logged state TLC must reach: Len(Trace), or less to find where one stops

VARIABLES
    index,      \* the logged state the model last matched
    since,      \* the model's steps since then
    arrived,    \* the frames that arrived at colibri, the preface counting as one
    handedOut   \* the frames colibri's caller handed the socket

counts == <<arrived, handedOut>>

(* The logged states as one value. TLC evaluates the operator a CONSTANT   *)
(* is bound to at each reference, but a definition without arguments once, *)
(* before it starts. A seed logs hundreds of states, and reading Trace     *)
(* itself made TLC's cost per state grow with their number.                *)
Logged == Trace

(* The position of stream s in the sequences the log writes.               *)
At(s) == (s + 1) \div 2

(* A function over the streams from a sequence the log writes.             *)
AsFunction(sequence) == [s \in StreamIds |-> sequence[At(s)]]

Matches(i) ==
    LET t == Logged[i] IN
    /\ reqRead = AsFunction(t.reqRead) /\ resp = AsFunction(t.resp)
    /\ respWritten = AsFunction(t.respWritten) /\ produced = AsFunction(t.produced)
    /\ sendWindow = AsFunction(t.sendWindow) /\ sendConnection = t.sendConnection
    /\ released = AsFunction(t.released) /\ releasedConnection = t.releasedConnection
    /\ acksOwed = t.acksOwed /\ connectionOwed = t.connectionOwed /\ streamOwed = t.streamOwed
    /\ out = t.out
    /\ firstRequestRead = t.firstRequestRead /\ idleStarted = t.idleStarted
    /\ settingsAcked = t.settingsAcked /\ smallIncrement = t.smallIncrement
    /\ toClient = t.toClient /\ toServer = t.toServer
    /\ cliReq = AsFunction(t.cliReq) /\ cliSent = AsFunction(t.cliSent)
    /\ cliWindow = AsFunction(t.cliWindow) /\ cliConnection = t.cliConnection
    /\ cliResp = AsFunction(t.cliResp) /\ cliReleased = AsFunction(t.cliReleased)
    /\ cliReleasedConnection = t.cliReleasedConnection
    /\ cliAcksOwed = t.cliAcksOwed /\ cliConnectionOwed = t.cliConnectionOwed
    /\ cliStreamOwed = t.cliStreamOwed
    /\ arrived = t.arrived /\ handedOut = t.handedOut
    \* The run offers write_body the rest of each response after every action, so colibri has
    \* taken all the content it can, and the model's colibri has none left to take.
    /\ \A s \in StreamIds : ~ENABLED WriteData(s)
    \* colibri's clocks run exactly when the model's rules say they do.
    /\ SettingsRuns = t.settingsRuns
    /\ \A s \in StreamIds : BodyRuns(s) = t.bodyRuns[At(s)] /\ SendRuns(s) = t.sendRuns[At(s)]

TraceInit == Init /\ arrived = 0 /\ handedOut = 0 /\ Matches(1) /\ index = 1 /\ since = 0

(* The model's state is the next logged one, so the trace moves on.       *)
Advance ==
    /\ index < Len(Logged) /\ Matches(index + 1)
    /\ index' = index + 1 /\ since' = 0
    /\ UNCHANGED <<vars, counts>>

(* One of the model's steps toward the next logged state. Only Arrive     *)
(* takes a frame from toServer, and only Send puts one in toClient.       *)
Move ==
    /\ index < Len(Logged) /\ Next
    /\ since' = since + 1
    /\ arrived' = arrived + (IF Len(toServer') < Len(toServer) THEN 1 ELSE 0)
    /\ handedOut' = handedOut + (IF Len(toClient') > Len(toClient) THEN 1 ELSE 0)
    /\ UNCHANGED index

TraceSpec == TraceInit /\ [][Advance \/ Move]_<<vars, counts, index, since>>

PartRank(p) == CASE p = "none" -> 0 [] p = "head" -> 1 [] p = "ended" -> 2

(* No variable the model only moves one way has passed the logged state   *)
(* i: a path that did can never match it, so TLC stops extending it.       *)
Toward(i) ==
    LET t == Logged[i] IN
    /\ firstRequestRead => t.firstRequestRead
    /\ settingsAcked => t.settingsAcked
    /\ smallIncrement => t.smallIncrement
    \* Every frame each side has read, and has written, only grows.
    /\ arrived <= t.arrived /\ handedOut <= t.handedOut
    /\ arrived + Len(toServer) <= t.arrived + Len(t.toServer)
    /\ handedOut + Len(out) <= t.handedOut + Len(t.out)
    /\ handedOut - Len(toClient) <= t.handedOut - Len(t.toClient)
    /\ \A s \in StreamIds :
        /\ PartRank(reqRead[s]) <= PartRank(t.reqRead[At(s)])
        /\ PartRank(resp[s]) <= PartRank(t.resp[At(s)])
        /\ PartRank(cliReq[s]) <= PartRank(t.cliReq[At(s)])
        /\ PartRank(cliResp[s]) <= PartRank(t.cliResp[At(s)])
        /\ respWritten[s] <= t.respWritten[At(s)] /\ produced[s] <= t.produced[At(s)]
        /\ cliSent[s] <= t.cliSent[At(s)]

(* The CONSTRAINT: a path that has not matched the next logged state in    *)
(* StepsMax steps, or has passed it, is one TLC stops extending.           *)
Within == since <= StepsMax /\ (index < Len(Logged) => Toward(index + 1))

(* The INVARIANT each seed expects violated: the model reached the goal.   *)
Unfinished == index < Goal

=============================================================================
