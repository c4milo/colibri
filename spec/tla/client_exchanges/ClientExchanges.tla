--------------------------- MODULE ClientExchanges ---------------------------
(***************************************************************************)
(* The exchanges colibri's client carries to one origin (decision 100,     *)
(* design §8 step 17d), for decision 105: each exchange from `request` to  *)
(* its one `finished` event, over the QUIC and TCP connections the client  *)
(* chooses between.                                                        *)
(*                                                                         *)
(* The caller makes up to N exchanges, and may cancel one before its       *)
(* event. The client holds an exchange itself until a connection is open,  *)
(* then hands it to that connection, which writes its request and reads    *)
(* its response. A QUIC stream may read the request's octets again until   *)
(* it closes or is reset (RFC 9000 §3.1), so an exchange whose stream      *)
(* holds its octets is not reported, and a cancel resets its stream (RFC   *)
(* 9114 §4.1.1).                                                           *)
(*                                                                         *)
(* The choice: when an exchange waits and no connection is open, the       *)
(* client opens QUIC first when its policy allows h3. It opens TCP when    *)
(* QUIC is not allowed, when this attempt's QUIC failed, when the fallback *)
(* delay passed during QUIC's handshake, or when a QUIC connection is      *)
(* still ending. The first connection whose handshake completes takes the  *)
(* waiting exchanges, and the other closes. An attempt ends when a         *)
(* handshake completes, or when every transport it may open failed, which  *)
(* ends each waiting exchange refused.                                     *)
(*                                                                         *)
(* A server passes a request to its application, then answers it or resets *)
(* it. It may refuse a request it did not process (RFC 9113 §8.7, RFC 9114 *)
(* §4.1.1) and send a GOAWAY (RFC 9113 §6.8, RFC 9114 §5.2), up to         *)
(* GoawaysMax in all, and its connection may fail. An exchange refused by  *)
(* a connection that takes no new exchange moves to another connection, at *)
(* most MovesMax times, as though it was never sent (RFC 9114 §4.1.1).     *)
(*                                                                         *)
(* The model leaves out what other models cover: the streams of h2 and h3  *)
(* (spec/tla/h2_connection, spec/tla/h3_connection) and QUIC's close       *)
(* (spec/tla/quic_close). Each transport has one connection at a time, as  *)
(* the client's memory holds one of each.                                  *)
(*                                                                         *)
(* Decision 105 checks colibri against this model: step 17d's simulator    *)
(* run logs this model's variables, and TLC must find each seed's log a    *)
(* behavior of Next.                                                       *)
(*                                                                         *)
(* Each rule constant is a rule colibri keeps. A configuration that turns  *)
(* one off must find a violation:                                          *)
(*   ReleaseOnFail      a connection that fails releases the octets of     *)
(*                      every exchange it held. Step 17d's tests found it  *)
(*                      broken before 35dfbde landed.                      *)
(*   CloseWhenDrained   a connection that takes no new exchange closes     *)
(*                      once it holds none. Step 17d's tests found it      *)
(*                      broken before 35dfbde landed.                      *)
(*   ReportWhenReleased an exchange is reported only once no stream holds  *)
(*                      its octets (RFC 9000 §3.1).                        *)
(*   CancelReleases     a cancel resets every direction of the exchange's  *)
(*                      stream still open (RFC 9114 §4.1.1), so nothing    *)
(*                      reads its memory after. colibri broke it for an    *)
(*                      exchange whose response had ended until 89c930d.   *)
(*   SentFailsClosed    a connection that fails ends an exchange it wrote  *)
(*                      `closed`, never `refused`: the server may have     *)
(*                      processed it (RFC 9113 §8.7).                      *)
(*   MoveRefused        an exchange refused by a connection that takes no  *)
(*                      new exchange moves to another one.                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,              \* exchanges the caller makes, 1..N
    Opens,          \* connections each transport opens at most
    MovesMax,       \* times an exchange moves to another connection at most
    QuicPolicy,     \* "first": QUIC before TCP; "learn": QUIC once Alt-Svc named h3; "never"
    HandshakeFails, \* the transports whose handshake may fail
    Breaks,         \* the transports whose open connection may fail
    Goaways,        \* the transports whose server may send a GOAWAY
    GoawaysMax,     \* GOAWAY frames the servers send at most
    Refusals,       \* the transports whose server may refuse a request it did not process
    Resets,         \* the transports whose server may reset a request
    ReleaseOnFail, CloseWhenDrained, ReportWhenReleased, CancelReleases, SentFailsClosed,
    MoveRefused

Transports == {"quic", "tcp"}

ASSUME N \in Nat \ {0} /\ Opens \in Nat \ {0} /\ MovesMax \in Nat /\ GoawaysMax \in Nat
ASSUME QuicPolicy \in {"first", "learn", "never"}
ASSUME \A set \in {HandshakeFails, Breaks, Goaways, Refusals, Resets} : set \subseteq Transports
ASSUME \A rule \in {ReleaseOnFail, CloseWhenDrained, ReportWhenReleased, CancelReleases,
                    SentFailsClosed, MoveRefused} : rule \in BOOLEAN

Exchanges == 1..N
\* An exchange's stage: not made; held by the client, which no connection has given it to;
\* held by a connection, its request not written; written; ended, its event owed; reported;
\* cancelled.
Stages == {"unmade", "waiting", "queued", "sent", "ended", "reported", "cancelled"}
\* A connection's phase: never opened; running its handshake; open, taking exchanges; draining,
\* taking none and carrying those it holds; failed, each exchange it held ended; closed, its
\* `closed` event reported.
Phases == {"none", "handshake", "open", "draining", "failed", "closed"}
\* How an exchange ended on its connection. `failed` stands for each outcome after which the
\* server may have processed the request: `closed`, `reset`, `malformed` and `too_large`.
Outcomes == {"pending", "response", "refused", "failed"}

VARIABLES
    \* Each exchange's stage, the transport of the connection holding it, whether a QUIC stream
    \* may still read its octets, and how it ended there.
    stage, carrier, holds, outcome,
    \* The times it moved, whether the server of the connection holding it processed it, and
    \* how many servers did.
    moved, seen, processed,
    \* Each transport's connection, how many it opened, and the GOAWAY frames the servers sent.
    phase, opens, goaways,
    \* The transports this attempt opened, whether the fallback delay passed during QUIC's
    \* handshake, whether a TCP response named h3 in Alt-Svc (RFC 7838), and whether the caller
    \* shut the client down.
    tried, fallback, learned, shut

exchangeVars == <<stage, carrier, holds, outcome, moved, seen, processed>>
connectionVars == <<phase, opens, goaways, tried, fallback, learned, shut>>
vars == <<exchangeVars, connectionVars>>

TypeOK ==
    /\ stage \in [Exchanges -> Stages]
    /\ carrier \in [Exchanges -> Transports \cup {"none"}]
    /\ holds \in [Exchanges -> BOOLEAN]
    /\ outcome \in [Exchanges -> Outcomes]
    /\ moved \in [Exchanges -> 0..MovesMax]
    /\ seen \in [Exchanges -> BOOLEAN]
    /\ processed \in [Exchanges -> 0..(MovesMax + 1)]
    /\ phase \in [Transports -> Phases]
    /\ opens \in [Transports -> 0..Opens]
    /\ goaways \in 0..GoawaysMax
    /\ tried \subseteq Transports
    /\ fallback \in BOOLEAN /\ learned \in BOOLEAN /\ shut \in BOOLEAN

Init ==
    /\ stage = [e \in Exchanges |-> "unmade"]
    /\ carrier = [e \in Exchanges |-> "none"]
    /\ holds = [e \in Exchanges |-> FALSE]
    /\ outcome = [e \in Exchanges |-> "pending"]
    /\ moved = [e \in Exchanges |-> 0]
    /\ seen = [e \in Exchanges |-> FALSE]
    /\ processed = [e \in Exchanges |-> 0]
    /\ phase = [t \in Transports |-> "none"]
    /\ opens = [t \in Transports |-> 0]
    /\ goaways = 0
    /\ tried = {}
    /\ fallback = FALSE /\ learned = FALSE /\ shut = FALSE

Live(t) == phase[t] \in {"open", "draining"}
Idle(t) == phase[t] \in {"none", "closed"}
Free(t) == Idle(t) /\ opens[t] < Opens
Waiting == {e \in Exchanges : stage[e] = "waiting"}
Held(t) == {e \in Exchanges : carrier[e] = t /\ stage[e] \in {"queued", "sent", "ended"}}
OpenOnes == {t \in Transports : phase[t] = "open"}
QuicAllowed == QuicPolicy = "first" \/ (QuicPolicy = "learn" /\ learned)
\* An exchange waits and no connection is open to take it.
Wanted == Waiting # {} /\ OpenOnes = {}

-----------------------------------------------------------------------------
(* The caller and the exchanges.                                           *)

(* The caller makes exchange e, which the client holds until a connection  *)
(* is open.                                                                *)
Make(e) ==
    /\ stage[e] = "unmade" /\ ~shut
    /\ stage' = [stage EXCEPT ![e] = "waiting"]
    /\ UNCHANGED <<carrier, holds, outcome, moved, seen, processed>>
    /\ UNCHANGED connectionVars

(* The open connection takes a waiting exchange.                           *)
Assign(e, t) ==
    /\ stage[e] = "waiting" /\ phase[t] = "open"
    /\ stage' = [stage EXCEPT ![e] = "queued"]
    /\ carrier' = [carrier EXCEPT ![e] = t]
    /\ UNCHANGED <<holds, outcome, moved, seen, processed>>
    /\ UNCHANGED connectionVars

(* The connection writes the request. Over QUIC, its stream holds the      *)
(* request's octets from now on (RFC 9000 §3.1).                           *)
Send(e) ==
    /\ stage[e] = "queued" /\ Live(carrier[e])
    /\ stage' = [stage EXCEPT ![e] = "sent"]
    /\ holds' = [holds EXCEPT ![e] = (carrier[e] = "quic")]
    /\ UNCHANGED <<carrier, outcome, moved, seen, processed>>
    /\ UNCHANGED connectionVars

(* The QUIC stream closes or is reset, and reads the exchange's octets no  *)
(* more (RFC 9000 §3.1). A server's STOP_SENDING can reset it before the   *)
(* response ends (§3.5).                                                   *)
Release(e) ==
    /\ holds[e] /\ stage[e] \in {"sent", "ended"}
    /\ holds' = [holds EXCEPT ![e] = FALSE]
    /\ UNCHANGED <<stage, carrier, outcome, moved, seen, processed>>
    /\ UNCHANGED connectionVars

(* Whether the client moves exchange e once its connection reports it: the *)
(* connection refused it, takes no new exchange, and e may move again.     *)
Movable(e) ==
    /\ MoveRefused /\ outcome[e] = "refused" /\ moved[e] < MovesMax
    /\ phase[carrier[e]] # "open"

(* The connection reports exchange e's end once no stream holds its        *)
(* octets, and the client passes the event to the caller.                  *)
Deliver(e) ==
    /\ stage[e] = "ended" /\ (ReportWhenReleased => ~holds[e]) /\ ~Movable(e)
    /\ stage' = [stage EXCEPT ![e] = "reported"]
    /\ UNCHANGED <<carrier, holds, outcome, moved, seen, processed>>
    /\ UNCHANGED connectionVars

(* Or the client holds it again for another connection, as though it was   *)
(* never sent (RFC 9114 §4.1.1).                                           *)
MoveOn(e) ==
    /\ stage[e] = "ended" /\ (ReportWhenReleased => ~holds[e]) /\ Movable(e)
    /\ stage' = [stage EXCEPT ![e] = "waiting"]
    /\ carrier' = [carrier EXCEPT ![e] = "none"]
    /\ outcome' = [outcome EXCEPT ![e] = "pending"]
    /\ moved' = [moved EXCEPT ![e] = @ + 1]
    /\ seen' = [seen EXCEPT ![e] = FALSE]
    /\ UNCHANGED <<holds, processed>>
    /\ UNCHANGED connectionVars

(* The caller cancels exchange e before its event, which then never comes. *)
(* Its stream is reset (RFC 9114 §4.1.1), so nothing reads its memory      *)
(* after.                                                                  *)
Cancel(e) ==
    /\ stage[e] \in {"waiting", "queued", "sent", "ended"}
    /\ stage' = [stage EXCEPT ![e] = "cancelled"]
    /\ holds' = [holds EXCEPT ![e] = IF CancelReleases THEN FALSE ELSE @]
    /\ UNCHANGED <<carrier, outcome, moved, seen, processed>>
    /\ UNCHANGED connectionVars

-----------------------------------------------------------------------------
(* The servers.                                                            *)

(* The server passes the request to its application: it processed it       *)
(* (RFC 9114 §4.1.1).                                                      *)
Process(e) ==
    /\ stage[e] = "sent" /\ ~seen[e] /\ Live(carrier[e])
    /\ seen' = [seen EXCEPT ![e] = TRUE]
    /\ processed' = [processed EXCEPT ![e] = @ + 1]
    /\ UNCHANGED <<stage, carrier, holds, outcome, moved>>
    /\ UNCHANGED connectionVars

EndWith(e, how) ==
    /\ stage' = [stage EXCEPT ![e] = "ended"]
    /\ outcome' = [outcome EXCEPT ![e] = how]
    /\ UNCHANGED <<carrier, holds, moved, seen, processed>>
    /\ UNCHANGED connectionVars

(* The response to a processed request arrives whole.                      *)
Respond(e) ==
    /\ stage[e] = "sent" /\ seen[e] /\ Live(carrier[e])
    /\ EndWith(e, "response")

(* The server refuses a request it did not process (RFC 9113 §8.7, RFC     *)
(* 9114 §4.1.1).                                                           *)
Refuse(e) ==
    /\ stage[e] = "sent" /\ ~seen[e] /\ carrier[e] \in Refusals /\ Live(carrier[e])
    /\ EndWith(e, "refused")

(* The server resets the stream, or sends a response the client refuses.   *)
Reset(e) ==
    /\ stage[e] = "sent" /\ carrier[e] \in Resets /\ Live(carrier[e])
    /\ EndWith(e, "failed")

(* The server sends a GOAWAY (RFC 9113 §6.8, RFC 9114 §5.2): connection t  *)
(* takes no new exchange, and ends refused each exchange it has not        *)
(* written and each written one the GOAWAY leaves unprocessed.             *)
Goaway(t, unprocessed) ==
    /\ t \in Goaways /\ Live(t) /\ goaways < GoawaysMax
    /\ unprocessed \subseteq {e \in Held(t) : stage[e] = "sent" /\ ~seen[e]}
    /\ LET ended == {e \in Held(t) : stage[e] = "queued"} \cup unprocessed IN
       /\ stage' = [e \in Exchanges |-> IF e \in ended THEN "ended" ELSE stage[e]]
       /\ outcome' = [e \in Exchanges |-> IF e \in ended THEN "refused" ELSE outcome[e]]
    /\ phase' = [phase EXCEPT ![t] = "draining"]
    /\ goaways' = goaways + 1
    /\ UNCHANGED <<carrier, holds, moved, seen, processed>>
    /\ UNCHANGED <<opens, tried, fallback, learned, shut>>

-----------------------------------------------------------------------------
(* The connections and the choice between them.                            *)

CanOpenQuic ==
    Wanted /\ QuicAllowed /\ "quic" \notin tried /\ Free("quic") /\ phase["tcp"] # "handshake"

CanOpenTcp ==
    /\ Wanted /\ "tcp" \notin tried /\ Free("tcp")
    /\ \/ ~QuicAllowed
       \/ "quic" \in tried /\ phase["quic"] # "handshake"
       \/ phase["quic"] = "handshake" /\ fallback
       \/ ~Free("quic") /\ phase["quic"] # "handshake"

(* The client asks its caller to open transport t, and runs its handshake. *)
Open(t) ==
    /\ IF t = "quic" THEN CanOpenQuic ELSE CanOpenTcp
    /\ phase' = [phase EXCEPT ![t] = "handshake"]
    /\ opens' = [opens EXCEPT ![t] = @ + 1]
    /\ tried' = tried \cup {t}
    /\ UNCHANGED <<goaways, fallback, learned, shut>>
    /\ UNCHANGED exchangeVars

(* The fallback delay passes while QUIC runs its handshake.                *)
Fallback ==
    /\ phase["quic"] = "handshake" /\ ~fallback
    /\ fallback' = TRUE
    /\ UNCHANGED <<phase, opens, goaways, tried, learned, shut>>
    /\ UNCHANGED exchangeVars

(* Connection t's handshake completes. The first one open takes the        *)
(* waiting exchanges and ends the attempt, and one that completes after it *)
(* drains at once.                                                         *)
Handshake(t) ==
    /\ phase[t] = "handshake"
    /\ IF OpenOnes = {}
       THEN /\ phase' = [phase EXCEPT ![t] = "open"]
            /\ tried' = {} /\ fallback' = FALSE
       ELSE /\ phase' = [phase EXCEPT ![t] = "draining"]
            /\ UNCHANGED <<tried, fallback>>
    /\ UNCHANGED <<opens, goaways, learned, shut>>
    /\ UNCHANGED exchangeVars

(* The client abandons a handshake another connection won, or one a client *)
(* the caller shut down has no exchange left for.                          *)
Abandon(t) ==
    /\ phase[t] = "handshake"
    /\ OpenOnes # {} \/ (shut /\ \A e \in Exchanges : stage[e] \in {"unmade", "reported", "cancelled"})
    /\ phase' = [phase EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED exchangeVars

(* Connection t's handshake fails: the server does not answer, TLS refuses *)
(* it, or ALPN selects no protocol the client offered (RFC 9114 §3.1).     *)
FailHandshake(t) ==
    /\ t \in HandshakeFails /\ phase[t] = "handshake"
    /\ phase' = [phase EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED exchangeVars

(* How a connection that fails ends an exchange it holds: `refused` when   *)
(* its request was not written, `failed` when it was (RFC 9113 §8.7).      *)
FailedOutcome(e) == IF stage[e] = "queued" \/ ~SentFailsClosed THEN "refused" ELSE "failed"

(* Open connection t fails: a protocol error, the idle timeout, or the     *)
(* server's close. Each exchange it holds ends, and with ReleaseOnFail its *)
(* streams read no exchange's octets any more.                             *)
Break(t) ==
    /\ t \in Breaks /\ Live(t)
    /\ LET ending == {e \in Held(t) : stage[e] # "ended"} IN
       /\ stage' = [e \in Exchanges |-> IF e \in ending THEN "ended" ELSE stage[e]]
       /\ outcome' = [e \in Exchanges |-> IF e \in ending THEN FailedOutcome(e) ELSE outcome[e]]
    /\ holds' = [e \in Exchanges |-> IF e \in Held(t) /\ ReleaseOnFail THEN FALSE ELSE holds[e]]
    /\ phase' = [phase EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<carrier, moved, seen, processed>>
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>

(* A TCP response names h3 in Alt-Svc (RFC 7838), which the next attempt   *)
(* uses.                                                                   *)
Learn ==
    /\ QuicPolicy = "learn" /\ ~learned /\ Live("tcp")
    /\ learned' = TRUE
    /\ UNCHANGED <<phase, opens, goaways, tried, fallback, shut>>
    /\ UNCHANGED exchangeVars

(* The caller shuts the client down: it takes no new exchange.             *)
Shutdown ==
    /\ ~shut
    /\ shut' = TRUE
    /\ UNCHANGED <<phase, opens, goaways, tried, fallback, learned>>
    /\ UNCHANGED exchangeVars

(* Shut down, an open connection with no exchange waiting drains.          *)
Drain(t) ==
    /\ shut /\ phase[t] = "open" /\ Waiting = {}
    /\ phase' = [phase EXCEPT ![t] = "draining"]
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED exchangeVars

(* Connection t reports `closed` once it holds no exchange: after it       *)
(* failed, or, draining, after its last exchange.                          *)
Close(t) ==
    /\ phase[t] = "failed" \/ (CloseWhenDrained /\ phase[t] = "draining")
    /\ Held(t) = {}
    /\ phase' = [phase EXCEPT ![t] = "closed"]
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED exchangeVars

(* No connection is left to take the waiting exchanges, and the attempt    *)
(* may open no transport. The client ends each waiting exchange refused    *)
(* and reports it itself, and the next exchange starts another attempt.    *)
GiveUp ==
    /\ Waiting # {} /\ \A t \in Transports : Idle(t)
    /\ ~CanOpenQuic /\ ~CanOpenTcp
    /\ stage' = [e \in Exchanges |-> IF e \in Waiting THEN "reported" ELSE stage[e]]
    /\ outcome' = [e \in Exchanges |-> IF e \in Waiting THEN "refused" ELSE outcome[e]]
    /\ tried' = {} /\ fallback' = FALSE
    /\ UNCHANGED <<carrier, holds, moved, seen, processed>>
    /\ UNCHANGED <<phase, opens, goaways, learned, shut>>

-----------------------------------------------------------------------------

Next ==
    \/ \E e \in Exchanges :
        \/ Make(e) \/ Send(e) \/ Release(e) \/ Deliver(e) \/ MoveOn(e) \/ Cancel(e)
        \/ Process(e) \/ Respond(e) \/ Refuse(e) \/ Reset(e)
        \/ \E t \in Transports : Assign(e, t)
    \/ \E t \in Transports :
        \/ Open(t) \/ Handshake(t) \/ Abandon(t) \/ FailHandshake(t) \/ Break(t)
        \/ Drain(t) \/ Close(t)
        \/ \E unprocessed \in SUBSET Exchanges : Goaway(t, unprocessed)
    \/ Fallback \/ Learn \/ Shutdown \/ GiveUp

Spec == Init /\ [][Next]_vars

(* The client, its connections and the servers each take the next step     *)
(* they can: a request is written and answered, a stream closes, a         *)
(* handshake completes, and an event is reported. The caller, a failure,   *)
(* a refusal and a GOAWAY need not come.                                   *)
Fairness ==
    /\ \A e \in Exchanges :
        /\ WF_vars(\E t \in Transports : Assign(e, t))
        /\ WF_vars(Send(e)) /\ WF_vars(Release(e)) /\ WF_vars(Deliver(e)) /\ WF_vars(MoveOn(e))
        /\ WF_vars(Process(e)) /\ WF_vars(Respond(e))
    /\ \A t \in Transports :
        /\ WF_vars(Open(t)) /\ WF_vars(Handshake(t)) /\ WF_vars(Drain(t)) /\ WF_vars(Close(t))
    /\ WF_vars(GiveUp)

FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Safe: nothing reads the memory of an exchange the caller has back, only *)
(* a live QUIC connection's stream holds an exchange's octets, a refused   *)
(* exchange was processed by no server and none is processed by two, and a *)
(* connection closes holding no exchange.                                  *)

Safe ==
    /\ \A e \in Exchanges : stage[e] \in {"reported", "cancelled"} => ~holds[e]
    /\ \A e \in Exchanges : holds[e] => carrier[e] = "quic" /\ Live("quic")
    /\ \A e \in Exchanges : outcome[e] = "refused" => processed[e] = 0
    /\ \A e \in Exchanges : processed[e] <= 1
    /\ \A t \in Transports : phase[t] = "closed" => Held(t) = {}
    /\ Cardinality(OpenOnes) <= 1

(* Every exchange made ends: the caller gets its event, or cancelled it.   *)
Ends == \A e \in Exchanges : stage[e] = "waiting" ~> stage[e] \in {"reported", "cancelled"}

(* Once the caller shuts the client down, every connection closes.         *)
Closes == shut ~> \A t \in Transports : Idle(t)

(* Every exchange made ends in a response, or was cancelled: step 17d's    *)
(* "one completed request per request made", where only QUIC fails.        *)
Completes ==
    \A e \in Exchanges :
        stage[e] = "waiting" ~> \/ stage[e] = "reported" /\ outcome[e] = "response"
                                \/ stage[e] = "cancelled"

=============================================================================
