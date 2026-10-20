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
(* still ending, and only when it speaks a version TCP carries (RFC 9114   *)
(* §3.1). The first connection whose handshake completes takes the         *)
(* waiting exchanges, and the other closes. An attempt ends when a         *)
(* connection takes the waiting exchanges, or when every transport it may  *)
(* open failed, which ends each waiting exchange refused.                  *)
(*                                                                         *)
(* A QUIC connection holding no exchange can sit idle until near its idle  *)
(* timeout, after which the client gives it no new exchange and it drains  *)
(* (RFC 9114 §5.1, design §8 step 17g). One holding an exchange sends a    *)
(* PING then (RFC 9000 §10.1.2), so the timeout never ends it. A           *)
(* connection the timeout reaches ends as a failed one does.               *)
(*                                                                         *)
(* A server passes a request to its application, then answers it or resets *)
(* it. It may refuse a request it did not process (RFC 9113 §8.7, RFC 9114 *)
(* §4.1.1) and send a GOAWAY (RFC 9113 §6.8, RFC 9114 §5.2), up to         *)
(* GoawaysMax in all, and its connection may fail. An exchange refused by  *)
(* a connection that takes no new exchange moves to another connection, as *)
(* though it was never sent (RFC 9114 §4.1.1). An idempotent exchange      *)
(* whose connection closed before any of its response arrived moves too    *)
(* (RFC 9110 §9.2.2, decision 124), and a server may then process it a     *)
(* second time. Both moves count against one budget: MovesMax in all.      *)
(*                                                                         *)
(* The model leaves out what other models cover: the streams of h2 and h3  *)
(* (spec/tla/h2_connection, spec/tla/h3_connection) and QUIC's close       *)
(* (spec/tla/quic_close).                                                  *)
(*                                                                         *)
(* A pool (decision 125) holds one QUIC connection and a TCP connection in *)
(* each slot of TcpSlots, one at a time in each. A TCP connection holds    *)
(* TcpCapacity exchanges at once: one for h11. h11 has no way to end one   *)
(* exchange alone, so with TcpDrops a cancel leaves the TCP connection     *)
(* reading the rest of the response, which it drops, and it has no room    *)
(* for that exchange until then. Once TCP carries the exchanges, another   *)
(* TCP slot opens when an exchange waits and no open connection has room   *)
(* for it. A QUIC connection holds every exchange, and while one carries   *)
(* them no TCP slot opens. An attempt also ends when an open connection    *)
(* takes a waiting exchange, so each slot opens once at most for each      *)
(* wait.                                                                   *)
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
(*   RetireStale        a QUIC connection that held no exchange until near *)
(*                      its idle timeout drains at once, so it takes no    *)
(*                      new exchange (RFC 9114 §5.1).                      *)
(*   KeepAlive          a QUIC connection holding an exchange sends a PING *)
(*                      before its idle timeout (RFC 9000 §10.1.2), so it  *)
(*                      never goes quiet until the timeout.                *)
(*   TakeAtHandshake    the connection whose handshake completes first     *)
(*                      takes every waiting exchange in that step, so a    *)
(*                      handshake ends an attempt only on a connection     *)
(*                      that carries the exchanges it was opened for. One  *)
(*                      that fails, or takes no new exchange, in the call  *)
(*                      that completes its handshake is a failed           *)
(*                      handshake, and its attempt goes on. colibri        *)
(*                      reopened such a transport without bound until step *)
(*                      21c.                                               *)
(*   TcpWhenAllowed     TCP opens only when the client speaks h11 or h2    *)
(*                      (RFC 9114 §3.1). Until step 21c a client that      *)
(*                      spoke h3 alone still asked for TCP.                *)
(*   ResendIdempotent   only an idempotent exchange moves after its        *)
(*                      connection closed before any of its response       *)
(*                      arrived (RFC 9110 §9.2.2, decision 124).           *)
(*   OneBudget          a move after a close and a move after a refusal    *)
(*                      count against one budget, MovesMax (decision 124). *)
(*                      A mutant in mutants/ turns each of the two off.    *)
(*   TakeWithinRoom     a connection takes no more exchanges than it holds *)
(*                      at once (decision 125).                            *)
(*   TryOncePerWait     a TCP slot opens once at most in each attempt, so  *)
(*                      a slot that fails is not opened again until an     *)
(*                      exchange leaves the wait (decision 125). A mutant  *)
(*                      in mutants/ turns each of the two off.             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,              \* exchanges the caller makes, 1..N
    Opens,          \* connections each transport opens at most
    MovesMax,       \* times an exchange moves to another connection at most
    QuicPolicy,     \* "first": QUIC before TCP; "learn": QUIC once Alt-Svc named h3; "never"
    TcpAllowed,     \* whether the client speaks a version TCP carries (decision 117)
    HandshakeFails, \* the transports whose handshake may fail
    Breaks,         \* the transports whose open connection may fail
    Goaways,        \* the transports whose server may send a GOAWAY
    GoawaysMax,     \* GOAWAY frames the servers send at most
    Refusals,       \* the transports whose server may refuse a request it did not process
    Resets,         \* the transports whose server may reset a request
    Idempotent,     \* the exchanges whose method is idempotent (RFC 9110 §9.2.2)
    TcpSlots,       \* the pool's TCP slots, each named apart from "quic" (decision 125)
    TcpCapacity,    \* the exchanges a TCP connection holds at once
    TcpDrops,       \* whether a TCP connection reads a cancelled response to its end, as h11 does
    ReleaseOnFail, CloseWhenDrained, ReportWhenReleased, CancelReleases, SentFailsClosed,
    MoveRefused, RetireStale, KeepAlive, TakeAtHandshake, TcpWhenAllowed, ResendIdempotent,
    OneBudget, TakeWithinRoom, TryOncePerWait

\* The connections a pool holds: its QUIC connection and one in each TCP slot. Each is named
\* after its slot, as a transport is: "quic", and each TCP slot's name.
Transports == {"quic"} \cup TcpSlots

ASSUME N \in Nat \ {0} /\ Opens \in Nat \ {0} /\ MovesMax \in Nat /\ GoawaysMax \in Nat
ASSUME TcpSlots # {} /\ "quic" \notin TcpSlots /\ TcpCapacity \in Nat \ {0}
ASSUME QuicPolicy \in {"first", "learn", "never"}
ASSUME TcpAllowed \in BOOLEAN /\ TcpDrops \in BOOLEAN
ASSUME \A set \in {HandshakeFails, Breaks, Goaways, Refusals, Resets} : set \subseteq Transports
ASSUME \A rule \in {ReleaseOnFail, CloseWhenDrained, ReportWhenReleased, CancelReleases,
                    SentFailsClosed, MoveRefused, RetireStale, KeepAlive,
                    TakeAtHandshake, TcpWhenAllowed, ResendIdempotent,
                    OneBudget, TakeWithinRoom, TryOncePerWait} : rule \in BOOLEAN

Exchanges == 1..N
ASSUME Idempotent \subseteq Exchanges
\* An exchange's stage: not made; held by the client, which no connection has given it to;
\* held by a connection, its request not written; written; ended, its event owed; reported;
\* cancelled.
Stages == {"unmade", "waiting", "queued", "sent", "ended", "reported", "cancelled"}
\* A connection's phase: never opened; running its handshake; open, taking exchanges; draining,
\* taking none and carrying those it holds; failed, each exchange it held ended; closed, its
\* `closed` event reported.
Phases == {"none", "handshake", "open", "draining", "failed", "closed"}
\* How an exchange ended on its connection. `closed`: the connection ended before the response
\* was whole. `failed` stands for each other outcome after which the server may have processed
\* the request: `reset`, `malformed` and `too_large`.
Outcomes == {"pending", "response", "refused", "closed", "failed"}

VARIABLES
    \* Each exchange's stage, the transport of the connection holding it, whether a QUIC stream
    \* may still read its octets, and how it ended there.
    stage, carrier, holds, outcome,
    \* The times it moved, whether the server of the connection holding it processed it, and
    \* how many servers did.
    moved, seen, processed,
    \* Whether any of its response arrived on the connection holding it before the response was
    \* whole, whether the client sent it again after a connection closed before that, and, once
    \* cancelled, whether its TCP connection still reads its response to drop it.
    answered, resent, drops,
    \* Each transport's connection, how many it opened, and the GOAWAY frames the servers sent.
    phase, opens, goaways,
    \* The transports this attempt opened, whether the fallback delay passed during QUIC's
    \* handshake, whether a TCP response named h3 in Alt-Svc (RFC 7838), and whether the caller
    \* shut the client down.
    tried, fallback, learned, shut,
    \* Whether the QUIC connection held no exchange until near its idle timeout, and whether it
    \* held one and heard nothing until then (RFC 9000 §10.1).
    stale, quiet

exchangeVars == <<stage, carrier, holds, outcome, moved, seen, processed, answered, resent, drops>>
idleVars == <<stale, quiet>>
connectionVars == <<phase, opens, goaways, tried, fallback, learned, shut, stale, quiet>>
vars == <<exchangeVars, connectionVars>>

TypeOK ==
    /\ stage \in [Exchanges -> Stages]
    /\ carrier \in [Exchanges -> Transports \cup {"none"}]
    /\ holds \in [Exchanges -> BOOLEAN]
    /\ outcome \in [Exchanges -> Outcomes]
    /\ moved \in [Exchanges -> 0..(MovesMax + 1)]
    /\ seen \in [Exchanges -> BOOLEAN]
    /\ processed \in [Exchanges -> 0..(MovesMax + 2)]
    /\ answered \in [Exchanges -> BOOLEAN]
    /\ resent \in [Exchanges -> BOOLEAN]
    /\ drops \in [Exchanges -> BOOLEAN]
    /\ phase \in [Transports -> Phases]
    /\ opens \in [Transports -> 0..Opens]
    /\ goaways \in 0..GoawaysMax
    /\ tried \subseteq Transports
    /\ fallback \in BOOLEAN /\ learned \in BOOLEAN /\ shut \in BOOLEAN
    /\ stale \in BOOLEAN /\ quiet \in BOOLEAN

Init ==
    /\ stage = [e \in Exchanges |-> "unmade"]
    /\ carrier = [e \in Exchanges |-> "none"]
    /\ holds = [e \in Exchanges |-> FALSE]
    /\ outcome = [e \in Exchanges |-> "pending"]
    /\ moved = [e \in Exchanges |-> 0]
    /\ seen = [e \in Exchanges |-> FALSE]
    /\ processed = [e \in Exchanges |-> 0]
    /\ answered = [e \in Exchanges |-> FALSE]
    /\ resent = [e \in Exchanges |-> FALSE]
    /\ drops = [e \in Exchanges |-> FALSE]
    /\ phase = [t \in Transports |-> "none"]
    /\ opens = [t \in Transports |-> 0]
    /\ goaways = 0
    /\ tried = {}
    /\ fallback = FALSE /\ learned = FALSE /\ shut = FALSE
    /\ stale = FALSE /\ quiet = FALSE

Live(t) == phase[t] \in {"open", "draining"}
Idle(t) == phase[t] \in {"none", "closed"}
Free(t) == Idle(t) /\ opens[t] < Opens
Waiting == {e \in Exchanges : stage[e] = "waiting"}
Held(t) == {e \in Exchanges : carrier[e] = t /\ stage[e] \in {"queued", "sent", "ended"}}
\* The cancelled exchanges whose response connection t still reads to drop it.
Dropping(t) == {e \in Exchanges : carrier[e] = t /\ drops[e]}
OpenOnes == {t \in Transports : phase[t] = "open"}
QuicAllowed == QuicPolicy = "first" \/ (QuicPolicy = "learn" /\ learned)
\* The exchanges connection t holds at once at most, and whether it has room for one more.
Capacity(t) == IF t = "quic" THEN N ELSE TcpCapacity
Room(t) == Cardinality(Held(t) \cup Dropping(t)) < Capacity(t)
\* TCP carries the exchanges: a TCP connection is open, and the QUIC connection is not.
TcpCarries == OpenOnes # {} /\ OpenOnes \subseteq TcpSlots
\* An exchange waits and no open connection has room for it.
Wanted == Waiting # {} /\ \A t \in OpenOnes : ~Room(t)

-----------------------------------------------------------------------------
(* The caller and the exchanges.                                           *)

(* The caller makes exchange e, which the client holds until a connection  *)
(* is open.                                                                *)
Make(e) ==
    /\ stage[e] = "unmade" /\ ~shut
    /\ stage' = [stage EXCEPT ![e] = "waiting"]
    /\ UNCHANGED <<carrier, holds, outcome, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED connectionVars

(* An open connection with room takes an exchange made while it is open,   *)
(* or one that waited for its room. Without TakeAtHandshake it also takes, *)
(* one step at a time, each exchange that waited for its handshake. The    *)
(* exchange leaves the wait, which ends the attempt.                       *)
Assign(e, t) ==
    /\ stage[e] = "waiting" /\ phase[t] = "open" /\ (TakeWithinRoom => Room(t))
    /\ stage' = [stage EXCEPT ![e] = "queued"]
    /\ carrier' = [carrier EXCEPT ![e] = t]
    /\ tried' = {}
    /\ UNCHANGED <<holds, outcome, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED <<phase, opens, goaways, fallback, learned, shut, stale, quiet>>

(* The connection writes the request. Over QUIC, its stream holds the      *)
(* request's octets from now on (RFC 9000 §3.1).                           *)
Send(e) ==
    /\ stage[e] = "queued" /\ Live(carrier[e])
    /\ stage' = [stage EXCEPT ![e] = "sent"]
    /\ holds' = [holds EXCEPT ![e] = (carrier[e] = "quic")]
    /\ UNCHANGED <<carrier, outcome, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED connectionVars

(* The QUIC stream closes or is reset, and reads the exchange's octets no  *)
(* more (RFC 9000 §3.1). A server's STOP_SENDING can reset it before the   *)
(* response ends (§3.5).                                                   *)
Release(e) ==
    /\ holds[e] /\ stage[e] \in {"sent", "ended"}
    /\ holds' = [holds EXCEPT ![e] = FALSE]
    /\ UNCHANGED <<stage, carrier, outcome, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED connectionVars

(* The connection refused exchange e unprocessed (RFC 9113 §8.7).          *)
RefusedMove(e) == MoveRefused /\ outcome[e] = "refused"

(* The connection closed before any of e's response arrived, and e's       *)
(* method is idempotent (RFC 9110 §9.2.2, RFC 9112 §9.3.1).                *)
ClosedMove(e) ==
    /\ outcome[e] = "closed" /\ ~answered[e]
    /\ ResendIdempotent => e \in Idempotent

(* Whether the client moves exchange e once its connection reports it: the *)
(* connection refused it or closed before its response, takes no new       *)
(* exchange, and e may move again. With OneBudget both moves count against *)
(* MovesMax; without, a move after a close has a budget of its own.        *)
Movable(e) ==
    /\ RefusedMove(e) \/ ClosedMove(e)
    /\ IF OneBudget \/ RefusedMove(e) THEN moved[e] < MovesMax ELSE ~resent[e]
    /\ phase[carrier[e]] # "open"

(* The connection reports exchange e's end once no stream holds its        *)
(* octets, and the client passes the event to the caller. One the client   *)
(* sent again that a later connection refused ends closed: the first       *)
(* server may have processed it.                                           *)
Deliver(e) ==
    /\ stage[e] = "ended" /\ (ReportWhenReleased => ~holds[e]) /\ ~Movable(e)
    /\ stage' = [stage EXCEPT ![e] = "reported"]
    /\ outcome' = [outcome EXCEPT ![e] = IF resent[e] /\ @ = "refused" THEN "closed" ELSE @]
    /\ UNCHANGED <<carrier, holds, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED connectionVars

(* Or the client holds it again for another connection: as though it was   *)
(* never sent (RFC 9114 §4.1.1), or sent again (RFC 9110 §9.2.2).          *)
MoveOn(e) ==
    /\ stage[e] = "ended" /\ (ReportWhenReleased => ~holds[e]) /\ Movable(e)
    /\ stage' = [stage EXCEPT ![e] = "waiting"]
    /\ carrier' = [carrier EXCEPT ![e] = "none"]
    /\ outcome' = [outcome EXCEPT ![e] = "pending"]
    /\ moved' = [moved EXCEPT ![e] = @ + 1]
    /\ seen' = [seen EXCEPT ![e] = FALSE]
    /\ answered' = [answered EXCEPT ![e] = FALSE]
    /\ resent' = [resent EXCEPT ![e] = @ \/ outcome[e] = "closed"]
    /\ UNCHANGED <<holds, processed, drops>>
    /\ UNCHANGED connectionVars

(* The caller cancels exchange e before its event, which then never comes. *)
(* Its stream is reset (RFC 9114 §4.1.1), so nothing reads its memory      *)
(* after. With TcpDrops, a TCP connection that wrote its request reads the *)
(* rest of its response and drops it, and the exchange keeps its room      *)
(* until then.                                                             *)
Cancel(e) ==
    /\ stage[e] \in {"waiting", "queued", "sent", "ended"}
    /\ stage' = [stage EXCEPT ![e] = "cancelled"]
    /\ holds' = [holds EXCEPT ![e] = IF CancelReleases THEN FALSE ELSE @]
    /\ drops' = [drops EXCEPT ![e] = TcpDrops /\ stage[e] = "sent" /\ carrier[e] \in TcpSlots]
    /\ UNCHANGED <<carrier, outcome, moved, seen, processed, answered, resent>>
    /\ UNCHANGED connectionVars

(* The response to cancelled exchange e ends, and its TCP connection drops *)
(* it, which frees the exchange's room.                                    *)
Drop(e) ==
    /\ drops[e] /\ seen[e] /\ Live(carrier[e])
    /\ drops' = [drops EXCEPT ![e] = FALSE]
    /\ UNCHANGED <<stage, carrier, holds, outcome, moved, seen, processed, answered, resent>>
    /\ UNCHANGED connectionVars

-----------------------------------------------------------------------------
(* The servers.                                                            *)

(* The server passes the request to its application: it processed it       *)
(* (RFC 9114 §4.1.1). A request the caller cancelled may still reach the   *)
(* server before the cancel does, while its connection lives.              *)
Process(e) ==
    /\ \/ stage[e] = "sent"
       \/ stage[e] = "cancelled" /\ outcome[e] = "pending" /\ carrier[e] # "none"
    /\ ~seen[e] /\ Live(carrier[e])
    /\ seen' = [seen EXCEPT ![e] = TRUE]
    /\ processed' = [processed EXCEPT ![e] = @ + 1]
    /\ UNCHANGED <<stage, carrier, holds, outcome, moved, answered, resent, drops>>
    /\ UNCHANGED connectionVars

(* The first of the response to a processed request arrives, and the rest  *)
(* has not: over h11 an octet of it, over h2 and h3 a HEADERS frame.       *)
Answer(e) ==
    /\ stage[e] = "sent" /\ seen[e] /\ ~answered[e] /\ Live(carrier[e])
    /\ answered' = [answered EXCEPT ![e] = TRUE]
    /\ UNCHANGED <<stage, carrier, holds, outcome, moved, seen, processed, resent, drops>>
    /\ UNCHANGED connectionVars

EndWith(e, how) ==
    /\ stage' = [stage EXCEPT ![e] = "ended"]
    /\ outcome' = [outcome EXCEPT ![e] = how]
    /\ UNCHANGED <<carrier, holds, moved, seen, processed, answered, resent, drops>>
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
    /\ UNCHANGED <<carrier, holds, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED <<opens, tried, fallback, learned, shut>>
    /\ UNCHANGED idleVars

-----------------------------------------------------------------------------
(* The connections and the choice between them.                            *)

\* The TCP slots whose handshake runs.
TcpOpening == {t \in TcpSlots : phase[t] = "handshake"}

CanOpenQuic ==
    /\ Wanted /\ QuicAllowed /\ "quic" \notin tried /\ Free("quic")
    /\ OpenOnes = {} /\ TcpOpening = {}

(* TCP slot t opens when an exchange waits, as the attempt allows: after   *)
(* QUIC as above, or once TCP carries the exchanges. Until TCP carries     *)
(* them, one TCP handshake runs at a time, so the client learns whether    *)
(* ALPN picks h2 first (RFC 9113 §9.1). A slot opens only while more       *)
(* exchanges wait than the TCP handshakes running will take.               *)
CanOpenTcp(t) ==
    /\ Wanted /\ (TryOncePerWait => t \notin tried) /\ Free(t)
    /\ (TcpWhenAllowed => TcpAllowed)
    /\ TcpOpening = {} \/ TcpCarries
    /\ Cardinality(TcpOpening) * TcpCapacity < Cardinality(Waiting)
    /\ \/ ~QuicAllowed
       \/ "quic" \in tried /\ phase["quic"] # "handshake"
       \/ phase["quic"] = "handshake" /\ fallback
       \/ ~Free("quic") /\ phase["quic"] # "handshake"
       \/ TcpCarries

(* The client asks its caller to open connection t, and runs its           *)
(* handshake.                                                              *)
Open(t) ==
    /\ IF t = "quic" THEN CanOpenQuic ELSE CanOpenTcp(t)
    /\ phase' = [phase EXCEPT ![t] = "handshake"]
    /\ opens' = [opens EXCEPT ![t] = @ + 1]
    /\ tried' = tried \cup {t}
    /\ UNCHANGED <<goaways, fallback, learned, shut>>
    /\ UNCHANGED idleVars
    /\ UNCHANGED exchangeVars

(* The fallback delay passes while QUIC runs its handshake.                *)
Fallback ==
    /\ phase["quic"] = "handshake" /\ ~fallback
    /\ fallback' = TRUE
    /\ UNCHANGED <<phase, opens, goaways, tried, learned, shut>>
    /\ UNCHANGED idleVars
    /\ UNCHANGED exchangeVars

\* The waiting exchanges a connection whose handshake completes takes: with TakeAtHandshake as
\* many as it holds at once, and without, none.
Takes(t) ==
    IF TakeAtHandshake
    THEN LET count == IF Cardinality(Waiting) < Capacity(t) THEN Cardinality(Waiting) ELSE Capacity(t)
         IN {taken \in SUBSET Waiting : Cardinality(taken) = count}
    ELSE {{}}

(* Connection t's handshake completes. The first one open ends the attempt *)
(* and, with TakeAtHandshake, takes the waiting exchanges it has room for  *)
(* in the same step. So does a TCP connection while TCP carries the        *)
(* exchanges. One of the other transport drains at once.                   *)
Handshake(t) ==
    /\ phase[t] = "handshake"
    /\ IF OpenOnes = {} \/ (t \in TcpSlots /\ TcpCarries)
       THEN /\ phase' = [phase EXCEPT ![t] = "open"]
            /\ tried' = {} /\ fallback' = FALSE
            /\ \E taken \in Takes(t) :
               /\ stage' = [e \in Exchanges |-> IF e \in taken THEN "queued" ELSE stage[e]]
               /\ carrier' = [e \in Exchanges |-> IF e \in taken THEN t ELSE carrier[e]]
       ELSE /\ phase' = [phase EXCEPT ![t] = "draining"]
            /\ UNCHANGED <<tried, fallback, stage, carrier>>
    /\ UNCHANGED <<holds, outcome, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED <<opens, goaways, learned, shut>>
    /\ UNCHANGED idleVars

\* A connection of the other transport is open: QUIC beside an open TCP one, or TCP beside QUIC.
OtherOpen(t) == IF t = "quic" THEN OpenOnes \cap TcpSlots # {} ELSE "quic" \in OpenOnes

(* The client abandons a handshake a connection of the other transport     *)
(* won, or one a client the caller shut down has no exchange left for.     *)
Abandon(t) ==
    /\ phase[t] = "handshake"
    /\ OtherOpen(t) \/ (shut /\ \A e \in Exchanges : stage[e] \in {"unmade", "reported", "cancelled"})
    /\ phase' = [phase EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED idleVars
    /\ UNCHANGED exchangeVars

(* Connection t's handshake fails: the server does not answer, TLS refuses *)
(* it, or ALPN selects no protocol the client offered (RFC 9114 §3.1). It  *)
(* also fails when the connection fails, or its server says it takes no    *)
(* request, in the flight that completes the handshake: the connection     *)
(* carried nothing, and its transport stays in the attempt.                *)
FailHandshake(t) ==
    /\ t \in HandshakeFails /\ phase[t] = "handshake"
    /\ phase' = [phase EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED idleVars
    /\ UNCHANGED exchangeVars

(* How a connection that fails ends an exchange it holds: `refused` when   *)
(* its request was not written, `closed` when it was (RFC 9113 §8.7).      *)
FailedOutcome(e) == IF stage[e] = "queued" \/ ~SentFailsClosed THEN "refused" ELSE "closed"

(* Live connection t fails. Each exchange it holds ends, with              *)
(* ReleaseOnFail its streams read no exchange's octets any more, and it    *)
(* drops no response.                                                      *)
Fail(t) ==
    /\ LET ending == {e \in Held(t) : stage[e] # "ended"} IN
       /\ stage' = [e \in Exchanges |-> IF e \in ending THEN "ended" ELSE stage[e]]
       /\ outcome' = [e \in Exchanges |-> IF e \in ending THEN FailedOutcome(e) ELSE outcome[e]]
    /\ holds' = [e \in Exchanges |-> IF e \in Held(t) /\ ReleaseOnFail THEN FALSE ELSE holds[e]]
    /\ drops' = [e \in Exchanges |-> drops[e] /\ carrier[e] # t]
    /\ phase' = [phase EXCEPT ![t] = "failed"]
    /\ UNCHANGED <<carrier, moved, seen, processed, answered, resent>>
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED idleVars

(* Open connection t fails: a protocol error or the server's close.        *)
Break(t) == t \in Breaks /\ Live(t) /\ Fail(t)

(* The QUIC connection holds no exchange until near its idle timeout (RFC  *)
(* 9114 §5.1). An open connection takes a waiting exchange at once, so no  *)
(* exchange waits while it idles. With RetireStale the client gives it no  *)
(* new exchange from then on: it drains at once.                           *)
Age ==
    /\ phase["quic"] = "open" /\ Held("quic") = {} /\ Waiting = {} /\ ~stale
    /\ stale' = TRUE
    /\ phase' = IF RetireStale THEN [phase EXCEPT !["quic"] = "draining"] ELSE phase
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut, quiet>>
    /\ UNCHANGED exchangeVars

(* The QUIC connection holds an exchange and hears nothing until near its  *)
(* idle timeout. With KeepAlive it sends a PING then (RFC 9000 §10.1.2),   *)
(* and the PING's acknowledgment restarts its idle timer, so it never gets *)
(* here.                                                                   *)
Silence ==
    /\ ~KeepAlive /\ Live("quic") /\ Held("quic") # {} /\ ~quiet
    /\ quiet' = TRUE
    /\ UNCHANGED <<phase, opens, goaways, tried, fallback, learned, shut, stale>>
    /\ UNCHANGED exchangeVars

(* The QUIC connection's idle timeout passes (RFC 9000 §10.1): it closes   *)
(* silently, and each exchange it holds ends as a failed connection's      *)
(* does.                                                                   *)
TimeOut == Live("quic") /\ (stale \/ quiet) /\ Fail("quic")

(* A TCP response names h3 in Alt-Svc (RFC 7838), which the next attempt   *)
(* uses.                                                                   *)
Learn ==
    /\ QuicPolicy = "learn" /\ ~learned /\ \E t \in TcpSlots : Live(t)
    /\ learned' = TRUE
    /\ UNCHANGED <<phase, opens, goaways, tried, fallback, shut>>
    /\ UNCHANGED idleVars
    /\ UNCHANGED exchangeVars

(* The caller shuts the client down: it takes no new exchange.             *)
Shutdown ==
    /\ ~shut
    /\ shut' = TRUE
    /\ UNCHANGED <<phase, opens, goaways, tried, fallback, learned>>
    /\ UNCHANGED idleVars
    /\ UNCHANGED exchangeVars

(* Shut down, an open connection with no exchange waiting drains.          *)
Drain(t) ==
    /\ shut /\ phase[t] = "open" /\ Waiting = {}
    /\ phase' = [phase EXCEPT ![t] = "draining"]
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED idleVars
    /\ UNCHANGED exchangeVars

(* Connection t reports `closed` once it holds no exchange: after it       *)
(* failed, or, draining, after its last exchange and the last response it  *)
(* drops. A QUIC connection that closed has no idle timer left.            *)
Close(t) ==
    /\ phase[t] = "failed" \/ (CloseWhenDrained /\ phase[t] = "draining")
    /\ Held(t) = {} /\ Dropping(t) = {}
    /\ phase' = [phase EXCEPT ![t] = "closed"]
    /\ stale' = (stale /\ t # "quic") /\ quiet' = (quiet /\ t # "quic")
    /\ UNCHANGED <<opens, goaways, tried, fallback, learned, shut>>
    /\ UNCHANGED exchangeVars

(* No connection is left to take the waiting exchanges, and the attempt    *)
(* may open no transport. The client ends each waiting exchange refused,   *)
(* or closed when it sent it again, and reports it itself, and the next    *)
(* exchange starts another attempt.                                        *)
GiveUp ==
    /\ Waiting # {} /\ \A t \in Transports : Idle(t)
    /\ ~CanOpenQuic /\ \A t \in TcpSlots : ~CanOpenTcp(t)
    /\ stage' = [e \in Exchanges |-> IF e \in Waiting THEN "reported" ELSE stage[e]]
    /\ outcome' = [e \in Exchanges |->
                    IF e \notin Waiting THEN outcome[e] ELSE IF resent[e] THEN "closed" ELSE "refused"]
    /\ tried' = {} /\ fallback' = FALSE
    /\ UNCHANGED <<carrier, holds, moved, seen, processed, answered, resent, drops>>
    /\ UNCHANGED <<phase, opens, goaways, learned, shut>>
    /\ UNCHANGED idleVars

-----------------------------------------------------------------------------

Next ==
    \/ \E e \in Exchanges :
        \/ Make(e) \/ Send(e) \/ Release(e) \/ Deliver(e) \/ MoveOn(e) \/ Cancel(e) \/ Drop(e)
        \/ Process(e) \/ Answer(e) \/ Respond(e) \/ Refuse(e) \/ Reset(e)
        \/ \E t \in Transports : Assign(e, t)
    \/ \E t \in Transports :
        \/ Open(t) \/ Handshake(t) \/ Abandon(t) \/ FailHandshake(t) \/ Break(t)
        \/ Drain(t) \/ Close(t)
        \/ \E unprocessed \in SUBSET Exchanges : Goaway(t, unprocessed)
    \/ Fallback \/ Learn \/ Shutdown \/ GiveUp \/ Age \/ Silence \/ TimeOut

Spec == Init /\ [][Next]_vars

(* The client, its connections and the servers each take the next step     *)
(* they can: a request is written and answered, a stream closes, a dropped *)
(* response ends, a handshake completes, and an event is reported. The     *)
(* caller, a failure, a refusal and a GOAWAY need not come.                *)
Fairness ==
    /\ \A e \in Exchanges :
        /\ WF_vars(\E t \in Transports : Assign(e, t))
        /\ WF_vars(Send(e)) /\ WF_vars(Release(e)) /\ WF_vars(Deliver(e)) /\ WF_vars(MoveOn(e))
        /\ WF_vars(Process(e)) /\ WF_vars(Respond(e)) /\ WF_vars(Drop(e))
    /\ \A t \in Transports :
        /\ WF_vars(Open(t)) /\ WF_vars(Handshake(t)) /\ WF_vars(Drain(t)) /\ WF_vars(Close(t))
    /\ WF_vars(GiveUp)

FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(* Safe: nothing reads the memory of an exchange the caller has back, only *)
(* a live QUIC connection's stream holds an exchange's octets, a           *)
(* connection refuses only what its server did not process, the caller     *)
(* hears `refused` only for an exchange no server processed, and a         *)
(* connection closes holding no exchange and dropping no response. An      *)
(* exchange moves at most MovesMax times, only an idempotent one moves     *)
(* after a close, and no other exchange is processed by two servers        *)
(* (decision 124). The open connections are QUIC's alone or TCP ones       *)
(* alone, and none holds more exchanges than it holds at once (decision    *)
(* 125).                                                                   *)

Safe ==
    /\ \A e \in Exchanges : stage[e] \in {"reported", "cancelled"} => ~holds[e]
    /\ \A e \in Exchanges : holds[e] => carrier[e] = "quic" /\ Live("quic")
    /\ \A e \in Exchanges : outcome[e] = "refused" => ~seen[e]
    /\ \A e \in Exchanges : stage[e] = "reported" /\ outcome[e] = "refused" => processed[e] = 0
    /\ \A e \in Exchanges \ Idempotent : processed[e] <= 1
    /\ \A e \in Exchanges : moved[e] <= MovesMax
    /\ \A e \in Exchanges : resent[e] => e \in Idempotent
    /\ \A t \in Transports : phase[t] = "closed" => Held(t) \cup Dropping(t) = {}
    /\ OpenOnes \subseteq TcpSlots \/ OpenOnes = {"quic"}
    /\ \A t \in Transports : Cardinality(Held(t) \cup Dropping(t)) <= Capacity(t)

(* Bounded: each connection's slot opens at most once for each wait of an  *)
(* exchange. `tried` is cleared only when an exchange leaves the wait: by  *)
(* Handshake, which with TakeAtHandshake takes waiting exchanges, by       *)
(* Assign, and by GiveUp, which reports every one. So two opens of one     *)
(* slot never serve the same wait, and an exchange waits once when made    *)
(* and once for each move.                                                 *)
Bounded == \A t \in Transports : opens[t] <= N * (MovesMax + 1)

(* NoTcp: a client that speaks no version TCP carries opens no TCP         *)
(* connection (RFC 9114 §3.1), whatever becomes of QUIC.                   *)
NoTcp == ~TcpAllowed => \A t \in TcpSlots : opens[t] = 0

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
