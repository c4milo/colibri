---------------------------- MODULE H3Deadlines -----------------------------
(***************************************************************************)
(* Decision 110's deadlines at one h3 server connection over QUIC          *)
(* (src/server/quic/), as design §8 step 20c built them, with an honest    *)
(* client and an application. It checks two things.                        *)
(*                                                                         *)
(* What the server tells the client when it ends the connection on its     *)
(* own. At its first-request or idle deadline, or at the program's         *)
(* shutdown, the server sends a GOAWAY naming the first request stream h3  *)
(* has not seen (RFC 9114 §5.2), rejects each request whose head h3 has    *)
(* not read with H3_REQUEST_REJECTED (§4.1.1), and closes with H3_NO_ERROR *)
(* once no request holds a record and the client acknowledged the GOAWAY,  *)
(* or when the drain deadline passes. Four invariants:                     *)
(*   - NothingUnsaid: when a close that the drain deadline did not force   *)
(*     reaches the client, the client knows of every request it opened     *)
(*     below the GOAWAY's identifier whether the server took it. One the   *)
(*     server did not take got a rejection or a 408, which say the client  *)
(*     may send it again; one it took got its response, a 408 or a reset.  *)
(*   - GoawayBeforeClose: such a close reaches a client that read the      *)
(*     GOAWAY.                                                             *)
(*   - RejectedUnprocessed: no request the application heard of is         *)
(*     rejected (RFC 9114 §4.1.1).                                         *)
(*   - OnlyChosenCounted: the server counts toward its reset limit only    *)
(*     the resets the client chose, never one the client sent because the  *)
(*     server asked it to stop (RFC 9000 §3.5).                            *)
(*                                                                         *)
(* Decision 110's rule 2 over QUIC: a deadline runs only while colibri     *)
(* waits on the peer. As spec/tla/server_deadlines does for h2, the model  *)
(* has no time. It checks when each deadline's clock runs, in the states   *)
(* where colibri has no step of its own left, since its own steps take no  *)
(* time. Four invariants:                                                  *)
(*   - HeadWaitsOnPeer and BodyWaitsOnPeer: a request's head or body clock *)
(*     never runs while the client has more of the request to send, its    *)
(*     credit is spent, and the credit that would let it send waits in     *)
(*     colibri.                                                            *)
(*   - IdleWaitsOnPeer: the idle clock never runs while the client's next  *)
(*     request waits for connection credit colibri holds, unless a head on *)
(*     its way to colibri will stop the clock.                             *)
(*   - SendWaitsOnPeer: the send clock runs only while a packet of         *)
(*     colibri's is on its way or unacknowledged.                          *)
(*                                                                         *)
(* QUIC, as this model has it:                                             *)
(*   - a unit of a request or of a response is one frame, and each frame   *)
(*     goes in a packet of its own, but for the credit colibri owes, which *)
(*     one packet carries whole;                                           *)
(*   - the network delivers colibri's packets in the order it sent them,   *)
(*     and the client's units of one stream in order, and loses none.      *)
(*     colibri's CONNECTION_CLOSE may pass any packet sent before it;      *)
(*   - colibri's QUIC takes what arrives when the datagram does (`take`),  *)
(*     and h3 reads it when the caller next reads (`receive`), one of      *)
(*     colibri's own steps. `settle`, which decides the close, runs at     *)
(*     both, so a close may come between them;                             *)
(*   - colibri's packets in flight, all of them ack-eliciting, number      *)
(*     CongestionWindow at most (RFC 9002 §7). Its CONNECTION_CLOSE is not *)
(*     counted, and once it owes one it sends nothing else (§10.2.1);      *)
(*   - the client acknowledges every packet it read in one step;           *)
(*   - colibri credits a request stream, or the connection, once what h3   *)
(*     read plus the window passes the advertised limit by half the        *)
(*     window (flow.Receiver's credit_frame_limit). It writes every new    *)
(*     limit in its next packet, ahead of response data (write_limits). h3 *)
(*     reads a request's head only once it is whole, so the units of a     *)
(*     head that is not whole hold their credit;                           *)
(*   - the client's credit for responses never binds.                      *)
(*                                                                         *)
(* colibri's rules, as this model has them (quic_deadline.zig,             *)
(* quic_body.zig, quic_sends.zig and quic_connection_h3.zig):              *)
(*   - first request: from the start until a whole head arrives;           *)
(*   - idle: after the first request, while no request is open. A          *)
(*     request is open from its whole head until its response is           *)
(*     acknowledged or it is cancelled;                                    *)
(*   - head: while h3 waits for a stream's head, which a head blocked on   *)
(*     QPACK still is. When it passes, a 408 and STOP_SENDING, and the     *)
(*     application never hears of the request;                             *)
(*   - body: from a request's whole head until its content ends. When it   *)
(*     passes, a 408 with no response written, a reset with                *)
(*     H3_REQUEST_CANCELLED with one begun, and STOP_SENDING alone with    *)
(*     one ended;                                                          *)
(*   - send: while a response the client has not acknowledged is unreset;  *)
(*   - drain: from the shutdown, until the close.                          *)
(* The first-request and idle deadlines stop once the connection shuts     *)
(* down.                                                                   *)
(*                                                                         *)
(* Left out: the handshake, which the first-request deadline also covers;  *)
(* the cap on a body and the arithmetic of the rates, which                *)
(* spec/lean/Colibri/Server/RateMeter.lean proves; the send meter of a     *)
(* stream the client's credit holds; the meters that close the connection  *)
(* with H3_EXCESSIVE_LOAD; the reset limit's period, so only what is       *)
(* counted is checked; the stream limit (RFC 9000 §4.6); loss; and time,   *)
(* so a deadline may pass whenever its clock runs.                         *)
(*                                                                         *)
(* Two scopes. The shutdown configurations let deadlines pass, with        *)
(* windows that never bind. The flow configurations let none pass, and     *)
(* bind both windows and the congestion window.                            *)
(*                                                                         *)
(* Each rule constant is a rule colibri keeps, or one it might, and a      *)
(* configuration that changes one says what TLC must find:                 *)
(*   RejectUnread      a shutdown rejects each request whose head h3 has   *)
(*                     not read (quic_connection_h3.zig's reject_unread).  *)
(*   CloseAfterAck     the close waits for the client's acknowledgment of  *)
(*                     the GOAWAY (finish_if_drained).                     *)
(*   UncountedAsked    a reset on a stream colibri abandoned is not        *)
(*                     counted (h3 does not report it).                    *)
(*   CloseAfterResets  the close also waits for the client's               *)
(*                     acknowledgment of every RESET_STREAM colibri sent   *)
(*                     (quic.connection_stream_acknowledged's              *)
(*                     resets_acknowledged).                               *)
(*   PauseForCredit    the head, body and idle clocks wait while colibri   *)
(*                     holds credit it has not sent. colibri does not keep *)
(*                     this rule.                                          *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    N,                  \* request streams the client may open: 0..N-1, in order
    HeadUnits,          \* units of a request's HEADERS frame
    Content,            \* units of DATA a request carries after its head
    ResponseUnits,      \* units of each response, which the application writes one at a time
    StreamWindow,       \* colibri's receive window on each request stream, in units
    ConnectionWindow,   \* colibri's receive window on the connection, in units
    CongestionWindow,   \* colibri's packets in flight, at most
    Fire,               \* whether deadlines pass and the program shuts down: the shutdown scope
    ClientCancels,      \* whether the client may cancel its requests
    RejectUnread, CloseAfterAck, CloseAfterResets, UncountedAsked, PauseForCredit

ASSUME N \in Nat \ {0} /\ HeadUnits \in Nat \ {0} /\ Content \in Nat
ASSUME ResponseUnits \in Nat \ {0} /\ CongestionWindow \in Nat \ {0}
\* colibri's windows hold a whole head on every stream at once.
ASSUME StreamWindow >= HeadUnits /\ ConnectionWindow >= N * HeadUnits
ASSUME \A rule \in {Fire, ClientCancels, RejectUnread, CloseAfterAck, CloseAfterResets,
                    UncountedAsked, PauseForCredit} : rule \in BOOLEAN

Requests == 0..(N - 1)
Units == HeadUnits + Content
\* No GOAWAY yet. It is above every stream, so "below the GOAWAY" holds for all.
NoGoaway == N + 1
\* colibri's quic `flow_credit_fraction`.
Fraction == 2

Max(a, b) == IF a > b THEN a ELSE b

Sum(f) == LET s[i \in 0..N] == IF i = 0 THEN 0 ELSE s[i - 1] + f[i - 1] IN s[N]

(* One of colibri's packets. A unit of a response carries its number in n, *)
(* and a GOAWAY its identifier. A credit packet carries every limit        *)
(* colibri raised when it wrote the packet, a stream's or the              *)
(* connection's, and 0 where it raised none (write_limits).                *)
NoLimits == [r \in Requests |-> 0]
Packet(kind, r, n) ==
    [kind |-> kind, stream |-> r, n |-> n, limits |-> NoLimits, connection |-> 0]
CreditPacket(limits, connection) ==
    [kind |-> "credit", stream |-> 0, n |-> 0, limits |-> limits, connection |-> connection]
(* What colibri owes and sends on its own, besides response units and      *)
(* credit: a 408, a RESET_STREAM with either code, STOP_SENDING and the    *)
(* GOAWAY.                                                                 *)
ControlKinds == {"timeout", "rejected", "cancelled", "stop", "goaway"}

Phases == {"unseen", "head", "content", "ended", "abandoned"}
Outcomes == {"none", "response", "timeout", "rejected", "cancelled"}

VARIABLES
    \* The client.
    opened,             \* request streams the client opened
    cliSent,            \* cliSent[r]: units of request r the client sent
    cliReset,           \* cliReset[r]: whether the client reset its sending part of r
    own,                \* own[r]: whether the client cancelled r by its own choice
    resetOut,           \* resetOut[r]: whether the client's RESET_STREAM on r is on its way
    stopOut,            \* stopOut[r]: whether the client's STOP_SENDING on r is on its way
    limitStream,        \* limitStream[r]: the units of r colibri lets the client send
    limitConnection,    \* the units of every request together colibri lets the client send
    got,                \* got[r]: the units of the response to r the client read
    outcome,            \* outcome[r]: what the client learned of r
    goawayRead,         \* whether the GOAWAY reached the client
    closeRead,          \* whether colibri's CONNECTION_CLOSE reached the client
    \* The network.
    inFlight,           \* colibri's packets on their way to the client, oldest first
    delivered,          \* colibri's packets the client read and has not acknowledged
    \* colibri's QUIC.
    atQuic,             \* atQuic[r]: the units of r that reached colibri's QUIC
    resetIn,            \* resetIn[r]: whether the client's RESET_STREAM on r reached it
    quicOpened,         \* the request streams it opened: one past the highest a frame named
    \* colibri.
    taken,              \* the request streams h3 has seen: `next_index`
    phase,              \* phase[r]: where h3 is on request stream r
    readUnits,          \* readUnits[r]: the units of r h3 read
    resetRead,          \* resetRead[r]: whether colibri read the client's RESET_STREAM on r
    processed,          \* processed[r]: whether the application heard of request r
    rec,                \* rec[r]: the server's record of r: "none", "open" or "over"
    bodyWaits,          \* bodyWaits[r]: whether the server waits for r's content
    written,            \* written[r]: the units of the response the application wrote
    sent,               \* sent[r]: the units of the response colibri sent
    acked,              \* acked[r]: the units of the response the client acknowledged
    aborted,            \* aborted[r]: whether colibri reset its response on r
    owed,               \* the control packets colibri owes and has not sent
    ackedControl,       \* the control packets the client acknowledged
    advStream,          \* advStream[r]: the limit colibri last advertised on r
    advConnection,      \* the limit colibri last advertised on the connection
    goawayId,           \* the identifier colibri's GOAWAY named, or NoGoaway
    firstRequestRead,   \* whether a whole request head arrived
    shuttingDown,       \* whether colibri takes no new request
    timedOut,           \* the deadline that began the shutdown or closed, or "none"
    closed,             \* "open", or how colibri closed: "drained" or "drain"
    counted             \* counted[r]: whether colibri counted a reset of r toward its limit

client == <<opened, cliSent, cliReset, own, resetOut, stopOut, limitStream, limitConnection,
            got, outcome, goawayRead, closeRead>>
network == <<inFlight, delivered>>
transport == <<atQuic, resetIn, quicOpened>>
colibri == <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, written, sent, acked,
             aborted, owed, ackedControl, advStream, advConnection, goawayId, firstRequestRead,
             shuttingDown, timedOut, closed, counted>>
vars == <<client, network, transport, colibri>>

TypeOK ==
    /\ opened \in 0..N /\ cliSent \in [Requests -> 0..Units]
    /\ outcome \in [Requests -> Outcomes] /\ got \in [Requests -> 0..ResponseUnits]
    /\ phase \in [Requests -> Phases] /\ rec \in [Requests -> {"none", "open", "over"}]
    /\ readUnits \in [Requests -> 0..Units] /\ written \in [Requests -> 0..ResponseUnits]
    /\ taken \in 0..N /\ goawayId \in 0..NoGoaway /\ quicOpened \in 0..N
    /\ atQuic \in [Requests -> 0..Units] /\ resetIn \in [Requests -> BOOLEAN]
    /\ closed \in {"open", "drained", "drain"}
    /\ Len(inFlight) + Cardinality(delivered) <= CongestionWindow

Init ==
    /\ opened = 0 /\ cliSent = [r \in Requests |-> 0]
    /\ cliReset = [r \in Requests |-> FALSE] /\ own = [r \in Requests |-> FALSE]
    /\ resetOut = [r \in Requests |-> FALSE] /\ stopOut = [r \in Requests |-> FALSE]
    /\ limitStream = [r \in Requests |-> StreamWindow] /\ limitConnection = ConnectionWindow
    /\ got = [r \in Requests |-> 0] /\ outcome = [r \in Requests |-> "none"]
    /\ goawayRead = FALSE /\ closeRead = FALSE
    /\ inFlight = <<>> /\ delivered = {}
    /\ atQuic = [r \in Requests |-> 0] /\ resetIn = [r \in Requests |-> FALSE] /\ quicOpened = 0
    /\ taken = 0 /\ phase = [r \in Requests |-> "unseen"] /\ readUnits = [r \in Requests |-> 0]
    /\ resetRead = [r \in Requests |-> FALSE] /\ processed = [r \in Requests |-> FALSE]
    /\ rec = [r \in Requests |-> "none"] /\ bodyWaits = [r \in Requests |-> FALSE]
    /\ written = [r \in Requests |-> 0] /\ sent = [r \in Requests |-> 0]
    /\ acked = [r \in Requests |-> 0] /\ aborted = [r \in Requests |-> FALSE]
    /\ owed = {} /\ ackedControl = {}
    /\ advStream = [r \in Requests |-> StreamWindow] /\ advConnection = ConnectionWindow
    /\ goawayId = NoGoaway /\ firstRequestRead = FALSE /\ shuttingDown = FALSE
    /\ timedOut = "none" /\ closed = "open" /\ counted = [r \in Requests |-> FALSE]

-----------------------------------------------------------------------------
(* What colibri knows.                                                     *)

Running == closed = "open"
TakesRequests == Running /\ ~shuttingDown

(* A response the client acknowledged whole: its stream's sending part is  *)
(* in "Data Recvd" (RFC 9000 §3.1), so its request is done.                *)
Done(r) == written[r] = ResponseUnits /\ acked[r] = ResponseUnits

(* A request the server holds a record of and has not ended: `any_open`.   *)
OpenRequest(r) == rec[r] = "open" /\ ~Done(r)

(* RFC 9000 §3: a stream closes once both its parts end. Its receiving     *)
(* part ends with the request's end, read whole or discarded, or with the  *)
(* client's reset; its sending part once the client acknowledged the       *)
(* response, the 408, or colibri's reset.                                  *)
ReceivingDone(r) ==
    \/ phase[r] = "ended" \/ resetRead[r]
    \/ phase[r] = "abandoned" /\ readUnits[r] = Units
SendingDone(r) ==
    \/ Done(r)
    \/ \E k \in {"timeout", "rejected", "cancelled"} : Packet(k, r, 0) \in ackedControl
StreamClosed(r) == ReceivingDone(r) /\ SendingDone(r)

(* The client acknowledged colibri's RESET_STREAM on r.                    *)
ResetAcked(r) == \E k \in {"rejected", "cancelled"} : Packet(k, r, 0) \in ackedControl

(* A record stays in use until its stream closes: `requests.idle()` is     *)
(* none in use.                                                            *)
InUse(r) == rec[r] # "none" /\ ~StreamClosed(r)

(* What h3 has read of each stream. A head that is not whole is peeked     *)
(* and not consumed, what a stream colibri abandoned brings is consumed    *)
(* as it is discarded, and a reset gives back the stream's final size      *)
(* (RFC 9000 §4.5).                                                        *)
Consumed(r) ==
    IF resetRead[r] THEN cliSent[r]
    ELSE IF phase[r] \in {"unseen", "head"} THEN 0
    ELSE readUnits[r]
ConsumedAll == Sum([r \in Requests |-> Consumed(r)])

(* flow.Receiver's credit_frame_limit: new credit is worth a frame once    *)
(* it reaches half the window. RFC 9000 §19.10: MAX_STREAM_DATA goes out   *)
(* only while the stream's receiving part is in "Recv".                    *)
StreamGain(r) == Consumed(r) + StreamWindow - advStream[r]
StreamCreditOwed(r) ==
    /\ phase[r] # "unseen" /\ ~ReceivingDone(r)
    /\ StreamGain(r) > 0 /\ StreamGain(r) >= StreamWindow \div Fraction
ConnectionGain == ConsumedAll + ConnectionWindow - advConnection
ConnectionCreditOwed ==
    ConnectionGain > 0 /\ ConnectionGain >= ConnectionWindow \div Fraction
CreditOwed == ConnectionCreditOwed \/ \E r \in Requests : StreamCreditOwed(r)

(* RFC 9002 §7: the packets in flight leave room for one more.             *)
Room == Len(inFlight) + Cardinality(delivered) < CongestionWindow

OnTheWay == {inFlight[i] : i \in 1..Len(inFlight)}

-----------------------------------------------------------------------------
(* When each clock runs, as colibri's code has it.                         *)

FirstRequestRuns == TakesRequests /\ ~firstRequestRead
IdleRuns ==
    /\ TakesRequests /\ firstRequestRead /\ \A r \in Requests : ~OpenRequest(r)
    /\ ~(PauseForCredit /\ CreditOwed)
HeadRuns(r) == Running /\ phase[r] = "head" /\ ~(PauseForCredit /\ CreditOwed)
BodyRuns(r) == Running /\ bodyWaits[r] /\ ~(PauseForCredit /\ CreditOwed)
TimeoutUnacked(r) == Packet("timeout", r, 0) \in owed \cup OnTheWay \cup delivered
Busy(r) == InUse(r) /\ ~aborted[r] /\ (acked[r] < written[r] \/ TimeoutUnacked(r))
SendRuns == Running /\ \E r \in Requests : Busy(r)
DrainRuns == Running /\ shuttingDown

-----------------------------------------------------------------------------
(* The client.                                                             *)

TotalSent == Sum(cliSent)

(* It opens its next request stream with the first unit of its head.       *)
(* RFC 9114 §5.2: "Endpoints MUST NOT initiate new requests ... after      *)
(* receipt of a GOAWAY frame".                                             *)
Open ==
    /\ ~closeRead /\ opened < N /\ ~goawayRead /\ TotalSent < limitConnection
    /\ cliSent' = [cliSent EXCEPT ![opened] = 1]
    /\ opened' = opened + 1
    /\ UNCHANGED <<cliReset, own, resetOut, stopOut, limitStream, limitConnection, got,
                   outcome, goawayRead, closeRead>>
    /\ UNCHANGED <<network, transport, colibri>>

(* It sends the next unit of r within both of colibri's limits.            *)
SendUnit(r) ==
    /\ ~closeRead /\ r < opened /\ ~cliReset[r] /\ cliSent[r] < Units
    /\ cliSent[r] < limitStream[r] /\ TotalSent < limitConnection
    /\ cliSent' = [cliSent EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<opened, cliReset, own, resetOut, stopOut, limitStream, limitConnection, got,
                   outcome, goawayRead, closeRead>>
    /\ UNCHANGED <<network, transport, colibri>>

(* RFC 9114 §4.1.1: it cancels a request by resetting its sending part,    *)
(* when it has more to send, and asking colibri to stop the response.      *)
Cancel(r) ==
    LET resets == ~cliReset[r] /\ cliSent[r] < Units IN
    /\ ClientCancels /\ ~closeRead /\ r < opened /\ ~own[r] /\ outcome[r] = "none"
    /\ own' = [own EXCEPT ![r] = TRUE]
    /\ cliReset' = [cliReset EXCEPT ![r] = @ \/ resets]
    /\ resetOut' = [resetOut EXCEPT ![r] = @ \/ resets]
    /\ stopOut' = [stopOut EXCEPT ![r] = TRUE]
    /\ UNCHANGED <<opened, cliSent, limitStream, limitConnection, got, outcome, goawayRead,
                   closeRead>>
    /\ UNCHANGED <<network, transport, colibri>>

(* It reads colibri's oldest packet on its way.                            *)
Deliver ==
    LET p == Head(inFlight)
        r == p.stream
        learns == outcome[r] = "none"
        \* RFC 9000 §3.5: "An endpoint that receives a STOP_SENDING frame MUST send a
        \* RESET_STREAM frame if the stream is in the "Ready" or "Send" state."
        resets == p.kind = "stop" /\ ~cliReset[r] /\ cliSent[r] < Units
    IN
    /\ ~closeRead /\ inFlight # <<>>
    /\ inFlight' = Tail(inFlight)
    /\ delivered' = delivered \cup {p}
    /\ got' = IF p.kind = "unit" THEN [got EXCEPT ![r] = p.n] ELSE got
    /\ outcome' =
        CASE p.kind = "unit" /\ p.n = ResponseUnits /\ learns ->
                [outcome EXCEPT ![r] = "response"]
          [] p.kind \in {"timeout", "rejected", "cancelled"} /\ learns ->
                [outcome EXCEPT ![r] = p.kind]
          [] OTHER -> outcome
    /\ cliReset' = IF resets THEN [cliReset EXCEPT ![r] = TRUE] ELSE cliReset
    /\ resetOut' = IF resets THEN [resetOut EXCEPT ![r] = TRUE] ELSE resetOut
    /\ limitStream' = [q \in Requests |-> Max(limitStream[q], p.limits[q])]
    /\ limitConnection' = Max(limitConnection, p.connection)
    /\ goawayRead' = (goawayRead \/ p.kind = "goaway")
    /\ UNCHANGED <<opened, cliSent, own, stopOut, closeRead>>
    /\ UNCHANGED <<transport, colibri>>

(* colibri's CONNECTION_CLOSE reaches the client, which then reads and     *)
(* sends nothing more (RFC 9000 §10.2.2). It may pass any packet sent      *)
(* before it.                                                              *)
ReadClose ==
    /\ ~Running /\ ~closeRead
    /\ closeRead' = TRUE
    /\ UNCHANGED <<opened, cliSent, cliReset, own, resetOut, stopOut, limitStream,
                   limitConnection, got, outcome, goawayRead>>
    /\ UNCHANGED <<network, transport, colibri>>

(* The client's acknowledgment of every packet it read reaches colibri,    *)
(* which frees its congestion window and notes what the client took. A     *)
(* closed colibri takes nothing.                                           *)
Acknowledge ==
    /\ ~closeRead /\ delivered # {}
    /\ delivered' = {}
    /\ acked' = IF Running
                THEN [r \in Requests |->
                        acked[r] + Cardinality({p \in delivered : p.kind = "unit" /\ p.stream = r})]
                ELSE acked
    /\ ackedControl' = IF Running
                       THEN ackedControl \cup {p \in delivered : p.kind \in ControlKinds}
                       ELSE ackedControl
    /\ UNCHANGED <<client, transport>>
    /\ UNCHANGED inFlight
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, written, sent,
                   aborted, owed, advStream, advConnection, goawayId, firstRequestRead,
                   shuttingDown, timedOut, closed, counted>>

-----------------------------------------------------------------------------
(* What the client sends reaches colibri's QUIC, which takes it when the   *)
(* datagram arrives (`take`). h3 reads it when the caller next reads       *)
(* (`receive`), which is one of colibri's own steps (Read).                *)

(* A unit of r reaches colibri's QUIC, which opens r and every lower       *)
(* request stream (RFC 9000 §3.2). A reset stream takes no more.           *)
ArriveUnit(r) ==
    /\ Running /\ atQuic[r] < cliSent[r] /\ ~resetIn[r]
    /\ atQuic' = [atQuic EXCEPT ![r] = @ + 1]
    /\ quicOpened' = Max(quicOpened, r + 1)
    /\ UNCHANGED resetIn
    /\ UNCHANGED <<client, network, colibri>>

(* The client's RESET_STREAM on r reaches colibri's QUIC.                  *)
ArriveReset(r) ==
    /\ Running /\ resetOut[r]
    /\ resetOut' = [resetOut EXCEPT ![r] = FALSE]
    /\ resetIn' = [resetIn EXCEPT ![r] = TRUE]
    /\ quicOpened' = Max(quicOpened, r + 1)
    /\ UNCHANGED atQuic
    /\ UNCHANGED <<opened, cliSent, cliReset, own, stopOut, limitStream, limitConnection, got,
                   outcome, goawayRead, closeRead>>
    /\ UNCHANGED <<network, colibri>>

(* The client's STOP_SENDING on r arrives. quic resets a response it has   *)
(* not had acknowledged whole (RFC 9000 §3.5), and the server's `settle`,  *)
(* which runs after each datagram, counts that as the client's cancel      *)
(* unless the request is over (settle_one).                                *)
ArriveStop(r) ==
    LET resets == ~aborted[r] /\ ~SendingDone(r)
        counts == resets /\ rec[r] = "open"
    IN
    /\ Running /\ stopOut[r]
    /\ stopOut' = [stopOut EXCEPT ![r] = FALSE]
    /\ quicOpened' = Max(quicOpened, r + 1)
    /\ aborted' = [aborted EXCEPT ![r] = @ \/ resets]
    /\ owed' = owed \cup (IF resets THEN {Packet("cancelled", r, 0)} ELSE {})
    /\ counted' = [counted EXCEPT ![r] = @ \/ counts]
    /\ rec' = IF counts THEN [rec EXCEPT ![r] = "over"] ELSE rec
    /\ bodyWaits' = IF counts THEN [bodyWaits EXCEPT ![r] = FALSE] ELSE bodyWaits
    /\ UNCHANGED <<atQuic, resetIn>>
    /\ UNCHANGED <<opened, cliSent, cliReset, own, resetOut, limitStream, limitConnection, got,
                   outcome, goawayRead, closeRead>>
    /\ UNCHANGED network
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, written, sent, acked,
                   ackedControl, advStream, advConnection, goawayId, firstRequestRead,
                   shuttingDown, timedOut, closed>>

(* Whether QUIC holds something h3 has not read: a request stream h3 has   *)
(* not seen, a unit, or a reset.                                           *)
Unread ==
    \/ quicOpened > taken
    \/ \E r \in Requests : atQuic[r] > readUnits[r] \/ (resetIn[r] /\ ~resetRead[r])

(* h3 reads what QUIC holds. It sees each request stream QUIC opened, in   *)
(* order (`accept`), and after its GOAWAY rejects one at or above the      *)
(* identifier the GOAWAY named (RFC 9114 §5.2), with H3_REQUEST_REJECTED   *)
(* (§4.1.1). Then it reads each stream: a reset first, which h3 reports    *)
(* unless colibri abandoned the stream (connection_request.zig's           *)
(* on_reset), and the units in order. A whole head is a request the        *)
(* application hears of (`on_request`), and the wait for its content       *)
(* starts (quic_body.zig's add). The last unit ends the request. The       *)
(* server counts a reset h3 reports toward its limit unless the request    *)
(* is over, and resets its own response with H3_REQUEST_CANCELLED          *)
(* (quic_connection_h3.zig's on_reset).                                    *)
Read ==
    LET seen == [q \in Requests |->
                   IF taken <= q /\ q < quicOpened
                   THEN (IF q >= goawayId THEN "abandoned" ELSE "head")
                   ELSE phase[q]]
        refused == {q \in Requests : taken <= q /\ q < quicOpened /\ q >= goawayId}
        resetNow(q) == resetIn[q] /\ ~resetRead[q]
        reported(q) == resetNow(q) /\ seen[q] \in {"head", "content"}
        over(q) == rec[q] = "over" \/ (rec[q] = "open" /\ Done(q))
        counts(q) == \/ reported(q) /\ ~over(q)
                     \/ ~UncountedAsked /\ resetNow(q) /\ seen[q] = "abandoned"
        cancels(q) == reported(q) /\ rec[q] = "open" /\ ~Done(q)
        whole(q) == ~resetNow(q) /\ seen[q] = "head" /\ atQuic[q] >= HeadUnits
        ends(q) == ~resetNow(q) /\ seen[q] \in {"head", "content"} /\ atQuic[q] = Units
        cancelled == {q \in Requests : cancels(q)}
    IN
    /\ Running /\ Unread
    /\ taken' = Max(taken, quicOpened)
    /\ readUnits' = [q \in Requests |-> IF resetNow(q) THEN readUnits[q] ELSE atQuic[q]]
    /\ resetRead' = [q \in Requests |-> resetRead[q] \/ resetNow(q)]
    /\ phase' = [q \in Requests |->
                   CASE resetNow(q) -> IF seen[q] = "ended" THEN "ended" ELSE "abandoned"
                     [] whole(q) /\ ends(q) -> "ended"
                     [] whole(q) -> "content"
                     [] seen[q] = "content" /\ ends(q) -> "ended"
                     [] OTHER -> seen[q]]
    /\ processed' = [q \in Requests |-> processed[q] \/ whole(q)]
    /\ rec' = [q \in Requests |->
                 IF whole(q) THEN "open" ELSE IF cancels(q) THEN "over" ELSE rec[q]]
    /\ bodyWaits' = [q \in Requests |->
                       CASE resetNow(q) -> FALSE
                         [] whole(q) -> ~ends(q)
                         [] seen[q] = "content" /\ ends(q) -> FALSE
                         [] OTHER -> bodyWaits[q]]
    /\ firstRequestRead' = (firstRequestRead \/ \E q \in Requests : whole(q))
    /\ counted' = [q \in Requests |-> counted[q] \/ counts(q)]
    /\ aborted' = [q \in Requests |-> aborted[q] \/ q \in refused \/ q \in cancelled]
    /\ owed' = owed \cup {Packet(k, q, 0) : k \in {"rejected", "stop"}, q \in refused}
                    \cup {Packet(k, q, 0) : k \in {"cancelled", "stop"}, q \in cancelled}
    /\ UNCHANGED <<client, network, transport>>
    /\ UNCHANGED <<written, sent, acked, ackedControl, advStream, advConnection, goawayId,
                   shuttingDown, timedOut, closed>>

-----------------------------------------------------------------------------
(* The application and the program.                                        *)

(* The application writes the next unit of its answer to a request it      *)
(* heard of, before or after the request's content ends.                   *)
Write(r) ==
    /\ Running /\ rec[r] = "open" /\ ~aborted[r] /\ written[r] < ResponseUnits
    /\ written' = [written EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<client, network, transport>>
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, sent, acked,
                   aborted, owed, ackedControl, advStream, advConnection, goawayId,
                   firstRequestRead, shuttingDown, timedOut, closed, counted>>

(* quic_deadline.zig's shut_down, and the program's `shutdown`: the        *)
(* connection takes no new request and sends a GOAWAY naming the first     *)
(* request stream h3 has not seen (RFC 9114 §5.2). With RejectUnread it    *)
(* rejects each request whose head h3 has not read (§4.1.1), and asks      *)
(* the client to stop sending it.                                          *)
ShutDown(passed) ==
    LET unread == {r \in Requests : RejectUnread /\ phase[r] = "head"} IN
    /\ Running /\ ~shuttingDown
    /\ shuttingDown' = TRUE
    /\ timedOut' = IF passed = "none" THEN timedOut ELSE passed
    /\ goawayId' = taken
    /\ phase' = [r \in Requests |-> IF r \in unread THEN "abandoned" ELSE phase[r]]
    /\ aborted' = [r \in Requests |-> aborted[r] \/ r \in unread]
    /\ owed' = owed \cup {Packet("goaway", 0, taken)}
                    \cup {Packet(k, r, 0) : k \in {"rejected", "stop"}, r \in unread}
    /\ UNCHANGED <<client, network, transport>>
    /\ UNCHANGED <<taken, readUnits, resetRead, processed, rec, bodyWaits, written, sent, acked,
                   ackedControl, advStream, advConnection, firstRequestRead, closed, counted>>

(* The program shuts the connection down, in the shutdown scope.           *)
Shutdown == Fire /\ ShutDown("none")

-----------------------------------------------------------------------------
(* colibri's own steps, which take no time.                                *)

(* It sends a unit of a response, behind any credit it owes.               *)
SendResponse(r) ==
    /\ Running /\ Room /\ ~CreditOwed /\ ~aborted[r] /\ sent[r] < written[r]
    /\ inFlight' = Append(inFlight, Packet("unit", r, sent[r] + 1))
    /\ sent' = [sent EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<client, transport>>
    /\ UNCHANGED delivered
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, written, acked,
                   aborted, owed, ackedControl, advStream, advConnection, goawayId,
                   firstRequestRead, shuttingDown, timedOut, closed, counted>>

(* It sends a control packet it owes.                                      *)
SendControl(p) ==
    /\ Running /\ Room /\ p \in owed
    /\ owed' = owed \ {p}
    /\ inFlight' = Append(inFlight, p)
    /\ UNCHANGED <<client, transport>>
    /\ UNCHANGED delivered
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, written, sent,
                   acked, aborted, ackedControl, advStream, advConnection, goawayId,
                   firstRequestRead, shuttingDown, timedOut, closed, counted>>

(* It sends every credit it owes in one packet: each new limit is what h3  *)
(* read plus the window.                                                   *)
SendCredit ==
    LET limits == [r \in Requests |->
                     IF StreamCreditOwed(r) THEN Consumed(r) + StreamWindow ELSE 0]
        connection == IF ConnectionCreditOwed THEN ConsumedAll + ConnectionWindow ELSE 0
    IN
    /\ Running /\ Room /\ CreditOwed
    /\ advStream' = [r \in Requests |-> IF limits[r] > 0 THEN limits[r] ELSE advStream[r]]
    /\ advConnection' = IF connection > 0 THEN connection ELSE advConnection
    /\ inFlight' = Append(inFlight, CreditPacket(limits, connection))
    /\ UNCHANGED <<client, transport>>
    /\ UNCHANGED delivered
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, written, sent,
                   acked, aborted, owed, ackedControl, goawayId, firstRequestRead, shuttingDown,
                   timedOut, closed, counted>>

(* quic_connection_h3.zig's finish_if_drained, which `settle` runs after   *)
(* each datagram and at each call: a connection shutting down closes with  *)
(* H3_NO_ERROR once no request holds a record and, with CloseAfterAck, the *)
(* client acknowledged the GOAWAY, and with CloseAfterResets every         *)
(* RESET_STREAM colibri sent. It may close before h3 reads a request       *)
(* stream a datagram opened, which the GOAWAY already puts among those the *)
(* server did not take.                                                    *)
Close ==
    /\ Running /\ shuttingDown
    /\ \A r \in Requests : ~InUse(r)
    /\ CloseAfterAck => Packet("goaway", 0, goawayId) \in ackedControl
    /\ CloseAfterResets => \A r \in Requests : aborted[r] => ResetAcked(r)
    /\ closed' = "drained"
    /\ UNCHANGED <<client, network, transport>>
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, written, sent,
                   acked, aborted, owed, ackedControl, advStream, advConnection, goawayId,
                   firstRequestRead, shuttingDown, timedOut, counted>>

ColibriStep ==
    \/ Read
    \/ Close
    \/ \E p \in owed : SendControl(p)
    \/ SendCredit
    \/ \E r \in Requests : SendResponse(r)

Quiescent == ~ENABLED ColibriStep

-----------------------------------------------------------------------------
(* A deadline passes, which only time does.                                *)

(* quic_deadline.zig's refuse_head: a request whose head is late gets a    *)
(* 408 (RFC 9110 §15.5.9), and colibri asks the client to stop sending it  *)
(* (RFC 9114 §4.1). The application never hears of it.                     *)
RefuseHead(r) ==
    /\ phase' = [phase EXCEPT ![r] = "abandoned"]
    /\ rec' = [rec EXCEPT ![r] = "over"]
    /\ owed' = owed \cup {Packet("timeout", r, 0), Packet("stop", r, 0)}
    /\ UNCHANGED <<client, network, transport>>
    /\ UNCHANGED <<taken, readUnits, resetRead, processed, bodyWaits, written, sent, acked,
                   aborted, ackedControl, advStream, advConnection, goawayId, firstRequestRead,
                   shuttingDown, timedOut, closed, counted>>

(* quic_body.zig's end_request: a body that falls short ends its request.  *)
(* With no response written it gets a 408; with one begun and not ended,   *)
(* a reset with H3_REQUEST_CANCELLED (RFC 9114 §4.1.1); with one ended,    *)
(* STOP_SENDING alone, and the response goes on.                           *)
EndRequest(r) ==
    LET finished == written[r] = ResponseUnits
        none == written[r] = 0
    IN
    /\ bodyWaits' = [bodyWaits EXCEPT ![r] = FALSE]
    /\ phase' = [phase EXCEPT ![r] = "abandoned"]
    /\ rec' = IF finished THEN rec ELSE [rec EXCEPT ![r] = "over"]
    /\ aborted' = IF ~finished /\ ~none THEN [aborted EXCEPT ![r] = TRUE] ELSE aborted
    /\ owed' = owed \cup {Packet("stop", r, 0)}
                    \cup (IF none THEN {Packet("timeout", r, 0)}
                          ELSE IF ~finished THEN {Packet("cancelled", r, 0)} ELSE {})
    /\ UNCHANGED <<client, network, transport>>
    /\ UNCHANGED <<taken, readUnits, resetRead, processed, written, sent, acked, ackedControl,
                   advStream, advConnection, goawayId, firstRequestRead, shuttingDown,
                   timedOut, closed, counted>>

PassFirstRequest == Fire /\ FirstRequestRuns /\ ShutDown("first_request")
PassIdle == Fire /\ IdleRuns /\ ShutDown("idle")
PassHead(r) == Fire /\ HeadRuns(r) /\ RefuseHead(r)
PassBody(r) == Fire /\ BodyRuns(r) /\ EndRequest(r)

(* The drain passes: the connection closes with the requests it holds.     *)
PassDrain ==
    /\ Fire /\ DrainRuns
    /\ closed' = "drain"
    /\ timedOut' = IF timedOut = "none" THEN "drain" ELSE timedOut
    /\ UNCHANGED <<client, network, transport>>
    /\ UNCHANGED <<taken, phase, readUnits, resetRead, processed, rec, bodyWaits, written, sent,
                   acked, aborted, owed, ackedControl, advStream, advConnection, goawayId,
                   firstRequestRead, shuttingDown, counted>>

Next ==
    \/ Open \/ ReadClose \/ Acknowledge \/ Shutdown \/ ColibriStep
    \/ PassFirstRequest \/ PassIdle \/ PassDrain
    \/ Deliver
    \/ \E r \in Requests :
        \/ SendUnit(r) \/ Cancel(r) \/ ArriveUnit(r) \/ ArriveReset(r) \/ ArriveStop(r)
        \/ Write(r) \/ PassHead(r) \/ PassBody(r)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What the server tells the client when it ends the connection.           *)

(* When a close the drain did not force reaches the client, the client     *)
(* knows of each request it opened below the GOAWAY whether the server     *)
(* took it.                                                                *)
NothingUnsaid ==
    closeRead /\ closed = "drained" =>
        \A r \in Requests :
            r < opened /\ r < goawayId /\ ~own[r] =>
                outcome[r] \in (IF processed[r] THEN {"response", "timeout", "cancelled"}
                                ELSE {"rejected", "timeout"})

GoawayBeforeClose == closeRead /\ closed = "drained" => goawayRead

(* RFC 9114 §4.1.1: H3_REQUEST_REJECTED says the server did not process    *)
(* the request, so the client may send it again.                           *)
RejectedUnprocessed == \A r \in Requests : outcome[r] = "rejected" => ~processed[r]

(* RFC 9000 §3.5 has the client answer the server's STOP_SENDING with a    *)
(* RESET_STREAM. Only a reset the client chose is a cancel of its own,     *)
(* which the reset limit counts.                                           *)
OnlyChosenCounted == \A r \in Requests : counted[r] => own[r]

-----------------------------------------------------------------------------
(* Rule 2: each clock runs only while the client holds colibri up.         *)

(* Credit on its way to the client that would let it send its next unit    *)
(* of r, or any next unit.                                                 *)
StreamCreditComing(r) == \E p \in OnTheWay : p.limits[r] > cliSent[r]
ConnectionCreditComing == \E p \in OnTheWay : p.connection > TotalSent

(* The client has more of r to send and has spent the credit its next      *)
(* unit needs, none on its way would let it send, and the credit that      *)
(* would waits in colibri.                                                 *)
Held(r) ==
    /\ r < opened /\ ~cliReset[r] /\ cliSent[r] < Units
    /\ \/ /\ cliSent[r] >= limitStream[r] /\ ~StreamCreditComing(r)
          /\ StreamCreditOwed(r)
       \/ /\ TotalSent >= limitConnection /\ ~ConnectionCreditComing
          /\ ConnectionCreditOwed

(* The head clock judges only what the client has left of the head.        *)
HeadWaitsOnPeer ==
    \A r \in Requests : Quiescent /\ HeadRuns(r) /\ cliSent[r] < HeadUnits => ~Held(r)

BodyWaitsOnPeer == \A r \in Requests : Quiescent /\ BodyRuns(r) => ~Held(r)

(* A whole head on its way to colibri, whose arrival opens a request and   *)
(* stops the idle clock.                                                   *)
HeadOnItsWay ==
    \E r \in Requests :
        /\ r < opened /\ cliSent[r] >= HeadUnits /\ atQuic[r] < HeadUnits
        /\ phase[r] \in {"unseen", "head"}

(* The client has a request to make, or a head to finish.                  *)
WantsRequest ==
    \/ opened < N /\ ~goawayRead
    \/ \E r \in Requests : r < opened /\ ~cliReset[r] /\ cliSent[r] < HeadUnits

(* The idle clock never runs while the connection credit the client's      *)
(* next request needs waits in colibri, and no head on its way will stop   *)
(* it.                                                                     *)
IdleWaitsOnPeer ==
    Quiescent /\ IdleRuns /\ WantsRequest /\ ~HeadOnItsWay =>
        ~(TotalSent >= limitConnection /\ ~ConnectionCreditComing /\ ConnectionCreditOwed)

(* The send clock runs only while a packet of colibri's is on its way or   *)
(* read and unacknowledged, which the network or the client holds.         *)
SendWaitsOnPeer == Quiescent /\ SendRuns => inFlight # <<>> \/ delivered # {}

=============================================================================
