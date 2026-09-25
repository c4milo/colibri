---------------------------- MODULE H3Connection ----------------------------
(***************************************************************************)
(* One h3 connection between a colibri client and a colibri server (RFC   *)
(* 9114), as design §8 step 12 builds it. The client opens request         *)
(* streams in order and may cancel any of them. The server takes each      *)
(* stream in order, reads its request, and answers it. Its control stream  *)
(* carries SETTINGS and then any number of GOAWAY frames, up to            *)
(* MaxGoaways. QPACK runs in the client-to-server direction: the client's  *)
(* encoder stream carries inserts, a request's HEADERS frame may reference *)
(* them, and the server's decoder stream carries acknowledgments,          *)
(* cancellations and increments back (RFC 9204 §4.3, §4.4).                *)
(*                                                                         *)
(* A frame is one unit of flow control. Each request stream carries one    *)
(* HEADERS frame and Content DATA frames. Every frame the client sends     *)
(* counts against the server's connection window, and every insert also    *)
(* counts against the encoder stream's window (RFC 9000 §4.1). The server  *)
(* returns credit as colibri's quic does: it consumes a frame when h3      *)
(* reads it, and it raises a limit once the gain reaches a window over     *)
(* FlowCreditFraction. A HEADERS frame blocked on the dynamic table stays  *)
(* unconsumed (RFC 9204 §2.2.1, decision 80), and so does every frame      *)
(* behind it on its stream.                                                *)
(*                                                                         *)
(* A frame the client sends arrives at once, because the server reads      *)
(* each stream in its own action and the order it reads them in is free.   *)
(* A RESET_STREAM arrives in an action of its own. Frames the server sends *)
(* and new credit arrive in any order.                                     *)
(*                                                                         *)
(* The model leaves out what other models or checks cover: the QPACK       *)
(* table's evictions (spec/tla/qpack_tables), QPACK for responses, which   *)
(* is the same with the roles swapped, the client's control stream and     *)
(* its GOAWAY, which names push IDs, request streams' own windows, which   *)
(* bound no more than Content does, and window growth (decision 49), which *)
(* only adds credit.                                                       *)
(*                                                                         *)
(* The configurations check two scopes, because both at once pass five    *)
(* million states before TLC finishes. The shutdown configurations run    *)
(* GOAWAY, rejection, cancels and the control stream, with no QPACK and a  *)
(* window that never binds. The flow configurations run QPACK against flow *)
(* control, with no GOAWAY and no cancels (ClientCancels).                 *)
(*                                                                         *)
(* H3ConnectionTrace checks colibri against this model                    *)
(* (tools/h3_trace.sh, https://github.com/c4milo/colibri/issues/58). The  *)
(* simulator's h3 trace run logs this model's variables from a colibri    *)
(* client and server, and TLC must find each seed's log to be a behavior  *)
(* of Next. DecoderTable is FALSE for a seed whose server decoder allows  *)
(* no dynamic table.                                                      *)
(*                                                                        *)
(* Each rule constant is a rule colibri keeps. A configuration that turns  *)
(* one off must find a violation:                                          *)
(*   RejectAboveGoaway  the server refuses a stream at or above the ID its *)
(*                      GOAWAY named (RFC 9114 §5.2).                       *)
(*   GoawayNamesUntaken the GOAWAY names the first stream the server has   *)
(*                      not taken, not the last one it has.                *)
(*   GoawayNeverRises   a GOAWAY names no more than the previous one (§5.2).*)
(*   KeepControlOpen    the server never ends its control stream (§6.2.1).*)
(*   SilentAfterCancel  a stream the client cancelled reports nothing more.*)
(*   EncoderFirst       the encoder stream's frames go before request      *)
(*                      streams' frames (RFC 9000 §2.3).                   *)
(*   InsertNeedsCredit  the encoder inserts only when the encoder stream   *)
(*                      and the connection have credit for it (RFC 9204    *)
(*                      §2.1.3, decision 81). colibri broke this rule      *)
(*                      until this model found the deadlock that breaking  *)
(*                      it causes.                                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    N,                  \* request streams the client may open: indices 0..N-1, stream IDs 4i
    Content,            \* DATA frames each request carries after its HEADERS frame
    MaxInserts,         \* inserts the client's encoder makes at most
    BlockedStreams,     \* the server's SETTINGS_QPACK_BLOCKED_STREAMS
    ConnectionWindow,   \* the server's connection receive window, in frames
    EncoderWindow,      \* the server's receive window on the client's encoder stream
    MaxGoaways,         \* GOAWAY frames the server sends at most
    ClientCancels,      \* whether the client may cancel requests
    DecoderTable,       \* whether the server's decoder allows a dynamic table (RFC 9204 §3.2.3)
    RejectAboveGoaway, GoawayNamesUntaken, GoawayNeverRises, KeepControlOpen,
    SilentAfterCancel, EncoderFirst, InsertNeedsCredit

ASSUME N \in Nat \ {0} /\ Content \in Nat /\ MaxInserts \in Nat /\ BlockedStreams \in Nat
ASSUME ConnectionWindow \in Nat \ {0} /\ EncoderWindow \in Nat \ {0} /\ MaxGoaways \in Nat
ASSUME ClientCancels \in BOOLEAN /\ DecoderTable \in BOOLEAN
ASSUME \A rule \in {RejectAboveGoaway, GoawayNamesUntaken, GoawayNeverRises, KeepControlOpen,
                    SilentAfterCancel, EncoderFirst, InsertNeedsCredit} : rule \in BOOLEAN

Requests == 0..(N - 1)
Units == 1 + Content
Total == N * Units + MaxInserts
\* No GOAWAY yet. It is above every stream, so "at or above the GOAWAY" holds for none.
NoGoaway == N + 1
\* colibri's quic `flow_credit_fraction`.
FlowCreditFraction == 2

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

RECURSIVE SumOver(_, _)
SumOver(f, S) == IF S = {} THEN 0
                 ELSE LET x == CHOOSE x \in S : TRUE IN f[x] + SumOver(f, S \ {x})

Settings == [type |-> "settings", id |-> 0]
Goaway(g) == [type |-> "goaway", id |-> g]
Acknowledgment(r) == [kind |-> "acknowledgment", stream |-> r, count |-> 0]
Cancellation(r) == [kind |-> "cancellation", stream |-> r, count |-> 0]
Increment(count) == [kind |-> "increment", stream |-> 0, count |-> count]

Phases == {"unseen", "head", "blocked", "content", "done", "answered", "abandoned"}

VARIABLES
    \* The client.
    opened,             \* request streams opened, in order
    inserted,           \* the encoder's insert count
    known,              \* the encoder's Known Received Count (RFC 9204 §2.1.4)
    ric,                \* each request's Required Insert Count (§4.5.1.1)
    outstanding,        \* the Required Insert Count of each unacknowledged section, or 0
    encoderQueued,      \* inserts written and not yet sent
    requestQueued,      \* each request's frames written and not yet sent
    encoderSent,        \* inserts sent
    requestSent,        \* each request's frames sent
    connectionLimit,    \* the server's MAX_DATA, as the client knows it
    encoderLimit,       \* the server's MAX_STREAM_DATA for the encoder stream, likewise
    settingsReceived,   \* whether the server's SETTINGS arrived
    goawayReceived,     \* the last GOAWAY's ID, or NoGoaway
    outcome,            \* how each request ended, as the client saw it
    reset,              \* each stream's RESET_STREAM from the client: none, sent, arrived, read
    \* The server.
    taken,              \* streams taken, in order: `next_index`
    phase,              \* where each request is
    processed,          \* whether each request went to the application (RFC 9114 §4.1.1)
    consumed,           \* each request's frames h3 has read
    encoderConsumed,    \* inserts the decoder has read: its insert count
    decoderKnown,       \* the insert count the decoder has reported
    decoderStream,      \* decoder instructions in flight
    toClient,           \* what each stream carries to the client: none, response, rejected
    goawaySent,         \* the last GOAWAY's ID, or NoGoaway
    goawayCount,        \* GOAWAY frames sent
    control,            \* the control stream's frames in flight
    controlEnded,       \* whether the server ended its control stream
    broken              \* the first rule a step broke, or "none"

client == <<opened, inserted, known, ric, outstanding, encoderQueued, requestQueued,
            encoderSent, requestSent, connectionLimit, encoderLimit, settingsReceived,
            goawayReceived, outcome, reset>>
server == <<taken, phase, processed, consumed, encoderConsumed, decoderKnown, decoderStream,
            toClient, goawaySent, goawayCount, control, controlEnded, broken>>
vars == <<client, server>>

Instructions == [kind : {"acknowledgment", "cancellation", "increment"},
                 stream : Requests, count : 0..MaxInserts]

TypeOK ==
    /\ opened \in 0..N /\ inserted \in 0..MaxInserts /\ known \in 0..MaxInserts
    /\ ric \in [Requests -> 0..MaxInserts] /\ outstanding \in [Requests -> 0..MaxInserts]
    /\ encoderQueued \in 0..MaxInserts /\ encoderSent \in 0..MaxInserts
    /\ requestQueued \in [Requests -> 0..Units] /\ requestSent \in [Requests -> 0..Units]
    /\ connectionLimit \in 0..(Total + ConnectionWindow)
    /\ encoderLimit \in 0..(MaxInserts + EncoderWindow)
    /\ settingsReceived \in BOOLEAN /\ goawayReceived \in 0..NoGoaway
    /\ outcome \in [Requests -> {"none", "response", "rejected", "cancelled"}]
    /\ reset \in [Requests -> {"none", "sent", "arrived", "read"}]
    /\ taken \in 0..N /\ phase \in [Requests -> Phases]
    /\ processed \in [Requests -> BOOLEAN] /\ consumed \in [Requests -> 0..Units]
    /\ encoderConsumed \in 0..MaxInserts /\ decoderKnown \in 0..MaxInserts
    /\ decoderStream \in Seq(Instructions)
    /\ toClient \in [Requests -> {"none", "response", "rejected"}]
    /\ goawaySent \in 0..NoGoaway /\ goawayCount \in 0..MaxGoaways
    /\ control \in Seq({Settings} \cup {Goaway(g) : g \in 0..N})
    /\ controlEnded \in BOOLEAN /\ broken \in STRING

Init ==
    /\ opened = 0 /\ inserted = 0 /\ known = 0
    /\ ric = [r \in Requests |-> 0] /\ outstanding = [r \in Requests |-> 0]
    /\ encoderQueued = 0 /\ requestQueued = [r \in Requests |-> 0]
    /\ encoderSent = 0 /\ requestSent = [r \in Requests |-> 0]
    /\ connectionLimit = ConnectionWindow /\ encoderLimit = EncoderWindow
    /\ settingsReceived = FALSE /\ goawayReceived = NoGoaway
    /\ outcome = [r \in Requests |-> "none"] /\ reset = [r \in Requests |-> "none"]
    /\ taken = 0 /\ phase = [r \in Requests |-> "unseen"]
    /\ processed = [r \in Requests |-> FALSE] /\ consumed = [r \in Requests |-> 0]
    /\ encoderConsumed = 0 /\ decoderKnown = 0 /\ decoderStream = <<>>
    /\ toClient = [r \in Requests |-> "none"]
    /\ goawaySent = NoGoaway /\ goawayCount = 0
    \* RFC 9114 §6.2.1: SETTINGS is the control stream's first frame, sent at `start`.
    /\ control = <<Settings>> /\ controlEnded = FALSE
    /\ broken = "none"

Break(rule) == broken' = IF broken = "none" THEN rule ELSE broken

ConnectionSent == encoderSent + SumOver(requestSent, Requests)
ConnectionConsumed == encoderConsumed + SumOver(consumed, Requests)

(***************************************************************************)
(* The client.                                                             *)
(***************************************************************************)

(* RFC 9204 §2.1.2: the streams whose section could block.                *)
CouldBlock == {q \in Requests : outstanding[q] > known}

(* RFC 9204 §2.1.3: the encoder stream and the connection have credit for *)
(* every insert already written and one more.                              *)
InsertCredit ==
    /\ encoderSent + encoderQueued < encoderLimit
    /\ ConnectionSent + encoderQueued < connectionLimit

(* The client opens the next request stream and writes its HEADERS frame, *)
(* first writing an insert when the encoder makes one. The section         *)
(* references entries below `required`, or none when it is 0.              *)
Open ==
    /\ opened < N
    \* RFC 9114 §5.2: "Endpoints MUST NOT initiate new requests ... after receipt of a GOAWAY".
    /\ goawayReceived = NoGoaway
    /\ \E insert \in BOOLEAN, required \in 0..MaxInserts :
        \* RFC 9204 §3.2.3: the dynamic table is used only once the peer's SETTINGS allow one.
        /\ insert => (DecoderTable /\ settingsReceived /\ inserted < MaxInserts /\ (InsertNeedsCredit => InsertCredit))
        /\ required <= inserted + (IF insert THEN 1 ELSE 0)
        /\ required > known => Cardinality(CouldBlock) < BlockedStreams
        /\ inserted' = inserted + (IF insert THEN 1 ELSE 0)
        /\ encoderQueued' = encoderQueued + (IF insert THEN 1 ELSE 0)
        /\ ric' = [ric EXCEPT ![opened] = required]
        /\ outstanding' = [outstanding EXCEPT ![opened] = required]
    /\ requestQueued' = [requestQueued EXCEPT ![opened] = Units]
    /\ opened' = opened + 1
    /\ UNCHANGED <<known, encoderSent, requestSent, connectionLimit, encoderLimit,
                   settingsReceived, goawayReceived, outcome, reset>>
    /\ UNCHANGED server

(* The encoder stream has an insert and credit on its own stream.         *)
EncoderReady == encoderQueued > 0 /\ encoderSent < encoderLimit

SendInsert ==
    /\ EncoderReady
    /\ ConnectionSent < connectionLimit
    /\ encoderQueued' = encoderQueued - 1
    /\ encoderSent' = encoderSent + 1
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, requestQueued, requestSent,
                   connectionLimit, encoderLimit, settingsReceived, goawayReceived, outcome, reset>>
    /\ UNCHANGED server

SendFrame(r) ==
    /\ requestQueued[r] > 0
    /\ ConnectionSent < connectionLimit
    \* RFC 9000 §2.3: h3 gives its own streams the lower priority value, so a request stream
    \* sends only when the encoder stream has nothing it may send.
    /\ EncoderFirst => ~EncoderReady
    /\ requestQueued' = [requestQueued EXCEPT ![r] = requestQueued[r] - 1]
    /\ requestSent' = [requestSent EXCEPT ![r] = requestSent[r] + 1]
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, encoderSent,
                   connectionLimit, encoderLimit, settingsReceived, goawayReceived, outcome, reset>>
    /\ UNCHANGED server

(* RFC 9114 §4.1.1: the client cancels a request by resetting its stream. *)
Cancel(r) ==
    /\ ClientCancels
    /\ r < opened
    /\ outcome[r] = "none"
    /\ outcome' = [outcome EXCEPT ![r] = "cancelled"]
    /\ requestQueued' = [requestQueued EXCEPT ![r] = 0]
    /\ reset' = [reset EXCEPT ![r] = "sent"]
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, encoderSent,
                   requestSent, connectionLimit, encoderLimit, settingsReceived, goawayReceived>>
    /\ UNCHANGED server

(* The client reads the next frame of the server's control stream.        *)
ReadControl ==
    /\ control # <<>>
    /\ LET frame == Head(control) IN
        IF frame.type = "settings"
        THEN /\ settingsReceived' = TRUE
             /\ UNCHANGED <<goawayReceived, broken>>
        \* RFC 9114 §6.2.1: a control stream whose first frame is not SETTINGS.
        ELSE IF ~settingsReceived
        THEN /\ Break("H3_MISSING_SETTINGS")
             /\ UNCHANGED <<settingsReceived, goawayReceived>>
        \* RFC 9114 §5.2: "Receiving a GOAWAY containing a larger identifier than previously
        \* received MUST be treated as a connection error of type H3_ID_ERROR."
        ELSE IF frame.id > goawayReceived
        THEN /\ Break("H3_ID_ERROR: a GOAWAY rose")
             /\ UNCHANGED <<settingsReceived, goawayReceived>>
        ELSE /\ goawayReceived' = frame.id
             /\ UNCHANGED <<settingsReceived, broken>>
    /\ control' = Tail(control)
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, requestQueued,
                   encoderSent, requestSent, connectionLimit, encoderLimit, outcome, reset>>
    /\ UNCHANGED <<taken, phase, processed, consumed, encoderConsumed, decoderKnown,
                   decoderStream, toClient, goawaySent, goawayCount, controlEnded>>

(* RFC 9114 §6.2.1: "If either control stream is closed at any point, this *)
(* MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM."*)
SeeControlEnd ==
    /\ control = <<>> /\ controlEnded /\ broken = "none"
    /\ Break("H3_CLOSED_CRITICAL_STREAM")
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, phase, processed, consumed, encoderConsumed, decoderKnown,
                   decoderStream, toClient, goawaySent, goawayCount, control, controlEnded>>

(* The client reads what the server sent on a request stream: a whole     *)
(* response, or a RESET_STREAM with H3_REQUEST_REJECTED.                   *)
ReadAnswer(r) ==
    /\ toClient[r] # "none"
    /\ toClient' = [toClient EXCEPT ![r] = "none"]
    /\ IF outcome[r] = "none"
       THEN /\ outcome' = [outcome EXCEPT ![r] = toClient[r]]
            /\ UNCHANGED broken
       ELSE /\ UNCHANGED outcome
            /\ IF SilentAfterCancel THEN UNCHANGED broken ELSE Break("a request ended two ways")
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, requestQueued,
                   encoderSent, requestSent, connectionLimit, encoderLimit, settingsReceived,
                   goawayReceived, reset>>
    /\ UNCHANGED <<taken, phase, processed, consumed, encoderConsumed, decoderKnown,
                   decoderStream, goawaySent, goawayCount, control, controlEnded>>

(* The server's STOP_SENDING on a stream it refused arrives, and the       *)
(* client's quic resets its side (RFC 9000 §3.5). It may arrive before or *)
(* after the client reads the refusal, and a quic that has had every octet *)
(* acknowledged sends no reset, so the action may never happen.            *)
StopSending(r) ==
    /\ phase[r] = "abandoned" /\ reset[r] = "none"
    /\ reset' = [reset EXCEPT ![r] = "sent"]
    /\ requestQueued' = [requestQueued EXCEPT ![r] = 0]
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, encoderSent,
                   requestSent, connectionLimit, encoderLimit, settingsReceived, goawayReceived,
                   outcome>>
    /\ UNCHANGED server

(* The encoder reads the next decoder instruction (RFC 9204 §4.4).         *)
ReadDecoder ==
    /\ decoderStream # <<>>
    /\ LET instruction == Head(decoderStream) IN
        CASE instruction.kind = "acknowledgment" ->
                \* RFC 9204 §4.4.1: an acknowledgment for a stream with no outstanding section
                \* is QPACK_DECODER_STREAM_ERROR.
                /\ IF outstanding[instruction.stream] = 0
                   THEN Break("QPACK_DECODER_STREAM_ERROR: nothing to acknowledge")
                   ELSE UNCHANGED broken
                /\ known' = Max(known, outstanding[instruction.stream])
                /\ outstanding' = [outstanding EXCEPT ![instruction.stream] = 0]
          [] instruction.kind = "cancellation" ->
                /\ outstanding' = [outstanding EXCEPT ![instruction.stream] = 0]
                /\ UNCHANGED <<known, broken>>
          [] instruction.kind = "increment" ->
                \* RFC 9204 §4.4.3: an increment past what the encoder sent is
                \* QPACK_DECODER_STREAM_ERROR.
                /\ IF known + instruction.count > inserted
                   THEN Break("QPACK_DECODER_STREAM_ERROR: increment past the inserts")
                   ELSE UNCHANGED broken
                /\ known' = Min(known + instruction.count, inserted)
                /\ UNCHANGED outstanding
    /\ decoderStream' = Tail(decoderStream)
    /\ UNCHANGED <<opened, inserted, ric, encoderQueued, requestQueued, encoderSent,
                   requestSent, connectionLimit, encoderLimit, settingsReceived, goawayReceived,
                   outcome, reset>>
    /\ UNCHANGED <<taken, phase, processed, consumed, encoderConsumed, decoderKnown, toClient,
                   goawaySent, goawayCount, control, controlEnded>>

(* A RESET_STREAM from the client arrives.                                *)
DeliverReset(r) ==
    /\ reset[r] = "sent"
    /\ reset' = [reset EXCEPT ![r] = "arrived"]
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, requestQueued,
                   encoderSent, requestSent, connectionLimit, encoderLimit, settingsReceived,
                   goawayReceived, outcome>>
    /\ UNCHANGED server

(* The server's MAX_DATA and MAX_STREAM_DATA arrive. RFC 9000 §4.2 leaves  *)
(* when to send one to the receiver; colibri sends one once the gain is at *)
(* least the window over FlowCreditFraction.                               *)
CreditConnection ==
    LET gain == ConnectionConsumed + ConnectionWindow - connectionLimit IN
    /\ gain > 0 /\ gain >= ConnectionWindow \div FlowCreditFraction
    /\ connectionLimit' = ConnectionConsumed + ConnectionWindow
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, requestQueued,
                   encoderSent, requestSent, encoderLimit, settingsReceived, goawayReceived,
                   outcome, reset>>
    /\ UNCHANGED server

CreditEncoder ==
    LET gain == encoderConsumed + EncoderWindow - encoderLimit IN
    /\ gain > 0 /\ gain >= EncoderWindow \div FlowCreditFraction
    /\ encoderLimit' = encoderConsumed + EncoderWindow
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, requestQueued,
                   encoderSent, requestSent, connectionLimit, settingsReceived, goawayReceived,
                   outcome, reset>>
    /\ UNCHANGED server

(***************************************************************************)
(* The server.                                                             *)
(***************************************************************************)

(* RFC 9000 §3.2: a stream is open once a frame for it, or for a later     *)
(* stream of its type, arrives.                                            *)
Live(r) == \E q \in r..(N - 1) : requestSent[q] > 0 \/ reset[q] \in {"arrived", "read"}

(* RFC 9204 §2.2.2.2: the decoder cancels a stream it abandons. A decoder *)
(* with no dynamic table MAY omit it, and colibri's does.                  *)
Cancelled(r) == IF DecoderTable THEN Append(decoderStream, Cancellation(r)) ELSE decoderStream

(* The server takes the next stream (`accept`). After its GOAWAY, a stream *)
(* at or above the ID it named is rejected (RFC 9114 §5.2), with           *)
(* H3_REQUEST_REJECTED (§4.1.1), and the decoder cancels it (RFC 9204      *)
(* §2.2.2.2).                                                              *)
Accept ==
    /\ taken < N /\ Live(taken)
    /\ IF RejectAboveGoaway /\ taken >= goawaySent
       THEN /\ phase' = [phase EXCEPT ![taken] = "abandoned"]
            /\ toClient' = [toClient EXCEPT ![taken] = "rejected"]
            /\ decoderStream' = Cancelled(taken)
       ELSE /\ phase' = [phase EXCEPT ![taken] = "head"]
            /\ UNCHANGED <<toClient, decoderStream>>
    /\ taken' = taken + 1
    /\ UNCHANGED client
    /\ UNCHANGED <<processed, consumed, encoderConsumed, decoderKnown, goawaySent, goawayCount,
                   control, controlEnded, broken>>

(* The decoder reads the next insert (RFC 9204 §4.3).                      *)
ReadInsert ==
    /\ encoderConsumed < encoderSent
    /\ encoderConsumed' = encoderConsumed + 1
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, phase, processed, consumed, decoderKnown, decoderStream, toClient,
                   goawaySent, goawayCount, control, controlEnded, broken>>

(* A request's section decodes: the request goes to the application, which *)
(* is what RFC 9114 §4.1.1 calls processed, and the decoder acknowledges   *)
(* the section when it referenced the dynamic table (RFC 9204 §4.4.1).     *)
Decode(r) ==
    /\ phase' = [phase EXCEPT ![r] = IF Units = 1 THEN "done" ELSE "content"]
    /\ consumed' = [consumed EXCEPT ![r] = 1]
    /\ processed' = [processed EXCEPT ![r] = TRUE]
    /\ IF ric[r] > 0
       THEN /\ decoderStream' = Append(decoderStream, Acknowledgment(r))
            /\ decoderKnown' = Max(decoderKnown, ric[r])
       ELSE UNCHANGED <<decoderStream, decoderKnown>>

(* The streams whose section still waits for inserts (RFC 9204 §2.2.1).   *)
StillBlocked == {q \in Requests : phase[q] = "blocked" /\ ric[q] > encoderConsumed}

(* h3 reads a HEADERS frame. The peer's reset is read first (`advance`).   *)
ReadHeaders(r) ==
    /\ phase[r] = "head" /\ requestSent[r] > 0 /\ reset[r] # "arrived"
    /\ IF ric[r] <= encoderConsumed
       THEN /\ Decode(r)
            /\ UNCHANGED broken
       ELSE /\ phase' = [phase EXCEPT ![r] = "blocked"]
            \* RFC 9204 §2.1.2: more blocked streams than the decoder allows is
            \* QPACK_DECOMPRESSION_FAILED.
            /\ IF Cardinality(StillBlocked) >= BlockedStreams
               THEN Break("QPACK_DECOMPRESSION_FAILED: too many blocked streams")
               ELSE UNCHANGED broken
            /\ UNCHANGED <<consumed, processed, decoderStream, decoderKnown>>
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, encoderConsumed, toClient, goawaySent, goawayCount, control,
                   controlEnded>>

(* A blocked section whose inserts arrived decodes.                        *)
Unblock(r) ==
    /\ phase[r] = "blocked" /\ ric[r] <= encoderConsumed /\ reset[r] # "arrived"
    /\ Decode(r)
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, encoderConsumed, toClient, goawaySent, goawayCount, control,
                   controlEnded, broken>>

(* h3 reads a DATA frame, and the stream's end with the last one.         *)
ReadContent(r) ==
    /\ phase[r] = "content" /\ consumed[r] < requestSent[r] /\ reset[r] # "arrived"
    /\ consumed' = [consumed EXCEPT ![r] = consumed[r] + 1]
    /\ phase' = [phase EXCEPT ![r] = IF consumed[r] + 1 = Units THEN "done" ELSE "content"]
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, processed, encoderConsumed, decoderKnown, decoderStream, toClient,
                   goawaySent, goawayCount, control, controlEnded, broken>>

(* The application answers a whole request.                               *)
Respond(r) ==
    /\ phase[r] = "done"
    /\ phase' = [phase EXCEPT ![r] = "answered"]
    /\ toClient' = [toClient EXCEPT ![r] = "response"]
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, processed, consumed, encoderConsumed, decoderKnown, decoderStream,
                   goawaySent, goawayCount, control, controlEnded, broken>>

(* h3 reads the client's reset: what arrived is discarded, which returns   *)
(* its credit (RFC 9000 §4.5), and the decoder cancels the stream (RFC     *)
(* 9204 §2.2.2.2). A stream whose end h3 read is gone, and its reset is    *)
(* read by no one.                                                         *)
ReadReset(r) ==
    /\ reset[r] = "arrived"
    /\ phase[r] \in {"head", "blocked", "content", "abandoned"}
    /\ reset' = [reset EXCEPT ![r] = "read"]
    /\ consumed' = [consumed EXCEPT ![r] = requestSent[r]]
    /\ phase' = [phase EXCEPT ![r] = "abandoned"]
    /\ decoderStream' = Cancelled(r)
    /\ UNCHANGED <<opened, inserted, known, ric, outstanding, encoderQueued, requestQueued,
                   encoderSent, requestSent, connectionLimit, encoderLimit, settingsReceived,
                   goawayReceived, outcome>>
    /\ UNCHANGED <<taken, processed, encoderConsumed, decoderKnown, toClient, goawaySent,
                   goawayCount, control, controlEnded, broken>>

(* h3 discards what arrives on a stream it refused (`discard`).            *)
Discard(r) ==
    /\ phase[r] = "abandoned" /\ consumed[r] < requestSent[r] /\ reset[r] # "arrived"
    /\ consumed' = [consumed EXCEPT ![r] = requestSent[r]]
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, phase, processed, encoderConsumed, decoderKnown, decoderStream,
                   toClient, goawaySent, goawayCount, control, controlEnded, broken>>

(* RFC 9204 §4.4.3: the decoder reports inserts no acknowledgment did.    *)
ReportInserts ==
    /\ encoderConsumed > decoderKnown
    /\ decoderStream' = Append(decoderStream, Increment(encoderConsumed - decoderKnown))
    /\ decoderKnown' = encoderConsumed
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, phase, processed, consumed, encoderConsumed, toClient, goawaySent,
                   goawayCount, control, controlEnded, broken>>

(* The server sends a GOAWAY (`shutdown`, `write_goaway`).                 *)
Shutdown ==
    /\ goawayCount < MaxGoaways /\ ~controlEnded
    /\ LET named == IF GoawayNamesUntaken THEN taken ELSE Max(taken - 1, 0)
           value == IF GoawayNeverRises THEN Min(goawaySent, named) ELSE named
       IN /\ control' = Append(control, Goaway(value))
          /\ goawaySent' = value
    /\ goawayCount' = goawayCount + 1
    /\ controlEnded' = ~KeepControlOpen
    /\ UNCHANGED client
    /\ UNCHANGED <<taken, phase, processed, consumed, encoderConsumed, decoderKnown,
                   decoderStream, toClient, broken>>

Next ==
    \/ Open \/ SendInsert \/ ReadControl \/ SeeControlEnd \/ ReadDecoder
    \/ CreditConnection \/ CreditEncoder
    \/ Accept \/ ReadInsert \/ ReportInserts \/ Shutdown
    \/ \E r \in Requests :
        \/ SendFrame(r) \/ Cancel(r) \/ ReadAnswer(r) \/ StopSending(r) \/ DeliverReset(r)
        \/ ReadHeaders(r) \/ Unblock(r) \/ ReadContent(r) \/ Respond(r) \/ ReadReset(r)
        \/ Discard(r)

(* Sending, delivery, reading and answering are fair. Opening, cancelling *)
(* and shutting down are the applications' choices. A frame a stream may   *)
(* send can lose its turn to another stream's, so sending is strongly      *)
(* fair.                                                                   *)
Fairness ==
    /\ SF_vars(SendInsert)
    /\ WF_vars(ReadControl) /\ WF_vars(SeeControlEnd) /\ WF_vars(ReadDecoder)
    /\ WF_vars(CreditConnection) /\ WF_vars(CreditEncoder)
    /\ WF_vars(Accept) /\ WF_vars(ReadInsert) /\ WF_vars(ReportInserts)
    /\ \A r \in Requests :
        /\ SF_vars(SendFrame(r))
        /\ WF_vars(ReadAnswer(r)) /\ WF_vars(DeliverReset(r))
        /\ WF_vars(ReadHeaders(r)) /\ WF_vars(Unblock(r)) /\ WF_vars(ReadContent(r))
        /\ WF_vars(Respond(r)) /\ WF_vars(ReadReset(r)) /\ WF_vars(Discard(r))

Spec == Init /\ [][Next]_vars /\ Fairness

(* No rule broken, and nothing processed that a GOAWAY or a rejection says *)
(* was not.                                                                *)
Safe ==
    /\ broken = "none"
    \* RFC 9114 §5.2: "Requests or pushes with the indicated identifier or greater are rejected".
    /\ \A r \in Requests : r >= goawaySent => ~processed[r]
    \* RFC 9114 §4.1.1: "The client can treat requests rejected by the server as though they
    \* had never been sent at all".
    /\ \A r \in Requests : outcome[r] = "rejected" => ~processed[r]

(* Every request the client opens ends: with a response, a rejection, or  *)
(* the client's own cancel.                                                *)
Settles == \A r \in Requests : (r < opened) ~> (outcome[r] # "none")

=============================================================================
