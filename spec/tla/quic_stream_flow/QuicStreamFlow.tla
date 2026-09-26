-------------------------- MODULE QuicStreamFlow --------------------------
(***************************************************************************)
(* One QUIC stream and the connection's flow control (RFC 9000 §3, §4), as *)
(* colibri keeps them (src/quic/flow.zig, src/quic/stream/, and            *)
(* connection_flow.zig and connection_stream/ in src/quic/connection/). A  *)
(* sender sends Len octets on one stream, the FIN with the last, and the   *)
(* receiver's application reads them. Each frame goes in a packet of its   *)
(* own. The network may lose a frame or its acknowledgment, deliver frames *)
(* in any order, and deliver a frame twice when it was sent again while a  *)
(* copy was on its way. LossMax bounds the losses in one behavior.         *)
(*                                                                         *)
(* Loss recovery (RFC 9002) is not modeled; spec/tla/probe_timeout checks  *)
(* it. A frame's acknowledgment arrives with it or is lost. A frame gone   *)
(* with no acknowledgment is declared lost in the end, and with Spurious a *)
(* frame still on its way may be declared lost too.                        *)
(*                                                                         *)
(* colibri's rules, as this model has them:                                *)
(*   - a sender frames a new octet only below both limits (§4.1), and      *)
(*     sends a lost octet again until it resets the stream (§13.3);        *)
(*   - a receiver advertises a new limit once consumed + window - limit    *)
(*     reaches window / Fraction (flow.Receiver), and sends                *)
(*     MAX_STREAM_DATA only in "Recv" (§13.3);                             *)
(*   - a limit frame, a BLOCKED frame, RESET_STREAM and STOP_SENDING are   *)
(*     owed again when the packet carrying the most recent one of their    *)
(*     kind is declared lost (frame.Latest, §13.3);                        *)
(*   - a BLOCKED frame goes out once per limit, and again one PTO after    *)
(*     the last ack-eliciting packet while the sender is blocked with      *)
(*     nothing in flight (Repeat,                                          *)
(*     https://github.com/c4milo/colibri/issues/43);                       *)
(*   - a received BLOCKED frame changes nothing;                           *)
(*   - colibri drops an owed BLOCKED or STOP_SENDING frame once it no      *)
(*     longer applies. Here the flag stays, and nothing sends it.          *)
(*                                                                         *)
(* The idle timeout (§10.1) closes the connection once nothing is in       *)
(* flight, nothing is owed and no shorter timer is armed. A PTO and the    *)
(* BLOCKED repeat are both shorter. The receiver's application may read    *)
(* later than the idle timeout, so without Repeat a blocked sender loses   *)
(* the connection. Configuration no_repeat keeps that path.                *)
(*                                                                         *)
(* A reset stream's final size counts against the connection's limit       *)
(* (§4.5). With ReturnOnReset, the octets the application did not read     *)
(* give their connection credit back when the reset arrives, because §4.5  *)
(* calls the final size "the amount of flow control credit that is         *)
(* consumed by a stream". Without it the connection loses that credit for  *)
(* good, which is what colibri did until this model found it:              *)
(* configuration reset_leak keeps that path.                               *)
(*                                                                         *)
(* Window growth (decision 49) is left out: both windows stay fixed.       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Len,                \* octets the sender sends, the FIN with the last
    StreamWindow,       \* the receiver's stream window, and the stream's first limit
    ConnectionWindow,   \* the receiver's connection window, and the connection's first limit
    Fraction,           \* flow_credit_fraction
    Repeat,             \* whether a blocked sender with nothing in flight sends BLOCKED again
    ResendLimits,       \* whether a lost MAX_DATA or MAX_STREAM_DATA is owed again
    ReturnOnReset,      \* whether a reset gives the octets never read back to the connection
    Resets,             \* whether the sender's application may reset the stream
    Stops,              \* whether the receiver's application may send STOP_SENDING
    Spurious,           \* whether a frame still on its way may be declared lost
    LossMax             \* frames and acknowledgments the network may lose in one behavior

ASSUME /\ {Len, StreamWindow, ConnectionWindow, Fraction} \subseteq Nat \ {0}
       /\ LossMax \in Nat
       /\ {Repeat, ResendLimits, ReturnOnReset, Resets, Stops, Spurious} \subseteq BOOLEAN

Sender == "sender"
Receiver == "receiver"
Endpoints == {Sender, Receiver}
None == -1
Octets == 0..Len-1
StreamMax == Len + StreamWindow
ConnectionMax == Len + ConnectionWindow
Larger(a, b) == IF a > b THEN a ELSE b

(* One frame. A STREAM frame carries one octet, and the FIN when it is the *)
(* last; every other frame carries one number.                            *)
Frame(type, value) == [type |-> type, value |-> value]
SenderFrames ==
    {Frame("stream", i) : i \in Octets}
    \cup {Frame("data_blocked", v) : v \in 0..ConnectionMax}
    \cup {Frame("stream_data_blocked", v) : v \in 0..StreamMax}
    \cup {Frame("reset_stream", v) : v \in 0..Len}
ReceiverFrames ==
    {Frame("max_data", v) : v \in 0..ConnectionMax}
    \cup {Frame("max_stream_data", v) : v \in 0..StreamMax}
    \cup {Frame("stop_sending", 0)}
FramesOf(e) == IF e = Sender THEN SenderFrames ELSE ReceiverFrames

SendStates == {"ready", "send", "data_sent", "data_recvd", "reset_sent", "reset_recvd"}
RecvStates == {"recv", "size_known", "data_recvd", "data_read", "reset_recvd", "reset_read"}
(* The frame kinds a frame.Latest tracks.                                  *)
LatestKinds == {"data_blocked", "stream_data_blocked", "reset_stream",
                "max_data", "max_stream_data", "stop_sending"}
LatestValue == [owed : BOOLEAN, sent : BOOLEAN, value : {None} \cup 0..ConnectionMax + StreamMax]

VARIABLES
    \* the sender
    sendState,          \* the sending part (§3.1)
    framed,             \* octets framed at least once: the send limits' `used`
    sendStreamLimit,    \* the stream limit the receiver gave
    sendConnectionLimit,\* the connection limit the receiver gave
    acked,              \* octets acknowledged
    lost,               \* octets declared lost and owed again
    streamReported,     \* the stream limit a STREAM_DATA_BLOCKED last named, or None
    connectionReported, \* the connection limit a DATA_BLOCKED last named, or None
    sentAny,            \* whether the sender has sent an ack-eliciting packet
    \* the receiver
    opened,             \* whether a frame of the sender's created the stream (§3.2)
    recvState,          \* the receiving part (§3.2)
    got,                \* octets that arrived and were kept
    finalSize,          \* the final size once known (§4.5), or None
    highest,            \* one past the largest offset received
    recvStreamLimit,    \* the stream limit advertised
    recvStreamUsed,     \* the stream's high-water mark
    recvStreamConsumed, \* octets of the stream the application took
    recvConnectionLimit,
    recvConnectionUsed,
    recvConnectionConsumed,
    \* both
    latest,             \* latest[k]: the frame.Latest of kind k
    net,                \* net[e]: frames e sent that are on their way
    inflight,           \* inflight[e]: frames e sent, neither acknowledged nor declared lost
    losses,             \* frames and acknowledgments lost so far
    closed,             \* whether the idle timeout closed the connection
    failure,            \* the connection error the receiver raised, or "none"
    forbidden           \* whether a frame went out in a state §3.3 forbids it in

senderVars == <<sendState, framed, sendStreamLimit, sendConnectionLimit, acked, lost,
                streamReported, connectionReported, sentAny>>
receiverVars == <<opened, recvState, got, finalSize, highest, recvStreamLimit, recvStreamUsed,
                  recvStreamConsumed, recvConnectionLimit, recvConnectionUsed,
                  recvConnectionConsumed>>
vars == <<senderVars, receiverVars, latest, net, inflight, losses, closed, failure, forbidden>>

TypeOK ==
    /\ sendState \in SendStates
    /\ framed \in 0..Len
    /\ sendStreamLimit \in 0..StreamMax /\ sendConnectionLimit \in 0..ConnectionMax
    /\ acked \subseteq Octets /\ lost \subseteq Octets
    /\ streamReported \in {None} \cup 0..StreamMax
    /\ connectionReported \in {None} \cup 0..ConnectionMax
    /\ sentAny \in BOOLEAN /\ opened \in BOOLEAN
    /\ recvState \in RecvStates
    /\ got \subseteq Octets
    /\ finalSize \in {None} \cup 0..Len
    /\ highest \in 0..Len
    /\ recvStreamLimit \in 0..StreamMax /\ recvConnectionLimit \in 0..ConnectionMax
    /\ recvStreamUsed \in 0..Len /\ recvConnectionUsed \in 0..Len
    /\ recvStreamConsumed \in 0..Len /\ recvConnectionConsumed \in 0..Len
    /\ latest \in [LatestKinds -> LatestValue]
    /\ \A e \in Endpoints : net[e] \cup inflight[e] \subseteq FramesOf(e)
    /\ losses \in 0..LossMax
    /\ closed \in BOOLEAN /\ forbidden \in BOOLEAN
    /\ failure \in {"none", "flow_control", "final_size"}

Init ==
    /\ sendState = "ready"
    /\ framed = 0
    /\ sendStreamLimit = StreamWindow
    /\ sendConnectionLimit = ConnectionWindow
    /\ acked = {} /\ lost = {}
    /\ streamReported = None /\ connectionReported = None
    /\ sentAny = FALSE
    /\ opened = FALSE
    /\ recvState = "recv"
    /\ got = {}
    /\ finalSize = None
    /\ highest = 0
    /\ recvStreamLimit = StreamWindow /\ recvStreamUsed = 0 /\ recvStreamConsumed = 0
    /\ recvConnectionLimit = ConnectionWindow /\ recvConnectionUsed = 0
    /\ recvConnectionConsumed = 0
    /\ latest = [k \in LatestKinds |-> [owed |-> FALSE, sent |-> FALSE, value |-> None]]
    /\ net = [e \in Endpoints |-> {}]
    /\ inflight = [e \in Endpoints |-> {}]
    /\ losses = 0
    /\ closed = FALSE
    /\ failure = "none"
    /\ forbidden = FALSE

Live == ~closed /\ failure = "none"

(* §3.3: the frames a part may not send in its state.                      *)
Forbidden(e, f) ==
    \/ e = Sender /\ f.type \in {"stream", "stream_data_blocked"}
                  /\ sendState \notin {"ready", "send", "data_sent"}
    \/ e = Sender /\ f.type = "reset_stream" /\ sendState \in {"data_recvd", "reset_recvd"}
    \/ e = Receiver /\ f.type = "max_stream_data" /\ recvState # "recv"
    \/ e = Receiver /\ f.type = "stop_sending" /\ recvState \in {"reset_recvd", "reset_read"}

Send(e, f) ==
    /\ net' = [net EXCEPT ![e] = @ \cup {f}]
    /\ inflight' = [inflight EXCEPT ![e] = @ \cup {f}]
    /\ forbidden' = (forbidden \/ Forbidden(e, f))

(* frame.Latest: packet `value` carried the most recent frame of kind k.   *)
Sent(k, v) == [latest EXCEPT ![k] = [owed |-> FALSE, sent |-> TRUE, value |-> v]]
Owe(k) == [latest EXCEPT ![k].owed = TRUE]

---------------------------------------------------------------------------
(* The sender.                                                             *)

MaySendData == sendState \in {"ready", "send"}
Retransmits == sendState \in {"send", "data_sent"}
Unframed == MaySendData /\ framed < Len
DataBlocked == framed = sendConnectionLimit /\ Unframed
StreamDataBlocked == framed = sendStreamLimit /\ Unframed

CanFrame == Live /\ Unframed /\ framed < sendStreamLimit /\ framed < sendConnectionLimit

FrameNew ==
    /\ CanFrame
    /\ framed' = framed + 1
    /\ sendState' = IF framed = Len - 1 THEN "data_sent" ELSE "send"
    /\ sentAny' = TRUE
    /\ Send(Sender, Frame("stream", framed))
    /\ UNCHANGED <<sendStreamLimit, sendConnectionLimit, acked, lost, streamReported,
                   connectionReported, receiverVars, latest, losses, closed, failure>>

CanRetransmit(i) == Live /\ i \in lost /\ Retransmits

Retransmit(i) ==
    /\ CanRetransmit(i)
    /\ lost' = lost \ {i}
    /\ Send(Sender, Frame("stream", i))
    /\ UNCHANGED <<sendState, framed, sendStreamLimit, sendConnectionLimit, acked,
                   streamReported, connectionReported, sentAny, receiverVars, latest,
                   losses, closed, failure>>

(* write_blocked_frame: a new limit reached, or a lost frame owed again.   *)
CanSendDataBlocked ==
    Live /\ DataBlocked
    /\ (connectionReported # sendConnectionLimit \/ latest["data_blocked"].owed)

SendDataBlocked ==
    /\ CanSendDataBlocked
    /\ connectionReported' = sendConnectionLimit
    /\ latest' = Sent("data_blocked", sendConnectionLimit)
    /\ sentAny' = TRUE
    /\ Send(Sender, Frame("data_blocked", sendConnectionLimit))
    /\ UNCHANGED <<sendState, framed, sendStreamLimit, sendConnectionLimit, acked, lost,
                   streamReported, receiverVars, losses, closed, failure>>

CanSendStreamDataBlocked ==
    Live /\ StreamDataBlocked
    /\ (streamReported # sendStreamLimit \/ latest["stream_data_blocked"].owed)

SendStreamDataBlocked ==
    /\ CanSendStreamDataBlocked
    /\ streamReported' = sendStreamLimit
    /\ latest' = Sent("stream_data_blocked", sendStreamLimit)
    /\ sentAny' = TRUE
    /\ Send(Sender, Frame("stream_data_blocked", sendStreamLimit))
    /\ UNCHANGED <<sendState, framed, sendStreamLimit, sendConnectionLimit, acked, lost,
                   connectionReported, receiverVars, losses, closed, failure>>

CanSendReset == Live /\ latest["reset_stream"].owed /\ sendState = "reset_sent"

(* §19.4: the final size is every octet framed, the same in every copy.    *)
SendReset ==
    /\ CanSendReset
    /\ latest' = Sent("reset_stream", framed)
    /\ Send(Sender, Frame("reset_stream", framed))
    /\ UNCHANGED <<senderVars, receiverVars, losses, closed, failure>>

(* §3.1: the application abandons the stream.                              *)
AppReset ==
    /\ Resets /\ Live /\ sendState \in {"ready", "send", "data_sent"}
    /\ sendState' = "reset_sent"
    /\ latest' = Owe("reset_stream")
    /\ UNCHANGED <<framed, sendStreamLimit, sendConnectionLimit, acked, lost, streamReported,
                   connectionReported, sentAny, receiverVars, net, inflight, losses, closed,
                   failure, forbidden>>

(* blocked_deadline_ns: armed one PTO after the last ack-eliciting packet  *)
(* while a limit holds octets back and nothing is in flight (§4.1).        *)
BlockedArmed ==
    Repeat /\ Live /\ sentAny /\ inflight[Sender] = {} /\ (DataBlocked \/ StreamDataBlocked)

BlockedRepeat ==
    /\ BlockedArmed
    /\ \/ DataBlocked /\ ~latest["data_blocked"].owed
       \/ StreamDataBlocked /\ ~latest["stream_data_blocked"].owed
    /\ latest' = [latest EXCEPT !["data_blocked"].owed = @ \/ DataBlocked,
                                !["stream_data_blocked"].owed = @ \/ StreamDataBlocked]
    /\ UNCHANGED <<senderVars, receiverVars, net, inflight, losses, closed, failure, forbidden>>

---------------------------------------------------------------------------
(* The receiver.                                                           *)

RecvClosed == recvState \in {"data_read", "reset_read"}
StreamGain == recvStreamConsumed + StreamWindow - recvStreamLimit
ConnectionGain == recvConnectionConsumed + ConnectionWindow - recvConnectionLimit
(* flow.Receiver.credit_frame_limit.                                       *)
Fresh(gain, window) == gain > 0 /\ gain >= window \div Fraction

CanSendMaxData ==
    Live /\ (Fresh(ConnectionGain, ConnectionWindow) \/ latest["max_data"].owed)

SendMaxData ==
    /\ CanSendMaxData
    /\ LET limit == IF Fresh(ConnectionGain, ConnectionWindow)
                    THEN recvConnectionConsumed + ConnectionWindow
                    ELSE recvConnectionLimit
       IN /\ recvConnectionLimit' = limit
          /\ latest' = Sent("max_data", limit)
          /\ Send(Receiver, Frame("max_data", limit))
    /\ UNCHANGED <<senderVars, opened, recvState, got, finalSize, highest, recvStreamLimit,
                   recvStreamUsed, recvStreamConsumed, recvConnectionUsed,
                   recvConnectionConsumed, losses, closed, failure>>

CanSendMaxStreamData ==
    Live /\ opened /\ recvState = "recv"
    /\ (Fresh(StreamGain, StreamWindow) \/ latest["max_stream_data"].owed)

SendMaxStreamData ==
    /\ CanSendMaxStreamData
    /\ LET limit == IF Fresh(StreamGain, StreamWindow)
                    THEN recvStreamConsumed + StreamWindow
                    ELSE recvStreamLimit
       IN /\ recvStreamLimit' = limit
          /\ latest' = Sent("max_stream_data", limit)
          /\ Send(Receiver, Frame("max_stream_data", limit))
    /\ UNCHANGED <<senderVars, opened, recvState, got, finalSize, highest, recvStreamUsed,
                   recvStreamConsumed, recvConnectionLimit, recvConnectionUsed,
                   recvConnectionConsumed, losses, closed, failure>>

WantsStop == recvState \in {"recv", "size_known"}

CanSendStopSending == Live /\ latest["stop_sending"].owed /\ WantsStop

SendStopSending ==
    /\ CanSendStopSending
    /\ latest' = Sent("stop_sending", 0)
    /\ Send(Receiver, Frame("stop_sending", 0))
    /\ UNCHANGED <<senderVars, receiverVars, losses, closed, failure>>

(* The application reads the next octet, which consumes credit (§4.1).     *)
Read ==
    /\ Live /\ recvState \in {"recv", "size_known", "data_recvd"}
    /\ recvStreamConsumed \in got
    /\ recvStreamConsumed' = recvStreamConsumed + 1
    /\ recvConnectionConsumed' = recvConnectionConsumed + 1
    /\ recvState' = IF recvState = "data_recvd" /\ recvStreamConsumed + 1 = finalSize
                    THEN "data_read" ELSE recvState
    /\ UNCHANGED <<senderVars, opened, got, finalSize, highest, recvStreamLimit, recvStreamUsed,
                   recvConnectionLimit, recvConnectionUsed, latest, net, inflight,
                   losses, closed, failure, forbidden>>

(* §3.2: the application learns of the reset.                              *)
ReadReset ==
    /\ Live /\ recvState = "reset_recvd"
    /\ recvState' = "reset_read"
    /\ UNCHANGED <<senderVars, opened, got, finalSize, highest, recvStreamLimit, recvStreamUsed,
                   recvStreamConsumed, recvConnectionLimit, recvConnectionUsed,
                   recvConnectionConsumed, latest, net, inflight, losses, closed, failure,
                   forbidden>>

(* §3.5: the application reads no more; connection_stream_send.stop_sending. *)
AppStop ==
    /\ Stops /\ Live /\ opened /\ WantsStop
    /\ ~latest["stop_sending"].owed /\ ~latest["stop_sending"].sent
    /\ latest' = Owe("stop_sending")
    /\ UNCHANGED <<senderVars, receiverVars, net, inflight, losses, closed, failure, forbidden>>

---------------------------------------------------------------------------
(* Frames arriving.                                                        *)

Fail(kind) ==
    /\ failure' = kind
    /\ UNCHANGED receiverVars

ReceiverIgnores == UNCHANGED <<receiverVars, failure>>

(* connection_stream_frames.take_stream: the connection's limit, then the  *)
(* stream's (§4.1), then the final size (§4.5), then the state (§3.2).     *)
TakeStream(i) ==
    LET reached == i + 1
        fin == i = Len - 1
        fresh == Larger(reached - recvStreamUsed, 0)
        sizeChanged ==
            IF fin THEN \/ finalSize # None /\ finalSize # reached
                        \/ finalSize = None /\ reached < highest
            ELSE finalSize # None /\ reached > finalSize
        size == IF fin THEN reached ELSE finalSize
        state == IF fin /\ recvState = "recv" THEN "size_known" ELSE recvState
        accepts == state \in {"recv", "size_known"}
        arrived == IF accepts THEN got \cup {i} ELSE got
        complete == accepts /\ size # None /\ \A k \in 0..size-1 : k \in arrived
    IN IF RecvClosed THEN ReceiverIgnores
       ELSE IF recvConnectionUsed + fresh > recvConnectionLimit \/ reached > recvStreamLimit
       THEN Fail("flow_control")
       ELSE IF sizeChanged THEN Fail("final_size")
       ELSE /\ opened' = TRUE
            /\ recvConnectionUsed' = recvConnectionUsed + fresh
            /\ recvStreamUsed' = Larger(recvStreamUsed, reached)
            /\ finalSize' = size
            /\ highest' = Larger(highest, reached)
            /\ got' = arrived
            /\ recvState' = IF complete THEN "data_recvd" ELSE state
            /\ UNCHANGED <<recvStreamLimit, recvStreamConsumed, recvConnectionLimit,
                           recvConnectionConsumed, failure>>

(* connection_stream_frames.take_reset: the final size counts against both *)
(* limits (§4.5), and the octets not yet read are dropped (§3.2).          *)
TakeReset(size) ==
    LET fresh == Larger(size - recvStreamUsed, 0)
        sizeChanged == \/ finalSize # None /\ finalSize # size
                       \/ finalSize = None /\ size < highest
        taken == recvState \in {"recv", "size_known", "data_recvd"}
        returned == IF taken /\ ReturnOnReset THEN size - recvStreamConsumed ELSE 0
    IN IF RecvClosed THEN ReceiverIgnores
       ELSE IF recvConnectionUsed + fresh > recvConnectionLimit \/ size > recvStreamLimit
       THEN Fail("flow_control")
       ELSE IF sizeChanged THEN Fail("final_size")
       ELSE /\ opened' = TRUE
            /\ recvConnectionUsed' = recvConnectionUsed + fresh
            /\ recvStreamUsed' = Larger(recvStreamUsed, size)
            /\ finalSize' = size
            /\ recvState' = IF taken THEN "reset_recvd" ELSE recvState
            /\ recvConnectionConsumed' = recvConnectionConsumed + returned
            /\ UNCHANGED <<got, highest, recvStreamLimit, recvStreamConsumed, recvConnectionLimit,
                           failure>>

(* A STREAM_DATA_BLOCKED creates the stream (§3.2) and obliges nothing.    *)
TakeOpening ==
    /\ opened' = TRUE
    /\ UNCHANGED <<recvState, got, finalSize, highest, recvStreamLimit, recvStreamUsed,
                   recvStreamConsumed, recvConnectionLimit, recvConnectionUsed,
                   recvConnectionConsumed, failure>>

ReceiverTakes(f) ==
    CASE f.type = "stream" -> TakeStream(f.value)
      [] f.type = "reset_stream" -> TakeReset(f.value)
      [] f.type = "stream_data_blocked" -> TakeOpening
      [] OTHER -> ReceiverIgnores

SenderIgnores == UNCHANGED <<sendState, sendStreamLimit, sendConnectionLimit, latest>>

(* §3.5: STOP_SENDING is answered with RESET_STREAM from "Ready", "Send"   *)
(* or "Data Sent".                                                         *)
TakeStop ==
    IF sendState \in {"ready", "send", "data_sent"}
    THEN /\ sendState' = "reset_sent"
         /\ latest' = Owe("reset_stream")
         /\ UNCHANGED <<sendStreamLimit, sendConnectionLimit>>
    ELSE SenderIgnores

(* §4.1: a limit that does not rise is ignored.                            *)
SenderTakes(f) ==
    CASE f.type = "max_data" ->
            /\ sendConnectionLimit' = Larger(sendConnectionLimit, f.value)
            /\ UNCHANGED <<sendState, sendStreamLimit, latest>>
      [] f.type = "max_stream_data" ->
            /\ sendStreamLimit' = Larger(sendStreamLimit, f.value)
            /\ UNCHANGED <<sendState, sendConnectionLimit, latest>>
      [] f.type = "stop_sending" -> TakeStop
      [] OTHER -> SenderIgnores

(* The sender's frame f is acknowledged.                                   *)
SenderAcked(f) ==
    CASE f.type = "stream" ->
            LET now == acked \cup {f.value} IN
            /\ acked' = now
            /\ sendState' = IF now = Octets /\ sendState = "data_sent"
                            THEN "data_recvd" ELSE sendState
            /\ UNCHANGED latest
      \* Streams.on_reset_acknowledged: "Reset Recvd" (§3.1), and nothing more owed.
      [] f.type = "reset_stream" ->
            /\ sendState' = "reset_recvd"
            /\ latest' = [latest EXCEPT !["reset_stream"] =
                              [owed |-> FALSE, sent |-> FALSE, value |-> None]]
            /\ UNCHANGED acked
      [] OTHER -> UNCHANGED <<acked, sendState, latest>>

(* A frame arrives. With `acknowledged` its acknowledgment arrives too;    *)
(* without, the acknowledgment is lost and the frame is declared lost.     *)
Deliver(e, f, acknowledged) ==
    /\ Live /\ f \in net[e]
    /\ acknowledged \/ (losses < LossMax /\ f \in inflight[e])
    /\ net' = [net EXCEPT ![e] = @ \ {f}]
    /\ losses' = IF acknowledged THEN losses ELSE losses + 1
    /\ LET ack == acknowledged /\ f \in inflight[e] IN
       /\ inflight' = IF ack THEN [inflight EXCEPT ![e] = @ \ {f}] ELSE inflight
       /\ IF e = Sender
          THEN /\ ReceiverTakes(f)
               /\ IF ack THEN SenderAcked(f) ELSE UNCHANGED <<acked, sendState, latest>>
               /\ UNCHANGED <<framed, sendStreamLimit, sendConnectionLimit, lost,
                              streamReported, connectionReported, sentAny>>
          ELSE /\ SenderTakes(f)
               /\ UNCHANGED <<receiverVars, failure, framed, acked, lost, streamReported,
                              connectionReported, sentAny>>
    /\ UNCHANGED <<closed, forbidden>>

Drop(e, f) ==
    /\ Live /\ f \in net[e] /\ losses < LossMax
    /\ net' = [net EXCEPT ![e] = @ \ {f}]
    /\ losses' = losses + 1
    /\ UNCHANGED <<senderVars, receiverVars, latest, inflight, closed, failure, forbidden>>

(* frame.Latest.on_lost: owed again only when it was the most recent.      *)
OnLostLatest(k, v) ==
    IF /\ latest[k].sent /\ latest[k].value = v
       /\ (ResendLimits \/ k \notin {"max_data", "max_stream_data"})
    THEN [latest EXCEPT ![k].owed = TRUE, ![k].sent = FALSE]
    ELSE latest

DeclareLost(e, f) ==
    /\ Live /\ f \in inflight[e]
    \* RFC 9002 §6.1: a frame still on its way may be declared lost too. Each
    \* such declaration uses the loss budget, so no behavior declares every
    \* copy lost before its acknowledgment arrives.
    /\ f \in net[e] => Spurious /\ losses < LossMax
    /\ losses' = IF f \in net[e] THEN losses + 1 ELSE losses
    /\ inflight' = [inflight EXCEPT ![e] = @ \ {f}]
    /\ IF f.type = "stream"
       THEN /\ lost' = IF f.value \in acked THEN lost ELSE lost \cup {f.value}
            /\ UNCHANGED latest
       ELSE /\ latest' = OnLostLatest(f.type, f.value)
            /\ UNCHANGED lost
    /\ UNCHANGED <<sendState, framed, sendStreamLimit, sendConnectionLimit, acked, streamReported,
                   connectionReported, sentAny, receiverVars, net, closed, failure, forbidden>>

(* §10.1: nothing in flight, nothing owed, and no shorter timer armed.     *)
Quiet ==
    /\ Live
    /\ \A e \in Endpoints : net[e] = {} /\ inflight[e] = {}
    /\ ~BlockedArmed
    /\ ~CanFrame /\ ~\E i \in Octets : CanRetransmit(i)
    /\ ~CanSendDataBlocked /\ ~CanSendStreamDataBlocked /\ ~CanSendReset
    /\ ~CanSendMaxData /\ ~CanSendMaxStreamData /\ ~CanSendStopSending

IdleTimeout ==
    /\ Quiet
    /\ closed' = TRUE
    /\ UNCHANGED <<senderVars, receiverVars, latest, net, inflight, losses, failure, forbidden>>

---------------------------------------------------------------------------

Next ==
    \/ FrameNew \/ \E i \in Octets : Retransmit(i)
    \/ SendDataBlocked \/ SendStreamDataBlocked \/ SendReset \/ AppReset
    \/ BlockedRepeat
    \/ SendMaxData \/ SendMaxStreamData \/ SendStopSending
    \/ Read \/ ReadReset \/ AppStop
    \/ \E e \in Endpoints : \E f \in FramesOf(e) :
          \/ \E acknowledged \in BOOLEAN : Deliver(e, f, acknowledged)
          \/ Drop(e, f) \/ DeclareLost(e, f)
    \/ IdleTimeout

(* The endpoints send what they owe, the application reads what arrived,   *)
(* a network that keeps carrying a frame delivers it and its               *)
(* acknowledgment in the end, and a frame gone unacknowledged is declared  *)
(* lost in the end.                                                        *)
Fairness ==
    /\ WF_vars(FrameNew) /\ \A i \in Octets : WF_vars(Retransmit(i))
    /\ WF_vars(SendDataBlocked) /\ WF_vars(SendStreamDataBlocked) /\ WF_vars(SendReset)
    /\ WF_vars(BlockedRepeat)
    /\ WF_vars(SendMaxData) /\ WF_vars(SendMaxStreamData) /\ WF_vars(SendStopSending)
    /\ WF_vars(Read) /\ WF_vars(ReadReset)
    /\ \A e \in Endpoints : \A f \in FramesOf(e) :
          /\ WF_vars(Deliver(e, f, TRUE))
          /\ WF_vars(DeclareLost(e, f) /\ f \notin net[e])

Spec == Init /\ [][Next]_vars /\ Fairness

---------------------------------------------------------------------------
(* Properties.                                                             *)

(* §4.1, §4.5: the receiver never closes the connection for a limit passed *)
(* or a final size changed.                                                *)
NoFailure == failure = "none"

(* §4.1: the sender stays within the limits it was given, and they are     *)
(* never above what the receiver advertised.                               *)
WithinLimits ==
    /\ framed <= sendStreamLimit /\ framed <= sendConnectionLimit
    /\ sendStreamLimit <= recvStreamLimit /\ sendConnectionLimit <= recvConnectionLimit

(* §3.2: "Data Recvd" only once every octet up to the final size arrived.  *)
DataRecvdComplete ==
    recvState \in {"data_recvd", "data_read"} =>
        finalSize = Len /\ \A k \in Octets : k \in got

(* §4.5: once the stream is done at the receiver, every octet it counted   *)
(* against the connection gave its credit back.                            *)
CreditReturned ==
    RecvClosed => recvConnectionConsumed = recvConnectionUsed

NoForbiddenFrame == ~forbidden

(* §4.5: a final size once known never changes.                            *)
FinalSizeFixed == [][finalSize # None => finalSize' = finalSize]_vars

(* A sender a limit holds back is released in the end.                     *)
Released == (DataBlocked \/ StreamDataBlocked) ~> ~(DataBlocked \/ StreamDataBlocked)

(* Both parts of the stream finish.                                        *)
Completes ==
    <>(/\ sendState \in {"data_recvd", "reset_recvd"}
       /\ recvState \in {"data_recvd", "data_read", "reset_recvd", "reset_read"})
=============================================================================
