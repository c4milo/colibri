--------------------------- MODULE ServerDeadlines ---------------------------
(***************************************************************************)
(* Decision 110's deadlines at one server connection over h2 in cleartext  *)
(* (src/server/connection/), and its rule 2: a deadline runs only while    *)
(* colibri waits on the peer                                               *)
(* (https://github.com/c4milo/colibri/issues/86). An honest client makes   *)
(* requests one stream at a time, or several at once with Pipelining, and  *)
(* an application answers each one.                                        *)
(*                                                                         *)
(* A deadline measures time, and this model has none. So it checks when    *)
(* each deadline's clock runs, as colibri's code starts, pauses and stops  *)
(* it, against what the peer must do for the clock to stop. The steps are  *)
(* of three kinds:                                                         *)
(*   - colibri's own, which take no time: it writes the replies it owes    *)
(*     into its output, its caller's socket takes a frame from the output, *)
(*     and it takes the content write_body offers;                         *)
(*   - the peer's and the network's: a frame arrives at colibri, which     *)
(*     reads it, and the client reads, sends or opens a request;           *)
(*   - the application's: it answers a request, and offers the content of  *)
(*     the answer ProduceStep octets at a time.                            *)
(* A state in which colibri can take no step of its own is Quiescent, and  *)
(* rule 2 is checked there: in any other state, colibri acts before any    *)
(* time passes.                                                            *)
(*                                                                         *)
(* Rule 2 becomes one invariant for each deadline a peer can hold up. TLC  *)
(* finds all four holding under colibri's rules, and each of the earlier   *)
(* rules breaking one of them:                                             *)
(*   - IdleWaitsOnPeer: the idle deadline runs only when colibri's output  *)
(*     holds none of the last response. Before 6639950 it started when the *)
(*     response was written, so the peer's reading of the response counted *)
(*     against it as well as against the send deadline (idle_at_write).    *)
(*   - SettingsWaitsOnPeer: the SETTINGS deadline does not run while the   *)
(*     next frame colibri reads is DATA, which the body deadline judges.   *)
(*     A client may send DATA before it reads colibri's SETTINGS, and its  *)
(*     acknowledgment then follows that DATA (settings_no_pause, before    *)
(*     decision 110 was amended).                                          *)
(*   - SendWaitsOnPeer: a stream's send deadline runs only while the       *)
(*     client holds credit that reaches its threshold, so it will open the *)
(*     window that holds the stream. The floor on a DATA frame once held a *)
(*     stream whose peer never had credit (floor_small_window), and then   *)
(*     one whose peer gives credit back only for nearly its whole window   *)
(*     (floor_any_update, https://github.com/c4milo/colibri/issues/90). It *)
(*     now applies only once the client has sent a small increment         *)
(*     (late_update).                                                      *)
(*   - BodyWaitsOnPeer: a body's deadline does not run while the client's  *)
(*     window is spent and the WINDOW_UPDATE that reopens it waits in      *)
(*     colibri's output, which the send deadline already judges the peer   *)
(*     on. The rate once ran then (body_update_held,                       *)
(*     https://github.com/c4milo/colibri/issues/89), and now waits while   *)
(*     colibri holds a WINDOW_UPDATE (upload_update_held).                 *)
(*                                                                         *)
(* The model counts octets as colibri does, so that a run of colibri's h2  *)
(* client and server can be checked against it state for state: each      *)
(* frame is HeaderLen octets and its payload, colibri's output holds       *)
(* OutputLen octets and each direction ChannelLen, and a DATA frame is as  *)
(* long as the windows, the floor, FrameMax and the room allow, as         *)
(* connection_send_window.zig's sendable has it. colibri owes the replies  *)
(* as connection_reply.zig queues them: SETTINGS acknowledgments, one      *)
(* increment for the connection, then the streams' in order. The client   *)
(* is colibri's h2 too, and owes its replies the same way.                 *)
(*                                                                         *)
(* Left out: TLS, h11, the head, first-request and drain deadlines, which  *)
(* no honest peer holds up; the caps on a body and on a connection's       *)
(* bodies together, which follow the same clocks; h2's stop on a full      *)
(* queue of replies, which spec/tla/h2_flow_control covers; and the        *)
(* frames the kernel holds, since colibri cannot see them. The client      *)
(* knows colibri's SETTINGS_INITIAL_WINDOW_SIZE from the start, since      *)
(* colibri advertises the default, and colibri knows the client's, which   *)
(* comes first in the client's preface.                                    *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    StreamCount,        \* the streams the client opens, one after another
    RequestBody,        \* the octets of DATA each request carries
    ResponseBody,       \* the octets of DATA each response carries
    ProduceStep,        \* the octets the application offers write_body at once
    ConnectionWindow,   \* the initial connection window, in both directions (§6.9.2)
    LocalWindow,        \* the SETTINGS_INITIAL_WINDOW_SIZE colibri advertises
    LocalThreshold,     \* the credit colibri gathers before it owes a WINDOW_UPDATE
    PeerWindow,         \* the SETTINGS_INITIAL_WINDOW_SIZE the client advertises
    PeerThreshold,      \* the credit the client gathers before it sends a WINDOW_UPDATE
    Floor,              \* data_frame_len_min
    FrameMax,           \* the longest payload one DATA frame carries (§4.2)
    HeaderLen,          \* the octets of a frame's header (§4.1)
    SettingsLen,        \* the payload octets of colibri's SETTINGS
    UpdateLen,          \* the payload octets of a WINDOW_UPDATE (§6.9)
    PrefaceLen,         \* the octets of the client's preface and its SETTINGS (§3.4)
    RequestHeadLen,     \* the payload octets of a request's HEADERS
    ResponseHeadLen,    \* the payload octets of a response's HEADERS
    OutputLen,          \* the octets colibri's output holds
    ChannelLen,         \* the octets in flight toward one endpoint at once
    Pipelining,         \* whether the client opens a stream before it has read the last response
    MaximalUploads,     \* whether the client's DATA frames are as long as it can send
    IdleAfterOutput,    \* whether the idle deadline starts once the output is empty (6639950)
    SettingsPause,      \* whether the SETTINGS deadline pauses while a body waits (decision 110)
    FloorOnlyAbove,     \* whether the floor applies only while PeerWindow is at least Floor
    FloorAfterSmall,    \* whether it applies only once the client sent an increment below Floor
    BodyPauseForUpdate  \* whether a body's rate waits while colibri holds a WINDOW_UPDATE

(* A client's streams take odd identifiers, in the order it opens them     *)
(* (§5.1.1).                                                               *)
Streams == [i \in 1..StreamCount |-> 2 * i - 1]
StreamIds == {Streams[i] : i \in 1..StreamCount}
Connection == 0         \* the stream identifier of the connection's own frames (§6.9)

ASSUME /\ StreamCount \in Nat \ {0}
       /\ {RequestBody, ResponseBody, HeaderLen, SettingsLen, UpdateLen, RequestHeadLen,
           ResponseHeadLen} \subseteq Nat
       /\ {ProduceStep, ConnectionWindow, LocalWindow, LocalThreshold, PeerWindow, PeerThreshold,
           Floor, FrameMax, PrefaceLen, OutputLen, ChannelLen} \subseteq Nat \ {0}
       /\ LocalThreshold <= LocalWindow /\ PeerThreshold <= PeerWindow
       /\ {Pipelining, MaximalUploads, IdleAfterOutput, SettingsPause, FloorOnlyAbove,
           FloorAfterSmall, BodyPauseForUpdate} \subseteq BOOLEAN

Min(a, b) == IF a < b THEN a ELSE b

(* One frame. Every frame carries every field, so any two compare: len is  *)
(* its payload's octets, and value a WINDOW_UPDATE's increment. PREFACE is *)
(* the client's connection preface and its SETTINGS, which are no one      *)
(* frame.                                                                  *)
Frame(type, stream, len, end, value) ==
    [type |-> type, stream |-> stream, len |-> len, end |-> end, value |-> value]

Octets(f) == IF f.type = "PREFACE" THEN PrefaceLen ELSE HeaderLen + f.len

Used(frames) ==
    LET sum[i \in 0..Len(frames)] == IF i = 0 THEN 0 ELSE sum[i - 1] + Octets(frames[i])
    IN sum[Len(frames)]

(* A queue of replies with the WINDOW_UPDATE frames owed on s dropped      *)
(* (connection_reply.zig's drop_window_updates).                           *)
DropStream(queue, s) == SelectSeq(queue, LAMBDA reply : reply[1] # s)

Parts == {"none", "head", "ended"}

VARIABLES
    \* colibri
    reqRead,            \* reqRead[s]: what colibri has read of request s
    resp,               \* resp[s]: what colibri has written of the response to s
    respWritten,        \* respWritten[s]: the response's octets colibri has written
    produced,           \* produced[s]: the response's octets the application has offered in all
    sendWindow,         \* sendWindow[s]: colibri's credit on s, which the client advertised
    sendConnection,     \* colibri's credit on the connection
    released,           \* released[s]: credit colibri gathered on s and does not owe yet
    releasedConnection, \* the same for the connection
    acksOwed,           \* the acknowledgments of the client's SETTINGS colibri owes
    connectionOwed,     \* the increment colibri owes on the connection, 0 for none
    streamOwed,         \* the increments colibri owes on streams, oldest first, as <<s, n>>
    out,                \* the frames colibri's output holds, oldest first
    firstRequestRead,   \* whether a whole request head has arrived
    idleStarted,        \* whether the idle deadline's clock has started
    settingsAcked,      \* whether the client acknowledged colibri's SETTINGS
    smallIncrement,     \* whether the client sent a WINDOW_UPDATE with an increment below Floor
    \* the network
    toClient,           \* the frames the caller's socket took, which the client has not read
    toServer,           \* the frames the client sent, which have not arrived at colibri
    \* the client
    cliReq,             \* cliReq[s]: what the client has sent of request s
    cliSent,            \* cliSent[s]: the request's octets the client has sent
    cliWindow,          \* cliWindow[s]: the client's credit on s, which colibri advertised
    cliConnection,      \* the client's credit on the connection
    cliResp,            \* cliResp[s]: what the client has read of the response to s
    cliReleased,        \* cliReleased[s]: credit the client gathered on s and has not returned
    cliReleasedConnection,
    cliAcksOwed,        \* the acknowledgments of colibri's SETTINGS the client owes
    cliConnectionOwed,  \* the increment the client owes on the connection, 0 for none
    cliStreamOwed       \* the increments the client owes on streams, oldest first

colibri == <<reqRead, resp, respWritten, produced, sendWindow, sendConnection, released,
             releasedConnection, acksOwed, connectionOwed, streamOwed, out, firstRequestRead,
             idleStarted, settingsAcked, smallIncrement>>
client == <<cliReq, cliSent, cliWindow, cliConnection, cliResp, cliReleased,
            cliReleasedConnection, cliAcksOwed, cliConnectionOwed, cliStreamOwed>>
vars == <<colibri, toClient, toServer, client>>

TypeOK ==
    /\ reqRead \in [StreamIds -> Parts] /\ resp \in [StreamIds -> Parts]
    /\ respWritten \in [StreamIds -> 0..ResponseBody] /\ produced \in [StreamIds -> 0..ResponseBody]
    /\ sendWindow \in [StreamIds -> Int] /\ sendConnection \in Int
    /\ firstRequestRead \in BOOLEAN /\ idleStarted \in BOOLEAN /\ settingsAcked \in BOOLEAN
    /\ smallIncrement \in BOOLEAN
    /\ Used(out) <= OutputLen /\ Used(toClient) <= ChannelLen /\ Used(toServer) <= ChannelLen
    /\ cliReq \in [StreamIds -> Parts] /\ cliSent \in [StreamIds -> 0..RequestBody]
    /\ cliResp \in [StreamIds -> Parts]

Init ==
    /\ reqRead = [s \in StreamIds |-> "none"]
    /\ resp = [s \in StreamIds |-> "none"]
    /\ respWritten = [s \in StreamIds |-> 0]
    /\ produced = [s \in StreamIds |-> 0]
    /\ sendWindow = [s \in StreamIds |-> PeerWindow]
    /\ sendConnection = ConnectionWindow
    /\ released = [s \in StreamIds |-> 0]
    /\ releasedConnection = 0
    /\ acksOwed = 0
    /\ connectionOwed = 0
    /\ streamOwed = <<>>
    \* RFC 9113 §3.4: the server's connection preface is its SETTINGS, the first frame it sends.
    /\ out = <<Frame("SETTINGS", Connection, SettingsLen, FALSE, 0)>>
    /\ firstRequestRead = FALSE
    /\ idleStarted = FALSE
    /\ settingsAcked = FALSE
    /\ smallIncrement = FALSE
    /\ toClient = <<>>
    /\ toServer = <<Frame("PREFACE", Connection, 0, FALSE, 0)>>
    /\ cliReq = [s \in StreamIds |-> "none"]
    /\ cliSent = [s \in StreamIds |-> 0]
    /\ cliWindow = [s \in StreamIds |-> LocalWindow]
    /\ cliConnection = ConnectionWindow
    /\ cliResp = [s \in StreamIds |-> "none"]
    /\ cliReleased = [s \in StreamIds |-> 0]
    /\ cliReleasedConnection = 0
    /\ cliAcksOwed = 0
    /\ cliConnectionOwed = 0
    /\ cliStreamOwed = <<>>

-----------------------------------------------------------------------------
(* What colibri knows and does.                                            *)

(* A stream colibri's h2 has closed: both sides ended it (§5.1).          *)
Closed(s) == reqRead[s] = "ended" /\ resp[s] = "ended"

(* A stream colibri's h2 counts as active: the request began and the       *)
(* stream has not closed.                                                  *)
Active(s) == reqRead[s] # "none" /\ ~Closed(s)

(* connection_deadline.zig's wait_h2: idle once a request has arrived and  *)
(* no stream is active.                                                    *)
IdleWait == firstRequestRead /\ \A s \in StreamIds : ~Active(s)

(* The idle clock starts at the first of colibri's calls that sees the     *)
(* connection idle, once the output is empty with IdleAfterOutput, and     *)
(* stops when a stream opens. Frames colibri writes later do not stop it.  *)
ObserveIdle ==
    idleStarted' = (IdleWait' /\ (idleStarted \/ ~IdleAfterOutput \/ out' = <<>>))

(* A body colibri waits for: its head arrived and its end has not.         *)
BodyWaits(s) == reqRead[s] = "head"
BodiesWait == \E s \in StreamIds : BodyWaits(s)

(* The octets write_body has offered on s that colibri has not taken.      *)
Ready(s) == produced[s] - respWritten[s]

Window(s) == Min(sendWindow[s], sendConnection)
OutputRoom == OutputLen - Used(out)

(* connection_send_window.zig's sendable: what fits both windows, but      *)
(* nothing when the windows are below the floor and do not take it all,   *)
(* once the client has sent a small increment (decision 110 as amended).   *)
FloorApplies == (~FloorOnlyAbove \/ PeerWindow >= Floor) /\ (~FloorAfterSmall \/ smallIncrement)
Sendable(s) ==
    IF Window(s) >= Ready(s) THEN Ready(s)
    ELSE IF FloorApplies /\ Window(s) < Floor THEN 0
    ELSE Window(s)

(* The DATA frame colibri writes next on s: what Sendable lets through, cut *)
(* at the frame size and at the room the output has left.                 *)
DataLen(s) == Min(Min(Sendable(s), FrameMax), OutputRoom - HeaderLen)

(* A stream a window holds: content waits and the windows take none of it  *)
(* (connection_sends.zig's entries).                                       *)
Held(s) == resp[s] = "head" /\ Ready(s) > 0 /\ Sendable(s) = 0
HeldByConnection(s) == sendConnection < sendWindow[s]

(* What colibri owes, in connection_reply.zig's order.                     *)
Owes == acksOwed > 0 \/ connectionOwed > 0 \/ streamOwed # <<>>
OwedFrame ==
    CASE acksOwed > 0 -> Frame("SETTINGS_ACK", Connection, 0, FALSE, 0)
      [] acksOwed = 0 /\ connectionOwed > 0 ->
            Frame("WINDOW_UPDATE", Connection, UpdateLen, FALSE, connectionOwed)
      [] acksOwed = 0 /\ connectionOwed = 0 /\ streamOwed # <<>> ->
            Frame("WINDOW_UPDATE", Head(streamOwed)[1], UpdateLen, FALSE, Head(streamOwed)[2])

(* colibri writes the oldest reply it owes into its output.                *)
Flush ==
    /\ Owes /\ Octets(OwedFrame) <= OutputRoom
    /\ out' = Append(out, OwedFrame)
    /\ acksOwed' = IF acksOwed > 0 THEN acksOwed - 1 ELSE 0
    /\ connectionOwed' = IF acksOwed = 0 THEN 0 ELSE connectionOwed
    /\ streamOwed' = IF acksOwed = 0 /\ connectionOwed = 0 THEN Tail(streamOwed) ELSE streamOwed
    /\ UNCHANGED <<reqRead, resp, respWritten, produced, sendWindow, sendConnection, released,
                   releasedConnection, firstRequestRead, settingsAcked, smallIncrement, toClient,
                   toServer>>
    /\ UNCHANGED client
    /\ ObserveIdle

(* The caller's socket takes the oldest frame colibri's output holds.      *)
Send ==
    /\ out # <<>> /\ Used(toClient) + Octets(Head(out)) <= ChannelLen
    /\ toClient' = Append(toClient, Head(out))
    /\ out' = Tail(out)
    /\ UNCHANGED <<reqRead, resp, respWritten, produced, sendWindow, sendConnection, released,
                   releasedConnection, acksOwed, connectionOwed, streamOwed, firstRequestRead,
                   settingsAcked, smallIncrement, toServer>>
    /\ UNCHANGED client
    /\ ObserveIdle

(* colibri takes what write_body offered on s as one DATA frame, the last  *)
(* one ending the stream.                                                  *)
WriteData(s) ==
    LET taken == DataLen(s)
        end == respWritten[s] + taken = ResponseBody
    IN /\ resp[s] = "head" /\ taken > 0
       /\ out' = Append(out, Frame("DATA", s, taken, end, 0))
       /\ respWritten' = [respWritten EXCEPT ![s] = @ + taken]
       /\ sendWindow' = [sendWindow EXCEPT ![s] = @ - taken]
       /\ sendConnection' = sendConnection - taken
       /\ resp' = [resp EXCEPT ![s] = IF end THEN "ended" ELSE @]
       /\ UNCHANGED <<reqRead, produced, released, releasedConnection, acksOwed, connectionOwed,
                      streamOwed, firstRequestRead, settingsAcked, smallIncrement, toClient,
                      toServer>>
       /\ UNCHANGED client
       /\ ObserveIdle

ColibriStep == Flush \/ Send \/ \E s \in StreamIds : WriteData(s)
Quiescent == ~ENABLED ColibriStep

-----------------------------------------------------------------------------
(* A frame arrives at colibri, which reads it.                             *)

(* DATA: the credit goes back at once, and colibri owes a WINDOW_UPDATE    *)
(* once it reaches LocalThreshold (window.Receiver). A stream the client   *)
(* ended owes nothing more (connection_reply.zig's drop_window_updates).   *)
ArriveData(f) ==
    LET s == f.stream
        streamOwes == released[s] + f.len >= LocalThreshold /\ ~f.end
        connectionOwes == releasedConnection + f.len >= LocalThreshold
        kept == IF f.end THEN DropStream(streamOwed, s) ELSE streamOwed
    IN /\ released' = [released EXCEPT ![s] = IF streamOwes \/ f.end THEN 0 ELSE @ + f.len]
       /\ releasedConnection' = IF connectionOwes THEN 0 ELSE releasedConnection + f.len
       /\ connectionOwed' = IF connectionOwes THEN connectionOwed + releasedConnection + f.len
                            ELSE connectionOwed
       /\ streamOwed' = IF streamOwes THEN Append(kept, <<s, released[s] + f.len>>) ELSE kept
       /\ reqRead' = [reqRead EXCEPT ![s] = IF f.end THEN "ended" ELSE @]
       /\ UNCHANGED <<acksOwed, firstRequestRead, settingsAcked, sendWindow, sendConnection,
                      smallIncrement>>

(* WINDOW_UPDATE: the increment opens the window it names. colibri         *)
(* discards one on a stream it has closed (stream_receive.zig's            *)
(* in_closed_by_end_stream), and notes no small increment from it.         *)
ArriveUpdate(f) ==
    LET ignored == f.stream # Connection /\ Closed(f.stream)
    IN /\ sendConnection' = IF f.stream = Connection THEN sendConnection + f.value
                            ELSE sendConnection
       \* RFC 9113 §6.9: a WINDOW_UPDATE on a closed stream is no error. §5.1: nothing but
       \* PRIORITY goes out on a closed stream, so the increment opens nothing.
       /\ sendWindow' = IF f.stream = Connection \/ ignored THEN sendWindow
                        ELSE [sendWindow EXCEPT ![f.stream] = @ + f.value]
       \* RFC 9113 §10.5: tiny increments can make a sender write many DATA frames. Decision
       \* 110 answers with the floor, which applies once an increment below Floor arrives.
       /\ smallIncrement' = (smallIncrement \/ (f.value < Floor /\ ~ignored))
       /\ UNCHANGED <<reqRead, released, releasedConnection, acksOwed, connectionOwed,
                      streamOwed, firstRequestRead, settingsAcked>>

Arrive ==
    /\ toServer # <<>>
    /\ LET f == Head(toServer)
       IN /\ toServer' = Tail(toServer)
          /\ CASE f.type = "PREFACE" ->
                    \* RFC 9113 §6.5.3: colibri acknowledges the client's SETTINGS.
                    /\ acksOwed' = acksOwed + 1
                    /\ UNCHANGED <<reqRead, released, releasedConnection, connectionOwed,
                                   streamOwed, firstRequestRead, settingsAcked, sendWindow,
                                   sendConnection, smallIncrement>>
               [] f.type = "HEADERS" ->
                    /\ reqRead' = [reqRead EXCEPT ![f.stream] = IF f.end THEN "ended" ELSE "head"]
                    /\ firstRequestRead' = TRUE
                    /\ UNCHANGED <<released, releasedConnection, acksOwed, connectionOwed,
                                   streamOwed, settingsAcked, sendWindow, sendConnection,
                                   smallIncrement>>
               [] f.type = "DATA" -> ArriveData(f)
               [] f.type = "SETTINGS_ACK" ->
                    /\ settingsAcked' = TRUE
                    /\ UNCHANGED <<reqRead, released, releasedConnection, acksOwed,
                                   connectionOwed, streamOwed, firstRequestRead, sendWindow,
                                   sendConnection, smallIncrement>>
               [] f.type = "WINDOW_UPDATE" -> ArriveUpdate(f)
    /\ out' = out
    /\ UNCHANGED <<resp, respWritten, produced, toClient>>
    /\ UNCHANGED client
    /\ ObserveIdle

-----------------------------------------------------------------------------
(* The application.                                                        *)

(* It answers a request whose head arrived with the response's HEADERS.    *)
Respond(s) ==
    LET end == ResponseBody = 0
    IN /\ reqRead[s] # "none" /\ resp[s] = "none" /\ HeaderLen + ResponseHeadLen <= OutputRoom
       /\ out' = Append(out, Frame("HEADERS", s, ResponseHeadLen, end, 0))
       /\ resp' = [resp EXCEPT ![s] = IF end THEN "ended" ELSE "head"]
       /\ UNCHANGED <<reqRead, respWritten, produced, sendWindow, sendConnection, released,
                      releasedConnection, acksOwed, connectionOwed, streamOwed,
                      firstRequestRead, settingsAcked, smallIncrement, toClient, toServer>>
       /\ UNCHANGED client
       /\ ObserveIdle

(* It offers write_body ProduceStep more octets of the response, or what   *)
(* is left.                                                                *)
Produce(s) ==
    /\ resp[s] = "head" /\ produced[s] < ResponseBody
    /\ produced' = [produced EXCEPT ![s] = @ + Min(ProduceStep, ResponseBody - @)]
    /\ UNCHANGED <<reqRead, resp, respWritten, sendWindow, sendConnection, released,
                   releasedConnection, acksOwed, connectionOwed, streamOwed, out,
                   firstRequestRead, settingsAcked, smallIncrement, toClient, toServer>>
    /\ UNCHANGED client
    /\ ObserveIdle

-----------------------------------------------------------------------------
(* The honest client, colibri's h2. What it owes, its SETTINGS             *)
(* acknowledgments and its WINDOW_UPDATE frames, goes out before anything  *)
(* it sends later.                                                         *)

ClientOwes == cliAcksOwed > 0 \/ cliConnectionOwed > 0 \/ cliStreamOwed # <<>>
ClientRoom == ChannelLen - Used(toServer)
ClientPut(f) == toServer' = Append(toServer, f)

(* Whether the client has read every response to the streams before s.     *)
EarlierRead(i) == \A j \in 1..(i - 1) : cliResp[Streams[j]] = "ended"

(* It opens the next stream with its request's HEADERS.                    *)
Open(i) ==
    LET s == Streams[i]
        end == RequestBody = 0
    IN /\ cliReq[s] = "none"
       /\ \A j \in 1..(i - 1) : cliReq[Streams[j]] # "none"
       /\ Pipelining \/ EarlierRead(i)
       /\ ~ClientOwes /\ HeaderLen + RequestHeadLen <= ClientRoom
       /\ ClientPut(Frame("HEADERS", s, RequestHeadLen, end, 0))
       /\ cliReq' = [cliReq EXCEPT ![s] = IF end THEN "ended" ELSE "head"]
       /\ UNCHANGED <<cliSent, cliWindow, cliConnection, cliResp, cliReleased,
                      cliReleasedConnection, cliAcksOwed, cliConnectionOwed, cliStreamOwed>>
       /\ UNCHANGED <<colibri, toClient>>

(* The longest DATA frame the client can send on s now.                    *)
UploadMax(s) ==
    Min(Min(Min(cliWindow[s], cliConnection), RequestBody - cliSent[s]),
        Min(FrameMax, ClientRoom - HeaderLen))
UploadLens(s) == IF MaximalUploads THEN {UploadMax(s)} ELSE 1..UploadMax(s)

(* It sends a DATA frame within both windows, the last ending the stream.  *)
Upload(s, len) ==
    LET end == cliSent[s] + len = RequestBody
    IN /\ cliReq[s] = "head" /\ len >= 1 /\ len <= UploadMax(s) /\ ~ClientOwes
       /\ ClientPut(Frame("DATA", s, len, end, 0))
       /\ cliSent' = [cliSent EXCEPT ![s] = @ + len]
       /\ cliWindow' = [cliWindow EXCEPT ![s] = @ - len]
       /\ cliConnection' = cliConnection - len
       /\ cliReq' = [cliReq EXCEPT ![s] = IF end THEN "ended" ELSE @]
       /\ UNCHANGED <<cliResp, cliReleased, cliReleasedConnection, cliAcksOwed,
                      cliConnectionOwed, cliStreamOwed>>
       /\ UNCHANGED <<colibri, toClient>>

(* What the client owes, in connection_reply.zig's order.                  *)
ClientOwedFrame ==
    CASE cliAcksOwed > 0 -> Frame("SETTINGS_ACK", Connection, 0, FALSE, 0)
      [] cliAcksOwed = 0 /\ cliConnectionOwed > 0 ->
            Frame("WINDOW_UPDATE", Connection, UpdateLen, FALSE, cliConnectionOwed)
      [] cliAcksOwed = 0 /\ cliConnectionOwed = 0 /\ cliStreamOwed # <<>> ->
            Frame("WINDOW_UPDATE", Head(cliStreamOwed)[1], UpdateLen, FALSE,
                  Head(cliStreamOwed)[2])

(* It sends the oldest frame it owes.                                      *)
Settle ==
    /\ ClientOwes /\ Octets(ClientOwedFrame) <= ClientRoom
    /\ ClientPut(ClientOwedFrame)
    /\ cliAcksOwed' = IF cliAcksOwed > 0 THEN cliAcksOwed - 1 ELSE 0
    /\ cliConnectionOwed' = IF cliAcksOwed = 0 THEN 0 ELSE cliConnectionOwed
    /\ cliStreamOwed' = IF cliAcksOwed = 0 /\ cliConnectionOwed = 0 THEN Tail(cliStreamOwed)
                        ELSE cliStreamOwed
    /\ UNCHANGED <<cliReq, cliSent, cliWindow, cliConnection, cliResp, cliReleased,
                   cliReleasedConnection>>
    /\ UNCHANGED <<colibri, toClient>>

(* It reads DATA: the credit goes back once it reaches PeerThreshold, and  *)
(* a stream colibri ended owes nothing more.                               *)
ReadData(f) ==
    LET s == f.stream
        streamOwes == cliReleased[s] + f.len >= PeerThreshold /\ ~f.end
        connectionOwes == cliReleasedConnection + f.len >= PeerThreshold
        kept == IF f.end THEN DropStream(cliStreamOwed, s) ELSE cliStreamOwed
    IN /\ cliReleased' = [cliReleased EXCEPT ![s] = IF streamOwes \/ f.end THEN 0 ELSE @ + f.len]
       /\ cliReleasedConnection' = IF connectionOwes THEN 0 ELSE cliReleasedConnection + f.len
       /\ cliConnectionOwed' = IF connectionOwes
                               THEN cliConnectionOwed + cliReleasedConnection + f.len
                               ELSE cliConnectionOwed
       /\ cliStreamOwed' = IF streamOwes THEN Append(kept, <<s, cliReleased[s] + f.len>>) ELSE kept
       /\ cliResp' = [cliResp EXCEPT ![s] = IF f.end THEN "ended" ELSE @]
       /\ UNCHANGED <<cliWindow, cliConnection, cliAcksOwed>>

(* The client, colibri's h2 too, discards a WINDOW_UPDATE on a stream it   *)
(* has closed.                                                             *)
ReadUpdate(f) ==
    LET ignored == f.stream # Connection
                   /\ cliReq[f.stream] = "ended" /\ cliResp[f.stream] = "ended"
    IN /\ cliConnection' = IF f.stream = Connection THEN cliConnection + f.value ELSE cliConnection
       /\ cliWindow' = IF f.stream = Connection \/ ignored THEN cliWindow
                       ELSE [cliWindow EXCEPT ![f.stream] = @ + f.value]
       /\ UNCHANGED <<cliResp, cliReleased, cliReleasedConnection, cliAcksOwed,
                      cliConnectionOwed, cliStreamOwed>>

(* It reads the oldest frame toward it.                                    *)
Read ==
    /\ toClient # <<>>
    /\ LET f == Head(toClient)
       IN /\ toClient' = Tail(toClient)
          /\ CASE f.type = "SETTINGS" ->
                    \* RFC 9113 §6.5.3: the receiver acknowledges SETTINGS once it applies them.
                    /\ cliAcksOwed' = cliAcksOwed + 1
                    /\ UNCHANGED <<cliWindow, cliConnection, cliResp, cliReleased,
                                   cliReleasedConnection, cliConnectionOwed, cliStreamOwed>>
               [] f.type = "SETTINGS_ACK" ->
                    /\ UNCHANGED <<cliWindow, cliConnection, cliResp, cliReleased,
                                   cliReleasedConnection, cliAcksOwed, cliConnectionOwed,
                                   cliStreamOwed>>
               [] f.type = "HEADERS" ->
                    /\ cliResp' = [cliResp EXCEPT ![f.stream] = IF f.end THEN "ended" ELSE "head"]
                    /\ UNCHANGED <<cliWindow, cliConnection, cliReleased, cliReleasedConnection,
                                   cliAcksOwed, cliConnectionOwed, cliStreamOwed>>
               [] f.type = "DATA" -> ReadData(f)
               [] f.type = "WINDOW_UPDATE" -> ReadUpdate(f)
    /\ UNCHANGED <<cliReq, cliSent>>
    /\ UNCHANGED <<colibri, toServer>>

Next ==
    \/ ColibriStep
    \/ Arrive
    \/ \E s \in StreamIds : Respond(s) \/ Produce(s)
    \/ \E s \in StreamIds : \E len \in UploadLens(s) : Upload(s, len)
    \/ \E i \in 1..StreamCount : Open(i)
    \/ Settle
    \/ Read

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* When each clock runs, as colibri's code has it.                         *)

(* connection_deadline.zig: the SETTINGS acknowledgment is owed from the   *)
(* instant the SETTINGS is written, and its clock pauses while a body      *)
(* waits (decision 110 as amended).                                        *)
SettingsRuns == ~settingsAcked /\ ~(SettingsPause /\ BodiesWait)

(* A WINDOW_UPDATE on `stream` colibri has not handed to the caller's      *)
(* socket: owed, or in its output.                                         *)
UpdateHeld(stream) ==
    \/ stream = Connection /\ connectionOwed > 0
    \/ \E i \in 1..Len(streamOwed) : streamOwed[i][1] = stream
    \/ \E i \in 1..Len(out) : out[i].type = "WINDOW_UPDATE" /\ out[i].stream = stream
UpdateHeldAny ==
    \/ connectionOwed > 0 \/ streamOwed # <<>>
    \/ \E i \in 1..Len(out) : out[i].type = "WINDOW_UPDATE"

(* connection_bodies.zig: a body's rate runs from its head to its end,     *)
(* and waits while colibri holds a WINDOW_UPDATE (decision 110 as          *)
(* amended).                                                               *)
BodyRuns(s) == BodyWaits(s) /\ ~(BodyPauseForUpdate /\ UpdateHeldAny)

(* connection_sends.zig: a stream's meter runs while a window holds it and *)
(* the output is empty.                                                    *)
SendRuns(s) == Held(s) /\ out = <<>>

(* Rule 2, for each deadline an honest peer can hold up.                   *)

(* The idle clock never runs while colibri's output holds a response the   *)
(* client must read before it makes its next request.                      *)
IdleWaitsOnPeer ==
    Quiescent /\ idleStarted => \A i \in 1..Len(out) : out[i].type \notin {"HEADERS", "DATA"}

(* The SETTINGS clock never runs while the next frame to arrive is DATA,   *)
(* which the body's clock judges.                                          *)
SettingsWaitsOnPeer ==
    Quiescent /\ SettingsRuns => ~(toServer # <<>> /\ Head(toServer).type = "DATA")

(* A body's clock never runs while the client has more of it to send, its  *)
(* window is spent, and the WINDOW_UPDATE that would let it send waits in  *)
(* colibri's output.                                                       *)
BodyWaitsOnPeer ==
    \A s \in StreamIds :
        Quiescent /\ BodyRuns(s) /\ cliReq[s] = "head" =>
            ~(\/ cliWindow[s] <= 0 /\ UpdateHeld(s)
              \/ cliConnection <= 0 /\ UpdateHeld(Connection))

(* The octets of DATA on s, or on every stream, the client has not read.  *)
RECURSIVE UnreadOf(_, _)
UnreadOf(frames, streams) ==
    IF frames = <<>> THEN 0
    ELSE (IF Head(frames).type = "DATA" /\ Head(frames).stream \in streams
          THEN Head(frames).len ELSE 0) + UnreadOf(Tail(frames), streams)
Unread(s) == UnreadOf(toClient, {s})
UnreadAll == UnreadOf(toClient, StreamIds)

(* Whether the client will give back credit on the window that holds s: a  *)
(* WINDOW_UPDATE on its way, or credit that reaches its threshold once it  *)
(* reads what is in flight.                                                *)
UpdateOnItsWay(stream) ==
    \/ stream = Connection /\ cliConnectionOwed > 0
    \/ \E i \in 1..Len(cliStreamOwed) : cliStreamOwed[i][1] = stream
    \/ \E i \in 1..Len(toServer) : toServer[i].type = "WINDOW_UPDATE" /\ toServer[i].stream = stream
WillCredit(s) ==
    IF HeldByConnection(s)
    THEN UpdateOnItsWay(Connection) \/ cliReleasedConnection + UnreadAll >= PeerThreshold
    ELSE UpdateOnItsWay(s) \/ cliReleased[s] + Unread(s) >= PeerThreshold

(* A stream's send clock runs only while the client will open the window   *)
(* that holds it.                                                          *)
SendWaitsOnPeer == \A s \in StreamIds : Quiescent /\ SendRuns(s) => WillCredit(s)

=============================================================================
