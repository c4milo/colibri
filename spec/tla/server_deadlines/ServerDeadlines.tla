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
(*   - colibri's own, which take no time: it writes the WINDOW_UPDATE      *)
(*     frames it owes into its output, its caller's socket takes a frame   *)
(*     from the output, and it takes the content write_body offers;        *)
(*   - the peer's and the network's: a frame arrives at colibri, which     *)
(*     reads it, and the client reads, sends or opens a request;           *)
(*   - the application's: it answers a request, and produces the content   *)
(*     of the answer a unit at a time.                                     *)
(* A state in which colibri can take no step of its own is Quiescent, and  *)
(* rule 2 is checked there: in any other state, colibri acts before any    *)
(* time passes.                                                            *)
(*                                                                         *)
(* Rule 2 becomes one invariant for each deadline a peer can hold up. TLC  *)
(* finds the first three holding under colibri's rules, and each of the    *)
(* earlier rules breaking one of them:                                     *)
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
(*     window that holds the stream. Before decision 110 was amended, the  *)
(*     floor on a DATA frame held a stream whose peer never had credit     *)
(*     (floor_small_window). The amended floor still holds one whose peer  *)
(*     gives credit back only once it has nearly its whole window, more    *)
(*     than PeerWindow - Floor + 1 (floor_late_update,                     *)
(*     https://github.com/c4milo/colibri/issues/90).                       *)
(*   - BodyWaitsOnPeer: a body's deadline does not run while the client's  *)
(*     window is spent and the WINDOW_UPDATE that reopens it waits in      *)
(*     colibri's output, which the send deadline already judges the peer   *)
(*     on. colibri's rules break it (body_update_held,                     *)
(*     https://github.com/c4milo/colibri/issues/89).                       *)
(*                                                                         *)
(* Left out: TLS, h11, the head, first-request and drain deadlines, which  *)
(* no honest peer holds up; the caps on a body and on a connection's       *)
(* bodies together, which follow the same clocks; h2's stop on a full      *)
(* queue of replies, which spec/tla/h2_flow_control covers; and the        *)
(* frames the kernel holds, since colibri cannot see them. The client      *)
(* knows colibri's SETTINGS_INITIAL_WINDOW_SIZE from the start, since      *)
(* colibri advertises the default, and colibri knows the client's, which   *)
(* comes first in the client's preface.                                    *)
(*                                                                         *)
(* Numbers are small stand-ins, in units of DATA: the windows for their    *)
(* 65,535 octets, LocalThreshold for window_update_threshold and Floor for *)
(* data_frame_len_min. OutputMax counts the frames colibri's output holds, *)
(* and ChannelMax those a transport's buffers hold.                        *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    StreamCount,        \* the streams the client opens, one after another
    RequestBody,        \* the DATA units each request carries
    ResponseBody,       \* the DATA units each response carries
    ConnectionWindow,   \* the initial connection window, in both directions (§6.9.2)
    LocalWindow,        \* the SETTINGS_INITIAL_WINDOW_SIZE colibri advertises
    LocalThreshold,     \* the credit colibri gathers before it owes a WINDOW_UPDATE
    PeerWindow,         \* the SETTINGS_INITIAL_WINDOW_SIZE the client advertises
    PeerThreshold,      \* the credit the client gathers before it sends a WINDOW_UPDATE
    Floor,              \* data_frame_len_min, in units
    OutputMax,          \* the frames colibri's output holds
    ChannelMax,         \* the frames in flight toward one endpoint
    Pipelining,         \* whether the client opens a stream before it has read the last response
    IdleAfterOutput,    \* whether the idle deadline starts once the output is empty (6639950)
    SettingsPause,      \* whether the SETTINGS deadline pauses while a body waits (decision 110)
    FloorOnlyAbove      \* whether the floor applies only while PeerWindow is at least Floor

(* A client's streams take odd identifiers, in the order it opens them     *)
(* (§5.1.1).                                                               *)
Streams == [i \in 1..StreamCount |-> 2 * i - 1]
StreamIds == {Streams[i] : i \in 1..StreamCount}
Connection == 0         \* the stream identifier of the connection's own frames (§6.9)

ASSUME /\ StreamCount \in Nat \ {0}
       /\ {RequestBody, ResponseBody} \subseteq Nat
       /\ {ConnectionWindow, LocalWindow, LocalThreshold, PeerWindow, PeerThreshold, Floor,
           OutputMax, ChannelMax} \subseteq Nat \ {0}
       /\ LocalThreshold <= LocalWindow /\ PeerThreshold <= PeerWindow
       /\ {Pipelining, IdleAfterOutput, SettingsPause, FloorOnlyAbove} \subseteq BOOLEAN

Min(a, b) == IF a < b THEN a ELSE b

(* One frame. Every frame carries every field, so any two compare: len is  *)
(* a DATA frame's units, and value a WINDOW_UPDATE's increment.            *)
Frame(type, stream, len, end, value) ==
    [type |-> type, stream |-> stream, len |-> len, end |-> end, value |-> value]

Parts == {"none", "head", "ended"}

VARIABLES
    \* colibri
    reqRead,            \* reqRead[s]: what colibri has read of request s
    resp,               \* resp[s]: what colibri has written of the response to s
    respWritten,        \* respWritten[s]: the response's units colibri has written
    produced,           \* produced[s]: the response's units the application has offered in all
    sendWindow,         \* sendWindow[s]: colibri's credit on s, which the client advertised
    sendConnection,     \* colibri's credit on the connection
    released,           \* released[s]: credit colibri gathered on s and does not owe yet
    releasedConnection, \* the same for the connection
    owed,               \* the WINDOW_UPDATE frames colibri owes and has not written, oldest first
    out,                \* the frames colibri's output holds, oldest first
    firstRequestRead,   \* whether a whole request head has arrived
    idleStarted,        \* whether the idle deadline's clock has started
    settingsAcked,      \* whether the client acknowledged colibri's SETTINGS
    \* the network
    toClient,           \* the frames the caller's socket took, which the client has not read
    toServer,           \* the frames the client sent, which have not arrived at colibri
    \* the client
    cliReq,             \* cliReq[s]: what the client has sent of request s
    cliSent,            \* cliSent[s]: the request's units the client has sent
    cliWindow,          \* cliWindow[s]: the client's credit on s, which colibri advertised
    cliConnection,      \* the client's credit on the connection
    cliResp,            \* cliResp[s]: what the client has read of the response to s
    cliReleased,        \* cliReleased[s]: credit the client gathered on s and has not returned
    cliReleasedConnection,
    cliOwed             \* the frames the client owes and has not sent, oldest first

colibri == <<reqRead, resp, respWritten, produced, sendWindow, sendConnection, released,
             releasedConnection, owed, out, firstRequestRead, idleStarted, settingsAcked>>
client == <<cliReq, cliSent, cliWindow, cliConnection, cliResp, cliReleased,
            cliReleasedConnection, cliOwed>>
vars == <<colibri, toClient, toServer, client>>

TypeOK ==
    /\ reqRead \in [StreamIds -> Parts] /\ resp \in [StreamIds -> Parts]
    /\ respWritten \in [StreamIds -> 0..ResponseBody] /\ produced \in [StreamIds -> 0..ResponseBody]
    /\ sendWindow \in [StreamIds -> Int] /\ sendConnection \in Int
    /\ firstRequestRead \in BOOLEAN /\ idleStarted \in BOOLEAN /\ settingsAcked \in BOOLEAN
    /\ Len(out) <= OutputMax /\ Len(toClient) <= ChannelMax /\ Len(toServer) <= ChannelMax
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
    /\ owed = <<>>
    \* RFC 9113 §3.4: the server's connection preface is its SETTINGS, the first frame it sends.
    /\ out = <<Frame("SETTINGS", Connection, 0, FALSE, 0)>>
    /\ firstRequestRead = FALSE
    /\ idleStarted = FALSE
    /\ settingsAcked = FALSE
    /\ toClient = <<>>
    /\ toServer = <<>>
    /\ cliReq = [s \in StreamIds |-> "none"]
    /\ cliSent = [s \in StreamIds |-> 0]
    /\ cliWindow = [s \in StreamIds |-> LocalWindow]
    /\ cliConnection = ConnectionWindow
    /\ cliResp = [s \in StreamIds |-> "none"]
    /\ cliReleased = [s \in StreamIds |-> 0]
    /\ cliReleasedConnection = 0
    /\ cliOwed = <<>>

-----------------------------------------------------------------------------
(* What colibri knows and does.                                            *)

(* A stream colibri's h2 counts as active: the request began and the two   *)
(* sides have not both ended (§5.1).                                       *)
Active(s) == reqRead[s] # "none" /\ ~(reqRead[s] = "ended" /\ resp[s] = "ended")

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

(* The units write_body has offered on s that colibri has not taken.       *)
Ready(s) == produced[s] - respWritten[s]

Window(s) == Min(sendWindow[s], sendConnection)

(* connection_send_window.zig's sendable: what fits both windows, but      *)
(* nothing when the windows are below the floor and do not take it all.    *)
FloorApplies == ~FloorOnlyAbove \/ PeerWindow >= Floor
Sendable(s) ==
    IF Window(s) >= Ready(s) THEN Ready(s)
    ELSE IF FloorApplies /\ Window(s) < Floor THEN 0
    ELSE Window(s)

(* A stream a window holds: content waits and the windows take none of it  *)
(* (connection_sends.zig's entries).                                       *)
Held(s) == resp[s] = "head" /\ Ready(s) > 0 /\ Sendable(s) = 0
HeldByConnection(s) == sendConnection < sendWindow[s]

(* colibri writes the oldest WINDOW_UPDATE it owes into its output.        *)
Flush ==
    /\ owed # <<>> /\ Len(out) < OutputMax
    /\ out' = Append(out, Head(owed))
    /\ owed' = Tail(owed)
    /\ UNCHANGED <<reqRead, resp, respWritten, produced, sendWindow, sendConnection, released,
                   releasedConnection, firstRequestRead, settingsAcked, toClient, toServer>>
    /\ UNCHANGED client
    /\ ObserveIdle

(* The caller's socket takes the oldest frame colibri's output holds.      *)
Send ==
    /\ out # <<>> /\ Len(toClient) < ChannelMax
    /\ toClient' = Append(toClient, Head(out))
    /\ out' = Tail(out)
    /\ UNCHANGED <<reqRead, resp, respWritten, produced, sendWindow, sendConnection, released,
                   releasedConnection, owed, firstRequestRead, settingsAcked, toServer>>
    /\ UNCHANGED client
    /\ ObserveIdle

(* colibri takes what write_body offered on s as one DATA frame, as much   *)
(* as Sendable lets through, the last one ending the stream.               *)
WriteData(s) ==
    LET taken == Sendable(s)
        end == respWritten[s] + taken = ResponseBody
    IN /\ resp[s] = "head" /\ taken > 0 /\ Len(out) < OutputMax
       /\ out' = Append(out, Frame("DATA", s, taken, end, 0))
       /\ respWritten' = [respWritten EXCEPT ![s] = @ + taken]
       /\ sendWindow' = [sendWindow EXCEPT ![s] = @ - taken]
       /\ sendConnection' = sendConnection - taken
       /\ resp' = [resp EXCEPT ![s] = IF end THEN "ended" ELSE @]
       /\ UNCHANGED <<reqRead, produced, released, releasedConnection, owed, firstRequestRead,
                      settingsAcked, toClient, toServer>>
       /\ UNCHANGED client
       /\ ObserveIdle

ColibriStep == Flush \/ Send \/ \E s \in StreamIds : WriteData(s)
Quiescent == ~ENABLED ColibriStep

-----------------------------------------------------------------------------
(* A frame arrives at colibri, which reads it.                             *)

(* A DATA unit: the credit goes back at once, and colibri owes a           *)
(* WINDOW_UPDATE once it reaches LocalThreshold (window.Receiver), on the  *)
(* connection first (connection_reply.zig).                                *)
ArriveData(f) ==
    LET s == f.stream
        streamOwes == released[s] + 1 >= LocalThreshold /\ ~f.end
        connectionOwes == releasedConnection + 1 >= LocalThreshold
        connectionUpdate == IF connectionOwes
                            THEN <<Frame("WINDOW_UPDATE", Connection, 0, FALSE,
                                         releasedConnection + 1)>>
                            ELSE <<>>
        streamUpdate == IF streamOwes
                        THEN <<Frame("WINDOW_UPDATE", s, 0, FALSE, released[s] + 1)>>
                        ELSE <<>>
    IN /\ released' = [released EXCEPT ![s] = IF streamOwes \/ f.end THEN 0 ELSE @ + 1]
       /\ releasedConnection' = IF connectionOwes THEN 0 ELSE releasedConnection + 1
       /\ owed' = owed \o connectionUpdate \o streamUpdate
       /\ reqRead' = [reqRead EXCEPT ![s] = IF f.end THEN "ended" ELSE @]
       /\ UNCHANGED <<firstRequestRead, settingsAcked, sendWindow, sendConnection>>

Arrive ==
    /\ toServer # <<>>
    /\ LET f == Head(toServer)
       IN /\ toServer' = Tail(toServer)
          /\ CASE f.type = "HEADERS" ->
                    /\ reqRead' = [reqRead EXCEPT ![f.stream] = IF f.end THEN "ended" ELSE "head"]
                    /\ firstRequestRead' = TRUE
                    /\ UNCHANGED <<released, releasedConnection, owed, settingsAcked, sendWindow,
                                   sendConnection>>
               [] f.type = "DATA" -> ArriveData(f)
               [] f.type = "SETTINGS_ACK" ->
                    /\ settingsAcked' = TRUE
                    /\ UNCHANGED <<reqRead, released, releasedConnection, owed, firstRequestRead,
                                   sendWindow, sendConnection>>
               [] f.type = "WINDOW_UPDATE" ->
                    /\ IF f.stream = Connection
                       THEN /\ sendConnection' = sendConnection + f.value
                            /\ UNCHANGED sendWindow
                       ELSE /\ sendWindow' = [sendWindow EXCEPT ![f.stream] = @ + f.value]
                            /\ UNCHANGED sendConnection
                    /\ UNCHANGED <<reqRead, released, releasedConnection, owed, firstRequestRead,
                                   settingsAcked>>
    /\ out' = out
    /\ UNCHANGED <<resp, respWritten, produced, toClient>>
    /\ UNCHANGED client
    /\ ObserveIdle

-----------------------------------------------------------------------------
(* The application.                                                        *)

(* It answers a request whose head arrived with the response's HEADERS.    *)
Respond(s) ==
    LET end == ResponseBody = 0
    IN /\ reqRead[s] # "none" /\ resp[s] = "none" /\ Len(out) < OutputMax
       /\ out' = Append(out, Frame("HEADERS", s, 0, end, 0))
       /\ resp' = [resp EXCEPT ![s] = IF end THEN "ended" ELSE "head"]
       /\ UNCHANGED <<reqRead, respWritten, produced, sendWindow, sendConnection, released,
                      releasedConnection, owed, firstRequestRead, settingsAcked, toClient,
                      toServer>>
       /\ UNCHANGED client
       /\ ObserveIdle

(* It offers one more unit of the response's content to write_body.        *)
Produce(s) ==
    /\ resp[s] = "head" /\ produced[s] < ResponseBody
    /\ produced' = [produced EXCEPT ![s] = @ + 1]
    /\ UNCHANGED <<reqRead, resp, respWritten, sendWindow, sendConnection, released,
                   releasedConnection, owed, out, firstRequestRead, settingsAcked, toClient,
                   toServer>>
    /\ UNCHANGED client
    /\ ObserveIdle

-----------------------------------------------------------------------------
(* The honest client. What it owes, the SETTINGS acknowledgment and its    *)
(* WINDOW_UPDATE frames, goes out before anything it sends later.          *)

ClientRoom == Len(toServer) < ChannelMax
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
       /\ cliOwed = <<>> /\ ClientRoom
       /\ ClientPut(Frame("HEADERS", s, 0, end, 0))
       /\ cliReq' = [cliReq EXCEPT ![s] = IF end THEN "ended" ELSE "head"]
       /\ UNCHANGED <<cliSent, cliWindow, cliConnection, cliResp, cliReleased,
                      cliReleasedConnection, cliOwed>>
       /\ UNCHANGED <<colibri, toClient>>

(* It sends one DATA unit within both windows, the last ending the stream. *)
Upload(s) ==
    LET end == cliSent[s] + 1 = RequestBody
    IN /\ cliReq[s] = "head" /\ cliWindow[s] > 0 /\ cliConnection > 0
       /\ cliOwed = <<>> /\ ClientRoom
       /\ ClientPut(Frame("DATA", s, 1, end, 0))
       /\ cliSent' = [cliSent EXCEPT ![s] = @ + 1]
       /\ cliWindow' = [cliWindow EXCEPT ![s] = @ - 1]
       /\ cliConnection' = cliConnection - 1
       /\ cliReq' = [cliReq EXCEPT ![s] = IF end THEN "ended" ELSE @]
       /\ UNCHANGED <<cliResp, cliReleased, cliReleasedConnection, cliOwed>>
       /\ UNCHANGED <<colibri, toClient>>

(* It sends the oldest frame it owes.                                      *)
Settle ==
    /\ cliOwed # <<>> /\ ClientRoom
    /\ ClientPut(Head(cliOwed))
    /\ cliOwed' = Tail(cliOwed)
    /\ UNCHANGED <<cliReq, cliSent, cliWindow, cliConnection, cliResp, cliReleased,
                   cliReleasedConnection>>
    /\ UNCHANGED <<colibri, toClient>>

(* It reads DATA: the credit goes back once it reaches PeerThreshold, on   *)
(* the connection first, and a stream colibri ended owes nothing more.     *)
ReadData(f) ==
    LET s == f.stream
        streamOwes == cliReleased[s] + f.len >= PeerThreshold /\ ~f.end
        connectionOwes == cliReleasedConnection + f.len >= PeerThreshold
        connectionUpdate == IF connectionOwes
                            THEN <<Frame("WINDOW_UPDATE", Connection, 0, FALSE,
                                         cliReleasedConnection + f.len)>>
                            ELSE <<>>
        streamUpdate == IF streamOwes
                        THEN <<Frame("WINDOW_UPDATE", s, 0, FALSE, cliReleased[s] + f.len)>>
                        ELSE <<>>
    IN /\ cliReleased' = [cliReleased EXCEPT ![s] = IF streamOwes \/ f.end THEN 0 ELSE @ + f.len]
       /\ cliReleasedConnection' = IF connectionOwes THEN 0 ELSE cliReleasedConnection + f.len
       /\ cliOwed' = cliOwed \o connectionUpdate \o streamUpdate
       /\ cliResp' = [cliResp EXCEPT ![s] = IF f.end THEN "ended" ELSE @]
       /\ UNCHANGED <<cliWindow, cliConnection>>

(* It reads the oldest frame toward it.                                    *)
Read ==
    /\ toClient # <<>>
    /\ LET f == Head(toClient)
       IN /\ toClient' = Tail(toClient)
          /\ CASE f.type = "SETTINGS" ->
                    \* RFC 9113 §6.5.3: the receiver acknowledges SETTINGS once it applies them.
                    /\ cliOwed' = Append(cliOwed, Frame("SETTINGS_ACK", Connection, 0, FALSE, 0))
                    /\ UNCHANGED <<cliWindow, cliConnection, cliResp, cliReleased,
                                   cliReleasedConnection>>
               [] f.type = "HEADERS" ->
                    /\ cliResp' = [cliResp EXCEPT ![f.stream] = IF f.end THEN "ended" ELSE "head"]
                    /\ UNCHANGED <<cliWindow, cliConnection, cliReleased, cliReleasedConnection,
                                   cliOwed>>
               [] f.type = "DATA" -> ReadData(f)
               [] f.type = "WINDOW_UPDATE" ->
                    /\ IF f.stream = Connection
                       THEN /\ cliConnection' = cliConnection + f.value
                            /\ UNCHANGED cliWindow
                       ELSE /\ cliWindow' = [cliWindow EXCEPT ![f.stream] = @ + f.value]
                            /\ UNCHANGED cliConnection
                    /\ UNCHANGED <<cliResp, cliReleased, cliReleasedConnection, cliOwed>>
    /\ UNCHANGED <<cliReq, cliSent>>
    /\ UNCHANGED <<colibri, toServer>>

Next ==
    \/ ColibriStep
    \/ Arrive
    \/ \E s \in StreamIds : Respond(s) \/ Produce(s) \/ Upload(s)
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

(* connection_bodies.zig: a body's meter runs from its head to its end.    *)
BodyRuns(s) == BodyWaits(s)

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

(* A WINDOW_UPDATE colibri has not handed to the caller's socket.          *)
UpdateHeld(stream) ==
    \/ \E i \in 1..Len(owed) : owed[i].stream = stream
    \/ \E i \in 1..Len(out) : out[i].type = "WINDOW_UPDATE" /\ out[i].stream = stream

(* A body's clock never runs while the client has more of it to send, its  *)
(* window is spent, and the WINDOW_UPDATE that would let it send waits in  *)
(* colibri's output.                                                       *)
BodyWaitsOnPeer ==
    \A s \in StreamIds :
        Quiescent /\ BodyRuns(s) /\ cliReq[s] = "head" =>
            ~(\/ cliWindow[s] <= 0 /\ UpdateHeld(s)
              \/ cliConnection <= 0 /\ UpdateHeld(Connection))

(* The units of DATA on s the client has not read yet.                     *)
Unread(s) == LET units[i \in 0..Len(toClient)] ==
                     IF i = 0 THEN 0
                     ELSE units[i - 1] + (IF toClient[i].type = "DATA" /\ toClient[i].stream = s
                                          THEN toClient[i].len ELSE 0)
             IN units[Len(toClient)]
UnreadAll == LET units[i \in 0..Len(toClient)] ==
                     IF i = 0 THEN 0
                     ELSE units[i - 1] + (IF toClient[i].type = "DATA" THEN toClient[i].len ELSE 0)
             IN units[Len(toClient)]

(* Whether the client will give back credit on the window that holds s: a  *)
(* WINDOW_UPDATE on its way, or credit that reaches its threshold once it  *)
(* reads what is in flight.                                                *)
UpdateOnItsWay(stream) ==
    \/ \E i \in 1..Len(cliOwed) : cliOwed[i].type = "WINDOW_UPDATE" /\ cliOwed[i].stream = stream
    \/ \E i \in 1..Len(toServer) : toServer[i].type = "WINDOW_UPDATE" /\ toServer[i].stream = stream
WillCredit(s) ==
    IF HeldByConnection(s)
    THEN UpdateOnItsWay(Connection) \/ cliReleasedConnection + UnreadAll >= PeerThreshold
    ELSE UpdateOnItsWay(s) \/ cliReleased[s] + Unread(s) >= PeerThreshold

(* A stream's send clock runs only while the client will open the window   *)
(* that holds it.                                                          *)
SendWaitsOnPeer == \A s \in StreamIds : Quiescent /\ SendRuns(s) => WillCredit(s)

=============================================================================
