-------------------------- MODULE H2FlowControl --------------------------
(***************************************************************************)
(* h2's stream states (RFC 9113 §5.1) and flow-control windows (§6.9), as  *)
(* colibri keeps them (src/h2/window.zig, src/h2/connection/): a client    *)
(* and a server exchange one request and one response per stream over one *)
(* connection, each DATA frame one unit of payload, and TCP delivers each  *)
(* direction in order, so nothing is lost (§2).                            *)
(*                                                                         *)
(* colibri's rules, as this model has them:                                *)
(*   - a sender sends DATA only while both windows are positive, and a     *)
(*     window a SETTINGS change drove negative waits for WINDOW_UPDATE     *)
(*     frames (§6.9.2);                                                    *)
(*   - a receiver charges each DATA frame to both windows and gives the    *)
(*     credit back at once, and owes a WINDOW_UPDATE once the credit       *)
(*     reaches Threshold (window.Receiver);                                *)
(*   - what a receiver owes is queued and written later, the SETTINGS      *)
(*     acknowledgments, then the connection's increment, then each         *)
(*     stream's (connection_reply.zig);                                    *)
(*   - once the peer ends its side of a stream, the credit owed on it is   *)
(*     dropped, since no more DATA comes (DropOnEnd). Without that, a      *)
(*     WINDOW_UPDATE went out on a stream already closed, which §5.1       *)
(*     forbids: this model found it, and the configuration                 *)
(*     update_after_end keeps the path. colibri drops the credit on a      *)
(*     RST_STREAM too, which this model does not send;                     *)
(*   - colibri never changes the initial window it advertises. Changer, a  *)
(*     peer that is not colibri, may: it adjusts what it advertised when   *)
(*     it sends the SETTINGS, and takes what the sender sent before        *)
(*     reading them (§6.9.3).                                              *)
(*                                                                         *)
(* Numbers are small stand-ins: Max for 2^31-1 (§6.9.1), InitialWindow for *)
(* the 65,535-octet initial window, Threshold for window_update_threshold. *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Client, Server,     \* the two endpoints
    Nobody,             \* no endpoint, as a value of Changer
    Streams,            \* the client's streams, as positive numbers
    Body,               \* DATA units each side sends on each stream
    InitialWindow,      \* the initial window, of the connection and of every stream
    Threshold,          \* the credit a receiver gathers before it owes a WINDOW_UPDATE
    Max,                \* the largest window (§6.9.1)
    ChannelMax,         \* frames in flight toward one endpoint at once
    Changer,            \* the endpoint that changes its SETTINGS_INITIAL_WINDOW_SIZE, or Nobody
    NewInits,           \* the values it may change it to
    ChangesMax,         \* how many times it may
    HonourNegative,     \* whether a sender waits while a window is not positive (§6.9.2)
    DropOnEnd           \* whether a receiver drops the stream credit it owes once the peer ends

Endpoints == {Client, Server}
Peer(e) == IF e = Client THEN Server ELSE Client
Connection == 0         \* the stream identifier of the connection's own frames (§6.9)

ASSUME /\ Streams \subseteq Nat \ {Connection}
       /\ {Body, InitialWindow, Threshold, Max, ChannelMax, ChangesMax} \subseteq Nat
       /\ Threshold >= 1 /\ InitialWindow <= Max
       /\ Changer \in Endpoints \cup {Nobody}
       /\ NewInits \subseteq 0..Max
       /\ HonourNegative \in BOOLEAN /\ DropOnEnd \in BOOLEAN

States == {"idle", "open", "half_closed_local", "half_closed_remote", "closed"}
Active == {"open", "half_closed_local", "half_closed_remote"}

(* One frame. Every frame carries every field, so any two compare.         *)
Frame(type, stream, end, value) == [type |-> type, stream |-> stream, end |-> end, value |-> value]

VARIABLES
    state,          \* state[e][s]: stream s at endpoint e (§5.1)
    headersSent,    \* headersSent[e][s]: e sent its HEADERS on s, its request or its response
    left,           \* left[e][s]: DATA units e still has to send on s
    sendWindow,     \* sendWindow[e][s]: e's credit on s, which the peer advertised
    connectionSend, \* connectionSend[e]: e's credit on the connection
    receiveWindow,  \* receiveWindow[e][s]: what e advertised on s that the peer may still fill
    released,       \* released[e][s]: credit e gave back on s and has not yet sent
    connectionReceive,  \* connectionReceive[e], the same for the connection
    connectionReleased, \* connectionReleased[e]
    peerInit,       \* peerInit[e]: the peer's SETTINGS_INITIAL_WINDOW_SIZE, as e applied it
    localInit,      \* localInit[e]: the SETTINGS_INITIAL_WINDOW_SIZE e advertises
    unacknowledged, \* unacknowledged[e]: SETTINGS frames e sent that the peer has not acknowledged
    changesLeft,    \* changes Changer may still make
    toward,         \* toward[e]: the frames in flight toward e, in order
    acksOwed,       \* acksOwed[e]: SETTINGS acknowledgments e owes
    connectionOwed, \* connectionOwed[e]: the connection increment e owes, 0 for none
    streamOwed,     \* streamOwed[e]: the stream increments e owes, oldest first, as <<s, n>>
    forbiddenSent,  \* a frame went out that its stream's state forbids (§5.1)
    flowError       \* a sender sent on a window that was not positive (§6.9.2), a receiver
                    \* got more than it advertised, or a window passed Max (§6.9.1)

vars == <<state, headersSent, left, sendWindow, connectionSend, receiveWindow, released,
          connectionReceive, connectionReleased, peerInit, localInit, unacknowledged, changesLeft,
          toward, acksOwed, connectionOwed, streamOwed, forbiddenSent, flowError>>

TypeOK ==
    /\ state \in [Endpoints -> [Streams -> States]]
    /\ headersSent \in [Endpoints -> [Streams -> BOOLEAN]]
    /\ left \in [Endpoints -> [Streams -> 0..Body]]
    /\ sendWindow \in [Endpoints -> [Streams -> -Max..Max]]
    /\ connectionSend \in [Endpoints -> -Max..Max]
    \* Changer's may go further below zero while it takes what §6.9.3 lets it.
    /\ receiveWindow \in [Endpoints -> [Streams -> (-2 * Max)..Max]]
    /\ forbiddenSent \in BOOLEAN /\ flowError \in BOOLEAN

Init ==
    /\ state = [e \in Endpoints |-> [s \in Streams |-> "idle"]]
    /\ headersSent = [e \in Endpoints |-> [s \in Streams |-> FALSE]]
    /\ left = [e \in Endpoints |-> [s \in Streams |-> Body]]
    /\ sendWindow = [e \in Endpoints |-> [s \in Streams |-> 0]]
    /\ connectionSend = [e \in Endpoints |-> InitialWindow]
    /\ receiveWindow = [e \in Endpoints |-> [s \in Streams |-> 0]]
    /\ released = [e \in Endpoints |-> [s \in Streams |-> 0]]
    /\ connectionReceive = [e \in Endpoints |-> InitialWindow]
    /\ connectionReleased = [e \in Endpoints |-> 0]
    /\ peerInit = [e \in Endpoints |-> InitialWindow]
    /\ localInit = [e \in Endpoints |-> InitialWindow]
    /\ unacknowledged = [e \in Endpoints |-> 0]
    /\ changesLeft = ChangesMax
    /\ toward = [e \in Endpoints |-> <<>>]
    /\ acksOwed = [e \in Endpoints |-> 0]
    /\ connectionOwed = [e \in Endpoints |-> 0]
    /\ streamOwed = [e \in Endpoints |-> <<>>]
    /\ forbiddenSent = FALSE
    /\ flowError = FALSE

Room(e) == Len(toward[Peer(e)]) < ChannelMax
Put(e, frame) == toward' = [toward EXCEPT ![Peer(e)] = Append(@, frame)]

(* The state a frame carrying END_STREAM leaves behind, sent or received   *)
(* (§5.1).                                                                 *)
AfterSentEnd(st) == IF st = "open" THEN "half_closed_local" ELSE "closed"
AfterReceivedEnd(st) == IF st = "open" THEN "half_closed_remote" ELSE "closed"

(* The client opens a stream with its request's HEADERS (§5.1), and the    *)
(* stream's windows start at the initial values each side knows (§6.9.2).  *)
Open(s) ==
    LET e == Client
        end == left[e][s] = 0
    IN /\ state[e][s] = "idle"
       /\ Room(e)
       /\ Put(e, Frame("HEADERS", s, end, 0))
       /\ state' = [state EXCEPT ![e][s] = IF end THEN "half_closed_local" ELSE "open"]
       /\ headersSent' = [headersSent EXCEPT ![e][s] = TRUE]
       /\ sendWindow' = [sendWindow EXCEPT ![e][s] = peerInit[e]]
       /\ receiveWindow' = [receiveWindow EXCEPT ![e][s] = localInit[e]]
       /\ UNCHANGED <<left, connectionSend, released, connectionReceive, connectionReleased,
                      peerInit, localInit, unacknowledged, changesLeft, acksOwed,
                      connectionOwed, streamOwed, forbiddenSent, flowError>>

(* The server answers a stream the request opened with its response's      *)
(* HEADERS, which may end its side at once.                                *)
Respond(s) ==
    LET e == Server
        end == left[e][s] = 0
    IN /\ state[e][s] \in {"open", "half_closed_remote"}
       /\ ~headersSent[e][s]
       /\ Room(e)
       /\ Put(e, Frame("HEADERS", s, end, 0))
       /\ headersSent' = [headersSent EXCEPT ![e][s] = TRUE]
       /\ state' = IF end THEN [state EXCEPT ![e][s] = AfterSentEnd(@)] ELSE state
       /\ UNCHANGED <<left, sendWindow, connectionSend, receiveWindow, released,
                      connectionReceive, connectionReleased, peerInit, localInit,
                      unacknowledged, changesLeft, acksOwed, connectionOwed, streamOwed,
                      forbiddenSent, flowError>>

(* One DATA unit, which only open and half-closed (remote) streams carry   *)
(* (§5.1), within both windows (§6.9.1). The last one carries END_STREAM.  *)
SendData(e, s) ==
    LET end == left[e][s] = 1
        windowsAllow == IF HonourNegative
                        THEN sendWindow[e][s] > 0 /\ connectionSend[e] > 0
                        ELSE sendWindow[e][s] > -Max /\ connectionSend[e] > -Max
    IN /\ state[e][s] \in {"open", "half_closed_remote"}
       /\ headersSent[e][s]
       /\ left[e][s] > 0
       /\ windowsAllow
       /\ Room(e)
       /\ Put(e, Frame("DATA", s, end, 1))
       /\ left' = [left EXCEPT ![e][s] = @ - 1]
       /\ sendWindow' = [sendWindow EXCEPT ![e][s] = @ - 1]
       /\ connectionSend' = [connectionSend EXCEPT ![e] = @ - 1]
       /\ state' = IF end THEN [state EXCEPT ![e][s] = AfterSentEnd(@)] ELSE state
       \* §6.9.2: "A sender MUST track the negative flow-control window and MUST NOT send new
       \* flow-controlled frames until it receives WINDOW_UPDATE frames that cause the
       \* flow-control window to become positive."
       /\ flowError' = (flowError \/ sendWindow[e][s] <= 0 \/ connectionSend[e] <= 0)
       /\ UNCHANGED <<headersSent, receiveWindow, released, connectionReceive,
                      connectionReleased, peerInit, localInit, unacknowledged, changesLeft,
                      acksOwed, connectionOwed, streamOwed, forbiddenSent>>

(* Writes the oldest thing e owes, in connection_reply.zig's order. A      *)
(* stream's WINDOW_UPDATE on a closed stream is a frame §5.1 forbids:      *)
(* "An endpoint MUST NOT send frames other than PRIORITY on a closed       *)
(* stream."                                                                *)
Flush(e) ==
    /\ Room(e)
    /\ \/ /\ acksOwed[e] > 0
          /\ Put(e, Frame("SETTINGS_ACK", Connection, FALSE, 0))
          /\ acksOwed' = [acksOwed EXCEPT ![e] = @ - 1]
          /\ UNCHANGED <<connectionOwed, streamOwed, forbiddenSent>>
       \/ /\ acksOwed[e] = 0
          /\ connectionOwed[e] > 0
          /\ Put(e, Frame("WINDOW_UPDATE", Connection, FALSE, connectionOwed[e]))
          /\ connectionOwed' = [connectionOwed EXCEPT ![e] = 0]
          /\ UNCHANGED <<acksOwed, streamOwed, forbiddenSent>>
       \/ /\ acksOwed[e] = 0 /\ connectionOwed[e] = 0
          /\ streamOwed[e] # <<>>
          /\ LET owed == Head(streamOwed[e])
             IN /\ Put(e, Frame("WINDOW_UPDATE", owed[1], FALSE, owed[2]))
                /\ forbiddenSent' = (forbiddenSent \/ state[e][owed[1]] = "closed")
          /\ streamOwed' = [streamOwed EXCEPT ![e] = Tail(@)]
          /\ UNCHANGED <<acksOwed, connectionOwed>>
    /\ UNCHANGED <<state, headersSent, left, sendWindow, connectionSend, receiveWindow, released,
                   connectionReceive, connectionReleased, peerInit, localInit, unacknowledged,
                   changesLeft, flowError>>

(* Changer advertises another initial window. It moves what it advertised  *)
(* on every active stream by the difference at once, and takes what the    *)
(* sender sent before reading the SETTINGS (§6.9.3).                       *)
ChangeSettings(e, value) ==
    /\ e = Changer
    /\ changesLeft > 0
    /\ value # localInit[e]
    /\ Room(e)
    /\ Put(e, Frame("SETTINGS", Connection, FALSE, value))
    /\ receiveWindow' = [receiveWindow EXCEPT ![e] =
            [s \in Streams |-> IF state[e][s] \in Active THEN @[s] + value - localInit[e] ELSE @[s]]]
    /\ localInit' = [localInit EXCEPT ![e] = value]
    /\ unacknowledged' = [unacknowledged EXCEPT ![e] = @ + 1]
    /\ changesLeft' = changesLeft - 1
    /\ UNCHANGED <<state, headersSent, left, sendWindow, connectionSend, released,
                   connectionReceive, connectionReleased, peerInit, acksOwed, connectionOwed,
                   streamOwed, forbiddenSent, flowError>>

(* Whether the credit gathered, with one more DATA unit, now owes a        *)
(* WINDOW_UPDATE (window.Receiver.release). The unit is charged to the     *)
(* window, then everything gathered goes back into it at once, so the      *)
(* window moves by what was gathered before.                               *)
Gathered(count) == count + 1 >= Threshold

(* Reads one DATA unit on s: both windows count it, the credit goes back   *)
(* at once, and a stream that ends changes state after the counting, as    *)
(* connection_data.zig orders it. With DropOnEnd, the credit a stream owes *)
(* is dropped once the peer has ended its side, since no more DATA comes.  *)
ReceiveData(e, frame) ==
    LET s == frame.stream
        tolerated == unacknowledged[e] > 0     \* §6.9.3, Changer alone
        streamGathered == Gathered(released[e][s])
        owedHere == IF streamGathered /\ ~(DropOnEnd /\ frame.end)
                    THEN Append(streamOwed[e], <<s, released[e][s] + 1>>)
                    ELSE streamOwed[e]
        stillOwed == IF DropOnEnd /\ frame.end
                     THEN SelectSeq(owedHere, LAMBDA owed : owed[1] # s)
                     ELSE owedHere
    IN /\ flowError' = (flowError \/ connectionReceive[e] < 1
                                   \/ (receiveWindow[e][s] < 1 /\ ~tolerated))
       /\ connectionReceive' = [connectionReceive EXCEPT ![e] =
            IF Gathered(connectionReleased[e]) THEN @ + connectionReleased[e] ELSE @ - 1]
       /\ connectionReleased' = [connectionReleased EXCEPT ![e] =
            IF Gathered(@) THEN 0 ELSE @ + 1]
       /\ connectionOwed' = [connectionOwed EXCEPT ![e] =
            IF Gathered(connectionReleased[e]) THEN @ + connectionReleased[e] + 1 ELSE @]
       /\ receiveWindow' = [receiveWindow EXCEPT ![e][s] =
            IF streamGathered THEN @ + released[e][s] ELSE @ - 1]
       /\ released' = [released EXCEPT ![e][s] = IF streamGathered THEN 0 ELSE @ + 1]
       /\ streamOwed' = [streamOwed EXCEPT ![e] = stillOwed]
       /\ state' = IF frame.end THEN [state EXCEPT ![e][s] = AfterReceivedEnd(@)] ELSE state
       /\ UNCHANGED <<headersSent, left, sendWindow, connectionSend, peerInit, localInit,
                      unacknowledged, acksOwed>>

(* Reads HEADERS: a request opens the server's stream, and its windows     *)
(* start at the initial values the server knows (§6.9.2).                  *)
ReceiveHeaders(e, frame) ==
    LET s == frame.stream
    IN /\ IF state[e][s] = "idle"
          THEN /\ state' = [state EXCEPT ![e][s] =
                    IF frame.end THEN "half_closed_remote" ELSE "open"]
               /\ sendWindow' = [sendWindow EXCEPT ![e][s] = peerInit[e]]
               /\ receiveWindow' = [receiveWindow EXCEPT ![e][s] = localInit[e]]
          ELSE /\ state' = IF frame.end THEN [state EXCEPT ![e][s] = AfterReceivedEnd(@)]
                                        ELSE state
               /\ UNCHANGED <<sendWindow, receiveWindow>>
       /\ UNCHANGED <<headersSent, left, connectionSend, released, connectionReceive,
                      connectionReleased, peerInit, localInit, unacknowledged, acksOwed,
                      connectionOwed, streamOwed, flowError>>

(* Reads a WINDOW_UPDATE. One past Max is an error, and one for a stream   *)
(* that is no longer active is taken and ignored (§5.1, §6.9).             *)
ReceiveUpdate(e, frame) ==
    LET s == frame.stream
    IN IF s = Connection
       THEN /\ flowError' = (flowError \/ connectionSend[e] + frame.value > Max)
            /\ connectionSend' = [connectionSend EXCEPT ![e] = @ + frame.value]
            /\ UNCHANGED sendWindow
       ELSE /\ flowError' = (flowError \/ (state[e][s] \in Active
                                           /\ sendWindow[e][s] + frame.value > Max))
            /\ sendWindow' = IF state[e][s] \in Active
                             THEN [sendWindow EXCEPT ![e][s] = @ + frame.value]
                             ELSE sendWindow
            /\ UNCHANGED connectionSend

(* Reads SETTINGS: every active stream's send window moves by the change,  *)
(* and may go negative (§6.9.2); past Max is an error. Then it owes the    *)
(* acknowledgment (§6.5.3).                                                *)
ReceiveSettings(e, frame) ==
    LET delta == frame.value - peerInit[e]
        moved == [s \in Streams |-> IF state[e][s] \in Active THEN sendWindow[e][s] + delta
                                                               ELSE sendWindow[e][s]]
    IN /\ flowError' = (flowError \/ \E s \in Streams : moved[s] > Max)
       /\ sendWindow' = [sendWindow EXCEPT ![e] = moved]
       /\ peerInit' = [peerInit EXCEPT ![e] = frame.value]
       /\ acksOwed' = [acksOwed EXCEPT ![e] = @ + 1]

Receive(e) ==
    /\ toward[e] # <<>>
    /\ LET frame == Head(toward[e])
       IN /\ toward' = [toward EXCEPT ![e] = Tail(@)]
          /\ CASE frame.type = "DATA" -> ReceiveData(e, frame)
               [] frame.type = "HEADERS" -> ReceiveHeaders(e, frame)
               [] frame.type = "WINDOW_UPDATE" ->
                    /\ ReceiveUpdate(e, frame)
                    /\ UNCHANGED <<state, headersSent, left, receiveWindow, released,
                                   connectionReceive, connectionReleased, peerInit, localInit,
                                   unacknowledged, acksOwed, connectionOwed, streamOwed>>
               [] frame.type = "SETTINGS" ->
                    /\ ReceiveSettings(e, frame)
                    /\ UNCHANGED <<state, headersSent, left, connectionSend, receiveWindow,
                                   released, connectionReceive, connectionReleased, localInit,
                                   unacknowledged, connectionOwed, streamOwed>>
               [] frame.type = "SETTINGS_ACK" ->
                    /\ unacknowledged' = [unacknowledged EXCEPT ![e] = @ - 1]
                    /\ UNCHANGED <<state, headersSent, left, sendWindow, connectionSend,
                                   receiveWindow, released, connectionReceive, connectionReleased,
                                   peerInit, localInit, acksOwed, connectionOwed, streamOwed,
                                   flowError>>
    /\ UNCHANGED <<changesLeft, forbiddenSent>>

Next ==
    \/ \E s \in Streams : Open(s) \/ Respond(s)
    \/ \E e \in Endpoints :
        \/ Receive(e)
        \/ Flush(e)
        \/ \E s \in Streams : SendData(e, s)
        \/ \E value \in NewInits : ChangeSettings(e, value)

Fairness ==
    /\ \A s \in Streams : WF_vars(Open(s)) /\ WF_vars(Respond(s))
    /\ \A e \in Endpoints :
        /\ WF_vars(Receive(e))
        /\ WF_vars(Flush(e))
        /\ \A s \in Streams : WF_vars(SendData(e, s))

Spec == Init /\ [][Next]_vars /\ Fairness

(* Safety: no frame a stream's state forbids goes out (§5.1), no receiver  *)
(* is sent past what it advertised and no window passes Max (§6.9.1).      *)
NoForbiddenFrame == ~forbiddenSent
NoFlowError == ~flowError

(* Liveness: every exchange finishes. A sender that flow control holds is  *)
(* released once the receiver takes the data, and every stream closes at   *)
(* both ends with nothing left in flight or owed.                          *)
Finished ==
    /\ \A e \in Endpoints, s \in Streams : state[e][s] = "closed"
    /\ \A e \in Endpoints : toward[e] = <<>>
Finishes == <>Finished

(* Found violated by a configuration of its own: a SETTINGS change drives  *)
(* a send window negative, so NoFlowError holding is not the case never    *)
(* arising.                                                                *)
NeverNegative == \A e \in Endpoints, s \in Streams : sendWindow[e][s] >= 0
=============================================================================
