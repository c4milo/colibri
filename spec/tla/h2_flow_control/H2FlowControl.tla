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
(*     update_after_end keeps the path;                                    *)
(*   - a receiver reads a frame only while its queue of replies about      *)
(*     single streams has a free slot (QueueMax, stream_replies_max), and  *)
(*     one frame owes at most one of them, so the queue never passes its   *)
(*     limit (QueueBounded);                                               *)
(*   - the caller of Resetter, one of the two endpoints, may reset any     *)
(*     active stream (§6.4), which closes it at once. The stream's record  *)
(*     owes the RST_STREAM, written after the queued replies (decision     *)
(*     113), and the credit owed on the stream is dropped (DropOnReset).   *)
(*     The receiver of the RST_STREAM closes the stream and drops its      *)
(*     credit too. DATA on a stream the receiver reset is discarded, and   *)
(*     still counts toward the connection window, which §5.1 requires      *)
(*     (ChargeAfterReset). Resets queued with the replies with no room     *)
(*     checked, as colibri queued them before decision 113, overflow the   *)
(*     queue: the configuration reset_in_queue keeps that path;            *)
(*   - colibri never changes the initial window it advertises. Changer, a  *)
(*     peer that is not colibri, may: it adjusts what it advertised when   *)
(*     it sends the SETTINGS, and takes what the sender sent before        *)
(*     reading them (§6.9.3);                                              *)
(*   - a sender's caller offers Chunk units of content at a time, and a    *)
(*     DATA frame carries what both windows take of the offer, up to       *)
(*     FrameMax (connection_send_window.zig's sendable). The server holds  *)
(*     a frame while the windows are below Floor and do not take the whole *)
(*     offer, but only once the peer's initial window is at least Floor    *)
(*     and the peer has sent an increment below it (decision 110 as        *)
(*     amended). The client has no floor. The rules before the amendments  *)
(*     stall a peer, and the configurations floor_small_window and         *)
(*     floor_any_update keep them;                                         *)
(*   - with ServerTimeout, the server's send deadline and then its linger  *)
(*     end the connection while the client takes nothing it sends: the     *)
(*     channel toward the client stays full (decision 110). It ends the    *)
(*     stall of https://github.com/c4milo/colibri/issues/85, which the     *)
(*     configuration queue_stall keeps;                                    *)
(*   - an endpoint in OwedFirst writes what it owes before a frame of its  *)
(*     own, so its HEADERS and DATA wait while it owes anything (decision  *)
(*     39 as amended). colibri's client and server both do. With           *)
(*     OwedFirst empty the order is free, as in queue_stall;               *)
(*   - with Weighted, the channel counts units, not frames: a DATA frame   *)
(*     takes its units and one more for its header, any other frame one,   *)
(*     and a DATA frame is cut to the room left (sendable). A reply then   *)
(*     costs far less room than a DATA frame, as its 13 octets do beside   *)
(*     16,384. Without Weighted every frame takes one of ChannelMax slots. *)
(*                                                                         *)
(* Numbers are small stand-ins: Max for 2^31-1 (§6.9.1), InitialWindow for *)
(* the 65,535-octet initial window, Threshold for window_update_threshold, *)
(* Floor for data_frame_len_min and FrameMax for SETTINGS_MAX_FRAME_SIZE.  *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Client, Server,     \* the two endpoints
    Nobody,             \* no endpoint, as a value of Changer or Resetter
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
    DropOnEnd,          \* whether a receiver drops the stream credit it owes once the peer ends
    QueueMax,           \* the replies about single streams a receiver's queue holds
    Resetter,           \* the endpoint whose caller resets streams (§6.4), or Nobody
    ResetOnRecord,      \* whether a reset is owed by the stream's record, not queued (decision 113)
    DropOnReset,        \* whether a reset drops the stream credit owed on that stream
    ChargeAfterReset,   \* whether DATA on a stream the receiver reset counts toward the connection
                        \* window (§5.1)
    FrameMax,           \* the most units one DATA frame carries (§4.2)
    Chunk,              \* the units a sender's caller offers at once, or what is left if less
    Floor,              \* data_frame_len_min at the server, 0 for none
    FloorOnlyAbove,     \* whether the floor applies only while the peer's initial window is
                        \* at least Floor (decision 110 as amended)
    FloorAfterSmall,    \* whether it applies only once the peer sent an increment below Floor
    ServerTimeout,      \* whether the server's send deadline ends a connection whose client takes
                        \* nothing (decision 110)
    OwedFirst,          \* the endpoints that write what they owe before a frame of their own
    Weighted            \* whether the channel counts DATA units rather than frames

Endpoints == {Client, Server}
Peer(e) == IF e = Client THEN Server ELSE Client
Connection == 0         \* the stream identifier of the connection's own frames (§6.9)

ASSUME /\ Streams \subseteq Nat \ {Connection}
       /\ {Body, InitialWindow, Threshold, Max, ChannelMax, ChangesMax} \subseteq Nat
       /\ Threshold >= 1 /\ InitialWindow <= Max
       /\ Changer \in Endpoints \cup {Nobody}
       /\ NewInits \subseteq 0..Max
       /\ HonourNegative \in BOOLEAN /\ DropOnEnd \in BOOLEAN
       /\ QueueMax \in Nat \ {0}
       /\ Resetter \in Endpoints \cup {Nobody}
       /\ {ResetOnRecord, DropOnReset, ChargeAfterReset} \subseteq BOOLEAN
       /\ {FrameMax, Chunk} \subseteq Nat \ {0} /\ Floor \in Nat /\ Floor <= FrameMax
       /\ {FloorOnlyAbove, FloorAfterSmall, ServerTimeout} \subseteq BOOLEAN
       /\ OwedFirst \subseteq Endpoints /\ Weighted \in BOOLEAN
       \* A weighted channel cuts a frame to the windows, so it sends none on a window not positive.
       /\ Weighted => HonourNegative

States == {"idle", "open", "half_closed_local", "half_closed_remote", "closed"}
Active == {"open", "half_closed_local", "half_closed_remote"}

(* One frame. Every frame carries every field, so any two compare: value   *)
(* is a DATA frame's units, a WINDOW_UPDATE's increment or a SETTINGS       *)
(* frame's initial window.                                                 *)
Frame(type, stream, end, value) == [type |-> type, stream |-> stream, end |-> end, value |-> value]

Min(a, b) == IF a < b THEN a ELSE b

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
    streamOwed,     \* streamOwed[e]: the stream replies e owes, oldest first, as <<s, n>>: an
                    \* increment n, or 0 for a RST_STREAM queued when ResetOnRecord is FALSE
    resetOwed,      \* resetOwed[e]: the streams whose records owe a RST_STREAM e's caller asked for
    resetSent,      \* resetSent[e][s]: e's caller reset s
    forbiddenSent,  \* a frame went out that its stream's state forbids (§5.1)
    flowError,      \* a sender sent on a window that was not positive (§6.9.2), a receiver
                    \* got more than it advertised, or a window passed Max (§6.9.1)
    smallIncrement, \* smallIncrement[e]: e read an increment below Floor (tiny_update_read)
    ended           \* the server ended the connection on its send deadline

vars == <<state, headersSent, left, sendWindow, connectionSend, receiveWindow, released,
          connectionReceive, connectionReleased, peerInit, localInit, unacknowledged, changesLeft,
          toward, acksOwed, connectionOwed, streamOwed, resetOwed, resetSent, forbiddenSent,
          flowError, smallIncrement, ended>>

TypeOK ==
    /\ state \in [Endpoints -> [Streams -> States]]
    /\ headersSent \in [Endpoints -> [Streams -> BOOLEAN]]
    /\ left \in [Endpoints -> [Streams -> 0..Body]]
    /\ sendWindow \in [Endpoints -> [Streams -> -Max..Max]]
    /\ connectionSend \in [Endpoints -> -Max..Max]
    \* Changer's may go further below zero while it takes what §6.9.3 lets it.
    /\ receiveWindow \in [Endpoints -> [Streams -> (-2 * Max)..Max]]
    /\ resetOwed \in [Endpoints -> SUBSET Streams]
    /\ resetSent \in [Endpoints -> [Streams -> BOOLEAN]]
    /\ forbiddenSent \in BOOLEAN /\ flowError \in BOOLEAN
    /\ smallIncrement \in [Endpoints -> BOOLEAN] /\ ended \in BOOLEAN

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
    /\ resetOwed = [e \in Endpoints |-> {}]
    /\ resetSent = [e \in Endpoints |-> [s \in Streams |-> FALSE]]
    /\ forbiddenSent = FALSE
    /\ flowError = FALSE
    /\ smallIncrement = [e \in Endpoints |-> FALSE]
    /\ ended = FALSE

(* The room a frame takes in the channel: with Weighted, a DATA frame's    *)
(* units and one for its header, and one for any other frame.              *)
Weight(frame) == IF Weighted /\ frame.type = "DATA" THEN frame.value + 1 ELSE 1

(* The room the frames in flight toward e take.                            *)
Used(e) ==
    LET flight == toward[e]
        total[i \in 0..Len(flight)] == IF i = 0 THEN 0 ELSE total[i - 1] + Weight(flight[i])
    IN total[Len(flight)]

(* Whether the channel from e has room for a frame that is not DATA, and   *)
(* the DATA units it has room for after a frame header.                    *)
Room(e) == Used(Peer(e)) < ChannelMax
DataRoom(e) == ChannelMax - Used(Peer(e)) - 1
Put(e, frame) == toward' = [toward EXCEPT ![Peer(e)] = Append(@, frame)]

(* Whether e owes a frame it has not written: a SETTINGS acknowledgment,   *)
(* an increment, or a RST_STREAM a record owes.                            *)
Owes(e) ==
    \/ acksOwed[e] > 0 \/ connectionOwed[e] > 0
    \/ streamOwed[e] # <<>> \/ resetOwed[e] # {}

(* Whether e may write a frame of its own, HEADERS or DATA: an endpoint in *)
(* OwedFirst writes what it owes first (h2's write_replies, decision 39 as *)
(* amended).                                                               *)
OwnFrameAllowed(e) == e \notin OwedFirst \/ ~Owes(e)

(* The replies e owes with the credit it owes on s dropped. A queued       *)
(* RST_STREAM on s stays (connection_reply.zig's drop_window_updates).     *)
DropCredit(owed, s) == SelectSeq(owed, LAMBDA reply : reply[1] # s \/ reply[2] = 0)

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
       /\ Room(e) /\ OwnFrameAllowed(e)
       /\ Put(e, Frame("HEADERS", s, end, 0))
       /\ state' = [state EXCEPT ![e][s] = IF end THEN "half_closed_local" ELSE "open"]
       /\ headersSent' = [headersSent EXCEPT ![e][s] = TRUE]
       /\ sendWindow' = [sendWindow EXCEPT ![e][s] = peerInit[e]]
       /\ receiveWindow' = [receiveWindow EXCEPT ![e][s] = localInit[e]]
       /\ UNCHANGED <<left, connectionSend, released, connectionReceive, connectionReleased,
                      peerInit, localInit, unacknowledged, changesLeft, acksOwed,
                      connectionOwed, streamOwed, resetOwed, resetSent, forbiddenSent, flowError,
                      smallIncrement>>

(* The server answers a stream the request opened with its response's      *)
(* HEADERS, which may end its side at once.                                *)
Respond(s) ==
    LET e == Server
        end == left[e][s] = 0
    IN /\ state[e][s] \in {"open", "half_closed_remote"}
       /\ ~headersSent[e][s]
       /\ Room(e) /\ OwnFrameAllowed(e)
       /\ Put(e, Frame("HEADERS", s, end, 0))
       /\ headersSent' = [headersSent EXCEPT ![e][s] = TRUE]
       /\ state' = IF end THEN [state EXCEPT ![e][s] = AfterSentEnd(@)] ELSE state
       /\ UNCHANGED <<left, sendWindow, connectionSend, receiveWindow, released,
                      connectionReceive, connectionReleased, peerInit, localInit,
                      unacknowledged, changesLeft, acksOwed, connectionOwed, streamOwed,
                      resetOwed, resetSent, forbiddenSent, flowError, smallIncrement>>

(* Whether the server holds a DATA frame shorter than Floor: once the       *)
(* peer's initial window is at least Floor, and once the peer has sent an   *)
(* increment below it (decision 110 as amended).                            *)
FloorApplies(e) ==
    /\ e = Server /\ Floor > 0
    /\ (~FloorOnlyAbove \/ peerInit[e] >= Floor)
    /\ (~FloorAfterSmall \/ smallIncrement[e])

(* connection_send_window.zig's sendable: the caller offers Chunk units, or *)
(* what is left if less, and the frame carries the offer when both windows  *)
(* take it, else what they take, but nothing while that is below the floor. *)
(* With Weighted, the frame is cut to the room left.                       *)
DataLen(e, s) ==
    LET window == Min(sendWindow[e][s], connectionSend[e])
        offer == Min(Chunk, left[e][s])
        taken == IF window >= offer THEN offer
                 ELSE IF FloorApplies(e) /\ window < Floor THEN 0
                 ELSE window
        framed == Min(taken, FrameMax)
    IN IF Weighted THEN Min(framed, DataRoom(e)) ELSE framed

(* One DATA frame, which only open and half-closed (remote) streams carry  *)
(* (§5.1), within both windows (§6.9.1). The last one carries END_STREAM.  *)
(* Without HonourNegative a sender sends one unit on any window.           *)
SendData(e, s) ==
    LET n == IF HonourNegative THEN DataLen(e, s) ELSE 1
        end == left[e][s] = n
        windowsAllow == IF HonourNegative
                        THEN n > 0
                        ELSE sendWindow[e][s] > -Max /\ connectionSend[e] > -Max
    IN /\ state[e][s] \in {"open", "half_closed_remote"}
       /\ headersSent[e][s]
       /\ left[e][s] > 0
       /\ windowsAllow
       /\ Room(e) /\ OwnFrameAllowed(e)
       /\ Put(e, Frame("DATA", s, end, n))
       /\ left' = [left EXCEPT ![e][s] = @ - n]
       /\ sendWindow' = [sendWindow EXCEPT ![e][s] = @ - n]
       /\ connectionSend' = [connectionSend EXCEPT ![e] = @ - n]
       /\ state' = IF end THEN [state EXCEPT ![e][s] = AfterSentEnd(@)] ELSE state
       \* §6.9.2: "A sender MUST track the negative flow-control window and MUST NOT send new
       \* flow-controlled frames until it receives WINDOW_UPDATE frames that cause the
       \* flow-control window to become positive."
       /\ flowError' = (flowError \/ sendWindow[e][s] < n \/ connectionSend[e] < n)
       /\ UNCHANGED <<headersSent, receiveWindow, released, connectionReceive,
                      connectionReleased, peerInit, localInit, unacknowledged, changesLeft,
                      acksOwed, connectionOwed, streamOwed, resetOwed, resetSent, forbiddenSent,
                      smallIncrement>>

(* Writes the oldest thing e owes, in connection_reply.zig's order, then a *)
(* RST_STREAM a record owes, in any order, since slot order is not         *)
(* modeled. A stream's WINDOW_UPDATE on a closed stream is a frame §5.1    *)
(* forbids: "An endpoint MUST NOT send frames other than PRIORITY on a     *)
(* closed stream." A RST_STREAM is the frame that closed it.               *)
Flush(e) ==
    /\ Room(e)
    /\ \/ /\ acksOwed[e] > 0
          /\ Put(e, Frame("SETTINGS_ACK", Connection, FALSE, 0))
          /\ acksOwed' = [acksOwed EXCEPT ![e] = @ - 1]
          /\ UNCHANGED <<connectionOwed, streamOwed, resetOwed, forbiddenSent>>
       \/ /\ acksOwed[e] = 0
          /\ connectionOwed[e] > 0
          /\ Put(e, Frame("WINDOW_UPDATE", Connection, FALSE, connectionOwed[e]))
          /\ connectionOwed' = [connectionOwed EXCEPT ![e] = 0]
          /\ UNCHANGED <<acksOwed, streamOwed, resetOwed, forbiddenSent>>
       \/ /\ acksOwed[e] = 0 /\ connectionOwed[e] = 0
          /\ streamOwed[e] # <<>>
          /\ LET owed == Head(streamOwed[e])
             IN IF owed[2] = 0
                THEN /\ Put(e, Frame("RST_STREAM", owed[1], FALSE, 0))
                     /\ UNCHANGED forbiddenSent
                ELSE /\ Put(e, Frame("WINDOW_UPDATE", owed[1], FALSE, owed[2]))
                     /\ forbiddenSent' = (forbiddenSent \/ state[e][owed[1]] = "closed")
          /\ streamOwed' = [streamOwed EXCEPT ![e] = Tail(@)]
          /\ UNCHANGED <<acksOwed, connectionOwed, resetOwed>>
       \/ /\ acksOwed[e] = 0 /\ connectionOwed[e] = 0 /\ streamOwed[e] = <<>>
          /\ \E s \in resetOwed[e] :
                /\ Put(e, Frame("RST_STREAM", s, FALSE, 0))
                /\ resetOwed' = [resetOwed EXCEPT ![e] = @ \ {s}]
          /\ UNCHANGED <<acksOwed, connectionOwed, streamOwed, forbiddenSent>>
    /\ UNCHANGED <<state, headersSent, left, sendWindow, connectionSend, receiveWindow, released,
                   connectionReceive, connectionReleased, peerInit, localInit, unacknowledged,
                   changesLeft, resetSent, flowError, smallIncrement>>

(* Resetter's caller resets stream s (§6.4), which only an active stream   *)
(* allows, and the stream closes at once. The record owes the RST_STREAM   *)
(* (decision 113), or, with ResetOnRecord FALSE, it is queued with the     *)
(* replies with no room checked. The credit e owes on s is dropped, since  *)
(* no DATA on s is read any more (§5.1).                                   *)
Reset(e, s) ==
    LET kept == IF DropOnReset THEN DropCredit(streamOwed[e], s) ELSE streamOwed[e]
    IN /\ e = Resetter
       /\ state[e][s] \in Active
       /\ state' = [state EXCEPT ![e][s] = "closed"]
       /\ resetSent' = [resetSent EXCEPT ![e][s] = TRUE]
       /\ IF ResetOnRecord
          THEN /\ streamOwed' = [streamOwed EXCEPT ![e] = kept]
               /\ resetOwed' = [resetOwed EXCEPT ![e] = @ \cup {s}]
          ELSE /\ streamOwed' = [streamOwed EXCEPT ![e] = Append(kept, <<s, 0>>)]
               /\ UNCHANGED resetOwed
       /\ UNCHANGED <<headersSent, left, sendWindow, connectionSend, receiveWindow, released,
                      connectionReceive, connectionReleased, peerInit, localInit, unacknowledged,
                      changesLeft, toward, acksOwed, connectionOwed, forbiddenSent, flowError,
                      smallIncrement>>

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
                   streamOwed, resetOwed, resetSent, forbiddenSent, flowError, smallIncrement>>

(* Whether the credit gathered, with a DATA frame's n more units, now owes *)
(* a WINDOW_UPDATE (window.Receiver.release). The frame is charged to the  *)
(* window, then everything gathered goes back into it at once, so the      *)
(* window moves by what was gathered before.                               *)
Gathered(count, n) == count + n >= Threshold

(* The connection window takes a DATA frame's n units and its credit goes  *)
(* back at once (window.Receiver), whatever the stream does with the frame.*)
ChargeConnection(e, n) ==
    /\ connectionReceive' = [connectionReceive EXCEPT ![e] =
            IF Gathered(connectionReleased[e], n) THEN @ + connectionReleased[e] ELSE @ - n]
    /\ connectionReleased' = [connectionReleased EXCEPT ![e] =
            IF Gathered(@, n) THEN 0 ELSE @ + n]
    /\ connectionOwed' = [connectionOwed EXCEPT ![e] =
            IF Gathered(connectionReleased[e], n) THEN @ + connectionReleased[e] + n ELSE @]

(* Reads a DATA frame of n units on s: both windows count it, the credit   *)
(* goes back at once, and a stream that ends changes state after the       *)
(* counting, as connection_data.zig orders it. With DropOnEnd, the credit  *)
(* a stream owes is dropped once the peer has ended its side, since no     *)
(* more DATA comes.                                                        *)
ReceiveData(e, frame) ==
    LET s == frame.stream
        n == frame.value
        tolerated == unacknowledged[e] > 0     \* §6.9.3, Changer alone
        streamGathered == Gathered(released[e][s], n)
        owedHere == IF streamGathered /\ ~(DropOnEnd /\ frame.end)
                    THEN Append(streamOwed[e], <<s, released[e][s] + n>>)
                    ELSE streamOwed[e]
        stillOwed == IF DropOnEnd /\ frame.end THEN DropCredit(owedHere, s) ELSE owedHere
    IN /\ flowError' = (flowError \/ connectionReceive[e] < n
                                   \/ (receiveWindow[e][s] < n /\ ~tolerated))
       /\ ChargeConnection(e, n)
       /\ receiveWindow' = [receiveWindow EXCEPT ![e][s] =
            IF streamGathered THEN @ + released[e][s] ELSE @ - n]
       /\ released' = [released EXCEPT ![e][s] = IF streamGathered THEN 0 ELSE @ + n]
       /\ streamOwed' = [streamOwed EXCEPT ![e] = stillOwed]
       /\ state' = IF frame.end THEN [state EXCEPT ![e][s] = AfterReceivedEnd(@)] ELSE state
       /\ UNCHANGED <<headersSent, left, sendWindow, connectionSend, peerInit, localInit,
                      unacknowledged, acksOwed>>

(* Reads one DATA unit on a stream e reset. §5.1 has e discard it, and     *)
(* "the content of DATA frames counts toward the connection flow-control   *)
(* window"; the stream's window is not charged (connection_data.zig).      *)
ReceiveDataAfterReset(e, frame) ==
    /\ flowError' = (flowError \/ connectionReceive[e] < frame.value)
    /\ IF ChargeAfterReset THEN ChargeConnection(e, frame.value)
       ELSE UNCHANGED <<connectionReceive, connectionReleased, connectionOwed>>
    /\ UNCHANGED <<state, headersSent, left, sendWindow, connectionSend, receiveWindow, released,
                   peerInit, localInit, unacknowledged, acksOwed, streamOwed>>

(* Reads a RST_STREAM. An active stream closes at once and the credit e    *)
(* owes on it is dropped (connection_stream.zig's on_rst_stream); a closed *)
(* stream ignores it (§5.1).                                               *)
ReceiveReset(e, frame) ==
    LET s == frame.stream
    IN /\ IF state[e][s] \in Active
          THEN /\ state' = [state EXCEPT ![e][s] = "closed"]
               /\ streamOwed' = [streamOwed EXCEPT ![e] = DropCredit(@, s)]
          ELSE UNCHANGED <<state, streamOwed>>
       /\ UNCHANGED <<headersSent, left, sendWindow, connectionSend, receiveWindow, released,
                      connectionReceive, connectionReleased, peerInit, localInit,
                      unacknowledged, acksOwed, connectionOwed, flowError>>

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
(* that is no longer active is taken and ignored (§5.1, §6.9). Receive     *)
(* notes an increment below Floor.                                         *)
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

(* An increment below Floor, on the connection or on a stream it is still  *)
(* active on, which h2's note_increment notes (decision 110 as amended).   *)
Small(e, frame) ==
    /\ frame.type = "WINDOW_UPDATE" /\ frame.value < Floor
    /\ (frame.stream = Connection \/ state[e][frame.stream] \in Active)

(* e reads the oldest frame toward it, while its queue of replies about    *)
(* single streams has a free slot (connection_receive.zig's is_full).      *)
Receive(e) ==
    /\ toward[e] # <<>>
    /\ Len(streamOwed[e]) < QueueMax
    /\ LET frame == Head(toward[e])
       IN /\ toward' = [toward EXCEPT ![e] = Tail(@)]
          /\ smallIncrement' = [smallIncrement EXCEPT ![e] = @ \/ Small(e, frame)]
          /\ CASE frame.type = "DATA" ->
                    IF resetSent[e][frame.stream] THEN ReceiveDataAfterReset(e, frame)
                    ELSE ReceiveData(e, frame)
               [] frame.type = "HEADERS" -> ReceiveHeaders(e, frame)
               [] frame.type = "RST_STREAM" -> ReceiveReset(e, frame)
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
    /\ UNCHANGED <<changesLeft, resetOwed, resetSent, forbiddenSent>>

(* The server's send deadline passes while the client takes nothing it     *)
(* sends, and after its linger the server ends the connection (decision    *)
(* 110): nothing moves on it any more.                                     *)
Timeout ==
    /\ ServerTimeout /\ ~ended
    /\ ~Room(Server)
    /\ ended' = TRUE
    /\ UNCHANGED <<state, headersSent, left, sendWindow, connectionSend, receiveWindow, released,
                   connectionReceive, connectionReleased, peerInit, localInit, unacknowledged,
                   changesLeft, toward, acksOwed, connectionOwed, streamOwed, resetOwed, resetSent,
                   forbiddenSent, flowError, smallIncrement>>

(* A step of an endpoint, which a connection the server ended takes no     *)
(* more.                                                                   *)
Live(A) == ~ended /\ A /\ UNCHANGED ended

Next ==
    \/ Timeout
    \/ \E s \in Streams : Live(Open(s)) \/ Live(Respond(s))
    \/ \E e \in Endpoints :
        \/ Live(Receive(e))
        \/ Live(Flush(e))
        \/ \E s \in Streams : Live(SendData(e, s)) \/ Live(Reset(e, s))
        \/ \E value \in NewInits : Live(ChangeSettings(e, value))

Fairness ==
    /\ WF_vars(Timeout)
    /\ \A s \in Streams : WF_vars(Live(Open(s))) /\ WF_vars(Live(Respond(s)))
    /\ \A e \in Endpoints :
        /\ WF_vars(Live(Receive(e)))
        /\ WF_vars(Live(Flush(e)))
        /\ \A s \in Streams : WF_vars(Live(SendData(e, s)))

Spec == Init /\ [][Next]_vars /\ Fairness

(* Safety: no frame a stream's state forbids goes out (§5.1), no receiver  *)
(* is sent past what it advertised and no window passes Max (§6.9.1).      *)
NoForbiddenFrame == ~forbiddenSent
NoFlowError == ~flowError

(* Safety: the replies a receiver's queue holds never pass its limit, so   *)
(* colibri never asserts a push into a full queue (decision 113).          *)
QueueBounded == \A e \in Endpoints : Len(streamOwed[e]) <= QueueMax

(* Safety: the frames in flight toward an endpoint never take more room    *)
(* than the channel has, which a DATA frame cut to the room keeps.         *)
ChannelBounded == \A e \in Endpoints : Used(e) <= ChannelMax

(* Liveness: every exchange finishes, or the server ends the connection.   *)
(* A sender that flow control holds is released once the receiver takes    *)
(* the data, and every stream closes at both ends with nothing left in     *)
(* flight or owed: every RST_STREAM a record owed has gone out.            *)
Finished ==
    /\ \A e \in Endpoints, s \in Streams : state[e][s] = "closed"
    /\ \A e \in Endpoints : toward[e] = <<>> /\ resetOwed[e] = {}
Finishes == <>(Finished \/ ended)

(* Found violated by a configuration of its own: a SETTINGS change drives  *)
(* a send window negative, so NoFlowError holding is not the case never    *)
(* arising.                                                                *)
NeverNegative == \A e \in Endpoints, s \in Streams : sendWindow[e][s] >= 0
=============================================================================
