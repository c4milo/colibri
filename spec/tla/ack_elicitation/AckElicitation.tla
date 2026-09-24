--------------------------- MODULE AckElicitation ---------------------------
(***************************************************************************)
(* RFC 9000 §13.2.4's PING, as docs/decisions.md entry 73 has colibri add  *)
(* it: to a packet carrying an ACK the space owes, when nothing else in it *)
(* elicits one, once the endpoint has sent Threshold packets of ACK frames *)
(* alone since its last ack-eliciting packet. The round trip entry 73 also *)
(* waits for is taken as always passed, which is the case most likely to   *)
(* loop.                                                                   *)
(*                                                                         *)
(* Two endpoints each send some data, then only what the other's packets  *)
(* ask for. The property is that the exchange ends: every packet arrives  *)
(* or is lost, and neither endpoint owes an acknowledgment. Without the    *)
(* count, each PING's answer carried a PING of its own and it never did.   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Endpoints,      \* the two endpoints, as model values
    Threshold,      \* ack_only_packets_before_ping
    DataPackets,    \* the ack-eliciting data packets each endpoint sends
    Lossy           \* whether the network may drop a packet

ASSUME Threshold \in Nat
ASSUME DataPackets \in Nat
ASSUME Lossy \in BOOLEAN

Peer(e) == CHOOSE p \in Endpoints : p # e
Kinds == {"eliciting", "ack_only"}

VARIABLES
    dataLeft,   \* data packets each endpoint has still to send
    owes,       \* RFC 9000 §13.2.1: an ack-eliciting packet arrived unacknowledged
    ackOnly,    \* packets of ACK frames alone since the last ack-eliciting one
    toward,     \* packets in flight toward each endpoint, counted by kind
    pinged      \* whether any endpoint has added a PING, which shows the rule runs

vars == <<dataLeft, owes, ackOnly, toward, pinged>>

(* Packets in flight toward one endpoint of one kind, which the data and   *)
(* the answers to it bound.                                                *)
InFlightMax == DataPackets + 2

TypeOK ==
    /\ dataLeft \in [Endpoints -> 0..DataPackets]
    /\ owes \in [Endpoints -> BOOLEAN]
    /\ ackOnly \in [Endpoints -> 0..Threshold]
    /\ toward \in [Endpoints -> [Kinds -> 0..InFlightMax]]
    /\ pinged \in BOOLEAN

Init ==
    /\ dataLeft = [e \in Endpoints |-> DataPackets]
    /\ owes = [e \in Endpoints |-> FALSE]
    /\ ackOnly = [e \in Endpoints |-> 0]
    /\ toward = [e \in Endpoints |-> [k \in Kinds |-> 0]]
    /\ pinged = FALSE

Put(e, kind) == [toward EXCEPT ![Peer(e)][kind] = @ + 1]

(* A data packet, which carries any ACK the endpoint owes.                 *)
SendData(e) ==
    /\ dataLeft[e] > 0
    /\ toward[Peer(e)]["eliciting"] < InFlightMax
    /\ dataLeft' = [dataLeft EXCEPT ![e] = @ - 1]
    /\ owes' = [owes EXCEPT ![e] = FALSE]
    /\ ackOnly' = [ackOnly EXCEPT ![e] = 0]
    /\ toward' = Put(e, "eliciting")
    /\ UNCHANGED pinged

(* An ACK the endpoint owes, with a PING once Threshold packets of ACK     *)
(* frames alone have gone since its last ack-eliciting packet.             *)
SendAck(e) ==
    /\ owes[e]
    /\ dataLeft[e] = 0
    /\ owes' = [owes EXCEPT ![e] = FALSE]
    /\ IF ackOnly[e] >= Threshold
       THEN /\ toward[Peer(e)]["eliciting"] < InFlightMax
            /\ ackOnly' = [ackOnly EXCEPT ![e] = 0]
            /\ toward' = Put(e, "eliciting")
            /\ pinged' = TRUE
       ELSE /\ toward[Peer(e)]["ack_only"] < InFlightMax
            /\ ackOnly' = [ackOnly EXCEPT ![e] = @ + 1]
            /\ toward' = Put(e, "ack_only")
            /\ UNCHANGED pinged
    /\ UNCHANGED dataLeft

Deliver(e, kind) ==
    /\ toward[e][kind] > 0
    /\ toward' = [toward EXCEPT ![e][kind] = @ - 1]
    /\ owes' = IF kind = "eliciting" THEN [owes EXCEPT ![e] = TRUE] ELSE owes
    /\ UNCHANGED <<dataLeft, ackOnly, pinged>>

Drop(e, kind) ==
    /\ Lossy
    /\ toward[e][kind] > 0
    /\ toward' = [toward EXCEPT ![e][kind] = @ - 1]
    /\ UNCHANGED <<dataLeft, owes, ackOnly, pinged>>

Next ==
    \E e \in Endpoints :
        \/ SendData(e)
        \/ SendAck(e)
        \/ \E k \in Kinds : Deliver(e, k) \/ Drop(e, k)

Fairness ==
    \A e \in Endpoints :
        /\ WF_vars(SendData(e))
        /\ WF_vars(SendAck(e))
        /\ \A k \in Kinds : WF_vars(Deliver(e, k))

Spec == Init /\ [][Next]_vars /\ Fairness

Quiet ==
    \A e \in Endpoints :
        /\ dataLeft[e] = 0
        /\ ~owes[e]
        /\ \A k \in Kinds : toward[e][k] = 0

(* The exchange ends and stays ended.                                      *)
GoesQuiet == <>[]Quiet

(* Found violated by a configuration of its own: the PING rule runs, so    *)
(* GoesQuiet holding is not the rule never firing.                         *)
NeverPings == ~pinged
=============================================================================
