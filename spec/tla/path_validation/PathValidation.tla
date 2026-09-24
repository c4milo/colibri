--------------------------- MODULE PathValidation ---------------------------
(***************************************************************************)
(* A server following its client to a new address after a NAT rebinding   *)
(* (RFC 9000 §9.3, docs/decisions.md entry 72). The rebinding has just     *)
(* happened: the client sends from its new address, and the server has    *)
(* not yet seen it.                                                        *)
(*                                                                         *)
(* The server moves on the first packet from the new address that is not *)
(* probing, then challenges the new path within §8's allowance: three     *)
(* octets out for each one in, counted here in packets. It sends another  *)
(* challenge each PTO while it has attempts and allowance left (§13.3),   *)
(* and gives up when its §8.2.4 timer runs out, which on this path closes *)
(* the connection: the old binding answers nothing (§9.3.2).              *)
(*                                                                         *)
(* The client sends within a congestion window. A PATH_RESPONSE counts in *)
(* it, and a PTO probe does not (RFC 9002 §7.5). Timers fire only once    *)
(* nothing is in flight and neither side has anything to do at once, and *)
(* in any order, so the server may give up before the client's probe     *)
(* goes. The network loses at most MaxLosses packets, and only once the  *)
(* server has seen the new address: before that, a client that only      *)
(* acknowledges has nothing to send again, and no server could find it.  *)
(* Keeping a connection alive is the application's (RFC 9000 §10.1.2).   *)
(*                                                                         *)
(* Every challenge repeats the server's latest ACK once it has something  *)
(* to acknowledge. Four constants are the defects colibri had or would    *)
(* have: WithholdAcks, NoAckRepeat (an ACK only when newly owed), one     *)
(* attempt, and FillWithData, a challenge's packet filled with stream     *)
(* data up to the allowance.                                              *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Attempts,           \* path_challenge_attempts
    WithholdAcks,       \* the server sends no ACK on the path until validated
    NoAckRepeat,        \* a challenge carries an ACK only when one is newly owed
    FillWithData,       \* a challenge's packet takes every octet §8 allows
    Window,             \* the client's congestion window, in packets
    ClientData,         \* packets the client uploads from the new address
    InitialAck,         \* the client's first packet there is an ACK alone
    MaxLosses           \* packets the network may lose

ASSUME Attempts \in Nat \ {0}
ASSUME WithholdAcks \in BOOLEAN /\ NoAckRepeat \in BOOLEAN
ASSUME FillWithData \in BOOLEAN /\ InitialAck \in BOOLEAN
ASSUME Window \in Nat \ {0} /\ ClientData \in Nat /\ MaxLosses \in Nat

(* RFC 9000 §8: three times what arrived. Counted in packets of one size.  *)
Amplification == 3
AllowanceMax == 12
InFlightMax == Window + Attempts + 2

ToServerKinds == {"data", "ack", "response"}
ToClientKinds == {"challenge", "challenge_ack", "ack"}

VARIABLES
    moved, validated, failed, allowance, attempts, serverAckOwed, ackable,
    toSend, inflight, responseOwed, clientAckOwed,
    toServer, toClient, lossesLeft

vars == <<moved, validated, failed, allowance, attempts, serverAckOwed, ackable,
          toSend, inflight, responseOwed, clientAckOwed,
          toServer, toClient, lossesLeft>>

server == <<moved, validated, failed, allowance, attempts, serverAckOwed, ackable>>
client == <<toSend, inflight, responseOwed, clientAckOwed>>

TypeOK ==
    /\ moved \in BOOLEAN /\ validated \in BOOLEAN /\ failed \in BOOLEAN
    /\ allowance \in 0..AllowanceMax
    /\ attempts \in 0..Attempts
    /\ serverAckOwed \in BOOLEAN /\ ackable \in BOOLEAN
    /\ toSend \in 0..ClientData
    /\ inflight \in 0..(Window + 1)
    /\ responseOwed \in BOOLEAN /\ clientAckOwed \in BOOLEAN
    /\ toServer \in [ToServerKinds -> 0..InFlightMax]
    /\ toClient \in [ToClientKinds -> 0..InFlightMax]
    /\ lossesLeft \in 0..MaxLosses

Init ==
    /\ moved = FALSE /\ validated = FALSE /\ failed = FALSE
    /\ allowance = 0 /\ attempts = 0 /\ serverAckOwed = FALSE /\ ackable = FALSE
    /\ toSend = ClientData /\ inflight = 0
    /\ responseOwed = FALSE /\ clientAckOwed = InitialAck
    /\ toServer = [k \in ToServerKinds |-> 0]
    /\ toClient = [k \in ToClientKinds |-> 0]
    /\ lossesLeft = MaxLosses

Quiet ==
    /\ \A k \in ToServerKinds : toServer[k] = 0
    /\ \A k \in ToClientKinds : toClient[k] = 0

Min(a, b) == IF a < b THEN a ELSE b
ToServer(k) == toServer' = [toServer EXCEPT ![k] = @ + 1]
ToClient(k) == toClient' = [toClient EXCEPT ![k] = @ + 1]

(* The client ------------------------------------------------------------ *)

ClientSend ==
    /\ toSend > 0 /\ inflight < Window /\ toServer["data"] < InFlightMax
    /\ toSend' = toSend - 1 /\ inflight' = inflight + 1
    /\ ToServer("data")
    /\ UNCHANGED <<server, responseOwed, clientAckOwed, toClient, lossesLeft>>

(* A packet of ACK frames alone, which no window holds back (RFC 9002 §7). *)
ClientAck ==
    /\ clientAckOwed /\ toServer["ack"] < InFlightMax
    /\ clientAckOwed' = FALSE
    /\ ToServer("ack")
    /\ UNCHANGED <<server, toSend, inflight, responseOwed, toClient, lossesLeft>>

(* RFC 9000 §8.2.2: a PATH_RESPONSE, in flight like any ack-eliciting      *)
(* packet, so the window holds it back.                                    *)
ClientRespond ==
    /\ responseOwed /\ inflight < Window /\ toServer["response"] < InFlightMax
    /\ responseOwed' = FALSE /\ inflight' = inflight + 1
    /\ ToServer("response")
    /\ UNCHANGED <<server, toSend, clientAckOwed, toClient, lossesLeft>>

ClientReceive(k) ==
    /\ toClient[k] > 0
    /\ toClient' = [toClient EXCEPT ![k] = @ - 1]
    /\ responseOwed' = (responseOwed \/ k \in {"challenge", "challenge_ack"})
    /\ inflight' = IF k \in {"challenge_ack", "ack"} THEN 0 ELSE inflight
    /\ UNCHANGED <<server, toSend, clientAckOwed, toServer, lossesLeft>>

(* The server ------------------------------------------------------------ *)

(* A packet from the new address. One that is not probing moves the path  *)
(* (§9.3); a PATH_RESPONSE alone is probing (§9.1) and validates it.       *)
ServerReceive(k) ==
    /\ toServer[k] > 0
    /\ toServer' = [toServer EXCEPT ![k] = @ - 1]
    /\ allowance' = Min(AllowanceMax, allowance + Amplification)
    /\ moved' = (moved \/ k \in {"data", "ack"})
    /\ serverAckOwed' = (serverAckOwed \/ k \in {"data", "response"})
    /\ ackable' = (ackable \/ k \in {"data", "response"})
    /\ validated' = (validated \/ (k = "response" /\ moved /\ attempts > 0))
    /\ UNCHANGED <<failed, attempts, client, toClient, lossesLeft>>

CanChallenge ==
    /\ moved /\ ~validated /\ ~failed /\ allowance >= 1
    /\ toClient["challenge"] + toClient["challenge_ack"] < InFlightMax

(* A PATH_CHALLENGE, with the latest ACK once there is anything to        *)
(* acknowledge, in a packet that costs one packet of allowance, or all of *)
(* it.                                                                     *)
CarriesAck == ~WithholdAcks /\ IF NoAckRepeat THEN serverAckOwed ELSE ackable

SendChallenge ==
    /\ attempts' = attempts + 1
    /\ allowance' = IF FillWithData THEN 0 ELSE allowance - 1
    /\ IF CarriesAck
       THEN /\ serverAckOwed' = FALSE /\ ToClient("challenge_ack")
       ELSE /\ UNCHANGED serverAckOwed /\ ToClient("challenge")
    /\ UNCHANGED <<moved, validated, failed, ackable, client, toServer, lossesLeft>>

ServerChallenge == CanChallenge /\ attempts = 0 /\ SendChallenge

ServerAck ==
    /\ moved /\ serverAckOwed /\ ~failed /\ toClient["ack"] < InFlightMax
    /\ validated \/ (~WithholdAcks /\ allowance >= 1)
    /\ serverAckOwed' = FALSE
    /\ allowance' = IF validated THEN allowance ELSE allowance - 1
    /\ ToClient("ack")
    /\ UNCHANGED <<moved, validated, failed, attempts, ackable, client, toServer, lossesLeft>>

(* What a side does at once, without waiting on a timer.                  *)
Immediate == ClientSend \/ ClientAck \/ ClientRespond \/ ServerChallenge \/ ServerAck

(* A timer fires only once nothing is in flight and neither side has       *)
(* anything to do at once: every timeout here is longer than a round trip  *)
(* and longer than the time an endpoint takes to answer a packet.          *)
Idle == Quiet /\ ~ENABLED Immediate

(* The timers ------------------------------------------------------------ *)

(* RFC 9002 §6.2.4: a PTO probe, which §7.5 lets past the window. It       *)
(* carries the PATH_RESPONSE when one is owed, and data sent again if not. *)
ClientProbe ==
    /\ Idle /\ inflight > 0
    /\ IF responseOwed
       THEN /\ responseOwed' = FALSE /\ ToServer("response")
       ELSE /\ UNCHANGED responseOwed /\ ToServer("data")
    /\ UNCHANGED <<server, toSend, inflight, clientAckOwed, toClient, lossesLeft>>

(* RFC 9000 §13.3: the next challenge, a PTO after the last went unanswered. *)
ServerResend == Idle /\ CanChallenge /\ 0 < attempts /\ attempts < Attempts /\ SendChallenge

(* RFC 9000 §8.2.4 and §9.3.2: the server can send no more challenges and *)
(* its timer runs out, which closes the connection.                        *)
Abandon ==
    /\ Idle /\ moved /\ ~validated /\ ~failed /\ attempts > 0
    /\ attempts = Attempts \/ allowance = 0
    /\ failed' = TRUE
    /\ UNCHANGED <<moved, validated, allowance, attempts, serverAckOwed, ackable, client, toServer, toClient, lossesLeft>>

(* The network ----------------------------------------------------------- *)

LoseToServer(k) ==
    /\ moved /\ lossesLeft > 0 /\ toServer[k] > 0
    /\ toServer' = [toServer EXCEPT ![k] = @ - 1] /\ lossesLeft' = lossesLeft - 1
    /\ UNCHANGED <<server, client, toClient>>

LoseToClient(k) ==
    /\ moved /\ lossesLeft > 0 /\ toClient[k] > 0
    /\ toClient' = [toClient EXCEPT ![k] = @ - 1] /\ lossesLeft' = lossesLeft - 1
    /\ UNCHANGED <<server, client, toServer>>

Next ==
    \/ ClientSend \/ ClientAck \/ ClientRespond \/ ClientProbe
    \/ \E k \in ToClientKinds : ClientReceive(k) \/ LoseToClient(k)
    \/ \E k \in ToServerKinds : ServerReceive(k) \/ LoseToServer(k)
    \/ ServerChallenge \/ ServerResend \/ ServerAck \/ Abandon

Fairness ==
    /\ WF_vars(ClientSend) /\ WF_vars(ClientAck) /\ WF_vars(ClientRespond)
    /\ WF_vars(ClientProbe)
    /\ \A k \in ToClientKinds : WF_vars(ClientReceive(k))
    /\ \A k \in ToServerKinds : WF_vars(ServerReceive(k))
    /\ WF_vars(ServerChallenge) /\ WF_vars(ServerResend) /\ WF_vars(ServerAck)

Spec == Init /\ [][Next]_vars /\ Fairness

(* The server never closes a connection whose client it can still reach.  *)
NeverFails == ~failed

(* The server validates the client's new address in the end.              *)
Validates == <>validated
=============================================================================
