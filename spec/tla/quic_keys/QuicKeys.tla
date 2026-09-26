------------------------------ MODULE QuicKeys ------------------------------
(***************************************************************************)
(* A QUIC handshake's encryption levels, and when each endpoint installs   *)
(* and discards each level's keys (RFC 9001 §4.1, §4.9), as colibri keeps  *)
(* them (src/quic/connection/connection_keys.zig, connection_recovery.zig  *)
(* and src/quic/recovery/recovery_timer.zig). A client and a server        *)
(* exchange the handshake's CRYPTO messages over a network that may lose   *)
(* any packet and deliver them in any order:                               *)
(*   - ClientHello at Initial, which gives the server the Handshake keys   *)
(*     and the 1-RTT write keys;                                           *)
(*   - ServerHello at Initial, which gives the client the Handshake keys;  *)
(*   - the server's flight to Finished at Handshake, which gives the       *)
(*     client the 1-RTT keys and completes its handshake;                  *)
(*   - the client's Finished at Handshake, which completes and confirms    *)
(*     the server's handshake (§4.1.2);                                    *)
(*   - HANDSHAKE_DONE at 1-RTT, which confirms the client's.               *)
(*                                                                         *)
(* colibri's rules, as this model has them:                                *)
(*   - a client discards its Initial keys when it first sends a Handshake  *)
(*     packet, and a server when it first processes one (§4.9.1); each     *)
(*     discards its Handshake keys when its handshake is confirmed         *)
(*     (§4.9.2);                                                           *)
(*   - a packet is sealed or opened only at a level whose keys are         *)
(*     available, and a 1-RTT packet is opened only once the handshake is  *)
(*     complete (RFC 9001 §5.7, invariant 21);                             *)
(*   - a server sends at most three packets for each it receives until a   *)
(*     Handshake packet validates the client's address (RFC 9000 §8.1),    *)
(*     and sets no timer while it may send nothing (RFC 9002 Appendix      *)
(*     A.8);                                                               *)
(*   - a PTO declares the CRYPTO data in flight at a level lost, so the    *)
(*     probe carries it (decision 64), or sends a PING when there is none; *)
(*   - a client whose address the server has not validated probes even     *)
(*     with nothing in flight, in a Handshake packet once it has the keys  *)
(*     and a padded Initial before (RFC 9002 §6.2.2.1);                    *)
(*   - a server that receives an ack-eliciting Initial with nothing new    *)
(*     sends its Initial CRYPTO data again at once, twice at most          *)
(*     (decision 65).                                                      *)
(* Time is left out: a timer that is set may fire at any moment. Only the  *)
(* server's ACK frames are modeled, because nothing the server waits for   *)
(* depends on the client's. With CreditMax 1 the server's flight takes the *)
(* whole allowance a client datagram grants, as a long certificate chain   *)
(* does, and configuration tight_credit shows the anti-deadlock probe      *)
(* carrying the handshake through. Three configurations each break one     *)
(* rule, and the handshake then stalls: no_anti_deadlock,                  *)
(* discard_on_complete and server_discard_on_send.                         *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    LossMax,                \* packets the network may lose in one behavior
    CreditMax,              \* the most datagrams the server's credit covers; 1 when its flight
                            \* takes the whole allowance a client datagram grants
    AntiDeadlock,           \* whether the client probes with nothing in flight (§6.2.2.1)
    DiscardOnComplete,      \* whether the client discards Handshake keys on completion instead
    ServerDiscardOnSend     \* whether the server discards Initial keys on its first Handshake send

ASSUME /\ {LossMax, CreditMax} \subseteq Nat /\ CreditMax >= 1
       /\ {AntiDeadlock, DiscardOnComplete, ServerDiscardOnSend} \subseteq BOOLEAN

C == "client"
S == "server"
Endpoints == {C, S}
Peer(e) == IF e = C THEN S ELSE C
Levels == {"initial", "handshake", "application"}
Directions == {"read", "write"}
(* An ACK acknowledges the CRYPTO data at its level once its sender has    *)
(* that data, which Heard says, and a PING always.                         *)
Kinds == {"crypto", "ping", "ack"}
Packet(from, level, kind) == [from |-> from, level |-> level, kind |-> kind]
Packets == {Packet(e, l, k) : e \in Endpoints, l \in Levels, k \in Kinds}
Min(a, b) == IF a < b THEN a ELSE b

(* The CRYPTO data (or HANDSHAKE_DONE) each endpoint sends at each level:  *)
(* "none" when there is none or it was acknowledged, "owed" when it is to  *)
(* be sent, "flight" when it is on its way unacknowledged.                 *)
DataStates == {"none", "owed", "flight"}

VARIABLES
    keys,           \* keys[e][l][d]: "none", "available" or "discarded" (invariant 21)
    data,           \* data[e][l]: the CRYPTO data e owes at l
    pinged,         \* pinged[e][l]: a PING e sent at l is unacknowledged
    ackOwed,        \* ackOwed[e][l]: e received an ack-eliciting packet at l
    complete,       \* complete[e]: the handshake is complete (§4.1.1)
    confirmed,      \* confirmed[e]: the handshake is confirmed (§4.1.2)
    validated,      \* the server has validated the client's address (RFC 9000 §8.1)
    peerValidated,  \* the client knows the server completed address validation (RFC 9002 A.8)
    credit,         \* packets the server may still send before validation
    resends,        \* early Initial resends the server made (decision 65)
    net,            \* packets on their way
    losses

vars == <<keys, data, pinged, ackOwed, complete, confirmed, validated, peerValidated,
          credit, resends, net, losses>>

KeyStates == {"none", "available", "discarded"}

TypeOK ==
    /\ keys \in [Endpoints -> [Levels -> [Directions -> KeyStates]]]
    /\ data \in [Endpoints -> [Levels -> DataStates]]
    /\ pinged \in [Endpoints -> [Levels -> BOOLEAN]]
    /\ ackOwed \in [Endpoints -> [Levels -> BOOLEAN]]
    /\ complete \in [Endpoints -> BOOLEAN] /\ confirmed \in [Endpoints -> BOOLEAN]
    /\ validated \in BOOLEAN /\ peerValidated \in BOOLEAN
    /\ credit \in 0..CreditMax /\ resends \in 0..2
    /\ net \subseteq Packets /\ losses \in 0..LossMax

(* Both endpoints begin with the Initial keys, which RFC 9001 §5.2 derives *)
(* from the client's first Destination Connection ID, and the client owes  *)
(* its ClientHello.                                                        *)
Init ==
    /\ keys = [e \in Endpoints |-> [l \in Levels |-> [d \in Directions |->
                  IF l = "initial" THEN "available" ELSE "none"]]]
    /\ data = [e \in Endpoints |-> [l \in Levels |->
                  IF e = C /\ l = "initial" THEN "owed" ELSE "none"]]
    /\ pinged = [e \in Endpoints |-> [l \in Levels |-> FALSE]]
    /\ ackOwed = [e \in Endpoints |-> [l \in Levels |-> FALSE]]
    /\ complete = [e \in Endpoints |-> FALSE] /\ confirmed = [e \in Endpoints |-> FALSE]
    /\ validated = FALSE /\ peerValidated = FALSE
    /\ credit = 0 /\ resends = 0
    /\ net = {} /\ losses = 0

Available(k, e, l, d) == k[e][l][d] = "available"
(* The client has the ServerHello once it holds the Handshake keys, which  *)
(* the ServerHello gives it.                                               *)
GotHello == keys[C]["handshake"]["read"] # "none"
(* Whether e has received the peer's CRYPTO data at l, which each step of  *)
(* the handshake shows: the server's Handshake keys come from the          *)
(* ClientHello, the client's completion from the server's flight, and each *)
(* confirmation from the Finished or HANDSHAKE_DONE.                       *)
Heard(e, l) ==
    CASE e = S /\ l = "initial" -> keys[S]["handshake"]["write"] # "none"
      [] e = C /\ l = "initial" -> GotHello
      [] e = C /\ l = "handshake" -> complete[C]
      [] e = S /\ l = "handshake" -> confirmed[S]
      [] e = C /\ l = "application" -> confirmed[C]
      [] OTHER -> FALSE
CanSeal(e, l) == Available(keys, e, l, "write")
(* RFC 9001 §5.7: no 1-RTT packet is opened before the handshake           *)
(* completes.                                                              *)
CanOpen(e, l) == Available(keys, e, l, "read") /\ (l = "application" => complete[e])

Install(k, e, l, ds) ==
    [k EXCEPT ![e][l] = [d \in Directions |->
                             IF d \in ds /\ @[d] = "none" THEN "available" ELSE @[d]]]
Discard(k, e, l) == [k EXCEPT ![e][l] = [d \in Directions |-> "discarded"]]

(* RFC 9000 §8.1: what the server may send before it has validated the     *)
(* client's address.                                                       *)
MaySend(e) == e = C \/ validated \/ credit > 0
Spend(e) == IF e = S /\ ~validated THEN credit - 1 ELSE credit

---------------------------------------------------------------------------
(* Sending.                                                                *)

(* The client's first Handshake packet discards its Initial keys (§4.9.1), *)
(* and, with ServerDiscardOnSend, the server's does too.                   *)
AfterSend(k, e, l) ==
    IF l = "handshake" /\ (e = C \/ ServerDiscardOnSend) /\ k[e]["initial"]["write"] # "discarded"
    THEN Discard(k, e, "initial") ELSE k

(* What e would put in a datagram now: the CRYPTO data and the ACK frames  *)
(* it owes at each level it can seal.                                      *)
DataDue(e, l) == data[e][l] = "owed" /\ CanSeal(e, l)
(* Only the server's ACK frames are modeled. Nothing the server waits for  *)
(* depends on the client's: it discards its Initial and Handshake keys on  *)
(* §4.9's triggers, and a server left unacknowledged only probes again.    *)
AckDue(e, l) == e = S /\ ackOwed[e][l] /\ CanSeal(e, l)
Due(e) == \E l \in Levels : DataDue(e, l) \/ AckDue(e, l)
Carried(e) == {Packet(e, l, "crypto") : l \in {x \in Levels : DataDue(e, x)}}
              \cup {Packet(e, l, "ack") : l \in {x \in Levels : AckDue(e, x)}}
SendsHandshake(e) == DataDue(e, "handshake") \/ AckDue(e, "handshake")

(* connection_send.send: one datagram carrying everything owed at every    *)
(* level, coalesced in order of level (RFC 9000 §12.2). With               *)
(* DiscardOnComplete, the client discards its Handshake keys once it has   *)
(* sent its Finished, which completes its handshake, instead of when the   *)
(* handshake is confirmed.                                                 *)
Flush(e) ==
    /\ Due(e) /\ MaySend(e)
    /\ net' = net \cup Carried(e)
    /\ data' = [data EXCEPT ![e] = [l \in Levels |-> IF DataDue(e, l) THEN "flight" ELSE @[l]]]
    /\ ackOwed' = [ackOwed EXCEPT ![e] = [l \in Levels |-> IF AckDue(e, l) THEN FALSE ELSE @[l]]]
    /\ credit' = Spend(e)
    /\ LET k1 == IF SendsHandshake(e) THEN AfterSend(keys, e, "handshake") ELSE keys
       IN keys' = IF DiscardOnComplete /\ e = C /\ DataDue(C, "handshake") /\ complete[C]
                  THEN Discard(k1, C, "handshake") ELSE k1
    /\ UNCHANGED <<pinged, complete, confirmed, validated, peerValidated, resends,
                   losses>>

(* An ack-eliciting packet waits for acknowledgment at l.                  *)
InFlight(e, l) == data[e][l] = "flight" \/ pinged[e][l]
AnyInFlight(e) == \E l \in Levels : InFlight(e, l)

(* RFC 9002 Appendix A.8: the PTO is set while something is in flight, not *)
(* for 1-RTT before the handshake is confirmed, and not by a server that   *)
(* may send nothing. A PTO at a level with CRYPTO data in flight declares  *)
(* it lost, and the probe carries it (decision 64); otherwise the probe is *)
(* a PING.                                                                 *)
Probe(e, l) ==
    /\ InFlight(e, l) /\ CanSeal(e, l) /\ MaySend(e)
    /\ l = "application" => confirmed[e]
    /\ net' = net \cup {Packet(e, l, IF data[e][l] = "flight" THEN "crypto" ELSE "ping")}
    /\ credit' = Spend(e)
    /\ keys' = AfterSend(keys, e, l)
    /\ UNCHANGED <<data, pinged>>
    /\ UNCHANGED <<ackOwed, complete, confirmed, validated, peerValidated, resends,
                   losses>>

(* RFC 9002 §6.2.2.1: a client whose address the server has not validated  *)
(* probes with nothing in flight, at Handshake once it has the keys.       *)
AntiDeadlockProbe ==
    LET l == IF CanSeal(C, "handshake") THEN "handshake" ELSE "initial" IN
    /\ AntiDeadlock /\ ~peerValidated /\ ~AnyInFlight(C) /\ ~confirmed[C] /\ CanSeal(C, l)
    \* The timer counts from the client's last send, and it has something
    \* to send before it has anything to probe for.
    /\ ~Due(C) /\ data[C]["initial"] # "owed"
    /\ net' = net \cup {Packet(C, l, "ping")}
    /\ pinged' = [pinged EXCEPT ![C][l] = TRUE]
    /\ keys' = AfterSend(keys, C, l)
    /\ UNCHANGED <<data, ackOwed, complete, confirmed, validated, peerValidated,
                   credit, resends, losses>>

---------------------------------------------------------------------------
(* Receiving.                                                              *)

(* What the CRYPTO data at `l` from the peer does at `e` (RFC 9001 §4.1).  *)
TakeCrypto(e, l, k0, d0) ==
    CASE e = S /\ l = "initial" ->
            IF k0[S]["handshake"]["write"] = "none"
            \* The ClientHello: the Handshake keys, the 1-RTT write keys, and the
            \* ServerHello and the flight to Finished owed.
            THEN [keys |-> Install(Install(k0, S, "handshake", Directions), S, "application",
                                   {"write"}),
                  data |-> [d0 EXCEPT ![S]["initial"] = "owed", ![S]["handshake"] = "owed"],
                  resend |-> FALSE]
            \* A repeat: decision 65's early resend of the ServerHello.
            ELSE [keys |-> k0,
                  data |-> IF d0[S]["initial"] = "flight" /\ resends < 2
                           THEN [d0 EXCEPT ![S]["initial"] = "owed"] ELSE d0,
                  resend |-> d0[S]["initial"] = "flight" /\ resends < 2]
      [] e = C /\ l = "initial" ->
            [keys |-> Install(k0, C, "handshake", Directions), data |-> d0, resend |-> FALSE]
      [] e = C /\ l = "handshake" /\ GotHello ->
            \* The server's flight to Finished: the 1-RTT keys, and the Finished owed.
            [keys |-> Install(k0, C, "application", Directions),
             data |-> IF complete[C] THEN d0 ELSE [d0 EXCEPT ![C]["handshake"] = "owed"],
             resend |-> FALSE]
      [] e = S /\ l = "handshake" ->
            \* The client's Finished: the 1-RTT read keys, and HANDSHAKE_DONE owed.
            [keys |-> Install(k0, S, "application", {"read"}),
             data |-> IF confirmed[S] THEN d0 ELSE [d0 EXCEPT ![S]["application"] = "owed"],
             resend |-> FALSE]
      [] OTHER -> [keys |-> k0, data |-> d0, resend |-> FALSE]

(* A packet from e's peer arrives at e. A server counts every datagram     *)
(* toward its credit (RFC 9000 §8.1), whether or not it opens.             *)
Receive(e, p) ==
    /\ p \in net /\ p.from = Peer(e)
    /\ net' = net \ {p}
    /\ LET l == p.level
           counted == IF e = S /\ ~validated THEN Min(credit + 3, CreditMax) ELSE credit
       IN IF ~CanOpen(e, l)
          THEN /\ credit' = counted
               /\ UNCHANGED <<keys, data, pinged, ackOwed, complete, confirmed,
                              validated, peerValidated, resends, losses>>
          ELSE LET taken == IF p.kind = "crypto"
                            THEN TakeCrypto(e, l, keys, data)
                            ELSE IF p.kind = "ping" /\ e = S /\ l = "initial"
                                         /\ keys[S]["handshake"]["write"] # "none"
                                 THEN TakeCrypto(e, l, keys, data)
                                 ELSE [keys |-> keys, data |-> data, resend |-> FALSE]
                   acked == p.kind = "ack"
                   finished == p.kind = "crypto" /\ e = C /\ l = "handshake" /\ GotHello
                   serverDone == p.kind = "crypto" /\ e = S /\ l = "handshake"
                   clientDone == p.kind = "crypto" /\ e = C /\ l = "application"
                   \* §4.9.1: a server discards its Initial keys on the first Handshake
                   \* packet it processes, which also validates the client's address.
                   k1 == IF e = S /\ l = "handshake" /\ keys[S]["initial"]["read"] # "discarded"
                         THEN Discard(taken.keys, S, "initial") ELSE taken.keys
                   \* §4.9.2: each endpoint discards its Handshake keys once confirmed.
                   k2 == IF (serverDone \/ clientDone) /\ k1[e]["handshake"]["read"] # "discarded"
                         THEN Discard(k1, e, "handshake") ELSE k1
               IN /\ keys' = k2
                  /\ data' = IF acked /\ Heard(Peer(e), l) /\ taken.data[e][l] # "none"
                             THEN [taken.data EXCEPT ![e][l] = "none"] ELSE taken.data
                  /\ pinged' = IF acked THEN [pinged EXCEPT ![e][l] = FALSE] ELSE pinged
                  /\ ackOwed' = IF ~acked /\ e = S THEN [ackOwed EXCEPT ![e][l] = TRUE] ELSE ackOwed
                  /\ complete' = [complete EXCEPT ![e] = @ \/ finished \/ serverDone]
                  /\ confirmed' = [confirmed EXCEPT ![e] = @ \/ serverDone \/ clientDone]
                  /\ validated' = (validated \/ (e = S /\ l = "handshake"))
                  /\ peerValidated' = (peerValidated \/ (e = C /\ acked /\ l = "handshake")
                                                     \/ clientDone)
                  /\ credit' = counted
                  /\ resends' = IF taken.resend THEN resends + 1 ELSE resends
                  /\ UNCHANGED losses

Lose(p) ==
    /\ p \in net /\ losses < LossMax
    /\ net' = net \ {p}
    /\ losses' = losses + 1
    /\ UNCHANGED <<keys, data, pinged, ackOwed, complete, confirmed, validated,
                   peerValidated, credit, resends>>

---------------------------------------------------------------------------

Next ==
    \/ \E e \in Endpoints : Flush(e) \/ \E l \in Levels : Probe(e, l)
    \/ AntiDeadlockProbe
    \/ \E e \in Endpoints, p \in Packets : Receive(e, p)
    \/ \E p \in Packets : Lose(p)

(* RFC 9002 Appendix A.8 fires the PTO for the space whose deadline comes  *)
(* first, so a space that keeps something in flight is probed in the end,  *)
(* however often another is; and what is owed goes out once the server has *)
(* credit, however often it runs out. Both are strong fairness here, since *)
(* the server's credit switches them on and off.                           *)
Fairness ==
    /\ \A e \in Endpoints : SF_vars(Flush(e)) /\ \A l \in Levels : SF_vars(Probe(e, l))
    /\ WF_vars(AntiDeadlockProbe)
    /\ \A e \in Endpoints, p \in Packets : WF_vars(Receive(e, p))

Spec == Init /\ [][Next]_vars /\ Fairness

---------------------------------------------------------------------------
(* Properties.                                                             *)

Rank(s) == IF s = "none" THEN 0 ELSE IF s = "available" THEN 1 ELSE 2

(* Invariant 21 and RFC 9001 §4.9: a level's keys go from none to          *)
(* available to discarded, never back.                                     *)
KeysMoveForward ==
    [][\A e \in Endpoints, l \in Levels, d \in Directions :
         Rank(keys'[e][l][d]) >= Rank(keys[e][l][d])]_vars

(* RFC 9001 §4.9.1: a client discards its Initial keys only once it holds  *)
(* the Handshake keys, and so does a server.                               *)
InitialAfterHandshake ==
    \A e \in Endpoints :
        keys[e]["initial"]["write"] = "discarded" => keys[e]["handshake"]["write"] # "none"

(* Both handshakes are confirmed in the end.                               *)
BothConfirmed == <>(confirmed[C] /\ confirmed[S])
=============================================================================
