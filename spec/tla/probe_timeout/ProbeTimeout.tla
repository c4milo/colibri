---------------------------- MODULE ProbeTimeout ----------------------------
(***************************************************************************)
(* What the probes of a Probe Timeout carry (RFC 9002 §6.2.4), and whether *)
(* a sender's frames reach its peer when the network may drop every packet *)
(* that carries only ACK frames. docs/decisions.md entries 64 and 66 are   *)
(* the two policies colibri runs; "ping" is the one they replaced.         *)
(*                                                                         *)
(* One packet number space, one sender and one receiver. Each item is a    *)
(* frame that goes in a packet of its own. The receiver sends nothing but  *)
(* ACK frames, so every packet it sends is one the network may drop, which *)
(* is the loss that left colibri's client, and quinn's, waiting on a       *)
(* request the path had lost. Every ack-eliciting packet the sender keeps  *)
(* sending reaches the receiver in the end (strong fairness).              *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Items,          \* the frames the sender must deliver
    ProbePackets,   \* RFC 9002 §6.2.4: a PTO sends one or two probes
    Policy,         \* "ping", "oldest" (decision 66) or "all" (decision 64)
    FairAcks,       \* whether the network must, in the end, carry an ACK
    Ping,           \* a packet carrying a PING frame alone
    NoAck           \* no ACK on its way back

(* Ping and NoAck are model values, which TLC compares with anything.      *)

ASSUME ProbePackets \in {1, 2}
ASSUME Policy \in {"ping", "oldest", "all"}
ASSUME FairAcks \in BOOLEAN

(* An ACK frame, which acknowledges every packet the receiver holds         *)
(* (RFC 9000 §19.3): the items it has, and whether a PING arrived.          *)
AckValue == [items : SUBSET Items, ping : BOOLEAN]

VARIABLES
    flight,     \* what the sender has in flight, oldest first
    waiting,    \* items not yet sent, or declared lost and owed again
    acked,      \* items the receiver acknowledged
    toPeer,     \* packets on their way to the receiver
    got,        \* the items the receiver holds
    pingSeen,   \* whether a PING arrived since the receiver last sent an ACK
    ackOwed,    \* RFC 9000 §13.2.1: an ack-eliciting packet arrived
    toSender    \* the ACK on its way back, or NoAck. A newer one replaces it.

vars == <<flight, waiting, acked, toPeer, got, pingSeen, ackOwed, toSender>>

Range(s) == {s[i] : i \in 1..Len(s)}
Without(s, drop) == SelectSeq(s, LAMBDA e : e \notin drop)
Max(set) == CHOOSE m \in set : \A n \in set : n <= m
Min(a, b) == IF a < b THEN a ELSE b

TypeOK ==
    /\ flight \in Seq(Items \cup {Ping})
    /\ waiting \subseteq Items
    /\ acked \subseteq Items
    /\ toPeer \subseteq Items \cup {Ping}
    /\ got \subseteq Items
    /\ pingSeen \in BOOLEAN
    /\ ackOwed \in BOOLEAN
    /\ toSender \in AckValue \cup {NoAck}

(* Invariant 29 of docs/invariants.md, for this model: every item is in    *)
(* exactly one place, and nothing is in flight twice.                      *)
OnePlace ==
    /\ Len(flight) = Cardinality(Range(flight))
    /\ \A i \in Items :
        Cardinality({place \in {"flight", "waiting", "acked"} :
            \/ place = "flight" /\ i \in Range(flight)
            \/ place = "waiting" /\ i \in waiting
            \/ place = "acked" /\ i \in acked}) = 1

Init ==
    /\ flight = <<>>
    /\ waiting = Items
    /\ acked = {}
    /\ toPeer = {}
    /\ got = {}
    /\ pingSeen = FALSE
    /\ ackOwed = FALSE
    /\ toSender = NoAck

(* The send path: an item waiting goes out in a new packet.                *)
Send(i) ==
    /\ i \in waiting
    /\ waiting' = waiting \ {i}
    /\ flight' = Append(flight, i)
    /\ toPeer' = toPeer \cup {i}
    /\ UNCHANGED <<acked, got, pingSeen, ackOwed, toSender>>

(* The packets a PTO declares lost before its probes go out.               *)
Declared ==
    CASE Policy = "ping"   -> <<>>
      [] Policy = "oldest" -> SubSeq(flight, 1, Min(ProbePackets, Len(flight)))
      [] Policy = "all"    -> flight

(* RFC 9002 §6.2.4: the probes carry what the declared packets held, and a *)
(* probe with nothing to carry is a PING. Nothing counts as congestion.    *)
Probe ==
    /\ flight # <<>>
    /\ LET declared == Declared
           carried  == Without(declared, {Ping})
           kept     == Without(flight, Range(declared))
           ping     == IF Len(carried) < ProbePackets THEN <<Ping>> ELSE <<>>
       IN /\ flight' = (IF ping = <<>> THEN kept ELSE Without(kept, {Ping})) \o carried \o ping
          /\ toPeer' = toPeer \cup Range(carried) \cup Range(ping)
    /\ UNCHANGED <<waiting, acked, got, pingSeen, ackOwed, toSender>>

Deliver(p) ==
    /\ p \in toPeer
    /\ toPeer' = toPeer \ {p}
    /\ IF p = Ping
         THEN /\ pingSeen' = TRUE
              /\ UNCHANGED got
         ELSE /\ got' = got \cup {p}
              /\ UNCHANGED pingSeen
    /\ ackOwed' = TRUE
    /\ UNCHANGED <<flight, waiting, acked, toSender>>

DropToPeer(p) ==
    /\ p \in toPeer
    /\ toPeer' = toPeer \ {p}
    /\ UNCHANGED <<flight, waiting, acked, got, pingSeen, ackOwed, toSender>>

(* The receiver acknowledges in a packet of ACK frames alone.              *)
Acknowledge ==
    /\ ackOwed
    /\ toSender' = [items |-> got, ping |-> pingSeen]
    /\ ackOwed' = FALSE
    /\ pingSeen' = FALSE
    /\ UNCHANGED <<flight, waiting, acked, toPeer, got>>

Acknowledges(a, e) == IF e = Ping THEN a.ping ELSE e \in a.items

(* RFC 9002 §6.1: what was sent before the largest acknowledged packet and *)
(* is not acknowledged is lost, once the packet or time threshold passes.  *)
ReceiveAck ==
    /\ toSender # NoAck
    /\ LET a       == toSender
           hits    == {i \in 1..Len(flight) : Acknowledges(a, flight[i])}
           largest == IF hits = {} THEN 0 ELSE Max(hits)
           gone    == Range(SubSeq(flight, 1, largest))
       IN /\ acked' = acked \cup a.items
          /\ waiting' = (waiting \cup (gone \ {Ping})) \ a.items
          /\ flight' = Without(SubSeq(flight, largest + 1, Len(flight)), a.items)
    /\ toSender' = NoAck
    /\ UNCHANGED <<toPeer, got, pingSeen, ackOwed>>

DropToSender ==
    /\ toSender # NoAck
    /\ toSender' = NoAck
    /\ UNCHANGED <<flight, waiting, acked, toPeer, got, pingSeen, ackOwed>>

Next ==
    \/ \E i \in Items : Send(i)
    \/ Probe
    \/ \E p \in Items \cup {Ping} : Deliver(p) \/ DropToPeer(p)
    \/ Acknowledge
    \/ ReceiveAck
    \/ DropToSender

Fairness ==
    /\ \A i \in Items : WF_vars(Send(i))
    /\ WF_vars(Probe)
    /\ WF_vars(Acknowledge)
    /\ \A p \in Items \cup {Ping} : SF_vars(Deliver(p))
    /\ SF_vars(FairAcks /\ ReceiveAck)

Spec == Init /\ [][Next]_vars /\ Fairness

(* Every item reaches the receiver.                                        *)
Delivered == <>(Items \subseteq got)
=============================================================================
