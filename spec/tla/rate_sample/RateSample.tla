----------------------------- MODULE RateSample -----------------------------
(***************************************************************************)
(* Delivery rate samples (draft-ietf-ccwg-bbr-06 §4.1) as                  *)
(* src/quic/recovery/recovery_delivery.zig takes them, and the mark of an  *)
(* application limit as src/quic/connection/connection_recovery.zig sets  *)
(* it (design §8 step 29a). TLC checks every order of sends, writes that   *)
(* run out of data, checks, ACK frames and losses that the bounds allow.   *)
(*                                                                         *)
(* Every packet is one octet, and packet numbers are 1..Packets in send    *)
(* order (RFC 9000 §12.3). An ACK frame takes any set of packets in        *)
(* flight, so ACK frames arrive in every order. The rates are not          *)
(* modelled: spec/lean/Colibri/Quic/DeliveryRate.lean proves their        *)
(* bounds, and this model checks which packet each sample comes from and   *)
(* when the mark holds.                                                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Packets,        \* the packets the model sends, which bounds the state space
    Window,         \* the congestion window, in packets
    Mutant          \* "none", or the one rule a mutant in mutants/ breaks

ASSUME Packets \in Nat /\ Packets >= 1
ASSUME Window \in Nat /\ Window >= 1
Mutants == {"none", "oldest_sample", "mark_without_in_flight", "never_cleared"}
ASSUME Mutant \in Mutants

Numbers == 1..Packets
Max(set) == CHOOSE n \in set : \A m \in set : m <= n
Min(set) == CHOOSE n \in set : \A m \in set : n <= m

VARIABLES
    next,           \* the next packet number to send
    inFlight,       \* the packets in flight, neither acknowledged nor lost
    delivered,      \* Delivery.delivered_len
    until,          \* Delivery.application_limited_until, 0 for no mark
    ranOut,         \* Connection.ran_out_of_data
    record,         \* each sent packet's snapshot: [delivered, limited]
    bubble,         \* the packets in flight when the mark was last set, a ghost
    sinceMark,      \* the packets acknowledged since the mark was last set, a ghost
    marked,         \* whether a mark was ever set, a ghost
    sample          \* the last ACK frame's packets and the packet its sample came from

vars == <<next, inFlight, delivered, until, ranOut, record, bubble, sinceMark, marked, sample>>

NoSample == [taken |-> {}, from |-> 0]

TypeOK ==
    /\ next \in 1..(Packets + 1)
    /\ inFlight \subseteq Numbers
    /\ delivered \in 0..Packets
    /\ until \in 0..(Packets + 1)
    /\ ranOut \in BOOLEAN
    /\ record \in [Numbers -> [delivered : 0..Packets, limited : BOOLEAN]]
    /\ bubble \subseteq Numbers
    /\ sinceMark \subseteq Numbers
    /\ marked \in BOOLEAN
    /\ sample.taken \subseteq Numbers
    /\ sample.from \in 0..Packets

Init ==
    /\ next = 1
    /\ inFlight = {}
    /\ delivered = 0
    /\ until = 0
    /\ ranOut = FALSE
    /\ record = [n \in Numbers |-> [delivered |-> 0, limited |-> FALSE]]
    /\ bubble = {}
    /\ sinceMark = {}
    /\ marked = FALSE
    /\ sample = NoSample

(* §4.1.2.2's OnPacketSent: the record keeps what was delivered, and whether a mark holds. *)
Send ==
    /\ next <= Packets
    /\ Cardinality(inFlight) < Window
    /\ record' = [record EXCEPT ![next] = [delivered |-> delivered, limited |-> until # 0]]
    /\ inFlight' = inFlight \cup {next}
    /\ next' = next + 1
    /\ ranOut' = FALSE
    /\ UNCHANGED <<delivered, until, bubble, sinceMark, marked, sample>>

(* A call to `send` that planned no packet while no limit held it. *)
RunOut ==
    /\ ~ranOut
    /\ Cardinality(inFlight) < Window
    /\ ranOut' = TRUE
    /\ UNCHANGED <<next, inFlight, delivered, until, record, bubble, sinceMark, marked, sample>>

(* §4.1.2.4's CheckIfApplicationLimited, which `send`, an ACK frame and a timer each run      *)
(* first. MarkConnectionAppLimited: C.app_limited = max(C.delivered + C.inflight, 1).          *)
Check ==
    /\ ranOut
    /\ Cardinality(inFlight) < Window
    /\ until' = IF Mutant = "mark_without_in_flight"
                THEN IF delivered > 1 THEN delivered ELSE 1
                ELSE IF delivered + Cardinality(inFlight) > 1 THEN delivered + Cardinality(inFlight) ELSE 1
    /\ bubble' = inFlight
    /\ sinceMark' = {}
    /\ marked' = TRUE
    /\ UNCHANGED <<next, inFlight, delivered, ranOut, record, sample>>

(* §4.1.2.3: one ACK frame takes `taken` out of flight. UpdateRateSample keeps the newest     *)
(* packet's snapshot, and GenerateRateSample clears the mark once `delivered` passes it.       *)
Ack(taken) ==
    /\ taken # {}
    /\ LET total == delivered + Cardinality(taken)
           from == IF Mutant = "oldest_sample" THEN Min(taken) ELSE Max(taken)
       IN /\ delivered' = total
          /\ until' = IF until # 0 /\ total > until /\ Mutant # "never_cleared" THEN 0 ELSE until
          /\ sample' = [taken |-> taken, from |-> from]
    /\ inFlight' = inFlight \ taken
    /\ sinceMark' = sinceMark \cup taken
    /\ UNCHANGED <<next, ranOut, record, bubble, marked>>

(* RFC 9002 §6: a packet declared lost leaves flight and is never delivered. *)
Lose(n) ==
    /\ n \in inFlight
    /\ inFlight' = inFlight \ {n}
    /\ UNCHANGED <<next, delivered, until, ranOut, record, bubble, sinceMark, marked, sample>>

Next ==
    \/ Send
    \/ RunOut
    \/ Check
    \/ \E taken \in SUBSET inFlight : Ack(taken)
    \/ \E n \in Numbers : Lose(n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The properties.                                                         *)
(***************************************************************************)

(* §4.1.2.3: a sample comes from the newest packet the ACK frame took, whose snapshot is the   *)
(* latest of them, so its interval is the shortest that holds every packet of the frame.       *)
SampleFromNewest == sample.from # 0 =>
    /\ sample.from \in sample.taken
    /\ \A n \in sample.taken : n <= sample.from /\ record[n].delivered <= record[sample.from].delivered

(* §4.1.1.3: the mark clears only once more packets were delivered since it than were in      *)
(* flight at it, which is when the bubble has left the path.                                   *)
HeldWhileBubbleOwed == (marked /\ until = 0) => Cardinality(sinceMark) > Cardinality(bubble)

(* §4.1.2.3: the mark clears once the bubble and one more packet are delivered, or two more    *)
(* on a path that held nothing, since a mark is never 0.                                        *)
ClearedOnceDelivered ==
    (marked /\ bubble \subseteq sinceMark /\ Cardinality(sinceMark) > Cardinality(bubble) + (IF bubble = {} THEN 1 ELSE 0))
        => until = 0

Properties ==
    /\ SampleFromNewest
    /\ HeldWhileBubbleOwed
    /\ ClearedOnceDelivered
=============================================================================
