----------------------------- MODULE SpuriousLoss -----------------------------
(***************************************************************************)
(* The spurious loss episodes of draft-ietf-ccwg-bbr-06 §5.5.11, as        *)
(* src/quic/recovery/recovery_spurious.zig finds them (design §8 step      *)
(* 29b.3). TLC checks every order of sends, deliveries, declared losses,   *)
(* acknowledgments and new episodes.                                       *)
(*                                                                         *)
(* A packet the path delivers may still be declared lost, as reordering    *)
(* makes RFC 9002 §6.1 do. The model keeps, apart from the code, every     *)
(* packet each episode declared lost, and the properties compare the       *)
(* detector's answer with it.                                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Packets,        \* the packet numbers the model sends
    ListMax,        \* spurious_loss_numbers_max
    Mutant          \* "none", or the one rule a mutant in mutants/ breaks

ASSUME Packets \subseteq Nat /\ ListMax \in Nat /\ ListMax >= 1
Mutants == {"none", "one_ack_enough", "overflow_ignored", "fires_twice", "no_reset"}
ASSUME Mutant \in Mutants
Kinds == {"none", "send", "deliver", "lose", "ack", "episode"}

VARIABLES
    sent,           \* packets sent
    delivered,      \* packets the path delivered
    acked,          \* packets the peer acknowledged
    declared,       \* packets RFC 9002 declared lost, in any episode
    list,           \* Spurious.numbers[0..count]
    marked,         \* the numbers of `list` acknowledged since
    overflowed,     \* Spurious.overflowed: a loss the list cannot hold, or the episode found
    episodeLost,    \* every packet this episode declared lost, counted apart from the code
    fired,          \* whether the detector answered true in this episode
    last            \* the last event, which the properties read

vars == <<sent, delivered, acked, declared, list, marked, overflowed, episodeLost, fired, last>>

TypeOK ==
    /\ sent \subseteq Packets /\ delivered \subseteq sent /\ acked \subseteq delivered
    /\ declared \subseteq sent
    /\ list \subseteq Packets /\ Cardinality(list) <= ListMax
    /\ marked \subseteq list
    /\ overflowed \in BOOLEAN /\ fired \in BOOLEAN
    /\ episodeLost \subseteq declared
    /\ last.kind \in Kinds

Init ==
    /\ sent = {} /\ delivered = {} /\ acked = {} /\ declared = {}
    /\ list = {} /\ marked = {} /\ overflowed = FALSE
    /\ episodeLost = {} /\ fired = FALSE
    /\ last = [kind |-> "none", answer |-> FALSE, firedBefore |-> FALSE]

Note(kind, answer) == [kind |-> kind, answer |-> answer, firedBefore |-> fired]

Send(p) ==
    /\ p \notin sent
    /\ sent' = sent \cup {p}
    /\ last' = Note("send", FALSE)
    /\ UNCHANGED <<delivered, acked, declared, list, marked, overflowed, episodeLost, fired>>

Deliver(p) ==
    /\ p \in sent \ delivered
    /\ delivered' = delivered \cup {p}
    /\ last' = Note("deliver", FALSE)
    /\ UNCHANGED <<sent, acked, declared, list, marked, overflowed, episodeLost, fired>>

(* RFC 9002 §6.1 declares a sent packet lost, which it has not seen acknowledged. *)
Lose(p) ==
    /\ p \in sent \ (declared \cup acked)
    /\ declared' = declared \cup {p}
    /\ episodeLost' = episodeLost \cup {p}
    /\ IF Cardinality(list) < ListMax
       THEN /\ list' = list \cup {p} /\ UNCHANGED overflowed
       ELSE /\ overflowed' = TRUE /\ UNCHANGED list
    /\ last' = Note("lose", FALSE)
    /\ UNCHANGED <<sent, delivered, acked, marked, fired>>

(* The peer acknowledges a delivered packet: Spurious.on_acknowledged. *)
Ack(p) ==
    /\ p \in delivered \ acked
    /\ acked' = acked \cup {p}
    /\ LET newMarked == IF p \in list THEN marked \cup {p} ELSE marked
           complete == IF Mutant = "one_ack_enough" THEN newMarked # {} ELSE newMarked = list
           counts == list # {} /\ (~overflowed \/ Mutant = "overflow_ignored")
           answer == counts /\ complete
       IN /\ last' = Note("ack", answer)
          /\ IF answer /\ Mutant # "fires_twice"
             THEN /\ list' = {} /\ marked' = {} /\ overflowed' = TRUE
             ELSE /\ marked' = newMarked /\ UNCHANGED <<list, overflowed>>
          /\ fired' = (fired \/ answer)
    /\ UNCHANGED <<sent, delivered, declared, episodeLost>>

(* A congestion event starts a new recovery period: Spurious.on_episode_start. *)
Episode ==
    /\ IF Mutant = "no_reset"
       THEN UNCHANGED <<list, marked, overflowed>>
       ELSE /\ list' = {} /\ marked' = {} /\ overflowed' = FALSE
    /\ episodeLost' = {}
    /\ fired' = FALSE
    /\ last' = Note("episode", FALSE)
    /\ UNCHANGED <<sent, delivered, acked, declared>>

Next ==
    \/ \E p \in Packets : Send(p) \/ Deliver(p) \/ Lose(p) \/ Ack(p)
    \/ Episode

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The properties.                                                         *)
(***************************************************************************)

(* §5.5.11: an episode is spurious only when every packet it declared lost was delivered and *)
(* acknowledged, so a packet the path truly lost never makes one spurious.                   *)
OnlyWhenAllArrived == (last.kind = "ack" /\ last.answer) =>
    /\ episodeLost # {}
    /\ episodeLost \subseteq acked

(* §5.2.5: the undo comes once an episode. *)
OncePerEpisode == (last.kind = "ack" /\ last.answer) => ~last.firedBefore

Properties ==
    /\ OnlyWhenAllArrived
    /\ OncePerEpisode
=============================================================================
