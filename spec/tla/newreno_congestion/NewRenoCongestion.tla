------------------------- MODULE NewRenoCongestion -------------------------
(***************************************************************************)
(* The congestion window of src/quic/recovery/recovery_congestion.zig     *)
(* under RFC 9002's own NewReno (§7.3 and Appendix B, decision 133 as     *)
(* amended, design §8 step 34): slow start, congestion avoidance, the     *)
(* recovery period and persistent congestion. The window counts           *)
(* datagrams, and `carry` counts the datagrams acknowledged toward the    *)
(* next increase. TLC checks every order of sends, acknowledgments,       *)
(* limited acknowledgments, losses and persistent congestion that the     *)
(* bounds allow.                                                          *)
(*                                                                         *)
(* The arithmetic in octets is spec/lean/Colibri/Quic/NewReno.lean's,     *)
(* which proves one acknowledgment of at most a window adds at most one   *)
(* datagram. Here the carry makes that hold over any sequence.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Minimum,        \* RFC 9002 §7.2's minimum window, in datagrams
    Maximum,        \* the largest window the model lets the window reach
    ClockMax,       \* the sends the model takes, which bounds the state space
    Mutant          \* "none", or the one rule a mutant in mutants/ breaks

ASSUME Minimum \in Nat /\ Minimum >= 2
ASSUME Maximum \in Nat /\ Maximum >= Minimum
ASSUME ClockMax \in Nat
Mutants == {"none", "reduce_again", "grow_in_recovery", "grow_limited", "no_floor", "every_ack"}
ASSUME Mutant \in Mutants

Max(a, b) == IF a >= b THEN a ELSE b
Min(a, b) == IF a <= b THEN a ELSE b

(* Appendix B.6: ssthresh = window × kLossReductionFactor (0.5), and the  *)
(* window max(ssthresh, kMinimumWindow).                                  *)
Halved(w) == w \div 2
Reduced(w) == IF Mutant = "no_floor" THEN Max(Halved(w), 1) ELSE Max(Halved(w), Minimum)
None == 0

VARIABLES
    window,         \* congestion_window
    threshold,      \* ssthresh; Maximum + 1 stands for RFC 9002's infinite
    recoveryStart,  \* congestion_recovery_start_time, as a send stamp; None outside
    inFlight,       \* the send stamps of the packets in flight
    clock,          \* the stamp the next send takes
    carry,          \* datagrams acknowledged in congestion avoidance toward the next increase
    last            \* the last event, which the properties read

vars == <<window, threshold, recoveryStart, inFlight, clock, carry, last>>

Infinite == Maximum + 1
Kinds == {"none", "send", "ack", "limited", "loss", "persistent"}

TypeOK ==
    /\ window \in 1..Maximum
    /\ threshold \in 0..Infinite
    /\ recoveryStart \in 0..ClockMax
    /\ inFlight \subseteq 1..ClockMax
    /\ clock \in 1..(ClockMax + 1)
    /\ carry \in 0..Maximum
    /\ last.kind \in Kinds

Init ==
    /\ window = Min(10, Maximum)
    /\ threshold = Infinite
    /\ recoveryStart = None
    /\ inFlight = {}
    /\ clock = 1
    /\ carry = 0
    /\ last = [kind |-> "none", inRecovery |-> FALSE, windowBefore |-> 0, avoidance |-> FALSE,
               carryBefore |-> 0]

InRecovery(p) == recoveryStart # None /\ p <= recoveryStart

Note(kind, p) == [kind |-> kind, inRecovery |-> InRecovery(p), windowBefore |-> window,
                  avoidance |-> window >= threshold, carryBefore |-> carry]

Send ==
    /\ clock <= ClockMax
    /\ Cardinality(inFlight) < window
    /\ inFlight' = inFlight \cup {clock}
    /\ clock' = clock + 1
    /\ last' = Note("send", clock)
    /\ UNCHANGED <<window, threshold, recoveryStart, carry>>

(* Appendix B.5: slow start adds what was acknowledged; congestion       *)
(* avoidance adds one datagram once a window has been acknowledged.      *)
AckFull(p) ==
    /\ p \in inFlight
    /\ inFlight' = inFlight \ {p}
    /\ last' = Note("ack", p)
    /\ IF InRecovery(p) /\ Mutant # "grow_in_recovery"
       THEN UNCHANGED <<window, carry>>
       ELSE IF window < threshold
       THEN /\ window' = Min(window + 1, Maximum)
            /\ UNCHANGED carry
       ELSE IF Mutant = "every_ack" \/ carry + 1 >= window
       THEN /\ window' = Min(window + 1, Maximum)
            /\ carry' = 0
       ELSE /\ carry' = carry + 1
            /\ UNCHANGED window
    /\ UNCHANGED <<threshold, recoveryStart, clock>>

(* RFC 9002 §7.8 and Appendix B.5: a limited acknowledgment grows nothing. *)
AckLimited(p) ==
    /\ p \in inFlight
    /\ inFlight' = inFlight \ {p}
    /\ last' = Note("limited", p)
    /\ IF Mutant = "grow_limited" /\ window < threshold
       THEN window' = Min(window + 1, Maximum)
       ELSE UNCHANGED window
    /\ UNCHANGED <<threshold, recoveryStart, clock, carry>>

(* Appendix B.6. A loss and an increase in the peer's ECN-CE count both  *)
(* arrive here.                                                           *)
Lose(p) ==
    /\ p \in inFlight
    /\ inFlight' = inFlight \ {p}
    /\ last' = Note("loss", p)
    /\ IF InRecovery(p) /\ Mutant # "reduce_again"
       THEN UNCHANGED <<window, threshold, recoveryStart, carry>>
       ELSE /\ recoveryStart' = clock - 1
            /\ threshold' = Halved(window)
            /\ window' = Reduced(window)
            /\ carry' = 0
    /\ UNCHANGED clock

(* RFC 9002 §7.6 and Appendix B.8.                                         *)
Persistent ==
    /\ window' = Minimum
    /\ recoveryStart' = None
    /\ carry' = 0
    /\ last' = [kind |-> "persistent", inRecovery |-> FALSE, windowBefore |-> window,
                avoidance |-> FALSE, carryBefore |-> carry]
    /\ UNCHANGED <<threshold, inFlight, clock>>

Next ==
    \/ Send
    \/ \E p \in inFlight : AckFull(p) \/ AckLimited(p) \/ Lose(p)
    \/ Persistent

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The properties.                                                         *)
(***************************************************************************)

(* RFC 9002 §7.2: the window never falls below the minimum.               *)
WindowFloor == window >= Minimum

(* Appendix B.5: an acknowledgment of a packet sent inside the recovery    *)
(* period grows nothing.                                                   *)
NoGrowthInRecovery == (last.kind = "ack" /\ last.inRecovery) => window <= last.windowBefore

(* RFC 9002 §7.8: a limited acknowledgment grows nothing.                  *)
NoGrowthWhenLimited == last.kind = "limited" => window = last.windowBefore

(* Appendix B.6: one recovery period reduces the window once.             *)
OneReductionPerPeriod == (last.kind = "loss" /\ last.inRecovery) => window = last.windowBefore

(* Appendix B.6: a new congestion event halves the window, held at the     *)
(* minimum.                                                                *)
EventHalves == (last.kind = "loss" /\ ~last.inRecovery) =>
    window = Max(last.windowBefore \div 2, Minimum)

(* §7.3.3: in congestion avoidance an acknowledgment adds at most one      *)
(* datagram, and only the one that completes a window of acknowledgments.  *)
AvoidanceOnePerWindow == (last.kind = "ack" /\ last.avoidance /\ ~last.inRecovery) =>
    /\ window <= last.windowBefore + 1
    /\ (window = last.windowBefore + 1 => last.carryBefore + 1 >= last.windowBefore)

Properties ==
    /\ WindowFloor
    /\ NoGrowthInRecovery
    /\ NoGrowthWhenLimited
    /\ OneReductionPerPeriod
    /\ EventHalves
    /\ AvoidanceOnePerWindow
=============================================================================
