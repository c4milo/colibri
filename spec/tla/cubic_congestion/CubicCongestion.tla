-------------------------- MODULE CubicCongestion --------------------------
(***************************************************************************)
(* The congestion window of src/quic/recovery/recovery_congestion.zig:     *)
(* RFC 9002 §7's slow start, recovery period and persistent congestion,   *)
(* with CUBIC (RFC 9438) in congestion avoidance (decision 133, design §8  *)
(* step 27). The window counts datagrams. TLC checks every order of sends, *)
(* acknowledgments, limited acknowledgments, losses and persistent         *)
(* congestion that the bounds allow.                                       *)
(*                                                                         *)
(* The cubic curve's arithmetic is spec/lean/Colibri/Quic/Cubic.lean's,    *)
(* which proves the target lies between the window and 1.5 times it. So   *)
(* here an acknowledgment in congestion avoidance may move the window to   *)
(* any value in that range, or to the Reno-friendly estimate, and TLC      *)
(* checks the properties against each of them.                             *)
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
Mutants == {"none", "reduce_again", "grow_in_recovery", "count_limited", "no_floor",
            "convergence_up", "curve_below"}
ASSUME Mutant \in Mutants

Max(a, b) == IF a >= b THEN a ELSE b
Min(a, b) == IF a <= b THEN a ELSE b

(* RFC 9438 §4.6: β = 0.7 of the window, held up by RFC 9002's minimum;    *)
(* §4.7: fast convergence lowers W_max to 17/20 of the window.            *)
Reduced(w) == IF Mutant = "no_floor" THEN Max((w * 7) \div 10, 1) ELSE Max((w * 7) \div 10, Minimum)
WMaxAfter(w, before) ==
    IF Mutant = "convergence_up" THEN w + 1
    ELSE IF w < before THEN (w * 17) \div 20 ELSE w
(* §4.2: the target's ceiling, 1.5 times the window, as Cubic.lean has it. *)
Ceiling(w) == Max(w, (w \div 2) * 3)
None == 0

VARIABLES
    window,         \* congestion_window
    threshold,      \* ssthresh; Maximum + 1 stands for RFC 9002's infinite
    recoveryStart,  \* congestion_recovery_start_time, as a send stamp; None outside
    inFlight,       \* the send stamps of the packets in flight
    clock,          \* the stamp the next send takes
    wMax,           \* RFC 9438's W_max; 0 before any event and after persistent congestion
    prior,          \* cwnd_prior
    epochWindow,    \* the window the current stage started from, or None before it starts
    curveWMax,      \* the W_max the current stage's curve aims at
    elapsed,        \* the stage's time, which only full acknowledgments advance
    last            \* the last event, which the properties read

vars == <<window, threshold, recoveryStart, inFlight, clock, wMax, prior, epochWindow, curveWMax, elapsed, last>>

Infinite == Maximum + 1
Kinds == {"none", "send", "ack", "limited", "loss", "persistent"}

TypeOK ==
    /\ window \in 1..Maximum
    /\ threshold \in 1..Infinite
    /\ recoveryStart \in 0..ClockMax
    /\ inFlight \subseteq 1..ClockMax
    /\ clock \in 1..(ClockMax + 1)
    /\ wMax \in 0..Maximum
    /\ prior \in 0..Maximum
    /\ epochWindow \in 0..Maximum
    /\ curveWMax \in 0..Maximum
    /\ elapsed \in 0..ClockMax
    /\ last.kind \in Kinds

Init ==
    /\ window = Min(10, Maximum)
    /\ threshold = Infinite
    /\ recoveryStart = None
    /\ inFlight = {}
    /\ clock = 1
    /\ wMax = 0
    /\ prior = 0
    /\ epochWindow = None
    /\ curveWMax = 0
    /\ elapsed = 0
    /\ last = [kind |-> "none", inRecovery |-> FALSE, windowBefore |-> 0, wMaxBefore |-> 0, elapsedBefore |-> 0]

InRecovery(p) == recoveryStart # None /\ p <= recoveryStart

Note(kind, p) == [kind |-> kind, inRecovery |-> InRecovery(p), windowBefore |-> window,
                  wMaxBefore |-> wMax, elapsedBefore |-> elapsed]

Send ==
    /\ clock <= ClockMax
    /\ Cardinality(inFlight) < window
    /\ inFlight' = inFlight \cup {clock}
    /\ clock' = clock + 1
    /\ last' = Note("send", clock)
    /\ UNCHANGED <<window, threshold, recoveryStart, wMax, prior, epochWindow, curveWMax, elapsed>>

(* RFC 9002 Appendix B.5 and RFC 9438 §4.2 to §4.5. A stage starts at its *)
(* first acknowledgment in congestion avoidance: its curve aims at W_max, *)
(* or at the window when W_max is at or below it (§4.8, §4.10). The window *)
(* then moves to any value up to the target's ceiling.                     *)
AckFull(p) ==
    /\ p \in inFlight
    /\ inFlight' = inFlight \ {p}
    /\ last' = Note("ack", p)
    /\ elapsed' = Min(elapsed + 1, ClockMax)
    /\ IF InRecovery(p) /\ Mutant # "grow_in_recovery"
       THEN UNCHANGED <<window, epochWindow, curveWMax>>
       ELSE IF window < threshold
       THEN /\ window' = Min(window + 1, Maximum)
            /\ UNCHANGED <<epochWindow, curveWMax>>
       ELSE /\ epochWindow' = IF epochWindow = None THEN window ELSE epochWindow
            /\ curveWMax' = IF epochWindow = None
                            THEN (IF wMax <= window
                                  THEN (IF Mutant = "curve_below" THEN window - 1 ELSE window)
                                  ELSE wMax)
                            ELSE curveWMax
            /\ window' \in window..Min(Ceiling(window), Maximum)
    /\ UNCHANGED <<threshold, recoveryStart, clock, wMax, prior>>

(* RFC 9002 §7.8, RFC 9438 §4.2: a limited acknowledgment grows nothing,   *)
(* and its time is left out of the stage's.                                *)
AckLimited(p) ==
    /\ p \in inFlight
    /\ inFlight' = inFlight \ {p}
    /\ last' = Note("limited", p)
    /\ elapsed' = IF Mutant = "count_limited" THEN Min(elapsed + 1, ClockMax) ELSE elapsed
    /\ UNCHANGED <<window, threshold, recoveryStart, clock, wMax, prior, epochWindow, curveWMax>>

(* RFC 9002 Appendix B.6, RFC 9438 §4.6 and §4.7. A loss and an increase  *)
(* in the peer's ECN-CE count both arrive here.                            *)
Lose(p) ==
    /\ p \in inFlight
    /\ inFlight' = inFlight \ {p}
    /\ last' = Note("loss", p)
    /\ IF InRecovery(p) /\ Mutant # "reduce_again"
       THEN UNCHANGED <<window, threshold, recoveryStart, wMax, prior, epochWindow>>
       ELSE /\ recoveryStart' = clock - 1
            /\ wMax' = WMaxAfter(window, wMax)
            /\ prior' = window
            /\ threshold' = Reduced(window)
            /\ window' = Reduced(window)
            /\ epochWindow' = None
    /\ UNCHANGED <<clock, curveWMax, elapsed>>

(* RFC 9002 §7.6, RFC 9438 §4.8.                                           *)
Persistent ==
    /\ window' = Minimum
    /\ recoveryStart' = None
    /\ wMax' = 0
    /\ epochWindow' = None
    /\ last' = [kind |-> "persistent", inRecovery |-> FALSE, windowBefore |-> window,
                wMaxBefore |-> wMax, elapsedBefore |-> elapsed]
    /\ UNCHANGED <<threshold, inFlight, clock, prior, curveWMax, elapsed>>

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

(* RFC 9002 Appendix B.5: an acknowledgment of a packet sent inside the    *)
(* recovery period grows nothing.                                          *)
NoGrowthInRecovery == (last.kind = "ack" /\ last.inRecovery) => window <= last.windowBefore

(* RFC 9002 Appendix B.6: one recovery period reduces the window once.     *)
OneReductionPerPeriod == (last.kind = "loss" /\ last.inRecovery) => window = last.windowBefore

(* RFC 9438 §4.6, §4.7: a decrease never raises the window, and W_max      *)
(* after fast convergence is never above the window it replaced.          *)
DecreaseLowers == (last.kind = "loss" /\ ~last.inRecovery) =>
    /\ window <= Max(last.windowBefore, Minimum)
    /\ wMax <= last.windowBefore

(* RFC 9438 §4.2: a stage's curve never starts below its window.          *)
CurveFromWindow == epochWindow # None => curveWMax >= epochWindow

(* RFC 9438 §4.2: a limited acknowledgment does not advance the stage's    *)
(* time.                                                                   *)
LimitedTimeLeftOut == last.kind = "limited" => elapsed = last.elapsedBefore

Properties ==
    /\ WindowFloor
    /\ NoGrowthInRecovery
    /\ OneReductionPerPeriod
    /\ DecreaseLowers
    /\ CurveFromWindow
    /\ LimitedTimeLeftOut
=============================================================================
