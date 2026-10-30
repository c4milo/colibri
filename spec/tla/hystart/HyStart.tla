------------------------------- MODULE HyStart -------------------------------
(***************************************************************************)
(* HyStart++ (RFC 9406) as src/quic/recovery/recovery_hystart.zig runs it  *)
(* in CUBIC's first slow start (decision 135, design §8 step 28). TLC      *)
(* checks every order of round ends, round trip samples and losses that   *)
(* the bounds allow.                                                       *)
(*                                                                         *)
(* Round trips are small integers, and the threshold is the constant      *)
(* Threshold: spec/lean/Colibri/Quic/HyStart.lean proves the threshold's  *)
(* arithmetic, and this model checks the stages the comparisons move.     *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Samples,        \* N_RTT_SAMPLE
    CssRounds,      \* CSS_ROUNDS
    Threshold,      \* RttThresh, which Lean bounds
    RttMax,         \* the largest round trip a sample takes
    RoundMax,       \* the rounds the model takes, which bounds the state space
    Mutant          \* "none", or the one rule a mutant in mutants/ breaks

ASSUME Samples \in Nat /\ Samples >= 1
ASSUME CssRounds \in Nat /\ CssRounds >= 1
ASSUME Threshold \in Nat /\ RttMax \in Nat /\ RoundMax \in Nat
Mutants == {"none", "no_round_limit", "partial_not_counted", "exit_early", "loss_kept",
            "resume_at_baseline"}
ASSUME Mutant \in Mutants

(* The Zig's null, infinity for a minimum. *)
Infinity == RttMax + 1
Stages == {"slow_start", "conservative", "done"}
Kinds == {"none", "round", "sample", "loss"}

VARIABLES
    stage,          \* HyStart.stage
    lastMin,        \* last_round_min_ns
    roundMin,       \* round_min_ns
    samples,        \* samples, held at Samples
    baseline,       \* css_baseline_ns
    cssRounds,      \* css_rounds
    inCss,          \* the rounds of CSS so far, the partial one included, counted apart from the code
    rounds,         \* the rounds started, which bounds the model
    last            \* the last event, which the properties read

vars == <<stage, lastMin, roundMin, samples, baseline, cssRounds, inCss, rounds, last>>

TypeOK ==
    /\ stage \in Stages
    /\ lastMin \in 1..Infinity
    /\ roundMin \in 1..Infinity
    /\ samples \in 0..Samples
    /\ baseline \in 1..Infinity
    /\ cssRounds \in Nat
    /\ inCss \in Nat
    /\ rounds \in 0..RoundMax
    /\ last.kind \in Kinds

Init ==
    /\ stage = "slow_start"
    /\ lastMin = Infinity
    /\ roundMin = Infinity
    /\ samples = 0
    /\ baseline = Infinity
    /\ cssRounds = 0
    /\ inCss = 0
    /\ rounds = 0
    /\ last = [kind |-> "none", stageBefore |-> "slow_start", samples |-> 0, roundMin |-> Infinity,
               lastMin |-> Infinity, baseline |-> Infinity, inCss |-> 0]

Note(kind) == [kind |-> kind, stageBefore |-> stage, samples |-> samples, roundMin |-> roundMin,
               lastMin |-> lastMin, baseline |-> baseline, inCss |-> inCss]

(* §4.2: "When windowEnd is ACKed, the current round ends". A round of CSS that ends the last *)
(* of CssRounds ends slow start.                                                              *)
RoundEnds ==
    /\ stage # "done"
    /\ rounds < RoundMax
    /\ rounds' = rounds + 1
    /\ lastMin' = roundMin
    /\ roundMin' = Infinity
    /\ samples' = 0
    /\ last' = Note("round")
    /\ IF stage # "conservative"
       THEN UNCHANGED <<stage, baseline, cssRounds, inCss>>
       ELSE IF cssRounds >= CssRounds /\ Mutant # "no_round_limit"
       THEN /\ stage' = "done"
            /\ baseline' = Infinity
            /\ UNCHANGED <<cssRounds, inCss>>
       ELSE /\ cssRounds' = cssRounds + 1
            /\ inCss' = inCss + 1
            /\ UNCHANGED <<stage, baseline>>

(* §4.2's two comparisons, once the round holds Samples samples. *)
Judged(min, count) ==
    IF count < Samples /\ Mutant # "exit_early" THEN [s |-> stage, b |-> baseline, c |-> cssRounds, i |-> inCss]
    ELSE IF stage = "slow_start"
    THEN IF lastMin # Infinity /\ min >= lastMin + Threshold
         THEN [s |-> "conservative", b |-> min, c |-> IF Mutant = "partial_not_counted" THEN 0 ELSE 1, i |-> 1]
         ELSE [s |-> stage, b |-> baseline, c |-> cssRounds, i |-> inCss]
    ELSE IF (min < baseline) \/ (Mutant = "resume_at_baseline" /\ min = baseline)
    THEN [s |-> "slow_start", b |-> Infinity, c |-> cssRounds, i |-> inCss]
    ELSE [s |-> stage, b |-> baseline, c |-> cssRounds, i |-> inCss]

(* One ACK frame with a round trip sample. *)
Sample(rtt) ==
    /\ stage # "done" \/ Mutant = "loss_kept"
    /\ LET min == IF rtt < roundMin THEN rtt ELSE roundMin
           count == IF samples < Samples THEN samples + 1 ELSE samples
           judged == IF stage = "done" THEN [s |-> stage, b |-> baseline, c |-> cssRounds, i |-> inCss]
                     ELSE Judged(min, count)
       IN /\ roundMin' = min
          /\ samples' = count
          /\ stage' = IF Mutant = "loss_kept" /\ stage = "done" THEN "slow_start" ELSE judged.s
          /\ baseline' = judged.b
          /\ cssRounds' = judged.c
          /\ inCss' = judged.i
    /\ last' = Note("sample")
    /\ UNCHANGED <<lastMin, rounds>>

(* §4.2: a loss or an ECN mark ends HyStart++ (§4.3: for the rest of the connection). *)
Loss ==
    /\ stage # "done"
    /\ stage' = "done"
    /\ baseline' = Infinity
    /\ last' = Note("loss")
    /\ UNCHANGED <<lastMin, roundMin, samples, cssRounds, inCss, rounds>>

Next ==
    \/ RoundEnds
    \/ \E rtt \in 1..RttMax : Sample(rtt)
    \/ Loss

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The properties.                                                         *)
(***************************************************************************)

(* §4.2: "CSS lasts at most CSS_ROUNDS rounds", the partial round included. *)
CssBounded == inCss <= CssRounds

(* §4.2: slow start ends for a delay increase only with Samples samples, a last round's     *)
(* minimum, and a minimum past it by the threshold.                                        *)
ExitNeedsIncrease == (last.kind = "sample" /\ last.stageBefore = "slow_start" /\ stage = "conservative") =>
    /\ samples >= Samples
    /\ last.lastMin # Infinity
    /\ roundMin >= last.lastMin + Threshold

(* §4.2: CSS resumes slow start only when the round's minimum falls below the baseline. *)
ResumeNeedsDrop == (last.kind = "sample" /\ last.stageBefore = "conservative" /\ stage = "slow_start") =>
    /\ samples >= Samples
    /\ roundMin < last.baseline

(* §4.2 and §4.3: once done, HyStart++ stays done, and a loss makes it done. *)
DoneStays == (last.stageBefore = "done") => stage = "done"
LossEnds == (last.kind = "loss") => stage = "done"

(* §4.2: congestion avoidance comes from CSS, after CssRounds rounds of it. *)
AvoidanceAfterRounds == (last.kind = "round" /\ last.stageBefore = "conservative" /\ stage = "done") =>
    last.inCss = CssRounds

Properties ==
    /\ CssBounded
    /\ ExitNeedsIncrease
    /\ ResumeNeedsDrop
    /\ DoneStays
    /\ LossEnds
    /\ AvoidanceAfterRounds
=============================================================================
