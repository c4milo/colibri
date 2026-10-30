/-!
# HyStart++ (RFC 9406, decision 135)

`src/quic/recovery/recovery_hystart.zig`'s `HyStart`, which runs CUBIC's first slow start. The
definitions follow the Zig line for line; the theorems are about them:

- `threshold_bounds`: RttThresh lies between MIN_RTT_THRESH and MAX_RTT_THRESH (§4.2).
- `onAck_done`: once HyStart++ is done, it stays done and leaves slow start to the standard
  algorithm (§4.3).
- `onAck_inv`: CSS never counts past CSS_ROUNDS rounds, and a round never past N_RTT_SAMPLE
  samples, whatever the acknowledgments.
- `onAck_avoidance`: the window enters congestion avoidance only after CSS_ROUNDS rounds of CSS,
  and HyStart++ is then done (§4.2).
- `cssGrowth_le`: CSS never grows the window faster than slow start (§4.2).

`spec/lean/Vectors.lean` writes `src/quic/recovery/hystart_vectors.txt` from these definitions,
and a Zig test requires `recovery_hystart.zig` to give the same answers (decision 77).
-/

namespace Colibri.Quic.HyStart

/-- `hystart.rtt_threshold_min_ns` and `hystart.rtt_threshold_max_ns`: 4 ms and 16 ms. -/
def thresholdMin : Nat := 4000000
def thresholdMax : Nat := 16000000
/-- `hystart.rtt_divisor`, `hystart.rtt_samples`, `hystart.css_growth_divisor` and
`hystart.css_rounds`. -/
def rttDivisor : Nat := 8
def rttSamples : Nat := 8
def cssGrowthDivisor : Nat := 4
def cssRounds : Nat := 5

inductive Stage where
  | slowStart
  | conservative
  | done
  deriving DecidableEq, Repr

inductive Growth where
  | full
  | conservative
  | avoidance
  deriving DecidableEq, Repr

/-- `HyStart`. `none` is the Zig's null: infinity for a minimum, no round yet for the start. -/
structure State where
  stage : Stage
  roundStarted : Option Nat
  lastRoundMin : Option Nat
  roundMin : Option Nat
  samples : Nat
  cssBaseline : Option Nat
  cssRoundsSoFar : Nat
  deriving DecidableEq, Repr

/-- `init`. -/
def init : State := ⟨.slowStart, none, none, none, 0, none, 0⟩

/-- `threshold_ns`. -/
def threshold (lastRoundMin : Nat) : Nat :=
  max thresholdMin (min (lastRoundMin / rttDivisor) thresholdMax)

/-- `finish`. -/
def finish (s : State) : State := { s with stage := .done, cssBaseline := none }

/-- The fields `start_round` sets whatever the stage. -/
def reset (s : State) (now : Nat) : State :=
  { s with roundStarted := some now, lastRoundMin := s.roundMin, roundMin := none, samples := 0 }

/-- `start_round`. `reset` leaves the stage as it is, so the stage it reads is `s`'s. -/
def startRound (s : State) (now : Nat) : State × Growth :=
  if s.stage ≠ .conservative then (reset s now, .full)
  else if cssRounds ≤ s.cssRoundsSoFar then (finish (reset s now), .avoidance)
  else ({ reset s now with cssRoundsSoFar := s.cssRoundsSoFar + 1 }, .conservative)

/-- `judge_round`, given the round's minimum. -/
def judgeRound (s : State) (roundMin : Nat) : State :=
  match s.stage with
  | .slowStart =>
    match s.lastRoundMin with
    | none => s
    | some last =>
      if roundMin < last + threshold last then s
      else { s with cssBaseline := some roundMin, stage := .conservative, cssRoundsSoFar := 1 }
  | .conservative =>
    match s.cssBaseline with
    | none => s
    | some baseline =>
      if baseline ≤ roundMin then s else { s with cssBaseline := none, stage := .slowStart }
  | .done => s

/-- The round's minimum once a sample is taken. -/
def minWith (roundMin : Option Nat) (sample : Nat) : Nat :=
  match roundMin with
  | none => sample
  | some m => min m sample

/-- The count, held at N_RTT_SAMPLE. -/
def bump (samples : Nat) : Nat := if samples < rttSamples then samples + 1 else samples

/-- A sample taken. -/
def sampled (s : State) (sample : Nat) : State :=
  { s with roundMin := some (minWith s.roundMin sample), samples := bump s.samples }

/-- A sample taken, and the round judged once it holds N_RTT_SAMPLE. -/
def afterSample (s : State) (sample : Nat) : State :=
  if rttSamples ≤ bump s.samples then judgeRound (sampled s sample) (minWith s.roundMin sample)
  else sampled s sample

/-- The sample part of `on_ack`. -/
def takeSample (s : State) (growth : Growth) (rtt : Option Nat) : State × Growth :=
  match rtt with
  | none => (s, growth)
  | some sample => (afterSample s sample, growth)

/-- Whether an acknowledgment of a packet sent at `sentAt` ends the round (§4.2's windowEnd). -/
def roundEnds (s : State) (sentAt : Nat) : Bool :=
  match s.roundStarted with
  | none => true
  | some started => decide (started ≤ sentAt)

/-- §4.2 grows the window by the stage the acknowledgment arrived in. -/
def stageGrowth (s : State) : Growth := if s.stage = .conservative then .conservative else .full

/-- `on_ack`. -/
def onAck (s : State) (sentAt : Nat) (rtt : Option Nat) (now : Nat) : State × Growth :=
  if s.stage = .done then (s, .full)
  else if roundEnds s sentAt then
    if (startRound s now).2 = .avoidance then startRound s now
    else takeSample (startRound s now).1 (stageGrowth (startRound s now).1) rtt
  else takeSample s (stageGrowth s) rtt

theorem threshold_bounds (last : Nat) :
    thresholdMin ≤ threshold last ∧ threshold last ≤ thresholdMax := by
  unfold threshold thresholdMin thresholdMax; omega

theorem onAck_done (s : State) (sentAt : Nat) (rtt : Option Nat) (now : Nat)
    (h : s.stage = .done) : onAck s sentAt rtt now = (s, .full) := by
  simp [onAck, h]

/-- What every state `init` leads to holds. -/
def Inv (s : State) : Prop := s.cssRoundsSoFar ≤ cssRounds ∧ s.samples ≤ rttSamples

theorem init_inv : Inv init := by
  simp [Inv, init, cssRounds, rttSamples]

theorem judgeRound_inv (s : State) (m : Nat) (h : Inv s) : Inv (judgeRound s m) := by
  unfold judgeRound
  split
  · split
    · exact h
    · split
      · exact h
      · exact ⟨by simp [cssRounds], h.2⟩
  · split
    · exact h
    · split
      · exact h
      · exact h
  · exact h

theorem sampled_inv (s : State) (x : Nat) (h : Inv s) : Inv (sampled s x) := by
  refine ⟨h.1, ?_⟩
  show bump s.samples ≤ rttSamples
  have := h.2
  unfold bump; split <;> omega

theorem takeSample_inv (s : State) (g : Growth) (rtt : Option Nat) (h : Inv s) :
    Inv (takeSample s g rtt).1 := by
  cases rtt with
  | none => exact h
  | some x =>
    show Inv (afterSample s x)
    unfold afterSample
    split
    · exact judgeRound_inv _ _ (sampled_inv s x h)
    · exact sampled_inv s x h

theorem startRound_inv (s : State) (now : Nat) (h : Inv s) : Inv (startRound s now).1 := by
  unfold startRound
  split
  · exact ⟨h.1, by simp [reset]⟩
  · split
    · exact ⟨h.1, by simp [reset, finish]⟩
    · next _ hlt => exact ⟨show s.cssRoundsSoFar + 1 ≤ cssRounds by omega, by simp [reset]⟩

theorem onAck_inv (s : State) (sentAt : Nat) (rtt : Option Nat) (now : Nat) (h : Inv s) :
    Inv (onAck s sentAt rtt now).1 := by
  unfold onAck
  split
  · exact h
  · split
    · split
      · exact startRound_inv s now h
      · exact takeSample_inv _ _ rtt (startRound_inv s now h)
    · exact takeSample_inv s _ rtt h

theorem startRound_avoidance (s : State) (now : Nat) (h : (startRound s now).2 = .avoidance) :
    s.stage = .conservative ∧ cssRounds ≤ s.cssRoundsSoFar ∧ (startRound s now).1.stage = .done := by
  unfold startRound at *
  split at h
  · simp at h
  · next hne =>
    simp only [ne_eq, Decidable.not_not] at hne
    split at h
    · next hge => simp [hne, hge, finish]
    · simp at h

theorem takeSample_growth (s : State) (g : Growth) (rtt : Option Nat) :
    (takeSample s g rtt).2 = g := by
  cases rtt <;> rfl

/-- Congestion avoidance comes only from the round that ends the last of CSS_ROUNDS, and leaves
HyStart++ done. -/
theorem onAck_avoidance (s : State) (sentAt : Nat) (rtt : Option Nat) (now : Nat)
    (h : (onAck s sentAt rtt now).2 = .avoidance) :
    s.stage = .conservative ∧ cssRounds ≤ s.cssRoundsSoFar ∧ (onAck s sentAt rtt now).1.stage = .done := by
  unfold onAck at *
  split at h
  · simp at h
  · next hnd =>
    simp only [hnd, ite_false]
    split at h
    · next hends =>
      simp only [hends, ite_true]
      split at h
      · next hav => simp only [hav, ite_true]; exact startRound_avoidance s now hav
      · rw [takeSample_growth] at h; unfold stageGrowth at h; split at h <;> simp at h
    · rw [takeSample_growth] at h; unfold stageGrowth at h; split at h <;> simp at h

/-- `grow_conservatively` adds a quarter of what was acknowledged, never more than slow start's
whole. -/
theorem cssGrowth_le (acknowledged : Nat) : acknowledged / cssGrowthDivisor ≤ acknowledged :=
  Nat.div_le_self _ _

end Colibri.Quic.HyStart
