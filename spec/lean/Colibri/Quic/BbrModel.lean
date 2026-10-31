/-!
# BBRv3's model of the path (draft-ietf-ccwg-bbr-06 §5.5, design §8 step 29b.1)

`src/quic/recovery/recovery_bbr/recovery_bbr_model.zig` keeps BBR's estimates of the path, and
`src/quic/recovery/recovery_bbr/recovery_bbr_filter.zig` the windowed maximum two of them are kept over. The
definitions follow the Zig; the theorems are about them:

- `windowMax_ge` and `windowMax_le`: the filter's answer is the largest value taken within the
  window, because it is at least each one of them and at most any bound on all of them.
- `updateRound_count`: the round count never falls, and rises by at most 1 on each ACK frame.
- `updateMinRtt_le_probe`: BBR.min_rtt is never above BBR.probe_rtt_min_delay (§5.3.4.3).
- `updateMinRtt_lower`: a sample below both estimates replaces both.
- `updateAggregation_le_window` and `updateAggregation_reset`: the extra octets are never more
  than the window, and after the interval starts again they are the frame's own (§5.5.9).

The Zig adds with saturation, near 2^64, which no connection reaches; these definitions add
without it. `spec/lean/Vectors.lean` writes `src/quic/recovery/recovery_bbr/bbr_model_vectors.txt` from them,
and a Zig test requires the two files to give the same answers (decision 77).
-/

namespace Colibri.Quic.BbrModel

/-- `constants.nanoseconds_per_second` in `src/core/constants.zig`. -/
def nanosecondsPerSecond : Nat := 1000000000
/-- The largest `u64`, at which `expected_delivered_len` saturates, and the draft's "Infinity". -/
def u64Max : Nat := 2 ^ 64 - 1
/-- §2.16.2's `BBR.ProbeRTTInterval` and §2.16.1's `BBR.MinRTTFilterLen`, in nanoseconds. -/
def probeRttInterval : Nat := 5 * nanosecondsPerSecond
def minRttFilterLen : Nat := 10 * nanosecondsPerSecond

/-- Whether a value taken at `time` is within the last `window` times up to `now`. -/
def inWindow (now window time : Nat) : Prop := time ≤ now ∧ now < time + window

instance (now window time : Nat) : Decidable (inWindow now window time) := by
  unfold inWindow; exact inferInstance

/-- One step of `windowMax`. -/
def keep (now window : Nat) (best : Nat) (taken : Nat × Nat) : Nat :=
  if inWindow now window taken.1 then max best taken.2 else best

/-- `MaxFilter.max`: the largest value of the `(time, value)` pairs taken within the window. -/
def windowMax (taken : List (Nat × Nat)) (now window : Nat) : Nat :=
  taken.foldl (keep now window) 0

theorem keep_ge (now window best : Nat) (taken : Nat × Nat) : best ≤ keep now window best taken := by
  unfold keep; split <;> omega

theorem fold_ge_init (now window : Nat) (taken : List (Nat × Nat)) (best : Nat) :
    best ≤ taken.foldl (keep now window) best := by
  induction taken generalizing best with
  | nil => simp
  | cons head tail ih =>
    simp only [List.foldl]
    exact Nat.le_trans (keep_ge now window best head) (ih _)

theorem fold_ge_mem (now window : Nat) (taken : List (Nat × Nat)) (best : Nat) (pair : Nat × Nat)
    (hmem : pair ∈ taken) (hin : inWindow now window pair.1) :
    pair.2 ≤ taken.foldl (keep now window) best := by
  induction taken generalizing best with
  | nil => simp at hmem
  | cons head tail ih =>
    simp only [List.foldl]
    rcases List.mem_cons.mp hmem with h | h
    · subst h
      have : pair.2 ≤ keep now window best pair := by
        unfold keep; simp [hin]; omega
      exact Nat.le_trans this (fold_ge_init now window tail _)
    · exact ih _ h

/-- The answer is at least each value taken within the window. -/
theorem windowMax_ge (taken : List (Nat × Nat)) (now window : Nat) (pair : Nat × Nat)
    (hmem : pair ∈ taken) (hin : inWindow now window pair.1) : pair.2 ≤ windowMax taken now window :=
  fold_ge_mem now window taken 0 pair hmem hin

theorem fold_le (now window bound : Nat) (taken : List (Nat × Nat)) (best : Nat)
    (hbest : best ≤ bound)
    (hall : ∀ pair ∈ taken, inWindow now window pair.1 → pair.2 ≤ bound) :
    taken.foldl (keep now window) best ≤ bound := by
  induction taken generalizing best with
  | nil => simpa using hbest
  | cons head tail ih =>
    simp only [List.foldl]
    apply ih
    · unfold keep
      split
      · next hin => exact Nat.max_le.mpr ⟨hbest, hall head (List.mem_cons_self ..) hin⟩
      · exact hbest
    · intro pair hmem hin
      exact hall pair (List.mem_cons_of_mem _ hmem) hin

/-- The answer is at most any bound on every value taken within the window. -/
theorem windowMax_le (taken : List (Nat × Nat)) (now window bound : Nat)
    (hall : ∀ pair ∈ taken, inWindow now window pair.1 → pair.2 ≤ bound) :
    windowMax taken now window ≤ bound :=
  fold_le now window bound taken 0 (Nat.zero_le _) hall

/-- §5.5.1's `BBR.next_round_delivered` and `BBR.round_count`. -/
structure Round where
  next : Nat
  count : Nat
  deriving Repr, DecidableEq

/-- §5.5.1's `UpdateRound`, from the sample's `RS.prior_delivered` and `RS.delivered`, and
whether a round started. -/
def updateRound (round : Round) (prior delivered : Nat) : Round × Bool :=
  if round.next ≤ prior then (⟨prior + delivered, round.count + 1⟩, true) else (round, false)

theorem updateRound_count (round : Round) (prior delivered : Nat) :
    round.count ≤ (updateRound round prior delivered).1.count ∧
      (updateRound round prior delivered).1.count ≤ round.count + 1 := by
  unfold updateRound; split <;> simp

/-- §5.3.4.3's state: `BBR.min_rtt`, `BBR.min_rtt_stamp`, `BBR.probe_rtt_min_delay` and
`BBR.probe_rtt_min_stamp`. -/
structure MinRtt where
  minRtt : Nat
  minAt : Nat
  probe : Nat
  probeAt : Nat
  deriving Repr, DecidableEq

/-- The probe's minimum after a sample, the first half of `UpdateMinRTT`. -/
def takeProbe (state : MinRtt) (rtt : Option Nat) (now : Nat) : MinRtt :=
  match rtt with
  | some sample =>
    if sample < state.probe ∨ now > state.probeAt + probeRttInterval then
      { state with probe := sample, probeAt := now }
    else state
  | none => state

/-- BBR.min_rtt after the probe's minimum moved, the second half of `UpdateMinRTT`. -/
def settle (probed : MinRtt) (now : Nat) : MinRtt :=
  if probed.probe < probed.minRtt ∨ now > probed.minAt + minRttFilterLen then
    { probed with minRtt := probed.probe, minAt := probed.probeAt }
  else probed

/-- §5.3.4.3's `UpdateMinRTT`. -/
def updateMinRtt (state : MinRtt) (rtt : Option Nat) (now : Nat) : MinRtt :=
  settle (takeProbe state rtt now) now

theorem updateMinRtt_le_probe (state : MinRtt) (rtt : Option Nat) (now : Nat) :
    (updateMinRtt state rtt now).minRtt ≤ (updateMinRtt state rtt now).probe := by
  unfold updateMinRtt settle
  split
  · simp
  · next h => omega

theorem updateMinRtt_lower (state : MinRtt) (sample now : Nat) (hprobe : sample < state.probe) :
    (updateMinRtt state (some sample) now).probe = sample ∧
      (updateMinRtt state (some sample) now).minRtt ≤ sample := by
  have hp : (takeProbe state (some sample) now).probe = sample := by
    unfold takeProbe; simp [hprobe]
  constructor
  · unfold updateMinRtt settle; split <;> simp [hp]
  · have := updateMinRtt_le_probe state (some sample) now
    have hq : (updateMinRtt state (some sample) now).probe = sample := by
      unfold updateMinRtt settle; split <;> simp [hp]
    omega

/-- §5.5.9's `expected_delivered`: the octets `bw` octets a second deliver in `interval`. -/
def expectedDelivered (bw interval : Nat) : Nat :=
  min (bw * interval / nanosecondsPerSecond) u64Max

/-- §5.5.9's `BBR.extra_acked_delivered` and `BBR.extra_acked_interval_start`. -/
structure Aggregation where
  delivered : Nat
  start : Nat
  deriving Repr, DecidableEq

/-- §5.5.9's `UpdateACKAggregation` up to the filter: the new state and the extra octets. -/
def updateAggregation (state : Aggregation) (acknowledged now bw window : Nat) : Aggregation × Nat :=
  if state.delivered ≤ expectedDelivered bw (now - state.start) then
    (⟨acknowledged, now⟩, min acknowledged window)
  else
    (⟨state.delivered + acknowledged, state.start⟩,
      min (state.delivered + acknowledged - expectedDelivered bw (now - state.start)) window)

theorem updateAggregation_le_window (state : Aggregation) (acknowledged now bw window : Nat) :
    (updateAggregation state acknowledged now bw window).2 ≤ window := by
  unfold updateAggregation; split <;> exact Nat.min_le_right _ _

theorem updateAggregation_reset (state : Aggregation) (acknowledged now bw window : Nat)
    (h : state.delivered ≤ expectedDelivered bw (now - state.start)) :
    updateAggregation state acknowledged now bw window = (⟨acknowledged, now⟩, min acknowledged window) := by
  unfold updateAggregation; simp [h]

end Colibri.Quic.BbrModel
