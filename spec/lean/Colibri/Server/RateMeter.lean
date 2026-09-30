/-!
# The minimum rate of a request body (decision 110)

`src/server/rate.zig`'s `Meter`, and `src/server/deadline.zig`'s `quota`, which the server checks a
body's rate with. A peer sends a body a unit at a time, an h2 DATA frame or a TLS record of up to
16,384 octets, and a unit arrives whole. The theorems give the exact condition under which a peer
that sends whole units at twice the minimum rate or more is never short in a window: twice the rate
over one window is a whole unit or more, before the quota rounds the octets up
(`never_short_iff`). A quota that rounds up to half a unit is not enough
(`half_unit_quota_short`); one of half a unit and one octet is (`half_unit_and_one_enough`).

The definitions follow `rate.zig` and `deadline.zig` line for line; the theorems are about them.
https://github.com/c4milo/colibri/issues/87 asked for them.
-/

namespace Colibri.Server.RateMeter

/-- `nanoseconds_per_second` in `src/server/constants.zig`. -/
def nanosecondsPerSecond : Nat := 1000000000

/-- `quota` in `deadline.zig`: the octets `rate` octets a second bring over `window` nanoseconds,
rounded up so a window always owes one at least. -/
def quota (rate window : Nat) : Nat :=
  (rate * window + nanosecondsPerSecond - 1) / nanosecondsPerSecond

/-- `Meter` in `rate.zig`: the instant the current window ends, `none` while the meter is stopped,
and the octets the current window has brought. -/
structure Meter where
  windowEnd : Option Nat
  octets : Nat
  deriving DecidableEq, Repr

/-- `start`: the first window ends a grace period and a window after `now`, with nothing counted. -/
def start (now grace window : Nat) : Meter := ⟨some (now + grace + window), 0⟩

/-- `stop`. -/
def stop : Meter := ⟨none, 0⟩

/-- `count`: a stopped meter counts nothing. -/
def Meter.count (meter : Meter) (octets : Nat) : Meter :=
  match meter.windowEnd with
  | none => meter
  | some _ => { meter with octets := meter.octets + octets }

/-- `check_ns`: the instant the meter next looks at a window, the current one's end, or the next
one's once the current one holds its quota. -/
def Meter.checkNs (meter : Meter) (quota window : Nat) : Option Nat :=
  match meter.windowEnd with
  | none => none
  | some e => some (if quota ≤ meter.octets then e + window else e)

/-- `short`: moves the meter to `now`, and says whether a window that ended by then fell short of
`quota`. A window that brought its quota gives way to the next one at its end, with nothing
counted, and the next one has fallen short too when it has ended as well. -/
def Meter.short (meter : Meter) (now quota window : Nat) : Meter × Bool :=
  match meter.windowEnd with
  | none => (meter, false)
  | some e =>
    if now < e then (meter, false)
    else if meter.octets < quota then (meter, true)
    else (⟨some (e + window), 0⟩, decide (e + window ≤ now))

/-! ## The windows

A meter started at `t0` looks at windows that follow one another: the first ends a grace period
and a window after `t0`, and each later one a window after the one before. Window `k` holds the
instants from the end of window `k - 1`, window 0 ending at `t0`, up to its own end and not
including it. The caller moves the meter to each instant with `short` before it counts what
arrived then, so octets that arrive at a window's end count in the next one. -/

/-- The instant window `k` ends; window 0 ends at the start. -/
def windowEnd (t0 grace window k : Nat) : Nat :=
  if k = 0 then t0 else t0 + grace + k * window

/-- A started meter looks first at window 1. -/
theorem start_windowEnd (t0 grace window : Nat) :
    start t0 grace window = ⟨some (windowEnd t0 grace window 1), 0⟩ := by
  simp [start, windowEnd]

/-- After window 1, each window is one window long. -/
theorem windowEnd_succ (t0 grace window k : Nat) (hk : 1 ≤ k) :
    windowEnd t0 grace window (k + 1) = windowEnd t0 grace window k + window := by
  have hk0 : k ≠ 0 := by omega
  simp only [windowEnd, hk0, Nat.add_one_ne_zero, ↓reduceIte, Nat.succ_mul]
  omega

/-- Before a window's end, `short` changes nothing, so what arrives then counts in that window. -/
theorem short_before_end (e octets now quota window : Nat) (h : now < e) :
    Meter.short ⟨some e, octets⟩ now quota window = (⟨some e, octets⟩, false) := by
  simp [Meter.short, h]

/-- A window that ended short of its quota is the verdict of every `short` from its end on. -/
theorem short_of_window_short (e octets now quota window : Nat) (hend : e ≤ now)
    (hshort : octets < quota) :
    (Meter.short ⟨some e, octets⟩ now quota window).2 = true := by
  have hnot : ¬ now < e := by omega
  simp [Meter.short, hnot, hshort]

/-- A window `k` that brought its quota gives way at its end to window `k + 1`, with nothing
counted, so a peer cannot bank octets from one window for the next. -/
theorem short_next_window (t0 grace window k octets now quota : Nat) (hk : 1 ≤ k)
    (hquota : quota ≤ octets) (hend : windowEnd t0 grace window k ≤ now)
    (hbefore : now < windowEnd t0 grace window (k + 1)) :
    Meter.short ⟨some (windowEnd t0 grace window k), octets⟩ now quota window =
      (⟨some (windowEnd t0 grace window (k + 1)), 0⟩, false) := by
  rw [windowEnd_succ t0 grace window k hk] at hbefore ⊢
  have hnot : ¬ now < windowEnd t0 grace window k := by omega
  have hnotshort : ¬ octets < quota := by omega
  have hnotended : ¬ windowEnd t0 grace window k + window ≤ now := by omega
  simp [Meter.short, hnot, hnotshort, hnotended]

/-! ## An honest peer

A peer that sends `peerRate` octets a second from the instant `peerStart`, in units of `unit`
octets, delivers each unit at the first instant by which it has sent the unit's last octet. -/

/-- The instant unit `m` arrives, counting from 1. -/
def arrival (peerRate unit peerStart m : Nat) : Nat :=
  peerStart + (m * unit * nanosecondsPerSecond + peerRate - 1) / peerRate

/-- The units that arrived before instant `t`. -/
def unitsBefore (peerRate unit peerStart t : Nat) : Nat :=
  peerRate * (t - 1 - peerStart) / (unit * nanosecondsPerSecond)

/-- `unitsBefore` counts exactly the units that arrived before `t`: units 1 to `unitsBefore t`. -/
theorem arrival_lt_iff (peerRate unit peerStart m t : Nat) (hp : 0 < peerRate) (hu : 0 < unit)
    (hm : 1 ≤ m) :
    arrival peerRate unit peerStart m < t ↔ m ≤ unitsBefore peerRate unit peerStart t := by
  have hU : 0 < unit * nanosecondsPerSecond := Nat.mul_pos hu (by decide)
  unfold arrival unitsBefore
  rw [Nat.le_div_iff_mul_le hU, Nat.mul_assoc m unit nanosecondsPerSecond]
  have hA : unit * nanosecondsPerSecond ≤ m * (unit * nanosecondsPerSecond) :=
    Nat.le_mul_of_pos_left _ (by omega)
  generalize m * (unit * nanosecondsPerSecond) = A at hA ⊢
  generalize unit * nanosecondsPerSecond = U at hU hA
  constructor
  · intro h
    have hc : (A + peerRate - 1) / peerRate ≤ t - 1 - peerStart := by omega
    rw [Nat.div_le_iff_le_mul_add_pred hp] at hc
    omega
  · intro h
    rcases Nat.eq_zero_or_pos (t - 1 - peerStart) with h0 | h0
    · rw [h0, Nat.mul_zero] at h
      omega
    · have hc : (A + peerRate - 1) / peerRate ≤ t - 1 - peerStart := by
        rw [Nat.div_le_iff_le_mul_add_pred hp]
        omega
      omega

/-- The octets window `k` brings: the units that arrived before its end and not before its start. -/
def brought (peerRate unit peerStart t0 grace window k : Nat) : Nat :=
  unit * (unitsBefore peerRate unit peerStart (windowEnd t0 grace window k) -
    unitsBefore peerRate unit peerStart (windowEnd t0 grace window (k - 1)))

/-- Unit `m` arrives in window `k` exactly when it is one of the units `brought` counts there. -/
theorem arrives_in_iff (peerRate unit peerStart t0 grace window k m : Nat) (hp : 0 < peerRate)
    (hu : 0 < unit) (hm : 1 ≤ m) :
    (windowEnd t0 grace window (k - 1) ≤ arrival peerRate unit peerStart m ∧
      arrival peerRate unit peerStart m < windowEnd t0 grace window k) ↔
    (unitsBefore peerRate unit peerStart (windowEnd t0 grace window (k - 1)) < m ∧
      m ≤ unitsBefore peerRate unit peerStart (windowEnd t0 grace window k)) := by
  have hbefore :=
    arrival_lt_iff peerRate unit peerStart m (windowEnd t0 grace window (k - 1)) hp hu hm
  have hend := arrival_lt_iff peerRate unit peerStart m (windowEnd t0 grace window k) hp hu hm
  constructor
  · rintro ⟨hlo, hhi⟩
    refine ⟨Nat.lt_of_not_le fun hle => ?_, hend.1 hhi⟩
    have := hbefore.2 hle
    omega
  · rintro ⟨hlo, hhi⟩
    refine ⟨Nat.le_of_not_lt fun hlt => ?_, hend.2 hhi⟩
    have := hbefore.1 hlt
    omega

/-- Whole quotients do not lose by adding: `x / d + y / d ≤ (x + y) / d`. -/
theorem div_add_div_le (x y d : Nat) : x / d + y / d ≤ (x + y) / d := by
  rcases Nat.eq_zero_or_pos d with h | h
  · simp [h]
  · rw [Nat.le_div_iff_mul_le h, Nat.add_mul]
    exact Nat.add_le_add (Nat.div_mul_le_self x d) (Nat.div_mul_le_self y d)

/-- Between two instants after the peer started, at least the whole units it sends in the time
between them arrive. -/
theorem unitsBefore_gap (peerRate unit peerStart a b : Nat) (hs : peerStart < a) (hab : a ≤ b) :
    peerRate * (b - a) / (unit * nanosecondsPerSecond) ≤
      unitsBefore peerRate unit peerStart b - unitsBefore peerRate unit peerStart a := by
  unfold unitsBefore
  have hsplit : b - 1 - peerStart = (a - 1 - peerStart) + (b - a) := by omega
  rw [hsplit, Nat.mul_add]
  have := div_add_div_le (peerRate * (a - 1 - peerStart)) (peerRate * (b - a))
    (unit * nanosecondsPerSecond)
  omega

/-- Each window brings at least the whole units the peer sends in a window's length, when the peer
starts before the grace period ends. -/
theorem brought_ge (peerRate unit peerStart t0 grace window k : Nat) (hs : peerStart < t0 + grace)
    (hk : 1 ≤ k) :
    unit * (peerRate * window / (unit * nanosecondsPerSecond)) ≤
      brought peerRate unit peerStart t0 grace window k := by
  unfold brought
  apply Nat.mul_le_mul_left
  rcases Nat.lt_or_ge 1 k with hk2 | hk1
  · -- Window k, after the first, is one window long and starts after the peer started.
    have hprev : 1 ≤ k - 1 := by omega
    have hend : windowEnd t0 grace window k = windowEnd t0 grace window (k - 1) + window := by
      have := windowEnd_succ t0 grace window (k - 1) hprev
      rwa [Nat.sub_add_cancel hk] at this
    have hstart : peerStart < windowEnd t0 grace window (k - 1) := by
      have hk0 : k - 1 ≠ 0 := by omega
      simp only [windowEnd, hk0, ↓reduceIte]
      omega
    have := unitsBefore_gap peerRate unit peerStart (windowEnd t0 grace window (k - 1))
      (windowEnd t0 grace window k) hstart (by omega)
    have hdiff : windowEnd t0 grace window k - windowEnd t0 grace window (k - 1) = window := by
      omega
    rwa [hdiff] at this
  · -- Window 1 runs from t0 for a grace period and a window.
    have hk1' : k = 1 := by omega
    subst hk1'
    simp only [Nat.sub_self]
    have hfirst : windowEnd t0 grace window 1 = t0 + grace + window := by simp [windowEnd]
    have hzero : windowEnd t0 grace window 0 = t0 := by simp [windowEnd]
    rw [hfirst, hzero]
    rcases Nat.lt_or_ge peerStart t0 with hbefore | hafter
    · -- The peer started before the meter: the first window lasts more than a window.
      have := unitsBefore_gap peerRate unit peerStart t0 (t0 + grace + window) hbefore (by omega)
      have hmore : peerRate * window ≤ peerRate * (t0 + grace + window - t0) :=
        Nat.mul_le_mul_left _ (by omega)
      have := Nat.div_le_div_right (c := unit * nanosecondsPerSecond) hmore
      omega
    · -- The peer started with the meter or after it: nothing arrived before the meter started.
      have hnone : unitsBefore peerRate unit peerStart t0 = 0 := by
        unfold unitsBefore
        have : t0 - 1 - peerStart = 0 := by omega
        simp [this]
      rw [hnone, Nat.sub_zero]
      unfold unitsBefore
      apply Nat.div_le_div_right
      exact Nat.mul_le_mul_left _ (by omega)

/-- The arithmetic of the bound. Once twice the rate over one window is a whole unit or more, the
whole units that twice the rate sends in a window hold the rounded quota. -/
theorem quota_le_units (rate window unit : Nat) (hu : 0 < unit)
    (h : unit * nanosecondsPerSecond ≤ 2 * (rate * window)) :
    quota rate window ≤ unit * (2 * (rate * window) / (unit * nanosecondsPerSecond)) := by
  have hU : 0 < unit * nanosecondsPerSecond := Nat.mul_pos hu (by decide)
  have hj : 1 ≤ 2 * (rate * window) / (unit * nanosecondsPerSecond) :=
    (Nat.le_div_iff_mul_le hU).2 (by omega)
  have hlo := Nat.div_mul_le_self (2 * (rate * window)) (unit * nanosecondsPerSecond)
  have hhi := Nat.lt_mul_div_succ (2 * (rate * window)) hU
  unfold quota
  generalize 2 * (rate * window) / (unit * nanosecondsPerSecond) = j at hj hlo hhi ⊢
  generalize hP : rate * window = P at h hlo hhi ⊢
  -- Every product left is a multiple of the unit's octets times a second.
  have e1 : j * (unit * nanosecondsPerSecond) = unit * j * nanosecondsPerSecond := by
    rw [Nat.mul_comm j, Nat.mul_right_comm]
  have e2 : unit * nanosecondsPerSecond * (j + 1) =
      unit * j * nanosecondsPerSecond + unit * nanosecondsPerSecond := by
    rw [Nat.mul_succ, Nat.mul_right_comm]
  have hunit : unit ≤ unit * j := Nat.le_mul_of_pos_right _ hj
  rw [e1] at hlo
  rw [e2] at hhi
  generalize unit * j = M at hunit hlo hhi ⊢
  simp only [nanosecondsPerSecond] at *
  omega

/-- Sufficiency: when twice the rate over one window is a whole unit or more, a peer that sends
whole units at twice the rate or more, and starts before the grace period ends, brings every window
its quota. -/
theorem never_short (rate window grace unit peerRate peerStart t0 k : Nat) (hu : 0 < unit)
    (hpeer : 2 * rate ≤ peerRate) (hs : peerStart < t0 + grace) (hk : 1 ≤ k)
    (h : unit * nanosecondsPerSecond ≤ 2 * (rate * window)) :
    quota rate window ≤ brought peerRate unit peerStart t0 grace window k := by
  calc quota rate window
      ≤ unit * (2 * (rate * window) / (unit * nanosecondsPerSecond)) :=
        quota_le_units rate window unit hu h
    _ ≤ unit * (peerRate * window / (unit * nanosecondsPerSecond)) := by
        apply Nat.mul_le_mul_left
        apply Nat.div_le_div_right
        rw [← Nat.mul_assoc]
        exact Nat.mul_le_mul_right window hpeer
    _ ≤ brought peerRate unit peerStart t0 grace window k :=
        brought_ge peerRate unit peerStart t0 grace window k hs hk

/-- A window owes one octet at least. -/
theorem quota_pos (rate window : Nat) (hr : 0 < rate) (hw : 0 < window) :
    0 < quota rate window := by
  have := Nat.mul_pos hr hw
  unfold quota nanosecondsPerSecond
  generalize rate * window = P at this ⊢
  omega

/-- Necessity: when twice the rate over one window is less than a whole unit, a peer at twice the
rate that starts in the grace period's last nanosecond brings nothing in the first window, which
falls short. -/
theorem first_window_short (rate window grace unit t0 : Nat) (hr : 0 < rate) (hw : 0 < window)
    (hg : 0 < grace) (h : 2 * (rate * window) < unit * nanosecondsPerSecond) :
    brought (2 * rate) unit (t0 + grace - 1) t0 grace window 1 < quota rate window := by
  have hq := quota_pos rate window hr hw
  have hnone : unitsBefore (2 * rate) unit (t0 + grace - 1) (windowEnd t0 grace window 1) = 0 := by
    unfold unitsBefore
    have : windowEnd t0 grace window 1 - 1 - (t0 + grace - 1) = window := by
      simp [windowEnd]
      omega
    rw [this, Nat.mul_assoc]
    exact Nat.div_eq_of_lt h
  simp [brought, hnone]
  exact hq

/-- The exact condition: every peer that sends whole units at twice the rate or more, and starts
before the grace period ends, brings every window its quota if and only if twice the rate over
one window is a whole unit or more. -/
theorem never_short_iff (rate window grace unit t0 : Nat) (hr : 0 < rate) (hw : 0 < window)
    (hg : 0 < grace) (hu : 0 < unit) :
    (∀ peerRate peerStart k, 2 * rate ≤ peerRate → peerStart < t0 + grace → 1 ≤ k →
      quota rate window ≤ brought peerRate unit peerStart t0 grace window k) ↔
    unit * nanosecondsPerSecond ≤ 2 * (rate * window) := by
  constructor
  · intro hall
    apply Nat.le_of_not_lt
    intro hlt
    have hsome := hall (2 * rate) (t0 + grace - 1) 1 (Nat.le_refl _) (by omega) (Nat.le_refl _)
    have hnone := first_window_short rate window grace unit t0 hr hw hg hlt
    omega
  · intro h peerRate peerStart k hpeer hs hk
    exact never_short rate window grace unit peerRate peerStart t0 k hu hpeer hs hk h

/-- A quota that rounds up to half a unit is not enough. At 8,192 octets a second over windows of
999,999,999 nanoseconds a window owes 8,192 octets, half of 16,384, yet a peer at twice the rate
can bring its first window nothing. -/
theorem half_unit_quota_short :
    2 * quota 8192 999999999 = 16384 ∧
      brought (2 * 8192) 16384 (0 + 1 - 1) 0 1 999999999 1 < quota 8192 999999999 :=
  ⟨by decide, first_window_short 8192 999999999 1 16384 0 (by decide) (by decide) (by decide)
    (by decide)⟩

/-- A quota of half a unit and one octet or more is enough. -/
theorem half_unit_and_one_enough (rate window unit : Nat)
    (h : unit ≤ 2 * (quota rate window - 1)) :
    unit * nanosecondsPerSecond ≤ 2 * (rate * window) := by
  unfold quota nanosecondsPerSecond at *
  generalize rate * window = P at h ⊢
  omega

end Colibri.Server.RateMeter
