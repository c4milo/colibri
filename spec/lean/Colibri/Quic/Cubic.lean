/-!
# CUBIC's integer arithmetic (RFC 9438, decision 133)

`src/quic/recovery/recovery_cubic.zig` computes RFC 9438 §4.2's curve in octets and microseconds,
with an integer cube root, because colibri reads no floating point on a protocol path. The
definitions follow the Zig line for line; the theorems are about them:

- `cubeRoot_spec`: the cube root is exact. For every value below 2^129 it gives the `r` with
  `r³ ≤ v < (r + 1)³`.
- `windowAt_start`: a stage's curve starts at or above the window it starts from, so CUBIC never
  lowers the window when a stage starts (§4.2: "cwnd_epoch").
- `target_bounds`: the target lies between the window and 1.5 times it (§4.2).
- `reduced_le` and `wMaxAfter_le`: the decrease and fast convergence never raise the window
  (§4.6, §4.7).

`spec/lean/Vectors.lean` writes `src/quic/recovery/cubic_vectors.txt` from these definitions,
and a Zig test requires `recovery_cubic.zig` to give the same answers (decision 77).
-/

namespace Colibri.Quic.Cubic

/-- `cubic.microseconds_per_second` in `src/quic/constants_cubic.zig`. -/
def microsecondsPerSecond : Nat := 1000000
/-- §5.1's C = 4 / 10. -/
def cNumerator : Nat := 4
def cDenominator : Nat := 10
/-- §4.6's β = 7 / 10, and §4.7's (1 + β) / 2 = 17 / 20. -/
def betaNumerator : Nat := 7
def betaDenominator : Nat := 10
def convergenceNumerator : Nat := 17
def convergenceDenominator : Nat := 20
/-- `cubic.elapsed_us_max`, the longest `t − K` the curve counts. -/
def elapsedMax : Nat := 2 ^ 34
/-- `cubic.cube_root_bits`. -/
def cubeRootBits : Nat := 43

def cube (n : Nat) : Nat := n * n * n

/-- `cube_root`'s loop: each pass decides one bit of the root, from the highest. The Zig sets the
bit with `|`; the root's lower bits are all clear when a bit is set, so `+` is the same. -/
def cubeRootStep (v root : Nat) : Nat → Nat
  | 0 => root
  | bit + 1 =>
    let candidate := root + 2 ^ bit
    if cube candidate ≤ v then cubeRootStep v candidate bit else cubeRootStep v root bit

/-- `cube_root`. -/
def cubeRoot (v : Nat) : Nat := cubeRootStep v 0 cubeRootBits

/-- The loop keeps `root³ ≤ v < (root + 2^bit)³`, and ends with `bit = 0`. -/
theorem cubeRootStep_spec (v : Nat) : ∀ (bit root : Nat),
    cube root ≤ v → v < cube (root + 2 ^ bit) →
    cube (cubeRootStep v root bit) ≤ v ∧ v < cube (cubeRootStep v root bit + 1) := by
  intro bit
  induction bit with
  | zero =>
    intro root hlow hhigh
    simpa [cubeRootStep] using And.intro hlow hhigh
  | succ bit ih =>
    intro root hlow hhigh
    have hsplit : root + 2 ^ (bit + 1) = (root + 2 ^ bit) + 2 ^ bit := by
      rw [Nat.pow_succ]; omega
    simp only [cubeRootStep]
    split
    · next hfits => exact ih (root + 2 ^ bit) hfits (by rw [← hsplit]; exact hhigh)
    · next hover => exact ih root hlow (by omega)

/-- The cube root is exact for every value below 2^129, the 128 bits `cube_root` takes. -/
theorem cubeRoot_spec (v : Nat) (hv : v < 2 ^ (3 * cubeRootBits)) :
    cube (cubeRoot v) ≤ v ∧ v < cube (cubeRoot v + 1) := by
  apply cubeRootStep_spec v cubeRootBits 0 (by simp [cube])
  have : cube (0 + 2 ^ cubeRootBits) = 2 ^ (3 * cubeRootBits) := by
    simp only [cube, Nat.zero_add, ← Nat.pow_add]; congr 1
  rw [this]; exact hv

/-- `Curve.of`'s K: cbrt((W_max − window) × 10^18 / (C × datagram)) microseconds, 0 when W_max is
at or below the window. -/
def kUs (wMax window datagram : Nat) : Nat :=
  if wMax ≤ window then 0
  else cubeRoot ((wMax - window) * cDenominator * microsecondsPerSecond ^ 3 / (cNumerator * datagram))

/-- `Curve.of`'s W_max: the window when the one given is at or below it. -/
def curveWMax (wMax window : Nat) : Nat := if wMax ≤ window then window else wMax

/-- `window_at`: W_max + C × (t − K)³ × datagram, in octets, with `t` and K held to `elapsedMax`.
Zig computes the cube signed and divides it with `@divTrunc`, which truncates toward zero: so
before K the drop is the floor of the positive cube's, and the window is 0 rather than negative. -/
def windowAt (wMax kUs datagram t : Nat) : Nat :=
  let elapsed := min t elapsedMax
  let k := min kUs elapsedMax
  let divisor := cDenominator * microsecondsPerSecond ^ 3
  if k ≤ elapsed then wMax + cube (elapsed - k) * cNumerator * datagram / divisor
  else wMax - cube (k - elapsed) * cNumerator * datagram / divisor

/-- `target`: W_cubic(t + RTT), held between the window and 1.5 times it. -/
def target (wMax kUs datagram t rtt window : Nat) : Nat :=
  let ceiling := window / 2 * 3
  max window (min (windowAt wMax kUs datagram (t + rtt)) (max window ceiling))

/-- `reduced`: β of the window. -/
def reduced (window : Nat) : Nat := window / betaDenominator * betaNumerator

/-- `w_max_after`: fast convergence lowers W_max to (1 + β) / 2 of the window when it fell short. -/
def wMaxAfter (window wMaxBefore : Nat) : Nat :=
  if window < wMaxBefore then window / convergenceDenominator * convergenceNumerator else window

/-- The target lies between the window and 1.5 times it, or is the window when that is less. -/
theorem target_bounds (wMax kUs datagram t rtt window : Nat) :
    window ≤ target wMax kUs datagram t rtt window ∧
    target wMax kUs datagram t rtt window ≤ max window (window / 2 * 3) := by
  dsimp only [target]
  generalize windowAt wMax kUs datagram (t + rtt) = ahead
  omega

/-- The decrease never raises the window. -/
theorem reduced_le (window : Nat) : reduced window ≤ window := by
  unfold reduced betaDenominator betaNumerator; omega

/-- Fast convergence never sets W_max above the window it replaces. -/
theorem wMaxAfter_le (window wMaxBefore : Nat) : wMaxAfter window wMaxBefore ≤ window := by
  unfold wMaxAfter convergenceDenominator convergenceNumerator; split <;> omega

/-- A stage's curve starts at or above the window it starts from: with K at most `elapsedMax`, the
cube K³ that K's root rounds down to brings W_max back down by no more than W_max − window. -/
theorem windowAt_start (wMax window datagram : Nat) (hgt : window < wMax)
    (hk : kUs wMax window datagram ≤ elapsedMax)
    (hv : (wMax - window) * cDenominator * microsecondsPerSecond ^ 3 / (cNumerator * datagram) <
      2 ^ (3 * cubeRootBits)) :
    window ≤ windowAt wMax (kUs wMax window datagram) datagram 0 := by
  have hnot : ¬ wMax ≤ window := by omega
  generalize hx : (wMax - window) * cDenominator * microsecondsPerSecond ^ 3 / (cNumerator * datagram) = x at hv
  have hroot : cube (cubeRoot x) ≤ x := (cubeRoot_spec x hv).1
  have hkdef : kUs wMax window datagram = cubeRoot x := by simp [kUs, hnot, hx]
  rw [hkdef] at hk ⊢
  generalize hkk : cubeRoot x = k at hroot hk
  -- K³ × C × datagram ≤ x × C × datagram ≤ (W_max − window) × 10 × 10^18.
  have hmul : cube k * (cNumerator * datagram) ≤ (wMax - window) * cDenominator * microsecondsPerSecond ^ 3 := by
    calc cube k * (cNumerator * datagram) ≤ x * (cNumerator * datagram) := Nat.mul_le_mul_right _ hroot
      _ ≤ _ := by rw [← hx]; exact Nat.div_mul_le_self _ _
  have hdrop : cube k * cNumerator * datagram / (cDenominator * microsecondsPerSecond ^ 3) ≤ wMax - window := by
    apply Nat.div_le_of_le_mul
    rw [Nat.mul_assoc (cube k)]
    calc cube k * (cNumerator * datagram) ≤ (wMax - window) * cDenominator * microsecondsPerSecond ^ 3 := hmul
      _ = cDenominator * microsecondsPerSecond ^ 3 * (wMax - window) := by
        rw [Nat.mul_assoc, Nat.mul_comm]
  have hmin : min k elapsedMax = k := Nat.min_eq_left hk
  dsimp only [windowAt]
  rw [Nat.zero_min, hmin]
  split
  · exact Nat.le_add_right_of_le (Nat.le_of_lt hgt)
  · rw [Nat.sub_zero]; omega

end Colibri.Quic.Cubic
