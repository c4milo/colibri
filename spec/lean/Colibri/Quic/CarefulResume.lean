/-!
# Careful Resume's arithmetic (RFC 9959, decision 149)

`src/quic/recovery/recovery_resume_phases.zig` computes the jump of §3.3 and the retreat of §3.5
in octets. The definitions follow the Zig line for line; the theorems are about them:

- `jump_le_half` and `jump_le_max`: the jump is at most half the saved window and at most
  max_jump (§3.3: "jump_cwnd is less than or equal to Min(max_jump,(saved_cwnd/2))").
- `retreat_le_half` and `retreat_ge_minimum`: the retreat leaves at most half of PipeSize, held at
  the minimum window, and never below it (§3.5, RFC 9002 §7.2).
- `retreat_le_window`: the retreat never raises the window it starts from.
- `threshold_le_pipe`: the slow start threshold after the retreat is at most PipeSize, for any
  β below 1 (§3.5: "no larger than the most recently measured PipeSize * Beta").
-/

namespace Colibri.Quic.CarefulResume

/-- `constants.protocol.resume_jump_divisor` and `resume_retreat_divisor`. -/
def jumpDivisor : Nat := 2
def retreatDivisor : Nat := 2

/-- `enter_unvalidated`'s jump. -/
def jump (jumpMax saved : Nat) : Nat := min jumpMax (saved / jumpDivisor)

/-- `enter_safe_retreat`'s window: half of PipeSize, held at the minimum, and never above the
window the controller left. -/
def retreat (pipe minimum window : Nat) : Nat := min (max (pipe / retreatDivisor) minimum) window

/-- `leave_safe_retreat`'s threshold: PipeSize times β = numerator / denominator. -/
def threshold (pipe numerator denominator : Nat) : Nat := pipe / denominator * numerator

theorem jump_le_half (jumpMax saved : Nat) : jump jumpMax saved ≤ saved / 2 := by
  unfold jump jumpDivisor
  exact Nat.min_le_right _ _

theorem jump_le_max (jumpMax saved : Nat) : jump jumpMax saved ≤ jumpMax := by
  unfold jump
  exact Nat.min_le_left _ _

theorem retreat_le_half (pipe minimum window : Nat) :
    retreat pipe minimum window ≤ max (pipe / 2) minimum := by
  unfold retreat retreatDivisor
  exact Nat.min_le_left _ _

theorem retreat_ge_minimum (pipe minimum window : Nat) (h : minimum ≤ window) :
    minimum ≤ retreat pipe minimum window := by
  unfold retreat
  exact Nat.le_min.mpr ⟨Nat.le_max_right _ _, h⟩

theorem retreat_le_window (pipe minimum window : Nat) : retreat pipe minimum window ≤ window := by
  unfold retreat
  exact Nat.min_le_right _ _

theorem threshold_le_pipe (pipe numerator denominator : Nat) (h : numerator ≤ denominator) :
    threshold pipe numerator denominator ≤ pipe := by
  unfold threshold
  calc pipe / denominator * numerator ≤ pipe / denominator * denominator := Nat.mul_le_mul_left _ h
    _ ≤ pipe := Nat.div_mul_le_self _ _

end Colibri.Quic.CarefulResume
