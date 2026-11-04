/-!
# NewReno's integer arithmetic (RFC 9002 §7.3 and Appendix B, decision 133 as amended)

`src/quic/recovery/recovery_congestion_newreno.zig` grows and cuts the window in octets. The
definitions follow the Zig line for line; the theorems are about them:

- `grow_conserves`: one acknowledgment's increase in congestion avoidance loses no octet. What
  it adds to the window, times the window, plus the carry it leaves, is the carry before plus
  `max_datagram_size × acknowledged` (Appendix B.5).
- `grow_carry_lt`: the carry stays below the window.
- `grow_le_datagram`: an acknowledgment of at most one window, with the carry below the window,
  adds at most one datagram (§7.3.3: "at most one maximum datagram size for each congestion
  window that is acknowledged").
- `reduced_le` and `afterEvent_ge_minimum`: a congestion event never raises the window, and
  never leaves it below the minimum (Appendix B.6, §7.2).
-/

namespace Colibri.Quic.NewReno

/-- Appendix B.1's kLossReductionFactor = 1 / 2. -/
def lossReductionNumerator : Nat := 1
def lossReductionDenominator : Nat := 2

/-- `grow_in_avoidance`: the octets the window gains, and the carry it keeps. -/
def grow (window datagram carry acknowledged : Nat) : Nat × Nat :=
  ((carry + datagram * acknowledged) / window, (carry + datagram * acknowledged) % window)

/-- `on_congestion_event`'s slow start threshold. -/
def reduced (window : Nat) : Nat := window / lossReductionDenominator * lossReductionNumerator

/-- `on_congestion_event`'s window: `max(ssthresh, kMinimumWindow)`. -/
def afterEvent (window minimum : Nat) : Nat := max (reduced window) minimum

theorem grow_conserves (window datagram carry acknowledged : Nat) :
    (grow window datagram carry acknowledged).1 * window + (grow window datagram carry acknowledged).2
      = carry + datagram * acknowledged := by
  unfold grow
  exact Nat.div_add_mod' _ _

theorem grow_carry_lt (window datagram carry acknowledged : Nat) (h : 0 < window) :
    (grow window datagram carry acknowledged).2 < window := by
  unfold grow
  exact Nat.mod_lt _ h

theorem grow_le_datagram (window datagram carry acknowledged : Nat) (hw : 0 < window)
    (hc : carry < window) (ha : acknowledged ≤ window) :
    (grow window datagram carry acknowledged).1 ≤ datagram := by
  unfold grow
  have hmul : datagram * acknowledged ≤ datagram * window := Nat.mul_le_mul_left _ ha
  have hlt : carry + datagram * acknowledged < (datagram + 1) * window := by
    rw [Nat.add_mul, Nat.one_mul]; omega
  exact Nat.lt_succ_iff.mp ((Nat.div_lt_iff_lt_mul hw).mpr hlt)

theorem reduced_le (window : Nat) : reduced window ≤ window := by
  unfold reduced lossReductionDenominator lossReductionNumerator
  rw [Nat.mul_one]
  exact Nat.div_le_self _ _

theorem afterEvent_ge_minimum (window minimum : Nat) : minimum ≤ afterEvent window minimum := by
  unfold afterEvent
  exact Nat.le_max_right _ _

theorem afterEvent_le (window minimum : Nat) (h : minimum ≤ window) :
    afterEvent window minimum ≤ window := by
  unfold afterEvent
  exact Nat.max_le.mpr ⟨reduced_le window, h⟩

end Colibri.Quic.NewReno
