/-!
# BBRv3's response to loss (draft-ietf-ccwg-bbr-06 §5.5.10, design §8 step 29b.3)

`src/quic/recovery/recovery_bbr/recovery_bbr_loss.zig` lowers BBR's bounds on loss. The
definitions follow the Zig; the theorems are about them:

- `atLoss_lt`: when a lost packet's losses are above 2% of what was in flight,
  `InflightAtLoss` puts the crossing inside or before that packet, never past it.
- `atLoss_nonneg`: the crossing is never below 0.
- `lower_ge_latest` and `lower_le`: one round with loss lowers the short-term model to at least
  what the round delivered, and never raises it past the larger of the two.
- `lower_ge_beta`: and never below 0.7 of what it was, up to the rounding of hundredths.

`spec/lean/Vectors.lean` writes `src/quic/recovery/recovery_bbr/bbr_loss_vectors.txt` from them,
and a Zig test requires the two files to give the same answers (decision 77).
-/

namespace Colibri.Quic.BbrLoss

/-- §5.5.10.2's `InflightAtLoss` in hundredths, from `RS.tx_in_flight`, `RS.lost` and the
packet's size, floored as the Zig's `@divFloor` floors, and held at 0. -/
def atLoss (tx lost size : Int) : Int :=
  max (tx - size + (2 * (tx - size) - 100 * (lost - size)) / 98) 0

/-- `IsInflightTooHigh`: the octets lost are above 2% of the octets in flight. -/
def tooHigh (tx lost : Int) : Prop := 2 * tx < 100 * lost

theorem atLoss_lt (tx lost size : Int) (hsize : 0 < size) (hlost : size ≤ lost)
    (hhigh : tooHigh tx lost) (htx : size ≤ tx) : atLoss tx lost size < tx := by
  unfold atLoss tooHigh at *
  omega

theorem atLoss_nonneg (tx lost size : Int) : 0 ≤ atLoss tx lost size := by
  unfold atLoss; omega

/-- §5.5.10.3's `LossLowerBounds` for one of the two bounds: the larger of the round's
delivery and 0.7 of the bound. -/
def lower (latest bound : Nat) : Nat := max latest (bound * 70 / 100)

theorem lower_ge_latest (latest bound : Nat) : latest ≤ lower latest bound := by
  unfold lower; omega

theorem lower_le (latest bound : Nat) : lower latest bound ≤ max latest bound := by
  unfold lower; omega

theorem lower_ge_beta (latest bound : Nat) : bound * 70 / 100 ≤ lower latest bound := by
  unfold lower; omega

end Colibri.Quic.BbrLoss
