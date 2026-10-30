/-!
# Delivery rate samples (draft-ietf-ccwg-bbr-06 §4.1, design §8 step 29a)

`src/quic/recovery/recovery_delivery.zig` gives one rate sample for each ACK frame, from the
octets delivered over the longer of two intervals: the one over which the packets went out, and
the one over which their acknowledgments came back (§4.1.1.2.4). The definitions follow the Zig
line for line; the theorems are about them:

- `sample_le_send` and `sample_le_ack`: a sample is never above the send rate or the ACK rate,
  each taken over the octets the sample counts.
- `sample_interval`: a sample's interval is never shorter than min_rtt (§4.1.2.3).
- `mark_pos`: the mark of an application limit is never 0, which the Zig reads as "no mark"
  (§4.1.2.4).
- `cleared_past` and `held_until`: the mark clears once the octets delivered pass it, and not
  before.

The Zig adds with saturation, at 2^64 octets, which no connection delivers; these definitions
add without it. `spec/lean/Vectors.lean` writes `src/quic/recovery/delivery_vectors.txt` from
them, and a Zig test requires `recovery_delivery.zig` to give the same answers (decision 77).
-/

namespace Colibri.Quic.DeliveryRate

/-- `constants.nanoseconds_per_second` in `src/core/constants.zig`. -/
def nanosecondsPerSecond : Nat := 1000000000
/-- The largest `u64`, at which `rate_of` saturates. -/
def rateMax : Nat := 2 ^ 64 - 1

/-- `rate_of`: octets a second, from octets over nanoseconds. -/
def rateOf (delivered interval : Nat) : Nat :=
  min (delivered * nanosecondsPerSecond / interval) rateMax

/-- The fields of `Sample` the theorems read. -/
structure Sample where
  rate : Nat
  delivered : Nat
  interval : Nat
  deriving Repr, DecidableEq

/-- `Delivery.on_ack`'s sample, from the octets delivered since the newest packet went out, its
send interval, its ACK interval and min_rtt. -/
def sample (delivered sendElapsed ackElapsed minRtt : Nat) : Option Sample :=
  if max sendElapsed ackElapsed < minRtt ∨ max sendElapsed ackElapsed = 0 then none
  else some ⟨rateOf delivered (max sendElapsed ackElapsed), delivered, max sendElapsed ackElapsed⟩

/-- A longer interval never gives a higher rate. -/
theorem rateOf_antitone (delivered : Nat) {short long : Nat} (hshort : 0 < short)
    (hle : short ≤ long) : rateOf delivered long ≤ rateOf delivered short := by
  unfold rateOf
  have : delivered * nanosecondsPerSecond / long ≤ delivered * nanosecondsPerSecond / short :=
    Nat.div_le_div_left hle hshort
  omega

/-- A sample is never above the send rate (§4.1.1.2.4). -/
theorem sample_le_send {delivered sendElapsed ackElapsed minRtt : Nat} {s : Sample}
    (h : sample delivered sendElapsed ackElapsed minRtt = some s) (hsend : 0 < sendElapsed) :
    s.rate ≤ rateOf delivered sendElapsed := by
  unfold sample at h
  split at h
  · exact absurd h (by simp)
  · cases h
    exact rateOf_antitone delivered hsend (Nat.le_max_left _ _)

/-- A sample is never above the ACK rate (§4.1.1.2.4). -/
theorem sample_le_ack {delivered sendElapsed ackElapsed minRtt : Nat} {s : Sample}
    (h : sample delivered sendElapsed ackElapsed minRtt = some s) (hack : 0 < ackElapsed) :
    s.rate ≤ rateOf delivered ackElapsed := by
  unfold sample at h
  split at h
  · exact absurd h (by simp)
  · cases h
    exact rateOf_antitone delivered hack (Nat.le_max_right _ _)

/-- A sample's interval is never shorter than min_rtt, nor 0 (§4.1.2.3). -/
theorem sample_interval {delivered sendElapsed ackElapsed minRtt : Nat} {s : Sample}
    (h : sample delivered sendElapsed ackElapsed minRtt = some s) :
    minRtt ≤ s.interval ∧ 0 < s.interval := by
  unfold sample at h
  split at h
  · exact absurd h (by simp)
  · next hkeep =>
    cases h
    simp only
    omega

/-- §4.1.2.4's `MarkConnectionAppLimited`: `max(C.delivered + C.inflight, 1)`. -/
def mark (delivered inFlight : Nat) : Nat := max (delivered + inFlight) 1

theorem mark_pos (delivered inFlight : Nat) : 0 < mark delivered inFlight := by
  unfold mark; omega

/-- §4.1.2.3's `GenerateRateSample`: the mark after an ACK frame raised `delivered`. -/
def cleared (delivered limit : Nat) : Nat :=
  if limit ≠ 0 ∧ delivered > limit then 0 else limit

/-- The mark clears once the octets delivered pass it. -/
theorem cleared_past {delivered limit : Nat} (h : limit < delivered) : cleared delivered limit = 0 := by
  unfold cleared; split <;> omega

/-- The mark holds while the octets delivered do not pass it. -/
theorem held_until {delivered limit : Nat} (h : delivered ≤ limit) :
    cleared delivered limit = limit := by
  unfold cleared; split <;> omega

end Colibri.Quic.DeliveryRate
