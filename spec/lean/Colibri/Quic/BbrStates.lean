/-!
# BBRv3's draws and volumes (draft-ietf-ccwg-bbr-06 §5.3, §5.6.4, design §8 step 29b.2)

`src/quic/recovery/recovery_bbr/recovery_bbr_wait.zig` draws each bandwidth probe wait, and
`src/quic/recovery/recovery_bbr/recovery_bbr_inflight.zig` computes the volumes BBR's states
compare with the octets in flight. The definitions follow the Zig; the theorems are about them:

- `draw_wait_ge` and `draw_wait_lt`: each wall clock wait is at least 2 s and below 3 s.
- `draw_start_le` and `reno_bound`: each round trip start is 0 or 1, so once the Reno bound is
  63 rounds, a wait lasts 63 or 62 of them (§5.3.3.8.2).
- `headroom_ge_pipe` and `headroom_le_longterm`: the volume with headroom is never below
  `BBR.MinPipeCwnd`, and never above `BBR.inflight_longterm` when that is at least the floor.
- `budget_ge_pipe`: no volume a state compares with is below `BBR.MinPipeCwnd`.

`spec/lean/Vectors.lean` writes `src/quic/recovery/recovery_bbr/bbr_states_vectors.txt` from
them, and a Zig test requires the two files to give the same answers (decision 77).
-/

namespace Colibri.Quic.BbrStates

def word : Nat := 2 ^ 64
def u64Max : Nat := word - 1
def nanosecondsPerSecond : Nat := 1000000000
def gainDenominator : Nat := 100

/-- `constants.recovery.bbr`'s SplitMix64 constants and the draws' bounds. -/
def increment : Nat := 0x9e3779b97f4a7c15
def firstMultiplier : Nat := 0xbf58476d1ce4e5b9
def secondMultiplier : Nat := 0x94d049bb133111eb
def waitMin : Nat := 2000000000
def waitSpread : Nat := 1000000000
def renoRoundsMax : Nat := 63

/-- `mix`, the SplitMix64 finalizer, in 64 bits. -/
def mix (input : Nat) : Nat :=
  let first := ((input ^^^ (input >>> 30)) * firstMultiplier) % word
  let second := ((first ^^^ (first >>> 27)) * secondMultiplier) % word
  second ^^^ (second >>> 31)

/-- `draw`'s input: the caller's value plus the count times the increment, in 64 bits. -/
def mixed (value count : Nat) : Nat := mix ((value + count * increment) % word)

/-- `draw`'s wall clock wait. -/
def waitOf (value count : Nat) : Nat := waitMin + (mixed value count >>> 1) % waitSpread

/-- `draw`'s round trip start. -/
def startOf (value count : Nat) : Nat := mixed value count % 2

theorem draw_wait_ge (value count : Nat) : waitMin ≤ waitOf value count := by
  unfold waitOf; omega

theorem draw_wait_lt (value count : Nat) : waitOf value count < waitMin + waitSpread := by
  unfold waitOf
  have : (mixed value count >>> 1) % waitSpread < waitSpread := Nat.mod_lt _ (by decide)
  omega

theorem draw_start_le (value count : Nat) : startOf value count ≤ 1 := by
  unfold startOf
  have : mixed value count % 2 < 2 := Nat.mod_lt _ (by decide)
  omega

/-- §5.3.3.8.2's `IsRenoCoexistenceProbeTime` bound, in rounds, from `TargetInflight` and the
maximum datagram size. -/
def renoRounds (target datagram : Nat) : Nat := min (target / datagram) renoRoundsMax

/-- Once the Reno bound is 63, a wait that starts at 0 or 1 lasts 63 or 62 rounds. -/
theorem reno_bound (target datagram start : Nat) (hstart : start ≤ 1)
    (hbig : renoRoundsMax ≤ target / datagram) :
    renoRounds target datagram - start = 63 ∨ renoRounds target datagram - start = 62 := by
  unfold renoRounds
  have : min (target / datagram) renoRoundsMax = 63 := by unfold renoRoundsMax at *; omega
  omega

/-- `scale`: `a * b / c`, held at the largest `u64`. -/
def scale (a b c : Nat) : Nat := min (a * b / c) u64Max

/-- `inflight_with_headroom` for a bounded `BBR.inflight_longterm`. -/
def headroom (longterm datagram pipe : Nat) : Nat :=
  max (longterm - max datagram (scale longterm 15 gainDenominator)) pipe

theorem headroom_ge_pipe (longterm datagram pipe : Nat) : pipe ≤ headroom longterm datagram pipe := by
  unfold headroom; omega

theorem headroom_le_longterm (longterm datagram pipe : Nat) (h : pipe ≤ longterm) :
    headroom longterm datagram pipe ≤ longterm := by
  unfold headroom; omega

/-- `quantization_budget`: at least the offload budget and the floor, and 2 datagrams more in
ProbeBW_UP. The Zig's addition saturates at 2^64, which no volume reaches. -/
def budget (cap offload pipe datagram : Nat) (up : Bool) : Nat :=
  max (max cap offload) pipe + (if up then 2 * datagram else 0)

theorem budget_ge_pipe (cap offload pipe datagram : Nat) (up : Bool) :
    pipe ≤ budget cap offload pipe datagram up := by
  unfold budget; split <;> omega

/-- `bdp_multiple` once BBR.min_rtt is known. -/
def bdpMultiple (bw minRtt gain : Nat) : Nat :=
  scale (scale bw minRtt nanosecondsPerSecond) gain gainDenominator

/-- `is_inflight_too_high`: the octets lost are above 2% of the octets in flight. -/
def tooHigh (lost inFlight : Nat) : Bool := decide (lost * gainDenominator > inFlight * 2)

end Colibri.Quic.BbrStates
