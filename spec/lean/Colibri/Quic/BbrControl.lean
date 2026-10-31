/-!
# BBRv3's control parameters (draft-ietf-ccwg-bbr-06 §5.6, design §8 step 29b.4)

`src/quic/recovery/recovery_bbr/recovery_bbr_control.zig` sets the pacing rate, the send quantum
and the window. The definitions follow the Zig; the theorems are about them:

- `window_ge_pipe`: the window never falls below `BBR.MinPipeCwnd`.
- `window_le_caps`: and never rises above ProbeRTT's cap or the model's.
- `window_full_le`: once the pipe is full, it is at most `BBR.max_inflight` or the floor.
- `quantum_ge` and `quantum_le`: the send quantum is at least 2 datagrams, and at most 64 KB
  when 2 datagrams fit in it.
- `pacing_le`: the pacing rate is never above the estimate at its gain.

`spec/lean/Vectors.lean` writes `src/quic/recovery/recovery_bbr/bbr_control_vectors.txt` from
them, and a Zig test requires the two files to give the same answers (decision 77).
-/

namespace Colibri.Quic.BbrControl

def u64Max : Nat := 2 ^ 64 - 1
def nanosecondsPerSecond : Nat := 1000000000
def quantumPeriod : Nat := 1000000
def quantumMax : Nat := 65536

/-- `next_window`'s growth, before the floor and the caps. The Zig's saturating additions are
written as additions: no window comes near 2^64 octets. -/
def grown (full : Bool) (window acked maxInflight delivered initial : Nat) : Nat :=
  if full then min (window + acked) maxInflight
  else if window < maxInflight ∨ delivered < initial then window + acked
  else window

/-- `next_window`. -/
def nextWindow (full : Bool) (window acked maxInflight delivered initial pipe probeCap modelCap : Nat) : Nat :=
  min (min (max (grown full window acked maxInflight delivered initial) pipe) probeCap) modelCap

theorem window_ge_pipe (full : Bool) (window acked maxInflight delivered initial pipe probeCap modelCap : Nat)
    (hprobe : pipe ≤ probeCap) (hmodel : pipe ≤ modelCap) :
    pipe ≤ nextWindow full window acked maxInflight delivered initial pipe probeCap modelCap := by
  unfold nextWindow; omega

theorem window_le_caps (full : Bool) (window acked maxInflight delivered initial pipe probeCap modelCap : Nat) :
    nextWindow full window acked maxInflight delivered initial pipe probeCap modelCap ≤ probeCap ∧
      nextWindow full window acked maxInflight delivered initial pipe probeCap modelCap ≤ modelCap := by
  unfold nextWindow
  constructor <;> omega

theorem window_full_le (window acked maxInflight delivered initial pipe probeCap modelCap : Nat) :
    nextWindow true window acked maxInflight delivered initial pipe probeCap modelCap ≤ max maxInflight pipe := by
  unfold nextWindow grown
  simp only [↓reduceIte]
  omega

/-- `set_send_quantum`: 1 ms of the pacing rate, held between 2 datagrams and 64 KB. -/
def quantum (rate datagram : Nat) : Nat :=
  max (min (min (rate * quantumPeriod / nanosecondsPerSecond) u64Max) quantumMax) (2 * datagram)

theorem quantum_ge (rate datagram : Nat) : 2 * datagram ≤ quantum rate datagram := by
  unfold quantum; omega

theorem quantum_le (rate datagram : Nat) (h : 2 * datagram ≤ quantumMax) : quantum rate datagram ≤ quantumMax := by
  unfold quantum; omega

/-- `set_pacing_rate_with_gain`'s rate: `gain` hundredths of `bw`, then 99 hundredths of that. -/
def pacing (bw gain : Nat) : Nat := min (min (bw * gain / 100) u64Max * 99 / 100) u64Max

theorem pacing_le (bw gain : Nat) : pacing bw gain ≤ bw * gain / 100 := by
  unfold pacing; omega

end Colibri.Quic.BbrControl
