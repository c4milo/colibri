import Colibri.Wire.Varint

/-!
# The packet number (RFC 9000 §17.1, Appendix A.2 and A.3)

A packet number is 0 to 2^62 - 1 (§12.3), and a header carries its 1 to 4 least significant
octets. The sender picks how many from the largest number the peer has acknowledged (Appendix
A.2), and the receiver rebuilds the rest from the largest number it has processed (Appendix A.3).
These definitions follow `encode` in `src/quic/packet/packet_number.zig` and `decode` in
`src/crypto/packet_number.zig` over natural numbers; the theorems are about them
(https://github.com/c4milo/colibri/issues/52).

What is proved:
- `encode_range` and `encode_shortest`: the length `encode` picks represents more than twice the
  range of unacknowledged numbers, as §17.1 requires, and no shorter length does.
- `encode_none`: `encode` refuses exactly when four octets do not represent twice that range.
- `decode_closest`: `decode` rebuilds every number within half a window of the one expected.
- `decode_encode`: a receiver that has processed at least what the sender saw acknowledged, and no
  number at or past the one sent, rebuilds the number `encode` truncated.
- `decode_bound` and `decode_field`: whatever field arrives, `decode` gives a packet number, and
  that number ends in the octets the field carried.
- `field_read_write`: the field's octets, most significant first, read back to its value.
-/

namespace Colibri.Quic.PacketNumber

open Colibri.Wire.Varint (digits fromDigits fromDigits_digits)

/-- §12.3: the largest packet number. `packet_number_max` in `constants.zig`. -/
def numberMax : Nat := 2 ^ 62 - 1

/-- §17.1: the count of values `len` octets carry. `window_of` in `packet_number.zig`. -/
def window (len : Nat) : Nat := 256 ^ len

/-- Appendix A.2: the numbers the peer has not acknowledged, up to `full`. Before any
acknowledgment every number from 0 counts, which §17.1's rule to send the full number needs. -/
def unacknowledged (full : Nat) : Option Nat → Nat
  | some acked => full - acked
  | none => full + 1

/-- Appendix A.2: the Packet Number field for `full`, as its value and its length: the shortest
of 1 to 4 octets whose window exceeds twice the unacknowledged range, or `none` when four octets
do not. `encode` in `src/quic/packet/packet_number.zig`. -/
def encode (full : Nat) (acked : Option Nat) : Option (Nat × Nat) :=
  let range := 2 * unacknowledged full acked
  if range < window 1 then some (full % window 1, 1)
  else if range < window 2 then some (full % window 2, 2)
  else if range < window 3 then some (full % window 3, 3)
  else if range < window 4 then some (full % window 4, 4)
  else none

/-- §17.1: the number expected next, one past the largest processed, or 0 before any. -/
def expected : Option Nat → Nat
  | some largest => largest + 1
  | none => 0

/-- Appendix A.3: the packet number closest to the one expected whose `len` least significant
octets are `value`, kept within 0 and `numberMax`. `decode` in `src/crypto/packet_number.zig`,
which builds `candidate` with a mask where this divides. -/
def decode (largest : Option Nat) (value len : Nat) : Nat :=
  let w := window len
  let half := w / 2
  let e := expected largest
  let candidate := e / w * w + value
  if candidate > numberMax then candidate - w
  else if candidate + half ≤ e ∧ candidate + w ≤ numberMax then candidate + w
  else if candidate > e + half ∧ candidate ≥ w then candidate - w
  else candidate

/-- §17.1: the Packet Number field's octets, most significant first. `write` in
`src/quic/packet/packet_number.zig`. -/
def field (value len : Nat) : List Nat := digits len value

theorem numberMax_eq : numberMax = 4611686018427387903 := by decide

theorem unacknowledged_eq (full : Nat) (acked : Option Nat)
    (hacked : ∀ a, acked = some a → a < full) :
    unacknowledged full acked = full + 1 - expected acked := by
  cases acked with
  | none => rfl
  | some a => have := hacked a rfl; simp only [unacknowledged, expected]; omega

/-- §17.1: the length `encode` picks is 1 to 4 octets, carries the low octets of `full`, and
represents more than twice the unacknowledged range. -/
theorem encode_range (full : Nat) (acked : Option Nat) (value len : Nat)
    (h : encode full acked = some (value, len)) :
    1 ≤ len ∧ len ≤ 4 ∧ value = full % window len ∧
      2 * unacknowledged full acked < window len := by
  simp only [encode] at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h; omega
  · split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h; omega
    · split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h; omega
      · split at h
        · simp only [Option.some.injEq, Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h; omega
        · simp at h

theorem window_mono (a b : Nat) (h : a ≤ b) : window a ≤ window b :=
  Nat.pow_le_pow_right (by decide) h

/-- No length shorter than the one `encode` picks represents twice the unacknowledged range. -/
theorem encode_shortest (full : Nat) (acked : Option Nat) (value len shorter : Nat)
    (h : encode full acked = some (value, len)) (hshorter : 1 ≤ shorter ∧ shorter < len) :
    window shorter ≤ 2 * unacknowledged full acked := by
  simp only [encode] at h
  have hw := window_mono shorter
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h; omega
  · split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      have := hw 1 (by omega); omega
    · split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        have := hw 2 (by omega); omega
      · split at h
        · simp only [Option.some.injEq, Prod.mk.injEq] at h
          have := hw 3 (by omega); omega
        · simp at h

/-- §17.1: `encode` refuses exactly when four octets do not represent twice the range. -/
theorem encode_none (full : Nat) (acked : Option Nat) :
    encode full acked = none ↔ window 4 ≤ 2 * unacknowledged full acked := by
  simp only [encode]
  have h12 := window_mono 1 4 (by decide)
  have h22 := window_mono 2 4 (by decide)
  have h32 := window_mono 3 4 (by decide)
  split <;> (try split) <;> (try split) <;> (try split) <;> simp <;> omega

/-- The four windows, with 2^62 a multiple of each. -/
theorem window_cases (len : Nat) (hlen : 1 ≤ len ∧ len ≤ 4) :
    window len = 256 ∨ window len = 65536 ∨ window len = 16777216 ∨ window len = 4294967296 := by
  have : len = 1 ∨ len = 2 ∨ len = 3 ∨ len = 4 := by omega
  rcases this with rfl | rfl | rfl | rfl <;> decide

/-- Appendix A.3: `decode` rebuilds every packet number within half a window of the one
expected, counting half a window above it and less than half below it. -/
theorem decode_closest (largest : Option Nat) (len full : Nat) (hlen : 1 ≤ len ∧ len ≤ 4)
    (hlargest : ∀ l, largest = some l → l ≤ numberMax) (hfull : full ≤ numberMax)
    (hlow : expected largest < full + window len / 2)
    (hhigh : full ≤ expected largest + window len / 2) :
    decode largest (full % window len) len = full := by
  have he : expected largest ≤ numberMax + 1 := by
    cases largest with
    | none => simp [expected]
    | some l => have := hlargest l rfl; simp only [expected]; omega
  simp only [decode]
  generalize expected largest = e at *
  rw [numberMax_eq] at *
  rcases window_cases len hlen with hw | hw | hw | hw <;> rw [hw] at hlow hhigh ⊢ <;>
    split <;> (try split) <;> (try split) <;> omega

/-- §12.3: whatever field arrives, `decode` gives a number from 0 to 2^62 - 1. -/
theorem decode_bound (largest : Option Nat) (value len : Nat) (hlen : 1 ≤ len ∧ len ≤ 4)
    (hlargest : ∀ l, largest = some l → l ≤ numberMax) (hvalue : value < window len) :
    decode largest value len ≤ numberMax := by
  have he : expected largest ≤ numberMax + 1 := by
    cases largest with
    | none => simp [expected]
    | some l => have := hlargest l rfl; simp only [expected]; omega
  simp only [decode]
  generalize expected largest = e at *
  rw [numberMax_eq] at *
  rcases window_cases len hlen with hw | hw | hw | hw <;> rw [hw] at hvalue ⊢ <;>
    split <;> (try split) <;> (try split) <;> omega

/-- §17.1: the number `decode` gives ends in the octets the field carried. -/
theorem decode_field (largest : Option Nat) (value len : Nat) (hlen : 1 ≤ len ∧ len ≤ 4)
    (hlargest : ∀ l, largest = some l → l ≤ numberMax) (hvalue : value < window len) :
    decode largest value len % window len = value := by
  have he : expected largest ≤ numberMax + 1 := by
    cases largest with
    | none => simp [expected]
    | some l => have := hlargest l rfl; simp only [expected]; omega
  simp only [decode]
  generalize expected largest = e at *
  rw [numberMax_eq] at *
  rcases window_cases len hlen with hw | hw | hw | hw <;> rw [hw] at hvalue ⊢ <;>
    split <;> (try split) <;> (try split) <;> omega

/-- §17.1: a receiver that has processed at least the number the sender saw acknowledged, and
none at or past the number sent, rebuilds the number `encode` truncated. -/
theorem decode_encode (full : Nat) (acked largest : Option Nat) (value len : Nat)
    (hfull : full ≤ numberMax) (hacked : ∀ a, acked = some a → a < full)
    (hseen : expected acked ≤ expected largest) (hbefore : expected largest ≤ full)
    (h : encode full acked = some (value, len)) :
    decode largest value len = full := by
  obtain ⟨hlen, hlen4, rfl, hrange⟩ := encode_range full acked value len h
  rw [unacknowledged_eq full acked hacked] at hrange
  have hlargest : ∀ l, largest = some l → l ≤ numberMax := by
    intro l hl; subst hl; simp only [expected] at hbefore; omega
  have hw : 256 ≤ window len := window_mono 1 len hlen
  have heven : window len % 2 = 0 := by
    rcases window_cases len ⟨hlen, hlen4⟩ with hw | hw | hw | hw <;> rw [hw]
  exact decode_closest largest len full ⟨hlen, hlen4⟩ hlargest hfull (by omega) (by omega)

/-- §17.1: the field's octets, most significant first, read back to its value. -/
theorem field_read_write (value len : Nat) (hvalue : value < window len) :
    fromDigits (field value len) 0 = value := by
  simp only [field, fromDigits_digits, Nat.zero_mul, Nat.zero_add]
  exact Nat.mod_eq_of_lt hvalue

end Colibri.Quic.PacketNumber
