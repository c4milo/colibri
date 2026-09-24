/-!
# Indices into the dynamic table (RFC 9204 §3.2.4 to §3.2.6, §4.5.1.2)

An entry has one absolute index for its life (§3.2.4). A field line names it relative to the Base,
counting back (§3.2.5), or past the Base, counting forward (§3.2.6); an encoder instruction names
it relative to the insert count. The Base itself travels as a Sign bit and a Delta Base from the
Required Insert Count (§4.5.1.2). These definitions follow `src/qpack/dynamic_table.zig`,
`src/qpack/decoder.zig`, `src/qpack/encoder.zig` and `src/qpack/representation.zig`.
-/

namespace Colibri.Qpack.Index

/-- §3.2.5, as the decoder reads it: relative index `i` below `base` is absolute `base - 1 - i`,
and one at or past the Base names no entry. -/
def ofRelative (base i : Nat) : Option Nat :=
  if i < base then some (base - 1 - i) else none

/-- §3.2.5, as the encoder writes it. -/
def toRelative (base absolute : Nat) : Nat := base - 1 - absolute

/-- §3.2.6: post-Base index `i` is absolute `base + i`. -/
def ofPostBase (base i : Nat) : Nat := base + i

/-- An encoder's relative index for an entry below the Base names that entry again. -/
theorem ofRelative_toRelative (base absolute : Nat) (h : absolute < base) :
    ofRelative base (toRelative base absolute) = some absolute := by
  unfold ofRelative toRelative
  have hbelow : base - 1 - absolute < base := by omega
  simp only [hbelow, ↓reduceIte]
  congr 1
  omega

/-- Every relative index the decoder accepts names an entry below the Base. -/
theorem ofRelative_below (base i absolute : Nat) (h : ofRelative base i = some absolute) :
    absolute < base := by
  simp [ofRelative] at h
  omega

/-- Relative indices name distinct entries: two that resolve to one entry are equal. -/
theorem ofRelative_injective (base i j absolute : Nat)
    (hi : ofRelative base i = some absolute) (hj : ofRelative base j = some absolute) : i = j := by
  simp [ofRelative] at hi hj
  omega

/-- Post-Base indices never name an entry below the Base, so the two forms never overlap. -/
theorem ofPostBase_not_below (base i : Nat) : ¬ ofPostBase base i < base := by
  simp [ofPostBase]

/-- §4.5.1.2, as the encoder writes it: a Sign bit, and the Delta Base. -/
def encodeBase (required base : Nat) : Bool × Nat :=
  if required ≤ base then (false, base - required) else (true, required - base - 1)

/-- §4.5.1.2, as the decoder reads it, with `none` for the invalid field block: "An endpoint MUST
treat a field block with a Sign bit of 1 as invalid if the value of Required Insert Count is less
than or equal to the value of Delta Base." -/
def decodeBase (required : Nat) (sign : Bool) (delta : Nat) : Option Nat :=
  if sign then (if required ≤ delta then none else some (required - delta - 1))
  else some (required + delta)

/-- Every Base goes out and comes back. -/
theorem decodeBase_encodeBase (required base : Nat) :
    decodeBase required (encodeBase required base).1 (encodeBase required base).2 = some base := by
  unfold encodeBase decodeBase
  split <;> simp <;> omega

/-- A Base the decoder accepts is never negative: with the Sign bit set it is below the Required
Insert Count, and otherwise at or above it. -/
theorem decodeBase_sign (required delta base : Nat) (h : decodeBase required true delta = some base) :
    base < required := by
  simp [decodeBase] at h
  omega

/-- colibri's encoder puts the Base at the insert count after its inserts, at or above the Required
Insert Count, so its Sign bit is always 0 (decision 76). -/
theorem encodeBase_at_or_above (required base : Nat) (h : required ≤ base) :
    encodeBase required base = (false, base - required) := by
  simp [encodeBase, h]

end Colibri.Qpack.Index
