/-!
# The Required Insert Count (RFC 9204 §4.5.1.1)

The encoder sends the Required Insert Count modulo twice `MaxEntries`, and the decoder rebuilds it
from its own insert count. These definitions follow `src/qpack/insert_count.zig` line for line;
the theorems are about them.
-/

namespace Colibri.Qpack.InsertCount

/-- §4.5.1.1: `FullRange = 2 * MaxEntries`. -/
def fullRange (maxEntries : Nat) : Nat := 2 * maxEntries

/-- §4.5.1.1: the encoder's transform. Zero is sent as zero. -/
def encode (required maxEntries : Nat) : Nat :=
  if required = 0 then 0 else required % fullRange maxEntries + 1

/-- §4.5.1.1: the decoder's algorithm, with `none` for the RFC's "Error". `total` is the
decoder's `TotalNumberOfInserts`. -/
def decode (encoded total maxEntries : Nat) : Option Nat :=
  if encoded = 0 then some 0
  else if encoded > fullRange maxEntries then none
  else
    let maxValue := total + maxEntries
    let maxWrapped := maxValue / fullRange maxEntries * fullRange maxEntries
    let required := maxWrapped + encoded - 1
    if required > maxValue then
      if required ≤ fullRange maxEntries then none
      else if required - fullRange maxEntries = 0 then none
      else some (required - fullRange maxEntries)
    else if required = 0 then none
    else some required

/-- Zero goes out as zero and comes back as zero. -/
theorem decode_encode_zero (total maxEntries : Nat) :
    decode (encode 0 maxEntries) total maxEntries = some 0 := by
  simp [encode, decode]

/-- A non-zero count is never sent as zero, so the decoder cannot mistake it for no reference. -/
theorem encode_ne_zero (required maxEntries : Nat) (h : required ≠ 0) :
    encode required maxEntries ≠ 0 := by
  simp [encode, h]

/-- With no dynamic table permitted, every non-zero encoded value is refused. -/
theorem decode_no_table (encoded total : Nat) (h : encoded ≠ 0) :
    decode encoded total 0 = none := by
  simp [decode, fullRange, h]

/-- A number `d` past a multiple of `F`, with `d` below `F`, leaves the residue `d`. -/
theorem mod_eq_of_offset {x d q F : Nat} (hx : x = d + q * F) (hd : d < F) : x % F = d := by
  rw [hx, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hd]

/-- The round trip: the decoder rebuilds the exact count whenever its own insert count lies in
the window the protocol keeps it in, no more than `MaxEntries` behind the count and less than
`MaxEntries` ahead of it. -/
theorem decode_encode (required total maxEntries : Nat)
    (hm : 0 < maxEntries) (hr : 0 < required)
    (hbehind : required ≤ total + maxEntries) (hahead : total < required + maxEntries) :
    decode (encode required maxEntries) total maxEntries = some required := by
  have hF : 0 < fullRange maxEntries := by simp [fullRange]; omega
  -- The names the argument needs: F, V, W and the residue s.
  generalize hFdef : fullRange maxEntries = F at hF ⊢
  have hFm : F = 2 * maxEntries := by rw [← hFdef]; rfl
  generalize hV : total + maxEntries = V
  have hW_le : V / F * F ≤ V := Nat.div_mul_le_self V F
  have hV_lt : V < V / F * F + F := Nat.lt_div_mul_add hF
  generalize hWdef : V / F * F = W at hW_le hV_lt
  have hs : required % F < F := Nat.mod_lt required hF
  have hr0 : required ≠ 0 := by omega
  have henc : encode required maxEntries = required % F + 1 := by
    simp [encode, hr0, hFdef]
  rw [henc]
  simp only [decode, hFdef, hV, hWdef]
  have hne : required % F + 1 ≠ 0 := by omega
  have hle : ¬ (required % F + 1 > F) := by omega
  simp only [hne, hle, ↓reduceIte]
  -- W is a multiple of F.
  have hWmul : W = V / F * F := hWdef.symm
  by_cases hge : W ≤ required
  · -- The count lies at or above W: its residue is its distance from W.
    have hd : required - W < F := by omega
    have hmod : required % F = required - W := mod_eq_of_offset (q := V / F) (by omega) hd
    rw [hmod]
    have h1 : ¬ (W + (required - W + 1) - 1 > V) := by omega
    have h2 : ¬ (W + (required - W + 1) - 1 = 0) := by omega
    simp only [h1, h2, ↓reduceIte]
    congr 1
    omega
  · -- The count lies below W: one full range above it is at or above W.
    have hlt : required < W := by omega
    have hd : required + F - W < F := by omega
    have hmod : required % F = required + F - W := by
      rw [← Nat.add_mod_right required F]
      exact mod_eq_of_offset (q := V / F) (by omega) hd
    rw [hmod]
    have h1 : W + (required + F - W + 1) - 1 > V := by omega
    have h2 : ¬ (W + (required + F - W + 1) - 1 ≤ F) := by omega
    have h3 : ¬ (W + (required + F - W + 1) - 1 - F = 0) := by omega
    simp only [h1, h2, h3, ↓reduceIte]
    congr 1
    omega

end Colibri.Qpack.InsertCount
