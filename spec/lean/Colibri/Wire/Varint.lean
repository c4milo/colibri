/-!
# The variable-length integer (RFC 9000 §16)

QUIC writes an integer in 1, 2, 4 or 8 octets. The two most significant bits of the first octet
give the length as a power of two, and the other bits carry the value in network byte order.
These definitions follow `src/wire/varint.zig` over natural numbers, with an octet a `Nat` below
256; the theorems are about them (https://github.com/c4milo/colibri/issues/52).

What is proved:
- `encode_octets`: an encoding in any of the four lengths is octets, each below 256.
- `decode_encode`: an encoding decodes to its value and its length, whatever octets follow it.
- `decode_bound`: whatever octets are decoded, the value fits the length the first octet names.
- `minimal_fits` and `minimal_shortest`: `encodedLenMinimal` names a length that carries the
  value, and no shorter length does.
-/

namespace Colibri.Wire.Varint

/-- §16: the largest value `len` octets carry, every bit but the two length bits. -/
def valueMax (len : Nat) : Nat := 2 ^ (8 * len - 2) - 1

/-- The low `k` octets of `v`, most significant first. -/
def digits : Nat → Nat → List Nat
  | 0, _ => []
  | k + 1, v => v / 256 ^ k % 256 :: digits k v

/-- The value of octets read most significant first, onto `acc`. -/
def fromDigits : List Nat → Nat → Nat
  | [], acc => acc
  | d :: ds, acc => fromDigits ds (acc * 256 + d)

/-- §16: `v` in `2 ^ tag` octets, the first carrying `tag` in its two most significant bits.
`encode_with_len` in `varint.zig`. -/
def encodeWithTag (v tag : Nat) : List Nat :=
  match digits (2 ^ tag) v with
  | [] => []
  | first :: rest => (tag * 64 + first) :: rest

/-- §16: the value and the length of the encoding at the start of `octets`, or `none` when fewer
octets are present than the first names. `decode` in `varint.zig`. -/
def decode : List Nat → Option (Nat × Nat)
  | [] => none
  | first :: rest =>
    if rest.length < 2 ^ (first / 64) - 1 then none
    else some (fromDigits (first % 64 :: rest.take (2 ^ (first / 64) - 1)) 0, 2 ^ (first / 64))

/-- The fewest octets that carry `v`. `encoded_len_minimal` in `varint.zig`. -/
def encodedLenMinimal (v : Nat) : Nat :=
  if v ≤ valueMax 1 then 1 else if v ≤ valueMax 2 then 2 else if v ≤ valueMax 4 then 4 else 8

theorem digits_length (k v : Nat) : (digits k v).length = k := by
  induction k with
  | zero => rfl
  | succ k ih => simp [digits, ih]

theorem digits_lt (k v : Nat) : ∀ d ∈ digits k v, d < 256 := by
  induction k with
  | zero => simp [digits]
  | succ k ih =>
    intro d hd
    simp only [digits, List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact Nat.mod_lt _ (by decide)
    · exact ih d hd

/-- Reading the low `k` octets of `v` back gives `v` below `256 ^ k`. -/
theorem fromDigits_digits (k v acc : Nat) :
    fromDigits (digits k v) acc = acc * 256 ^ k + v % 256 ^ k := by
  induction k generalizing acc with
  | zero => simp [digits, fromDigits, Nat.mod_one]
  | succ k ih =>
    simp only [digits, fromDigits, ih, Nat.pow_succ]
    rw [Nat.mod_mul]
    generalize 256 ^ k = p
    simp only [Nat.mul_add, Nat.mul_comm, Nat.mul_left_comm]
    omega

/-- Octets below 256 read back stay below `(acc + 1) * 256 ^ length`. -/
theorem fromDigits_lt (ds : List Nat) (acc : Nat) (h : ∀ d ∈ ds, d < 256) :
    fromDigits ds acc < (acc + 1) * 256 ^ ds.length := by
  induction ds generalizing acc with
  | nil => simp [fromDigits]
  | cons d ds ih =>
    have hd : d < 256 := h d (by simp)
    have hrest := ih (acc * 256 + d) (fun x hx => h x (by simp [hx]))
    simp only [fromDigits, List.length_cons, Nat.pow_succ]
    have : (acc * 256 + d + 1) * 256 ^ ds.length ≤ (acc + 1) * (256 ^ ds.length * 256) := by
      rw [show (acc + 1) * (256 ^ ds.length * 256) = (acc * 256 + 256) * 256 ^ ds.length by
        generalize 256 ^ ds.length = p
        simp only [Nat.add_mul, Nat.mul_add, Nat.mul_comm, Nat.mul_left_comm, Nat.one_mul]]
      exact Nat.mul_le_mul_right _ (by omega)
    omega

theorem pow_two_eight (m : Nat) : 2 ^ (8 * (m + 1) - 2) = 64 * 256 ^ m := by
  rw [show 8 * (m + 1) - 2 = 6 + 8 * m by omega, Nat.pow_add, Nat.pow_mul]

/-- §16: an encoding decodes to its value and its length, whatever octets follow it. The four
lengths are what keep the first octet below 256 (`encode_octets`); the round trip needs no more. -/
theorem decode_encode (v tag : Nat) (rest : List Nat) (hv : v ≤ valueMax (2 ^ tag)) :
    decode (encodeWithTag v tag ++ rest) = some (v, 2 ^ tag) := by
  obtain ⟨m, hm⟩ : ∃ m, 2 ^ tag = m + 1 := ⟨2 ^ tag - 1, by have := Nat.one_le_two_pow (n := tag); omega⟩
  have hbound : v < 64 * 256 ^ m := by
    have := pow_two_eight m
    unfold valueMax at hv
    rw [hm] at hv
    have hpos : 0 < 2 ^ (8 * (m + 1) - 2) := Nat.two_pow_pos _
    omega
  have hq : v / 256 ^ m < 64 := by
    rw [Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))]
    exact hbound
  have hmod : v / 256 ^ m % 256 = v / 256 ^ m := Nat.mod_eq_of_lt (by omega)
  have hfirst_div : (tag * 64 + v / 256 ^ m) / 64 = tag := by omega
  have hfirst_mod : (tag * 64 + v / 256 ^ m) % 64 = v / 256 ^ m := by omega
  unfold encodeWithTag
  rw [hm]
  simp only [digits, hmod, List.cons_append, decode, hfirst_div, hfirst_mod, hm]
  have hlen : (digits m v ++ rest).length = m + rest.length := by
    simp [digits_length]
  have htake : (digits m v ++ rest).take (m + 1 - 1) = digits m v := by
    simp [digits_length]
  simp only [hlen, htake, show ¬ (m + rest.length < m + 1 - 1) by omega, ↓reduceIte]
  simp only [fromDigits, fromDigits_digits, Nat.zero_mul, Nat.zero_add]
  have := Nat.div_add_mod v (256 ^ m)
  rw [Nat.mul_comm] at this
  simp [this]

/-- §16: in any of the four lengths, every octet of an encoding is below 256. -/
theorem encode_octets (v tag : Nat) (htag : tag ≤ 3) (hv : v ≤ valueMax (2 ^ tag)) :
    ∀ d ∈ encodeWithTag v tag, d < 256 := by
  obtain ⟨m, hm⟩ : ∃ m, 2 ^ tag = m + 1 := ⟨2 ^ tag - 1, by have := Nat.one_le_two_pow (n := tag); omega⟩
  have hbound : v < 64 * 256 ^ m := by
    have := pow_two_eight m
    unfold valueMax at hv
    rw [hm] at hv
    have hpos : 0 < 2 ^ (8 * (m + 1) - 2) := Nat.two_pow_pos _
    omega
  have hq : v / 256 ^ m < 64 := by
    rw [Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))]
    exact hbound
  unfold encodeWithTag
  rw [hm]
  intro d hd
  simp only [digits, List.mem_cons] at hd
  rcases hd with rfl | hd
  · have : v / 256 ^ m % 256 < 64 := Nat.lt_of_le_of_lt (Nat.mod_le _ _) hq
    omega
  · exact digits_lt m v d hd

/-- §16: whatever octets are decoded, the value fits the length the first octet names. -/
theorem decode_bound (octets : List Nat) (v len : Nat) (h : ∀ d ∈ octets, d < 256)
    (hd : decode octets = some (v, len)) : v ≤ valueMax len := by
  match octets, hd with
  | first :: rest, hd =>
    simp only [decode] at hd
    split at hd
    · simp at hd
    · simp only [Option.some.injEq, Prod.mk.injEq] at hd
      obtain ⟨hv, hlen⟩ := hd
      subst hv hlen
      obtain ⟨m, hm⟩ : ∃ m, 2 ^ (first / 64) = m + 1 :=
        ⟨2 ^ (first / 64) - 1, by have := Nat.one_le_two_pow (n := first / 64); omega⟩
      rw [hm]
      have htake_len : (rest.take (m + 1 - 1)).length = m := by
        simp only [List.length_take]; omega
      have hlt := fromDigits_lt (rest.take (m + 1 - 1)) (first % 64)
        (fun x hx => h x (by simp [List.mem_of_mem_take hx]))
      simp only [fromDigits, Nat.zero_mul, Nat.zero_add]
      rw [htake_len] at hlt
      have hq : first % 64 + 1 ≤ 64 := Nat.mod_lt _ (by decide)
      have := Nat.mul_le_mul_right (256 ^ m) hq
      unfold valueMax
      rw [pow_two_eight m]
      omega

/-- `encodedLenMinimal` names a length that carries `v`, for every value §16 can carry. -/
theorem minimal_fits (v : Nat) (hv : v ≤ valueMax 8) : v ≤ valueMax (encodedLenMinimal v) := by
  unfold encodedLenMinimal
  split
  · assumption
  · split
    · assumption
    · split
      · assumption
      · exact hv

/-- No length shorter than `encodedLenMinimal v` carries `v`. -/
theorem minimal_shortest (v len : Nat) (hlen : len = 1 ∨ len = 2 ∨ len = 4)
    (hshort : len < encodedLenMinimal v) : valueMax len < v := by
  have h1 : valueMax 1 = 63 := by decide
  have h2 : valueMax 2 = 16383 := by decide
  have h4 : valueMax 4 = 1073741823 := by decide
  unfold encodedLenMinimal at hshort
  rw [h1, h2, h4] at hshort
  rcases hlen with rfl | rfl | rfl
  · rw [h1]; split at hshort <;> omega
  · rw [h2]; split at hshort <;> (try split at hshort) <;> omega
  · rw [h4]; split at hshort <;> (try split at hshort) <;> (try split at hshort) <;> omega

end Colibri.Wire.Varint
