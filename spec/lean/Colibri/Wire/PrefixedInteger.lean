/-!
# The prefixed integer (RFC 7541 §5.1)

HPACK and QPACK write an integer in the low `n` bits of an octet whose high bits belong to the
field before it (RFC 9204 §4.1.1 uses it unmodified). A value below `2 ^ n - 1` fits in the prefix.
A larger one fills the prefix with ones and carries the rest in continuation octets, seven bits
each, least significant group first, with the high bit set on every octet but the last. These
definitions follow `src/wire/prefixed_integer.zig` over natural numbers, with an octet a `Nat`
below 256; the theorems are about them (https://github.com/c4milo/colibri/issues/52).

What is proved:
- `decode_encode`: an encoding decodes to its value and its length, whatever high bits the
  caller put in the first octet and whatever octets follow.
- `encode_octets`: every octet of an encoding is below 256, for every prefix size 1 to 8.
- `encode_length`: every value up to 2^62 - 1 takes at most `lenMax` octets at every prefix size,
  which is why `integer_len_max` never refuses an integer colibri must read (RFC 9204 §4.1.1).
- `decodeLimited_encode`: with colibri's two limits, the decoder `prefixed_integer.zig` follows
  still reads every encoding of a value up to 2^62 - 1 back, so the limits refuse nothing valid.
-/

namespace Colibri.Wire.PrefixedInteger

/-- §5.1: `2 ^ n - 1`, the largest value the prefix holds. -/
def prefixMax (n : Nat) : Nat := 2 ^ n - 1

/-- RFC 9204 §4.1.1: the 62 bits a decoder must read. `integer_value_max` in `constants.zig`. -/
def valueMax : Nat := 2 ^ 62 - 1

/-- The most octets one integer takes. `integer_len_max` in `constants.zig`. -/
def lenMax : Nat := 10

/-- §5.1: the continuation octets of `r`, seven bits each, least significant group first, the high
bit set on all but the last. -/
def continuation (r : Nat) : List Nat :=
  if r < 128 then [r] else (r % 128 + 128) :: continuation (r / 128)
termination_by r
decreasing_by omega

/-- §5.1: `v` with its prefix in the low `n` bits of the first octet, whose high bits are
`high`. `encode` in `prefixed_integer.zig`. -/
def encode (n high v : Nat) : List Nat :=
  if v < prefixMax n then [high + v] else (high + prefixMax n) :: continuation (v - prefixMax n)

/-- The value of continuation octets whose groups start at bit `shift`, and how many octets they
took, or `none` when the octets end before one with its high bit clear. -/
def readContinuation : List Nat → Nat → Option (Nat × Nat)
  | [], _ => none
  | o :: rest, shift =>
    if o < 128 then some (o * 2 ^ shift, 1)
    else (readContinuation rest (shift + 7)).map fun (v, c) => ((o % 128) * 2 ^ shift + v, c + 1)

/-- §5.1 with no limit: the value and the octets it took, or `none` when they end too soon. -/
def decode (n : Nat) : List Nat → Option (Nat × Nat)
  | [] => none
  | first :: rest =>
    if first % 2 ^ n < prefixMax n then some (first % 2 ^ n, 1)
    else (readContinuation rest 0).map fun (v, c) => (prefixMax n + v, c + 1)

/-- What `decode` in `prefixed_integer.zig` answers, in the order it checks (invariant 7). -/
inductive Outcome where
  | value (v len : Nat)
  | truncated
  | tooLong
  | tooLarge
  deriving DecidableEq, Repr

/-- The continuation octets as `decode` in `prefixed_integer.zig` reads them: at most
`lenMax - 1` of them, onto `acc`, group `group` next. -/
def readLimited (octets : List Nat) (group acc : Nat) : Outcome :=
  if lenMax - 1 ≤ group then .tooLong
  else
    match octets with
    | [] => .truncated
    | o :: rest =>
      if o < 128 then
        if valueMax < acc + (o % 128) * 2 ^ (7 * group) then .tooLarge
        else .value (acc + (o % 128) * 2 ^ (7 * group)) (group + 2)
      else readLimited rest (group + 1) (acc + (o % 128) * 2 ^ (7 * group))
termination_by lenMax - 1 - group

/-- `decode` in `prefixed_integer.zig`: `decode` above, with colibri's two limits. -/
def decodeLimited (n : Nat) : List Nat → Outcome
  | [] => .truncated
  | first :: rest =>
    if first % 2 ^ n < prefixMax n then .value (first % 2 ^ n) 1
    else readLimited rest 0 (prefixMax n)

theorem continuation_lt (r : Nat) : ∀ d ∈ continuation r, d < 256 := by
  induction r using Nat.strongRecOn with
  | ind r ih =>
    rw [continuation]
    split
    · intro d hd; simp at hd; omega
    · intro d hd
      simp only [List.mem_cons] at hd
      rcases hd with rfl | hd
      · have := Nat.mod_lt r (show 128 > 0 by decide); omega
      · exact ih (r / 128) (by omega) d hd

/-- Continuation octets read back give their value, whatever octets follow. -/
theorem readContinuation_continuation (r shift : Nat) (rest : List Nat) :
    readContinuation (continuation r ++ rest) shift = some (r * 2 ^ shift, (continuation r).length) := by
  induction r using Nat.strongRecOn generalizing shift with
  | ind r ih =>
    rw [continuation]
    split
    · simp [readContinuation, *]
    · rename_i hr
      simp only [List.cons_append, readContinuation, show ¬ (r % 128 + 128 < 128) by omega, ↓reduceIte,
        ih (r / 128) (by omega) (shift + 7), Option.map_some, List.length_cons,
        show (r % 128 + 128) % 128 = r % 128 by omega]
      congr 2
      rw [Nat.pow_add, show (2 : Nat) ^ 7 = 128 by decide]
      have := Nat.div_add_mod r 128
      generalize 2 ^ shift = p at *
      conv => rhs; rw [← this]
      rw [Nat.add_mul, Nat.mul_comm p 128, ← Nat.mul_assoc, Nat.mul_comm (r / 128) 128]
      omega

/-- The prefix of the first octet, whatever high bits a multiple of `2 ^ n` puts above it. -/
theorem first_prefix (n high x : Nat) (hhigh : high % 2 ^ n = 0) (hx : x < 2 ^ n) :
    (high + x) % 2 ^ n = x := by
  rw [Nat.add_mod, hhigh, Nat.zero_add, Nat.mod_mod, Nat.mod_eq_of_lt hx]

/-- §5.1: an encoding decodes to its value and its length, whatever high bits the caller put in
the first octet and whatever octets follow. -/
theorem decode_encode (n high v : Nat) (rest : List Nat) (hhigh : high % 2 ^ n = 0) :
    decode n (encode n high v ++ rest) = some (v, (encode n high v).length) := by
  have hpos : 0 < 2 ^ n := Nat.two_pow_pos n
  unfold encode
  split
  · rename_i hv
    have : v < 2 ^ n := by unfold prefixMax at hv; omega
    simp [decode, first_prefix n high v hhigh this, hv]
  · rename_i hv
    have hmax : prefixMax n < 2 ^ n := by unfold prefixMax; omega
    simp only [List.cons_append, decode, first_prefix n high (prefixMax n) hhigh hmax,
      Nat.lt_irrefl, ↓reduceIte, readContinuation_continuation, Nat.pow_zero, Nat.mul_one,
      Option.map_some, List.length_cons]
    congr 2
    omega

/-- §5.1: every octet of an encoding is below 256, for every prefix size 1 to 8, when the high
bits sit above the prefix. -/
theorem encode_octets (n high v : Nat) (hn : 1 ≤ n ∧ n ≤ 8) (hhigh : high < 256)
    (hmul : high % 2 ^ n = 0) : ∀ d ∈ encode n high v, d < 256 := by
  have hroom : high + prefixMax n < 256 := by
    unfold prefixMax
    have : n = 1 ∨ n = 2 ∨ n = 3 ∨ n = 4 ∨ n = 5 ∨ n = 6 ∨ n = 7 ∨ n = 8 := by omega
    rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp at hmul ⊢ <;> omega
  unfold encode
  split
  · intro d hd; simp at hd; omega
  · intro d hd
    simp only [List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact hroom
    · exact continuation_lt _ d hd

/-- A value below `128 ^ k` takes at most `k` continuation octets. -/
theorem continuation_length (r k : Nat) (hk : 1 ≤ k) (hr : r < 128 ^ k) :
    (continuation r).length ≤ k := by
  induction r using Nat.strongRecOn generalizing k with
  | ind r ih =>
    rw [continuation]
    split
    · simp; exact hk
    · rename_i hr128
      obtain ⟨j, rfl⟩ : ∃ j, k = j + 1 := ⟨k - 1, by omega⟩
      have hj : 1 ≤ j := by
        rcases Nat.eq_zero_or_pos j with rfl | h
        · simp at hr; omega
        · exact h
      have hdiv : r / 128 < 128 ^ j := by
        rw [Nat.div_lt_iff_lt_mul (by decide)]
        rw [Nat.pow_succ] at hr; exact hr
      simp only [List.length_cons]
      have := ih (r / 128) (by omega) j hj hdiv
      omega

/-- RFC 9204 §4.1.1: every value up to 2^62 - 1 takes at most `lenMax` octets, at every prefix
size, so the limit never refuses an integer a decoder must read. -/
theorem encode_length (n high v : Nat) (hv : v ≤ valueMax) :
    (encode n high v).length ≤ lenMax := by
  unfold encode lenMax
  split
  · simp
  · simp only [List.length_cons]
    have : v - prefixMax n < 128 ^ 9 := by
      have : (128 : Nat) ^ 9 = 2 ^ 63 := by decide
      unfold valueMax at hv
      have : (2 : Nat) ^ 62 < 2 ^ 63 := by decide
      omega
    have := continuation_length (v - prefixMax n) 9 (by decide) this
    omega

/-- Continuation octets read with colibri's limits give their value on top of `acc`, while they
fit the octet limit and the value fits `valueMax`. -/
theorem readLimited_continuation (r group acc : Nat) (rest : List Nat)
    (hlen : group + (continuation r).length ≤ lenMax - 1)
    (hv : acc + r * 2 ^ (7 * group) ≤ valueMax) :
    readLimited (continuation r ++ rest) group acc =
      .value (acc + r * 2 ^ (7 * group)) (group + 1 + (continuation r).length) := by
  induction r using Nat.strongRecOn generalizing group acc with
  | ind r ih =>
    have hlen_pos : 1 ≤ (continuation r).length := by
      rw [continuation]; split <;> simp
    revert hlen hv
    rw [continuation]
    split
    · rename_i hr
      intro hlen hv
      rw [readLimited.eq_def]
      simp only [show ¬ (lenMax - 1 ≤ group) by simp at hlen; omega, ↓reduceIte]
      simp only [List.cons_append, hr, ↓reduceIte, Nat.mod_eq_of_lt hr,
        show ¬ (valueMax < acc + r * 2 ^ (7 * group)) by omega, List.length_cons, List.length_nil]
    · rename_i hr
      intro hlen hv
      simp only [List.length_cons] at hlen
      have hstep : acc + (r % 128) * 2 ^ (7 * group) + (r / 128) * 2 ^ (7 * (group + 1)) =
          acc + r * 2 ^ (7 * group) := by
        rw [show 7 * (group + 1) = 7 * group + 7 by omega, Nat.pow_add, show (2 : Nat) ^ 7 = 128 by decide]
        have := Nat.div_add_mod r 128
        generalize 2 ^ (7 * group) = p at *
        conv => rhs; rw [← this]
        rw [Nat.add_mul, Nat.mul_comm p 128, ← Nat.mul_assoc, Nat.mul_comm (r / 128) 128]
        omega
      rw [readLimited.eq_def]
      simp only [show ¬ (lenMax - 1 ≤ group) by omega, ↓reduceIte]
      simp only [List.cons_append, show ¬ (r % 128 + 128 < 128) by omega, ↓reduceIte,
        show (r % 128 + 128) % 128 = r % 128 by omega]
      rw [ih (r / 128) (by omega) (group + 1) _ (by omega) (by rw [hstep]; exact hv), hstep]
      simp only [List.length_cons]
      congr 1
      omega

/-- With colibri's two limits, every encoding of a value up to 2^62 - 1 reads back, whatever high
bits the caller put in the first octet and whatever octets follow. -/
theorem decodeLimited_encode (n high v : Nat) (rest : List Nat) (hhigh : high % 2 ^ n = 0)
    (hv : v ≤ valueMax) :
    decodeLimited n (encode n high v ++ rest) = .value v (encode n high v).length := by
  have hpos : 0 < 2 ^ n := Nat.two_pow_pos n
  have hlength := encode_length n high v hv
  revert hlength
  unfold encode
  split
  · rename_i hsmall
    intro _
    have : v < 2 ^ n := by unfold prefixMax at hsmall; omega
    simp [decodeLimited, first_prefix n high v hhigh this, hsmall]
  · rename_i hsmall
    intro hlength
    have hmax : prefixMax n < 2 ^ n := by unfold prefixMax; omega
    simp only [List.length_cons] at hlength
    simp only [List.cons_append, decodeLimited, first_prefix n high (prefixMax n) hhigh hmax,
      Nat.lt_irrefl, ↓reduceIte, List.length_cons]
    rw [readLimited_continuation (v - prefixMax n) 0 (prefixMax n) rest (by omega)
      (by simp; omega)]
    congr 1
    · simp; omega
    · omega

end Colibri.Wire.PrefixedInteger
