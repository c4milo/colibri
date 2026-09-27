import Colibri.Wire.HuffmanTable

/-!
# The Huffman code (RFC 7541 Appendix B, §5.2)

HPACK and QPACK encode a string literal with Appendix B's code. Each octet becomes its code, most
significant bit first. Then the most significant bits of EOS pad the string to an octet boundary.
These definitions follow `src/wire/huffman.zig` over natural numbers, with an octet a `Nat` below
256 and a code a `List Bool`. The theorems are about them
(https://github.com/c4milo/colibri/issues/52).

The decoder here reads one bit at a time and looks the bits read so far up in the table.
`huffman.zig`'s decoder uses the table's canonical ranges instead, so the vectors `Vectors.lean`
writes are what tie the two together.

What is proved:
- `prefix_free`: no symbol's code is a prefix of another's, which is what lets a decoder end a
  symbol as soon as its bits match one.
- `eos_ones`: EOS is thirty ones, so the padding §5.2 asks for is a run of ones.
- `decode_encode`: every string of octets decodes back from its encoding, padding included.
- `decode_octets`: whatever a decoding accepts is octets, each below 256; EOS never reaches the
  output.
-/

namespace Colibri.Wire.Huffman

/-- The low `n` bits of `code`, most significant first. -/
def bitsOf (code : Nat) : Nat → List Bool
  | 0 => []
  | n + 1 => code.testBit n :: bitsOf code n

/-- The value of bits read most significant first, onto `acc`. -/
def ofBits : List Bool → Nat → Nat
  | [], acc => acc
  | bit :: rest, acc => ofBits rest (2 * acc + if bit then 1 else 0)

/-- Every symbol's code as bits, indexed by symbol. `table.codes` in `huffman_table.zig`. -/
def table : List (List Bool) := codes.map fun (code, length) => bitsOf code length

/-- The symbol whose code is exactly `bits`, if any. -/
def symbolOf (bits : List Bool) : Option Nat := table.findIdx? (· == bits)

/-- The bits of a string: each octet's code in turn. -/
def encodeBits (octets : List Nat) : List Bool := octets.flatMap fun octet => table.getD octet []

/-- §5.2: the most significant bits of EOS, ones, up to the next octet boundary after `n` bits. -/
def padding (n : Nat) : List Bool := List.replicate ((8 - n % 8) % 8) true

/-- Bits as octets, eight at a time, most significant first. -/
def pack : List Bool → List Nat
  | b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: b7 :: rest =>
    ofBits [b0, b1, b2, b3, b4, b5, b6, b7] 0 :: pack rest
  | _ => []

/-- Octets as bits, most significant first. -/
def unpack (octets : List Nat) : List Bool := octets.flatMap fun octet => bitsOf octet 8

/-- §5.2: `bytes` encoded and padded. `encode` in `huffman.zig`. -/
def encode (octets : List Nat) : List Nat :=
  pack (encodeBits octets ++ padding (encodeBits octets).length)

/-- What `decode` in `huffman.zig` answers, in the order it checks (invariant 7). -/
inductive Outcome where
  | octets (octets : List Nat)
  | eosInData
  | paddingTooLong
  | paddingNotEos
deriving DecidableEq, Repr

/-- A decoded symbol in front of what the rest decodes to; an error stays the error. -/
def Outcome.cons (symbol : Nat) : Outcome → Outcome
  | .octets rest => .octets (symbol :: rest)
  | other => other

/-- §5.2, one bit at a time: `partialCode` holds the bits of the code being read. A complete EOS is
an error; at the end, more than seven bits left, or bits that are not all ones, are errors. -/
def decodeFrom : List Bool → List Bool → Outcome
  | [], partialCode =>
    if partialCode.length > 7 then .paddingTooLong
    else if partialCode = List.replicate partialCode.length true then .octets []
    else .paddingNotEos
  | bit :: rest, partialCode =>
    match symbolOf (partialCode ++ [bit]) with
    | some symbol => if symbol = 256 then .eosInData else (decodeFrom rest []).cons symbol
    | none => decodeFrom rest (partialCode ++ [bit])

/-- `decode` in `huffman.zig`. -/
def decode (encoded : List Nat) : Outcome := decodeFrom (unpack encoded) []

/-! ## The table, checked by the kernel over its numbers -/

/-- Whether `a`'s code is a prefix of `b`'s, read as numbers. -/
def natPrefix (a b : Nat × Nat) : Bool := a.2 ≤ b.2 && b.1 >>> (b.2 - a.2) == a.1

theorem codes_length : codes.length = 257 := by decide +kernel

theorem codes_bound : ∀ row ∈ codes, row.1 < 2 ^ row.2 ∧ 5 ≤ row.2 := by decide +kernel

theorem codes_prefix_free :
    codes.Pairwise (fun a b => natPrefix a b = false ∧ natPrefix b a = false) := by
  decide +kernel

/-! ## Bits -/

theorem bitsOf_length (code n : Nat) : (bitsOf code n).length = n := by
  induction n with
  | zero => rfl
  | succ n ih => simp [bitsOf, ih]

/-- The low `a + b` bits are the `a` bits above the low `b`, then the low `b`. -/
theorem bitsOf_add (code a b : Nat) :
    bitsOf code (a + b) = bitsOf (code >>> b) a ++ bitsOf code b := by
  induction a with
  | zero => simp [bitsOf]
  | succ a ih =>
    rw [show a + 1 + b = (a + b) + 1 by omega]
    simp only [bitsOf, ih, List.cons_append, Nat.testBit_shiftRight, Nat.add_comm b a]

theorem bitsOf_testBit (x y n i : Nat) (h : bitsOf x n = bitsOf y n) (hi : i < n) :
    x.testBit i = y.testBit i := by
  induction n with
  | zero => omega
  | succ n ih =>
    simp only [bitsOf, List.cons.injEq] at h
    by_cases hin : i = n
    · subst hin; exact h.1
    · exact ih h.2 (by omega)

theorem bitsOf_inj (x y n : Nat) (h : bitsOf x n = bitsOf y n) (hx : x < 2 ^ n) (hy : y < 2 ^ n) :
    x = y := by
  apply Nat.eq_of_testBit_eq
  intro i
  by_cases hi : i < n
  · exact bitsOf_testBit x y n i h hi
  · have hpow : 2 ^ n ≤ 2 ^ i := Nat.pow_le_pow_right (by decide) (by omega)
    rw [Nat.testBit_lt_two_pow (by omega), Nat.testBit_lt_two_pow (by omega)]

/-- A code that is a prefix of another as bits is one as numbers. -/
theorem natPrefix_of_prefix (a b : Nat × Nat) (ha : a.1 < 2 ^ a.2) (hb : b.1 < 2 ^ b.2)
    (h : bitsOf a.1 a.2 <+: bitsOf b.1 b.2) : natPrefix a b = true := by
  obtain ⟨rest, hrest⟩ := h
  have hlen := congrArg List.length hrest
  simp only [List.length_append, bitsOf_length] at hlen
  have hsplit : bitsOf b.1 b.2 = bitsOf (b.1 >>> (b.2 - a.2)) a.2 ++ bitsOf b.1 (b.2 - a.2) := by
    rw [← bitsOf_add]; congr 1; omega
  rw [hsplit] at hrest
  have heq := (List.append_inj hrest (by simp [bitsOf_length])).1
  have hshift : b.1 >>> (b.2 - a.2) < 2 ^ a.2 := by
    rw [Nat.shiftRight_eq_div_pow, Nat.div_lt_iff_lt_mul (Nat.two_pow_pos _), ← Nat.pow_add]
    rw [show a.2 + (b.2 - a.2) = b.2 by omega]; exact hb
  have := bitsOf_inj _ _ _ heq ha hshift
  simp only [natPrefix, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
  exact ⟨by omega, this.symm⟩

/-! ## The code -/

theorem table_length : table.length = 257 := by simp [table, codes_length]

/-- No symbol's code is a prefix of another's. -/
theorem prefix_free : table.Pairwise (fun c d => ¬ c <+: d ∧ ¬ d <+: c) := by
  unfold table
  rw [List.pairwise_map]
  refine List.Pairwise.imp_of_mem ?_ codes_prefix_free
  intro a b ha hb hab
  have hba := codes_bound a ha
  have hbb := codes_bound b hb
  refine ⟨fun h => ?_, fun h => ?_⟩
  · have := natPrefix_of_prefix a b hba.1 hbb.1 h; simp_all
  · have := natPrefix_of_prefix b a hbb.1 hba.1 h; simp_all

/-- §5.2: EOS is thirty ones. -/
theorem eos_ones : table[256]'(by simp [table_length]) = List.replicate 30 true := by decide +kernel

theorem table_length_ge (symbol : Nat) (h : symbol < table.length) : 5 ≤ table[symbol].length := by
  simp only [table, List.getElem_map, bitsOf_length]
  exact (codes_bound _ (List.getElem_mem _)).2

/-- Two symbols whose codes are a prefix of one another are the same symbol. -/
theorem symbol_eq_of_prefix (s t : Nat) (hs : s < table.length) (ht : t < table.length)
    (h : table[t] <+: table[s]) : t = s := by
  have hpair := List.pairwise_iff_getElem.1 prefix_free
  rcases Nat.lt_trichotomy t s with hlt | heq | hgt
  · exact absurd h (hpair t s ht hs hlt).1
  · exact heq
  · exact absurd h (hpair s t hs ht hgt).2

theorem symbolOf_table (s : Nat) (hs : s < table.length) : symbolOf table[s] = some s := by
  unfold symbolOf
  rw [List.findIdx?_eq_some_iff_getElem]
  refine ⟨hs, by simp, fun j hj => ?_⟩
  simp only [beq_iff_eq]
  intro heq
  have := symbol_eq_of_prefix s j hs (by omega) ⟨[], by simp [heq]⟩
  omega

theorem symbolOf_some (bits : List Bool) (t : Nat) (h : symbolOf bits = some t) :
    ∃ ht : t < table.length, table[t] = bits := by
  unfold symbolOf at h
  rw [List.findIdx?_eq_some_iff_getElem] at h
  obtain ⟨ht, heq, _⟩ := h
  exact ⟨ht, by simpa using heq⟩

/-- Bits that stop short of a symbol's code are no symbol's code. -/
theorem symbolOf_proper_prefix (s : Nat) (hs : s < table.length) (bits more : List Bool)
    (h : bits ++ more = table[s]) (hmore : more ≠ []) : symbolOf bits = none := by
  cases hsym : symbolOf bits with
  | none => rfl
  | some t =>
    obtain ⟨ht, htable⟩ := symbolOf_some bits t hsym
    have := symbol_eq_of_prefix s t hs ht ⟨more, htable ▸ h⟩
    subst this
    have hlen := congrArg List.length h
    rw [← htable] at hlen
    simp only [List.length_append] at hlen
    have : more.length ≠ 0 := by simpa using hmore
    omega

/-! ## Decoding what was encoded -/

/-- The rest of a symbol's code, read with its start already in `partialCode`, gives that symbol. -/
theorem decodeFrom_code (s : Nat) (hs : s < table.length) (rest : List Bool) :
    ∀ (suffix partialCode : List Bool), partialCode ++ suffix = table[s] → suffix ≠ [] →
      decodeFrom (suffix ++ rest) partialCode =
        if s = 256 then .eosInData else (decodeFrom rest []).cons s := by
  intro suffix
  induction suffix with
  | nil => intro _ _ h; exact absurd rfl h
  | cons bit more ih =>
    intro partialCode h _
    simp only [List.cons_append, decodeFrom]
    cases more with
    | nil =>
      have hcode : partialCode ++ [bit] = table[s] := by simpa using h
      rw [hcode, symbolOf_table s hs]
      simp
    | cons next more' =>
      have hnone : symbolOf (partialCode ++ [bit]) = none :=
        symbolOf_proper_prefix s hs (partialCode ++ [bit]) (next :: more') (by simpa using h)
          (by simp)
      rw [hnone]
      exact ih (partialCode ++ [bit]) (by simpa using h) (by simp)

/-- §5.2: up to seven ones after the last symbol are padding. -/
theorem decodeFrom_padding (k j : Nat) (h : j + k ≤ 7) :
    decodeFrom (List.replicate k true) (List.replicate j true) = .octets [] := by
  induction k generalizing j with
  | zero =>
    simp only [List.replicate, decodeFrom, List.length_replicate]
    split
    · omega
    · simp
  | succ k ih =>
    have heos : List.replicate (j + 1) true ++ List.replicate (29 - j) true =
        table[256]'(by simp [table_length]) := by
      rw [eos_ones, List.replicate_append_replicate]; congr 1; omega
    have hnone := symbolOf_proper_prefix 256 (by simp [table_length]) _ _ heos
      (by simp; omega)
    simp only [List.replicate_succ, decodeFrom]
    rw [show List.replicate j true ++ [true] = List.replicate (j + 1) true by
      simp [List.replicate_succ']]
    rw [hnone]
    exact ih (j + 1) (by omega)

theorem getD_table (octet : Nat) (h : octet < table.length) : table.getD octet [] = table[octet] := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h]

theorem decodeFrom_encodeBits (octets : List Nat) (h : ∀ octet ∈ octets, octet < 256) (k : Nat)
    (hk : k ≤ 7) :
    decodeFrom (encodeBits octets ++ List.replicate k true) [] = .octets octets := by
  induction octets with
  | nil => simpa [encodeBits] using decodeFrom_padding k 0 (by omega)
  | cons octet rest ih =>
    have hoctet : octet < 256 := h octet (by simp)
    have hlt : octet < table.length := by rw [table_length]; omega
    have hne : table[octet] ≠ [] := by
      intro hnil; have := table_length_ge octet hlt; simp [hnil] at this
    simp only [encodeBits, List.flatMap_cons, getD_table octet hlt, List.append_assoc]
    rw [decodeFrom_code octet hlt _ table[octet] [] (by simp) hne]
    simp only [show octet ≠ 256 by omega, ↓reduceIte]
    rw [show (rest.flatMap fun octet => table.getD octet []) = encodeBits rest from rfl,
      ih (fun o ho => h o (by simp [ho]))]
    rfl

/-- One octet's eight bits read back to themselves. -/
theorem bitsOf_ofBits_octet :
    ∀ b0 b1 b2 b3 b4 b5 b6 b7 : Bool,
      bitsOf (ofBits [b0, b1, b2, b3, b4, b5, b6, b7] 0) 8 = [b0, b1, b2, b3, b4, b5, b6, b7] := by
  decide

theorem unpack_pack (bits : List Bool) (h : bits.length % 8 = 0) : unpack (pack bits) = bits := by
  induction bits using pack.induct with
  | case1 b0 b1 b2 b3 b4 b5 b6 b7 rest ih =>
    simp only [pack, unpack, List.flatMap_cons]
    rw [bitsOf_ofBits_octet]
    simp only [List.length_cons] at h
    rw [show (List.flatMap (fun octet => bitsOf octet 8) (pack rest)) = unpack (pack rest) from rfl,
      ih (by omega)]
    rfl
  | case2 bits hnot =>
    match bits, hnot with
    | [], _ => rfl
    | [_], _ | [_, _], _ | [_, _, _], _ | [_, _, _, _], _ | [_, _, _, _, _], _
    | [_, _, _, _, _, _], _ | [_, _, _, _, _, _, _], _ => simp at h
    | _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: _, hnot => exact absurd rfl (hnot _ _ _ _ _ _ _ _ _)

/-- §5.2: every string of octets decodes back from its encoding. -/
theorem decode_encode (octets : List Nat) (h : ∀ octet ∈ octets, octet < 256) :
    decode (encode octets) = .octets octets := by
  unfold decode encode
  rw [unpack_pack _ (by simp [padding, List.length_replicate]; omega)]
  exact decodeFrom_encodeBits octets h ((8 - (encodeBits octets).length % 8) % 8) (by omega)

theorem cons_eq_octets (symbol : Nat) (outcome : Outcome) (octets : List Nat)
    (h : outcome.cons symbol = .octets octets) :
    ∃ rest, outcome = .octets rest ∧ octets = symbol :: rest := by
  cases outcome with
  | octets rest => simp only [Outcome.cons, Outcome.octets.injEq] at h; exact ⟨rest, rfl, h.symm⟩
  | _ => simp [Outcome.cons] at h

/-- Whatever a decoding accepts is octets: EOS and nothing above it reaches the output. -/
theorem decode_octets (encoded : List Nat) (octets : List Nat) (h : decode encoded = .octets octets) :
    ∀ octet ∈ octets, octet < 256 := by
  unfold decode at h
  generalize unpack encoded = bits at h
  suffices ∀ (bits partialCode : List Bool) (octets : List Nat),
      decodeFrom bits partialCode = .octets octets → ∀ octet ∈ octets, octet < 256 from
    this bits [] octets h
  intro bits
  induction bits with
  | nil =>
    intro partialCode octets h
    simp only [decodeFrom] at h
    split at h
    · cases h
    · split at h
      · cases h; simp
      · cases h
  | cons bit rest ih =>
    intro partialCode octets h
    simp only [decodeFrom] at h
    split at h
    · rename_i symbol hsym
      split at h
      · cases h
      · obtain ⟨tail, htail, rfl⟩ := cons_eq_octets symbol _ octets h
        obtain ⟨hlt, _⟩ := symbolOf_some _ symbol hsym
        rw [table_length] at hlt
        intro octet hmem
        simp only [List.mem_cons] at hmem
        rcases hmem with rfl | hmem
        · omega
        · exact ih [] tail htail octet hmem
    · exact ih _ octets h

end Colibri.Wire.Huffman
