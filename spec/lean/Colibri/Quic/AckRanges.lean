/-!
# ACK ranges (RFC 9000 §19.3.1)

An ACK frame names the largest packet number acknowledged and the First ACK Range below it, then
walks downward in Gap and ACK Range Length pairs. Each pair names one more range: its largest is
the previous range's smallest less the gap less two, and it reaches the length below that. A
computed packet number below zero is a connection error of FRAME_ENCODING_ERROR.

These definitions follow `src/quic/frame/frame_ack.zig`, which reads the ranges, and
`write_ack_at` in `src/quic/space/space.zig`, which writes them, over natural numbers; the
theorems are about them (https://github.com/c4milo/colibri/issues/52).

What is proved:
- `decode_encode`: ranges that descend with a number unacknowledged between each two, as
  `space_received.zig` keeps them, read back from what `encode` writes.
- `encode_decode` and `decode_wellFormed`: whatever `decode` accepts is such ranges, and `encode`
  writes them back as the same fields, so the two are inverse.
- `decode_none_iff`: `decode` refuses a frame exactly when a packet number §19.3.1 computes over
  the integers is below zero.
-/

namespace Colibri.Quic.AckRanges

/-- One run of acknowledged packet numbers, smallest and largest inclusive. `Range` in
`frame_ack.zig`. -/
structure Range where
  smallest : Nat
  largest : Nat
deriving DecidableEq, Repr

/-- §19.3.1: the ranges the Gap and ACK Range Length pairs name below `previous`, the smallest of
the range before them, or `none` when a number would go below zero. `walk_ranges` and
`Iterator.next` in `frame_ack.zig`. -/
def walk : Nat → List (Nat × Nat) → Option (List Range)
  | _, [] => some []
  | previous, (gap, length) :: rest =>
    if previous < gap + 2 then none
    else
      let largest := previous - gap - 2
      if length > largest then none
      else (walk (largest - length) rest).map (fun ranges => ⟨largest - length, largest⟩ :: ranges)

/-- §19.3.1: the ranges an ACK frame names, from its Largest Acknowledged, its First ACK Range
and its pairs, or `none` when a number would go below zero. `read` in `frame_ack.zig`. -/
def decode (largest first : Nat) (pairs : List (Nat × Nat)) : Option (List Range) :=
  if first > largest then none
  else (walk (largest - first) pairs).map (fun ranges => ⟨largest - first, largest⟩ :: ranges)

/-- §19.3.1: the pairs that name `ranges` below `previous`. -/
def encodePairs : Nat → List Range → List (Nat × Nat)
  | _, [] => []
  | previous, range :: rest =>
    (previous - range.largest - 2, range.largest - range.smallest) :: encodePairs range.smallest rest

/-- §19.3: the Largest Acknowledged, the First ACK Range and the pairs that name `ranges`.
`write_ack_at` in `space.zig`. -/
def encode : List Range → Option (Nat × Nat × List (Nat × Nat))
  | [] => none
  | range :: rest => some (range.largest, range.largest - range.smallest, encodePairs range.smallest rest)

/-- Ranges below `previous` that descend, each at least two below the smallest of the one before,
so that a number between them is unacknowledged. -/
def Descending : Nat → List Range → Prop
  | _, [] => True
  | previous, range :: rest =>
    range.smallest ≤ range.largest ∧ range.largest + 2 ≤ previous ∧ Descending range.smallest rest

/-- The ranges an ACK frame can carry: at least one, descending as `Descending` says. -/
def WellFormed : List Range → Prop
  | [] => False
  | range :: rest => range.smallest ≤ range.largest ∧ Descending range.smallest rest

/-- §19.3.1's arithmetic over the integers, with no refusal: the largest and smallest of every
range the pairs name below `previous`. -/
def computedFrom : Int → List (Nat × Nat) → List Int
  | _, [] => []
  | previous, (gap, length) :: rest =>
    let largest := previous - gap - 2
    let smallest := largest - length
    largest :: smallest :: computedFrom smallest rest

/-- Every packet number §19.3.1 computes for a frame, over the integers. -/
def computed (largest first : Nat) (pairs : List (Nat × Nat)) : List Int :=
  ((largest : Int) - first) :: computedFrom ((largest : Int) - first) pairs

/-- One pair accepted, taken apart. -/
theorem walk_cons (previous gap length : Nat) (rest : List (Nat × Nat)) (ranges : List Range)
    (h : walk previous ((gap, length) :: rest) = some ranges) :
    gap + 2 ≤ previous ∧ length ≤ previous - gap - 2 ∧ ∃ tail,
      walk (previous - gap - 2 - length) rest = some tail ∧
      ranges = ⟨previous - gap - 2 - length, previous - gap - 2⟩ :: tail := by
  simp only [walk] at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rw [Option.map_eq_some_iff] at h
      obtain ⟨tail, htail, rfl⟩ := h
      exact ⟨by omega, by omega, tail, htail, rfl⟩

theorem walk_encodePairs (previous : Nat) (ranges : List Range) (h : Descending previous ranges) :
    walk previous (encodePairs previous ranges) = some ranges := by
  induction ranges generalizing previous with
  | nil => rfl
  | cons range rest ih =>
    simp only [Descending] at h
    obtain ⟨h1, h2, h3⟩ := h
    have e1 : previous - (previous - range.largest - 2) - 2 = range.largest := by omega
    have e2 : range.largest - (range.largest - range.smallest) = range.smallest := by omega
    simp only [encodePairs, walk, e1, e2, ih range.smallest h3,
      show ¬ (previous < previous - range.largest - 2 + 2) by omega,
      show ¬ (range.largest - range.smallest > range.largest) by omega, ↓reduceIte, Option.map_some]

theorem walk_descending (previous : Nat) (pairs : List (Nat × Nat)) (ranges : List Range)
    (h : walk previous pairs = some ranges) : Descending previous ranges := by
  induction pairs generalizing previous ranges with
  | nil => simp only [walk, Option.some.injEq] at h; subst h; trivial
  | cons pair rest ih =>
    obtain ⟨gap, length⟩ := pair
    obtain ⟨hgap, hlength, tail, htail, rfl⟩ := walk_cons previous gap length rest ranges h
    exact ⟨by dsimp only; omega, by dsimp only; omega, ih _ tail htail⟩

theorem encodePairs_walk (previous : Nat) (pairs : List (Nat × Nat)) (ranges : List Range)
    (h : walk previous pairs = some ranges) : encodePairs previous ranges = pairs := by
  induction pairs generalizing previous ranges with
  | nil => simp only [walk, Option.some.injEq] at h; subst h; rfl
  | cons pair rest ih =>
    obtain ⟨gap, length⟩ := pair
    obtain ⟨hgap, hlength, tail, htail, rfl⟩ := walk_cons previous gap length rest ranges h
    simp only [encodePairs, ih _ tail htail, List.cons.injEq, Prod.mk.injEq, and_true]
    omega

/-- §19.3.1: ranges that descend with a number unacknowledged between each two read back from
what `encode` writes. -/
theorem decode_encode (range : Range) (rest : List Range) (h : WellFormed (range :: rest)) :
    decode range.largest (range.largest - range.smallest) (encodePairs range.smallest rest) =
      some (range :: rest) := by
  simp only [WellFormed] at h
  obtain ⟨h1, h2⟩ := h
  have e : range.largest - (range.largest - range.smallest) = range.smallest := by omega
  simp only [decode, e, walk_encodePairs range.smallest rest h2,
    show ¬ (range.largest - range.smallest > range.largest) by omega, ↓reduceIte, Option.map_some]

theorem decode_cons (largest first : Nat) (pairs : List (Nat × Nat)) (ranges : List Range)
    (h : decode largest first pairs = some ranges) :
    first ≤ largest ∧ ∃ tail, walk (largest - first) pairs = some tail ∧
      ranges = ⟨largest - first, largest⟩ :: tail := by
  simp only [decode] at h
  split at h
  · simp at h
  · rw [Option.map_eq_some_iff] at h
    obtain ⟨tail, htail, rfl⟩ := h
    exact ⟨by omega, tail, htail, rfl⟩

/-- §19.3.1: whatever `decode` accepts descends with a number unacknowledged between each two
ranges. -/
theorem decode_wellFormed (largest first : Nat) (pairs : List (Nat × Nat)) (ranges : List Range)
    (h : decode largest first pairs = some ranges) : WellFormed ranges := by
  obtain ⟨hfirst, tail, htail, rfl⟩ := decode_cons largest first pairs ranges h
  exact ⟨by dsimp only; omega, walk_descending _ pairs tail htail⟩

/-- §19.3: `encode` writes what `decode` accepted back as the same fields. -/
theorem encode_decode (largest first : Nat) (pairs : List (Nat × Nat)) (ranges : List Range)
    (h : decode largest first pairs = some ranges) : encode ranges = some (largest, first, pairs) := by
  obtain ⟨hfirst, tail, htail, rfl⟩ := decode_cons largest first pairs ranges h
  simp only [encode, encodePairs_walk _ pairs tail htail, Option.some.injEq, Prod.mk.injEq,
    and_true, true_and]
  omega

theorem walk_none_iff (previous : Nat) (pairs : List (Nat × Nat)) :
    walk previous pairs = none ↔ ∃ x ∈ computedFrom (previous : Int) pairs, x < 0 := by
  induction pairs generalizing previous with
  | nil => simp [walk, computedFrom]
  | cons pair rest ih =>
    obtain ⟨gap, length⟩ := pair
    simp only [computedFrom, List.mem_cons, or_and_right, exists_or, exists_eq_left]
    by_cases hgap : previous < gap + 2
    · simp only [walk, hgap, ↓reduceIte, true_iff]
      left; omega
    · by_cases hlength : length > previous - gap - 2
      · simp only [walk, hgap, hlength, ↓reduceIte, true_iff]
        right; left; omega
      · have hcast : ((previous - gap - 2 - length : Nat) : Int) =
            (previous : Int) - gap - 2 - length := by omega
        simp only [walk, hgap, hlength, ↓reduceIte, Option.map_eq_none_iff, ih, hcast,
          show ¬ ((previous : Int) - gap - 2 < 0) by omega,
          show ¬ ((previous : Int) - gap - 2 - length < 0) by omega, false_or]

/-- §19.3.1: `decode` refuses a frame exactly when a packet number it computes over the integers
is below zero, which is the connection error of FRAME_ENCODING_ERROR that section names. -/
theorem decode_none_iff (largest first : Nat) (pairs : List (Nat × Nat)) :
    decode largest first pairs = none ↔ ∃ x ∈ computed largest first pairs, x < 0 := by
  simp only [computed, List.mem_cons, or_and_right, exists_or, exists_eq_left]
  by_cases hfirst : first > largest
  · simp only [decode, hfirst, ↓reduceIte, true_iff]
    left; omega
  · have hcast : ((largest - first : Nat) : Int) = (largest : Int) - first := by omega
    simp only [decode, hfirst, ↓reduceIte, Option.map_eq_none_iff, walk_none_iff, hcast,
      show ¬ ((largest : Int) - first < 0) by omega, false_or]

end Colibri.Quic.AckRanges
