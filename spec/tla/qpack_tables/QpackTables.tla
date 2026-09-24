----------------------------- MODULE QpackTables -----------------------------
(***************************************************************************)
(* The QPACK encoder's and decoder's views of one dynamic table (RFC 9204 *)
(* §2.1, §2.2), as docs/decisions.md entries 74 and 76 have colibri keep   *)
(* them. The encoder inserts entries and sends field sections that         *)
(* reference them; the encoder stream carries the inserts in order, each   *)
(* section travels on a stream of its own, and the decoder stream carries  *)
(* acknowledgments, cancellations and increments back in order. Any of the *)
(* three may lag the others, and any section may be cancelled.             *)
(*                                                                         *)
(* An entry takes one unit of Capacity. A section references a run of     *)
(* entries, from its smallest reference to one below its Required Insert  *)
(* Count. The encoder evicts from the oldest end, and an entry is          *)
(* evictable once its insertion is acknowledged and no unacknowledged      *)
(* section references it (§2.1.1). A section referencing an entry the      *)
(* decoder has not acknowledged may go out only while fewer than           *)
(* BlockedStreams streams could block (§2.1.2).                            *)
(*                                                                         *)
(* RespectFloor and RespectBlockedLimit switch those two rules; a         *)
(* configuration with either off must find a violation. CountReady is the  *)
(* decoder's error colibri had until this model found it: a section whose  *)
(* entries have arrived, but which the decoder has not read again, still   *)
(* counted against the limit, while the encoder, told of the entries, no   *)
(* longer counted it.                                                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Streams,              \* request streams, one section each, as model values
    MaxInserts,           \* inserts the encoder makes at most
    Capacity,             \* entries the table holds
    BlockedStreams,       \* SETTINGS_QPACK_BLOCKED_STREAMS
    RespectFloor,         \* whether an eviction spares referenced entries (§2.1.1)
    RespectBlockedLimit,  \* whether the encoder holds blocked streams to the limit (§2.1.2)
    CountReady            \* whether the decoder counts a section whose entries arrived as blocked

ASSUME MaxInserts \in Nat /\ Capacity \in Nat \ {0} /\ BlockedStreams \in Nat
ASSUME RespectFloor \in BOOLEAN /\ RespectBlockedLimit \in BOOLEAN /\ CountReady \in BOOLEAN

States == {"unsent", "sent", "blocked", "decoded", "cancelled"}
None == [ric |-> 0, smallest |-> 0]

VARIABLES
    inserted,        \* the encoder's insert count
    dropped,         \* the encoder's oldest live entry: entries [dropped, inserted) are live
    known,           \* §2.1.4's Known Received Count, at the encoder
    outstanding,     \* the unacknowledged section on each stream, or None
    section,         \* the section each stream sent: its Required Insert Count and smallest reference
    state,           \* where each stream's section is
    encoderStream,   \* inserts in flight, each the encoder's `dropped` after it
    decoderInserted, \* the decoder's insert count
    decoderDropped,  \* the decoder's oldest live entry
    decoderKnown,    \* the count the decoder has reported
    decoderStream,   \* decoder instructions in flight
    broken           \* the first rule a step broke, or "none"

vars == <<inserted, dropped, known, outstanding, section, state, encoderStream,
          decoderInserted, decoderDropped, decoderKnown, decoderStream, broken>>

Instructions ==
    [kind : {"acknowledgment", "cancellation"}, stream : Streams]
        \cup [kind : {"increment"}, count : 1..MaxInserts]

TypeOK ==
    /\ inserted \in 0..MaxInserts /\ dropped \in 0..inserted /\ known \in 0..MaxInserts
    /\ outstanding \in [Streams -> [ric : 0..MaxInserts, smallest : 0..MaxInserts]]
    /\ section \in [Streams -> [ric : 0..MaxInserts, smallest : 0..MaxInserts]]
    /\ state \in [Streams -> States]
    /\ encoderStream \in Seq(0..MaxInserts)
    /\ decoderInserted \in 0..MaxInserts /\ decoderDropped \in 0..MaxInserts
    /\ decoderKnown \in 0..MaxInserts
    /\ decoderStream \in Seq(Instructions)
    /\ broken \in STRING

Init ==
    /\ inserted = 0 /\ dropped = 0 /\ known = 0
    /\ outstanding = [s \in Streams |-> None]
    /\ section = [s \in Streams |-> None]
    /\ state = [s \in Streams |-> "unsent"]
    /\ encoderStream = <<>>
    /\ decoderInserted = 0 /\ decoderDropped = 0 /\ decoderKnown = 0
    /\ decoderStream = <<>>
    /\ broken = "none"

Break(rule) == broken' = IF broken = "none" THEN rule ELSE broken

(* The smallest entry an unacknowledged section references, or inserted   *)
(* when none does.                                                         *)
Floor ==
    LET referencing == {s \in Streams : outstanding[s].ric > 0}
    IN IF referencing = {} THEN inserted
       ELSE CHOOSE f \in {outstanding[s].smallest : s \in referencing} :
                \A s \in referencing : f <= outstanding[s].smallest

(* §2.1.1: evictable once acknowledged and referenced by nothing           *)
(* outstanding.                                                            *)
Evictable(entry) == entry < known /\ (~RespectFloor \/ entry < Floor)

(* §2.1.2: streams whose section could block.                             *)
CouldBlock == {s \in Streams : outstanding[s].ric > known}

(* The encoder inserts an entry, evicting the oldest when the table is     *)
(* full.                                                                   *)
Insert ==
    /\ inserted < MaxInserts
    /\ IF inserted - dropped < Capacity
       THEN /\ dropped' = dropped
            /\ UNCHANGED broken
       ELSE /\ Evictable(dropped)
            /\ dropped' = dropped + 1
            /\ IF \E s \in Streams : outstanding[s].ric > dropped /\ outstanding[s].smallest <= dropped
               THEN Break("an entry a section references was evicted")
               ELSE UNCHANGED broken
    /\ inserted' = inserted + 1
    /\ encoderStream' = Append(encoderStream, dropped')
    /\ UNCHANGED <<known, outstanding, section, state, decoderInserted, decoderDropped,
                   decoderKnown, decoderStream>>

(* The encoder sends stream s's section, referencing entries smallest to   *)
(* ric - 1. Entries the decoder has not acknowledged need a stream that    *)
(* may block.                                                              *)
SendSection(s) ==
    /\ state[s] = "unsent"
    /\ \E smallest \in dropped..(inserted - 1), largest \in dropped..(inserted - 1) :
        /\ smallest <= largest
        /\ largest >= known =>
              (~RespectBlockedLimit \/ Cardinality(CouldBlock) < BlockedStreams)
        /\ section' = [section EXCEPT ![s] = [ric |-> largest + 1, smallest |-> smallest]]
        /\ outstanding' = [outstanding EXCEPT ![s] = [ric |-> largest + 1, smallest |-> smallest]]
    /\ state' = [state EXCEPT ![s] = "sent"]
    /\ UNCHANGED <<inserted, dropped, known, encoderStream, decoderInserted, decoderDropped,
                   decoderKnown, decoderStream, broken>>

(* The decoder reads the next insert, and evicts what the encoder did.     *)
ReceiveInsert ==
    /\ encoderStream # <<>>
    /\ decoderInserted' = decoderInserted + 1
    /\ decoderDropped' = Head(encoderStream)
    /\ encoderStream' = Tail(encoderStream)
    /\ UNCHANGED <<inserted, dropped, known, outstanding, section, state, decoderKnown,
                   decoderStream, broken>>

(* The decoder decodes stream s's section, which must reference only       *)
(* entries it holds (§2.2.3), and acknowledges it (§4.4.1).                *)
Decode(s) ==
    /\ section[s].ric <= decoderInserted
    /\ state' = [state EXCEPT ![s] = "decoded"]
    /\ IF section[s].smallest < decoderDropped
       THEN Break("a section referenced an entry the decoder had evicted")
       ELSE UNCHANGED broken
    /\ decoderStream' = Append(decoderStream, [kind |-> "acknowledgment", stream |-> s])
    /\ decoderKnown' = IF section[s].ric > decoderKnown THEN section[s].ric ELSE decoderKnown

(* The streams whose section still waits for entries (§2.2.1).            *)
StillBlocked == {t \in Streams : state[t] = "blocked" /\ (CountReady \/ section[t].ric > decoderInserted)}

(* A section reaches the decoder: decoded, or blocked (§2.2.1).            *)
ReceiveSection(s) ==
    /\ state[s] = "sent"
    /\ IF section[s].ric <= decoderInserted
       THEN Decode(s)
       ELSE /\ state' = [state EXCEPT ![s] = "blocked"]
            \* §2.2.1: a stream is blocked while its Required Insert Count is above the insert
            \* count, whether or not the decoder has gone back to its section yet.
            /\ IF Cardinality(StillBlocked) >= BlockedStreams
               THEN Break("more streams blocked than SETTINGS_QPACK_BLOCKED_STREAMS allows")
               ELSE UNCHANGED broken
            /\ UNCHANGED <<decoderStream, decoderKnown>>
    /\ UNCHANGED <<inserted, dropped, known, outstanding, section, encoderStream,
                   decoderInserted, decoderDropped>>

(* A blocked section whose entries have arrived is decoded.                *)
Unblock(s) ==
    /\ state[s] = "blocked"
    /\ section[s].ric <= decoderInserted
    /\ Decode(s)
    /\ UNCHANGED <<inserted, dropped, known, outstanding, section, encoderStream,
                   decoderInserted, decoderDropped>>

(* §2.2.2.2: the stream is reset before its section is decoded.            *)
Cancel(s) ==
    /\ state[s] \in {"sent", "blocked"}
    /\ state' = [state EXCEPT ![s] = "cancelled"]
    /\ decoderStream' = Append(decoderStream, [kind |-> "cancellation", stream |-> s])
    /\ UNCHANGED <<inserted, dropped, known, outstanding, section, encoderStream,
                   decoderInserted, decoderDropped, decoderKnown, broken>>

(* §4.4.3: the decoder reports inserts no acknowledgment reported.         *)
Increment ==
    /\ decoderInserted > decoderKnown
    /\ decoderStream' = Append(decoderStream, [kind |-> "increment", count |-> decoderInserted - decoderKnown])
    /\ decoderKnown' = decoderInserted
    /\ UNCHANGED <<inserted, dropped, known, outstanding, section, state, encoderStream,
                   decoderInserted, decoderDropped, broken>>

(* The encoder reads the next decoder instruction (§4.4).                  *)
ReceiveInstruction ==
    /\ decoderStream # <<>>
    /\ LET instruction == Head(decoderStream) IN
        CASE instruction.kind = "acknowledgment" ->
                /\ known' = IF outstanding[instruction.stream].ric > known
                            THEN outstanding[instruction.stream].ric ELSE known
                /\ outstanding' = [outstanding EXCEPT ![instruction.stream] = None]
          [] instruction.kind = "cancellation" ->
                /\ outstanding' = [outstanding EXCEPT ![instruction.stream] = None]
                /\ UNCHANGED known
          [] instruction.kind = "increment" ->
                /\ known' = known + instruction.count
                /\ UNCHANGED outstanding
    /\ decoderStream' = Tail(decoderStream)
    /\ UNCHANGED <<inserted, dropped, section, state, encoderStream, decoderInserted,
                   decoderDropped, decoderKnown, broken>>

Next ==
    \/ Insert
    \/ ReceiveInsert
    \/ Increment
    \/ ReceiveInstruction
    \/ \E s \in Streams : SendSection(s) \/ ReceiveSection(s) \/ Unblock(s) \/ Cancel(s)

(* Delivery and decoding are fair; sending and cancelling are choices.     *)
Fairness ==
    /\ WF_vars(ReceiveInsert)
    /\ WF_vars(ReceiveInstruction)
    /\ WF_vars(Increment)
    /\ \A s \in Streams : WF_vars(ReceiveSection(s)) /\ WF_vars(Unblock(s))

Spec == Init /\ [][Next]_vars /\ Fairness

(* No rule broken, and the counts stay consistent.                         *)
Safe ==
    /\ broken = "none"
    /\ known <= inserted
    /\ decoderInserted <= inserted

(* Every section sent is eventually decoded or cancelled.                  *)
Settles == \A s \in Streams : (state[s] \in {"sent", "blocked"}) ~> (state[s] \in {"decoded", "cancelled"})

=============================================================================
