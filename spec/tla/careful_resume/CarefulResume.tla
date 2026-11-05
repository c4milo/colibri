--------------------------- MODULE CarefulResume ---------------------------
(***************************************************************************)
(* Careful Resume's phases (RFC 9959 §3, decision 149, design §8 step 35e) *)
(* as src/quic/recovery/recovery_resume_phases.zig runs them under CUBIC   *)
(* and NewReno. The window, PipeSize and the flight count datagrams. TLC   *)
(* checks every order of acknowledgments, sends, congestion events and     *)
(* persistent congestion that the bounds allow.                           *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Initial,        \* the initial window, in datagrams (RFC 9002 §7.2)
    Minimum,        \* RFC 9002 §7.2's minimum window
    Saved,          \* §3.1's saved_cwnd
    MaxJump,        \* §3.3's max_jump
    Maximum,        \* the largest window or flight the model reaches
    Mutant          \* "none", or the one rule a mutant in mutants/ breaks

ASSUME Minimum \in Nat /\ Minimum >= 2 /\ Initial >= Minimum
ASSUME Saved \in Nat /\ MaxJump \in Nat /\ Maximum >= Saved
Mutants == {"none", "jump_whole", "confirm_early", "no_halve", "grow_in_retreat", "resume_after_off"}
ASSUME Mutant \in Mutants

Min(a, b) == IF a <= b THEN a ELSE b
Max(a, b) == IF a >= b THEN a ELSE b

Jump == IF Mutant = "jump_whole" THEN Min(MaxJump, Saved) ELSE Min(MaxJump, Saved \div 2)

VARIABLES
    phase,      \* "reconnaissance", "unvalidated", "validating", "safe_retreat" or "off"
    window,     \* congestion_window
    flight,     \* datagrams in flight
    acked,      \* datagrams acknowledged in the Reconnaissance Phase
    pipe,       \* §3.3's PipeSize
    unvalidated,\* datagrams sent in the Unvalidated Phase still unacknowledged
    retreated,  \* whether §3.5 deleted the saved set
    last        \* the last event, which the properties read

vars == <<phase, window, flight, acked, pipe, unvalidated, retreated, last>>
Phases == {"reconnaissance", "unvalidated", "validating", "safe_retreat", "off"}

TypeOK ==
    /\ phase \in Phases
    /\ window \in 1..Maximum
    /\ flight \in 0..Maximum
    /\ acked \in 0..Maximum
    /\ pipe \in 0..Maximum
    /\ unvalidated \in 0..Maximum
    /\ retreated \in BOOLEAN

Init ==
    /\ phase = "reconnaissance"
    /\ window = Initial
    /\ flight = 0
    /\ acked = 0
    /\ pipe = 0
    /\ unvalidated = 0
    /\ retreated = FALSE
    /\ last = [kind |-> "none", phaseBefore |-> "reconnaissance", windowBefore |-> Initial, pipeBefore |-> 0]

Note(kind) == [kind |-> kind, phaseBefore |-> phase, windowBefore |-> window, pipeBefore |-> pipe]

(* §3.3's "check flight_size".                                            *)
LeaveUnvalidated(f) ==
    IF f < Initial \/ f <= pipe
    THEN /\ window' = Max(pipe, Initial)
         /\ phase' = "off"
         /\ UNCHANGED pipe
    ELSE /\ window' = f
         /\ phase' = "validating"
         /\ UNCHANGED pipe

(* A datagram goes out while the window has room (§3.3 counts the        *)
(* unvalidated ones). A full window in the Unvalidated Phase ends it.     *)
Send ==
    /\ flight < window
    /\ flight < Maximum
    /\ flight' = flight + 1
    /\ unvalidated' = IF phase = "unvalidated" THEN Min(unvalidated + 1, Maximum) ELSE unvalidated
    /\ last' = Note("send")
    /\ IF phase = "unvalidated" /\ flight + 1 >= window
       THEN LeaveUnvalidated(flight + 1)
       ELSE UNCHANGED <<phase, window, pipe>>
    /\ UNCHANGED <<acked, retreated>>

(* §3.2: the initial window acknowledged with no congestion confirms the  *)
(* path, and the window jumps (§3.3) when the jump passes it.             *)
Confirm(newAcked) ==
    IF newAcked >= (IF Mutant = "confirm_early" THEN 1 ELSE Initial)
    THEN IF Jump > window
         THEN /\ phase' = "unvalidated"
              /\ window' = Jump
              /\ pipe' = flight - 1
         ELSE /\ phase' = "off"
              /\ UNCHANGED <<window, pipe>>
    ELSE UNCHANGED <<phase, window, pipe>>

Ack ==
    /\ flight > 0
    /\ flight' = flight - 1
    /\ last' = Note("ack")
    /\ CASE phase = "reconnaissance" ->
              /\ acked' = Min(acked + 1, Maximum)
              /\ Confirm(acked + 1)
              /\ UNCHANGED <<unvalidated, retreated>>
         [] phase = "unvalidated" ->
              /\ pipe' = Min(pipe + 1, Maximum)
              /\ unvalidated' = IF unvalidated > 0 THEN unvalidated - 1 ELSE 0
              /\ UNCHANGED <<phase, window, acked, retreated>>
         [] phase = "validating" ->
              /\ pipe' = Min(pipe + 1, Maximum)
              /\ unvalidated' = IF unvalidated > 0 THEN unvalidated - 1 ELSE 0
              /\ phase' = IF unvalidated <= 1 THEN "off" ELSE "validating"
              /\ window' = Min(window + 1, Maximum)
              /\ UNCHANGED <<acked, retreated>>
         [] phase = "safe_retreat" ->
              /\ pipe' = Min(pipe + 1, Maximum)
              /\ unvalidated' = IF unvalidated > 0 THEN unvalidated - 1 ELSE 0
              /\ phase' = IF unvalidated <= 1 THEN "off" ELSE "safe_retreat"
              /\ window' = IF Mutant = "grow_in_retreat" THEN Min(window + 1, Maximum) ELSE window
              /\ UNCHANGED <<acked, retreated>>
         [] phase = "off" ->
              /\ window' = Min(window + 1, Maximum)
              /\ phase' = IF Mutant = "resume_after_off" THEN "unvalidated" ELSE "off"
              /\ UNCHANGED <<acked, pipe, unvalidated, retreated>>

(* §3.2 to §3.5: a congestion event, after the controller's own cut.      *)
Congestion ==
    /\ flight > 0
    /\ flight' = flight - 1
    /\ last' = Note("congestion")
    /\ CASE phase \in {"unvalidated", "validating"} ->
              /\ phase' = IF unvalidated = 0 THEN "off" ELSE "safe_retreat"
              /\ window' = IF Mutant = "no_halve"
                           THEN Max(pipe, Minimum)
                           ELSE Max(pipe \div 2, Minimum)
              /\ retreated' = TRUE
              /\ UNCHANGED <<acked, pipe, unvalidated>>
         [] phase = "reconnaissance" ->
              /\ phase' = "off"
              /\ window' = Max(window \div 2, Minimum)
              /\ UNCHANGED <<acked, pipe, unvalidated, retreated>>
         [] phase \in {"safe_retreat", "off"} ->
              /\ window' = Max(window \div 2, Minimum)
              /\ UNCHANGED <<phase, acked, pipe, unvalidated, retreated>>

(* §3.6: persistent congestion ends Careful Resume.                        *)
Persistent ==
    /\ phase # "off"
    /\ phase' = "off"
    /\ window' = Minimum
    /\ last' = Note("persistent")
    /\ UNCHANGED <<flight, acked, pipe, unvalidated, retreated>>

Next == Send \/ Ack \/ Congestion \/ Persistent

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The properties.                                                         *)
(***************************************************************************)

(* §3.3: "jump_cwnd is less than or equal to Min(max_jump,(saved_cwnd/2))". *)
JumpBound == (phase = "unvalidated") => window <= Min(MaxJump, Saved \div 2)

(* §3.2: the window jumps only once the initial window is acknowledged.   *)
ConfirmFirst == (phase = "unvalidated" /\ last.phaseBefore = "reconnaissance") => acked >= Initial

(* §3.5: "The CWND MUST be reduced to no more than (PipeSize/2)", held at  *)
(* RFC 9002's minimum.                                                     *)
RetreatHalves == (phase = "safe_retreat" /\ last.phaseBefore # "safe_retreat") =>
    window <= Max(last.pipeBefore \div 2, Minimum)

(* §3.5: "The CWND MUST NOT be increased in the Safe Retreat Phase."        *)
NoGrowthInRetreat == (last.kind = "ack" /\ last.phaseBefore = "safe_retreat") => window <= last.windowBefore

(* §3.7: once Careful Resume ends, the connection stays on normal CC.     *)
OffIsFinal == (last.phaseBefore = "off") => phase = "off"

(* §3.5: a retreat deletes the saved set.                                  *)
RetreatDeletes == (phase = "safe_retreat") => retreated

Properties ==
    /\ JumpBound
    /\ ConfirmFirst
    /\ RetreatHalves
    /\ NoGrowthInRetreat
    /\ OffIsFinal
    /\ RetreatDeletes
=============================================================================
