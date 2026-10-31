--------------------------------- MODULE Bbr ---------------------------------
(***************************************************************************)
(* BBRv3's states (draft-ietf-ccwg-bbr-06 §5.3, §5.4) as                   *)
(* src/quic/recovery/recovery_bbr/ moves them on each ACK frame and each    *)
(* send (design §8 step 29b.2). TLC checks every order of ACK frames, idle *)
(* periods and the signals each frame carries. Each state must end at the  *)
(* first ACK frame its rules allow, so on a path that delivers, it ends.  *)
(*                                                                         *)
(* Time is counted in ticks, and each clock is an age held one tick past   *)
(* the largest value any rule compares it with, so the state space is      *)
(* finite with no bound on how long the model runs.                        *)
(* spec/lean/Colibri/Quic/BbrStates.lean proves the volumes and the draws, *)
(* and this model checks the moves those comparisons make.                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    Interval,       \* BBR.ProbeRTTInterval, in ticks
    Duration,       \* BBR.ProbeRTTDuration, in ticks
    Wait,           \* the longest bandwidth probe wait, in ticks
    RenoRounds,     \* the Reno bound on a probe wait, in rounds
    DrainRounds,    \* the rounds after which Drain ends
    FullRounds,     \* the rounds without growth that fill the pipe
    Mutant          \* "none", or the one rule a mutant in mutants/ breaks

ASSUME Duration \in Nat /\ Duration < Interval
ASSUME Wait \in Nat /\ RenoRounds \in Nat /\ DrainRounds \in Nat /\ FullRounds \in Nat /\ FullRounds >= 1
Mutants == {"none", "entry_at_interval", "exit_without_round", "no_refresh_at_exit", "drain_waits",
            "exit_to_cruise", "round_counted_late"}
ASSUME Mutant \in Mutants

States == {"startup", "drain", "down", "cruise", "refill", "up", "probe_rtt"}
ProbeBw == {"down", "cruise", "refill", "up"}
Kinds == {"none", "ack", "idle"}

(* An age held one tick past the largest value it is compared with. *)
Cap(age, limit) == IF age > limit THEN limit + 1 ELSE age

VARIABLES
    state,          \* Bbr.state
    fullCount,      \* full_bw_count
    fullNow,        \* full_bw_now
    reached,        \* full_bw_reached
    drainRounds,    \* the rounds since Drain started
    cycleAge,       \* the time since cycle_start_ns
    roundsSince,    \* rounds_since_probe_up
    probeAge,       \* the time since probe_rtt_min_at_ns
    doneSet,        \* probe_rtt_done_at_ns # 0
    doneAge,        \* the time since probe_rtt_done_at_ns was set
    roundDone,      \* probe_rtt_round_done
    idle,           \* idle_restart
    sinceExit,      \* the time since ProbeRTT last ended, counted apart from the code
    last            \* the last event, which the properties read

vars == <<state, fullCount, fullNow, reached, drainRounds, cycleAge, roundsSince, probeAge,
          doneSet, doneAge, roundDone, idle, sinceExit, last>>

TypeOK ==
    /\ state \in States
    /\ fullCount \in 0..FullRounds
    /\ fullNow \in BOOLEAN /\ reached \in BOOLEAN
    /\ drainRounds \in 0..(DrainRounds + 1)
    /\ cycleAge \in 0..(Wait + 1)
    /\ roundsSince \in 0..(RenoRounds + 1)
    /\ probeAge \in 0..(Interval + 1)
    /\ doneSet \in BOOLEAN /\ doneAge \in 0..(Duration + 1) /\ roundDone \in BOOLEAN
    /\ idle \in BOOLEAN
    /\ sinceExit \in 0..(Interval + 1)
    /\ last.kind \in Kinds /\ last.before \in States

Init ==
    /\ state = "startup"
    /\ fullCount = 0 /\ fullNow = FALSE /\ reached = FALSE
    /\ drainRounds = 0 /\ cycleAge = 0 /\ roundsSince = 0
    /\ probeAge = 0 /\ doneSet = FALSE /\ doneAge = 0 /\ roundDone = FALSE
    /\ idle = FALSE
    /\ sinceExit = Interval + 1
    /\ last = [kind |-> "none", before |-> "startup", spaced |-> TRUE, ready |-> FALSE,
               roundSeen |-> FALSE, reached |-> FALSE, timed |-> FALSE, small |-> FALSE,
               drainOver |-> FALSE]

(* What the properties read of one event: the state before it, and of the ages and flags as   *)
(* the event's rules compared them, after time passed and before the event moved anything.    *)
Note(kind, b, roundStart, small) ==
    [kind |-> kind, before |-> state, spaced |-> b.sinceExit > Interval, ready |-> b.doneAge > Duration,
     roundSeen |-> b.roundDone \/ roundStart, reached |-> b.reached, timed |-> b.doneSet,
     small |-> small, drainOver |-> b.drainRounds > DrainRounds]

(* The record each step of an ACK frame passes to the next. *)
Bundle(s, fc, fn, r, dr, ca, rs, pa, ds, da, rd, se) ==
    [state |-> s, fullCount |-> fc, fullNow |-> fn, reached |-> r, drainRounds |-> dr,
     cycleAge |-> ca, roundsSince |-> rs, probeAge |-> pa, doneSet |-> ds, doneAge |-> da,
     roundDone |-> rd, sinceExit |-> se]

(* §5.3.3.9's StartProbeBW_DOWN: a new wait, whose Reno start is 0 or 1. *)
StartDown(b, start) == [b EXCEPT !.state = "down", !.cycleAge = 0, !.roundsSince = start]

(* §5.3.1.2's CheckFullBWReached. *)
FullBw(b, roundStart, grew, limited) ==
    IF b.fullNow \/ ~roundStart \/ limited THEN b
    ELSE IF grew THEN [b EXCEPT !.fullCount = 0, !.fullNow = FALSE]
    ELSE LET count == b.fullCount + 1
         IN [b EXCEPT !.fullCount = count, !.fullNow = (count >= FullRounds),
                      !.reached = b.reached \/ (count >= FullRounds)]

(* §5.3.1.1's CheckStartupDone, and §5.3.2's CheckDrainDone. *)
StartupDone(b) == IF b.state = "startup" /\ b.reached THEN [b EXCEPT !.state = "drain", !.drainRounds = 0] ELSE b
DrainDone(b, small, start) ==
    IF b.state = "drain" /\ (small \/ (b.drainRounds > DrainRounds /\ Mutant # "drain_waits"))
    THEN StartDown(b, start) ELSE b

(* §5.3.3.9's UpdateProbeBWCyclePhase, with no loss: BBR.inflight_longterm stays unbounded. *)
TimeToProbe(b) == b.cycleAge > Wait \/ b.roundsSince >= RenoRounds
Refill(b) == [b EXCEPT !.state = "refill"]
Cycle(b, roundStart, small, start) ==
    IF ~b.reached THEN b
    ELSE CASE b.state = "down" -> IF TimeToProbe(b) THEN Refill(b)
                                  ELSE IF small THEN [b EXCEPT !.state = "cruise"] ELSE b
           [] b.state = "cruise" -> IF TimeToProbe(b) THEN Refill(b) ELSE b
           [] b.state = "refill" -> IF roundStart THEN [b EXCEPT !.state = "up", !.fullCount = 0, !.fullNow = FALSE] ELSE b
           [] b.state = "up" -> IF b.fullNow THEN StartDown(b, start) ELSE b
           [] OTHER -> b

(* §5.3.4.3's UpdateMinRTT for the probe's minimum. *)
Expired(b) == IF Mutant = "entry_at_interval" THEN b.probeAge >= Interval ELSE b.probeAge > Interval
MinRtt(b, lower) == IF lower \/ Expired(b) THEN [b EXCEPT !.probeAge = 0] ELSE b

(* §5.3.4.3's CheckProbeRTTDone and §5.3.4.4's ExitProbeRTT. *)
ExitProbeRtt(b, start) ==
    LET refreshed == IF Mutant = "no_refresh_at_exit" THEN b ELSE [b EXCEPT !.probeAge = 0]
        ended == [refreshed EXCEPT !.sinceExit = 0, !.doneSet = FALSE]
    IN IF b.reached \/ Mutant = "exit_to_cruise" THEN [StartDown(ended, start) EXCEPT !.state = "cruise"]
       ELSE [ended EXCEPT !.state = "startup"]
DoneReady(b) == b.doneSet /\ b.doneAge > Duration

(* §5.3.4.3's CheckProbeRTT and HandleProbeRTT. `expired` is what UpdateMinRTT computed. *)
ProbeRtt(b, expired, roundStart, small, start) ==
    LET entered == IF b.state # "probe_rtt" /\ expired /\ ~idle
                   THEN [b EXCEPT !.state = "probe_rtt", !.doneSet = FALSE] ELSE b
    IN IF entered.state # "probe_rtt" THEN entered
       ELSE IF ~entered.doneSet
       THEN IF small THEN [entered EXCEPT !.doneSet = TRUE, !.doneAge = 0, !.roundDone = FALSE] ELSE entered
       ELSE LET seen == IF Mutant = "round_counted_late" THEN FALSE ELSE roundStart
                rounded == [entered EXCEPT !.roundDone = entered.roundDone \/ seen]
            IN IF (rounded.roundDone \/ Mutant = "exit_without_round") /\ DoneReady(rounded)
               THEN ExitProbeRtt(rounded, start) ELSE rounded

(* Time passes: every age grows by `elapsed` ticks, held past its limit. *)
Aged(b, elapsed) ==
    [b EXCEPT !.cycleAge = Cap(b.cycleAge + elapsed, Wait), !.probeAge = Cap(b.probeAge + elapsed, Interval),
              !.doneAge = Cap(b.doneAge + elapsed, Duration), !.sinceExit = Cap(b.sinceExit + elapsed, Interval)]

(* A round start counts for the Reno bound and for Drain. *)
Rounded(b, roundStart) ==
    IF ~roundStart THEN b
    ELSE [b EXCEPT !.roundsSince = Cap(b.roundsSince + 1, RenoRounds),
                   !.drainRounds = IF b.state = "drain" THEN Cap(b.drainRounds + 1, DrainRounds) ELSE b.drainRounds]

Apply(b) ==
    /\ state' = b.state /\ fullCount' = b.fullCount /\ fullNow' = b.fullNow /\ reached' = b.reached
    /\ drainRounds' = b.drainRounds /\ cycleAge' = b.cycleAge /\ roundsSince' = b.roundsSince
    /\ probeAge' = b.probeAge /\ doneSet' = b.doneSet /\ doneAge' = b.doneAge
    /\ roundDone' = b.roundDone /\ sinceExit' = b.sinceExit

Now == Bundle(state, fullCount, fullNow, reached, drainRounds, cycleAge, roundsSince, probeAge,
              doneSet, doneAge, roundDone, sinceExit)

(* One ACK frame, in the order of Bbr.on_ack. `small` says the octets in flight fit every    *)
(* target the states compare them with; `start` is the Reno start a new wait draws.         *)
Ack(elapsed, roundStart, grew, limited, small, lower, start) ==
    LET aged == Aged(Now, elapsed)
        b1 == Rounded(aged, roundStart)
        b2 == FullBw(b1, roundStart, grew, limited)
        b3 == StartupDone(b2)
        b4 == DrainDone(b3, small, start)
        b5 == Cycle(b4, roundStart, small, start)
        b6 == MinRtt(b5, lower)
        b7 == ProbeRtt(b6, Expired(b5), roundStart, small, start)
    IN /\ Apply(b7)
       /\ idle' = FALSE
       /\ last' = Note("ack", [b6 EXCEPT !.sinceExit = aged.sinceExit, !.doneAge = aged.doneAge,
                                          !.drainRounds = b1.drainRounds], roundStart, small)

(* §5.4.1's HandleRestartFromIdle, before a send with nothing in flight. *)
Idle ==
    /\ idle' = TRUE
    /\ IF state = "probe_rtt" /\ DoneReady(Now)
       THEN Apply(ExitProbeRtt(Now, 0))
       ELSE UNCHANGED <<state, fullCount, fullNow, reached, drainRounds, cycleAge, roundsSince, probeAge,
                        doneSet, doneAge, roundDone, sinceExit>>
    /\ last' = Note("idle", Now, FALSE, FALSE)

Next ==
    \/ \E elapsed \in 0..1, roundStart, grew, limited, small, lower \in BOOLEAN, start \in 0..1 :
        Ack(elapsed, roundStart, grew, limited, small, lower, start)
    \/ Idle

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* The properties.                                                         *)
(***************************************************************************)

(* §5.3.4.2: ProbeRTT comes at most once each BBR.ProbeRTTInterval. *)
ProbeRttSpaced == (last.kind = "ack" /\ last.before # "probe_rtt" /\ state = "probe_rtt") =>
    last.spaced

(* §5.3.4.3: ProbeRTT holds BBR.ProbeRTTDuration, and one round unless an idle period ends it. *)
ProbeRttHolds == (last.before = "probe_rtt" /\ state # "probe_rtt") =>
    /\ last.ready
    /\ last.roundSeen \/ last.kind = "idle"

(* §5.3.4.4: ProbeRTT ends in CRUISE once the pipe is full, and in Startup before. *)
ProbeRttExits == (last.before = "probe_rtt" /\ state # "probe_rtt") =>
    state = IF last.reached THEN "cruise" ELSE "startup"

(* §5.3.2: Drain lasts at most DrainRounds rounds and one more ACK frame. *)
DrainBounded == state = "drain" => drainRounds <= DrainRounds

(* §5.3.3: ProbeBW comes only once the pipe is full, and Startup never comes after it. *)
ProbeBwAfterFull == state \in ProbeBw => reached
StartupBeforeFull == reached => state # "startup"

(* §5.3.4.3: once in flight fits, ProbeRTT starts its timer, and it ends at the first ACK     *)
(* frame after both the timer and a round. Checking that each end comes when it is due     *)
(* stands in for a liveness property, which costs TLC a thousand times the time here.       *)
ProbeRttTimes == (last.kind = "ack" /\ last.before = "probe_rtt" /\ ~last.timed /\ last.small) =>
    doneSet \/ state # "probe_rtt"
ProbeRttEndsWhenDue == (last.kind = "ack" /\ last.before = "probe_rtt" /\ last.timed /\ last.ready
                        /\ last.roundSeen) => state # "probe_rtt"

(* §5.3.2: Drain ends at the first ACK frame with in flight fitting the BDP, or past its rounds. *)
DrainEndsWhenDue == (last.kind = "ack" /\ last.before = "drain" /\ (last.small \/ last.drainOver)) =>
    state # "drain"

Properties ==
    /\ ProbeRttTimes
    /\ ProbeRttEndsWhenDue
    /\ DrainEndsWhenDue
    /\ ProbeRttSpaced
    /\ ProbeRttHolds
    /\ ProbeRttExits
    /\ DrainBounded
    /\ ProbeBwAfterFull
    /\ StartupBeforeFull
=============================================================================
