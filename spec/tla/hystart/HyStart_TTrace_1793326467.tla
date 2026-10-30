---- MODULE HyStart_TTrace_1793326467 ----
EXTENDS Sequences, TLCExt, HyStart, Toolbox, Naturals, TLC

_expression ==
    LET HyStart_TEExpression == INSTANCE HyStart_TEExpression
    IN HyStart_TEExpression!expression
----

_trace ==
    LET HyStart_TETrace == INSTANCE HyStart_TETrace
    IN HyStart_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        cssRounds = (6)
        /\
        inCss = (6)
        /\
        last = ([lastMin |-> 4, roundMin |-> 4, samples |-> 0, baseline |-> 2, inCss |-> 5, kind |-> "round", stageBefore |-> "conservative"])
        /\
        stage = ("conservative")
        /\
        roundMin = (4)
        /\
        baseline = (2)
        /\
        lastMin = (4)
        /\
        samples = (0)
        /\
        rounds = (6)
    )
----

_init ==
    /\ inCss = _TETrace[1].inCss
    /\ samples = _TETrace[1].samples
    /\ rounds = _TETrace[1].rounds
    /\ roundMin = _TETrace[1].roundMin
    /\ last = _TETrace[1].last
    /\ baseline = _TETrace[1].baseline
    /\ lastMin = _TETrace[1].lastMin
    /\ cssRounds = _TETrace[1].cssRounds
    /\ stage = _TETrace[1].stage
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ inCss  = _TETrace[i].inCss
        /\ inCss' = _TETrace[j].inCss
        /\ samples  = _TETrace[i].samples
        /\ samples' = _TETrace[j].samples
        /\ rounds  = _TETrace[i].rounds
        /\ rounds' = _TETrace[j].rounds
        /\ roundMin  = _TETrace[i].roundMin
        /\ roundMin' = _TETrace[j].roundMin
        /\ last  = _TETrace[i].last
        /\ last' = _TETrace[j].last
        /\ baseline  = _TETrace[i].baseline
        /\ baseline' = _TETrace[j].baseline
        /\ lastMin  = _TETrace[i].lastMin
        /\ lastMin' = _TETrace[j].lastMin
        /\ cssRounds  = _TETrace[i].cssRounds
        /\ cssRounds' = _TETrace[j].cssRounds
        /\ stage  = _TETrace[i].stage
        /\ stage' = _TETrace[j].stage

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("HyStart_TTrace_1793326467.json", _TETrace)

=============================================================================

 Note that you can extract this module `HyStart_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `HyStart_TEExpression.tla` file takes precedence 
  over the module `HyStart_TEExpression` below).

---- MODULE HyStart_TEExpression ----
EXTENDS Sequences, TLCExt, HyStart, Toolbox, Naturals, TLC

expression == 
    [
        \* To hide variables of the `HyStart` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        inCss |-> inCss
        ,samples |-> samples
        ,rounds |-> rounds
        ,roundMin |-> roundMin
        ,last |-> last
        ,baseline |-> baseline
        ,lastMin |-> lastMin
        ,cssRounds |-> cssRounds
        ,stage |-> stage
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_inCssUnchanged |-> inCss = inCss'
        
        \* Format the `inCss` variable as Json value.
        \* ,_inCssJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(inCss)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_inCssModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].inCss # _TETrace[s-1].inCss
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE HyStart_TETrace ----
\*EXTENDS IOUtils, HyStart, TLC
\*
\*trace == IODeserialize("HyStart_TTrace_1793326467.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE HyStart_TETrace ----
EXTENDS HyStart, TLC

trace == 
    <<
    ([cssRounds |-> 0,inCss |-> 0,last |-> [lastMin |-> 4, roundMin |-> 4, samples |-> 0, baseline |-> 4, inCss |-> 0, kind |-> "none", stageBefore |-> "slow_start"],stage |-> "slow_start",roundMin |-> 4,baseline |-> 4,lastMin |-> 4,samples |-> 0,rounds |-> 0]),
    ([cssRounds |-> 0,inCss |-> 0,last |-> [lastMin |-> 4, roundMin |-> 4, samples |-> 0, baseline |-> 4, inCss |-> 0, kind |-> "sample", stageBefore |-> "slow_start"],stage |-> "slow_start",roundMin |-> 1,baseline |-> 4,lastMin |-> 4,samples |-> 1,rounds |-> 0]),
    ([cssRounds |-> 0,inCss |-> 0,last |-> [lastMin |-> 4, roundMin |-> 1, samples |-> 1, baseline |-> 4, inCss |-> 0, kind |-> "round", stageBefore |-> "slow_start"],stage |-> "slow_start",roundMin |-> 4,baseline |-> 4,lastMin |-> 1,samples |-> 0,rounds |-> 1]),
    ([cssRounds |-> 0,inCss |-> 0,last |-> [lastMin |-> 1, roundMin |-> 4, samples |-> 0, baseline |-> 4, inCss |-> 0, kind |-> "sample", stageBefore |-> "slow_start"],stage |-> "slow_start",roundMin |-> 2,baseline |-> 4,lastMin |-> 1,samples |-> 1,rounds |-> 1]),
    ([cssRounds |-> 1,inCss |-> 1,last |-> [lastMin |-> 1, roundMin |-> 2, samples |-> 1, baseline |-> 4, inCss |-> 0, kind |-> "sample", stageBefore |-> "slow_start"],stage |-> "conservative",roundMin |-> 2,baseline |-> 2,lastMin |-> 1,samples |-> 2,rounds |-> 1]),
    ([cssRounds |-> 2,inCss |-> 2,last |-> [lastMin |-> 1, roundMin |-> 2, samples |-> 2, baseline |-> 2, inCss |-> 1, kind |-> "round", stageBefore |-> "conservative"],stage |-> "conservative",roundMin |-> 4,baseline |-> 2,lastMin |-> 2,samples |-> 0,rounds |-> 2]),
    ([cssRounds |-> 3,inCss |-> 3,last |-> [lastMin |-> 2, roundMin |-> 4, samples |-> 0, baseline |-> 2, inCss |-> 2, kind |-> "round", stageBefore |-> "conservative"],stage |-> "conservative",roundMin |-> 4,baseline |-> 2,lastMin |-> 4,samples |-> 0,rounds |-> 3]),
    ([cssRounds |-> 4,inCss |-> 4,last |-> [lastMin |-> 4, roundMin |-> 4, samples |-> 0, baseline |-> 2, inCss |-> 3, kind |-> "round", stageBefore |-> "conservative"],stage |-> "conservative",roundMin |-> 4,baseline |-> 2,lastMin |-> 4,samples |-> 0,rounds |-> 4]),
    ([cssRounds |-> 5,inCss |-> 5,last |-> [lastMin |-> 4, roundMin |-> 4, samples |-> 0, baseline |-> 2, inCss |-> 4, kind |-> "round", stageBefore |-> "conservative"],stage |-> "conservative",roundMin |-> 4,baseline |-> 2,lastMin |-> 4,samples |-> 0,rounds |-> 5]),
    ([cssRounds |-> 6,inCss |-> 6,last |-> [lastMin |-> 4, roundMin |-> 4, samples |-> 0, baseline |-> 2, inCss |-> 5, kind |-> "round", stageBefore |-> "conservative"],stage |-> "conservative",roundMin |-> 4,baseline |-> 2,lastMin |-> 4,samples |-> 0,rounds |-> 6])
    >>
----


=============================================================================

---- CONFIG HyStart_TTrace_1793326467 ----
CONSTANTS
    Samples = 2
    CssRounds = 5
    Threshold = 1
    RttMax = 3
    RoundMax = 8
    Mutant = "no_round_limit"

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Thu Oct 29 22:14:28 EDT 2026