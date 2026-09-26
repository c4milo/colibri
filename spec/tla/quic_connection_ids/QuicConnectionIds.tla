------------------------ MODULE QuicConnectionIds ------------------------
(***************************************************************************)
(* The connection IDs a peer issues and colibri uses and retires (RFC 9000 *)
(* §5.1.1, §5.1.2, §19.15, §19.16), as src/quic/connection_id.zig's        *)
(* `Remote` keeps them. The peer issues IDs with NEW_CONNECTION_ID, and    *)
(* asks for older ones back by raising Retire Prior To. colibri retires    *)
(* them with RETIRE_CONNECTION_ID and addresses its packets to an active   *)
(* one. Any frame may be lost or arrive out of order, and a lost frame is  *)
(* sent again (§13.3). An acknowledgment arrives with its frame or is      *)
(* lost, and a frame gone with none is declared lost in the end.           *)
(*                                                                         *)
(* Sequence number 0 is the ID the peer sent in its handshake packets'     *)
(* Source Connection ID field (§5.1.1). Three constants choose between     *)
(* what colibri did when this model was written and what it does now:      *)
(*   - TrackInitial: ID 0 is in the set, counts against the limit, and a   *)
(*     Retire Prior To above 0 retires it. Before, the set held only IDs   *)
(*     from NEW_CONNECTION_ID frames, so ID 0 was never retired;           *)
(*   - Follow: colibri addresses its packets to an active ID in the set,   *)
(*     and moves off one it retired before it sends again. Before, every   *)
(*     packet went to ID 0 (connection_identity.destination);              *)
(*   - OverflowCloses: a retirement past the queue that holds the owed     *)
(*     RETIRE_CONNECTION_ID frames closes the connection with              *)
(*     CONNECTION_ID_LIMIT_ERROR, which §5.1.2 allows. Before, it was      *)
(*     forgotten, which §5.1.2 forbids: "An endpoint MUST NOT forget a     *)
(*     connection ID without retiring it".                                 *)
(* The configuration pinned keeps the first two as they were, and forget   *)
(* the third.                                                              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    MaxSeq,             \* the largest sequence number the peer issues
    Limit,              \* colibri's active_connection_id_limit (§18.2)
    QueueMax,           \* retirements colibri holds before their frames are acknowledged
    LossMax,            \* frames the network may lose in one behavior
    RotateEarly,        \* whether the peer raises Retire Prior To before older IDs are retired
    TrackInitial,
    Follow,
    OverflowCloses

ASSUME /\ {MaxSeq, Limit, QueueMax, LossMax} \subseteq Nat /\ Limit >= 2 /\ QueueMax >= 1
       /\ {RotateEarly, TrackInitial, Follow, OverflowCloses} \subseteq BOOLEAN

Seqs == 0..MaxSeq
None == -1
Packet(dcid, retire) == [dcid |-> dcid, retire |-> retire]
Packets == {Packet(d, r) : d \in Seqs, r \in Seqs \cup {None}}

VARIABLES
    \* the peer, which issues the IDs
    issued,         \* IDs issued so far: 0..issued-1
    rpt,            \* the largest Retire Prior To it sent
    rptOf,          \* rptOf[s]: the Retire Prior To the NEW_CONNECTION_ID for s carries
    retiredAtPeer,  \* IDs colibri's RETIRE_CONNECTION_ID frames retired
    ncidOwed,       \* NEW_CONNECTION_ID frames owed, by sequence number
    ncidInflight,   \* NEW_CONNECTION_ID frames sent and neither acknowledged nor declared lost
    \* colibri
    active,         \* the peer's IDs colibri holds active
    rptSeen,        \* the largest Retire Prior To colibri received
    dcid,           \* the ID colibri addresses its packets to
    retiring,       \* retirements whose frames the peer has not acknowledged
    owed,           \* retirements whose frames are owed now
    retireInflight, \* retirements whose frames are sent and neither acknowledged nor declared lost
    reported,       \* every ID colibri retired
    \* both
    toColibri,      \* NEW_CONNECTION_ID frames on their way, by sequence number
    toPeer,         \* colibri's packets on their way
    losses,
    failure,        \* "none", or "limit" for CONNECTION_ID_LIMIT_ERROR
    sentOnRetired,  \* colibri sent a packet to an ID it had retired (§5.1.2)
    retireOnItself  \* a RETIRE_CONNECTION_ID named its own packet's ID (§19.16)

vars == <<issued, rpt, rptOf, retiredAtPeer, ncidOwed, ncidInflight, active, rptSeen, dcid,
          retiring, owed, retireInflight, reported, toColibri, toPeer, losses, failure,
          sentOnRetired, retireOnItself>>
peerVars == <<issued, rpt, rptOf, retiredAtPeer, ncidOwed, ncidInflight>>
colibriVars == <<active, rptSeen, dcid, retiring, owed, retireInflight, reported>>
flags == <<failure, sentOnRetired, retireOnItself>>

TypeOK ==
    /\ issued \in 1..MaxSeq + 1 /\ rpt \in Seqs /\ rptOf \in [Seqs -> Seqs]
    /\ retiredAtPeer \subseteq Seqs /\ ncidOwed \subseteq Seqs /\ ncidInflight \subseteq Seqs
    /\ active \subseteq Seqs /\ rptSeen \in Seqs /\ dcid \in Seqs
    /\ retiring \subseteq Seqs /\ owed \subseteq retiring /\ retireInflight \subseteq retiring
    /\ reported \subseteq Seqs
    /\ toColibri \subseteq Seqs /\ toPeer \subseteq Packets
    /\ losses \in 0..LossMax /\ failure \in {"none", "limit"}
    /\ sentOnRetired \in BOOLEAN /\ retireOnItself \in BOOLEAN

Init ==
    /\ issued = 1 /\ rpt = 0 /\ rptOf = [s \in Seqs |-> 0]
    /\ retiredAtPeer = {} /\ ncidOwed = {} /\ ncidInflight = {}
    /\ active = IF TrackInitial THEN {0} ELSE {}
    /\ rptSeen = 0 /\ dcid = 0
    /\ retiring = {} /\ owed = {} /\ retireInflight = {} /\ reported = {}
    /\ toColibri = {} /\ toPeer = {} /\ losses = 0
    /\ failure = "none" /\ sentOnRetired = FALSE /\ retireOnItself = FALSE

Live == failure = "none"

---------------------------------------------------------------------------
(* The peer.                                                               *)

(* §5.1.1: the peer issues a new ID, and may raise Retire Prior To with    *)
(* it. The IDs below the new Retire Prior To leave colibri's set before    *)
(* the new one joins it (§5.1.2), so they do not count against the limit.  *)
(* §5.1.2: it "SHOULD NOT issue updates of the Retire Prior To field       *)
(* before receiving RETIRE_CONNECTION_ID frames that retire all connection *)
(* IDs indicated by the previous Retire Prior To value", unless            *)
(* RotateEarly.                                                            *)
Issue(newRpt) ==
    LET s == issued
        kept == {k \in 0..s : k >= newRpt /\ k \notin retiredAtPeer}
    IN /\ Live /\ s <= MaxSeq
       /\ newRpt \in rpt..s
       /\ Cardinality(kept) <= Limit
       /\ newRpt > rpt => (RotateEarly \/ \A k \in 0..rpt - 1 : k \in retiredAtPeer)
       /\ issued' = s + 1
       /\ rpt' = newRpt
       /\ rptOf' = [rptOf EXCEPT ![s] = newRpt]
       /\ ncidOwed' = ncidOwed \cup {s}
       /\ UNCHANGED <<retiredAtPeer, ncidInflight, colibriVars, toColibri, toPeer, losses, flags>>

SendNcid(s) ==
    /\ Live /\ s \in ncidOwed
    /\ ncidOwed' = ncidOwed \ {s}
    /\ ncidInflight' = ncidInflight \cup {s}
    /\ toColibri' = toColibri \cup {s}
    /\ UNCHANGED <<issued, rpt, rptOf, retiredAtPeer, colibriVars, toPeer, losses, flags>>

(* §13.3: a lost NEW_CONNECTION_ID is sent again.                          *)
NcidLost(s) ==
    /\ Live /\ s \in ncidInflight /\ s \notin toColibri
    /\ ncidInflight' = ncidInflight \ {s}
    /\ ncidOwed' = ncidOwed \cup {s}
    /\ UNCHANGED <<issued, rpt, rptOf, retiredAtPeer, colibriVars, toColibri, toPeer, losses,
                   flags>>

---------------------------------------------------------------------------
(* colibri.                                                                *)

(* `Remote.record_retiring`: a retirement is owed a frame once, and one    *)
(* past the queue closes the connection or is forgotten.                   *)
RetireAll(ids, held, queue, known) ==
    LET fresh == ids \ known
        room == QueueMax - Cardinality(queue)
        full == Cardinality(fresh) > room
        kept == IF full THEN CHOOSE sub \in SUBSET fresh : Cardinality(sub) = room ELSE fresh
    IN [held |-> held \ ids,
        queue |-> IF full /\ OverflowCloses THEN queue ELSE queue \cup kept,
        known |-> known \cup ids,
        closes |-> full /\ OverflowCloses]

(* `Remote.offer`, for the NEW_CONNECTION_ID of s (§19.15). The IDs below  *)
(* a raised Retire Prior To are retired first (§5.1.2), then s is retired  *)
(* if it is below it, or else added, which past the limit is               *)
(* CONNECTION_ID_LIMIT_ERROR (§5.1.1).                                     *)
TakeNcid(s) ==
    LET r == rptOf[s]
        raised == IF r > rptSeen THEN r ELSE rptSeen
        below == {a \in active : a < raised}
        retired == IF s < raised THEN below \cup {s} ELSE below
        after == RetireAll(retired, active, retiring, reported)
        added == IF s < raised THEN after.held ELSE after.held \cup {s}
    IN IF s \in active THEN UNCHANGED <<colibriVars, failure>>
       ELSE /\ rptSeen' = raised
            /\ reported' = after.known
            /\ retiring' = after.queue
            /\ owed' = owed \cup (after.queue \ retiring)
            /\ IF after.closes \/ Cardinality(added) > Limit
               THEN /\ failure' = "limit"
                    /\ active' = after.held
               ELSE /\ active' = added
                    /\ UNCHANGED failure
            /\ UNCHANGED <<dcid, retireInflight>>

(* A NEW_CONNECTION_ID arrives, and its acknowledgment with it or not.     *)
DeliverNcid(s, acknowledged) ==
    /\ Live /\ s \in toColibri
    /\ acknowledged \/ losses < LossMax
    /\ toColibri' = toColibri \ {s}
    /\ losses' = IF acknowledged THEN losses ELSE losses + 1
    /\ ncidInflight' = IF acknowledged THEN ncidInflight \ {s} ELSE ncidInflight
    /\ TakeNcid(s)
    /\ UNCHANGED <<issued, rpt, rptOf, retiredAtPeer, ncidOwed, toPeer, sentOnRetired,
                   retireOnItself>>

(* With Follow, colibri moves off an ID it retired to an active one.       *)
SwitchDcid ==
    /\ Live /\ Follow /\ dcid \notin active /\ active # {}
    /\ dcid' = CHOOSE a \in active : \A b \in active : a <= b
    /\ UNCHANGED <<peerVars, active, rptSeen, retiring, owed, retireInflight, reported,
                   toColibri, toPeer, losses, flags>>

(* §5.1.2: an ID colibri retired is one it no longer sends to.             *)
RetiredAtColibri(d) == d \in reported \/ d < rptSeen

Ready == ~Follow \/ dcid \in active

(* A packet to dcid, carrying the RETIRE_CONNECTION_ID for x or nothing.   *)
Put(x) ==
    /\ toPeer' = toPeer \cup {Packet(dcid, x)}
    /\ sentOnRetired' = (sentOnRetired \/ RetiredAtColibri(dcid))
    /\ retireOnItself' = (retireOnItself \/ x = dcid)

SendRetire(x) ==
    /\ Live /\ Ready /\ x \in owed
    /\ owed' = owed \ {x}
    /\ retireInflight' = retireInflight \cup {x}
    /\ Put(x)
    /\ UNCHANGED <<peerVars, active, rptSeen, dcid, retiring, reported, toColibri, losses, failure>>

(* colibri sends a packet with no frame about connection IDs.              *)
Talk ==
    /\ Live /\ Ready
    /\ Put(None)
    /\ UNCHANGED <<peerVars, colibriVars, toColibri, losses, failure>>

(* §13.3: a lost RETIRE_CONNECTION_ID is sent again, while its ID is still *)
(* waiting to be acknowledged.                                             *)
RetireLost(x) ==
    /\ Live /\ x \in retireInflight /\ \A p \in toPeer : p.retire # x
    /\ retireInflight' = retireInflight \ {x}
    /\ owed' = owed \cup {x}
    /\ UNCHANGED <<peerVars, active, rptSeen, dcid, retiring, reported, toColibri, toPeer, losses,
                   flags>>

(* A packet of colibri's arrives at the peer, and its acknowledgment       *)
(* reaches colibri with it or not. The peer takes a RETIRE_CONNECTION_ID   *)
(* for an ID other than the packet's own (§19.16).                         *)
DeliverPacket(p, acknowledged) ==
    /\ Live /\ p \in toPeer
    /\ acknowledged \/ losses < LossMax
    /\ toPeer' = toPeer \ {p}
    /\ losses' = IF acknowledged THEN losses ELSE losses + 1
    /\ retiredAtPeer' = IF p.retire # None /\ p.retire # p.dcid
                        THEN retiredAtPeer \cup {p.retire} ELSE retiredAtPeer
    /\ IF acknowledged /\ p.retire # None /\ p.retire \in retireInflight
       THEN /\ retiring' = retiring \ {p.retire}
            /\ retireInflight' = retireInflight \ {p.retire}
       ELSE UNCHANGED <<retiring, retireInflight>>
    /\ UNCHANGED <<issued, rpt, rptOf, ncidOwed, ncidInflight, active, rptSeen, dcid, owed,
                   reported, toColibri, flags>>

---------------------------------------------------------------------------

Next ==
    \/ \E r \in Seqs : Issue(r)
    \/ \E s \in Seqs : SendNcid(s) \/ NcidLost(s) \/ \E a \in BOOLEAN : DeliverNcid(s, a)
    \/ SwitchDcid \/ Talk
    \/ \E x \in Seqs : SendRetire(x) \/ RetireLost(x)
    \/ \E p \in Packets : \E a \in BOOLEAN : DeliverPacket(p, a)

(* Both endpoints send what they owe, colibri moves off a retired ID, and  *)
(* a frame the network keeps carrying arrives with its acknowledgment in   *)
(* the end. Neither endpoint need issue an ID or send anything else.       *)
Fairness ==
    /\ WF_vars(SwitchDcid)
    /\ \A s \in Seqs : WF_vars(SendNcid(s)) /\ WF_vars(NcidLost(s)) /\ WF_vars(DeliverNcid(s, TRUE))
    /\ \A x \in Seqs : WF_vars(SendRetire(x)) /\ WF_vars(RetireLost(x))
    /\ \A p \in Packets : WF_vars(DeliverPacket(p, TRUE))

Spec == Init /\ [][Next]_vars /\ Fairness

---------------------------------------------------------------------------
(* Properties.                                                             *)

(* §5.1.1: colibri never holds more active IDs than its limit.             *)
WithinLimit == Cardinality(active) <= Limit

(* §5.1.2: "Upon receipt of an increased Retire Prior To field, the peer   *)
(* MUST stop using the corresponding connection IDs".                      *)
NoSendOnRetired == ~sentOnRetired

(* §19.16: a RETIRE_CONNECTION_ID never names its own packet's ID.         *)
NotOnItself == ~retireOnItself

(* §5.1.2: every ID below a Retire Prior To the peer sent is retired in    *)
(* the end, unless the connection closed on CONNECTION_ID_LIMIT_ERROR.     *)
AllRetired ==
    \A k \in 1..MaxSeq :
        (rpt >= k) ~> ((\A s \in 0..k - 1 : s \in retiredAtPeer) \/ failure # "none")
=============================================================================
