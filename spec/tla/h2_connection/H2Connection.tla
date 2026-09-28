---------------------------- MODULE H2Connection ----------------------------
(***************************************************************************)
(* One h2 connection between a colibri client and a colibri server (RFC   *)
(* 9113), as design §8 steps 4 and 5 build it, for                         *)
(* https://github.com/c4milo/colibri/issues/75 (decision 104).             *)
(*                                                                         *)
(* The client opens streams 1..N in order, stream i being identifier       *)
(* 2i - 1 (§5.1.1), and sends a request on each: a head, up to Content     *)
(* DATA frames, and a trailer section, END_STREAM on the last frame. The   *)
(* server answers each request it read: up to Interims interim heads, one  *)
(* final head, up to Content DATA frames, and a trailer section (§8.1).    *)
(* Either endpoint may reset a stream (§6.4), and the server may send up   *)
(* to MaxGoaways GOAWAY frames (§6.8). TCP delivers each direction in      *)
(* order (§2), so each direction is a queue of frames.                     *)
(*                                                                         *)
(* A stream's state at each endpoint follows §5.1's Figure 2, with the     *)
(* choices colibri makes where §5.1 leaves one (src/h2/stream/stream.zig): *)
(* a frame on a stream closed by END_STREAM in both directions ends the    *)
(* connection unless it is a RST_STREAM, a frame on a stream whose peer    *)
(* reset it ends the connection unless it is another RST_STREAM, and a     *)
(* frame on a stream colibri reset is discarded. A server that sent a      *)
(* GOAWAY ignores a stream above its last stream identifier, and a client  *)
(* that read one opens no stream after it.                                 *)
(*                                                                         *)
(* A receiver reads each message against §8.1's order: one head, then      *)
(* DATA, then trailers, for a request; interim heads, one final head,      *)
(* then DATA and trailers, for a response. A frame out of that order makes *)
(* the message malformed (§8.1.1). Two colibri endpoints never send one,   *)
(* and never provoke a connection error, which is what Safe says.          *)
(*                                                                         *)
(* The model leaves out what other models and checks cover: flow control  *)
(* (spec/tla/h2_flow_control), whose windows never hold back the DATA      *)
(* here, SETTINGS and PING, which change no stream, and field compression. *)
(*                                                                         *)
(* H2ConnectionTrace checks colibri against this model                    *)
(* (tools/h2_trace.sh). The simulator's h2 trace run draws write calls the *)
(* connection must refuse as well as ones it takes, and logs this model's  *)
(* variables from a colibri client and server; TLC must find each seed's   *)
(* log to be a behavior of Next.                                           *)
(*                                                                         *)
(* Each rule constant is a rule colibri keeps. A configuration that turns  *)
(* one off must find a violation:                                          *)
(*   SendInState       a frame goes out only in a state §5.1 lets its      *)
(*                     sender send it: nothing after END_STREAM or a       *)
(*                     RST_STREAM.                                         *)
(*   DataAfterHead     a response's DATA and trailers follow its final     *)
(*                     head (§8.1). colibri broke this rule until c32cabe. *)
(*   OneFinalHead      no response head follows the final one (§8.1).      *)
(*   DiscardAfterReset an endpoint discards the frames it receives on a    *)
(*                     stream it reset (§5.1, §5.4.2).                     *)
(*   IgnoreAboveGoaway a server that sent a GOAWAY ignores every frame on  *)
(*                     a stream above its last identifier (§6.8).          *)
(*   NoStreamAfterGoaway a client opens no stream after it read a GOAWAY   *)
(*                     (§6.8).                                             *)
(*                                                                         *)
(* colibri's GOAWAY never rises (§6.8): it names the highest stream the    *)
(* server opened, and the server opens none above a GOAWAY it sent, so no  *)
(* path here makes one rise. The client still checks each one it reads,   *)
(* and invariant 16 asserts the rule where the GOAWAY is written.          *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    N,              \* streams the client may open, 1..N
    Content,        \* DATA frames a message carries at most
    Interims,       \* interim heads a response carries at most
    MaxGoaways,     \* GOAWAY frames the server sends at most
    Resets,         \* whether the endpoints may reset streams
    SendInState, DataAfterHead, OneFinalHead, DiscardAfterReset, IgnoreAboveGoaway,
    NoStreamAfterGoaway

ASSUME N \in Nat \ {0} /\ Content \in Nat /\ Interims \in Nat /\ MaxGoaways \in Nat
ASSUME Resets \in BOOLEAN
ASSUME \A rule \in {SendInState, DataAfterHead, OneFinalHead, DiscardAfterReset,
                    IgnoreAboveGoaway, NoStreamAfterGoaway} : rule \in BOOLEAN

Streams == 1..N
\* No GOAWAY: above every stream, so no stream is above it.
NoGoaway == N + 1

States == {"idle", "open", "half_closed_local", "half_closed_remote", "closed"}
Closings == {"none", "end_stream", "rst_sent", "rst_received"}
\* A request's progress, written or read: nothing, the head, or ended by END_STREAM.
RequestPhases == {"none", "head", "ended"}
\* A response's progress: nothing, interim heads, the final head, or ended by END_STREAM.
ResponsePhases == {"none", "interim", "final", "ended"}
\* The frames a stream carries: a request's head or a response's final head, an interim head, DATA,
\* a trailer section, and RST_STREAM. GOAWAY names the connection, stream 0.
Kinds == {"head", "interim", "data", "trailers", "rst", "goaway"}

Frame(i, kind, end) == [stream |-> i, kind |-> kind, end |-> end, last |-> 0]
Goaway(last) == [stream |-> 0, kind |-> "goaway", end |-> FALSE, last |-> last]

Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    \* Each stream's state and how it closed, at each endpoint (§5.1).
    clientState, clientClosed,
    serverState, serverClosed,
    \* How far each message is written, and its DATA frames.
    request, requestData,
    response, responseInterims, responseData,
    \* How far each message is read.
    requestRead, responseRead,
    \* The frames in flight in each direction, oldest first.
    toServer, toClient,
    \* The last stream the server's latest GOAWAY named, the GOAWAY frames it sent, and the lowest
    \* last stream a GOAWAY the client read named.
    goawaySent, goawayCount, goawayRead,
    \* A receiver read a message out of §8.1's order, or found a connection error, and the client
    \* opened a stream after it read a GOAWAY.
    malformed, broken, lateOpen

vars == <<clientState, clientClosed, serverState, serverClosed, request, requestData,
          response, responseInterims, responseData, requestRead, responseRead,
          toServer, toClient, goawaySent, goawayCount, goawayRead, malformed, broken, lateOpen>>

TypeOK ==
    /\ clientState \in [Streams -> States] /\ serverState \in [Streams -> States]
    /\ clientClosed \in [Streams -> Closings] /\ serverClosed \in [Streams -> Closings]
    /\ request \in [Streams -> RequestPhases] /\ requestRead \in [Streams -> RequestPhases]
    /\ response \in [Streams -> ResponsePhases] /\ responseRead \in [Streams -> ResponsePhases]
    /\ requestData \in [Streams -> 0..Content] /\ responseData \in [Streams -> 0..Content]
    /\ responseInterims \in [Streams -> 0..Interims]
    /\ goawaySent \in 0..NoGoaway /\ goawayCount \in 0..MaxGoaways /\ goawayRead \in 0..NoGoaway
    /\ malformed \in BOOLEAN /\ broken \in BOOLEAN /\ lateOpen \in BOOLEAN

Init ==
    /\ clientState = [i \in Streams |-> "idle"] /\ serverState = [i \in Streams |-> "idle"]
    /\ clientClosed = [i \in Streams |-> "none"] /\ serverClosed = [i \in Streams |-> "none"]
    /\ request = [i \in Streams |-> "none"] /\ requestData = [i \in Streams |-> 0]
    /\ response = [i \in Streams |-> "none"] /\ responseInterims = [i \in Streams |-> 0]
    /\ responseData = [i \in Streams |-> 0]
    /\ requestRead = [i \in Streams |-> "none"] /\ responseRead = [i \in Streams |-> "none"]
    /\ toServer = <<>> /\ toClient = <<>>
    /\ goawaySent = NoGoaway /\ goawayCount = 0 /\ goawayRead = NoGoaway
    /\ malformed = FALSE /\ broken = FALSE /\ lateOpen = FALSE

-----------------------------------------------------------------------------
(* Sending (§5.1): a HEADERS or DATA frame leaves open or half-closed      *)
(* (remote), and END_STREAM half-closes an open stream and closes a        *)
(* half-closed (remote) one. SendInState off lets a frame go out in any    *)
(* state, and the stream keeps the state it had.                           *)

Sendable(state) == state \in {"open", "half_closed_remote"}

AfterSend(state, end) ==
    IF ~end THEN state
    ELSE IF state = "open" THEN "half_closed_local"
    ELSE IF state = "half_closed_remote" THEN "closed"
    ELSE state

ClosingAfterSend(state, closing, end) ==
    IF end /\ state = "half_closed_remote" THEN "end_stream" ELSE closing

(* The client opens stream i, the lowest it has not opened (§5.1.1), with *)
(* its request's head, which ends the request when end.                    *)
Open(i, end) ==
    /\ clientState[i] = "idle"
    /\ \A j \in Streams : j < i => clientState[j] # "idle"
    /\ NoStreamAfterGoaway => goawayRead = NoGoaway
    /\ clientState' = [clientState EXCEPT ![i] = IF end THEN "half_closed_local" ELSE "open"]
    /\ request' = [request EXCEPT ![i] = IF end THEN "ended" ELSE "head"]
    /\ toServer' = Append(toServer, Frame(i, "head", end))
    /\ lateOpen' = (lateOpen \/ goawayRead # NoGoaway)
    /\ UNCHANGED <<clientClosed, serverState, serverClosed, requestData, response,
                   responseInterims, responseData, requestRead, responseRead, toClient,
                   goawaySent, goawayCount, goawayRead, malformed, broken>>

(* The client sends DATA or its trailer section on stream i.              *)
ClientSend(i, kind, end) ==
    /\ kind \in {"data", "trailers"}
    /\ request[i] # "none"
    /\ SendInState => Sendable(clientState[i]) /\ request[i] = "head"
    /\ kind = "data" => requestData[i] < Content
    /\ kind = "trailers" => end
    /\ clientState' = [clientState EXCEPT ![i] = IF SendInState THEN AfterSend(@, end) ELSE @]
    /\ clientClosed' = [clientClosed EXCEPT ![i] = ClosingAfterSend(clientState[i], @, end)]
    /\ request' = [request EXCEPT ![i] = IF end THEN "ended" ELSE @]
    /\ requestData' = [requestData EXCEPT ![i] = IF kind = "data" THEN @ + 1 ELSE @]
    /\ toServer' = Append(toServer, Frame(i, kind, end))
    /\ UNCHANGED <<serverState, serverClosed, response, responseInterims, responseData,
                   requestRead, responseRead, toClient, goawaySent, goawayCount, goawayRead,
                   malformed, broken, lateOpen>>

(* The server sends a head, DATA or its trailer section on stream i, a    *)
(* stream whose request it read.                                           *)
ServerSend(i, kind, end) ==
    /\ kind \in {"interim", "head", "data", "trailers"}
    /\ serverState[i] # "idle"
    /\ SendInState => Sendable(serverState[i]) /\ response[i] # "ended"
    /\ kind = "interim" => ~end /\ responseInterims[i] < Interims
    /\ kind \in {"interim", "head"} /\ OneFinalHead => response[i] \in {"none", "interim"}
    /\ kind \in {"data", "trailers"} /\ DataAfterHead => response[i] = "final"
    /\ kind = "data" => responseData[i] < Content
    /\ kind = "trailers" => end
    /\ serverState' = [serverState EXCEPT ![i] = IF SendInState THEN AfterSend(@, end) ELSE @]
    /\ serverClosed' = [serverClosed EXCEPT ![i] = ClosingAfterSend(serverState[i], @, end)]
    /\ response' = [response EXCEPT ![i] =
                       IF end THEN "ended"
                       ELSE IF kind = "interim" /\ @ = "none" THEN "interim"
                       ELSE IF kind = "head" THEN "final"
                       ELSE @]
    /\ responseInterims' = [responseInterims EXCEPT ![i] = IF kind = "interim" THEN @ + 1 ELSE @]
    /\ responseData' = [responseData EXCEPT ![i] = IF kind = "data" THEN @ + 1 ELSE @]
    /\ toClient' = Append(toClient, Frame(i, kind, end))
    /\ UNCHANGED <<clientState, clientClosed, request, requestData, requestRead, responseRead,
                   toServer, goawaySent, goawayCount, goawayRead, malformed, broken, lateOpen>>

Resettable(state) == state \in {"open", "half_closed_local", "half_closed_remote"}

(* An endpoint resets stream i (§6.4), which closes it at once.            *)
ClientReset(i) ==
    /\ Resets /\ Resettable(clientState[i])
    /\ clientState' = [clientState EXCEPT ![i] = "closed"]
    /\ clientClosed' = [clientClosed EXCEPT ![i] = "rst_sent"]
    /\ toServer' = Append(toServer, Frame(i, "rst", FALSE))
    /\ UNCHANGED <<serverState, serverClosed, request, requestData, response, responseInterims,
                   responseData, requestRead, responseRead, toClient, goawaySent, goawayCount,
                   goawayRead, malformed, broken, lateOpen>>

ServerReset(i) ==
    /\ Resets /\ Resettable(serverState[i])
    /\ serverState' = [serverState EXCEPT ![i] = "closed"]
    /\ serverClosed' = [serverClosed EXCEPT ![i] = "rst_sent"]
    /\ toClient' = Append(toClient, Frame(i, "rst", FALSE))
    /\ UNCHANGED <<clientState, clientClosed, request, requestData, response, responseInterims,
                   responseData, requestRead, responseRead, toServer, goawaySent, goawayCount,
                   goawayRead, malformed, broken, lateOpen>>

(* The highest stream the server opened, or 0 for none: what colibri's    *)
(* GOAWAY names (RFC 9113 §8.7).                                           *)
HighestOpened ==
    IF \A i \in Streams : serverState[i] = "idle" THEN 0
    ELSE CHOOSE i \in Streams : serverState[i] # "idle" /\ \A j \in Streams : j > i => serverState[j] = "idle"

(* The server sends a GOAWAY naming the highest stream it opened, and no  *)
(* more than its previous one.                                             *)
ServerGoaway ==
    /\ goawayCount < MaxGoaways
    /\ LET last == Min(HighestOpened, goawaySent)
       IN /\ goawaySent' = last
          /\ toClient' = Append(toClient, Goaway(last))
    /\ goawayCount' = goawayCount + 1
    /\ UNCHANGED <<clientState, clientClosed, serverState, serverClosed, request, requestData,
                   response, responseInterims, responseData, requestRead, responseRead, toServer,
                   goawayRead, malformed, broken, lateOpen>>

-----------------------------------------------------------------------------
(* Receiving (§5.1): the state after a HEADERS or DATA frame the receiver  *)
(* takes, END_STREAM half-closing an open stream and closing a half-closed *)
(* (local) one.                                                            *)

AfterReceive(state, end) ==
    IF ~end THEN state
    ELSE IF state = "open" THEN "half_closed_remote"
    ELSE IF state = "half_closed_local" THEN "closed"
    ELSE state

ClosingAfterReceive(state, closing, end) ==
    IF end /\ state = "half_closed_local" THEN "end_stream" ELSE closing

(* What a frame does to a stream that is not idle at its receiver, as     *)
(* colibri decides it: "take" the frame, "discard" it, a "stream" error    *)
(* (the receiver resets the stream), or a "connection" error.              *)
Verdict(state, closing, kind) ==
    CASE state \in {"open", "half_closed_local"} -> "take"
      [] state = "half_closed_remote" ->
            IF kind = "rst" THEN "take" ELSE "stream"
      [] state = "closed" /\ closing = "rst_sent" ->
            IF DiscardAfterReset THEN "discard" ELSE "connection"
      [] state = "closed" /\ closing = "rst_received" ->
            IF kind = "rst" THEN "discard" ELSE "connection"
      [] state = "closed" /\ closing = "end_stream" ->
            IF kind = "rst" THEN "discard" ELSE "connection"
      [] OTHER -> "connection"

(* Whether a request frame is out of §8.1's order when read after phase.  *)
RequestOutOfOrder(phase, kind) ==
    \/ kind = "head" /\ phase # "none"
    \/ kind \in {"data", "trailers"} /\ phase # "head"
    \/ kind = "interim"

ResponseOutOfOrder(phase, kind) ==
    \/ kind = "interim" /\ phase \notin {"none", "interim"}
    \/ kind = "head" /\ phase \notin {"none", "interim"}
    \/ kind \in {"data", "trailers"} /\ phase # "final"

NextRequestRead(phase, kind, end) ==
    IF end THEN "ended" ELSE IF kind = "head" THEN "head" ELSE phase

NextResponseRead(phase, kind, end) ==
    IF end THEN "ended"
    ELSE IF kind = "interim" THEN "interim"
    ELSE IF kind = "head" THEN "final"
    ELSE phase

(* The server takes a frame it keeps for stream i.                         *)
ServerTakes(f) ==
    LET i == f.stream IN
    IF f.kind = "rst" THEN
        /\ serverState' = [serverState EXCEPT ![i] = "closed"]
        /\ serverClosed' = [serverClosed EXCEPT ![i] = "rst_received"]
        /\ UNCHANGED <<requestRead, malformed>>
    ELSE
        /\ serverState' = [serverState EXCEPT ![i] =
                               IF @ = "idle" THEN (IF f.end THEN "half_closed_remote" ELSE "open")
                               ELSE AfterReceive(@, f.end)]
        /\ serverClosed' = [serverClosed EXCEPT ![i] = ClosingAfterReceive(serverState[i], @, f.end)]
        /\ requestRead' = [requestRead EXCEPT ![i] = NextRequestRead(@, f.kind, f.end)]
        /\ malformed' = (malformed \/ RequestOutOfOrder(requestRead[i], f.kind))

(* The server reads the oldest frame the client sent.                      *)
ServerReceive ==
    /\ toServer # <<>>
    /\ LET f == Head(toServer)
           i == f.stream
           above == i > goawaySent /\ serverState[i] = "idle"
       IN /\ toServer' = Tail(toServer)
          /\ CASE above /\ IgnoreAboveGoaway ->
                    \* §6.8: a stream above the GOAWAY's last identifier is ignored.
                    UNCHANGED <<serverState, serverClosed, requestRead, malformed, broken, toClient>>
               [] serverState[i] = "idle" ->
                    \* §5.1: only a HEADERS frame opens an idle stream.
                    IF f.kind = "head"
                    THEN ServerTakes(f) /\ UNCHANGED <<broken, toClient>>
                    ELSE broken' = TRUE /\ UNCHANGED <<serverState, serverClosed, requestRead, malformed, toClient>>
               [] OTHER ->
                    LET verdict == Verdict(serverState[i], serverClosed[i], f.kind) IN
                    CASE verdict = "take" -> ServerTakes(f) /\ UNCHANGED <<broken, toClient>>
                      [] verdict = "discard" ->
                            UNCHANGED <<serverState, serverClosed, requestRead, malformed, broken, toClient>>
                      [] verdict = "stream" ->
                            \* §5.1: a stream error of STREAM_CLOSED; the server resets the stream.
                            /\ serverState' = [serverState EXCEPT ![i] = "closed"]
                            /\ serverClosed' = [serverClosed EXCEPT ![i] = "rst_sent"]
                            /\ toClient' = Append(toClient, Frame(i, "rst", FALSE))
                            /\ malformed' = TRUE
                            /\ UNCHANGED <<requestRead, broken>>
                      [] OTHER ->
                            broken' = TRUE /\ UNCHANGED <<serverState, serverClosed, requestRead, malformed, toClient>>
    /\ UNCHANGED <<clientState, clientClosed, request, requestData, response, responseInterims,
                   responseData, responseRead, goawaySent, goawayCount, goawayRead, lateOpen>>

ClientTakes(f) ==
    LET i == f.stream IN
    IF f.kind = "rst" THEN
        /\ clientState' = [clientState EXCEPT ![i] = "closed"]
        /\ clientClosed' = [clientClosed EXCEPT ![i] = "rst_received"]
        /\ UNCHANGED <<responseRead, malformed>>
    ELSE
        /\ clientState' = [clientState EXCEPT ![i] = AfterReceive(@, f.end)]
        /\ clientClosed' = [clientClosed EXCEPT ![i] = ClosingAfterReceive(clientState[i], @, f.end)]
        /\ responseRead' = [responseRead EXCEPT ![i] = NextResponseRead(@, f.kind, f.end)]
        /\ malformed' = (malformed \/ ResponseOutOfOrder(responseRead[i], f.kind))

(* The client reads the oldest frame the server sent.                      *)
ClientReceive ==
    /\ toClient # <<>>
    /\ LET f == Head(toClient) IN
       /\ toClient' = Tail(toClient)
       /\ IF f.kind = "goaway" THEN
             \* §6.8: a GOAWAY that names more than the one before is a connection error.
             /\ goawayRead' = Min(goawayRead, f.last)
             /\ broken' = (broken \/ f.last > goawayRead)
             /\ UNCHANGED <<clientState, clientClosed, responseRead, malformed, toServer>>
          ELSE LET i == f.stream IN
             /\ UNCHANGED goawayRead
             /\ IF clientState[i] = "idle"
                THEN \* §5.1: a server opens no stream, since decision 17 refuses push.
                     broken' = TRUE /\ UNCHANGED <<clientState, clientClosed, responseRead, malformed, toServer>>
                ELSE LET verdict == Verdict(clientState[i], clientClosed[i], f.kind) IN
                     CASE verdict = "take" -> ClientTakes(f) /\ UNCHANGED <<broken, toServer>>
                       [] verdict = "discard" ->
                             UNCHANGED <<clientState, clientClosed, responseRead, malformed, broken, toServer>>
                       [] verdict = "stream" ->
                             /\ clientState' = [clientState EXCEPT ![i] = "closed"]
                             /\ clientClosed' = [clientClosed EXCEPT ![i] = "rst_sent"]
                             /\ toServer' = Append(toServer, Frame(i, "rst", FALSE))
                             /\ malformed' = TRUE
                             /\ UNCHANGED <<responseRead, broken>>
                       [] OTHER ->
                             broken' = TRUE /\ UNCHANGED <<clientState, clientClosed, responseRead, malformed, toServer>>
    /\ UNCHANGED <<serverState, serverClosed, request, requestData, response, responseInterims,
                   responseData, requestRead, goawaySent, goawayCount, lateOpen>>

-----------------------------------------------------------------------------

Next ==
    \/ \E i \in Streams, end \in BOOLEAN : Open(i, end)
    \/ \E i \in Streams, kind \in {"data", "trailers"}, end \in BOOLEAN : ClientSend(i, kind, end)
    \/ \E i \in Streams, kind \in {"interim", "head", "data", "trailers"}, end \in BOOLEAN :
           ServerSend(i, kind, end)
    \/ \E i \in Streams : ClientReset(i) \/ ServerReset(i)
    \/ ServerGoaway
    \/ ServerReceive
    \/ ClientReceive

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Safe: two colibri endpoints never provoke a connection error or read a *)
(* malformed message, a server processes no stream above a GOAWAY it sent, *)
(* and a client opens no stream after it read one.                         *)

Safe ==
    /\ ~broken
    /\ ~malformed
    /\ ~lateOpen
    /\ \A i \in Streams : serverState[i] # "idle" => i <= goawaySent

=============================================================================
