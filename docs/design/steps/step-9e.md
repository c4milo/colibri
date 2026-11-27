# Design §8 step 9e: the handshake over CRYPTO frames, and the interop runner

[Design §8, the build plan](../../design.md#8-build-plan)

CRYPTO frame reassembly by offset, the handshake driven through `tls.Provider`'s QUIC mode, and the
transport parameters of §7.4. **This is the only part of step 9 that waits on chapulin**: its
`ch_quic_*` calls were stubs until 2026-09-20, when chapulin implemented all fifteen; the client
role is on its `main` and the server role has no driver yet. **Check:** step 9's, above. *Large.*

**This step is about ten pieces, and only the last needs chapulin, 2026-09-20.** Steps 9a to 9d
built ten leaves and nothing joining them: no `Connection` exists in `src/quic/`, nothing
declares three `Space`s, and the simulator's QUIC checks drive modules one at a time. What 9e
owes is the assembly — a receive path, a frame dispatch loop, a datagram send path with §12.2's
coalescing and §14.1's padding, CRYPTO reassembly per level, the key-schedule timing calls of
RFC 9001 §4.9 and §6, Retry and version negotiation — plus three things that do not exist at
all: `tls.Provider`'s QUIC mode, the transport parameters, and a simulator connection check.
The test-only endpoint and `tools/interop.sh` are the only part that waits on chapulin.

`src/tls/tls.zig` said QUIC mode "lands with design §8 step 7". It did not: step 7 shipped the
packet formats and, after [decision 48](../../decisions/0048-the-suite-holds-every-key-and.md), a
`crypto.Suite` that protects packets and drives no handshake. The comment is corrected.

**The transport parameters are done, 2026-09-20.** `src/quic/transport_parameters.zig` holds
RFC 9000 §18.2's seventeen parameters, their defaults and the writer;
`transport_parameters_read.zig` holds the reader. Every value is stored inline, so a
`Parameters` is one struct the caller owns.

A default is not an absence, and four of §18.2's are not zero: `max_udp_payload_size` is 65527,
`ack_delay_exponent` is 3, `max_ack_delay` is 25 milliseconds and `active_connection_id_limit`
is 2. `Parameters.initial()` is what an empty extension means, the reader starts from it, and
the writer leaves out any value that equals its default — so two endpoints agreeing on
everything exchange no bytes at all, which one test pins.

Two things are read past rather than kept. `preferred_address` is skipped by the length every
parameter carries, because [decision 21](../../decisions/0021-connection-migration-no-to-initiating-it.md) refuses migration in both directions and
§9.6 makes using one a MAY. And a repeat of an identifier colibri does not know goes
undetected, although §7.4 forbids a repeat of any parameter: detecting it means holding every
identifier a peer chose to send, which is the trade the ACK range walk of §19.3.1 already
refuses, and §18.1 gives an unknown parameter no semantics to conflict with.

**Fuzzing, 2026-09-26.** A fuzz property reads each input as a client's extension and as a
server's ([#53](https://github.com/c4milo/colibri/issues/53)). An accepted extension must keep §18.2's bounds and each value's shape. It
must name no §18.2 identifier twice (§7.4), and a client's must name no server-only one.
Written again, it must read back the same. Its 20 corpus inputs sit on each side of every
bound. 10 mutations, 10 **CAUGHT** by the fuzz test alone, two of them only after it checked
each value's shape.

**The connection exists, 2026-09-20.** `src/quic/connection/connection.zig` is what joins the
ten pieces steps 9a to 9d built: three packet number spaces paired with three encryption
levels, the CRYPTO stream of each, the stream table, both levels of flow control, the
connection IDs each side holds, the path, the termination state and RFC 9002's recovery. Every
one was tested alone; what is new is that they belong to one connection and agree about it.

It holds no key, no socket and no provider — a test refuses a field whose name says otherwise,
because the keys are the caller's `crypto.Suite` (decision 48) and the handshake is the
caller's `tls.QuicProvider` (decision 8). It reads no clock: `init` takes the instant.

The shape worth naming is that a connection starts not knowing what its peer will accept. RFC
9000 §7.4 carries the peer's parameters in the handshake, so what colibri may spend against
begins at zero and `apply_peer_parameters` raises it. That is not a special case: §18.2 says a
stream limit that is "absent or zero" means the peer cannot open streams until a MAX_STREAMS
frame, which is the state a connection begins in. What colibri *grants* is its own parameters
and is in force from the first packet.

Mutations: seven applied, all **CAUGHT** — a level paired with the wrong space, colibri
spending its own grant instead of the peer's, the send window starting at colibri's own limit,
the peer's parameters not raising it, an idle timeout of zero arming the timer instead of
disabling it, every level answering one CRYPTO stream, and the idle timeout read as nanoseconds
rather than milliseconds.

**The handshake over CRYPTO frames runs, 2026-09-20.** `connection_crypto.zig` is the wiring
step 9e is named for, and it owns none of the three things it joins: `crypto_stream` turns the
peer's frames into an in-order run per level, the caller's `tls.QuicProvider` consumes it and
produces what colibri owes back, and `quic.frame` writes that into CRYPTO frames. No key passes
through it — decision 48 sends the secrets from the provider to the suite inside the caller's
code.

The transport parameters are part of the handshake rather than something beside it: RFC 9001
§8.2 carries them in a TLS extension, so `take_peer_parameters` reads the peer's out of the
provider and gives them to the connection, which is what raises every limit colibri may spend
against. Its absence is only fatal once the handshake completes, because a client has not read
EncryptedExtensions before then; `require_peer_parameters` is where §8.2's MUST is applied.

Each failure carries the code RFC 9000 §20.1 gives it, and an alert is not among them: RFC 9001
§4.8 makes its code the description plus 0x0100, which `alert_error_code` computes.

Mutations: six applied, all **CAUGHT** — bytes handed to the provider twice, every frame
claiming offset 0, the peer's parameters read under colibri's own role, and three failures
closing with the wrong code. Writing them found a weak test: the parameters it exchanged held
nothing server-only, so reading them under the wrong role would have passed. It now carries a
stateless reset token, which only a server may send.

**What 9e still owes, 2026-09-20.** Five agents mapped the remaining work against the vendored
RFCs and a sixth checked every claim they made against the tree. The list is longer than the six
items this paragraph used to hold, and it is ordered: each piece needs the ones above it. The
four prerequisites are done and struck through; the entries below say what each one printed.

1. ~~Connection identity.~~ **Done, `da116dd`.** `connection_identity.zig` holds §7.3's five
   values, apart from the §5.1 set `connection_id.Local` holds. `destination` is derived from
   Figures 7 and 8 read in order, and `describe` writes the three parameters so the extension
   cannot disagree with the headers.
2. ~~The client's path, and a read-only duplicate query.~~ **Done**, `8f3152e` and `52c71f1`.
   The limit is the server's (§8.1, §21.1.1.1) and a client had been unable to send its first
   Initial; `Space.duplicate_verdict` is the read-only half §12.3 needs.
3. ~~Key-schedule state.~~ **Done, `b9ae985`.** `connection_keys.zig` holds invariant 21's
   none, available or discarded per level and direction, which `keys_available` cannot answer,
   and `can_open` asks the handshake as well because of §5.7. §4.9's triggers are there; §6's
   key update is piece 7.
4. ~~A null `tls.QuicVTable`.~~ **Done, `cc93d7a`.** `src/sim/null_quic_provider.zig` carries a
   pair through §4.1.5's Figure 5 to §4.1.1's completion, framing each message as RFC 9846 §4
   frames one. No check drives it through `connection_crypto.zig` yet: `sim` is given only
   `core`, `tls` and `crypto`, so that check belongs in the `sim_run_quic` module with piece 10.
5. ~~The receive path — one datagram walked into packets and frames.~~ **Done**, and recorded
   below.
6. **The send path** — §12.2's coalescing and §14.1's padding, into a buffer the caller owns.
7. ~~Key-update timing.~~ **Done**, `4d0cc65` and `871d034..ac522a2`, and recorded below. All
   of RFC 9001 §6, at the call sites pieces 5 and 6 own.
8. ~~Version negotiation.~~ **Done, `fc2a6ae`**, and recorded below. `connection_version.zig` holds §6's
   two connection-level decisions, above the packet `packet/invariant.zig` already read and
   wrote.
9. ~~Retry, with §7.3's validation.~~ **Done**, `bb33948` to `89a4bfa`, and recorded below.
   Both halves of §17.2.5, §8.1.2's token, and the connection IDs §7.3 authenticates.
10. ~~The simulator connection check for invariants 17 to 21.~~ **Done**, `79d8d29`, and
    recorded below.
11. **The test-only endpoint and `tools/interop.sh`**, which is the only part that waits on
    chapulin, whose QUIC server has not yet exchanged a packet with any implementation.

**The receive path is done, 2026-09-20.** A datagram arrives from the caller and comes apart
into packets, then frames, then acts on the connection. Seven commits: the read-only duplicate
query (`52c71f1`), §12.4's permitted-frame table (`b64307d`), §12.2's coalescing walk
(`8befbd5`), the frame dispatch (`391da52`), the frames naming a stream (`3c0a31f`), the
connection ID and path frames (`37f2450`) and §19.16's in-use refusal (`a4f0881`).

The shape worth naming is where a rule stops being a discard and starts being a connection
error. Everything `connection_receive.zig` does is a discard, because until the AEAD tag matches
nothing in a packet is the peer's word for anything: §12.2 has the walk carry on past a packet
it could not read and RFC 9001 §5.5 forbids closing on one. Once the tag matches,
`connection_frames.zig` applies §12.4's refusals and every rule §19 states, each with its own
code.

Two rules pull against each other and the split between asking and recording is what settles
them. §12.3 wants a duplicate suppressed before the packet is processed and §13.1 forbids
recording it for acknowledgment until every frame has been. One call could not do both, so
`Space.duplicate_verdict` is the read-only half and `Space.receive` is what the caller records
with afterwards.

Two checks colibri makes that the RFC leaves optional, both for the reason design §8 step 9c
already gave — colibri answers an optional check it has the state for. §19.16's "MUST NOT refer
to the Destination Connection ID field of the packet in which the frame is contained" is a MAY
for the receiver, and `connection_id.Local` now keeps bytes so it can answer; §5.1.1 makes the
identity's own Source Connection ID sequence number 0, which is what gives a packet a connection
ID to name from the first flight. And §4.5's final size rules are answered while a stream
exists, though not after it closes, because §4.5 says generating them "is not mandatory" exactly
when an endpoint would have to keep state for closed streams, and colibri keeps none.

One check was left unmade there and is now made: §8.2.3's path MTU. `take_path_response` passed
a hard-coded false, so the second validation was owed after every probe. `Path.Challenge`
remembers instead, and `on_challenge_sent` takes the datagram's length rather than a flag, so
§8.2.1's 1,200 bytes are compared in one place. Recorded below, `4aafd03`.

**Version negotiation is done, 2026-09-20.** RFC 8999 §6 defines the packet for every version
of QUIC and `packet/invariant.zig` already read and wrote it. What `connection_version.zig`
adds is RFC 9000 §6's two decisions: when a server owes one, and what a client does with one.

The server's half takes no `Connection` and takes a datagram rather than a packet. §6.1 says
the scheme "allows a server to process packets with unsupported versions without retaining
state", so there is no connection to take. §17.2.1's "A server MUST NOT send more than one
Version Negotiation packet in response to a single UDP datagram" is then kept by the shape of
the call — one datagram in, at most one packet out — rather than by counting what was sent.
§17.2.1 also forbids a version-specific rule from reaching the decision, which is why the
datagram is read through `invariant.read_long`: that reader cannot apply one, so a 255-byte
connection ID is echoed although version 1 stops at 20.

A client checks that both connection IDs echo what it sent. §17.2.1 states those two echoes as
rules on the server and their purpose on the client — they give "some assurance that the
server received the packet and that the Version Negotiation packet was not generated by an
entity that did not observe the Initial packet" — so the check is step 9c's precedent again,
colibri answering an optional check it holds the state for. What turns on it is abandoning the
connection attempt, which an off-path sender must not be able to cause.

§6.2's "received and successfully processed any other packet" is read off the three spaces,
because the caller records a packet in one once its frames have been processed, which is what
the phrase names. Two packets leave no such record and are read separately: an earlier Version
Negotiation packet acted on, which left the connection no longer active, and a Retry, which
§17.2.5.2 gives no packet number for a space to hold.

24 mutations, 24 CAUGHT. Two of them only after a test was written: `answer` guards an empty
datagram and a header cut short, and nothing passed it either.

Mutations: 44 applied across the seven commits, 38 CAUGHT first time and one a no-op control
that correctly was not. Five gaps, every one in the tests rather than the code, and all of one
shape — a test that checked a length or a wrapper where the distinguishing thing was elsewhere.
A payload slice taken one byte early kept the right length. Three of §18.2's stream data
parameters were set to one value, so swapping two was invisible. A retransmission reaching the
same distance did not separate a high-water mark from a running total. A stream limit was read
through the error the dispatch flattens it to rather than its own. And no test had a client
process a Handshake packet, which is the trigger RFC 9001 §4.9.1 gives the other role.

`zig build test` passes and `zig build lint` and `zig fmt --check` are clean after each commit.

**Seven more things 9e owes that no piece above claims.** ~~Sending a CONNECTION_CLOSE that
carries an error code~~ is done, `368344e`, and recorded below. ~~Driving the timers, which is
one deadline out and one instant in (§4.2)~~ is done, `18e9949`, and recorded below.
~~Generating a PATH_CHALLENGE and running §8.2's validation~~ is done, `10aabc5`, and recorded
below. ~~Validating the ECN counts a peer reports (§13.4.2)~~ is done, `ab178c3`, and recorded
below. ~~Sending a Stateless Reset (§10.3)~~ is done, `9d902e1`, and recorded below.
~~Retransmitting a lost packet's frames under a new number~~ is done for every frame colibri
sends, `79d5dd9` and `a15af0f`, and recorded below; §13.3's other rules land with the senders
they belong to. Scheduling the application level's frames. And golden corpus cases for the receive path's
new refusals, with their entries in `src/golden/mutations.zig`.

**The CONNECTION_CLOSE writer is done, 2026-09-20**, `368344e`. Reading the peer's frame was
already `connection_frames.zig`'s; `connection_close.zig` is the other half, and every piece
above had been naming connection errors that nothing could send.

RFC 9000 §10.2.3 is the whole of it, and its rule is about keys rather than about closing.
§10.2.3 states the goal — "the goal is to ensure that the peer will process the frame" — and
before the handshake is confirmed neither endpoint knows for certain which keys the other
holds. So the frame goes out at every level that can seal one, §12.2 coalesces those into a
single datagram, and the peer reads whichever copy it can open. A test pins the reason: a
client that has not completed its handshake cannot open the 1-RTT copy at all (RFC 9001 §5.7),
and it is the Initial and Handshake copies that reach it.

§12.5 confines a type 0x1d frame to the application packet number space, so `frame_for` writes
§10.2.3's replacement below it: type 0x1c, APPLICATION_ERROR, and the Reason Phrase cleared,
because §10.2.3 says otherwise "information about the application state might be revealed".
The Reason Phrase is the caller's bytes and colibri copies none of them (decision 35); a
reason that will not fit the packet is dropped rather than the frame, which §19.19 allows by
making the field able to be zero length.

Two rules turned out to be owned already and one was not. §10.2.1's rate limit is
`Termination.permission`, which answers a closing endpoint on a doubling count of received
packets. §10.2.1's "limit the cumulative size of packets it sends to an unvalidated address to
three times the size of packets it receives" is §8's limit, which `Path` already holds — and
checking it here is what exposed the defect below. §10.2.2's MAY, a single close before
entering the draining state, is declined: `on_close_received` enters draining at once.

21 mutations, 21 CAUGHT, three of them only after a test was written.

**A fourth defect, found while building the close writer**, `64c13a2`. `connection_send`
asserted RFC 9000 §8.1's anti-amplification limit after sealing instead of bounding the
datagram by it: `datagram_ceiling` never read `Path.send_allowance`, so a server that had
received nothing halted rather than answering that it had nothing to send. That is the
ordinary state of every server at the start of a connection, not colibri's own defect, and
the file header already said the limit was checked before the datagram was returned. No test
had ever sent from a server with a zero allowance.

**Key-update timing is done, 2026-09-21**, `4d0cc65`. `connection_key_update.zig` is RFC 9001
§6, which is timing and nothing else: colibri holds no key, so every rule in §6 is about when it
calls `crypto.Suite.update_keys` and when it refuses. Both call sites existed already and
neither used the answer — `packet_build.zig` wrote the Key Phase bit as a constant 0, and
nothing read the `key_set` that `crypto.Suite.open` reports.

§6.1 states its own recipe — "tracking the lowest packet number sent with each key phase and the
highest acknowledged packet number in the 1-RTT space" — so `Connection` gains
`phase_lowest_sent` beside the `current_phase_lowest` §6.5 already needed. The first update is
held to that rule as well as a subsequent one, because §6.1's recipe does not except it and a
phase nothing was sent in is one no peer can have acknowledged.

Two refusals are the peer's to trigger and both carry KEY_UPDATE_ERROR (§6.7): §6.2's second
update, before this endpoint acknowledged the first under the new keys, and §6.4's packet opened
with old keys above the lowest number the current keys opened. A third failure is not the
peer's — a suite that opens a packet with its next keys and then refuses to move to them — and
it closes with INTERNAL_ERROR, which RFC 9000 §11 gives an endpoint with no more specific code.

Three rules of §6 were left without a call site and each has one now, recorded below. 20
mutations, 20 CAUGHT, one of them only after a test was written: a 1-RTT space the peer had
acknowledged nothing in read as acknowledged, because no case had sent a packet without also
recording an acknowledgment. `zig build test`: 1155 passed, 18 skipped.

**The handshake's connection IDs are authenticated, 2026-09-21**, `bb33948`. RFC 9000 §7.3
says "Endpoints MUST validate that received transport parameters match received connection ID
values", and nothing did: `connection_identity.zig` held §7.3's five values and wrote its own
into the parameters colibri sends, and the peer's arrived unchecked.

§7.2's half was missing too, and it is what makes §7.3's possible. `Identity.on_peer_initial`
had no caller outside a test, so a client never addressed the Source Connection ID the server's
Initial carried and there was nothing to hold the peer's parameter to. It is now taken off the
first long-header packet that opened — never off one that did not, because until the AEAD tag
matches nothing in a packet is the peer's word for anything — and a later long header carrying a
different Source Connection ID is discarded, which §7.2 requires of both roles.

`authenticate` runs before the peer's limits are raised, so parameters that fail §7.3 never
widen what colibri may spend. Every failure carries TRANSPORT_PARAMETER_ERROR: §7.3 mandates it
for the absent parameters and permits it for the rest, so one code answers the whole section.

17 mutations, 16 CAUGHT. The survivor compared connection IDs by prefix, which no case
separated because every pair a test used was the same length; §7.3's "If a zero-length
connection ID is selected, the corresponding transport parameter is included with a zero-length
value" is the case that does, and it is now a test.

**A client acts on a Retry, 2026-09-21**, `20e51c0`. `packet/packet_header.zig` could read a
Retry packet and nothing decided what to do with one. `connection_retry.zig` is that decision:
RFC 9000 §17.2.5.2's refusals, the Retry Integrity Tag checked over the pseudo-packet RFC 9001
§5.8 defines, and what a Retry that survives changes.

Nothing in a Retry is protected, which §17.2.5 says in as many words, so every rule is a discard
and none is a connection error. Two of the refusals are §7.2's work from the commit above:
"After the client has received and processed an Initial or Retry packet from the server, it MUST
discard any subsequent Retry packets" is `retry_source` and `peer_initial_source` being null.

colibri installs no key. RFC 9001 §5.2 changes the Initial keys with the Destination Connection
ID, so `Taken` reports the Retry's Source Connection ID and the caller installs over it, exactly
as it installed the first set — the shape decision 48 already had. A token longer than decision
54's `token_len_max` is discarded, because §8.1.2 has the client repeat the token in every later
Initial and one it cannot hold is one it cannot answer.

12 mutations, 11 CAUGHT. The survivor sized an Initial's header without its Token field, which
no case separated because what bounded every payload was what the provider owed rather than the
room the header left. A packet built into an output the payload fills is the case that does.

`zig build test`: 1190 passed, 18 skipped.

**Each CRYPTO stream keeps what it sent, 2026-09-21**, `fd97a12`. RFC 9000 §17.2.5.3: "A
client MUST use the same cryptographic handshake message it included in this packet." The
provider gives its bytes up once — `write_handshake` is a drain — and `CryptoStream` held
`sent_len` and no bytes, so the Initial that answers a Retry could not be written. The owner
ruled a per-level send window on 2026-09-21; `crypto_send_buffer_len` is its size, a judgement
set equal to the window §7.5 fixes for the other direction, and three of them sit in every
connection.

The window forgets only bytes it has already framed, and only when it has no room left. A
flight that fits is therefore never forgotten, which is what makes a repeat possible; a longer
one carries on at the offset it reached rather than stalling, which a window anchored at zero
would have done. A Retry arriving after a flight was forgotten is discarded, because colibri
cannot repeat what it no longer holds.

The same window is what §13.3's retransmission will read, which is why it is per level and not
a copy of the client's first flight. When the sent-packet table records which frames a packet
carried, the window can be anchored at what the peer acknowledged instead of at what was framed.
Step 33e made this change on 2026-11-06. The window now forgets only bytes the peer
acknowledged, so a flight longer than the window waits for acknowledgments.

8 mutations, 8 CAUGHT, two only after a test was written: one framed the provider's bytes
without keeping them, which no case separated because none sent anything twice; and one forgot
a flight that fits as soon as the next packet asked for room, which no case separated because
none asked for room between framing and repeating.

`zig build test`: 1196 passed, 18 skipped.

**The server writes a Retry, 2026-09-21**, `89a4bfa`. Decision 55's two members land on
`crypto.Suite`, which makes twelve: RFC 9000 §8.1.4 wants an address validation token
authenticated and expiring, and non-negotiables 2 and 3 leave colibri neither a key nor a clock.
Decision 48's list and invariant 23 move with them, which is the procedure invariant 23 exists
to force.

`answer` holds nothing, because §8.1.2 says a Retry is how a server "defers the state and
processing costs of connection establishment". §17.2.5.1's "A server MUST NOT send more than one
Retry packet in response to a single UDP datagram" is then kept by the shape of the call — one
request in, at most one packet out — which is the same answer version negotiation gave to the
same rule. Everything it writes is the caller's: §5.1 wants a connection ID unpredictable and
invariant 5 forbids colibri a random number, and the client's address is opaque bytes because
colibri owns no socket.

`verify_token` reads a later Initial's Token field as absent, validated or invalid, which are
the three things §8.1.2 has a server do next: send a Retry, continue, or close with
INVALID_TOKEN. The last is a verdict and not an error value, because §8.1.2 says the server "has
not established any state for the connection at this point and so does not enter the closing
period", so there is no connection to fail.

The strongest case is a round trip in one file: the server writes a Retry and the client half of
§17.2.5.2 reads it back and accepts it, which checks the pseudo-packet both sides build against
each other rather than against an expected byte string.

11 mutations, 10 CAUGHT. The survivor wrote a Retry carrying a zero-length token — the one thing
§17.2.5.2 has a client discard outright — which no suite in a test had produced.

`zig build test`: 1204 passed, 18 skipped.

**§8.2.3's path MTU is recorded where it is known, 2026-09-21**, `4aafd03`. The receive path
had no way to answer RFC 9000 §8.2.3's question — "If an endpoint sends a PATH_CHALLENGE frame
in a datagram that is not expanded to at least 1200 bytes and if the response to it validates
the peer address, the path is validated but not the path MTU" — because the fact belongs to the
datagram that went out and nothing kept it. So `take_path_response` passed false, which was safe
and always wrong: every probe left a second validation owed.

`Path.Challenge` keeps it now. `on_challenge_sent` takes the datagram's length rather than a
flag, so §8.2.1's "at least the smallest allowed maximum datagram size of 1200 bytes" is
compared once, in `path.zig`, instead of at every call site that might get it wrong;
`on_response` loses the parameter it could have been lied to through.

7 mutations, 6 CAUGHT. The survivor let an unexpanded probe unsettle an MTU an earlier probe had
validated, which no case had sent in that order — §8.2.3 asks for the MTU to be verified once,
not for every probe to verify it again.

`zig build test`: 1205 passed, 18 skipped.

**The timers are driven, 2026-09-21**, `18e9949`. Five deadlines were armed across a
connection — RFC 9002 Appendix A.8's loss timer, RFC 9000 §10.1's idle timeout, §10.2's closing
period, §8.2.4's PATH_CHALLENGE and RFC 9001 §6.5's previous read keys — and nothing put them
together, so a caller had to ask each piece and take the smallest itself.

`connection_timer.zig` is one question and one answer. colibri still sets no timer, which is
design §4.2: "It returns the instant at which it next wants to be called, and the caller
arranges that." `Fired` is a set rather than a choice, because more than one deadline can come
due at one instant.

Loss detection is reported and not run. RFC 9002 Appendix A.9's `OnLossDetectionTimeout` needs
storage for the packets it declares lost, which decision 35 leaves with the caller, so the timer
is reported and `Recovery.on_timeout` stays the caller's to call. Everything else is state
colibri already holds, so it acts on it.

15 mutations, 14 CAUGHT. The survivor guarded a state the key phase cannot reach — read keys
discarded while the instant that times them is still recorded — so the guard went and an
assertion says why one field answers.

`zig build test`: 1214 passed, 18 skipped.

**A lone ack-eliciting packet is acknowledged, 2026-09-21**, `53205ae`. Found while wiring the
timers above, and a real defect rather than a missing piece. `Space.owes_ack` answered on
RFC 9000 §13.2.2's two ack-eliciting packets or on §13.2.1's immediate cases, and nothing knew
about the deadline under both: one in-order ack-eliciting 1-RTT packet set neither, so colibri
waited for a second that might never arrive and the peer's Probe Timeout fired instead. §13.2.1
calls max_ack_delay "an explicit contract".

The space records the instant the oldest packet it has not acknowledged arrived — the oldest,
because the promise is about every packet and the oldest is nearest to breaking it — and
`owes_ack` takes the instant. Only the application space arms a deadline: §13.2.1 has every
ack-eliciting Initial and Handshake packet acknowledged immediately, which `receive` already
records as `ack_immediately`, so those two are owed at once and want no timer.

The recovery check's census moved with it, which is recorded above rather than pinned over.

11 mutations, 8 CAUGHT first time. One guarded a path that could not be reached — a deadline
taken across three spaces where only one ever arms one — so the loop went. The other two were
tests that computed their expectation from the code they check: a deadline read back off the
connection rather than spelled as §18.2's 25 milliseconds, and no case that built a packet after
the delay rather than before it.

`zig build test`: 1219 passed, 18 skipped.

**The path frames are sent, 2026-09-21**, `10aabc5`. `Path` had run RFC 9000 §8.2's validation
since step 9c and nothing wrote a frame: `on_challenge_sent` had no caller, and the PATH_RESPONSE
a peer's challenge earned was reported to the caller in `Report.owed` rather than sent. The
connection remembers both now — sixteen bytes each — and the send path writes them into the
next 1-RTT packet, which is where §12.5's Table 3 permits them.

§8.2.1 and §8.2.2 both expand the datagram that carries one to §14.1's 1,200 bytes, and both
except the anti-amplification limit. Neither needs a check for that exception: `datagram_ceiling`
already bounds every datagram by §8's allowance, so a server that may not send 1,200 bytes sends
fewer and §8.2.3's second validation is exactly what the short datagram leaves owed. The two
rules meet in one place rather than arguing at two.

§8.2.4's timer is "three times the larger of the current PTO or the PTO for the new path (using
kInitialRtt)", which is why `Rtt` gained `new_path_probe_timeout_ns`. It keeps the peer's
max_ack_delay, because RFC 9002 §5.3 resets the estimator on migration and leaves that alone: it
is a property of the peer and not of the path.

What stays the caller's is the unpredictable data §8.2.1 requires, because invariant 5 forbids
colibri a random number, and the decision to probe at all. `Path.owe_challenge` is the whole of
the entry point.

15 mutations, 13 CAUGHT. Both survivors were tests that could not tell two values apart: one
never read whether the packet elicited an acknowledgment, which Table 3 says it does; and one
gave the connection a round trip equal to kInitialRtt, so §8.2.4's "larger" chose between two
equal numbers and choosing wrongly looked the same.

A follow-up, `605a9c9`, named a literal the magic-numbers rule refuses. It was pushed broken:
the lint result was read after the commit rather than before it.

`zig build test`: 1224 passed, 18 skipped.

**The peer's ECN counts are validated, 2026-09-21**, `ab178c3`. RFC 9000 §13.4.2.1: "An
endpoint that receives an ACK frame with ECN counts therefore validates the counts before using
them." colibri used them. A rise in the reported ECN-CE count was a congestion event whatever
else the frame said, so a peer — or a network element rewriting the field — could halve the
congestion window by reporting counts for markings nobody applied.

colibri marks nothing: §13.4.2 has an endpoint set ECT(0) in the IP header, and the IP header is
the caller's (non-negotiable 1). So the caller says what it set, one `Record` at a time, and
`recovery_ecn.zig` judges what comes back against it. All four of §13.4.2.1's checks are there —
counts absent where a marked packet was acknowledged, a total above what was marked, an increase
smaller than the packets newly acknowledged, and the reordering rule that forbids failing on a
frame which did not raise the largest acknowledged. §13.4.2.2's answer is one flag, because
§13.4.2 validates "for each network path" and a connection holds one path here.

A frame that fails leaves nothing behind: its counts are exactly what stopped being believed, so
they are not recorded and no congestion event follows from them.

14 mutations, 10 CAUGHT. All four survivors were in the wiring rather than the checks, and one
of them was a defect the mutation found: `recovery_ack.take` merges a `Removed` per ACK range,
and the new per-codepoint counts were assigned rather than summed, so a two-range frame
under-counted what it had acknowledged. A case with two ranges pins it now.

`recovery_sent.zig` passed 500 lines with the codepoint on `Record`, so its tests moved to
`recovery_sent_test.zig`.

`zig build test`: 1236 passed, 18 skipped, and `zig build test-sim -Drelease` agrees.

**A Stateless Reset can be written, 2026-09-22**, `9d902e1`. colibri could read one and not
write one, which made RFC 9000 §10.3's datagram the only wire format in the tree it can take
apart and not assemble. The owner asked for it on 2026-09-22, for failing fast where a peer
would otherwise wait out an idle timeout, and ruled the invariant change it needed.

Every part that needs a secret stays the caller's, and each for a rule of its own: §10.3's
unpredictable bytes because invariant 5 forbids colibri a random number, §10.3.2's token
because it comes from a static key and non-negotiable 2 keeps keys out of this tree, and the
decision to send because §10.3 answers a datagram no connection could be found for and
non-negotiable 1 leaves the socket with the caller. `write` lays out Figure 10 around them,
which is the division a Retry packet already had.

**Invariant 20 was what had to move, and it came out stronger.** It had said nothing in
`src/quic/` may build a Stateless Reset, because RFC 9000 §9 forbids answering a peer's
migration with one: a third party could then close connections by spoofing traffic. That rule is
about a connection, and §10.3's answer is to a datagram that belongs to none, so the invariant
now names the shape rather than the absence: `write` takes no `Connection`, and a function that
cannot see one cannot be reached from the path that refuses a migration.

The old check was a test that no declaration of `stateless_reset` is named `write` or `build`.
Replacing it exposed that the new one was vacuous — no function took a `Connection`, so
weakening the assertion changed nothing and the test could not fail. It now runs the rule
against a canary shaped the way §9 forbids, which is what `build/lint.zig` does for the lint
rules, so the passing line is evidence.

12 mutations, 12 CAUGHT, two of them the invariant's own check once it had a canary to fail on.

`zig build test`: 1240 passed, 18 skipped.

**Lost CRYPTO bytes are sent again, 2026-09-22**, `79d5dd9`. RFC 9000 §13.3's first rule:
"Data sent in CRYPTO frames is retransmitted according to the rules in [QUIC-RECOVERY], until
all data has been acknowledged." Nothing did, so a lost handshake packet ended the attempt.

§13.3's shape is worth stating, because it is not the one the name suggests. "QUIC packets that
are determined to be lost are not retransmitted whole. The same applies to the frames" — the
*information* is sent again, by whoever holds it. So there is no queue of frames to replay:
each piece keeps what it owes and writes it afresh. The send window `fd97a12` added for a
Retry's repeat is the CRYPTO half of exactly that, and what was missing was the record of which
bytes a packet carried.

A `recovery_sent.Record` carries that range now, and `connection_crypto.on_packets_lost` rewinds
the level's flow to the lowest lost offset. Nothing is tracked per packet, because §13.3 permits
sending more than was lost — "a receiver MUST accept packets containing an outdated frame" — so
the lowest rewind covers every higher one. A new packet number carries the repeat, which
invariant 17 requires and §17.2.5.3 says of a Retry for the same reason.

`Record` grew from 24 bytes to 32. 256 of them sit in each of three spaces, so a test pins the
size: the next field added to it is measured rather than assumed. The range is two flat fields
rather than a struct, because a struct of a `u64` and a `u16` pads to sixteen bytes and would
have cost 40.

`packet_build.zig` passed 500 lines, so its framing half became `packet_build_frames.zig`; that
made four files sharing the prefix, which moved them into `packet_build/`.

10 mutations, 8 CAUGHT. One survivor rewound to the last lost offset rather than the lowest,
which nothing separated until a case sent a flight across two packets; the other was an anchor
the split had moved.

What is left of §13.3 is its other rules: STREAM data, which needs the stream send buffers;
RESET_STREAM and STOP_SENDING, which are sent until a state is reached; the limit frames, which
carry the current value rather than the lost one; NEW_CONNECTION_ID, RETIRE_CONNECTION_ID and
NEW_TOKEN, which carry the same content again; and HANDSHAKE_DONE, which "MUST be retransmitted
until it is acknowledged".

`zig build test`: 1245 passed, 18 skipped.

**§13.3's table is in the frame it belongs to, 2026-09-22**, `a15af0f`. `Frame.repair` answers
what a lost packet owes for each frame type, one arm per sentence of §13.3, beside
`permitted_at` and `is_ack_eliciting` because it is the same kind of fact about a frame. The
switch has no `else`, so a frame type added to the union stops the build until its rule is
written down.

That closes the retransmission piece for what colibri can send, which is five frames: CRYPTO,
ACK, PATH_RESPONSE, PATH_CHALLENGE and CONNECTION_CLOSE. The CRYPTO one sends its bytes again;
the other four need no repair, and §13.3 gives a different reason for each — PING and PADDING
"contain no information", an ACK is superseded by the next, a connection close is resent by §10
rather than by loss detection, and a PATH_RESPONSE is "sent just once". Four of those were true
by colibri having built nothing, which is the state mutation testing exists to find, so a case
sends all four in one packet and loses it.

What is left of §13.3 belongs to senders that do not exist: STREAM data, RESET_STREAM,
STOP_SENDING, the limit and blocked frames, the connection ID frames, NEW_TOKEN and
HANDSHAKE_DONE. Each lands with the piece that sends it rather than with a queue of its own,
which is what §13.3 asks for: "the information that might be carried in frames is sent again in
new frames as needed". The exhaustive switch is what will stop a sender landing without its rule.

7 mutations, 7 CAUGHT, one per classification the table could have got wrong.

`zig build test`: 1247 passed, 18 skipped.

**Every acknowledged record reaches the caller, 2026-09-22**, `272b179`. This is the first
piece of [decision 57](../../decisions/0057-the-caller-keeps-a-streams-unacknowledged.md). It counts the bytes the peer has
acknowledged on each stream, and only a packet's record says which bytes it carried.
`recovery_sent.Removed` kept the largest record alone, because RFC 9002 needs no more: the
round trip sample and the congestion event both come from the largest. So `remove_range_into`
writes each record it takes into a slice the caller places, and `recovery_ack.on_ack_received`
passes that slice through one ACK range after another, as `recovery_loss.detect` already does
for lost records. A slice too short is told how many records did not fit.

The recovery simulator now settles acknowledged packets from those records rather than from
the ACK ranges it wrote itself. A run that ends with a packet neither acknowledged nor declared
lost fails as `NotDrained`.

10 mutations, 10 CAUGHT: four on the table's writes, four on the sums across ranges and the
outcome, and two through the simulator.

`zig build test`: 1250 passed, 18 skipped.

**A sent record holds one range for CRYPTO or STREAM, 2026-09-22**, `d9bde2e`. Decision 57's
second piece. A packet carries at most one CRYPTO frame or one STREAM frame and never both, so
the CRYPTO pair on `recovery_sent.Record` becomes `data_offset` and `data_len`, tagged by
`carries`: none, CRYPTO, STREAM, or STREAM with the FIN. The record names the stream by its
62-bit identifier, never a table slot, because a slot is reused. It grows from 32 bytes to 40,
where a separate stream range would have made it 56. Nothing frames STREAM yet, so only the
record carries `stream_id`; the send path gains it with the frames that fill it.

`connection_crypto.on_packets_lost` now reads `carries` and not a nonzero length, and a test
loses a record that carried stream bytes at an offset the CRYPTO flow also used.

7 mutations, 7 CAUGHT.

`zig build test`: 1250 passed, 18 skipped.

**Each stream counts what it sent, lost and had acknowledged, 2026-09-22**, `9df4675`. Decision
57's third piece. A stream holds no bytes. `stream_outgoing.Outgoing` holds four offsets:
how far the caller's bytes reach, how far colibri has framed them, how many the peer has
acknowledged, and whether the caller ended the stream there. `Streams.on_range_acknowledged`
adds an acknowledged range to its stream and moves the sending part to "Data Recvd" once every
byte and the FIN are acknowledged (RFC 9000 §3.1). `Streams.on_range_lost` keeps a lost range
in `stream_lost.LostRanges`, the ranges owed again across every stream, oldest first, unless the
stream has sent RESET_STREAM (§13.3).

The count is exact because each framed byte is in one place: one packet in flight, the lost
table, or acknowledged. [Invariant 29](../../invariants.md#inv-29) states that, and
`Outgoing.on_acknowledged` asserts that the count never passes the framed offset.

The lost table holds `stream_lost_ranges_max` ranges, which is `sent_packets_max`: a lost range
comes from one lost packet, and new bytes wait while any range is owed. A range split to fit
a smaller packet (§13.3) lies next to its remainder, so the table joins adjacent ranges of one
stream, and losing the piece again leaves one entry and not two. A table that fills anyway
refuses the range with `Full`, which the connection turns into INTERNAL_ERROR.

30 mutations, 30 CAUGHT. Two cases were written for one mutation each: a range whose bytes go
out before its FIN, and a stream still in "Send" losing a range. One check in
`is_all_acknowledged` was removed rather than tested, because an acknowledged FIN implies the
stream was ended.

`zig build test`: 1263 passed, 18 skipped.

**Stream bytes are sent, read through the stream provider, 2026-09-22**, `3c1453d`. Decision
57's fourth piece. `stream_provider.StreamProvider` is design §4.5's vtable, one member,
`read(stream_id, offset, output)`. `connection_send.send` takes one, and
`StreamProvider.none()` serves a caller that sends no stream data. The caller opens a stream
with `connection_stream_send.open` and says how far its bytes reach with `supply`. It never
passes bytes.

`connection_stream_send.write` puts one STREAM frame in an application-level packet (decision
56; RFC 9000 §12.4, Table 3). The oldest lost range goes first (§13.3), and a lost range whose
stream was reset or closed since is dropped. Otherwise the first stream in the table with new
bytes and credit sends them. Each new byte spends the stream's limit and the connection's
(§4.1), and a lost range sent again spends neither. A packet that carries CRYPTO carries no
STREAM frame, because the record holds one range. The provider writes its bytes straight into
the packet scratch after a header measured for the room. The Length field keeps that width even
when the provider answers fewer bytes, which RFC 9000 §16 permits, so no byte is moved. The
field is always present, so PADDING may follow the frame. Choosing among streams is the frame
scheduler's, [#29](https://github.com/c4milo/colibri/issues/29).

The tests open each packet as the peer, run its frames through the receive path, and check
every byte of the STREAM frame against its offset. They cover a lost range sent again before
new bytes, a lost range split to fit a smaller packet, a FIN sent alone and lost, a reset or
closed stream's lost range dropped, both flow control limits, a provider with fewer bytes than
supplied, and CRYPTO and STREAM kept apart.

34 mutations, 34 CAUGHT. The Length field's width was first NOT CAUGHT: no provider had
answered fewer than 64 bytes for a range measured at two, so the short read now reads 50. One
check in `frame` was removed rather than tested, because the check after it answers the same
case.

`zig build test`: 1276 passed, 18 skipped.

**Acknowledged and lost records reach the streams, 2026-09-22**, `f08de58`. Decision 57's last
piece. Loss recovery is the caller's to drive, and `recovery_ack.on_ack_received` hands it the
records an ACK took out and the ones it found lost. `connection_stream_recovery` reads the
stream range each record names. `on_packets_acknowledged` counts the range toward its stream
and writes the identifier of each stream that enters "Data Recvd" into a slice the caller
places. From then on the caller may drop that stream's bytes. `on_packets_lost` puts the
ranges in the lost table for `send`, and a table that cannot hold one closes the connection
with INTERNAL_ERROR (RFC 9000 §20.1). A record that carried CRYPTO or nothing is passed over.

Four files now started `connection_stream_`, so `a0562d8` moved them into
`connection/connection_stream/`, as CLAUDE.md asks, before this piece added two more.

11 mutations, 11 CAUGHT.

`zig build test`: 1282 passed, 18 skipped.

What decision 57 leaves to other pieces: RESET_STREAM and STOP_SENDING are not sent yet
([#37](https://github.com/c4milo/colibri/issues/37)). A probe carries new bytes or a PING and
never a range in flight, which invariant 29 needs, but nothing writes a probe yet
([#29](https://github.com/c4milo/colibri/issues/29)). The simulator check that each stream's
count reaches its final size belongs to the QUIC connection check
([#24](https://github.com/c4milo/colibri/issues/24)).

**The handshake completes, and a server sends HANDSHAKE_DONE, 2026-09-22**, `064022f`. Nothing
set `handshake_complete` outside the tests, so a server never confirmed its handshake or sent
HANDSHAKE_DONE, and a colibri client never confirmed either. `connection_handshake.complete`
marks the handshake complete once the provider reports it (RFC 9001 §4.1.1), after requiring
the peer's transport parameters (§8.2). A server confirms at the same moment (§4.1.2), owes a
HANDSHAKE_DONE frame and discards its Handshake keys (§4.9.2).

The frame goes in a 1-RTT packet (RFC 9000 §12.4, Table 3), after the path frames and before
any bytes. RFC 9000 §13.3 retransmits it until it is acknowledged, and that needs only the
number of the packet that last carried it. So the connection keeps that number and
`recovery_sent.Record` stays at 40 bytes. Losing that packet owes the frame again. An
acknowledgment of it, and of no other packet or space, ends the obligation.

At a client, `connection_frames.Report.handshake_done` says a HANDSHAKE_DONE confirmed the
handshake, and the caller then discards the Handshake keys with
`connection_keys.on_handshake_confirmed`, because `process` is not given the suite. The tests'
suite now records key discards by level rather than treating one as unreachable.

22 mutations, 22 CAUGHT. Matching a later packet number was first NOT CAUGHT, and a case now
acknowledges a later packet that carried something else. A call in `complete` that read the
peer's parameters was removed rather than tested, because reading them is the caller's step
as the handshake carries them.

`zig build test`: 1288 passed, 18 skipped.

**The limit frames are sent, 2026-09-22**, `ad5cbe1`. Nothing gave a peer more credit, so a
peer stopped at the first limit it reached. `connection_flow` writes MAX_DATA,
MAX_STREAM_DATA and MAX_STREAMS (RFC 9000 §19.9 to §19.11) in 1-RTT packets, after
HANDSHAKE_DONE and before any bytes. `flow.Receiver` still decides when new credit is worth a
frame. What it measures from is what the application consumed (§4.1), so
`connection_flow.consume` is how the caller reports that it read a stream's bytes.
`Streams.close` gives a count back for each stream the peer opened (§4.6), which is what
MAX_STREAMS then offers. MAX_STREAM_DATA stops once the stream's receiving part leaves "Recv"
(§13.3's SHOULD).

§13.3 resends a lost limit frame at the current value, and only when the lost packet carried
the most recent frame for its scope. `flow.Advertised` holds that packet's number for each
scope: the connection, each stream, and each stream type. A loss is matched by number, so an
acknowledgment needs nothing, and a frame with no room stays owed for the next packet.

Two defects came up on the way. With a window of 0 or 1, `window / flow_credit_fraction` is
0, so `credit_frame_limit` offered a limit on every call, and MAX_STREAMS went out in every
packet for a peer allowed one stream. Credit that raises nothing is now never offered (§4.1:
a limit that does not rise "has no effect"). The second defect is filed, not fixed: every
receiver starts with its cap equal to its window, so decision 49's growth never happens
([#42](https://github.com/c4milo/colibri/issues/42)). Choosing the cap is a named limit and the
owner's to set. A test gives one connection a larger cap and shows the window doubling
against the round trip.

The caller still has no stream bytes to read and report, because nothing hands received
stream data to it ([#41](https://github.com/c4milo/colibri/issues/41)).

22 mutations, 22 CAUGHT. The resend of a lost MAX_STREAMS and the round trip passed to the
window's growth each got a test case for their mutation. One check in MAX_STREAM_DATA became an
assertion, because credit comes only from `consume`, which already refuses a stream this
endpoint does not receive on.

`zig build test`: 1299 passed, 18 skipped.

**The BLOCKED frames are sent, 2026-09-22**, `01bb196`. `connection_flow.write_blocked`
writes DATA_BLOCKED, STREAM_DATA_BLOCKED and STREAMS_BLOCKED (RFC 9000 §19.12 to §19.14) after
the limit frames. Each goes once per limit, through `flow.Sender.blocked_frame_limit`, and
only while the limit holds something back. For the two data frames that means bytes supplied
and unsent on a stream still in "Ready" or "Send" (§4.1: a sender that "has data to write but
is blocked"). For STREAMS_BLOCKED it means an open the peer's limit refused since the last
stream this endpoint opened (§4.6: "unable to open a new stream"), which `Streams.open_local`
now records. A lost one goes again at the current limit while the endpoint is still blocked,
and the debt is dropped once it is not (§13.3). The same `on_packets_lost` covers all six flow
control frames.

Not done: §4.1's SHOULD to send a BLOCKED frame "periodically" while blocked with nothing in
flight, which needs a timer and belongs with the scheduler
([#29](https://github.com/c4milo/colibri/issues/29)). A test that expected nothing after a
stream limit now expects the one STREAM_DATA_BLOCKED that goes out.

16 mutations, 16 CAUGHT. The tests read the frames back at the peer, because it ignores all
three, so the limit and stream type each one names are checked.

`zig build test`: 1303 passed, 18 skipped.

**RESET_STREAM and STOP_SENDING are sent, 2026-09-22**, `861bc84` and `2d1f70f`. Nothing could
end one direction of a stream, and a peer's STOP_SENDING went unanswered, which RFC 9000 §3.5
says MUST be answered with RESET_STREAM. `connection_stream_send.reset` abandons a sending part
(§3.1, §19.4). It enters "Reset Sent" when the reset is asked for, not when the frame goes out,
so nothing is framed after the decision. The frame's final size is every byte framed, which
can no longer change, so each copy is the same (§13.3: its content "MUST NOT change when it is
sent again"). `stop_sending` asks the peer to stop, while the receiving part is in "Recv" or
"Size Known" (§19.5). A STOP_SENDING from the peer now owes a reset with the peer's error code
(§3.5). colibri resets at once in "Data Sent" too, where §3.5 allows but does not require a
wait.

A lost RESET_STREAM goes again until one copy is acknowledged, and that acknowledgment enters
"Reset Recvd" (§3.1). A lost STOP_SENDING goes again while the peer may still send (§13.3). Both
keep the packet that carried their most recent copy in `frame.Latest`, which `861bc84` renamed
from `flow.Advertised` because the record is not about limits. `connection_stream_recovery`'s
two functions now take the packet number space, because acknowledging a reset matches packet
numbers, and a number means nothing outside its space (§12.3). An acknowledgment walks the
streams only while one is in "Reset Sent".

28 mutations, 28 CAUGHT: 4 on the renamed record and 24 on the endings. A check in the
acknowledgment walk that could never fail was removed rather than kept as an equivalent mutant.

`zig build test`: 1309 passed, 18 skipped.

**The application frame scheduler, 2026-09-22**, `b020293`, `7a320ac` and `38b8326`.
`packet_build_frames.zig`'s header now states the order frames compete in for one packet's
room, with the rule behind each place. Three rules were missing from it.

RFC 9000 §13.2.1: "An endpoint SHOULD send an ACK frame with other frames when there are new
ack-eliciting packets to acknowledge." An ACK went out only once it was owed. Now a pending one
is written whenever the packet carries anything else. If nothing follows, the ACK is taken back
and the space's count and instant are restored, so a lone ACK still waits for its deadline.

RFC 9002 §6.2.4's probes. `Recovery.Action.probe` asked the caller for ack-eliciting packets
that nothing could build when there was nothing to send. `connection_send.owe_probes` records
the count per level. Each ack-eliciting packet at that level counts one off, and one that would
elicit nothing carries a PING. A probe carries new frames or a PING and never repeats a range
in flight, which invariant 29 needs.

RFC 9000 §2.3: an implementation "SHOULD provide ways in which an application can indicate the
relative priority of streams." Until now the first stream in the table sent until it ran out.
`connection_stream_send.set_priority` orders new bytes, a lower value first, from
`stream_priority_default` in the middle of the range. Streams of one value take turns, and one
whose provider has nothing yet gives way to the next. Lost bytes still go before new ones
(§13.3).

Not done: §4.1's SHOULD to send a BLOCKED frame "periodically" while nothing is in flight. It
needs a timer of its own and the connection's own recovery bookkeeping, and it is filed as
[#43](https://github.com/c4milo/colibri/issues/43).

24 mutations: 22 CAUGHT and 2 equivalent. The ACK snapshot's at-once flag is always clear when
an ACK is taken back, so it was removed. Two priority ranks are never equal, so no tie can
break either way. Two mutations first NOT CAUGHT got a test case each: an ACK taken back that
must leave its count, and a first-ranked stream that frames nothing.

`zig build test`: 1318 passed, 18 skipped.

**NEW_CONNECTION_ID and RETIRE_CONNECTION_ID are sent, 2026-09-22**, `0e074ef` and `e07bad8`.
Nothing gave a peer a second connection ID. The retirements a peer's Retire Prior To owed were
queued and never sent.

`connection_id_frames.issue` takes a connection ID's bytes and its Stateless Reset Token from
the caller. colibri draws no random number for the bytes (invariant 5), and RFC 9000 §10.3.2
derives the token from a key colibri does not hold (non-negotiable 2), the division [#31](https://github.com/c4milo/colibri/issues/31) settled
for the Stateless Reset itself. It refuses:
- an endpoint whose peer sends it zero-length IDs (§19.15);
- bytes of a length other than this endpoint's first, because a short header does not encode
  the length (§17.3.1);
- more IDs than the peer's `active_connection_id_limit` (§5.1.1: "An endpoint MUST NOT provide
  more connection IDs than the peer's limit").

The caller routes datagrams by Destination Connection ID and chose the bytes, so it knows each
one this connection answers to.

Both frames travel in 1-RTT packets, after RESET_STREAM and STOP_SENDING. Each keeps a
`frame.Latest`, so a lost one goes again with the same content (§13.3). A NEW_CONNECTION_ID
stays owed-on-loss until the peer retires the ID. A retirement leaves once its frame is
acknowledged, which `connection_id_frames.on_packets_acknowledged` does; before, the queue
drained as the frame was read, whether or not it arrived. `0e074ef` split `connection_id.zig`'s
tests out first, for length.

Not built: NEW_TOKEN, which a server MAY send (§8.1.3). colibri asks the peer to retire none of
its IDs, so every Retire Prior To it writes is 0.

18 mutations, 18 CAUGHT. One first survived: no test checked that a retirement already sent is
not written again.

`zig build test`: 1325 passed, 18 skipped.

**The simulator drives a QUIC connection, 2026-09-23**, `79d8d29`. Piece 10,
[#24](https://github.com/c4milo/colibri/issues/24). Two colibri endpoints finish a handshake
and move one 16,384-byte stream across the network of step 8. Each is a `Connection` with the
null QUIC provider and the null suite. `src/sim/quic_endpoint.zig` plays the rest of a caller:
- it derives the Initial keys from the client's first Destination Connection ID (RFC 9001
  §5.2);
- it hands the provider this endpoint's transport parameters (§8.2);
- it installs the Handshake and 1-RTT keys when the null provider's script reaches them
  (§4.1.4);
- it keeps the bytes of the stream it sends (decision 57).

Each of 256 seeds draws up to 10% loss and 10% duplication over delays that reorder.
`quic_invariants.zig` reads invariants 17 to 21 after every datagram and every step: numbers
never reused, a server within three times what it received, flow control limits that never
fall, every datagram to the one path's connection ID, and no call on a level without keys.

Over 256 seeds on macOS 25.6 arm64: 13,986 datagrams, 13,991 packets, 722 dropped. Digest
`0x1693a3d7` in Debug and in `-Drelease`. `zig build test-sim-run-quic` runs it, in the module
with no HTTP module in its graph (decision 5).

Building the check found six gaps, each fixed in a commit of its own before it:
- `88c7945`: RFC 9001 §4.9.1's two triggers for discarding the Initial keys had no caller.
- `d6c8970`, `4d87ab2`: receiving a datagram took seven steps that no library code ran, so the
  idle timer never restarted on receive. Decision 60 has `connection_datagram.receive` run
  them all in one call.
- `695c63f`: the frame layer flattened stream, path, crypto and recovery refusals into one
  error, which closed with INTERNAL_ERROR where RFC 9000 names FLOW_CONTROL_ERROR and the
  rest. A TLS alert's description was dropped, so its CRYPTO_ERROR code was lost too.
- `25bf319`: the peer's max_idle_timeout was never read, and no send restarted the idle timer
  (RFC 9000 §10.1).

Running it found two more:
- `feeb757`: a tiny packet's number widened for the header protection sample (decision 54)
  was left out of the planned length, so a server's padded PING sealed two bytes past its
  RFC 9000 §8.1 allowance.
- `10ce41f`: a handshake deadlocked. The client's lost Finished waited behind 1-RTT packets
  the server could not read yet. RFC 9002 §6.2.1 forbids an Application Data PTO before
  confirmation, and the Handshake space held nothing in flight. RFC 9002 §7.3.2's one
  datagram past the window on entering recovery is what lets the Finished go again.

`306603e` has the null suite count each call at a level without keys, which is what invariant
21's read compares against zero.

Not built: pacing, ECN marking, and a server that coalesces its Handshake flight with its
ServerHello. The last is the harness's: the null provider's keys can only be installed
between `send` calls, so the ServerHello and the Handshake packets go in separate datagrams.

Mutations: 13 over the check, 13 CAUGHT. The per-step read of invariants 19 and 21 first
survived, because nothing broke one during a run; two faults now break each read mid-run.

`zig build test`: 1379 passed, 18 skipped.

**Received stream bytes are reassembled, 2026-09-23**, `8bf3794` and `290fbf4`. Decision 61,
[#41](https://github.com/c4milo/colibri/issues/41) and
[#42](https://github.com/c4milo/colibri/issues/42). colibri had checked every STREAM frame and
kept none of its bytes, so no caller could read a stream and no window could grow.
- `stream_incoming.Pool(capacity)` is one pool per connection, which the caller places and
  passes as `Options.receive`. Streams take its blocks of `stream_receive_block_len` = 1,024
  bytes as they need them. Each block marks which of its bytes arrived (RFC 9000 §2.2). One
  pool serves every stream because the bytes waiting across them never pass the connection
  window. It holds two blocks per stream beyond its capacity for the ends of each stream's
  span, so a peer within its limits cannot exhaust it.
- `connection_stream_read.read` copies a stream's bytes in order up to the first gap and
  gives each block back once read. What it reads is what gives the peer credit (RFC 9000
  §4.1). Reading every byte moves the stream to "Data Read" (§3.2), and a reset is reported
  once as `StreamReset`.
- The pool's capacity caps every receive window, the connection's and each stream's: decision
  49's cap, `receive_pool_len_default` = 1 MiB. A connection given no pool keeps no bytes and
  its windows stay where they start.
- The simulator's server now reads the client's stream and checks every byte against what the
  client sent. The census did not move: 16 KiB of reads earns no credit frame against 64 KiB
  windows, so the datagrams are the same.

Mutations: 15 over the library, 14 CAUGHT. The fifteenth was equivalent: `contiguous_end`'s
early stop repeated what its block-number check already does, so the stop went. Bytes kept
after a reset first survived; the test that catches it is new. 3 over the simulator, 3
CAUGHT; dropping the byte check first survived, and a fault now changes a byte.

`zig build test`: 1396 passed, 20 skipped.

**A finished stream closes, 2026-09-23**, `9fb82ce`,
[#44](https://github.com/c4milo/colibri/issues/44). Nothing closed a stream, so a finished one
kept its table slot and the peer never got its stream count back (RFC 9000 §4.6). A connection
could open 128 streams over its whole life.
- `connection_stream_close.close_if_finished` closes a stream once each part it has is in a
  terminal state: "Data Recvd" or "Reset Recvd" for the sending part (§3.1), "Data Read" or
  "Reset Read" for the receiving part (§3.2). Closing frees the table slot and the stream's
  receive blocks.
- Three events can finish a part, and each calls it: an acknowledgment of the last bytes or
  of a RESET_STREAM, a read of the last byte, and a read that reports a reset.

Mutations: 7, 7 CAUGHT. `zig build test`: 1400 passed, 20 skipped.

**A colibri client and server finish a QUIC handshake over chapulin, 2026-09-23.** Piece 11's
first part, [#25](https://github.com/c4milo/colibri/issues/25). It is the first run of
colibri's connection with a real TLS 1.3 stack and real packet protection.
- `src/testing/quic/chapulin_quic.zig` puts one `ch_quic` behind both `tls.QuicProvider` and
  `crypto.Suite` (decisions 10 and 48). A chapulin client stages one message for the caller to
  pull, and a chapulin server pushes its flight through a callback. Both land in one buffer per
  level, which `write_handshake` hands out.
- chapulin reports each level ready from inside the call that fed it. The session keeps the
  report and the endpoint marks the level installed after the colibri call returns, as decision
  60 has the caller do.
- `tools/quic_loopback.sh` runs a colibri client and a colibri server in one process over one
  chapulin object built `TRANSPORT=quic ROLE=both KEYLOG=on`. Datagrams move in memory, and the
  check advances its own instant 5 ms a round. The client verifies the server's chain, both
  select "hq-interop" (RFC 9001 §8.1), and the server reads a 1 MiB stream. That length takes
  the 1-RTT packet numbers past 256, where a one-byte Packet Number field no longer decodes
  without the largest number received (RFC 9000 Appendix A.3). The check requires four key log
  lines per endpoint.

First run, on an Apple M1 Pro under macOS 26.6.2 with a chapulin copy patched as below:
handshake complete and confirmed in round 5 and the stream read in round 43; 904 client
datagrams, 1,082,906 bytes; 44 server datagrams, 3,791 bytes.

Mutations of the adapter and the check: 17, 16 CAUGHT and one equivalent. Three were caught
only after a change: a lost largest packet number needed the longer stream, and a discard not
passed to chapulin and a wrong byte read as right each needed a test. The equivalent one read
`keys_available` in the other direction, which cannot differ because chapulin sets and clears
both directions of a level together.

It found three defects:
- colibri, fixed in `a7e5404`: a datagram grew to the peer's `max_udp_payload_size`, and the
  client sent 1,313 bytes. RFC 9000 §14.2 says an endpoint without PMTU discovery "SHOULD NOT
  send datagrams larger than the smallest allowed maximum datagram size". Every datagram now
  stays at 1,200 bytes, the size RFC 9002's controller already counted in. 3 mutations, 3
  CAUGHT. The simulator's census moved to 13,660 datagrams, 13,683 packets and 706 dropped.
- chapulin: in a `ROLE=both` object every session derives the server's Initial keys, because
  `quic.c` picks the role with `#ifdef CH_ROLE_SERVER`. A client there seals under the wrong
  label, so no Initial opens.
- chapulin: a QUIC server's EncryptedExtensions buffer has no room for the transport
  parameters, so the server fails with an internal_error alert after its ServerHello.

chapulin fixed both in `9c903d8`, and `tools/quic_loopback.sh` passes against that commit
unpatched, on the same machine, with the same rounds and datagram counts as the first run.

The run also shows the cost of [#45](https://github.com/c4milo/colibri/issues/45). The client
drops the Handshake packet that follows the ServerHello in the server's first datagram, and the
handshake waits for the server's PTO.

`zig build test`: 1403 passed, 23 skipped.

**Each packet's handshake bytes reach TLS before the next packet, 2026-09-23.** Decision 62,
[#45](https://github.com/c4milo/colibri/issues/45).
- `receive` advances the handshake after each packet it processes, and
  `connection_keys.take_available` then marks each level and direction the suite holds keys
  for. `receive` and `send` ask the same at their start. Callers no longer call
  `on_keys_installed`.
- The null provider gives its suite each level's keys at the step that makes them, as a
  caller's code would. The simulator's endpoint and the loopback check lost their install
  loops.
- `tools/quic_loopback.sh` against chapulin `9c903d8`, on the same machine: the handshake is
  confirmed in round 1 rather than 5, and the 1 MiB stream is read by round 8 rather than 43,
  in 901 client datagrams and 9 server datagrams. The old run also lost the 1-RTT packets that
  shared a datagram with the client's Finished, and those losses cut the congestion window.
- The simulator's census keeps 13,660 datagrams and moves to 13,687 packets and 708 dropped.
  Its null server makes its Handshake keys while it writes the ServerHello, inside `send`, so
  its first datagram never carried a Handshake packet to lose.

Mutations: 10, 9 CAUGHT and one equivalent. Asking the suite about the read direction alone
was caught only after a test gave the two directions different answers. The equivalent one let
the null provider hand over a discarded level, which never happens: colibri discards a level
only after the script's last step.

`zig build test`: 1407 passed, 23 skipped.

**A colibri client fetches files from a colibri server over UDP, 2026-09-23.** Piece 11's
second part, [#25](https://github.com/c4milo/colibri/issues/25).
- `testing_udp` grew from the socket into §9's UDP QUIC endpoint, with the owner's leave for its
  new edge to `quic`. `zig build quic-udp` runs it as the hq-interop server or client over one
  chapulin session and Rotor's loop. Its instant comes from Rotor's `Loop.now_ns` (decision
  63, Rotor `ead3669`).
- hq-interop is the QUIC Interop Runner's HTTP/0.9 over QUIC: one `GET /path` line per
  bidirectional stream, answered with the file and the end of the stream. The server refuses a
  path with an empty, "." or ".." segment, and resets the stream of a file it does not hold.
- `tools/quic_udp.sh` runs both on 127.0.0.1. The client fetches files of 1,000, 100,000 and
  3,000,000 bytes, each compared byte for byte. The server must exit within 5 seconds of the
  client's close, and a request for a missing file must end in a reset stream.

It found a colibri defect, fixed in its own commit. A server treated the client's address as
validated only after a PATH_RESPONSE, so RFC 9000 §8's three-times limit held it for the whole
connection. The first run sent 6 KB of a 100 KB file and then as much as each small ACK
allowed. RFC 9000 §8.1 lets an endpoint treat the address as validated once it "has
successfully processed a Handshake packet from the peer", and a server now does. The
simulator missed it because its server sends little. 2 mutations, 2 CAUGHT, one of them only
after the test read an Initial packet first.

The endpoint's mutations: 7, 7 CAUGHT. A receive that ran out of buffers was caught only after
a test ran the group out, which moved the restart into `udp.zig`.

`zig build test`: 1421 passed, 26 skipped.

**Fuzzing, 2026-09-26.** `hq.zig` has a fuzz property ([#53](https://github.com/c4milo/colibri/issues/53)). An accepted path must be
the request's own bytes after `GET `, with only CR and LF after it. It must name a file inside
the served directory, which the property checks again without `check_path`. 6 mutations, 6
**CAUGHT**.

**colibri meets another QUIC implementation, 2026-09-23.** `tools/quic_aioquic.sh` runs the
UDP endpoint against aioquic 1.3.0's, a Python stack pinned and installed into a cached virtual
environment, over 127.0.0.1 in both directions. `tools/quic_interop/hq_peer.py` is the
aioquic side, a small hq-interop server and client on its public API.
- colibri's client fetches files of 1,000, 100,000 and 3,000,000 bytes from aioquic's server,
  and aioquic's client fetches the same three from colibri's. Every file arrives byte for
  byte, and colibri's server exits on aioquic's CONNECTION_CLOSE.
- Both directions passed on the first run, on the same machine as above, with chapulin
  `9c903d8`. It is the first time colibri's connection or chapulin's QUIC mode exchanged a
  packet with another implementation.

Mutations: 2, 2 CAUGHT, one for each direction's comparison.

**The endpoint runs in the QUIC Interop Runner, 2026-09-23.** `tools/interop.sh` builds the
`colibri-qns` image from the working tree and a chapulin checkout, and runs the runner at commit
`740c05a` against each peer, with colibri as the server and as the client.
- The image builds chapulin `TRUST=raw-ecdsa`, selected here with `-Dchapulin-quic-trust`. The
  runner's certificates carry no extended key usage, so they fail chapulin's Web PKI profile.
  Its client pins the server's P-256 key, which the runner's shared `/certs` holds.
- `tools/quic_interop/qns_identity.py` converts the runner's PEM into the raw DER and key
  bytes the endpoint reads. `run_endpoint.sh` maps `ROLE`, `TESTCASE` and `REQUESTS` onto
  `quic-udp`, and exits 127 for the cases the endpoint does not build.
- The runner's simulator learns a server is listening by sending it an unknown version, so the
  endpoint now answers with Version Negotiation (RFC 9000 §6.1).
- A server holds `quic_connections_max` connections, routed by the client's address, so a
  connection whose close was lost does not turn the next one away.
- On a connection error the endpoint closes with its code (RFC 9000 §11) instead of exiting.
- `tools/quic_interop/run_runner.py` lets the runner run on Python 3.14, which dropped two
  asyncio calls pyshark makes.

Against quic-go on this machine, colibri client and server, and colibri against itself:

| Test | colibri server | colibri client |
|---|---|---|
| handshake, transfer, chacha20, multiplexing, transferloss, handshakeloss | pass | pass |
| retry | unsupported: the suite mints no token | pass |

The runs found a colibri defect, fixed in its own commit. RFC 9000 §3.2 has a frame for a
peer's stream open every lower stream too, and only the named stream got its §18.2 limits.
The others kept a one-byte window, so their own frames, arriving late on a lossy path, broke
flow control. 2 mutations, 2 CAUGHT.

handshakeloss failed in both roles at first. A probe (RFC 9002 §6.2.4) carried a PING and never
the unacknowledged CRYPTO bytes, so under the case's bursty loss the probes that arrived gave
the peer nothing it could use. Decision 64 has a PTO at the Initial or Handshake level declare
that level's packets lost, so the probes carry the bytes (`09da2fa`). 4 mutations, 4 CAUGHT,
one by the simulator's check alone, whose census moved to 13,281 datagrams, 13,318 packets and
690 dropped. The server side then failed on its own table: four connections whose clients'
closes were lost filled it until their idle timeouts, so `6072b07` gives the next client the
connection idle longest. The last run passed every case the endpoint builds, in both roles.

Not built yet: a qlog, IPv6, Retry as a server, and `tools/ci.sh` running the runner. The hosted
runner's tshark is older than the 4.5.0 the runner needs.

**More peers, and the loss the random seeds missed, 2026-09-23.** Against ngtcp2, neqo and
quinn, colibri's client passed every case the endpoint builds, and its server failed
handshakeloss against all three, each for its own reason:
- `193fa99`: neqo reused a UDP port for its next connection, and the server routed a datagram by
  its sender's address, so the new connection's Initial packets went to the old one and were
  dropped. It now routes by Destination Connection ID (RFC 9000 §5.2), which
  `Connection.addressed_by` answers. 7 mutations, 7 CAUGHT.
- `2f5afeb`: quinn opens all 50 connections at once, and a table of 4 evicted connections still
  in their handshakes. The owner ruled a run-time option: the table holds
  `quic_connections_max`, 64, and `connections=<n>` uses fewer. 4 mutations, 4 CAUGHT.
- `a5063ee` and `1360983`, decision 65: one ngtcp2 connection lost the server's first flight and
  the CRYPTO probe of each of the next three PTOs. The server now sends its Initial CRYPTO bytes
  again at once when an ack-eliciting Initial packet brings no new CRYPTO bytes, at most twice
  per connection (RFC 9002 §6.2.3). 11 mutations, 11 CAUGHT.

quinn then showed the same failure in both roles: a request sent once and lost, the
acknowledgments that would have shown the loss lost too, and probes that never carried the
request. quinn's client probes carry NEW_CONNECTION_ID, and colibri's carried PING. Decision 66
(`37df3cb`, `4789639`) has a PTO at the application level declare its oldest ack-eliciting
packets lost, one for each probe, so the probes carry their frames. 7 mutations, 7 CAUGHT. The
QUIC check's census moved to 13,181 datagrams, 13,217 packets and 674 dropped. colibri's server
cannot change what quinn's probes carry, so handshakeloss with quinn as the client stays
flaky: it failed 3 of the 5 runs today, each time on a request quinn never sent again.

The random seeds never dropped every acknowledgment in a row, so two checks now look for exactly
that:
- Decision 67: `spec/tla/probe_timeout/ProbeTimeout.tla` lets the network drop every packet of
  ACK frames alone. TLC finds a lost frame never sent again under PING probes, and every frame
  delivered under decisions 64 and 66. `zig build tla` runs it through pepegrillo's `tla` tool.
- `18f8aa0`: the QUIC check gains an adversary that drops every datagram of ACK frames alone,
  and the client sends a one-packet request under it. All 256 seeds deliver it: 5,170
  datagrams, 1,645 dropped by the adversary. 6 mutations, 6 CAUGHT, and reverting decision 64 or
  66 leaves seed 0 stuck.

Also: `3747a77` writes the endpoint's key log after each step, because a server with many
handshakes at once filled it; `9baa6f3` fixes a UDP test that failed on Linux, where io_uring
delivers a datagram the receive group turned away and the next one in a single tick, which had
kept CI red since `db27985`.

The runner at `740c05a`, colibri at `18f8aa0`, on this machine:

| Peer | colibri server | colibri client |
|---|---|---|
| quic-go, ngtcp2, neqo, quinn | pass: H, DC, C20, M, L1, L2; S unsupported | pass: H, DC, C20, M, L1, L2, S |
| colibri | pass: H, DC, C20, M, L1, L2 | same run |

colibri against itself first failed DC, C20 and M, while other Docker containers were compiling
on the same machine: the runner's 60-second limit ran out. Run again alone, all three passed.

**Retry as a server, 2026-09-23.** Decision 55, amended (`aa0b37a`), has a Retry token carry the
client's first Destination Connection ID and the Retry's Source Connection ID, which RFC 9000 §7.3
has the server send back and which a server that keeps no state has nowhere else.
- `28375bb`: `retry_token_check` replaces `retry_token_valid` and gives both IDs back. A token
  returned to an ID its Retry did not name is invalid (§17.2.5.2), a token of another type is no
  token (§8.1.3), and a server routes the client's next Initial by the Retry's ID. 11
  mutations, 11 CAUGHT.
- `f4f4ad0`: the UDP server's `retry` option answers each client's first Initial with a Retry
  whose token chapulin mints (`cc88adb`) under a key drawn per run. It starts a connection only
  for an Initial that returns the token, and derives its Initial keys from the Retry's ID
  (§17.2.5.2). 9 mutations, 9 CAUGHT: 7 by unit tests, and 2 by the runner's retry case.

The runner at `740c05a`, colibri at `f4f4ad0`, chapulin `cc88adb` built `TRUST=raw-ecdsa`: retry
and handshake pass with colibri as the server against quic-go, ngtcp2, neqo, quinn and colibri,
and as the client against the four. The loopback, UDP and aioquic checks pass over chapulin
`992043f`, which fixed the `TRUST=webpki` QUIC build `756ad91` had broken.

**Key update, amplification and IPv6 in the runner, 2026-09-24.**
- `cf3872c`: the runner's `amplificationlimit` case sends a chain of nine certificates, a 10 KB
  Handshake flight. Decision 64 sends a level's whole flight again on a PTO, and the 4 KiB
  `crypto_send_buffer_len` had already forgotten the flight's first bytes, which closed the
  connection. The owner approved 16 KiB. 1 mutation, 1 CAUGHT.
- `169c91d`: the UDP endpoint takes an IPv4 or an IPv6 address. A server binds `::`, which
  takes both families on Linux, because the runner gives the server no hint of which family its
  `ipv6` case uses. A client's `keyupdate` option starts one key update as soon as RFC 9001
  §6.1 permits. The runner gives the server `transfer` for all three cases. 4 mutations, 4
  CAUGHT: 2 by unit tests, once one of them checked the IPv6 port, and the key update and the
  `::` bind by the runner.

The owner also approved three limits in `src/testing/constants.zig` that the nine-certificate
chain needs:
- `tls_der_len_max`, from 2 KiB to 8 KiB. The leaf carries twenty 250-byte DNS names, 5,514
  bytes in all.
- `quic_crypto_out_len`, from 8 KiB to 20 KiB. The Certificate message is 9,663 bytes, and a
  comptime assert holds this limit above twice `tls_der_len_max`.
- `quic_chain_len_max`, from 8 to 16. The chain is a leaf under eight intermediates.

The runner at `740c05a`, colibri at `169c91d`, where "all" is H, DC, C20, M, L1, L2, S, U, A
and 6:

| Peer | colibri server | colibri client |
|---|---|---|
| quic-go | all but L1 | all but L1 |
| ngtcp2, neqo | all | all |
| quinn | all but L1 | all |
| colibri | all | same run |

Against quic-go, L1 passed in both roles when run again. In the failed client run every file
had arrived, but the runner counted 51 handshakes where it expects 50: quic-go's server opened
two connections, 12 seconds apart, for one connection of the client's. "`handshakeloss` against
quic-go's server" below gives the cause. With quinn as the client, L1 stays flaky, as "More
peers, and the loss the random seeds missed" records.

**Rebinding in the runner, 2026-09-24.** The runner's `rebind-port` and `rebind-addr` cases
give the client a new port, or a new address and port, one second into the run and every five
seconds after. The server's first packet on each new path must carry a PATH_CHALLENGE, and the
client must answer every such challenge.
- [Decision 72](../../decisions/0072-the-caller-names-the-peer-address.md) and its amendments: `0800bd4`, `ddf82ce`, `80240da`, `c679b56`
  and `1786088`. The last lets a moved path's challenge go out past the congestion window and
  the pacer, because RFC 9000 §9.4 keeps the old path's packets out of the new path's
  congestion control.
- [Decision 73](../../decisions/0073-an-endpoint-that-sends-only-ack.md): `80240da`, with its TLA+ model in `9e6e0a0`.
- `f155153`: the simulator rebinds the client as a NAT does. Over 256 seeds the server moves
  once for each rebind: 276 times in the port check and 275 in the address check.
- `2a23bc7`: the UDP endpoint names each datagram's address, draws the challenge data, and
  issues spare connection IDs once the handshake is confirmed. quic-go's server waits for one
  before it sends on the client's new path (RFC 9000 §9.5). 3 mutations, 3 CAUGHT by the
  runner's `rebind-port` against quic-go: no challenge data, datagrams sent to the old
  address, and no spare connection IDs.

Two runs of the runner at `740c05a`, with chapulin built `TRUST=raw-ecdsa`: the first at
colibri `2a23bc7` with chapulin `992043f`, the second at colibri `66dd187` with chapulin
`2262eee`.

| Peer | colibri server | colibri client |
|---|---|---|
| colibri | first: `rebind-port`; second: `rebind-addr` | the same runs |
| quic-go | both cases, both runs | both cases, both runs |
| ngtcp2 | both cases, both runs | first: neither; second: `rebind-addr` |

No failure is a rule colibri broke. There are two causes:
- The network dropped the first PATH_CHALLENGE on the new path, three times: colibri's server
  against itself in both runs, and ngtcp2's server in the second run's `rebind-port`. Each
  time the server was sending to the client's old address near the path's 10 Mbps, so the
  25-packet queue was full. The next challenge was answered, and every file arrived. The
  runner checks only the first challenge on each path, so one lost datagram fails the case.
- In the first run, colibri's client sent its first packet to ngtcp2's server 0.94 and 1.02
  seconds into the capture, where against quic-go it sent at 0.73. The runner's
  `wait-for-it.sh` polls once a second, so the first rebind came as the handshake ended. In
  `rebind-addr` ngtcp2's server went on sending to the old address, which no longer reached
  the client, and the handshake never finished. In `rebind-port` its first packet on the new
  path carried no PATH_CHALLENGE.

**Resumption in the runner, 2026-09-24.** The runner's `resumption` case has the client fetch
one file, keep the server's session ticket, and fetch a second file on a second connection
that presents it. The runner fails the case if the second handshake carries a Certificate.
chapulin `2262eee` issues and accepts tickets in both roles (chapulin's decision 51).
- colibri itself needed no change. RFC 9001 §4.5 carries a NewSessionTicket in CRYPTO frames
  after the handshake, and colibri already moved CRYPTO frames at the application level.
- `66dd187`: the UDP server draws its ticket key when it starts and takes its start time as
  `seconds=<unix-seconds>`, which Rotor's instant advances (decision 63). A client given
  `resumption` keeps the first connection's ticket and presents it once, on the second, with
  the age RFC 9846 §4.3.11.1 defines. RFC 9001 §4.5 says a client "SHOULD NOT reuse tickets".
- chapulin fails a handshake whose ticket the server declines, so a second connection that
  fetches its file resumed. `tools/quic_udp.sh` now runs one such resumption between two
  colibri endpoints.

14 mutations, 14 CAUGHT: 11 by `tools/quic_udp.sh` and 3 by unit tests. The runner at
`740c05a`, chapulin `2262eee` built `TRUST=raw-ecdsa`, passed `resumption` in both roles
against colibri, quic-go and ngtcp2 on the first run.

**`handshakeloss` against quic-go's server, 2026-09-27**
([#72](https://github.com/c4milo/colibri/issues/72)). With colibri as the client, the case
fails with "Expected 50 handshakes. Got: 51": 3 of 11 runs at `ecb5924`, and 1 of 2 at
`a6a4791`. In the three captures below, the client opened 50 connections and completed 50
handshakes, and quic-go's server opened 51. colibri needs no change.
- The runner counts a handshake for each distinct Source Connection ID in the server's Initial
  packets, read from the server-side capture (`_count_handshakes` in its `testcase.py`).
- In each capture, one client connection lost what the server sent back, and then every
  packet it sent for 5 seconds. Its probes were seconds apart by then, because its PTO doubles
  on each one (RFC 9002 §6.2.1). quic-go's server destroyed the connection 5 seconds after the
  client's last packet reached it, and logged "timeout: no recent network activity".
- The client had received nothing from the server, so its next probe kept its first Destination
  Connection ID (RFC 9000 §7.2). quic-go started a second connection for it, under a second
  Source Connection ID, and the handshake completed on that one.
- No endpoint broke a rule. quic-go's server had processed no Handshake packet from the client,
  so the client's address was not validated (RFC 9000 §8.1), and RFC 9000 §10 lets an endpoint
  discard connection state when it has no validated path.

Three failed captures, each with quic-go at `9d085cc`:

| Run | colibri | Client port | quic-go's Source Connection IDs | Apart |
|---|---|---|---|---|
| 2026-09-24 | `169c91d` | 55685 | `673c38de`, then `18a9a339` | 12 s |
| 2026-09-27 | `ecb5924` | 55456 | `c1c1d964`, then `504eca39` | 6 s |
| 2026-09-27 | `a6a4791` | 57256 | `0518e848`, then `ec4de6cd` | 6 s |

In each, the capture holds 51 distinct Source Connection IDs in the server's Initial packets, and
the client's key log holds 50 `CLIENT_TRAFFIC_SECRET_0` lines.

[Decision 99](../../decisions/0099-colibris-runs-of-the-quic-interop.md), the same day: colibri's runs count the client's connection attempts,
the distinct Destination Connection IDs of the client's Initial packets numbered 0.
`tools/interop.sh` applies the change to the pinned runner, and it went upstream as
[quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509).
- Over 27 saved captures, the old count gave 51 and the new one 50 on the three failed runs
  above. The other 24 gave the same number both ways: `handshakeloss` with colibri's client once
  and quic-go's 15 times, `handshake`, `retry` and `resumption` for three client and server
  pairs, and `zerortt` for quic-go.
- A count of the client's Source Connection IDs, or of the server's IDs the client later used, is
  wrong for quic-go's client. It uses zero-length connection IDs, and it moves to a
  NEW_CONNECTION_ID one during the handshake.
- quic-go's own client failed 1 of 15 `handshakeloss` runs against quic-go's server. It gave up
  at its handshake timeout.
- With the patch, colibri at `08d631e` passed 10 of 10 runs as the client. In one, quic-go
  dropped a connection and started a second for the same client 7 seconds later: the old count
  gives 51 there.
- 1 mutation, **CAUGHT**: without the patch, the four captures with a dropped connection count
  51, and the case fails.

**`rebind-port` with colibri on both sides, 2026-09-28**
([#78](https://github.com/c4milo/colibri/issues/78)). The weekly run at `a5a97d2` failed
`rebind-port` with colibri's client against colibri's server, with "PATH_CHALLENGE without a
PATH_RESPONSE: ['c2:0c:4d:ea:0d:78:8a:b2']", though every file arrived. From the run's captures
and both endpoints' qlogs:
- At the first rebinding, 1.001 s into the server's capture, the server sent two
  PATH_CHALLENGEs 21 µs apart. Packet 175 went to the client's old port, a path RFC 9000 §9.3.3
  has the server validate, and the NAT dropped it for its lost binding. Packet 176 went to the
  new port. It is in neither the client's capture nor its qlog, and the simulator logs no drop
  for it. The likely place is the scenario's 25-packet queue, which the transfer's data filled.
- 95 ms later the server sent a new PATH_CHALLENGE on the new path, with new data (RFC 9000
  §13.3). The client answered it, and the PATH_RESPONSE reached the server 127 ms after packet
  176 left it. The second rebinding lost nothing on its new path.
- The runner's check, `TestCasePortRebinding.check` in its `testcases_quic.py`, takes only the
  PATH_CHALLENGE in the server's first packet on each new path.

[Decision 106](../../decisions/0106-colibris-runs-of-the-quic-interop.md), the same day: colibri's runs pass a new path once the client
answers any PATH_CHALLENGE sent on it. `tools/interop.sh` applies the change to the pinned
runner, and it went upstream as
[quic-interop-runner#511](https://github.com/quic-interop/quic-interop-runner/pull/511).
- Over the failed run's captures, the runner's check fails and the patched one passes.
- 1 mutation, **CAUGHT**: with the client's PATH_RESPONSE frames left out of its capture, the
  patched check fails, and names both new paths.
- `tools/interop.sh quic-go rebind-port,rebind-addr` with the patch, on an Apple M1 Pro:
  colibri's server passed both cases against colibri's client and quic-go's, and colibri's
  client passed both against quic-go's server. The 8 qlog directories passed
  `tools/qlog_check.py`.

**Probes that repeat the latest ACK, 2026-09-28**
([#76](https://github.com/c4milo/colibri/issues/76)). [Decision 107](../../decisions/0107-a-probe-above-the-initial-level.md): a PTO probe
at the Handshake or application level carries its space's latest ACK frame, though nothing new
asks for one (RFC 9000 §13.2). An Initial probe does not.
- `repeats_ack` in `packet_build_frames.zig` decides it, beside decision 72's packets to a path
  awaiting validation. 3 tests in `packet_build_probe_test.zig`: an application probe and a
  Handshake probe each carry an ACK whose own packet the path lost, and an Initial probe
  carries none.
- 3 mutations, each CAUGHT by `zig build test-quic`: no probe repeating an ACK, the application
  level's alone, and the Initial level's too.
- The simulator's pinned censuses and logs changed, and Debug and ReleaseSafe agree on the new
  ones. Decision 107 gives the times, and `tools/quic_udp.sh` and `tools/quic_aioquic.sh`
  passed.
- `tools/interop.sh quinn handshakeloss`, five times on an Apple M1 Pro: colibri's client passed
  all 10 of its runs, against colibri's server and against quinn's. quinn's client against
  colibri's server passed 4 of 5, where [#76](https://github.com/c4milo/colibri/issues/76) counted 3 of 5 against the same quinn image before
  the change. The runs kept no logs, because `INTEROP_LOGS` was not set, so the failed case's
  cause is not known yet.

**Three more pieces, 2026-09-23.**
- `3d0b2d7`: `send` asks the provider whether the handshake completed, as `receive` does. A
  client's stack finishes once its own Finished is written, which happens inside `send`, so
  the client had stayed incomplete until the next datagram arrived (RFC 9001 §4.1.1). 3
  mutations, 3 CAUGHT.
- `7d2c208`, [#43](https://github.com/c4milo/colibri/issues/43): a sender held back by flow
  control with no ack-eliciting packet in flight owes its DATA_BLOCKED and STREAM_DATA_BLOCKED
  frames again one PTO after its last ack-eliciting 1-RTT packet (RFC 9000 §4.1's
  "periodically"). `connection_timer` reports it as `Kind.blocked`. The period is the named
  limit `blocked_repeat_probe_timeouts`, one PTO. That is longer than a round trip, and a
  comptime assert holds it below the three PTOs RFC 9000 §10.1 sets as the idle timeout's
  floor. 10 mutations, 10 CAUGHT; a draining connection owing the frames first survived.
- `5a64471`, [#33](https://github.com/c4milo/colibri/issues/33): the golden corpus gains
  `quic_receive`, 17 cases walked through `connection_receive` at a client in a state the
  manifest names. Each pins the first discard, or the connection error the walk returns.
  Together they cover RFC 9000 §7.2, §12.2 and §12.3, and RFC 9001 §4.9, §5.5, §5.7, §6.2,
  §6.4 and §6.6. The golden module is given `quic` and not `sim`, so the corpus has a suite
  of its own. The last byte of a packet's tag says which keys open it, which models what a
  real suite learns by trying its keys. 9 corpus mutations added. 9 mutations of the receive
  path, 9 CAUGHT by `zig build test-golden` alone.

`zig build test`: 1382 passed, 18 skipped.

**The connection drives loss recovery, 2026-09-23**, `d7b56e6`, `0319c7a`, `33f2c69` and
`1dfc8e3`. Decision 59. Before it, `send` recorded no packet, an ACK frame updated only its
packet number space, and nothing called the loss timeout, so RFC 9002 never ran on a connection.

The four pieces:
- `connection_recovery` hands each batch of acknowledged or lost packets to every piece that
  keeps a record of what it sent: CRYPTO, stream bytes, the flow control frames,
  HANDSHAKE_DONE and the connection ID frames. A lost CRYPTO range the level's window has
  forgotten, or a full table of lost stream ranges, closes the connection with INTERNAL_ERROR
  (RFC 9000 §20.1).
- An ACK frame runs Appendix A.7's `OnAckReceived` where `connection_frames.process` reads it.
  The ACK Delay is decoded by the peer's exponent (RFC 9000 §19.3) and ignored at the Initial
  level (RFC 9002 §5.3). The caller places a `connection_recovery.Scratch` for the packets.
- `send` records each packet in flight (Appendix A.5). A packet of ACK frames alone is not
  recorded: Appendix A.1 tracks ack-eliciting packets, and a peer need not acknowledge one
  (RFC 9000 §13.2.1), so its record would hold a table slot until loss detection gave it up.
- `connection_timer.on_instant` runs Appendix A.9's `OnLossDetectionTimeout`. The packets it
  declares lost go through `connection_recovery`, and a Probe Timeout owes the probes `send`
  builds. Discarding Initial or Handshake keys discards that space's records (RFC 9002 §6.4),
  and the peer's max_ack_delay now reaches the Probe Timeout.

RFC 9002 §7 bounds what `send` puts in flight by the congestion window. A level sends
ack-eliciting packets only while the window holds the rest of the datagram, so a packet is never
cut short to fit and §14.1's padding fits too. Until then it sends only an ACK the space owes.
A PTO probe and a CONNECTION_CLOSE go whatever the window says. A client the window holds back
sends no Initial, because §14.1's padding would put it in flight. A space whose table is full
sends nothing until an acknowledgment arrives.

Appendix A.8's timer reads four facts from the rest of the connection: whether the handshake is
confirmed, whether this endpoint holds Handshake keys, whether the peer has validated its
address, and whether §8.1's limit leaves it anything to send. Nothing set any of them.
`connection_recovery` now copies them in from the connection's own state before the timer is
read.

One defect showed up along the way. The anti-deadlock probe counted from the instant the timer
was asked for, so each question moved it later and it never fired. It now counts from the last
event that set the timer (A.5, A.7 or A.9), which `recovery_timer.State.armed_at_ns` holds, and
`next_timer` takes no instant.

Not built: pacing (§7.7), which `send` does not consult, and ECN marking. `send` records every
packet as unmarked (RFC 9000 §13.4), so a caller that marks ECT would fail §13.4.2.1's
validation and stop marking.

Mutations: 8, 9, 21 and 23, all CAUGHT. Two first survived: an ACK that could still
wait was sent past the window, and a server arming an anti-deadlock probe.

`zig build test`: 1354 passed, 18 skipped.

**The rest of §6 is done, 2026-09-21**, `871d034`, `6169041`, `adf663c` and `ac522a2`.

§6.2's last paragraph refuses an acknowledgment carried under the old keys that names a packet
this endpoint protected with the newer ones. It needs the ACK's contents beside the key set the
packet opened under, and the frame layer was told neither, so `connection_frames.process` now
takes the `receive.Opened` the receive path already built — which carries both and replaces
three of its parameters. RFC 9000 §19.3 makes Largest Acknowledged a packet the frame
acknowledges and no number it names is above that one, so that field alone answers §6.2's "any
acknowledged packet".

§6.6's two limits are the suite's counts, so each arrives as a refusal, and colibri had been
throwing both away: a seal refusal became "the packet does not fit" and a failed open became
§5.5's discard. §6.6 wants the opposite of each. On the confidentiality limit the send path
initiates §6.1's key update and seals again, and closes with AEAD_LIMIT_REACHED only when no
update is possible — below the application level that is always, because §6.1's Note updates no
other level's keys. On the integrity limit the walk stops, because §6.6 says to "not process any
more packets". `packet_build.connection_error_code` answers null for a space out of packet
numbers: RFC 9000 §12.3 ends that connection with no CONNECTION_CLOSE at all.

§6.5's two waits are both three Probe Timeouts and neither had a clock. The old read keys go
three PTOs after a packet arrived under the new ones, and a key update this endpoint starts
waits three PTOs from the acknowledgment that confirmed the current phase. §6.6's update skips
the second wait, which is why there are two entry points: a SHOULD about packets a peer might
discard does not hold up a MUST about what the AEAD is still safe to protect. `on_instant` is
public so the timer piece can drive it; until then the receive path calls it on every 1-RTT
packet that opens, which is when colibri is told an instant at all.

The three loose fields `Connection` held for §6 became `key_update.Phase`, the way
`connection_keys.Keys` holds invariant 21's, because §6.5's timing needed three more.

Mutations: 31 applied across the three, 27 CAUGHT first time. The four gaps were all in the
tests. Two were rules only reachable when §6.1 would have permitted an update, and the cases
had set up a connection where it would not. One was the wire itself — reporting every packet as
the current key set — which nothing caught until a test walked a packet and then read its
frames. And one was a deadline the test computed from the same constant the code reads, so
changing the constant moved both; a comptime assert pins the three to what §6.5 says instead.
`zig build test`: 1170 passed, 18 skipped.

**Three defects the mapping found in committed code, 2026-09-20.** A client could not send its
first Initial: `Path.init` left every path unvalidated, so its allowance was three times nothing
and `on_datagram_sent`'s assertion would have halted on the first datagram. Invariant 18 stated
the claim for both roles and now names the server (`8f3152e`). `Record.in_flight` was documented
against ack-eliciting alone, while RFC 9002 §2 counts a PADDING frame too, which is the datagram
RFC 9000 §14.1 makes a client pad; `counts_in_flight` states it once (`e99d93d`). And
`write_crypto` sized a CRYPTO frame's Offset from `consumed_len`, the receiving mark, while
`write_frame` writes `sent_len`; the writer is bounds-checked so nothing overran, but a frame
that fit was refused on an asymmetric flight (`9c37af2`).

`zig build test` passes and `zig build lint` and `zig fmt --check` are clean after each of the
seven commits. Mutations: four on the path, three on the in-flight rule, seven on the identity,
seven on the key schedule, two on the offset and seventeen on the null provider. Three were
NOT CAUGHT first time and each was a missing test — a zero-length connection ID never reaching
the set §19.16 refuses a retirement for, no client ever processing a Handshake packet, and a
server treating a poll of `write_handshake` as the start of its handshake.

Two of the pieces above cannot be finished as the RFCs ask without a ruling: Retry's token needs
a key and a clock, and invariant 20's positive half needs an address on `sim.network`, whose
`Endpoint` is a client-or-server enum today, and a classifier for §9.1's probing frames.

**`tls.Provider`'s QUIC mode is declared, 2026-09-20.** `src/tls/quic_provider.zig` is the
eight members [decision 8](../../decisions/0008-the-tls-provider-is-a-caller.md) names for this mode, with no
implementation in the tree as non-negotiable 2 requires. A test holds the list to decision 8's
and to invariant 23's rule that no member moves a key, a secret or an IV — decision 48 removed
`on_secret` and `hkdf_expand_label`, so the secrets of RFC 9001 §4.1.4 go from the provider to
the suite inside the caller's code and colibri asks `crypto.Suite.keys_available` instead.

Three things are not in it, and each for a reason RFC 9001 states. There is no
`encrypt_record` or `decrypt_record`, because §3 says QUIC "takes over the responsibilities of
the TLS record layer" and `crypto.Suite` protects a packet instead. There is no
`send_close_notify`, because §4.8 closes a QUIC connection with a CONNECTION_CLOSE frame. And
`take_alert` answers an AlertDescription rather than a record, because §4.8 adds it to 0x0100
to make a CRYPTO_ERROR code and makes every alert fatal, so there is no level to report beside
it; `quic.error_code.crypto_error` already does that arithmetic.

The encryption level moved to `core`. `crypto.Suite` protects a packet at a level and this
vtable moves handshake bytes at one, and design §3 makes `tls` and `crypto` siblings with no
edge between them, so the type they share is `core.Level` and `crypto.suite.Level` is an alias
of it. No module-graph edge was added: both already import `core`.

`tls.constants` gains `alpn_h3`, RFC 9114 §3.1's token, beside `alpn_h2`.

**The CRYPTO streams are done, 2026-09-20.** `src/quic/crypto_stream.zig` is RFC 9000 §19.6's
one ordered flow of handshake bytes per encryption level, reassembled from the frames that
carried them. `src/quic/stream/` could not serve: a CRYPTO stream has no identifier, no FIN, no
flow control and no final size, so none of §3.2's receiving states or §4.5's final-size rules
apply to it. What it has instead is §7.5's buffer limit, which is the only thing bounding what
a peer can make colibri hold, because "there is no flow control of CRYPTO frames".

The window is anchored at what the handshake has read: `buffer[0]` is the byte at `base`,
`contiguous` counts the bytes from there with no gap, `readable` is the run the handshake may
take now and `consume` slides the window. Data past the window is a connection error of
CRYPTO_BUFFER_EXCEEDED, which §7.5 names for exactly it. The window is `crypto_buffer_len`,
4096, which is the RFC's floor rather than a choice of colibri's — in-order data is handed over
as it arrives and never sits here, so the number bounds only what a gap holds. Which bytes are
present is a bit each, not a byte: a byte would cost eight times the window per level.

Mutations: eight applied, all **CAUGHT** — the window's last byte refused, the bound removed,
the in-order run never extending, `consume` losing what was buffered above it, `consume` moving
the marks and not the bytes, a frame straddling the base written at the wrong offset, every
level answering as one, and `consume` not advancing the base.

Mutations: nine applied, all **CAUGHT** — two defaults changed, the 1200 floor removed,
`max_ack_delay` admitting 2^14 itself, a repeat accepted, a client's server-only parameter
accepted, an integer carrying trailing bytes, a connection ID past 20 bytes, and an unknown
parameter refused instead of ignored. Writing them found a weak test of colibri's own: it
compared a parsed value against the same constant it came from, so the constants are now pinned
to the numbers §18.2 states. `zig build test` passes 996 of 996.

**The TLA+ model, 2026-09-26** ([#49](https://github.com/c4milo/colibri/issues/49)).
- `spec/tla/quic_keys` models both endpoints' handshake over Initial, Handshake and 1-RTT, as
  colibri installs and discards each level's keys, over a network that loses packets and
  delivers them in any order. It carries the server's anti-amplification credit (RFC 9000
  §8.1), the client's anti-deadlock probe (RFC 9002 §6.2.2.1), the PTO that resends a level's
  CRYPTO data (decision 64) and the server's early Initial resend (decision 65). The properties:
  a level's keys go from none to available to discarded and never back (invariant 21); an
  endpoint discards its Initial keys only once it holds Handshake keys (RFC 9001 §4.9.1); and
  both handshakes are confirmed in the end.
- Three abstractions keep it small. Time is left out, so a timer that is set may fire at any
  moment; each level's probe is strongly fair, which RFC 9002 Appendix A.8's choice of the
  earliest deadline guarantees; and only the server's ACK frames are modeled, because nothing
  the server waits for depends on the client's.
- It found no defect. Writing it found three abstractions of the model's own that were wrong,
  each caught by TLC as a stall no colibri connection can reach: a server that sent one level
  at a time where colibri coalesces them (RFC 9000 §12.2), an ACK that acknowledged CRYPTO data
  its sender never received, and an anti-deadlock probe sent before the ClientHello.
- What `zig build tla` printed, on macOS arm64:
  - holds, as expected: `colibri`, 53059 distinct states; `tight_credit`, a server flight that
    takes the whole allowance a client datagram grants, 65876;
  - violated, as expected: `no_anti_deadlock`, where the client's first flight is acknowledged,
    the server's is lost, and neither side may send; `discard_on_complete`, a client that drops
    its Handshake keys on sending its Finished and cannot send it again; and
    `server_discard_on_send`, a server that drops its Initial keys on its first Handshake packet
    and cannot send its ServerHello again.

**The runner in CI, 2026-09-27.** The workflow's `quic-interop-runner` job runs
`tools/interop.sh` against quic-go, ngtcp2, neqo and quinn on Ubuntu 26.04, by hand and every
Monday (decision 47 as amended). Its first runs found three faults, each fixed:
- `b3088c5`: Zig 0.16.0 writes a zip package to `tmp/` in its global cache without creating
  that directory, so `zig build --fetch=all` failed on a fresh machine. The job creates it.
- `653cbde`: the client wrote each download with mode 0o600. On Linux the file belongs to the
  container's root, and the runner, comparing it as its own user, got Permission denied, so
  every case with colibri as the client failed. Docker Desktop maps ownership, so runs on macOS
  passed.
- `a1f557c`: decision 99's count took a client's first Initial to be numbered 0. ngtcp2's and
  neqo's clients began at 671978432 and 31, so every case with them failed although each
  transfer completed. Decision 99 as amended counts the connection IDs the client chose.

Run 36367616620, at `a1f557c` on Ubuntu 26.04, passed every case in both roles against quic-go,
ngtcp2, neqo and quinn, with `ecn` unsupported against quic-go alone. It took 72 minutes of the
job's 150. In the push job, h3spec 0.1.13 printed "49 examples, 0 failures" (run 36357580797,
at `54335d0`).

The count at `a1f557c` scored 2 for one quic-go handshake against quic-go's own server, a
pairing the job does not run: quic-go's client sends its last Initial packet to an ID from
NEW_CONNECTION_ID. Decision 99, amended again, counts only client Initial packets that carry
the start of the ClientHello. It gives each test's expected number on all 151 captures of run
36359234791 and on 16 from macOS arm64.

**Decision 64 amended, 2026-09-28.** With the count fixed, `handshakeloss` against quic-go's
server still failed 2 of 8 runs at `c881163`. The client's Finished went in one probe datagram
and a PING in the other, the network dropped the Finished's copy each time, and quic-go dropped
the connection 5 seconds after the client's last packet, although it had announced a 30-second
`max_idle_timeout` ([quic-go#4215](https://github.com/quic-go/quic-go/issues/4215)). The second
probe at the Initial and Handshake levels now repeats the first one's CRYPTO bytes.
- Over 2,000 seeds of the simulator's runner network, colibri against itself, the mean
  handshake fell from 1.36 to 1.26 seconds, those over 8 seconds from 17 to 10, and the slowest
  from 34.2 to 32.2 seconds.
- The QUIC check's census is now 13,719 datagrams, 13,790 packets, 684 dropped and 541 marked,
  crc32 `0xedec6668`, in Debug and in ReleaseSafe on macOS arm64. The other four QUIC censuses
  and both h3 digests moved with it.
- 4 mutations, 4 CAUGHT: no repeat, a repeat with no probe owed, a repeat from offset 0, and a
  PTO that notes no offset.
- The runner at `740c05a` against quic-go on macOS arm64, with the change at `c881163`: every
  case of `handshake`, `transfer`, `retry`, `resumption` and `handshakeloss` passed in both
  roles, and then `handshakeloss` passed 9 of 10 more runs as the client and 4 of 4 as the
  server. No run failed as the 2 of 8 had. The one that failed lost quic-go's ServerHello six
  times running, and quic-go ended the handshake at its 10-second limit, silently again.
