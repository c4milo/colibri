# Design decisions

Every entry here is a trade we made on purpose: what it costs, and what it buys. Changing one
means re-arguing the trade, not just editing the code. The README states what colibri does; this
file states why it does nothing more.

Entries marked **owner** are waiting on a ruling and are not settled. Everything else is settled
and is re-argued, not edited.

## Scope and shape

1. **One library for h2 and h3, not two in one repository.** Cost: a module graph that has to be
   defended, and a build that must prove the boundaries rather than assert them (§3 of
   docs/design.md). Gain: the surface that genuinely shares — the Huffman coder, the prefixed
   integer codec, the RFC 9110 semantics core, the field validators, and every harness — is
   written once and tested once. Entries 11 to 16 say exactly what shares and what does not, each
   from the RFC text rather than from the shape of the two protocols.

   Two separate libraries was the alternative. It was rejected because the shared surface is not
   incidental: RFC 9204 §4.1.2 adopts the RFC 7541 Appendix B Huffman code "without
   modification", and RFC 9114 §4.2 delegates the connection-specific field rules to RFC 9110
   §7.6.1 rather than restating them. Two libraries would copy both, and a copy of a 257-symbol
   code table is a copy that drifts.

2. **No HTTP/1.1.** Cost: colibri cannot serve or speak to an h1 peer, and a consumer that needs
   one keeps whatever it already has. Gain: the whole of RFC 9112 stays out — the eight-step
   message-body-length precedence of §6.3, the chunked decoder of §7.1, `obs-fold` unfolding
   (§5.2), the whitespace-before-colon rejection of §5.1, the connection-persistence state
   machine of §9.3, and the request-smuggling surface that §11.2 exists to narrow. None of that
   machinery is reused by h2 or h3, where framing is the transport's job and `Content-Length`
   degrades to a consistency check (RFC 9113 §8.1.1, RFC 9114 §4.1.2). It is a second,
   structurally unrelated parser for one version.

   h2c *upgrade* is also out, and for a different reason: RFC 9113 §3.1 says the `h2c` token and
   the Upgrade mechanism "was never widely deployed and is deprecated". Prior-knowledge cleartext
   h2 stays, and entry 8 explains why it is load-bearing rather than a convenience.

3. **QUIC is a module inside colibri, not its own library.** Ruled by the owner on 2026-09-16. A
   module, `src/quic/`, that imports `core`, `wire`, `crypto` and `tls` and nothing else, and that
   may never import `http`, `h2`, `h3`, `hpack` or `qpack`. Cost: colibri's repository carries the
   larger half of the work, and somebody who wants QUIC alone takes an HTTP library to get it.
   Gain: one CLAUDE.md, one simulator, one corpus format, one commit discipline, and no version skew
   between two repositories that change together for a year. The boundary that a separate
   repository would enforce socially is enforced here mechanically, by the module graph in
   `build.zig`, and the gate that proves it is that the QUIC simulator runs with no HTTP module
   in the graph at all.

   Extraction stays cheap on purpose: moving `src/quic/` to its own repository is a build-file
   change plus a vendoring step, because no edge points out of it. Reopen trigger: a second
   consumer wants QUIC without HTTP, or colibri's repository passes the point where one person
   can hold both halves.

4. **Client and server, both, from the first step.** Cost: roughly a third more state machine —
   stream-id parity in both directions (RFC 9113 §5.1.1), the two connection prefaces (§3.4),
   and both halves of every settings exchange. Gain: the conformance suites are server-side
   (h2spec, h3spec) and the interop runner needs both roles (design §9), so a client-only library
   could not be tested against anything. The server also *is* the product for stompy's `ops-api`
   and `platform-api`; a client-only library would be half a deliverable.

5. **`quic` knows nothing about HTTP.** RFC 9000 defines a transport with streams and no opinion
   about payloads. Cost: h3 cannot reach into QUIC for a shortcut, and anything h3 needs from a
   stream must be expressible in transport terms. Gain: the boundary is the same one the RFCs
   draw, so a rule is only ever in one place, and the QUIC simulator is a transport simulator
   that no HTTP change can perturb. Violation: a `if (stream_type == control)` inside `src/quic/`.

## The seams

6. **colibri owns no I/O.** No socket, no descriptor, no `poll`, no thread. The caller reads
   bytes and hands them in; colibri writes bytes into storage the caller owns and tells it how
   many. Cost: the caller writes the event loop, and colibri cannot hide a syscall optimization
   from it. Gain: the same code runs under stompy's io_uring plane, under a test harness, and
   under the deterministic simulator, with nothing conditionally compiled. chapulin's
   caller-supplied I/O callbacks are the precedent, and colibri takes it one step further:
   chapulin's callbacks block, and colibri has no callbacks at all.

   The rejected alternative is an I/O abstraction with a simulated implementation in-tree. It
   fails on the consumer side: stompy's rule is that every role's I/O extends `src/io/` so the
   simulator can substitute it, and an abstraction colibri defines would be a second one to
   bridge.

7. **Time is a value the caller passes, never a clock read.** Every function that needs the
   current instant takes it as a parameter, typed as nanoseconds since an origin the caller
   chooses. Cost: the parameter threads deep — RFC 9002's pseudocode reads `now()` at nine sites
   across five entry points, and the ninth is inside the congestion controller, so the instant
   must reach there too. Gain: loss recovery, idle timeouts and the PTO are testable and
   deterministic, and a failure found at one seed replays exactly. No source file imports a
   clock, and `tools/lint/determinism.zig` is what holds it.

8. **The TLS provider is a caller-supplied vtable with no production implementation in this tree.**
   Two modes, because the two protocols need different things from TLS, and RFC 9001 §3 is
   explicit about why: QUIC "takes over the responsibilities of the TLS record layer".
   - *Record mode*, for h2: `handshake_read`/`handshake_write`, `encrypt_record`,
     `decrypt_record`, `negotiated_alpn`, `handshake_complete`, `take_alert`, `send_close_notify`,
     `initiate_key_update`. h2 needs no access to any traffic secret, so the provider keeps the
     whole
     key schedule private. RFC 8446 does not require that of a TLS API — its §7.1 only defines the
     key schedule — so it is colibri's choice and not a citation.
   - *QUIC mode*, for h3: `set_transport_params`/`peer_transport_params` (the
     `quic_transport_parameters` extension, codepoint 0x39, RFC 9001 §8.2), `provide_handshake`
     and `write_handshake` per encryption level carrying unframed handshake-message bytes (§4.1.3),
     `on_secret(level, direction, secret, aead_id, kdf_hash)` (§4.1.4), `hkdf_expand_label` as a
     primitive (§5.1), `negotiated_alpn`, `handshake_complete`, and `take_alert` returning an
     `AlertDescription` value rather than a record (§4.8).

   Both modes also carry `export_keying_material`, RFC 8446 §7.5's exporter, which is the one
   operation RFC 8446 defines as a standardized, exposed interface.

   Cost: every consumer supplies a stack, and colibri cannot ship a working client on its own.
   Gain: colibri never links a TLS stack, never holds a private key, never chooses a suite, and
   the deterministic simulator substitutes a null provider of its own. RFC 8446 defines an API
   shape for exactly two things — the exporter (§7.5) and
   the handshake-complete indication (Appendix E.5) — so everything else in this interface is
   colibri's to specify, citing 8446 only for the semantics.

   The exporter is in the interface for both modes, and it is worth stating what it cannot do:
   it only reaches `exporter_master_secret`, which exists after the server's Finished, whereas
   QUIC needs Initial, 0-RTT, Handshake and 1-RTT secrets at four distinct points in time. That
   is exactly why QUIC mode needs new provider API rather than exporter calls, and it is the
   sharpest way to say what "no record layer" costs.

9. **Packet protection is a *second* caller-supplied vtable, so the TLS provider never has to carry
   AES.** Ruled by the owner on 2026-09-16. `crypto.Suite` supplies
   `aead_seal`, `aead_open`, `header_protection_mask(hp_key, sample) -> [5]u8`, `hkdf_extract` and
   `hkdf_expand_label`.
   colibri drives it directly for QUIC packet protection; the TLS provider never sees it.

   The header-protection member is a mask function and not a block cipher on purpose. RFC 9001
   §5.4.3 makes it AES in Electronic Codebook mode under a 128- or 256-bit key, and §5.4.4 makes
   it the **raw ChaCha20 function** over a 4-octet counter and a 12-octet nonce taken from the
   sample, encrypting five zero octets. Those are not the same primitive and neither is an AEAD
   call, so a vtable exposing one ECB block could not protect a ChaCha20 connection at all. The
   mask function is the smallest member that covers both.

   This is the answer to the AES problem, and the problem is real. RFC 9001 requires AES
   unconditionally, whatever suite TLS negotiates, in three places:
   - Initial packets use `AEAD_AES_128_GCM` with keys derived from the client's Destination
     Connection ID (§5, and the Initial salt and labels in §5.2).
   - Header protection before a suite is selected is AES-based, matching `AEAD_AES_128_GCM`
     (§5.4.1), and AES-based header protection is 128-bit AES in Electronic Codebook mode
     (§5.4.3).
   - The Retry packet integrity tag is `AEAD_AES_128_GCM` under a hardcoded key and nonce (§5.8).

   Beyond those three, the suite must also carry whatever TLS goes on to negotiate: RFC 9001 §5.3
   makes the packet-protection AEAD the negotiated one and §5.4.1 makes the header-protection
   algorithm follow it.

   None of that is negotiated and none of it is optional, so a QUIC endpoint cannot be built
   without AES-128-GCM, AES-128-ECB and HKDF-SHA256 — even one that negotiates
   `TLS_CHACHA20_POLY1305_SHA256` for every packet after the Initial packets, which RFC 9001 §5.3
   does permit. Two notes for the code: RFC 9001 never writes "MUST use AES-128-GCM", it states it
   declaratively with no alternative offered, so cite §5 and §5.4.1 and do not write MUST; and
   the header-protection key never changes across a key update (§5.4, §6.1), so it is installed
   once per direction at 1-RTT and never touched again while `key` and `iv` rotate under
   `"quic ku"`.

   Splitting packet protection away from the TLS provider is what makes this tractable, and the
   reason it works is that once QUIC takes over the record layer (§3) the TLS stack does no bulk
   cipher work at all: the Initial keys, the AES header protection and the Retry tag are all
   computed by the QUIC layer from a fixed salt, a hardcoded key and the client's connection ID.
   A caller may therefore fill the TLS provider from a stack with no AES and the suite from a
   separate AES source. Cost: two vtables where a smaller library would have one, and a caller that
   must fill both. Rejected: one combined vtable, which would have made every h3 consumer's TLS
   stack an AES stack.

   Be precise about the gain, because it is narrower than it first looks, and entry 10 narrowed it
   again. h3 is not blocked on the TLS provider **carrying** AES, but colibri's own tree does not
   use that freedom: entry 10 has chapulin fill both vtables, so chapulin supplies the AES as well,
   and [the request](chapulin.md) reverses chapulin's decision 6 to get it. What the split still
   buys there is placement: the AES sits behind `crypto.Suite`, where chapulin can carry it as a
   host-side mode of its own rather than inside its TLS record layer. Nor is h3 independent of what
   the TLS stack **negotiates**: RFC 9001 §5.3 and §5.4.1 make packet protection and header
   protection follow the negotiated suite, so a TLS provider that offers only
   `TLS_CHACHA20_POLY1305_SHA256` obliges the suite to carry ChaCha20-Poly1305 and raw ChaCha20 as
   well as the three mandatory members, AES-128-GCM, AES-128-ECB and HKDF-SHA256. That is why the
   request asks chapulin's suite for all five.

   A caller that supplies a suite without AES-128-GCM, AES-128-ECB or HKDF-SHA256 is rejected at
   init, not at the first Initial packet. A suite that lacks the AEAD or header-protection
   algorithm TLS goes on to negotiate cannot be caught that early, because the suite is unknown
   until EncryptedExtensions is decrypted; that case returns the same configuration error class at
   the first Handshake packet, so it still does not read like an attack.

10. **chapulin provides all of colibri's crypto, through colibri's two vtables.** Ruled by the
    owner on 2026-09-16. chapulin fills both `tls.Provider` (entry 8) and `crypto.Suite` (entry
    9). colibri's library source never imports chapulin, so the packaged library still links no
    TLS stack and this tree still carries no production implementation of either vtable.
    `src/testing/` links chapulin. That answers the dependency question design §8 step 5 raised
    under CLAUDE.md's "Ask before": the gates from step 5 onward get their TLS 1.3 server, and
    its certificate signing, from chapulin.

    The request is [docs/chapulin.md](chapulin.md). Sending it is the owner's, and this repository
    never edits chapulin's. It asks for a server role, ALPN, a non-blocking handshake with no
    global state, the exporter, a QUIC mode and host-side AES, and it names what each item
    reverses: chapulin's decisions 6, 8, 9, 20 and 28, and its server non-goal. chapulin's decision
    36, "a mode, not a change", is the shape it follows.

    Cost: every colibri gate that needs TLS or real packet protection now waits on work in another
    repository, and that work reverses five of chapulin's recorded decisions. Gain: one crypto
    source for colibri's whole tree, argued under one charter, with no third-party stack in
    `src/testing/`. Two alternatives lost. The ask this entry used to make, ALPN and nothing else,
    left every gate from step 5 onward with no TLS server at all. A different test-only TLS stack
    would have added a dependency whose charter nobody here argued, and its interop results would
    measure that stack rather than chapulin.

    If chapulin declines an item, colibri's source does not change. The vtables already have zero
    implementations in this tree, and steps 0 to 4, 6, 8 and 11 need no crypto at all: step 4
    ships prior-knowledge cleartext h2, so the whole h2 core is built and tested with no TLS. Only
    the gates that need the declined item wait, and naming a different provider for
    `src/testing/` would be a new "Ask before".

## What is shared between h2 and h3

Entries 11 to 16 are the shared-surface question answered from the RFC text. Three of them
correct a candidate that looked shared and is not, or looked unshared and is.

11. **The Huffman coder and the prefixed-integer codec are shared, and both are RFC 7541's.**
    RFC 9204 §4.1.2 says the Huffman table of RFC 7541 Appendix B "is used without modification":
    257 symbols, codes of 5 to 30 bits, EOS = 0x3fffffff. One table in `.rodata`, one coder, no
    divergence. The three mandatory decode errors travel with it, stated in RFC 7541 §5.2:
    padding strictly longer than 7 bits, padding that is not the high bits of EOS, and a complete
    EOS inside the data.

    The two padding rules reduce to run-of-ones arithmetic on the tail, because EOS is thirty set
    bits. **The third does not, and a decoder written as though it did rejects legal input.** A run
    of thirty ones can be produced by adjacent long codes with no EOS present: Appendix B's symbol
    204 is 27 bits ending in five ones and symbol 22 is 30 bits beginning with twenty-nine, so the
    two-octet string `0xCC 0x16` encodes to a run of thirty-four ones containing no EOS. EOS must
    therefore be detected at a symbol boundary inside the decode loop, never by scanning for a run.

    **Correction to a premise:** the prefixed integer codec is shared too. RFC 9204 §4.1.1 says
    "The format from [RFC7541] is used unmodified", so HPACK and QPACK read the same integers.
    The confusion is worth writing down because it is easy to repeat: QUIC's variable-length
    integer (RFC 9000 §16) is a *different* primitive, used by the QUIC and h3 framing layers and
    never by a field-section representation. colibri therefore has two integer codecs, and the
    split is not h2-against-h3 — it is *field compression* against *framing*. `src/wire/` holds
    both and says so.

    Two details the codec must carry: QPACK uses prefix widths HPACK never uses (RFC 9204 §4.1.1
    notes it), so the codec is generic over N in 1..8 rather than specialised to HPACK's 4, 5, 6
    and 7; and RFC 9204 §4.1.1 requires decoding integers up to and including 62 bits, where RFC
    7541 §7.4 only says to pick a limit. Size for 62 bits and both are satisfied.

    One more shared piece: the dynamic-table size formula. RFC 7541 §4.1 and RFC 9204 §3.2.1 give
    the same rule word for word — name length plus value length plus 32, measured on the
    unencoded strings — and the eviction loop is the same shape. The arithmetic is shared; the
    tables are not, which is the next entry.

12. **The static tables and the index address space are not shared, and cannot be.** HPACK's
    static table has 61 entries numbered from 1 (RFC 7541 Appendix A); QPACK's has 99 numbered
    from 0 (RFC 9204 Appendix A), and RFC 9204 §3.1 states the off-by-one deliberately. Worse
    than different contents: RFC 7541 §2.3.3 fuses static and dynamic into one address space where
    an index above the static length addresses the dynamic table, and RFC 9204 §3 opens by saying
    the opposite — "entries in the QPACK static and dynamic tables are addressed separately" —
    with a `T` bit in the representation to say which. A shared "resolve an index to an entry"
    function is not a simplification, it is a bug. Two tables, two resolvers.

    The representations do not share either. Every QPACK *field line* representation (RFC 9204
    §4.5) has a different bit pattern and prefix width from its HPACK analogue, and two of them —
    indexed with post-base index, and literal with post-base name reference — have no HPACK
    analogue at all. The one exception is the table-size instruction: HPACK's Dynamic Table Size
    Update (RFC 7541 §6.3) and QPACK's Set Dynamic Table Capacity (RFC 9204 §4.3.1) share the
    `001` pattern and the 5-bit prefix, and they still live in different modules because they
    arrive on different streams.

    And the reason runs deeper than encoding. RFC 9204 §2.2 names it: in HPACK the encoded field
    section carries the instructions that mutate the dynamic table, while in QPACK the field
    sections and the table-mutating instructions arrive on separate streams. That one difference
    is why QPACK needs Known Received Count, Required Insert Count, a Base, blocked-stream
    accounting and per-entry reference counts, and why HPACK needs none of them. HPACK also
    assumes a reliable, ordered byte stream and says nothing about out-of-order delivery — a
    structural assumption, not a syntactic one.

13. **Correction to a premise: flow control is not shared.** It looked like the same shape over
    different frames. It is not the same shape. h2's flow control is a *credit* counter: 31-bit
    windows, an initial value of 65,535 (RFC 9113 §6.9.2), `WINDOW_UPDATE` adding credit, DATA
    payloads alone consuming it, and a send window that must be a *signed* quantity because a
    reduction in `SETTINGS_INITIAL_WINDOW_SIZE` can drive it negative and RFC 9113 §6.9.2
    requires tracking that. QUIC's flow control is a *high-water mark*: 62-bit absolute offsets,
    `MAX_DATA` and `MAX_STREAM_DATA` naming the offset a peer may send up to rather than an
    increment, every byte of stream data counting rather than one frame type's payload, and a
    final-size rule with no h2 equivalent.

    They are different algorithms with a common purpose. Cost of the honest answer: two
    implementations. Gain: no accounting bug born of forcing a credit counter and an offset
    tracker through one interface. The RFC 9113 §6.9.2 retroactive sweep — every stream's window
    adjusted on a settings change — is the clearest sign they do not belong together; QUIC has
    nothing like it, because an offset limit needs no retroactive adjustment.

14. **The stream *table* is not shared; a bounded slot pool is.** The candidate was the table and
    its id and half-close rules. The rules do not travel: h2 ids are 31-bit with client-odd and
    server-even parity and a closed set of seven states (RFC 9113 §5.1); QUIC ids are 62-bit with
    the two low bits encoding initiator and directionality, and separate sending and receiving
    state machines (RFC 9000 §3.1, §3.2). h3 does not have a stream table at all — RFC 9114 says
    stream concurrency is QUIC's, so h3 holds per-stream *frame decode* state and nothing else.

    What is genuinely shared is one data structure: a fixed slot pool with a per-parity watermark,
    where "closed" is the implicit default for anything below the watermark rather than a stored
    record. Both protocols need it for the same reason. In h2, ids cannot be reused and any stream
    leaving idle implicitly closes every lower-numbered idle stream the peer could have opened
    (RFC 9113 §5.1.1), so a map keyed by id can grow by 2^31 entries from one frame. In QUIC, a
    single out-of-order STREAM frame implicitly opens every lower-numbered stream of its type
    (RFC 9000 §3.2; §21.8 is the exhaustion hazard that rule creates). Same hazard, same structure,
    different rules on top. The structure lives in
    `core`; the rules live in `h2` and `quic`.

15. **The semantics core is shared; the verdicts are not.** RFC 9110 §2.5 says core semantics do
    not change between versions, only their expression on the wire, and that sentence is the
    module boundary. `src/http/` holds: method as an opaque case-sensitive token (§9.1); status as
    a `u16` in 100..599 with class from the first digit and an unrecognised code treated as the
    x00 of its class (§15); the `field-name = token` and `tchar` grammar (§5.1, §5.6.2) and
    case-insensitive comparison; the `field-value` grammar with `obs-text` at %x80-FF and the
    rule that CR, LF and NUL are invalid (§5.5); the order-preserving field-section model, because
    §5.3 makes the order of same-name lines significant; the connection-option denylist of §7.6.1,
    which RFC 9114 §4.2 delegates to rather than restates; the "no content" table of §6.4.1, which
    both RFC 9113 §8.1.1 and RFC 9114 §4.1.2 carry; `Content-Length` as a semantic field
    (§8.6); trailer policy (§6.5.1); and `HTTP-date` (§5.6.7). On the "no content" table, RFC 9113
    §8.1.1 points back to §6.4.1 by name and RFC 9114 §4.1.2 restates the rule without a
    cross-reference.

    What stays out, and why each would be a bug if it went in: **`obs-fold`**, which is RFC 9112
    §5.2 and appears nowhere in 9110 — any unfolding code in a shared core is h1 contamination.
    **The lowercase-on-the-wire rule**, which 9110 does not state; it is RFC 9113 §8.2 with its
    receive-side check in §8.2.1, and RFC 9114 §4.2, worded differently and hanging off different
    errors. **The malformed verdict**:
    same predicate, different enum — h2 gives a stream error of `PROTOCOL_ERROR` (RFC 9113
    §8.1.1), h3 gives `H3_MESSAGE_ERROR` (RFC 9114 §4.1.2) — so the core returns a *reason*, never
    a code. **Pseudo-headers**, which are RFC 9113 §8.3 and RFC 9114 §4.3, not 9110, and which
    genuinely differ: h2 says a recipient MUST NOT use `Host` when `:authority` is present, h3
    says if both are present they must be equal. Do not write one shared authority resolver.
    **Message-body length determination**, which is h1's. **Field-section size accounting**, whose
    name+value+32 formula is in RFC 9113 §6.5.2 and RFC 9114 §4.2.2 under different setting names
    at the same identifier 0x06 — share the arithmetic, not the setting.

16. **No caching, and the conformance bar for RFC 9111 is zero.** RFC 9111 §2 says caching is "an
    entirely OPTIONAL feature of HTTP", every normative requirement in its §3 and §4 is scoped to
    the subject "a cache", and the single requirement binding a non-cache — §5.2, pass cache
    directives through in forwarded messages — binds *proxies*. colibri is neither. Cost: a
    consumer that wants a cache writes one. Gain: no revalidation, no freshness arithmetic, no
    `Vary` matching, no stored-response state that would have to survive a connection.

    The practical obligation, which is not a conformance requirement: hand `Cache-Control`, `Age`,
    `Expires`, `Vary`, `Date`, `ETag` and `Last-Modified` to the caller byte-exact, so a
    caller-built cache can itself be conformant. `Pragma` is deprecated (§5.4) and `Warning` is
    obsolete (§5.5); neither gets a line of code.

## What colibri does not build

Each of the seven is a no with a reason, and each records what saying no still costs on the wire,
because a feature you refuse is not a feature you can ignore. A no now is cheaper than a maybe.

17. **Server push: no.** It is optional in both protocols. Cost of refusing, h2: a client must
    send `SETTINGS_ENABLE_PUSH` (0x02) with value 0, because its initial value is 1 (RFC 9113
    §6.5.2) and silence is consent; and until the peer's SETTINGS ACK arrives a `PUSH_PROMISE`
    may legally arrive, which cannot simply be dropped — it reserves a stream, its field block
    must still be HPACK-decoded or the dynamic table desynchronises (§4.3), and the correct
    answer is decode, reserve, `RST_STREAM` with `CANCEL` or `REFUSED_STREAM` (§8.4.2). After the
    ACK, a `PUSH_PROMISE` is a connection error of `PROTOCOL_ERROR`. A colibri *server* has it
    easier: RFC 9113 §6.5.2 says a server MUST NOT set the value to 1, so omitting the setting is
    already a refusal. Cost of refusing, h3: never send `MAX_PUSH_ID`, whose value is unset at
    connection creation (RFC 9114 §7.2.7), and answer a push stream or an oversized push id with
    `H3_ID_ERROR` (§4.6). One check.

    **State the reason correctly.** RFC 9113 does not deprecate server push. §8.4 says it is
    "difficult to use effectively"; Appendix B deprecates the RFC 7540 priority scheme and the
    h2c Upgrade mechanism, not push. colibri's reason is "optional and unused", and writing
    "deprecated" would be a citation nobody can check.

18. **Priorities: no to scheduling, yes to the mandatory parsing.** RFC 9113 §5.3.2 deprecates
    RFC 7540's priority signalling but deliberately keeps the frame syntax and some of its
    mandatory handling for interoperability, so colibri still owes all of: accept `PRIORITY`
    (0x02) in every stream state including idle and closed; a stream error of `FRAME_SIZE_ERROR`
    when its length is not exactly 5 octets; a connection error of `PROTOCOL_ERROR` when its
    stream identifier is 0x00; and skipping exactly 5 octets when `HEADERS` carries the PRIORITY
    flag 0x20, or the HPACK block starts at the wrong offset. That last one is the bug this entry
    exists to prevent.

    RFC 9218 is squarely optional: §1 says servers "can ignore client priority signals and still
    successfully serve HTTP responses", and §10 says expressing priority is only a suggestion.
    colibri ignores it and does the generic thing — discard `PRIORITY_UPDATE` as an unknown frame
    type, and ignore the `SETTINGS_NO_RFC7540_PRIORITIES` identifier if a peer sends it. It does
    take the one cheap position RFC 9218 §2.1 offers: send `SETTINGS_NO_RFC7540_PRIORITIES` with
    value 1 in its first SETTINGS frame, immutable thereafter, to declare that it ignores 7540
    signals. §2.1 permits that without adopting 9218's scheme.

19. **Extended CONNECT: no.** `SETTINGS_ENABLE_CONNECT_PROTOCOL` is identifier 0x08 with initial
    value 0 (RFC 8441 §9.1), and a client may use extended CONNECT only on receipt of value 1
    (§3). Refusing is pure omission. What a non-supporting endpoint must still do is specified,
    and colibri gets it for free: an unexpected `:protocol` is an undefined pseudo-header, which
    RFC 9113 §8.3 makes the request malformed, which is a *stream* error and not a connection
    error. The only way to get this wrong is to kill the connection, so the pseudo-header
    validator's error class is what this entry is really about.

    For h3, note honestly what we know: RFC 9114 defines base CONNECT only (§4.4), says
    pseudo-header restrictions can be relaxed only by an extension (§4.3), and does not itself
    define extended CONNECT. The document that does is outside the set colibri read, so this entry
    cites no section for it and colibri's h3 side simply treats `:protocol` as undefined.

20. **0-RTT: no, in both protocols.** Refusal is the specified default and is expressed by
    omission: a server omits the `early_data` extension from its NewSessionTicket (RFC 9001
    §4.6.1) and, mid-handshake, omits it from EncryptedExtensions (§4.6.2). Two structural
    reasons make this more than a scope cut. RFC 9001 §5.6 says a client MUST NOT use 0-RTT for
    application data unless the application specifically requests it and the application protocol
    supplies a 0-RTT profile — colibri owns no application semantics and cannot supply one. And
    RFC 9000 §7.4.1 requires a 0-RTT client to remember every server transport parameter it can
    process, apart from seven it must never reuse, and forbids a server accepting 0-RTT from
    lowering seven named limits; that is persistent cross-connection state, which conflicts
    directly with allocating once at init.

    Saying no also deletes the stream-state rollback a client must perform when a server rejects
    0-RTT (RFC 9001 §4.6.2), which is a path that would otherwise exist solely to be got wrong.

21. **Connection migration: no to initiating it and no to accepting it — and this is the smallest
    saving of the seven.** The mechanism is the `disable_active_migration` transport parameter,
    identifier 0x0c with a zero-length value (RFC 9000 §18.2). It refuses exactly one thing: the
    peer using a *new local address* when sending to the address colibri used during the
    handshake. Three consequences that are routinely got wrong, and that colibri writes down
    because the saving is so much smaller than the name suggests:

    - **Refusing is not an error you may signal.** If a peer migrates anyway, RFC 9000 §9 permits
      exactly two responses: drop the packets silently without a Stateless Reset, or validate the
      path and allow it. Closing the connection is forbidden, because it would let a third party
      close connections by spoofing traffic. There is no `MIGRATION_REFUSED` code in §20.1.
      colibri's refusal path is a silent drop plus a counter.
    - **It does not exempt colibri from path validation.** RFC 9000 §9 says not all changes of
      peer address are intentional migrations, and then requires path validation on *any* detected
      change to a peer's address unless already validated. NAT rebinding is not active migration
      and is not refusable. So colibri still implements the whole of §8.2 and the migration rules
      that hang off it: `PATH_CHALLENGE` and `PATH_RESPONSE` with the 8-octet echo (§19.17,
      §19.18), the one-response-per-challenge rule and the 1200-octet datagram expansion (§8.2.2),
      the anti-amplification limit (§8), the revert-to-last-validated-address rule on failure with
      a silent close when no such address is held (§9.3.2), the challenge to the previously active
      path on an apparent migration (§9.3.3), and the congestion and RTT reset on confirming a new
      address with the port-only exemption it may take (§9.4).
    - **A connection-ID pool is still required.** `active_connection_id_limit` must be at least 2
      and defaults to 2 (RFC 9000 §18.2), so `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID` are
      implemented by an endpoint that never moves.

    One consistency rule: colibri does not send `preferred_address` if it sends
    `disable_active_migration`, because RFC 9000 §9 exempts migration following a preferred
    address and sending both re-opens the door just closed.

22. **HTTP datagrams: no, at the QUIC layer.** `max_datagram_frame_size` is transport parameter
    0x20 with default 0, and 0 means the endpoint does not support DATAGRAM frames (RFC 9221 §3).
    Omit it and a conformant peer will not send one. The only wire obligation is the error case,
    and it has a trap: receiving a DATAGRAM frame without having advertised support must terminate
    the connection with `PROTOCOL_VIOLATION` (§3), and colibri must recognise **both** codepoints,
    0x30 and 0x31, because the low bit is the LEN flag (§4). A dispatcher that knows only 0x30
    lets 0x31 fall through as an unknown frame type and produces the wrong error.

    There is also a design-fit reason. RFC 9221 §5.3 says DATAGRAM frames carry no explicit flow
    control signalling and do not contribute to any per-flow or connection-wide data limit. They
    are the one data carrier in QUIC with no backpressure, so colibri would have to own a drop
    policy, which is an application decision colibri has no standing to make.

    Scope note: this covers the QUIC extension only. The HTTP-layer datagram binding is a separate
    document colibri has not read, and this entry makes no claim about it.

23. **Multipath: no, and there is nothing to decline.** RFC 9000 is single-path by construction —
    §9.3 chooses the active path by the highest-numbered non-probing packet, one integer of state.
    Multipath is an extension defined outside the set colibri read, and RFC 9000 §7.4.2 says the
    absence of a transport parameter disables any optional feature negotiated by it, so the
    conformance cost of saying no is zero. The one related obligation is not to choke on reserved
    transport-parameter identifiers of the form 31*N+27 (§18.1), which exist precisely to exercise
    that ignore path — and colibri tests it rather than assuming it.

## Correctness

24. **Reading the RFC is not evidence.** Every step in the build plan names which of the five
    gates proves it, and a step with no gate is not a step. The five are the golden corpus,
    published test vectors, the conformance suites, interop against real stacks, and the
    deterministic simulator — with fuzzing over every parser and mutation over every test.

25. **Published vectors before invented ones.** HPACK and the h2 frame layer both have published
    corpora and colibri uses them rather than writing its own: `http2jp/hpack-test-case` and
    `http2jp/http2-frame-test-case`. **Correction worth recording:** there is no
    `httpwg/hpack-test-case`; that path does not exist, and the canonical repository is
    `http2jp/`. Decode every encoder directory in it, not only nghttp2's — the naive, static and
    linear strategies crossed with Huffman and plain are what exercise the dynamic table and the
    Huffman paths.

    QPACK's equivalent is `qpackers/qifs` in the QIF format, and its maturity must be stated
    rather than assumed: its newest outputs target draft-ietf-quic-qpack-05 rather than RFC 9204,
    and the repository has not moved since January 2021. A mismatch is checked against the RFC
    first and is not automatically colibri's bug. RFC 9204 Appendix B carries the only reference
    encodings inside the RFC itself, and RFC 9001 Appendix A carries sample packet protection —
    both are corpus cases in `src/golden/` on the first commit of their step.

26. **The golden corpus is exact bytes with a manifest**, in the shape stompy's `src/golden/`
    uses: one directory per format, one file per case, and a manifest line per file naming its
    length, its checksum, its expected verdict and the parameters it was built from. Valid and
    invalid cases both, because a parser that accepts everything passes a valid-only corpus.
    `zig build golden` regenerates and refuses a directory carrying a `FROZEN` marker.

27. **Conformance suites are gates, and their versions are pinned.** h2spec for the h2 server,
    h3spec for the h3 server. Both need a test-only server entry point, which design §9 names,
    and their maturity is not equal: h2spec has 147 cases but is written against RFC 7540 and
    7541 rather than 9113, with its last release in 2020 — so its version is pinned and a
    disagreement is checked against RFC 9113 before it is treated as colibri's bug. h3spec is
    narrower, roughly 50 cases and error cases only, with no happy path and no flow control, but
    it is the better maintained of the two. Neither is sufficient alone, which is why entry 28
    exists.

28. **Interop against real stacks, both directions, is the bar for h3.** The QUIC Interop Runner's
    matrix is the standard, and joining it is a design constraint rather than a later chore: an
    endpoint implements a Docker contract reading `ROLE`, `TESTCASE` and `REQUESTS`, serving `/www`
    on port 443, writing to `/downloads`, emitting a keylog and qlog — and **exiting 127 for any
    test case it does not support**, which is what lets colibri join with handshake, transfer and
    http3 alone and light up the rest later without showing red. Most transfers run HTTP/0.9 over
    ALPN `hq-interop`, so that ALPN is a test-only entry point too. For h2 the equivalent is
    nghttp2, curl, Go's `net/http2` and h2o, in both directions.

29. **Fuzz every parser, and every gate is seeded.** A parser is anything that reads peer bytes:
    the frame readers, the packet reader, HPACK, QPACK, the varint and prefixed-integer decoders,
    the field validators, the transport-parameter reader. chapulin's `fuzz/` is the shape.

30. **The deterministic simulator is the gate that the others cannot be.** Seeded connection
    state, flow control, loss, reordering and recovery, with byte-identical replay across hosts
    and build modes as the pass condition. It is built before the protocol it drives (CLAUDE.md
    non-negotiable 7), which is possible only because entries 6, 7 and 8 made I/O, time and crypto
    into seams.

    Say what the null crypto suite does and does not buy, because it is easy to overclaim. It is
    **not** what makes a seed replay: AES-GCM and ChaCha20-Poly1305 are pure functions of key,
    nonce and plaintext, so a real suite replays just as deterministically. What it buys is that
    the simulator needs no crypto dependency and costs no cipher time. It must therefore be
    **size-faithful, not an identity function** — it appends a 16-octet tag and returns a 5-octet
    mask exactly as a real suite would — because RFC 9001 §5.3's expansion feeds §5.4.2's sample
    offset, the Length varint, RFC 9000 §14.1's 1200-octet minimum and the anti-amplification
    count. A null suite that shortened packets would simulate a protocol QUIC does not have.

## Performance

31. **The workload colibri intends to win is many short connections with small requests and high
    connection churn**, not single-stream bulk throughput. Handshake cost and per-connection
    memory dominate there. colibri states where it expects to win, where it expects only to match,
    and where it expects to lose, and reports all three:

    - **Win, plausibly:** per-connection memory and per-connection allocation, and the teardown
      cost nobody optimises. A fixed connection struct from a preallocated slab, a small advertised
      field-table capacity, windows sized for small requests rather than bulk transfer, and
      reset-instead-of-construct on reuse. Also tail latency under churn, by having no garbage
      collector.

      Two QUIC-specific optimizations are worth naming and are **not** colibri's to claim as the
      seams stand: batching header protection across a datagram's packets into one pass, and
      precomputing the key schedule for the fixed Initial salt. Both live behind `crypto.Suite`
      (entry 9), so they belong to the caller. Reaching them means widening the vtable with a
      many-sample mask call and a precomputed extract handle, which is a decision nobody has
      taken.
    - **Match, at best:** the asymmetric crypto, which is a caller-supplied primitive and the same
      one every competitor calls; AEAD bulk throughput; HPACK on small field sections; and the
      syscalls, which are the caller's.
    - **Lose, probably:** bulk single-stream throughput, where msquic's GSO and GRO work is years
      deep; congestion control and ACK policy maturity, where getting ACK frequency wrong costs
      more than every allocator win combined; and the whole maturity surface — PMTUD, ECN
      validation, key update, stateless reset, QPACK dynamic tables under load.

    The honest opportunity is narrower and better than "we beat quiche". With an ECDSA certificate
    the asymmetric work in a TLS 1.3 handshake is tens of microseconds rather than hundreds, and a
    short connection stops being crypto-bound and becomes bound by syscalls, allocation and
    state-machine work — which is the part colibri controls. And there is no credible
    apples-to-apples handshakes-per-second or bytes-per-idle-connection comparison across QUIC
    implementations in public. Publishing a rigorous one is a contribution that does not currently
    exist, and it is a stronger position than a throughput claim colibri would lose.

32. **Real numbers come from Linux, and the machine is written down beside them.** io_uring,
    UDP_SEGMENT, UDP_GRO, `sendmmsg`, SO_REUSEPORT and ECN handling are Linux mechanisms, and a
    number measured on the development Mac predicts nothing about them. Cost: the bench does not
    run in the inner loop. Gain: colibri never publishes a number that is an artifact of the wrong
    kernel. macOS runs the simulator, the corpus and the unit tests, which need no kernel at all.

33. **The method is fixed before the first measurement, so the numbers cannot be shaped later.**
    Pinned cores and a fixed governor; warmup discarded; at least five runs reported as median with
    spread, never a best-of; the A/B against the competitor in the same session on the same kernel;
    and the machine, the kernel, the certificate type, the cipher suite and the socket buffer sizes
    published with the result. Instructions per connection is the primary metric because it is the
    most reproducible counter across machines and frequencies, with cycles, IPC, cache misses,
    context switches and syscall counts beside it.

    Best-of-N is rejected because it reports the favourable tail of the noise distribution rather
    than what a user sees. Anything under about 5% is treated as noise until shown otherwise: link
    order and environment size alone move results by percent-scale amounts, and core assignment can
    be worth far more. Loopback is not a network — its MTU and its absent driver path flatter
    everything — so a published number names the path it was measured over.

34. **The regression gate has two layers, because there is no CI here.** The cheap layer runs
    inside the deterministic simulator and cannot drift with the weather: counted allocations,
    syscalls, copies and bytes per request, committed as exact numbers that a diff has to change on
    purpose. That layer runs in `zig build test` on every change. The expensive layer is `bench/`
    with committed baselines and a threshold that fails, run by a person before a step is called
    done — stompy's full crash tier is the precedent. Static memory per connection is a comptime
    number and is measured the way chapulin's `bench/sram.sh` measures its SRAM rows, never
    estimated, and the README's table is generated from the measurement rather than written beside
    it.
