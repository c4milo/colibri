# Design decisions

Every entry here is a trade we made on purpose: what it costs, and what it buys. Changing one means
re-arguing the trade, not just editing the code. The README states what colibri does; this file
states why colibri does nothing more.

Entries marked **owner** are waiting on a ruling and are not settled. Everything else is settled
and is re-argued, not edited.

## Scope and shape

1. **One library for h2 and h3, not two in one repository.** Cost: a module graph that has to be
   defended, and a build that must prove the boundaries rather than assert them (§3 of
   docs/design.md). Gain: the code both protocols share — the Huffman coder, the prefixed
   integer codec, the RFC 9110 semantics core, the field validators, and every harness — is
   written once and tested once. Entries 11 to 16 say exactly what shares and what does not, each
   from the RFC text rather than from the shape of the two protocols.

   Two separate libraries was the alternative. It was rejected because the shared surface is not
   incidental: RFC 9204 §4.1.2 adopts the RFC 7541 Appendix B Huffman code "without modification",
   and RFC 9114 §4.2 delegates the connection-specific field rules to RFC 9110 §7.6.1 rather than
   restating them. Two libraries would copy both, and two copies of a 257-symbol code table diverge
   over time.

2. **No HTTP/1.1.** Cost: colibri cannot serve or speak to an h1 peer, and a consumer that needs
   one keeps whatever it already has. Gain: the whole of RFC 9112 stays out — the eight-step
   message-body-length precedence of §6.3, the chunked decoder of §7.1, `obs-fold` unfolding
   (§5.2), the whitespace-before-colon rejection of §5.1, the connection-persistence state
   machine of §9.3, and the request-smuggling surface that §11.2 exists to narrow. None of that
   machinery is reused by h2 or h3, where framing is the transport's job and `Content-Length`
   degrades to a consistency check (RFC 9113 §8.1.1, RFC 9114 §4.1.2). It is a second,
   structurally unrelated parser for one version.

   h2c *upgrade* is also out, and for a different reason: RFC 9113 §3.1 says the `h2c` token and the
   Upgrade mechanism "was never widely deployed and is deprecated". Prior-knowledge cleartext h2
   stays, and entry 8 explains why colibri depends on it rather than offering it as a convenience.

   Entry 88 amends this entry: colibri builds HTTP/1.1 as h11, client and server. The h2c upgrade
   stays out.

3. **QUIC is a module inside colibri, not its own library.** Ruled by the owner on 2026-09-16. A
   module, `src/quic/`, that imports `core`, `wire`, `crypto` and `tls` and nothing else, and that
   may never import `http`, `h2`, `h3`, `hpack` or `qpack`. Cost: colibri's repository carries the
   larger half of the work, and somebody who wants QUIC alone takes an HTTP library to get it.
   Gain: one CLAUDE.md, one simulator, one corpus format, one commit discipline, and no version skew
   between two repositories that change together for a year. The boundary that a separate
   repository would enforce socially is enforced here mechanically, by the module graph in
   `build.zig`, and the check that proves it is that the QUIC simulator runs with no HTTP module
   in the graph at all.

   Extraction stays cheap on purpose: moving `src/quic/` to its own repository is a build-file
   change plus a vendoring step, because no edge points out of it. Reopen trigger: a second consumer
   wants QUIC without HTTP, or one person can no longer maintain QUIC and HTTP together.

   Entry 102 amends this entry: `quic` also imports `qlog`, which imports stdx's `json` and
   `codec` alone (entry 102 as amended), so moving `src/quic/` out takes `src/qlog/` with it.

4. **Client and server, both, from the first step.** Cost: roughly a third more state machine —
   stream-id parity in both directions (RFC 9113 §5.1.1), the two connection prefaces (§3.4),
   and both halves of every settings exchange. Gain: the conformance suites are server-side
   (h2spec, h3spec) and the interop runner needs both roles (design §9), so a client-only library
   could not be tested against anything. The server also *is* the product for stompy's `ops-api`
   and `platform-api`; a client-only library would be half a deliverable.

5. **`quic` knows nothing about HTTP.** RFC 9000 defines a transport with streams and no opinion
   about payloads. Cost: h3 cannot use a QUIC internal as a shortcut, and anything h3 needs from a
   stream must be expressible in transport terms. Gain: the boundary is the same one the RFCs
   draw, so a rule is only ever in one place, and the QUIC simulator is a transport simulator
   that no HTTP change can perturb. Violation: a `if (stream_type == control)` inside `src/quic/`.

## What the caller supplies

6. **colibri owns no I/O.** No socket, no descriptor, no `poll`, no thread. The caller reads bytes
   and passes them to colibri; colibri writes bytes into storage the caller owns and tells it how
   many. Cost: the caller writes the event loop, and colibri cannot hide a syscall optimization from
   it. Gain: the same code runs under stompy's io_uring plane, under a test harness, and under the
   deterministic simulator, with nothing conditionally compiled. chapulin's caller-supplied I/O
   callbacks are the precedent, and colibri removes more than chapulin does: chapulin's callbacks
   block, and colibri has no callbacks at all.

   The rejected alternative is an I/O abstraction with a simulated implementation in-tree. It fails
   on the consumer side: stompy's rule is that every role's I/O extends `src/io/` so the simulator
   can substitute it, and an abstraction colibri defines would be a second one for the caller to
   adapt to.

7. **Time is a value the caller passes, never a clock read.** Every function that needs the current
   instant takes it as a parameter, typed as nanoseconds since an origin the caller chooses. Cost:
   the parameter appears on functions at every depth — RFC 9002's pseudocode reads `now()` at nine
   sites across five entry points, and the ninth is inside the congestion controller, so the instant
   must be passed to it too. Gain: loss recovery, idle timeouts and the PTO are testable and
   deterministic, and a failure found at one seed replays exactly. No source file imports a clock,
   and `tools/lint/determinism.zig` enforces that.

8. **The TLS provider is a caller-supplied vtable with no production implementation in this tree.**
   Two modes, because the two protocols need different things from TLS, and RFC 9001 §3 is
   explicit about why: QUIC "takes over the responsibilities of the TLS record layer".
   - *Record mode*, for h2: `handshake_read`/`handshake_write`, `encrypt_record`,
     `decrypt_record`, `negotiated_alpn`, `handshake_complete`, `take_alert`, `send_close_notify`,
     `initiate_key_update`. h2 needs no access to any traffic secret, so the provider keeps the
     whole
     key schedule private. RFC 9846 does not require that of a TLS API — its §7.1 only defines the
     key schedule — so it is colibri's choice and not a citation.
   - *QUIC mode*, for h3: `set_transport_params`/`peer_transport_params` (the
     `quic_transport_parameters` extension, codepoint 0x39, RFC 9001 §8.2), `provide_handshake`
     and `write_handshake` per encryption level carrying unframed handshake-message bytes (§4.1.3),
     `negotiated_alpn`, `handshake_complete`, and `take_alert` returning an `AlertDescription`
     value rather than a record (§4.8). This mode used to carry `on_secret(level, direction,
     secret, aead_id, kdf_hash)` (§4.1.4) and `hkdf_expand_label` as a primitive (§5.1) too.
     Entry 48 removed both: the secrets of §4.1.4 go from the provider to the suite inside the
     caller's code, and colibri never sees one.

   Both modes also carry `export_keying_material`, RFC 9846 §7.5's exporter, which is the one
   operation RFC 9846 gives a standard interface.

   Cost: every consumer supplies a stack, and colibri cannot ship a working client on its own.
   Gain: colibri never links a TLS stack, never holds a private key, never chooses a suite, and
   the deterministic simulator substitutes a null provider of its own. RFC 9846 specifies no API
   shape. It keeps the exporter's interface unchanged from RFC 5705 (§7.5), and it places a few
   MUSTs on what an implementation lets the application see or choose. The application must be
   able to tell whether the handshake has completed, and 0-RTT is enabled only when the
   application asks for it (both Appendix E.5, in its discussion of 0-RTT replay). The
   exporter_master_secret is used unless the application specifies otherwise (§7.5). No data is
   sent or received after an error alert (§6). Its API SHOULDs include a separate interface for
   the early exporter (§7.5) and a way to log alerts (§6.2). The rest of this interface is
   colibri's to specify, citing 8446 only for the semantics.

   The exporter is in the interface for both modes, and it has one limit: it derives only from
   `exporter_master_secret`, which exists after the server's Finished, whereas QUIC needs Initial,
   0-RTT, Handshake and 1-RTT secrets at four distinct points in time. That is why QUIC mode needs
   new provider API rather than exporter calls, and it is what "no record layer" costs. Since
   entry 48 that API is between the provider and the suite, and is the caller's to write.

   Entry 94 amends this on 2026-09-26: colibri links chapulin, so a user no longer supplies a
   provider. The vtable stays inside colibri, filled by chapulin and by the simulator's null
   provider, and the gain above, a library that links no TLS stack, is given up.

9. **Packet protection is a *second* caller-supplied vtable, so the TLS provider never has to carry
   AES.** Ruled by the owner on 2026-09-16, and amended on 2026-09-19 by entry 48, which keeps
   the second vtable and replaces its members. As first ruled, `crypto.Suite` supplied
   `aead_seal`, `aead_open`, `header_protection_mask(hp_key, sample) -> [5]u8`, `hkdf_extract` and
   `hkdf_expand_label`, and colibri derived every key and drove those five directly. Entry 48
   makes the members whole-packet operations and leaves every key with the suite. What follows is
   the reasoning of the first ruling. Its account of what RFC 9001 fixes to AES still holds, and
   is now what a suite must carry rather than what colibri must call.

   The header-protection member is a mask function and not a block cipher on purpose. RFC 9001
   §5.4.3 makes it AES in Electronic Codebook mode under a 128- or 256-bit key, and §5.4.4 makes
   it the **raw ChaCha20 function** over a 4-octet counter and a 12-octet nonce taken from the
   sample, encrypting five zero octets. Those are not the same primitive and neither is an AEAD
   call, so a vtable exposing one ECB block could not protect a ChaCha20 connection at all. The
   mask function is the smallest member that covers both.

   This is the answer to the AES problem. RFC 9001 requires AES
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

   Splitting packet protection away from the TLS provider works because once QUIC takes over the
   record layer (§3) the TLS stack does no bulk cipher work at all: the Initial keys, the AES header
   protection and the Retry tag are all computed by the QUIC layer from a fixed salt, a hardcoded
   key and the client's connection ID. A caller may therefore fill the TLS provider from a stack
   with no AES and the suite from a separate AES source. Cost: two vtables where a smaller library
   would have one, and a caller that must fill both. Rejected: one combined vtable, which would have
   made every h3 consumer's TLS stack an AES stack.

   The gain is narrower than it first looks, and entry 10 narrowed it again. h3 is not blocked on
   the TLS provider **carrying** AES, but colibri's own tree does not use that freedom: entry 10 has
   chapulin fill both vtables, so chapulin supplies the AES as well, and [the request](chapulin.md)
   reverses chapulin's decision 6 to get it. What the split still buys there is placement: the AES
   is implemented behind `crypto.Suite`, where chapulin can hold it as a host-side mode of its own
   rather than inside its TLS record layer. Nor is h3 independent of what the TLS stack
   **negotiates**: RFC 9001 §5.3 and §5.4.1 make packet protection and header protection follow the
   negotiated suite, so a TLS provider that offers only `TLS_CHACHA20_POLY1305_SHA256` obliges the
   suite to carry ChaCha20-Poly1305 and raw ChaCha20 as well as the three mandatory members,
   AES-128-GCM, AES-128-ECB and HKDF-SHA256. That is why the request asks chapulin's suite for all
   five.

   A caller that supplies a suite without AES-128-GCM, AES-128-ECB or HKDF-SHA256 is rejected at
   init, not at the first Initial packet. A suite that lacks the AEAD or header-protection algorithm
   TLS goes on to negotiate cannot be caught that early, because the suite is unknown until
   EncryptedExtensions is decrypted; that case returns the same configuration error class at the
   first Handshake packet, so the caller still sees a configuration error rather than a peer fault.
   Since entry 48 colibri cannot see what a suite carries, so the rule is now about the one call
   that shows it: a suite that refuses `install_initial_keys` is a configuration error
   ([invariant 25](invariants.md#inv-25--a-suite-that-cannot-protect-initial-packets-is-a-configuration-error)).

   Entry 94 amends this on 2026-09-26: colibri links chapulin, so a user no longer supplies this
   vtable. It stays inside colibri, filled by chapulin and by the simulator's null suite.

10. **chapulin provides all of colibri's crypto, through colibri's two vtables.** Ruled by the
    owner on 2026-09-16. chapulin fills both `tls.Provider` (entry 8) and `crypto.Suite` (entry
    9). colibri's library source never imports chapulin, so the packaged library still links no
    TLS stack and this tree still carries no production implementation of either vtable.
    `src/testing/` links chapulin. That answers the dependency question design §8 step 5 raised
    under CLAUDE.md's "Ask before": the checks from step 5 onward get their TLS 1.3 server, and
    its certificate signing, from chapulin.

    The request is [docs/chapulin.md](chapulin.md). The owner sends it, and this repository
    never edits chapulin's. It asks for a server role, ALPN, a non-blocking handshake with no
    global state, the exporter, a QUIC mode and host-side AES, and it names what each item
    reverses: chapulin's decisions 6, 8, 9, 20 and 28, and its server non-goal. chapulin's decision
    36, "a mode, not a change", is the shape it follows.

    Cost: every colibri check that needs TLS or real packet protection now waits on work in another
    repository, and that work reverses five of chapulin's recorded decisions. Gain: one crypto
    source for colibri's whole tree, argued under one charter, with no third-party stack in
    `src/testing/`. Two alternatives lost. The ask this entry used to make, ALPN and nothing else,
    left every check from step 5 onward with no TLS server at all. A different test-only TLS stack
    would have added a dependency whose charter nobody here argued, and its interop results would
    measure that stack rather than chapulin.

    If chapulin declines an item, colibri's source does not change. The vtables already have zero
    implementations in this tree, and steps 0 to 4, 6, 8 and 11 need no crypto at all: step 4
    ships prior-knowledge cleartext h2, so the whole h2 core is built and tested with no TLS. Only
    the checks that need the declined item wait, and naming a different provider for
    `src/testing/` would be a new "Ask before".

    Entry 94 amends this on 2026-09-26: the library itself now links chapulin, pinned as a
    package, and the adapters leave `src/testing/` for the library.

## What is shared between h2 and h3

Entries 11 to 16 are the shared-surface question answered from the RFC text. Three of them
correct a premise: a piece that looked shared and is not, or looked unshared and is.

11. **The Huffman coder and the prefixed-integer codec are shared, and both are RFC 7541's.**
    RFC 9204 §4.1.2 says the Huffman table of RFC 7541 Appendix B "is used without modification":
    257 symbols, codes of 5 to 30 bits, EOS = 0x3fffffff. One table in `.rodata`, one coder, no
    divergence. The coder also implements the three mandatory decode errors of RFC 7541 §5.2:
    padding strictly longer than 7 bits, padding that is not the high bits of EOS, and a complete
    EOS inside the data.

    The two padding rules reduce to run-of-ones arithmetic on the tail, because EOS is thirty set
    bits. **The third does not, and a decoder written as though it did rejects legal input.** A run
    of thirty ones can be produced by adjacent long codes with no EOS present: Appendix B's symbol
    204 is 27 bits ending in five ones and symbol 22 is 30 bits beginning with twenty-nine, so the
    two-octet string `0xCC 0x16` encodes to a run of thirty-four ones containing no EOS. EOS must
    therefore be detected at a symbol boundary inside the decode loop, never by scanning for a run.

    **Correction to a premise:** the prefixed integer codec is shared too. RFC 9204 §4.1.1 says "The
    format from [RFC7541] is used unmodified", so HPACK and QPACK read the same integers. The
    distinction is easy to miss: QUIC's variable-length integer (RFC 9000 §16) is a *different*
    primitive, used by the QUIC and h3 framing layers and never by a field-section representation.
    colibri therefore has two integer codecs, and the split is not h2-against-h3 — it is *field
    compression* against *framing*. `src/wire/` holds both codecs and its file header states the
    split.

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
    function would be a bug. colibri implements two tables and two resolvers.

    The representations do not share either. Every QPACK *field line* representation (RFC 9204 §4.5)
    has a different bit pattern and prefix width from its HPACK analogue, and two of them — indexed
    with post-base index, and literal with post-base name reference — have no HPACK analogue at all.
    The one exception is the table-size instruction: HPACK's Dynamic Table Size Update (RFC 7541
    §6.3) and QPACK's Set Dynamic Table Capacity (RFC 9204 §4.3.1) share the `001` pattern and the
    5-bit prefix, and they are still implemented in different modules because they arrive on
    different streams.

    The difference is not only in the encoding. RFC 9204 §2.2 names it: in HPACK the encoded field
    section carries the instructions that mutate the dynamic table, while in QPACK the field
    sections and the table-mutating instructions arrive on separate streams. That one difference
    is why QPACK needs Known Received Count, Required Insert Count, a Base, blocked-stream
    accounting and per-entry reference counts, and why HPACK needs none of them. HPACK also
    assumes a reliable, ordered byte stream and says nothing about out-of-order delivery — a
    structural assumption, not a syntactic one.

13. **Correction to a premise: flow control is not shared.** The premise was one mechanism carried
    by different frames. The two mechanisms are not the same. h2's flow
    control is a *credit* counter: 31-bit windows, an initial value of 65,535 (RFC 9113 §6.9.2),
    `WINDOW_UPDATE` adding credit, DATA payloads alone consuming it, and a send window that must be
    a *signed* quantity because a reduction in `SETTINGS_INITIAL_WINDOW_SIZE` can drive it negative
    and RFC 9113 §6.9.2 requires tracking that. QUIC's flow control is a *high-water mark*: 62-bit
    absolute offsets, `MAX_DATA` and `MAX_STREAM_DATA` naming the offset a peer may send up to
    rather than an increment, every byte of stream data counting rather than one frame type's
    payload, and a final-size rule with no h2 equivalent.

    They are different algorithms with a common purpose. Cost: two implementations. Gain: no
    accounting bug born of forcing a credit counter and an offset tracker through one interface. The
    RFC 9113 §6.9.2 retroactive sweep — every stream's window adjusted on a settings change — is the
    clearest evidence that the two cannot share one implementation; QUIC has no counterpart, because
    an offset limit needs no retroactive adjustment.

14. **The stream *table* is not shared; a bounded slot pool is.** The candidate was the table and
    its id and half-close rules. The rules differ between the protocols: h2 ids are 31-bit with
    client-odd and server-even parity and a closed set of seven states (RFC 9113 §5.1); QUIC ids are
    62-bit with the two low bits encoding initiator and directionality, and separate sending and
    receiving state machines (RFC 9000 §3.1, §3.2). h3 does not have a stream table at all — RFC
    9114 says stream concurrency is QUIC's, so h3 holds per-stream *frame decode* state and nothing
    else.

    What is shared is one data structure: a fixed slot pool with a per-parity watermark,
    where "closed" is the implicit default for anything below the watermark rather than a stored
    record. Both protocols need it for the same reason. In h2, ids cannot be reused and any stream
    leaving idle implicitly closes every lower-numbered idle stream the peer could have opened
    (RFC 9113 §5.1.1), so a map keyed by id can grow by 2^31 entries from one frame. In QUIC, a
    single out-of-order STREAM frame implicitly opens every lower-numbered stream of its type
    (RFC 9000 §3.2; §21.8 is the exhaustion hazard that rule creates). Same hazard, same structure,
    different rules on top. `core` holds the structure; `h2` and `quic` hold the rules.

15. **The semantics core is shared; the verdicts are not.** RFC 9110 §2.5 says core semantics do not
    change between versions, only their expression on the wire, and colibri draws the module
    boundary there. `src/http/` holds: method as an opaque case-sensitive token (§9.1); status as a
    `u16` in 100..599 with class from the first digit and an unrecognised code treated as the x00 of
    its class (§15); the `field-name = token` and `tchar` grammar (§5.1, §5.6.2) and
    case-insensitive comparison; the `field-value` grammar with `obs-text` at %x80-FF and the rule
    that CR, LF and NUL are invalid (§5.5); the order-preserving field-section model, because §5.3
    makes the order of same-name lines significant; the connection-option denylist of §7.6.1, which
    RFC 9114 §4.2 delegates to rather than restates; the "no content" table of §6.4.1, which both
    RFC 9113 §8.1.1 and RFC 9114 §4.1.2 carry; `Content-Length` as a semantic field (§8.6); trailer
    policy (§6.5.1); and `HTTP-date` (§5.6.7). On the "no content" table, RFC 9113 §8.1.1 points
    back to §6.4.1 by name and RFC 9114 §4.1.2 restates the rule without a cross-reference.

    What stays out, and why each would be a bug if it went in: **`obs-fold`**, which is RFC 9112
    §5.2 and appears nowhere in 9110 — any unfolding code in a shared core is h1 code that does not
    belong there. **The lowercase-on-the-wire rule**, which 9110 does not state; it is RFC 9113 §8.2
    with its receive-side check in §8.2.1, and RFC 9114 §4.2, worded differently and producing
    different errors. **The malformed verdict**: same predicate, different enum — h2 gives a stream
    error of `PROTOCOL_ERROR` (RFC 9113 §8.1.1), h3 gives `H3_MESSAGE_ERROR` (RFC 9114 §4.1.2) — so
    the core returns a *reason*, never a code. **Pseudo-headers**, which are RFC 9113 §8.3 and RFC
    9114 §4.3, not 9110, and which differ: h2 says a recipient MUST NOT use `Host` when `:authority`
    is present, h3 says if both are present they must be equal. Do not write one shared authority
    resolver. **Message-body length determination**, which is h1's. **Field-section size
    accounting**, whose name+value+32 formula is in RFC 9113 §6.5.2 and RFC 9114 §4.2.2 under
    different setting names at the same identifier 0x06 — share the arithmetic, not the setting.

    **TE is read as its grammar defines it.** Ruled by the owner on 2026-09-16. RFC 9113 §8.2.2 and
    RFC 9114 §4.2 permit TE only in a request, and only when its value is "trailers". RFC 9110
    §10.1.4 makes TE a list, and RFC 9110 §5.6.1.2 requires a recipient to accept empty members and
    whitespace around the commas. "trailers" is an ABNF quoted string, which matches in any case
    (RFC 5234 §2.3). So the core accepts "Trailers", "trailers," and "trailers, TRAILERS", and
    nothing with another member. The rejected alternative was comparing the exact octets. It refuses
    values the grammar admits, and a refusal there reports the peer's request as malformed when the
    fault is colibri's.

    **h3 refuses a field value with leading or trailing whitespace, as h2 does, with one
    exception.** Ruled by the owner on 2026-09-16. RFC 9113 §8.2.1 makes such a value malformed in
    h2. RFC 9114 has no such rule: its §4.1.2 and §10.3 refuse invalid characters, and SP and HTAB
    are valid inside a value. The ruling takes h2's rule for h3 because no conformant sender
    generates such a value: RFC 9110 §5.5's field-value grammar has no whitespace at either end,
    and RFC 9110 §2.2 forbids a sender to generate an element outside its grammar. Nor does
    RFC 9110 §5.5's instruction to exclude that whitespace apply. It binds a version that lets
    whitespace appear around a value, which is HTTP/1.1 (RFC 9112 §5), and h3 carries a value as a
    length-delimited string.

    The exception is RFC 9110 §5.6.1.2, which requires a recipient to accept a list whose first or
    last member is empty, as in `, gzip` after leading OWS or `gzip, ` with trailing OWS. Senders
    that merge values produce those. h2 still refuses them, because RFC 9113 §8.2.1 is the more
    specific rule. h3 trims exactly that whitespace with `field.trim_empty_member_whitespace` and
    refuses any that remains. Two alternatives lost. Refusing every such value in h3 would break
    §5.6.1.2's MUST. Trimming all edge whitespace in h3 would give the two protocols different
    verdicts for octets no conformant sender produces. What remains is refused with
    `H3_MESSAGE_ERROR`, the code RFC 9114 §8.1 defines for a malformed message, applied here by
    colibri's classification rather than an RFC 9114 rule. A conformant intermediary that forwards
    such a value unchanged is refused too, though only the value's first sender broke the grammar.

16. **No caching, and the conformance bar for RFC 9111 is zero.** RFC 9111 §2 says caching is "an
    entirely OPTIONAL feature of HTTP", every normative requirement in its §3 and §4 is scoped to
    the subject "a cache", and the single requirement binding a non-cache — §5.2, pass cache
    directives through in forwarded messages — binds *proxies*. colibri is neither. Cost: a
    consumer that wants a cache writes one. Gain: no revalidation, no freshness arithmetic, no
    `Vary` matching, no stored-response state that would have to survive a connection.

    The practical obligation, which is not a conformance requirement: pass `Cache-Control`, `Age`,
    `Expires`, `Vary`, `Date`, `ETag` and `Last-Modified` to the caller byte-exact, so a
    caller-built cache can itself be conformant. `Pragma` is deprecated (§5.4) and `Warning` is
    obsolete (§5.5); colibri implements neither.

## What colibri does not build

Each of the seven is a no with a reason, and each records what saying no still costs on the wire,
because a refused feature still imposes obligations on the wire.

17. **Server push: no.** It is optional in both protocols. Cost of refusing, h2: a client must send
    `SETTINGS_ENABLE_PUSH` (0x02) with value 0, because its initial value is 1 (RFC 9113 §6.5.2) and
    an endpoint that sends no such setting permits push; and until the peer's SETTINGS ACK arrives a
    `PUSH_PROMISE` may legally arrive, which cannot simply be dropped — it reserves a stream, its
    field block must still be HPACK-decoded or the dynamic table desynchronises (§4.3), and the
    correct answer is decode, reserve, `RST_STREAM` with `CANCEL` or `REFUSED_STREAM` (§8.4.2).
    After the ACK, a `PUSH_PROMISE` is a connection error of `PROTOCOL_ERROR`. A colibri *server*
    has less to do: RFC 9113 §6.5.2 says a server MUST NOT set the value to 1, so omitting the
    setting is already a refusal. Cost of refusing, h3: never send `MAX_PUSH_ID`, whose value is
    unset at connection creation (RFC 9114 §7.2.7), and answer a push stream or an oversized push id
    with `H3_ID_ERROR` (§4.6). One check.

    **State the reason correctly.** RFC 9113 does not deprecate server push. §8.4 says it is
    "difficult to use effectively"; Appendix B deprecates the RFC 7540 priority scheme and the
    h2c Upgrade mechanism, not push. colibri's reason is "optional and unused", and writing
    "deprecated" would be a citation nobody can check.

18. **Priorities: no to scheduling, yes to the mandatory parsing.** RFC 9113 §5.3.2 deprecates RFC
    7540's priority signalling but deliberately keeps the frame syntax and some of its mandatory
    handling for interoperability, so colibri still owes all of: accept `PRIORITY` (0x02) in every
    stream state including idle and closed; a stream error of `FRAME_SIZE_ERROR` when its length is
    not exactly 5 octets; a connection error of `PROTOCOL_ERROR` when its stream identifier is 0x00;
    and skipping exactly 5 octets when `HEADERS` carries the PRIORITY flag 0x20, or the HPACK block
    starts at the wrong offset. Skipping the wrong number of octets is the bug this entry exists to
    prevent.

    RFC 9218 is optional: §1 says servers "can ignore client priority signals and still successfully
    serve HTTP responses", and §10 says expressing priority is only a suggestion. colibri ignores it
    and applies the unknown-extension rules — discard `PRIORITY_UPDATE` as an unknown frame type,
    and ignore the `SETTINGS_NO_RFC7540_PRIORITIES` identifier if a peer sends it. RFC 9218 §2.1
    offers one cheap position, sending `SETTINGS_NO_RFC7540_PRIORITIES` with value 1 in the first
    SETTINGS frame, immutable thereafter, to declare that 7540 signals are ignored; §2.1 permits
    that without adopting 9218's scheme, and colibri does not send it today — its preface carries
    the six settings of RFC 9113 §6.5.2 alone. §2.1 permits that without adopting 9218's scheme.

19. **Extended CONNECT: no.** `SETTINGS_ENABLE_CONNECT_PROTOCOL` is identifier 0x08 with initial
    value 0 (RFC 8441 §9.1), and a client may use extended CONNECT only on receipt of value 1 (§3).
    Refusing is pure omission. What a non-supporting endpoint must still do is specified, and
    colibri needs no extra code for it: an unexpected `:protocol` is an undefined pseudo-header,
    which RFC 9113 §8.3 makes the request malformed, which is a *stream* error and not a connection
    error. The only way to get this wrong is to close the connection, so this entry is about the
    pseudo-header validator's error class.

    For h3, the RFCs colibri read say this: RFC 9114 defines base CONNECT only (§4.4), says
    pseudo-header restrictions can be relaxed only by an extension (§4.3), and does not itself
    define extended CONNECT. The document that does is outside the set colibri read, so this entry
    cites no section for it and colibri's h3 side treats `:protocol` as undefined.

20. **0-RTT: no, in both protocols.** Refusal is the specified default and is expressed by
    omission: a server omits the `early_data` extension from its NewSessionTicket (RFC 9001
    §4.6.1) and, mid-handshake, omits it from EncryptedExtensions (§4.6.2). Two structural
    reasons make this more than a scope cut. RFC 9001 §5.6 says a client MUST NOT use 0-RTT for
    application data unless the application specifically requests it and the application protocol
    supplies a 0-RTT profile — colibri owns no application semantics and cannot supply one. And
    RFC 9000 §7.4.1 requires a 0-RTT client to remember every server transport parameter it can
    process, apart from seven it must never reuse, and forbids a server accepting 0-RTT from
    lowering seven named limits; that is persistent cross-connection state, which conflicts
    directly with fixed storage the caller owns per connection (entry 35).

    Saying no also deletes the stream-state rollback a client must perform when a server rejects
    0-RTT (RFC 9001 §4.6.2), which is a path colibri would otherwise have to implement and test.

21. **Connection migration: no to initiating it and no to accepting it — and this is the smallest
    saving of the seven.** The mechanism is the `disable_active_migration` transport parameter,
    identifier 0x0c with a zero-length value (RFC 9000 §18.2). It refuses exactly one thing: the
    peer using a *new local address* when sending to the address colibri used during the handshake.
    Three consequences that are routinely got wrong, recorded because the saving is smaller than the
    name suggests:

    - **Refusing is not an error you may signal.** If a peer migrates anyway, RFC 9000 §9 permits
      exactly two responses: drop the packets silently without a Stateless Reset, or validate the
      path and allow it. Closing the connection is forbidden, because it would let a third party
      close connections by spoofing traffic. There is no `MIGRATION_REFUSED` code in §20.1.
      colibri's refusal path is a silent drop plus a counter.
    - **It does not exempt colibri from path validation.** RFC 9000 §9 says not all changes of peer
      address are intentional migrations, and then requires path validation on *any* detected change
      to a peer's address unless already validated. NAT rebinding is not active migration and is not
      refusable. So colibri still implements the whole of §8.2 and the migration rules that depend
      on it: `PATH_CHALLENGE` and `PATH_RESPONSE` with the 8-octet echo (§19.17, §19.18), the
      one-response-per-challenge rule and the 1200-octet datagram expansion (§8.2.2), the
      anti-amplification limit (§8), the revert-to-last-validated-address rule on failure with a
      silent close when no such address is held (§9.3.2), the challenge to the previously active
      path on an apparent migration (§9.3.3), and the congestion and RTT reset on confirming a new
      address with the port-only exemption it may take (§9.4).
    - **A connection-ID pool is still required.** `active_connection_id_limit` must be at least 2
      and defaults to 2 (RFC 9000 §18.2), so `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID` are
      implemented by an endpoint that never moves.

    One consistency rule: colibri does not send `preferred_address` if it sends
    `disable_active_migration`, because RFC 9000 §9 exempts migration following a preferred
    address, so sending both permits the migration `disable_active_migration` refuses.

22. **HTTP datagrams: no, at the QUIC layer.** `max_datagram_frame_size` is transport parameter 0x20
    with default 0, and 0 means the endpoint does not support DATAGRAM frames (RFC 9221 §3). Omit it
    and a conformant peer will not send one. The only wire obligation is the error case, and it is
    easy to get wrong: receiving a DATAGRAM frame without having advertised support must terminate
    the connection with `PROTOCOL_VIOLATION` (§3), and colibri must recognise **both** codepoints,
    0x30 and 0x31, because the low bit is the LEN flag (§4). A dispatcher that knows only 0x30 lets
    0x31 fall through as an unknown frame type and produces the wrong error.

    There is also a design-fit reason. RFC 9221 §5.3 says DATAGRAM frames carry no explicit flow
    control signalling and do not contribute to any per-flow or connection-wide data limit. They
    are the one data carrier in QUIC with no backpressure, so colibri would have to own a drop
    policy, which is an application decision and not colibri's.

    Scope note: this covers the QUIC extension only. The HTTP-layer datagram binding is a separate
    document colibri has not read, and this entry makes no claim about it.

23. **Multipath: no, and there is nothing to decline.** RFC 9000 is single-path by construction —
    §9.3 chooses the active path by the highest-numbered non-probing packet, one integer of state.
    Multipath is an extension defined outside the set colibri read, and RFC 9000 §7.4.2 says the
    absence of a transport parameter disables any optional feature negotiated by it, so the
    conformance cost of saying no is zero. The one related obligation is to ignore reserved
    transport-parameter identifiers of the form 31*N+27 (§18.1), which exist to exercise
    that ignore path — and colibri tests it rather than assuming it.

## Correctness

24. **Reading the RFC is not evidence.** Every step in the build plan names which of the five
    checks proves it, and a step with no check is not a step. The five are the golden corpus,
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

26. **The golden corpus is exact bytes with a manifest**, in the layout stompy's `src/golden/`
    uses: one directory per format, one file per case, and a manifest line per file naming its
    length, its checksum, its expected verdict and the parameters it was built from. Valid and
    invalid cases both, because a parser that accepts everything passes a valid-only corpus.
    `zig build golden` regenerates and refuses a directory carrying a `FROZEN` marker.

27. **Conformance suites are checks, and their versions are pinned.** h2spec for the h2 server,
    h3spec for the h3 server. Both need a test-only server entry point, which design §9 names, and
    their maturity is not equal: h2spec has 147 cases but is written against RFC 7540 and 7541
    rather than 9113, with its last release in 2020 — so its version is pinned and a disagreement is
    checked against RFC 9113 before it is treated as colibri's bug. h3spec is narrower, roughly 50
    cases and error cases only, with no happy path and no flow control, but it is the better
    maintained of the two. Neither is sufficient alone, so entry 28 adds interop testing.

28. **Interop against real stacks, both directions, is the bar for h3.** The QUIC Interop Runner's
    matrix is the standard, and joining it is a design constraint rather than a later chore: an
    endpoint implements a Docker contract reading `ROLE`, `TESTCASE` and `REQUESTS`, serving `/www`
    on port 443, writing to `/downloads`, emitting a keylog and qlog — and **exiting 127 for any
    test case it does not support**, which is what lets colibri join with handshake, transfer and
    http3 alone and add the rest later without recording failures. Most transfers run HTTP/0.9 over
    ALPN `hq-interop`, so that ALPN is a test-only entry point too. For h2 the equivalent is
    nghttp2, curl, Go's `net/http2` and h2o, in both directions.

29. **Fuzz every parser, and every check is seeded.** A parser is anything that reads peer bytes:
    the frame readers, the packet reader, HPACK, QPACK, the varint and prefixed-integer decoders,
    the field validators, the transport-parameter reader. Every property function lives in the file
    it tests, with the shared harness in `src/core/fuzz.zig`.

30. **The deterministic simulator is the check that the others cannot be.** Seeded connection
    state, flow control, loss, reordering and recovery, with byte-identical replay across hosts
    and build modes as the pass condition. It is built before the protocol it drives (CLAUDE.md
    non-negotiable 7), which is possible only because entries 6, 7 and 8 made I/O, time and crypto
    the caller's.

    The null crypto suite buys less than it appears to. It is
    **not** what makes a seed replay: AES-GCM and ChaCha20-Poly1305 are pure functions of key,
    nonce and plaintext, so a real suite replays just as deterministically. What it buys is that
    the simulator needs no crypto dependency and costs no cipher time. It must therefore be
    **size-faithful, not an identity function** — it appends a 16-octet tag and returns a 5-octet
    mask exactly as a real suite would — because RFC 9001 §5.3's expansion feeds §5.4.2's sample
    offset, the Length varint, RFC 9000 §14.1's 1200-octet minimum and the anti-amplification
    count. A null suite that shortened packets would produce packet sizes QUIC never produces.

## Performance

31. **The workload colibri intends to win is many short connections with small requests and high
    connection churn**, not single-stream bulk throughput. Handshake cost and per-connection
    memory dominate there. colibri states where it expects to win, where it expects only to match,
    and where it expects to lose, and reports all three:

    - **Win, plausibly:** per-connection memory, no allocation at all, and the teardown cost
      nobody optimises. A fixed connection struct whose size is a comptime constant and whose
      storage the caller owns (entry 35), a small advertised field-table capacity, windows sized
      for small requests rather than bulk transfer, and reset-instead-of-construct on reuse. Also
      tail latency under churn, by having no garbage collector.

      Two QUIC-specific optimizations are worth naming and are **not** colibri's to claim as the
      vtables stand: batching header protection across a datagram's packets into one pass, and
      precomputing the key schedule for the fixed Initial salt. Both are implemented behind
      `crypto.Suite` (entries 9 and 48), so they belong to the caller. The second needs nothing
      from colibri. The first means a `seal` that takes every packet of a datagram at once, which
      is a decision nobody has taken.
    - **Match, at best:** the asymmetric crypto, which is a caller-supplied primitive and the same
      one every competitor calls; AEAD bulk throughput; HPACK on small field sections; and the
      syscalls, which are the caller's.
    - **Lose, probably:** bulk single-stream throughput, where msquic's GSO and GRO work is years
      deep; congestion control and ACK policy maturity, where getting ACK frequency wrong costs
      more than every memory win combined; and the whole maturity surface — PMTUD, ECN
      validation, key update, stateless reset, QPACK dynamic tables under load.

    The opportunity is narrower than "we beat quiche" and worth more. With an ECDSA certificate the
    asymmetric work in a TLS 1.3 handshake is tens of microseconds rather than hundreds, and a short
    connection stops being crypto-bound and becomes bound by syscalls, allocation and state-machine
    work — which is the part colibri controls. And there is no credible apples-to-apples
    handshakes-per-second or bytes-per-idle-connection comparison across QUIC implementations in
    public. Publishing a rigorous one is a contribution nobody has made, and it is a stronger
    position than a throughput claim colibri would lose.

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
    be worth far more. Loopback is not a network — its MTU and its absent driver path make every
    result look better than it would on a real link — so a published number names the path it was
    measured over.

34. **The regression check has two layers.** It was ruled when there was no CI here; entry 47
    adds one and keeps both layers. The cheap layer runs
    inside the deterministic simulator and does not vary between runs: counted syscalls, copies
    and bytes per request, committed as exact numbers that a diff has to change on purpose.
    Allocations are not counted, because entry 35 makes that number zero by construction. That
    layer runs in `zig build test` on every change. The expensive layer is `bench/` with committed
    baselines and a threshold that fails, run by a person before a step is called done — stompy's
    full crash tier is the precedent. Static memory per connection is a comptime
    number and is measured the way chapulin's `bench/sram.sh` measures its SRAM rows, never
    estimated, and the README's table is generated from the measurement rather than written beside
    it.

## Memory

Entry 35 was ruled after entries 1 to 34 were numbered, so it takes the next number.

35. **colibri is zero heap.** Ruled by the owner on 2026-09-16. There is no `Allocator` anywhere in
    `src/`: no parameter, no field, no `std.heap`, and no test that allocates. The caller owns
    every connection struct and every buffer, and places each one where it chooses: static
    storage, its own arena, or memory it mapped. colibri exposes their sizes as comptime
    constants, so `@sizeOf` and the named limits of design §7 account for all of colibri's memory.
    chapulin's decision 18 is the precedent.

    The rejected alternative is the rule this repository started with: allocate at init, through
    one constructor per connection type that takes an `Allocator`, and never after. Three things
    beat it. An allocating constructor puts `error.OutOfMemory` into colibri's API, and a failure
    path into every caller that no protocol requires. The lint could enforce that rule only by
    function name, so any function named `init` could take an allocator. And a connection pool
    that colibri allocated would have made colibri decide how many connections a process holds and
    where their memory lives, which is the caller's decision.

    Cost: the caller places every struct and cannot ask colibri to grow one, so a peer that exceeds
    a limit colibri sized for is refused, never accommodated. Gain: nothing to allocate, fail or
    leak; no signature that obtains memory; and an embedding runtime that places memory as it
    chooses, such as on huge pages or in buffers registered with the kernel, without colibri
    knowing. `tools/lint/heap.zig` enforces the rule with no exception by name, and invariant 1
    asserts it at runtime.

## Tooling

Entry 36 was ruled after entries 1 to 35 were numbered, so it takes the next number.

36. **colibri's developer tooling comes from pepegrillo, a Zig package pinned by hash.** Ruled by
    the owner on 2026-09-16. The lint driver and its generic rules, the cognitive-complexity
    scorer, the commit-message linter and the pre-push hook are in
    [github.com/c4milo/pepegrillo](https://github.com/c4milo/pepegrillo). `build.zig.zon` names it
    by URL and hash as a lazy dependency, and `build.zig` requests it only when colibri is the root
    build, so a project that depends on colibri never fetches it. `tools/` keeps what is colibri's
    alone: the configuration of each rule and the fixtures that pin it, the `module-graph` rule,
    and the graph check. `.githooks/pre-push` is a copy of pepegrillo's hook, and `zig build test`
    compares the two byte for byte. The library never imports pepegrillo.

    Design §8 step 0 copied the tooling from another repository, and within a day the two copies
    had drifted in naming, output format and logic. Four alternatives lost. Keeping the copies
    meant fixing every defect twice. A vendored copy needs no network, but keeps a copy per
    repository and a sync step per change. A git submodule needs `git submodule update --init` in
    every clone and every worktree. A `.path` dependency resolves from the build root, so inside
    `.claude/worktrees/` it points at the wrong directory.

    Cost: the first build on a machine, and the first after a bump, needs the network to fetch
    pepegrillo (`zig build --fetch` does it ahead), and Zig extracts it into `zig-pkg/`. A rule
    change is a pepegrillo commit before it is a colibri one, and a bump must also copy the hook.
    Gain: one copy of the tooling; the hash as the guard against an edited copy; and
    `zig build --fork=<path>`, which builds this tree against an unpushed pepegrillo checkout.

## The simulator

37. **The checks and the `zig build sim` command line are a module of their own, `sim_run`, rooted
    at `src/sim/run.zig`.** Ruled by the owner on 2026-09-16. A check drives a protocol module
    through the harness, so some module must import both `sim` and the module under test, and that
    is a new edge in the §3 graph. `sim_run` takes it: `core`, `wire` and `sim` at step 2, and each
    protocol module as its check lands. `sim` never imports `sim_run`, so the direction stays
    acyclic, and `sim` still imports no protocol module. colibri follows the layout of stompy's
    `sim_run`.

    Two alternatives lost. A `testing` module under `src/testing/` needs no lint exemption, since
    that directory is already the one permitted to touch a socket, but it departs from stompy's
    layout for no gain, and design §9's entry points are servers, not checks. `sim` importing
    `wire` directly puts a codec in the harness, which §3 forbids, and still leaves the command
    line with no home. Cost: `src/sim/run_main.zig` reads arguments and writes to the terminal, so
    `tools/lint/io.zig` exempts that one file by path.

38. **Published vectors are vendored as the files their authors published, and a tool reads
    them.** Ruled by the owner on 2026-09-16 for `http2jp/hpack-test-case`, 478 JSON stories of
    66 MB, about 3 MB packed, at `src/hpack/hpack-test-case/` with its commit and license in
    `COLIBRI.md`. The library is zero heap (decision 35) and `std.json` allocates, so the module's
    own tests cannot read the corpus; `tools/hpack_vectors.zig` reads it, drives the module, and
    `zig build test` runs the tool. The check stays in-process, as design §9 says the HPACK vectors
    are, and nothing is generated from the corpus.

    Two alternatives lost. A fetch-on-demand script keeps the repository small but takes the check
    out of `zig build test`, leaving it to be run by hand like h2spec. A converted binary form
    adds a colibri format to version, a regenerate-and-check pair, and a copy of the corpus that
    is not what its authors published. Cost: a clone carries the corpus.

## The h2 connection

39. **The connection consumes one frame per call and returns what it produced.** Design §4.1 has the
    caller hand colibri the octets it read and learn how many were consumed. `receive` takes a slice
    and an instant, consumes at most one whole frame, and returns the count consumed and at most one
    event: a field section, a data payload, a stream reset, a GOAWAY, an acknowledged PING or
    SETTINGS. A count of 0 means the slice holds no whole frame yet, or the queued replies must be
    written before more frames are read; `has_pending` tells the two apart. Frames colibri owes in
    reply, a SETTINGS or PING acknowledgment, a WINDOW_UPDATE, a RST_STREAM, a GOAWAY, are queued in
    fixed slots and written by `write_pending` into the caller's buffer when the caller asks.

    Two alternatives lost. Consuming every whole frame in the slice needs somewhere to hold every
    event that produces, and a bounded event queue either drops events or refuses input, both of
    which hide a peer's frame from the caller. Callbacks the caller registers give colibri a call
    it makes at a time of its choosing, which design §4 forbids. Cost: a caller loops over
    `receive` until it returns 0, one frame per iteration. Gain: an event's slices point into the
    caller's own input or into one slot the connection owns, valid until the next call, and no
    frame is ever processed before the caller has seen the last one's event.

40. **A field block is decoded fragment by fragment, and the connection holds one partial
    representation, never a whole block.** RFC 9113 §4.3 delivers a field block as a HEADERS or
    PUSH_PROMISE frame and any number of CONTINUATION frames, contiguous on the connection. Each
    fragment is fed to the HPACK decoder as it arrives, which reads every representation the
    fragment completes and leaves the cursor at the first it does not (hpack's block reader is
    all-or-nothing per representation for this reason). The connection keeps that tail, at most one
    representation long, and prepends it to the next fragment. The decoded lines go into one field
    section slot on the connection, and on END_HEADERS the connection returns the section to the
    caller.

    The alternative lost is reassembling the whole block before decoding, which needs storage of
    `continuation_count_max` times `frame_size_max` octets per connection, 512 KiB at the limits,
    for a block that decodes to at most `field_section_size_max`. Cost: a representation that
    spans two fragments is read twice, once to find it cut and once whole. Gain: the slot is one
    representation plus one frame, invariant 14's byte count is a counter rather than a buffer,
    and a peer that never sends END_HEADERS holds no more memory than one that does; the count of
    CONTINUATION frames is still bounded by `continuation_count_max` (§10.5's limits).

41. **h2spec's two self-dependency cases are skipped, because RFC 9113 is the authority.** Ruled by
    the owner on 2026-09-18. h2spec 2.6.0 runs `http2/5.3.1/1` and `/2`, which send a HEADERS frame
    and a PRIORITY frame whose stream depends on itself and require a stream error of
    PROTOCOL_ERROR. That rule is RFC 7540 §5.3.1. RFC 9113 obsoletes RFC 7540, §5.3.2 drops the
    priority scheme and says its text is not included, and §6.3 keeps two rules about PRIORITY,
    both of which colibri enforces: a stream identifier of 0x00 is a connection error of
    PROTOCOL_ERROR, and a PRIORITY frame may not come between the frames of a field block.

    colibri parses the priority fields and acts on none of them (entry 18), so a stream that
    depends on itself is a signal it ignores rather than an error it reports. The alternative lost
    is adding the check for the suite's sake, which would put a rule in the code that the RFC
    colibri implements does not state, cited to a document CLAUDE.md forbids reading. The cost is
    that h2spec never prints 146 of 146; `tools/h2spec.sh` names the two cases and fails if any
    other case fails.

42. **A client accepts any number of interim responses, with no limit of colibri's own.** Ruled by
    the owner on 2026-09-18. RFC 9113 §8.1 lets a server send any number of interim responses
    before the final one, and colibri holds none of them: each 1xx field section is decoded into
    the one field-block slot, returned to the caller as an event, and the slot is reused. Nothing
    accumulates per interim response, so there is no storage to exhaust.

    The alternative lost is an `interim_responses_max` with a stream error past it. It was weighed
    because non-negotiable 4 bounds every loop and queue, but this is neither: the sections arrive
    across separate `receive` calls the caller drives, and the caller sees every one and may close
    the connection. The §10.5 rate limit colibri does hold, `rst_stream_rate_max`, bounds the
    RST_STREAM frames colibri sends and does not cover this. The ruling is "for now": a limit
    remains available if a peer is ever seen to abuse it.

43. **The record-mode vtable carries `negotiated_parameters`, an eleventh member.** Ruled by the
    owner on 2026-09-18, amending entry 8. The member returns the version and cipher suite
    codepoints the handshake selected, or null before it has them. RFC 9113 §9.2 puts a MUST on
    implementations of HTTP/2 to use TLS 1.2 or higher, and colibri is the implementation that
    sentence addresses; §9.2.2 lets an endpoint answer a suite Appendix A prohibits with
    INADEQUATE_SECURITY, and it puts a MUST NOT on generating that error for any suite that is not
    prohibited, which needs the exact codepoint rather than a summary. Entry 8's ten members supply
    neither number.

    The alternative lost is enforcing none of §9.2 and recording that compliance is the
    deployment's, which §9.2's own closing sentence would support. It was rejected because the
    version floor is a MUST addressed to implementations. Reading two codepoints is not a crypto
    operation: colibri chooses no suite and holds no key, so non-negotiable 2 is untouched.

    §9.2.1 and §9.2.2 are TLS 1.2 rules alone. §9.2 says so: deployments that negotiate TLS 1.3
    are subject to §9.2.3 instead. A check reads the version first and skips the whole set on
    1.3, where §9.2.3's one rule is that a post-handshake CertificateRequest is a connection error
    of PROTOCOL_ERROR, which `decrypt_record`'s `Content` already carries.

44. **The provider is an optional field on `h2.Connection`.** Ruled by the owner on 2026-09-18.
    A connection with no provider is the cleartext prior-knowledge endpoint step 4 built and
    h2spec checks, so `init` keeps working unchanged and the simulator's cleartext check keeps the
    census it committed. A connection with one runs h2 over TLS.

    The alternative lost is a second h2 type above `Connection` holding the provider and the record
    buffers. It would keep `Connection` free of TLS, at the cost of a second entry point for every
    caller and for both endpoints of design §9. The documents settled that h2 calls the vtable
    (entry 8, design §3 and §4) and left the type open; this entry closes it.

    One consequence is recorded here so it is not rediscovered: an ALPN mismatch cannot go through
    `Connection.fail`. That queues a GOAWAY, and RFC 9113 §3.2 sends the connection preface only
    after TLS completes, so there is no HTTP/2 connection to send one on. RFC 7301 §3.2 makes it
    the provider's fatal `no_application_protocol` alert, value 120.

45. **colibri admits TLS 1.3 alone, and three cipher suites.** Ruled by the owner on 2026-09-18.
    The negotiated version must be 0x0304, and the suite must be one of TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256 (RFC 9846 Appendix B.4). These are the
    three RFC 9846 §9.1 names: a compliant application MUST implement the first and SHOULD
    implement the other two. They are also the three RFC 9001 §5.3 permits for QUIC, which excludes
    TLS_AES_128_CCM_8_SHA256 by name for its 64-bit tag, so h2 and h3 admit the same set.

    RFC 9113 §9.2 makes TLS 1.2 the floor. Admitting 1.3 alone is stricter than the floor and so
    inside it; a peer that offers less is refused before any HTTP/2 octet moves, and §7's
    INADEQUATE_SECURITY names the class.

    The alternative lost is honouring §9.2 as written: admit TLS 1.2 and refuse the suites
    RFC 9113 Appendix A prohibits. It fails on a practical point that is worth recording, because
    it is not obvious. Appendix A lists 276 suites **by name with no codepoint**, and the wire
    carries a codepoint. Mapping one to the other needs the IANA TLS Cipher Suite registry, which
    is not an RFC and is not in `docs/rfcs/`, so the check could not be written from the documents
    non-negotiable 10 permits. An allowlist needs no registry: Appendix B.4 carries the five
    TLS 1.3 codepoints in the RFC itself. The narrower rule is both safer and the only one this
    repository can source.

46. **Every endpoint in `src/testing/` does its I/O without blocking.** Ruled by the owner on
    2026-09-19: the checks must show that colibri works under non-blocking I/O and uses the
    processor well, because that is how a consumer will run it. A test-only endpoint holds its
    connections in a fixed array, waits on all of them in one `poll` call, and makes no other call
    that waits. The h2 server did this already; the h2 client of design §9 does it from its first
    commit, its `connect` included.

    The ruling decides what the client can link today. chapulin's TLS client reads its socket
    through a callback that must return octets or fail: `io.c` turns any result of 0 or less into
    `CH_EIO` and the session is dead, so there is no way to say "nothing yet". Under a loop that
    never blocks it cannot run. The client therefore speaks cleartext h2 with prior knowledge
    (RFC 9113 §3.3), which carries the same h2 octets, and TLS joins through `tls.Provider` when
    chapulin offers a record mode that takes octets in and returns octets, the third h2 item of
    [docs/chapulin.md](chapulin.md). chapulin's server role is headers and fail-closed stubs
    today, and its design names the same blocking callbacks, so the request applies to it before
    it is written.

    Two alternatives lost. A blocking client around `ch_connect`, `ch_read` and `ch_write` works
    today and would show ALPN and TLS 1.3 against real servers, but it needs a thread for each
    connection, it is not the shape a consumer would use, and it never crosses `tls.Provider`, so
    it proves nothing about `connection_tls.zig`. A private stack for each connection, on which
    the callback yields instead of blocking, keeps one thread; `std.Io`'s evented implementations
    are the ready-made form, and they take an allocator for those stacks, which non-negotiable 4
    forbids in `src/`.

    Cost: the TLS half of step 5's interop waits on chapulin in both directions, not the server
    direction alone. Gain: the client that exists is the one the TLS provider will sit under, so
    no harness is written twice.

47. **Every check runs on each push to main, and the run leaves a report.** Ruled by the owner on
    2026-09-19, to spot regressions in interoperability and performance. This amends the premise
    of entry 34, "there is no CI here"; its two layers stay. `.github/workflows/main.yml` installs
    Zig, h2spec and h2load, each pinned by checksum, and runs `tools/ci.sh`, which a person can run
    by hand for the same answer. The script runs the format check, `zig build test`, the three
    simulator checks in Debug and ReleaseSafe, `tools/h2spec.sh` and `tools/h2_interop.sh`, and it
    runs every section even after one fails, so the report is whole. The report is Markdown on the
    run's summary page and an artifact named for the commit.

    The report keeps two kinds of number apart. The test count, the simulator's checksums and the
    counted costs of entry 34's cheap layer are exact: a change in one is a change in the code, and
    `zig build test` already fails on it. The h2load throughput is indicative. A hosted runner pins
    no core and fixes no governor, which entry 33 requires of a published number, so the figure
    shows a large regression and proves nothing about a small one. It carries no threshold, and
    entry 32 holds: it comes from Linux with the machine written beside it.

    Two alternatives lost. A self-hosted Linux runner would meet entry 33 and make the throughput
    a baseline with a threshold; it costs a machine to keep, and the same script runs there the day
    one exists. Committing each report to a branch would keep the history past the 90 days an
    artifact lives, and it would give the workflow write access to the repository, which a job
    that runs on every push should not hold.

    Amended by the owner on 2026-09-25, for design §8 step 15d: the HTTP Garden runs in a job of
    its own, started by hand and every Monday, and not in `tools/ci.sh`. It builds every origin
    the Garden carries from source, which takes hours and tens of GB, past the 45 minutes of the
    push job. Its work is still one script, `tools/http_garden.sh`, which a person on Linux runs
    for the same answer; the job adds only what a hosted runner lacks: uv, and room on the disk.
    The alternatives offered: a manual job alone, which lets the comparison go stale while colibri
    changes; and a person running it on Linux with no job, which leaves no record between runs.

    Amended by the owner on 2026-09-27, for design §8 steps 9e and 12: `tools/h3spec.sh` joins
    `tools/ci.sh`, and the QUIC Interop Runner, `tools/interop.sh`, runs in a job of its own,
    started by hand and every Monday. Until then neither ran in CI, although CLAUDE.md said both
    did. h3spec has passed all 49 of its cases in every run design §8 records since 2026-09-25, and
    it tests the endpoint that h2spec's section has already built. The runner stays out of the
    push job for three reasons:

    - It takes about 30 minutes against quic-go in both roles, and the push job took about 25 of
      its 45 minutes on `13b7dbd`.
    - It needs tshark from Wireshark 4.5.0 or newer. Ubuntu 24.04 packages 4.2 and Ubuntu 26.04
      packages 4.6, so its job runs on Ubuntu 26.04.
    - Its `handshakeloss` case with colibri as the client failed some runs against quic-go's
      server, because the runner counted one client connection twice
      ([#72](https://github.com/c4milo/colibri/issues/72)). A push should not fail on that.
      Decision 99, ruled the same day, patches the count, so this reason no longer holds.

    Its work is still one script, which a person runs for the same answer; the job adds only what
    a hosted runner lacks: Zig and the directory in its global cache that its fetch of a zip
    package needs, tshark, and the kernel module the simulator's IPv6 needs. The
    alternatives offered: both checks in the push job, which needs a longer limit and fails a push
    whenever `handshakeloss` fails; h3spec in the push job and the runner by hand alone, which
    leaves no record between runs; and CLAUDE.md corrected to say both run by hand, with nothing
    added to CI.

    Amended again by the owner on 2026-09-27, after those jobs first ran, so that CI runs four
    checks it did not:

    - The push job runs the tests in ReleaseSafe as well as in Debug. ReleaseSafe is the mode
      colibri ships in, and until then only the simulator ran in both.
    - The push job builds the Lean proofs. It installs the Lean release that
      `spec/lean/lean-toolchain` pins, checked against its SHA-256, and fails when the workflow and
      that file name different releases. Until then `tools/ci.sh` skipped the proofs, because no
      hosted runner has lake.
    - A job of its own runs `zig build test` on Linux arm64 on each push. Every simulator check
      pins its census in its test, so a pass shows that a seed replays byte-identically on a second
      architecture, and the tests run over chapulin's objects built with the Arm AES instructions.
      The job is the third exception to the rule that a new check joins `tools/ci.sh`: its work is
      one `zig build` step, which a person on an arm64 machine runs as it is.
    - The runner job runs against ngtcp2, neqo and quinn as well as quic-go. Each pairing of a
      server and a client takes about 7 minutes, so that job's limit rises from 90 minutes to 150,
      and the push job's from 45 to 60 for the two sections it gains.

    The alternatives offered and not taken: commit messages linted in CI, as the pre-push hook
    lints them; more simulator seeds and coverage-guided fuzzing every Monday; and
    `tools/h3load.sh` in CI, which stays a check a person runs.

    Amended a third time by the owner on 2026-09-27: the arm64 job runs on macOS 26 as well as on
    Linux, on GitHub's standard macOS runners, which cost a public repository nothing. macOS on
    arm64 is the development host, where until then a person ran every check by hand; the job runs
    `zig build test` there on each push, with the test endpoints on Rotor's kqueue backend. The
    checks that need Docker stay on Linux, because GitHub's Apple Silicon runners have no Docker.

48. **The suite holds every key and protects every packet, and colibri holds none.** Ruled by the
    owner on 2026-09-19. It amends entries 8 and 9. `crypto.Suite` stays the second
    caller-supplied vtable, and its members become whole-packet operations at one of the three
    encryption levels colibri uses (RFC 9001 §4.1.4, less 0-RTT, which entry 20 rules out):
    `install_initial_keys`, `keys_available`, `seal`, `open`, `retry_tag_valid`,
    `retry_tag_write`, `update_keys`, `key_phase`, `discard_previous_keys` and `discard_keys`.
    Entry 55 adds `retry_token_write` and `retry_token_valid` for the same reason, which makes
    twelve. No member takes or returns a key, a secret or an IV. The secrets RFC 9001 §4.1.4 has TLS
    produce go from the provider to the suite inside the caller's code, so entry 8's QUIC mode
    loses `on_secret` and `hkdf_expand_label`.

    `open` removes header protection, recovers the packet number and removes packet protection
    in one call. RFC 9001 §9.5 requires the three applied together, with no timing or other side
    channel between them, and only the code that holds the key can promise that. So the packet
    number is an output of `open`, and colibri passes what RFC 9000 Appendix A.3 reads: the
    largest packet number it has processed in that space. `seal` takes a packet colibri has
    framed whole: the header with the packet number encoded, the Key Phase bit taken from
    `key_phase`, and a payload long enough for the sample of §5.4.2.

    What stays colibri's is every rule about *when*. It discards the Initial and Handshake keys
    (§4.9), starts a key update only once the handshake is confirmed and the current phase has
    been acknowledged (§6.1), answers a peer's update before it sends the acknowledgment (§6.2),
    drops the previous receive keys about three PTOs later (§6.5), reads the Reserved Bits once
    `open` returns (RFC 9000 §17.2), and sends KEY_UPDATE_ERROR and AEAD_LIMIT_REACHED, which a
    suite reports as values and never as frames.

    The ruling follows chapulin's, which its `docs/quic.md` records under "chapulin owns packet
    protection at every level". Entry 10 has chapulin fill both vtables, and chapulin exports no
    key: its `quic.h` offers `ch_quic_seal` and `ch_quic_open` and no primitive. Its reasons are
    colibri's as well. §9.5's constant-time MUST lands in code with the tooling to prove it, and
    colibri has none. No live traffic secret leaves the object that derived it. The six QUIC
    labels are written once.

    Cost. The null suite of design §10 must model keys, levels, phases and discards, because
    colibri's connection logic will be checked against it. RFC 9001 Appendix A's sample packets
    now check a provider through the vtable, so that half of step 7's check needs chapulin's
    `ch_quic_*` calls, which fail closed today. A caller whose TLS stack hands out secrets
    writes `seal` and `open` around its own AEAD, which is more work than five primitives were.
    The interop runner's keylog (design §9) must come from the provider, because colibri has
    nothing to log. Gain: colibri holds no secret in either mode
    ([invariant 23](invariants.md#inv-23--colibri-holds-no-secret)).

    Two alternatives lost. Entry 9's five primitives need the secrets out of the provider, which
    chapulin refuses, and would put §9.5's obligation in a library with no way to check it. One
    combined vtable lost again, for entry 9's reason and a new one: with protection apart from
    the handshake, the QUIC simulator of step 8 runs over a null suite before any handshake
    exists.

    Entry 94 amends this on 2026-09-26: chapulin fills the suite inside the library. Every rule
    above stands, and colibri still holds no key.

49. **colibri auto-tunes its flow control receive window.** Ruled by the owner on 2026-09-19,
    after the first flow control landed with a fixed window and the cost was put to him. A fixed
    window caps one stream at `window / round trip` whatever the path can carry — a megabyte at
    a hundred milliseconds is about ten megabytes a second, on any link — because a sender that
    fills the window waits a round trip to hear of more credit. Growing the window is how every
    implementation that competes on throughput avoids that: Chromium's QUIC, quiche and msquic
    all do it, and TCP has done it for two decades as receive buffer auto-tuning.

    The rule is the one those implementations share. When a receiver advertises credit, it asks
    how long since it last did. Less than a few round trips means the application drained the
    window faster than the peer could learn of new room, so the window and not the path is what
    is limiting the transfer, and the window doubles, up to a cap. Longer means something else
    is the limit and the window stays. The round trip is a parameter, because RFC 9002 computes
    it in design §8 step 10 and colibri reads no clock; so is the instant.

    RFC 9000 permits this and specifies none of it. §4.1 fixes the mechanism — absolute offsets,
    MAX_DATA and MAX_STREAM_DATA — and §4.2 leaves an implementation to decide when to send
    them; §4.1 adds only that a smaller limit than one already advertised has no effect, which a
    growing window never produces.

    This applies to both levels. A connection window that does not grow with its streams becomes
    the limit instead, which is the same problem one level up.

    Cost: two more numbers per receiver and a growth rule that a test must pin, and a window
    that no longer has one size a reader can predict from a transport parameter. Against
    [decision 35](decisions.md#memory) the cap is what bounds the memory, so it is a named limit
    like any other and a connection's worst case is still a comptime number. Gain: throughput
    that follows the path rather than the initial parameter, which is the one place §11.1's
    workload does not protect colibri — a short connection never reaches the window, but the
    interop runner's `transfer` case and any consumer moving a large body do.

    The alternative lost was the fixed window this replaces. It is simpler, it is what the first
    implementation did, and for design §11.1's stated workload — short connections, small
    requests — it is never reached. It was rejected because §11's own measurement plan puts
    colibri against msquic and quiche on transfers where it would lose for a reason that is a
    policy choice rather than a design one.

50. **Where RFC 9002 disagrees with itself about the round trip variation, colibri follows
    Appendix A.7.** This is design §12 question 4, which step 10 was required to settle in writing
    and pin with a test.

    The disagreement is one arithmetic ordering. §5.3 updates the smoothed estimate and then
    measures the variation against the value it has just written; Appendix A.7 measures the
    variation against the value as it stood and then updates. Written with `S` for the smoothed
    estimate, `V` for the variation and `A` for the adjusted sample:

    ```text
    Appendix A.7:  V' = 3/4 V + 1/4 |S  - A|   then   S' = 7/8 S + 1/8 A
    §5.3:          S' = 7/8 S + 1/8 A          then   V' = 3/4 V + 1/4 |S' - A|
    ```

    They differ by an exact factor, not by a rounding. `S' - A` is `7/8 S + 1/8 A - A`, which is
    `7/8 (S - A)`, so §5.3's new term is always exactly seven eighths of Appendix A.7's. A path
    holding steady drives the variation to the mean of that term, so §5.3's variation settles at
    seven eighths of Appendix A.7's, and §6.2.1's Probe Timeout carries four times the variation,
    so the timeout is shorter by an eighth of that term. On one sample with `S` at 100 ms, `V` at
    25 ms and `A` at 140 ms, Appendix A.7 gives a variation of 28.75 ms and a timeout of 220 ms,
    and §5.3 gives 27.5 ms and 215 ms.

    Appendix A.7 wins on three grounds. It is the executable text: Appendix A is presented as the
    complete algorithm and §5 as prose describing it, so where they part the algorithm is what an
    implementation transcribes. It is the more conservative of the two, since its variation is the
    larger, and a Probe Timeout that is too short sends a probe the path did not need, which costs
    the peer bandwidth and can pull the congestion window down for no loss — colibri fails closed
    everywhere else and does so here. And it is the ordering that makes the variation a measure of
    the estimate the sample was compared against rather than of an estimate the sample has already
    moved, which is the quantity §5.3's own prose says it wants.

    **One piece of evidence was not gathered.** §5.3 says its method is similar to RFC 6298's, so
    RFC 6298 would say which ordering the family intends. It is not in `docs/rfcs/`, and
    CLAUDE.md non-negotiable 10 forbids reading a summary of it, so it was not read. Vendoring
    RFC 6298 is what would settle the question from outside rather than from the two texts alone.

    The alternative lost is §5.3's ordering. It is the shorter timeout, so it recovers from real
    loss marginally sooner, and it is what a reader following the prose alone would write. It was
    rejected because the appendix is the algorithm and because the error it makes when it is wrong
    is a spurious probe rather than a late one.

51. **h2 and h3 share their message validation through `http`, and each names its own errors.**
    Ruled by the owner on 2026-09-20, answering design §12 question 6.

    RFC 9114 §4.1 to §4.3 restates most of RFC 9113 §8. The checks are the same: the
    pseudo-header rules, the field name and value rules, the ban on connection-specific fields,
    the CONNECT rules. What differs is the RFC section each check cites and the error a violation
    carries — PROTOCOL_ERROR for h2 (§8.1.1), H3_MESSAGE_ERROR for h3 (§4.1.2).

    So the shared rules move into `http` and return a reason. Each protocol maps that reason to
    its own error. This finishes the split [decision 15](#correctness) already describes, rather
    than changing it: `http` already holds the field-level checks, and `content_length` already
    works this way.

    A shared check in `http` cites both RFCs on the line that does the checking. Both state the
    rule, so both citations are true, and CLAUDE.md non-negotiable 9 is satisfied.

    Four rules stay per protocol, because they differ in what they accept:

    - `:authority` against `Host`. RFC 9114 §4.3.1 has four MUSTs. RFC 9113 §8.3.1 has one
      SHOULD that needs URI normalization, which colibri's h2 does not implement.
    - A repeated pseudo-header name. RFC 9113 §8.3 states it for any pseudo-header. RFC 9114
      states only that a request carries exactly one `:method`, `:scheme` and `:path`, and says
      nothing about `:status`.
    - An informational response with END_STREAM (RFC 9113 §8.1). h3 has no END_STREAM flag.
    - `:protocol` from RFC 8441. It is defined for h2 alone. colibri's h2 does not implement
      extended CONNECT today, so both protocols refuse it, but the rule would part if it did.

    **A fifth rule joined the four when RFC 9114 was read against them, 2026-09-20.** A field
    value that starts or ends with SP or HTAB is malformed in h2, which RFC 9113 §8.2.1 states in
    a MUST of its own. RFC 9114 states no such rule: the word HTAB does not appear in it, and the
    nearest sentence, §10.3's "Any request or response that contains a character not permitted in
    a field value MUST be treated as malformed", is about which octets appear and not about where
    they sit. SP and HTAB are permitted inside a value. The position rule reaches h3 only through
    RFC 9110 §5.5, which states it and which §10.3 imports for its character set alone. So this
    check stays per protocol under the same criterion as the other four, and `http` reports the
    character rules and the position rule as separate reasons rather than one. h2 folds both back
    into `FieldValueInvalid`, which is what it answers today.

    Two more citations moved in the same read, without changing what runs. RFC 9114 states the
    field-name token rule and the field-value character rule in §10.3, not in §4.2, and states
    both as MUSTs where RFC 9113 §8.2.1 makes the full grammar a SHOULD. A shared line therefore
    cites RFC 9113 §8.2.1 with RFC 9114 §10.3, and citing §4.2 there would name a section that
    does not state the rule.

    The alternatives lost. Duplicating the rules in `src/h3/message/` is what step 12's check
    exists to refuse; the two copies would part the first time an erratum moved one. Having h3
    call h2's code adds an `h3` to `h2` edge that design §3 does not have, and every check would
    cite RFC 9113 while running for h3, which non-negotiable 9 forbids.

52. **I/O stays outside colibri, and the test endpoints keep their own loops for now.** Ruled by
    the owner on 2026-09-20, and amended on 2026-09-22 by entry 58, which adopts Rotor for the UDP
    endpoints.

    colibri's library owns no socket, no descriptor and no loop. That is non-negotiable 1 and it
    does not change. The application that integrates colibri brings its own loop, and colibri
    never learns which one. Rotor is one such loop and so is anything else.

    The only place the question was open is `src/testing/`, which owns sockets by design (§9).
    The answer there is not yet, for one reason: Rotor carries no datagrams today. It has no
    `recvfrom`, no `sendto` and no `SOCK_DGRAM`. colibri's TCP endpoints already pass h2spec and
    interop, so replacing them buys nothing, and the endpoints that would gain are the UDP ones
    of steps 9, 12 and 13, which Rotor cannot carry.

    Waiting costs nothing. Every endpoint is already a pure session and a thin socket file, so a
    later swap touches the thin file alone. colibri does not invest in the hand-written loops:
    no threads, no batching, and no io_uring of its own.

    Decide again at step 9e, whose interop endpoint is the first UDP code in the tree. Adopting
    Rotor then would make it a third test-only dependency after chapulin and pepegrillo, which
    CLAUDE.md's "Ask before" covers.


53. **colibri reads RFC 9846, not RFC 8446, and re-cited all 158 citations against the revision
    rather than renumbering them by hand.** Ruled by the owner on 2026-09-20.

    RFC 9846 is the July 2026 revision of TLS 1.3. It obsoletes RFC 8446, keeps the same version
    codepoint and the same wire format, and is backward compatible. It renumbers section 4 and
    tightens a handful of requirements. `docs/rfcs/rfc8446.txt` is gone and non-negotiable 10
    now names both obsoletions.

    A find-and-replace of "8446" with "9846" would have been wrong. RFC 9846 §1.2 lists the
    changes, and its section 4 moved a whole level: 8446's §4.1.x became §4.2.x, §4.2.x became
    §4.3.x, §4.3.x became §4.4.x, §4.4.x became §4.5.x, §4.5 became §4.6 and §4.6.x became
    §4.7.x, while "The Transcript Hash" moved up from §4.4.1 to §4.1. Sections 5, 6, 7 and 9
    and appendices B.1, B.4 and E.5 held their numbers and their titles. Eighteen of colibri's
    citations sat in the moved range, and each one was checked against the section title it
    names before it moved. Two examples of what a blind renumber would have produced: the
    certificate chain order in `src/testing/tls/chapulin_server.zig` cited §4.4.2, which in
    RFC 9846 is "Certificate Request" and not "Certificate"; the KeyUpdate rules cited §4.6.3,
    which in RFC 9846 is "Post-Handshake Authentication".

    The audit read RFC 9846 §1.2's fifteen technical changes against colibri. Nine land inside a
    TLS stack colibri does not own: KeyShare reuse, the PSK and HelloRetryRequest hash, the
    NewSessionTicket rule, three corrected extension length bounds, KEM wording, the transcript
    hash note and the RSA PSS removal are all the provider's. Three cost colibri nothing: it
    refuses any version but TLS 1.3, so the TLS 1.0 and 1.1 prohibition is moot; it models no
    alert level, so restoring "close_notify" to warning changes nothing; and it never enforces
    the §5.5 limits on receive, which §5.5 now says receivers SHOULD NOT do. §5.5's upgrade to a
    MUST reworded two comments in `src/tls/provider.zig` and moved no code, because the sender
    that must act is the provider.

    Three reached colibri's own code. The new "general_error" alert is named in
    `src/tls/alert.zig` as part of this commit: the enum is not exhaustive, so 117 already
    arrived as an unknown error alert and was treated as one, and naming it documents the value
    without moving any behaviour. The other two are behaviour and wait on the owner:
    https://github.com/c4milo/colibri/issues/18 for "user_canceled", which colibri treats as a
    connection error although §6.1 now says to keep reading until the "close_notify" that must
    follow it, and https://github.com/c4milo/colibri/issues/19 for §4.7.3's cap on the number of
    key updates, which no member of `KeyUpdateError` lets a provider report.

    `zig build test` passes 967 of 967 with both chapulin roles linked, and
    `tools/tls_handshake.sh ../chapulin` still prints `complete alpn=h2 version=0x0304
    suite=0x1303`.

54. **The four choices RFC 9000 and RFC 9001 leave to a sender, ruled together.** Ruled by the
    owner on 2026-09-20, before the send path was written, because each one changes what a
    packet costs and all four would otherwise be settled by whoever typed first.

    **RFC 9001 §5.4.2's four-octet floor is met by widening the packet number, not by PADDING.**
    Header protection samples four octets, so a packet's Packet Number field and payload together
    must reach that; a packet carrying only PING or HANDSHAKE_DONE under a one-octet packet number
    falls short. §17.1 permits any width that represents the range, so widening is always legal.
    The alternative it beat is writing PADDING, which most implementations do and which is
    simpler. It loses because RFC 9002 §2 counts a packet in flight when it is ack-eliciting "or
    contains a PADDING frame": padding a bare probe or keep-alive spends congestion window on the
    packets least able to afford it, and widening the number spends none.

    **RFC 9000 §14.1's expansion to 1,200 octets lands on the last packet of the datagram.** §14.1
    permits "adding PADDING frames to the Initial packet or ... coalescing the Initial packet" and
    does not say which. Padding the Initial is what §14.1 names first; it loses because the Initial
    then counts about 1,200 octets in flight, so a lost first flight costs the whole datagram
    against the congestion window rather than the Initial's own contents. A trailing PADDING-only
    packet was also refused: it accounts most cleanly and spends a packet number for nothing,
    which invariant 17 makes irreversible.

    **The frame scratch is a comptime parameter defaulting to 1,200 octets.** `crypto.Sealing`
    forbids the payload overlapping the output, so the frames cannot be framed at their final
    offset and a separate buffer is forced. Decision 35 makes the caller place it, so its size is
    storage the caller commits per connection. `datagram_len_max` was refused at 64 KiB each; a
    flat `datagram_len_min` was refused because it would forgo a larger path MTU permanently. The
    comptime parameter follows `recovery_sent`, which already takes its capacity that way.

    **`token_len_max` is 256 octets.** RFC 9000 bounds an Initial's Token field only by the packet
    carrying it (§17.2.2, §19.7), so there is no number to derive. 256 comfortably holds the
    authenticated, address-bound, expiring token §8.1.1 describes. It is a judgement and the
    constant says so: 128 risks refusing a Retry from a server that mints something larger, and
    512 buys headroom at the cost of a larger fixed header buffer on every connection.

55. **The Retry token is the caller's to mint and to check, and the instant is a parameter.**
    Ruled by the owner on 2026-09-20, and amended on 2026-09-23: the token carries the two
    connection IDs a server that sent a Retry needs again.

    RFC 9000 §8.1.1 and §8.1.4 want a token that is authenticated, bound to the client's address
    and expiring. Authenticating it needs a key, which non-negotiable 2 refuses colibri, and
    expiring it needs the current instant, which non-negotiable 3 makes a parameter rather than
    something read. So the token is the caller's: two members are added to `crypto.Suite`, one
    that mints a token over an address the caller supplies and one that checks it, and both take
    `now_ns` from colibri rather than reading a clock.

    Taking the instant as a parameter is not a formality here. The deterministic simulator
    supplies it (non-negotiable 5), so a token minted in a seeded run expires at a seeded instant
    and one seed replays byte for byte. A token whose validity depended on a clock the suite read
    would make every Retry check unreproducible, which is the one thing design §8's whole method
    rests on.

    The alternatives refused. colibri holding a key of its own is non-negotiable 2. A token that
    is unauthenticated, which §8.1.4 warns lets an attacker replay one, would make Retry worse
    than not offering it. And a plain parameter on the server's Retry entry point rather than a
    vtable member was refused because the same key must mint and check across two connections,
    which is state colibri does not hold (decision 35).

    The amendment. A server that sent a Retry puts two connection IDs in its transport parameters
    (RFC 9000 §7.3): `original_destination_connection_id`, the Destination Connection ID of the
    client's first Initial, and `retry_source_connection_id`, the Source Connection ID of the
    Retry. The client's next Initial carries the second as its Destination Connection ID and
    never the first, and colibri keeps nothing between the Retry and that Initial (decision 35).
    So the token carries both:
    - `retry_token_write` takes both IDs, beside the address and the instant.
    - `retry_token_check` replaces `retry_token_valid`. A Retry token that verifies gives both IDs
      back. A Retry token that fails is `invalid`, which §8.1.2 closes with INVALID_TOKEN. Any
      other token is `not_retry`, which §8.1.3 has the server treat as no token.
    - colibri refuses a token that verifies but whose Retry Source Connection ID is not the
      Initial's Destination Connection ID: §17.2.5.2 has the client address exactly that ID, so
      the token came from another Retry.

    The alternative the amendment refused: the caller keeping a table from each Retry's Source
    Connection ID to the first Destination Connection ID. That puts per-Retry state and its expiry
    in every caller, and the token would no longer bind the IDs it vouches for.

56. **One STREAM frame per packet, so a lost packet's stream octets are one range.** Ruled by the
    owner on 2026-09-22, and amended the same day by entry 57, which replaces its rewind on loss
    and its last paragraph.

    RFC 9000 §13.3 has application data "retransmitted in new STREAM frames", which means a lost
    packet must be able to say which stream octets it carried. CRYPTO needed no ruling for this:
    one packet carries at most one CRYPTO frame, so `recovery_sent.Record` holds one offset and
    one length. A packet may carry STREAM frames for several streams, and that is what this
    entry settles: it carries one.

    So `Record` gains a stream identifier, an offset and a length, flat, as it holds the CRYPTO
    pair. Nothing else is stored and no second structure has to be kept in step with the sent
    packets. Loss rewinds the stream's send offset to the lowest lost one, which is what the
    CRYPTO rule already does, and §13.3 permits sending more than was lost: "a receiver MUST
    accept packets containing an outdated frame".

    The cost is on the wire and it is the reason this is a ruling rather than an obvious choice.
    A packet that could have carried three small streams' data carries one, so a connection
    multiplexing many small responses sends more packets and pays more header overhead. Design
    §11's benchmarks are where that shows, and entry 56 is meant to be revisited against a
    measured number rather than argued again.

    The alternatives refused. **A fixed array of ranges on `Record`** costs 36 kilobytes a
    connection at two ranges and 72 at four, against `Record`'s 32 octets and the 768 of them a
    connection holds; it also caps how many streams a packet may carry, which is a protocol limit
    invented for storage rather than read from an RFC. **A side table keyed by packet number**
    costs about the same without the cap, and is a second structure that must stay in step with
    the first — two places to get a retransmission wrong instead of one. And **tracking only
    acknowledged ranges per stream, with no packet mapping**, cannot work at all: an ACK frame
    names packet numbers and not stream offsets, so the mapping has to exist somewhere.

    What this does not settle. The octets themselves stay with the caller, which is
    non-negotiable 1 and decision 35 and needs no entry of its own: `h2`'s `write_data` already
    takes the caller's payload and answers how much it consumed, and QUIC only strengthens that
    contract from "hold until consumed" to "hold until acknowledged". Which stream sends next is
    the frame scheduler's, not this entry's.

57. **The caller keeps a stream's unacknowledged octets, and colibri reads them through a stream
    provider.** Ruled by the owner on 2026-09-22. It amends entry 56: one STREAM frame per packet
    and the flat range on `Record` stand, and this entry replaces the rest.

    Entry 56 said the octets stay with the caller and that this needed no ruling, because `h2`'s
    `write_data` already works that way. That precedent does not carry over. Under h2 the kernel
    retransmits, so an octet colibri has consumed is no longer the caller's concern. Under QUIC
    colibri retransmits (RFC 9000 §13.3), so the caller must keep each octet until the peer
    acknowledges it, and colibri must be able to read it again. Entry 56 gave colibri no way to
    read it and gave the caller no way to learn when it may let it go.

    So the caller supplies a third vtable, the stream provider. Its one member,
    `read(stream_id, offset, output)`, writes the stream's octets from `offset` into `output` and
    returns how many it wrote. colibri calls it only inside `send`, as it calls the suite's
    `seal`, so it is not a callback at a time colibri chooses (design §4). New octets and lost
    octets both arrive this way, straight into the packet scratch, so each octet is copied once
    before sealing, as today. The caller tells colibri how far each stream's octets reach and
    whether the stream ends there, in a call that passes no octets. The provider must answer the
    same octets for an offset every time (RFC 9000 §2.2: "The data at a given offset MUST NOT
    change if it is sent multiple times"). colibri holds no copy to check this against, so it is
    the provider's promise, as protecting a packet correctly is the suite's.

    Loss resends exactly what was lost. Entry 56 rewound the stream to the lowest lost offset, as
    the CRYPTO rule does. That is cheap for a handshake flight of a few kilobytes. For a stream it
    resends every octet from the lost one to the send offset, up to 256 packets of them at
    `sent_packets_max`, most of them already acknowledged. Instead, a lost packet's range goes
    into a table of lost ranges that the stream table keeps, and `send` frames those before any
    new octets (§13.3: "Endpoints SHOULD prioritize retransmission of data over sending new
    data"). New octets wait while a lost range is owed, so the table needs `sent_packets_max`
    ranges. A range split to fit a smaller packet (§13.3) is the exception, and the table joins
    adjacent ranges of one stream to absorb it; a table that fills anyway closes the connection
    with INTERNAL_ERROR.

    Each range of a stream is then in exactly one place: in one packet in flight, in the lost
    table, or acknowledged. So a count of acknowledged octets per stream is exact in any order of
    acknowledgment. The stream enters Data Recvd when the count reaches the final size and the
    FIN is acknowledged (§3.1: "Once all stream data has been successfully acknowledged"), and
    colibri reports it. From then on the caller may drop the stream's octets. A reset ends the
    obligation too (§13.3: "Once an endpoint sends a RESET_STREAM frame, no further STREAM frames
    are needed"). Two rules keep the count exact. A probe (RFC 9002 §6.2.4) carries new octets or
    a PING, never a range already in flight. And recovery reports every acknowledged record,
    where `recovery_sent.Removed` today reports only the largest.

    Three things in entry 56 were wrong. `Record` must name a stream by its 62-bit identifier and
    not by a slot index, because a slot is reused and a late acknowledgment would count toward
    the next stream in it. A FIN sent alone is a range of length zero and is resent when lost
    (§4.5: "A sender always communicates the final size of a stream to the receiver reliably").
    And 56 priced the refused array of ranges over all three packet number spaces, but STREAM
    frames travel in the application space alone (RFC 9000 §12.4, Table 3), so four ranges a
    packet cost about 12 kilobytes a connection, not 72. One frame per packet still stands on
    its other ground, that a cap on streams per packet is a limit invented for storage, and its
    wire cost is still design §11's to measure.

    The cost falls on the caller. It keeps each stream's octets until Data Recvd or a reset. For
    a small response that is the whole response, which a server holds anyway. For a file it is
    nothing extra, because the provider reads the file. A caller that generates a long body it
    cannot produce again must keep all of it until the stream ends, because colibri reports no
    acknowledged prefix: that needs per-stream bookkeeping of acknowledged ranges, and it serves
    bulk transfer, which decision 31 expects colibri to lose. When `h3` is the caller, it answers
    for the octets it writes itself, such as SETTINGS and frame headers; that is for `h3` to
    settle when its send path is built. Design §4 gains a fifth item.

    The alternatives refused. **colibri keeps the octets** in a pool the caller places, copied in
    at write. That keeps `h2`'s contract as it is, but it adds a copy per octet and 40 to 90
    kilobytes a connection, and the pool's size caps the octets in flight: 64 kilobytes is about
    26 Mbit/s over a 20 ms round trip, the kind of cap decision 49 removed on the receive side.
    **Keeping each packet's payload** until it is acknowledged, and reading lost frames back out
    of it, is the queue of frames to replay that design §8 step 9e refused, and it holds 300
    kilobytes a connection at the constants' worst case. **The caller keeps the octets and learns
    of a loss** by asking for each stream's send offset before every write. That is entry 56 made
    explicit, and it puts resend logic in every caller, where colibri's simulator cannot test it.

58. **Rotor is the loop of `src/testing/`'s UDP endpoints, a third test-only dependency.** Ruled
    by the owner on 2026-09-22. It amends entry 52, which deferred the question to step 9e, and
    entry 63 extends it: the loop reports the instant the endpoints pass to colibri.

    Entry 52 had one reason to wait: Rotor carried no datagrams. Its version one does. It runs
    the same conformance suite over kqueue on macOS and io_uring on Linux, UDP included, and it
    allocates nothing: the caller hands each loop its memory. Step 9e's interop endpoint is the
    first UDP code in the tree, so the question entry 52 left open is now due.

    Rotor is a lazy package in `build.zig.zon`, pinned by commit. Only colibri's own build
    requests it, after the point where a dependent project's build stops, as pepegrillo is
    requested (decision 36). One module imports it: `testing_udp`, rooted at
    `src/testing/udp.zig`, the thin socket file around a QUIC session that entry 52 asked for.
    The library never imports it, and non-negotiable 1 does not change: colibri owns no socket
    and no loop, and a consumer brings its own.

    Decision 46 still holds in substance. An endpoint on Rotor waits only in the loop's one
    system call per tick, and makes no other call that waits. The h2 endpoints keep their `poll`
    loops: they pass h2spec and interop, and moving them buys nothing (entry 52's reasoning).

    The alternatives refused. **Another hand-written `poll` loop for UDP** is what entry 52
    asked colibri not to invest in, and it would be a second loop to keep correct beside one the
    owner maintains. **libuv or libxev** would be a dependency no one here maintains, and Rotor
    already measures itself against both, the rows it loses included.
    **`std.Io`'s evented implementations** take an allocator, which decision 46 already refused.

59. **The connection drives RFC 9002's loss recovery.** Ruled by the owner on 2026-09-23.

    The design said recovery was the caller's to drive, and nothing drove it. A `Connection` holds
    a `Recovery`, but `send` recorded no packet in it, an ACK frame updated only the packet number
    space, and nothing called the loss timeout. A caller could not have done it either: ACK frames
    are read inside `connection_frames.process` and never reach the caller. And every piece that
    acts on an acknowledged or lost packet lives in the connection: CRYPTO, stream octets, the flow
    control frames, HANDSHAKE_DONE and the connection ID frames.

    So the connection runs RFC 9002 itself. `send` records each packet it builds (Appendix A.5) and
    sends no more than the congestion window allows (§7). An ACK frame runs `OnAckReceived`
    (Appendix A.7) where the frame is read. The loss timer runs `OnLossDetectionTimeout`
    (Appendix A.9). Both hand the packets they acknowledge or declare lost to every piece through
    one function. The caller still places the storage those packets are written into (decision
    35) and still supplies every instant (non-negotiable 3); what it no longer does is order
    RFC 9002's steps.

    The alternative refused: the caller drives, with ACK frames returned in the frame report and
    one colibri function to hand their packets to every piece. That keeps the design text as it
    was, but it puts the order of RFC 9002's steps in every caller, where the simulator cannot
    check it, and a caller that forgets one breaks recovery with nothing to say so.

60. **One call takes a received datagram.** Ruled by the owner on 2026-09-23, and amended the same
    day by entry 62, which has colibri, not the caller, mark each level's keys installed.

    Receiving a datagram took seven steps, and no library code ran them. They were: count the
    datagram toward RFC 9000 §8.1's limit; walk its packets (§12.2); process each packet's
    frames; record each packet in its space once its frames are processed (§13.1); discard the
    Handshake keys when a HANDSHAKE_DONE arrives (RFC 9001 §4.9.2); hand the provider what arrived
    (§4.1.3); and ask whether the handshake completed (§4.1.1). Only tests ran them, each in its
    own order. A Retry or a Version Negotiation packet needed a function of its own besides.

    So `connection_datagram.receive` takes one datagram and runs every step in the order the RFCs
    set. That is CLAUDE.md's "cross the caller's boundary in bulk" for the receive side. It reports
    the peer's CONNECTION_CLOSE, the streams that finished, and what a Retry or a Version
    Negotiation packet did. An error is a connection error, and
    `connection_datagram.connection_error_code` names its code. The caller still owns the octets,
    the instant and the scratch (decision 35), and still installs each level's keys as its provider
    produces them (decision 48).

    The alternative refused: the caller keeps the steps, and the simulator is the reference
    caller that every other caller copies. A caller that records a packet before its frames, or
    never counts a datagram, then breaks §13.1 or §8.1 with nothing to say so. It is decision 59's
    reasoning, applied to the receive side.

61. **colibri reassembles received stream octets into a pool the caller places.** Ruled by the
    owner on 2026-09-23. It settles [#41](https://github.com/c4milo/colibri/issues/41) and
    [#42](https://github.com/c4milo/colibri/issues/42).

    colibri checked every STREAM frame against RFC 9000's flow control, final size and state
    rules and kept none of the octets, so no caller could read a stream. And decision 49's
    window growth had no cap, so no window grew.

    So colibri reassembles. A connection's received octets go into one pool the caller places,
    `stream_incoming.Pool(capacity)`, in fixed-size blocks any stream may take. The application
    reads a stream's octets in order, and what it reads is what gives the peer new credit (RFC
    9000 §4.1). One pool is enough for every stream: the octets waiting across all streams can
    never pass the connection window, so the pool is sized by it plus two blocks per stream for
    the ends of each stream's span. colibri never advertises more than it can hold, so the pool's
    capacity is decision 49's cap, for the connection and for each stream alike. The default
    capacity is 1 MiB, a named limit: about 80 Mbit/s per connection at a 100 ms round trip. A
    caller that wants more places a larger pool. A connection given no pool reads no stream: it
    checks STREAM frames and keeps nothing, and its windows stay where they start.

    Three alternatives were refused. Handing each frame's octets to the caller puts reassembly
    in every caller, which is decision 60's reasoning again. A buffer per stream, sized to that
    stream's largest window, commits 128 of them per connection. Handing in-order octets out as
    they arrive and keeping only what sits past a gap needs less pool, but makes the caller take
    octets whenever they come rather than when it reads.

62. **colibri marks each level's keys installed, reading them from the suite, before the next
    packet.** Ruled by the owner on 2026-09-23. It amends entry 60 and settles
    [#45](https://github.com/c4milo/colibri/issues/45).

    Entry 60 had the caller mark each level installed once `receive` returned. A server's first
    datagram coalesces its Initial packet, which carries the ServerHello, with Handshake packets
    (RFC 9000 §12.2). The client had no Handshake keys while it walked that datagram, so it dropped
    the Handshake packets, and every handshake waited for the server to send them again. A 1-RTT
    packet coalesced behind the client's Finished was dropped at the server the same way. RFC
    9001 §4.1.4 says an endpoint "SHOULD buffer received packets if they might be processed using
    keys that are not yet available".

    So `receive` advances the handshake after each packet it processes. It hands TLS the octets
    that packet's CRYPTO frames completed, takes the peer's parameters and asks whether the
    handshake completed. Then it asks `crypto.Suite.keys_available` about each level and
    direction still in state `none` (invariant 21) and marks the ready ones installed, before it
    walks to the next packet. `receive` and `send` ask the same at their start, which covers the
    Initial keys. The caller still derives the Initial keys (RFC 9001 §5.2) and still moves each
    level's secrets from its provider to its suite (entry 48). It no longer tells colibri about
    either.

    Cost: during the handshake, a few provider calls per datagram instead of one, and one
    `keys_available` call per level still waiting. Once every level is available or discarded,
    the question asks the suite nothing. A peer that coalesces a packet ahead of the one that
    makes its keys still loses it, which §12.2 asks senders not to do.

    Two alternatives were refused. `receive` could report the packets it refused for want of keys
    and the caller feed them in again, but their octets would count twice toward RFC 9000 §8.1's
    limit unless a second entry point skipped the count. Leaving it costs every handshake at least
    one round trip.

63. **The test-only UDP endpoints take the instant from Rotor's loop.** Ruled by the owner on
    2026-09-23. It extends entry 58 and leaves entry 7 as it stands.

    A QUIC endpoint on a real network needs the current instant for RTT estimates, loss recovery,
    the PTO and the idle timeout, which colibri runs on the instants the caller passes. Entry 7
    says no source file imports a clock, and `tools/lint/determinism.zig` holds `src/testing/` to
    it too. Rotor already reads the monotonic clock in every backend's `tick`, for its own timers.

    So Rotor's loop reports the instant its last `tick` read, and the endpoints of design §9 pass
    that to colibri. No file under `src/` reads a clock. Rotor is the dependency that owns the
    endpoints' socket already, and a loop that reports its own instant is what libuv's `uv_now`
    and libxev's `now` do.

    Two alternatives were refused. Exempting `src/testing/` from entry 7 would put the first
    clock read in the tree and narrow the lint for it. Taking the instant from outside the process
    through a file or a pipe keeps the rule but adds a read to every timer.

    Randomness was never this entry's question, but the lint held `src/testing/` to it all the
    same, so the endpoints read `/dev/urandom` as a file. The owner ruled on 2026-09-24 that this
    was a defect: the endpoints are real network peers, and their connection IDs, keys and
    PATH_CHALLENGE data must be unpredictable. So `determinism` no longer reads `src/testing/`,
    and `testing-clock` holds it to this entry's clock rule alone.

64. **A PTO at the Initial or Handshake level declares that level's packets in flight lost, so its
    probe carries their CRYPTO octets.** Ruled by the owner on 2026-09-23. It keeps entry 57's rule
    that no octet is in two packets at once, and settles the QUIC Interop Runner's handshake loss
    case.

    A probe (RFC 9002 §6.2.4) carried new octets or a PING, and at the handshake levels there are
    rarely new octets, so it carried a PING. Lost CRYPTO octets were sent again only once an
    acknowledgment showed them lost. Under bursty loss the probes that did arrive gave the peer
    nothing it could use, and the runner's handshake loss case failed in both roles.

    §6.2.4 offers: "instead of sending an ack-eliciting packet, the sender MAY mark any packets
    still in flight as lost." colibri does that at the Initial and Handshake levels when their PTO
    fires, and then sends the probes. Their CRYPTO octets enter the lost ranges, so the probes
    carry them, and each octet is still in exactly one place.

    These packets are declared lost to move their octets, not because the path signalled
    congestion, so they are no congestion event. §6.2.4 names "an unnecessary rate reduction by the
    congestion controller" as the risk of this choice, and colibri takes none.

    Two alternatives were refused. Letting a probe repeat octets still in flight breaks entry 57's
    rule, and the CRYPTO stream's accounting would have to take one octet in two packets. Leaving
    PING-only probes keeps every lossy handshake waiting on a round trip it need not.

    Amended by the owner on 2026-09-28: when a PTO at the Initial or Handshake level owes two
    probes and the first carries all of the level's CRYPTO octets, the second carries them again
    in place of a PING. This reverses the first alternative refused above, for CRYPTO octets
    alone.
    - In the QUIC Interop Runner's `handshakeloss` case against quic-go, colibri's client lost 2
      of 8 runs to one pattern. Its Finished went in one probe datagram and a PING in the other,
      the network dropped the Finished's copy each time, and quic-go's server dropped the
      connection after 5 seconds without a packet from the client
      ([#72](https://github.com/c4milo/colibri/issues/72)). In both runs a PING arrived where a
      second copy of the Finished would have ended the handshake.
    - RFC 9002 §6.2.4 permits it: "Previously sent data MAY be sent if no new data can be sent",
      and a second datagram is there "to avoid an expensive consecutive PTO expiration due to a
      single lost datagram". RFC 9000 §2.2 has the receiver discard octets it already holds.
    - The CRYPTO accounting already takes it. A CRYPTO stream keeps no record of which octets
      were acknowledged: a lost packet rewinds the level's send offset, "the lowest rewind wins",
      and nothing is tracked per packet. So a copy in flight changes no count. Stream octets keep
      entry 57's rule and INV-29 unchanged.
    - `Connection.crypto_probe_from` notes where the PTO's rewind left each level. A packet
      built while a probe is owed, with nothing left unsent at its level, rewinds there and
      frames the octets again. A single probe, such as decision 70's in another space, and a
      flight longer than one packet, whose second probe carries the next octets, are as before.

65. **A server whose client shows it lacks the server's Initial CRYPTO octets sends them again at
    once, at most twice per connection.** Ruled by the owner on 2026-09-23. It takes RFC 9002
    §6.2.3's option to speed up handshake completion, and moves the octets as entry 64 does.

    In the QUIC Interop Runner's handshake loss case, one connection lost the server's first
    flight and the CRYPTO probe of each of the next three PTOs, while the PING probes arrived.
    The client repeated its ClientHello and then sent padded Initial PINGs. The server answered
    each with an ACK and waited for its next PTO, which doubled each time, and the client gave up.

    §6.2.3: "When a server receives an Initial packet containing duplicate CRYPTO data, it can
    assume the client did not receive all of the server's CRYPTO data sent in Initial packets."
    An endpoint then "MAY, for a limited number of times per connection, send a packet containing
    unacknowledged CRYPTO data earlier than the PTO expiry". A padded Initial PING shows the same
    thing: §6.2.2.1 has a client send one when its PTO fires only if it has no Handshake keys, and
    a client with the server's Initial CRYPTO octets has them.

    So a server takes either as the signal: an ack-eliciting Initial packet that brings no new
    CRYPTO octets, while its own Initial CRYPTO octets are in flight. It declares its Initial
    packets in flight lost, and the next datagram carries their octets. Like entry 64, this is no
    congestion event.

    The limit is `early_crypto_resends_max`, 2. §6.2.3 warns that "An endpoint that always
    retransmits packets in response to receiving packets that it cannot process risks creating an
    infinite exchange of packets." It calls one resend "adequate to quickly recover from a single
    packet loss", and the runner's losses come in bursts, so colibri allows a second.

    colibri takes the server's half alone. §6.2.3 also lets a client that receives Handshake
    packets before it has Handshake keys resend early. colibri's client passes the handshake loss
    case without it.

    Two alternatives were refused. One resend, the RFC's example, leaves nothing when that resend
    is lost too. Resending on every such packet, with no limit, is the exchange §6.2.3 warns of.

    Decision 71 amends this entry: the second resend waits until one PTO has passed since the
    first.

66. **A PTO at the application level declares the oldest ack-eliciting packets in flight lost, as
    many as the probes it owes, so the probes carry what those packets held.** Ruled by the owner
    on 2026-09-23. It extends entry 64 to the application level with a bound.

    Against quinn in the QUIC Interop Runner's handshake loss case, colibri's client sent its
    request once, in a 1-RTT packet the path lost. The four acknowledgments that would have shown
    the loss were lost too. Each PTO's probes carried a PING, because at the application level no
    packet was declared lost, and the connection reached its idle timeout with the request never
    sent again.

    RFC 9002 §6.2.4 lets a sender "mark any packets still in flight as lost". At the application
    level colibri marks the oldest ack-eliciting ones, `probe_packets` of them, and the probes
    carry their frames. Each octet is still in one place (entry 57). Like entry 64, this is no
    congestion event.

    Two alternatives were refused. Declaring every application packet in flight lost, as entry 64
    does at the handshake levels, sends a whole window again on each PTO, and on a path that is
    only slow most of it arrives twice. Leaving PING probes keeps a lost request waiting on an
    acknowledgment that may be lost as well.

67. **TLA+ specifications, checked by the TLC model checker, check the designs colibri's protocol
    decisions rule.** Ruled by the owner on 2026-09-23, and amended the same day: the runner lives
    in pepegrillo and the models in `spec/tla/`. TLC is the fourth tool colibri takes from outside,
    beside chapulin, pepegrillo and Rotor, and like them the library never links it.

    The simulator runs colibri's code over seeds of random loss. Entries 64 to 66 each repaired a
    loss pattern its seeds never produced: a network that drops every packet of ACK frames alone.
    Random loss rarely drops every acknowledgment in a row. TLC explores every behavior of a
    model, so it finds such a pattern at once. `spec/tla/probe_timeout/ProbeTimeout.tla` models
    what the probes of a PTO carry. With PING probes, TLC finds a lost frame never sent again.
    With entries 64 and 66, it finds every frame delivered.

    `zig build tla` runs pepegrillo's `tla` tool, configured in `tools/tla.zig`. It fetches
    `tla2tools.jar` from tlaplus's v1.7.4 release, the last one not marked prerelease, once into
    pepegrillo's cache. Before each run it checks the jar against the SHA-256 `tools/tla.zig` pins,
    because the release publishes none. Each configuration names the result TLC must find. One
    that must find a violation shows the property can fail, as a mutation does for a test.
    `tools/ci.sh` runs the check where a Java runtime is installed.

    The amendment makes the runner and the layout the ones every project of the owner's shares.
    pepegrillo (entry 36) holds the runner, so no project keeps a script of its own. Each model is
    a directory of `spec/tla/`, and Lean proofs, when colibri has any, go in `spec/lean/`. The pin
    stayed v1.7.4: tlaplus replaced its v1.8.0 prerelease jar on 2026-09-23, so a v1.8.0 pin taken
    earlier no longer matched what its URL served.

    A model is not the code. A specification states the design a decision rules, and the
    simulator and the tests check that the code does what the design says.

    Two alternatives were refused. Committing the jar puts a binary in the history for what a
    pinned hash already fixes. Running the models by hand alone lets a specification fall out of
    date with no one noticing.

68. **A caller says, with two flags, whether it reads received ECN codepoints and whether it sets
    them on what it sends.** Ruled by the owner on 2026-09-24.

    RFC 9000 §13.4 splits ECN into two halves, and each needs something only a socket has.
    Reporting ECN counts in ACK frames (§13.4.1) needs the codepoint of every received datagram,
    and "If an endpoint does not implement ECN support or does not have access to received ECN
    codepoints, it does not process or report ECN". Marking packets ECT(0) and validating the path
    (§13.4.2) needs the codepoint set on every sent datagram. colibri owns no socket
    (non-negotiable 1), so the caller says which halves it can do:
    - `ecn_reads`: the caller passes each datagram's real codepoint, and colibri reports the counts
      in its ACK frames.
    - `ecn_marks`: colibri names in `Sent` the codepoint the caller sets on the datagram. It is
      ECT(0) while §13.4.2's validation holds, and Not-ECT once validation fails (§13.4.2.2).
      Decision 69 narrows when it marks: through a testing period, then once the path is capable.

    Both default to false, which is what colibri did before: no report and no mark.

    The alternative refused: one flag for both halves. A caller whose socket can do only one half
    would then get neither, though the RFC treats the two as separate.

69. **An endpoint with `ecn_marks` tests a path with its first ten marked packets or three PTOs,
    whichever ends first, as RFC 9000 Appendix A.4 describes.** Ruled by the owner on 2026-09-24.

    Decision 68 marked every datagram until §13.4.2.1's count checks failed. A path that drops
    marked packets never lets an ACK through to fail them, so every packet is lost and the
    connection dies. §13.4.2 names the remedy: "the endpoint could set an ECT codepoint for only
    the first ten outgoing packets on a path, or for a period of three PTOs". Appendix A.4 gives
    the path four states:
    - testing: marks ECT(0). It ends once ten marked packets have gone out
      (`ecn_testing_packets`) or three PTOs have passed since the first did
      (`ecn_testing_probe_timeouts`), whichever comes first.
    - unknown: sends Not-ECT. An ACK frame that passes validation, once any marked packet has been
      acknowledged, makes the path capable.
    - capable: marks ECT(0).
    - failed: sends Not-ECT for the rest of the connection. Validation failing reaches it from any
      state (§13.4.2.2).

    The two limits are §13.4.2's numbers. Ten packets alone was ruled first and replaced the same
    day: before any round trip sample the PTO is about one second and doubles with each expiry,
    and a client sends at most two probes each time, so a handshake on a path that drops marked
    packets would take about 31 seconds to send ten, past a 30-second idle timeout. Three PTOs
    end the test after about seven.

    The alternatives refused:
    - Mark every packet until validation fails, which decision 68 did alone. A path that drops
      marked packets ends the connection.
    - Fail validation once every marked packet sent so far is declared lost. The first Initial
      lost to ordinary loss would then turn ECN off for the whole connection. Appendix A.4 lets an
      endpoint mark such a path failed; here it stays unknown, which sends the same Not-ECT and
      still becomes capable if a late acknowledgment shows a marked packet arrived.

70. **A PTO also probes every other packet number space that has ack-eliciting packets in
    flight, one packet each, coalesced into the same datagram when it fits.** Ruled by the owner
    on 2026-09-24. It takes RFC 9002 §6.2.4's SHOULD, which colibri had not.

    §6.2.4: "In addition to sending data in the packet number space for which the timer expired,
    the sender SHOULD send ack-eliciting packets from other packet number spaces with in-flight
    data, coalescing packets if possible. This is particularly valuable when the server has both
    Initial and Handshake data in flight or when the client has both Handshake and Application
    Data in flight because the peer might only have receive keys for one of the two packet
    number spaces."

    A colibri pair failed the QUIC Interop Runner's handshake loss case that way: the datagram
    carrying the server's ServerHello was lost, and the server's Handshake probes arrived at a
    client that could not read them. The simulator's copy of the runner's network (2,000 seeds,
    30% loss each way, at most three in a row) showed the same stall: one seed took 43 seconds to
    confirm the handshake. With this rule it took 15, and seeds at 16 seconds or more fell from
    11 to 3.

    Each other space's packet follows the rule of its level: decision 64 declares an Initial or
    Handshake space's packets in flight lost, so the probe carries their CRYPTO octets, and
    decision 66 declares the oldest application packet lost.

    The alternative refused: probing only the space whose timer expired, which is what colibri
    did, and which leaves the peer holding packets it has no keys for.

71. **Decision 65's second early resend waits until one PTO has passed since the first.** Ruled by
    the owner on 2026-09-24. It amends entry 65.

    A client whose PTO fires sends two probes at once (RFC 9002 §6.2.4), and each is an Initial
    packet that brings the server no new CRYPTO octets. Under entry 65 the server answered each
    with an early resend, so both resends went out 6 ms apart, and in the QUIC Interop Runner's
    handshake loss case one loss took both. The simulator cannot show this, because it delivers
    every datagram due at one instant before either endpoint sends.

    The PTO is RFC 9002 §6.2.1's period without backoff and without `max_ack_delay`, which
    §6.2.1 leaves out at the Initial level. A client's next PTO fires about that long later, so
    its next probe can spend the second resend.

    The alternatives refused:
    - Resends as entry 65 had them: one burst of loss can take both.
    - A limit of one resend: RFC 9002 §6.2.3's example, which entry 65 already refused.

72. **The caller names the peer address each datagram came from, and colibri decides when the path
    moves.** Ruled by the owner on 2026-09-24. It carries out what entry 21 requires of an endpoint
    that refuses migration: RFC 9000 §9's rules for a peer whose address changes anyway, as NAT
    rebinding does.

    colibri owns no socket (non-negotiable 1), so it cannot see an address. The caller passes one
    with each datagram: up to `peer_address_len_max` octets and a port, which colibri compares
    and never reads otherwise. From that:
    - A client discards a datagram from any address but its server's. §9: "If a client receives
      packets from an unknown server address, the client MUST discard these packets."
    - A server moves its path to a new address when a datagram from it carries the
      highest-numbered non-probing packet. §9.3: "An endpoint only changes the address to which
      it sends packets in response to the highest-numbered non-probing packet."
    - On a move, `Received` says so. The caller then gives colibri the data of two
      PATH_CHALLENGE frames: one for the new path (§9.3) and one for the previously active path
      (§9.3.3). Invariant 5 forbids colibri a random number, and §8.2.1 wants the data
      unpredictable.
    - `Sent` names the address each datagram goes to, because the challenge to the previous path
      goes out in a datagram of its own.
    - The new path starts unvalidated, so §8's anti-amplification limit applies to it (§9.3.1).
      If its validation fails, colibri moves back to the last validated address, and with none
      it closes silently (§9.3.2).
    - Once the new address is validated, colibri resets its congestion controller and RTT
      estimator (§9.4), except when only the port changed. §9.4 lets an endpoint keep both then,
      "Because port-only changes are commonly the result of NAT rebinding", and colibri does.

    The alternative refused: the caller compares addresses itself and passes flags for a change
    and for a change of port alone. colibri would decide the same things, but the caller would
    also have to keep the previous address and map colibri's names for the two paths back to
    sockets, which is state colibri already has to hold to revert.

    Amended the same day, while building it: one PATH_CHALLENGE on the new path is not enough.
    RFC 9000 §13.3 sends one "periodically until a matching PATH_RESPONSE frame is received",
    each with "a different payload". A NAT's old binding answers nothing, so if the one challenge
    on the new path is lost too, both attempts run out together and the connection closes. So
    the caller gives `path_challenge_attempts` payloads for the new path with the one for the
    previous path. colibri sends the next each PTO without an answer, and a response to any of
    them validates the path (§8.2.3).

    Amended again after the QUIC Interop Runner's rebind cases, where a colibri server lost the
    first challenge on a new path and then had no room to send another. The client's 117 octets
    from its new port allowed 351, and the challenge's packet was filled with stream data. So,
    until a path the peer moved to is validated, colibri sends ACK and path frames alone there,
    and a datagram carrying a path frame is padded only when all 1,200 octets fit (§8.2.1 excepts
    the rest, and part of the padding validates no path MTU). The octets §8 allows then go to the
    challenges §13.3 sends. The ACK frames stay because withholding them deadlocked the
    simulator: a peer whose window was full of unacknowledged data could not send its
    PATH_RESPONSE. Each challenge also repeats the latest ACK, whether or not anything new asks
    for one: `spec/tla/path_validation/` found that if the first challenge's packet carried the
    ACK and was lost, a client whose window that ACK would have freed could not answer the
    resends. The cost is a pause of about one round trip in data on each move.

73. **An endpoint that sends only ACK frames adds a PING about once a round trip, as RFC 9000
    §13.2.4 suggests.** Adopted on 2026-09-24, while building decision 72; the owner may overrule
    it.

    §13.2.4: "A receiver that sends only non-ack-eliciting packets, such as ACK frames, might not
    receive an acknowledgment for a long period of time ... a receiver could send a PING or other
    small ack-eliciting frame occasionally, such as once per round trip, to elicit an ACK from
    the peer." A colibri client that only downloads sent only ACK frames, so it had nothing in
    flight and no PTO armed. In the QUIC Interop Runner's rebind case, quic-go's server followed
    the client to its new port and sent one PATH_CHALLENGE, padded to all the octets §8 allowed
    it. The challenge was lost, and the server could send nothing more until the client sent
    again, which a client that receives nothing and owes nothing never did. With a PING in flight
    the client's PTO stays armed, and its probes give the server the octets to challenge again.
    (A first reading, that quic-go ignored packets of ACK frames alone, was wrong: it was waiting
    for a spare connection ID, RFC 9000 §9.3, which colibri's test endpoint now issues.)

    So at the application level colibri adds a PING to a packet carrying an ACK the space owes,
    when that packet elicits nothing else, a smoothed round trip has passed since its last
    ack-eliciting packet there, and it has sent `ack_only_packets_before_ping` packets of ACK
    frames alone since. The last condition ends the exchange: the peer answers a PING with one
    such packet, which is not enough to add a PING of its own. Without it, two colibri endpoints
    each added a PING to the answer and never went quiet. `spec/tla/ack_elicitation/` checks it
    under entry 67: with the count, two endpoints always go quiet, with or without loss; with a
    PING on every ACK, TLC finds the exchange that never ends.

    The alternatives refused:
    - Never adding one, which is what colibri did. A peer that follows only ack-eliciting packets
      never learns a client's new address.
    - A PING on a timer of its own. It would send packets when nothing needs acknowledging, and
      §10.1.2 leaves keeping a connection alive to the application.

74. **The QPACK decoder hands a blocked field section back to the caller unread, and holds the
    decoder instructions it owes until the caller asks for them.** Adopted on 2026-09-24 for
    design §8 step 11; the owner may overrule it.

    RFC 9204 §2.2.1 blocks a stream whose field section needs dynamic table entries that have not
    arrived yet. colibri owns no I/O and no heap (non-negotiables 1 and 4), so the decoder holds
    none of the section's octets:
    - `read_section` reads the prefix. When the Required Insert Count is above the decoder's
      insert count, it records the stream as blocked and returns `blocked`. The caller keeps the
      octets, which §2.2.1 already asks it to leave in the stream's flow-control window.
    - `ready_stream` names a blocked stream whose section can now be decoded, and the caller
      calls `read_section` for it again. The decoder holds each blocked stream's ID and Required
      Insert Count, at most `blocked_streams_max` of them. That limit is also the most the caller
      may advertise as SETTINGS_QPACK_BLOCKED_STREAMS, and one blocked stream more than it
      advertised is QPACK_DECOMPRESSION_FAILED (§2.1.2).
    - `read_encoder_stream` applies every whole encoder instruction the caller has and leaves a
      partial one unread. An instruction longer than `encoder_instruction_len_max` is
      QPACK_ENCODER_STREAM_ERROR, which §7.4 permits, so the caller never holds more than that.
    - The decoder owes Section Acknowledgments (§4.4.1), Stream Cancellations (§4.4.2) and Insert
      Count Increments (§4.4.3). It queues the first two, at most
      `decoder_instructions_owed_max`, and works out the increment when it writes: the insert
      count less the Known Received Count that the queued acknowledgments leave. So every insert
      is reported, once, in the next `write_decoder_stream`.
    - When the queue is full, `read_section` and `abandon_stream` return `owes_instructions` and
      do nothing, so no instruction is ever dropped. Decision 39 has h2's replies work the same
      way.
    - A Required Insert Count larger than the largest reference needs is refused as
      QPACK_DECOMPRESSION_FAILED. §2.2.1 says a decoder "MAY" refuse it, and a count set too
      high blocks a stream for nothing.

    The alternatives refused:
    - The decoder copies a blocked section's octets. That needs room for `blocked_streams_max`
      sections, and the caller already holds the octets.
    - A callback when a stream unblocks. Design §4 forbids colibri a call into the caller at a
      time of its choosing.
    - Each decoder instruction written into the caller's buffer as it arises. That crosses the
      caller's boundary once per instruction, where one `write_decoder_stream` crosses it once.

    Amended the same day, after `spec/tla/qpack_tables/` found an error in the first version. The
    decoder counted every stream it held against SETTINGS_QPACK_BLOCKED_STREAMS, including one
    whose entries had arrived but whose section the caller had not read again. An encoder told of
    those entries by an Insert Count Increment no longer counts that stream, and may send a section
    that blocks another, so the decoder refused a peer that kept the rule. §2.2.1 says a stream
    "becomes unblocked when the Insert Count becomes greater than or equal to the Required Insert
    Count", so the decoder now counts only streams still waiting for entries. Its list of held
    streams can then fill with streams that are ready, and `read_section` returns
    `read_ready_first`, consuming nothing, until the caller reads one.

75. **The QPACK vectors are a lazy Zig package, fetched once and pinned by hash, and a tool
    decodes them in `zig build test`.** Ruled by the owner on 2026-09-24 for design §8 step 11.

    `qpackers/qifs` holds six inputs and 529 files six encoders made of them, 119 MB unpacked.
    `build.zig.zon` names its archive at commit `da52cd9` with `.lazy = true`, as it names
    pepegrillo and Rotor. The first build on a machine downloads 20 MB and caches it, and a project
    that depends on colibri never fetches it. `tools/qpack_vectors.zig` decodes every encoded file
    with colibri's decoder and compares the sections with the inputs, and `zig build test` runs it,
    as it runs the HPACK corpus of entry 38.

    The files follow the QUIC working group's "QPACK Offline Interop" format, which differs from
    RFC 9204 in one place: the table starts at its maximum capacity, where RFC 9204 §3.2.2 starts
    it at zero, so the tool sets it. The corpus disagrees with itself in one place, and entry 25
    makes the RFC the authority: `examples.out.220.100.1` encodes RFC 9204 Appendix B, while the
    input beside it lists an earlier draft's examples. The tool skips that file and says so, and
    `src/qpack/decoder_test.zig` checks Appendix B.

    The alternatives refused:
    - Vendoring the corpus compressed, 1.7 MB as `tar.xz`. It works offline, but it puts a binary
      file in the repository and needs the tool to unpack it.
    - Vendoring the files as published, as entry 38 does for HPACK. That is 119 MB of files that
      have not changed since 2021.
    - A script that fetches the corpus on demand. Entry 38 refused this for HPACK because it takes
      the check out of `zig build test`, and a package keeps it in.

76. **The QPACK encoder inserts before it writes a section, and references only entries that are
    safe to reference.** Adopted on 2026-09-24 for design §8 step 11; the owner may overrule it.

    RFC 9204 §2.1 leaves to the encoder what to insert and when to risk a blocked stream.
    colibri's encoder decides this way:
    - `write_section` takes the field section and writes two outputs: the encoded section and the
      encoder stream. It first decides every line, writing each insert to the encoder stream as it
      goes. It then writes the prefix and the lines, with the Base at the insert count, which
      §4.5.1.2 names as one of an encoder's choices. No line then needs a post-Base index.
    - The caller marks each line `may_insert`, `no_insert` or `never_indexed`, as h2's callers mark
      each line for HPACK. A `never_indexed` line is a literal with its N bit, naming at most a
      static name, and is never inserted (§7.1.3).
    - A `may_insert` line the static table does not hold whole is inserted when four things hold.
      The peer permits a table. The entry takes at most the capacity over `insert_size_divisor`,
      so one line cannot evict every other. Making room evicts only evictable entries: §2.1.1 makes
      an entry evictable once its insertion is acknowledged and no unacknowledged section
      references it, this section included. And the whole instruction fits the encoder stream
      writer, which is how the caller passes the flow-control credit §2.1.3 asks the encoder to
      respect.
    - An entry at or above the Known Received Count is referenced only when the stream may block
      under the peer's SETTINGS_QPACK_BLOCKED_STREAMS (§2.1.2). Otherwise the section references
      only acknowledged entries and cannot block. It still inserts a line the table lacks, and
      writes that line as a literal: later sections reference the entry once the decoder
      acknowledges it, as Appendix B.3's speculative insert does. Without this, a peer that
      advertises no blocked streams, which is §5's default, would never see the table used.
    - A line already in the table but not yet acknowledged is not inserted a second time.
    - Set Dynamic Table Capacity goes out once, before the first insert, at the peer's maximum or
      `dynamic_table_capacity_max`, whichever is lower (§3.2.2, §3.2.3). The Required Insert Count
      is encoded against the peer's maximum, which is what the peer's decoder uses (§4.5.1.1).
    - When `outstanding_sections_max` sections are unacknowledged, the next section references no
      dynamic entry, so it needs no record.
    - The encoder stream octets it wrote are owed even when the field section did not fit. The
      inserts are in the encoder's table, so the decoder must receive them too.

    The alternatives refused:
    - Appendix C's single pass, which writes each line as it decides it and the prefix last. It
      needs the prefix in a second buffer, and a line inserted mid-section needs a post-Base index.
    - A draining index and the Duplicate instruction (§2.1.1.1). They keep a table from filling
      with referenced entries. Without them an encoder whose peer acknowledges late writes literals
      until the acknowledgments arrive, which is correct and costs compression only. Design §11
      measures before adding them.
    - A dynamic name reference in an insert. The static name or a literal name serves, and a
      reference to the dynamic table's own octets would need a copy before the insert evicts them.

77. **Lean 4 proves the pure arithmetic under colibri's codecs, and vector files tie each proved
    definition to the Zig function it mirrors.** Ruled by the owner on 2026-09-24, on issue #52:
    the Lean toolchain is a dependency, pinned in `spec/lean/lean-toolchain`, built with lake
    through pepegrillo's `lean` tool, with no Mathlib. Entry 67 placed the project in `spec/lean/`.

    TLA+ checks the interleavings of a design; Lean proves that a function is right for every
    input. The first proofs are QPACK's:
    - RFC 9204 §4.5.1.1's Required Insert Count. The decoder rebuilds the exact count whenever its
      own insert count is at most `MaxEntries` behind it and less than `MaxEntries` ahead. §2.1.1
      is what keeps a decoder in that window: an encoder evicts an entry only after the decoder
      acknowledges it, so it cannot fall further behind.
    - §3.2.5, §3.2.6 and §4.5.1.2's index arithmetic: relative and post-Base indices name distinct
      entries on either side of the Base, and every Base the encoder writes comes back.

    A proof covers the Lean definition, not the Zig code. So each definition follows its Zig
    function line by line, and `spec/lean/Vectors.lean` writes the definition's outputs over every
    input in a range to a file beside the Zig function. A Zig unit test reads that file and
    requires the Zig function to give the same outputs, so `zig build test` runs it with no Lean
    installed. `zig build lean` builds the proofs and checks that the committed files are still what
    the proved definitions give, and `zig build lean -- write` rewrites them. `tools/ci.sh` runs
    `zig build lean` where lake is installed, as it runs TLC where Java is.

    The alternatives refused:
    - Proofs with no tie to the code. They would prove a function nothing runs.
    - Generating the Zig function from Lean. It would put a second implementation in the build,
      and the Zig code would stop being the one people read and review.
    - Proving the Zig code itself. There is no verifier for Zig.

78. **colibri reports how far a stream's octets are acknowledged from its start.** Ruled by the
    owner on 2026-09-24, for design §8 step 12. It amends entry 57, which said colibri reports no
    acknowledged prefix.

    h3 writes three streams of its own that never end: its control stream (RFC 9114 §6.2.1) and
    QPACK's encoder and decoder streams (RFC 9204 §4.2). Closing any of them is a connection
    error. Entry 57 lets a caller drop a stream's octets only once the stream reaches "Data
    Recvd" or is reset, and these three do neither. So every octet h3 writes on them would stay
    in memory for the whole connection, and the encoder stream grows with every insert.

    `connection_stream_acknowledged.acknowledged_end(connection, id)` returns the offset below
    which the peer has acknowledged every octet of the stream, and the caller may drop those
    octets. It keeps no new state. Each framed octet sits in one packet in flight, in the lost
    table, or is acknowledged (invariant 29). So the answer is the lowest offset that an
    in-flight record or a lost range of the stream holds, or the end of what was framed when
    neither holds any. It scans the application space's sent records and the lost table, at most
    `sent_packets_max` and `stream_lost_ranges_max` entries, and a caller asks only when it needs
    room. Entry 57 refused per-stream bookkeeping of acknowledged ranges, and this adds none.

    The alternatives refused:
    - Emptying h3's storage for a stream only when everything framed on it is acknowledged, which
      the existing count shows. Under steady load something is always in flight, so a full
      buffer would stop inserts and acknowledgments for up to a round trip.
    - A static-table-only h3: a QPACK table capacity of 0 advertised, and an encoder that stops
      inserting after a fixed budget. It needs nothing from `quic`, but no peer could use a
      dynamic table toward colibri.

79. **h3 keeps the octets of its own three streams, and the caller keeps every request stream's.**
    Ruled by the owner on 2026-09-24, for design §8 step 12. Entry 57 left the octets h3 writes
    itself for h3 to settle.
    - The control stream and QPACK's encoder and decoder streams are h3's. It writes them and
      holds each in a fixed buffer on the h3 connection. It drops the part below the stream's
      acknowledged end (entry 78) and moves the rest to the front, so the free room is one slice
      a writer can fill. A buffer with no room never drops an octet. The encoder then does not
      insert, and the decoder holds the instructions it owes, as entry 74 has it.
    - A request stream's octets are the caller's: the HEADERS frame, each DATA frame's header, and
      the body. h3 writes the frames' octets into the caller's buffer, as `h2`'s write path does.
      The caller keeps them with the body until the stream reaches "Data Recvd" or is reset. h3
      keeps nothing per request stream but its state.
    - h3 hands `quic` one stream provider. It answers h3's three streams from the rings and
      passes every other stream to the caller's provider.

    The alternative refused: h3 keeps the frame octets of each request stream and asks the
    caller's provider for body octets only. The caller's provider is simpler. But h3 would then
    hold up to one encoded field section per open stream, `field_section_size_max` octets each,
    in memory decision 35 counts.

80. **An application may copy a stream's received octets without reading them, and take them
    later.** Adopted on 2026-09-24 for design §8 step 12; the owner may overrule it. It adds to
    entry 61.

    h3 needs a HEADERS frame whole before QPACK decodes it. A field section blocked on the dynamic
    table (RFC 9204 §2.2.1) must wait until the entries it needs arrive. Entry 74 hands a blocked
    section back unread and leaves its octets with the caller, "which §2.2.1 already asks it to
    leave in the stream's flow-control window". But entry 61's `read` copies octets out and
    consumes them in one step, so h3 would need a buffer of its own for every blocked section.

    So `connection_stream_read` gains two calls:
    - `peek` copies what `read` would and leaves the octets unread. They give the peer no credit
      (RFC 9000 §4.1) until they are taken.
    - `consume` takes a count of them as `read` would, without copying them again.

    h3 peeks a frame, decodes it from its copy, and consumes it once decoded. A blocked section
    stays in the pool, and h3 peeks it again when it unblocks. The cost is a second copy of a
    section that blocked.

    The alternatives refused:
    - h3 copies each blocked section into storage of its own. That needs room for
      `blocked_streams_max` sections per connection, which the pool already holds.
    - A read that hands out the pool's blocks in place. It saves the copy, but a frame across two
      blocks needs one anyway, and the caller would hold pointers into colibri's pool across calls.

81. **h3 lets the QPACK encoder insert only what the encoder stream's flow-control credit
    carries.** Adopted on 2026-09-24 for design §8 step 12; the owner may overrule it. It carries
    out entry 76, whose encoder takes the room of the encoder stream's writer as "the
    flow-control credit §2.1.3 asks the encoder to respect".

    h3 gave the encoder its buffer's free room instead of the credit. `spec/tla/h3_connection`
    then found the deadlock RFC 9204 §2.1.3 warns of:
    1. The encoder wrote an insert while the encoder stream had no credit.
    2. The section that referenced the insert went out on a request stream, which had credit, and
       blocked at the peer (§2.2.1).
    3. A blocked section stays unread (entry 80), so blocked sections held the peer's whole
       connection window.
    4. The peer consumed nothing more and sent no credit, so the insert never went out.

    `connection_stream_credit.send_credit(connection, id)` returns the octets a stream can still
    send. That is the smaller of the stream's credit and the connection's, each less the octets
    not yet framed that spend it first. For the connection's credit, those are the octets of every
    stream that RFC 9000 §2.3's order frames before this one or in turn with it. h3 cuts the
    encoder's writer to that length. An insert the credit cannot carry is not made, and the
    encoder writes the line as a literal.

    The alternatives refused:
    - Leave it to the receiver's windows. Blocked sections cannot fill a connection window larger
      than SETTINGS_QPACK_BLOCKED_STREAMS times a request stream's window. But the encoder's side
      sets neither window, and windows grow (entry 49).
    - Hold the insert in the encoder until credit arrives. Entry 76 inserts before it writes the
      section, and a section that references a held entry blocks all the same.

82. **The test-only TLS server drives chapulin's record-mode handshake.** Ruled by the owner on
    2026-09-24, for design §8 step 5 and https://github.com/c4milo/colibri/issues/20. Entry 46
    stands: this is the handshake it was waiting for.

    chapulin's `ROLE=server TRANSPORT=record` object takes the octets the caller read through
    `ch_srv_record_in`, and hands the server's flight to an `on_record_out` callback. It never
    calls `send` or `recv` during the handshake (its INV-28). So the h2 server's `--tls` mode runs
    a handshake inside its one `poll` loop:
    - `chapulin_server.zig` passes the octets read, and gets the flight back in the connection's
      output.
    - `h2_tls.zig` opens the records into h2's byte stream once `attach_tls` accepts the
      handshake, and seals what the session writes.
    - After the handshake, the record adapter gives `ch_read` one whole record at a time. It
      seals only what fits the output, because chapulin fails a session whose `send` cannot take
      a whole record.
    - The TLS mode runs one worker. chapulin's generator is one process-wide state with no lock
      (its `drbg.h`).

    colibri's checks found two chapulin defects on the way, and chapulin fixed both (`8e556ca`,
    `24301d1`). colibri did not work around either.

    The client followed on 2026-09-24, under the owner's ruling on
    https://github.com/c4milo/colibri/issues/62 to leave no known bug in place. Its
    `TRANSPORT=tls` object failed the session on any record that carries no data, a
    NewSessionTicket or a KeyUpdate, because its blocking `recv` cannot answer "no record yet".
    `chapulin_client.zig` now drives `ch_record_init`, `ch_record_in` and `ch_record_out`, and
    every TLS endpoint checks the linked object against the headers with chapulin's
    `ch_build_matches` before its first call.

    The alternatives refused, both offered in the issue on 2026-09-20:
    - A separate serial TLS endpoint, one blocking handshake at a time. It passes h2spec, which
      opens one connection per case, but it is not how a consumer runs colibri.
    - A thread for each handshake, joining the poll set when done. It keeps the loop from waiting,
      at the cost of threads and a pool in a file that has neither.

83. **The h2 endpoints run on Rotor too.** Ruled by the owner on 2026-09-24, for
    https://github.com/c4milo/colibri/issues/61. It amends entry 58, which kept the h2 endpoints
    on `poll` because moving them "buys nothing".
    - `h2-server`, in cleartext and in its `--tls` mode, runs one Rotor loop per worker, each with
      its own listener bound with SO_REUSEPORT. `h2-client` runs one loop for the whole run.
    - A worker keeps one accept in flight while it has a free slot. Each connection has at most
      one receive, one send and, at its end, one close in flight, and its slot is reused only
      after every one of them has its final event (Rotor's rule 1).
    - A receive writes into a buffer of its own, and its octets are appended to the session's
      input when its event arrives. The session moves what is left of its input as it consumes,
      and Rotor owns a receive's buffer until its final event (Rotor's rule 3), so a receive never
      targets the input.
    - h11's endpoints are written on Rotor from their first commit
      (https://github.com/c4milo/colibri/issues/60).
    - The one-connection checks `tls-handshake` and `tls-accept` still block. They serve one
      connection and exit, and entry 46 does not govern them.

    The gain is one loop model for every endpoint of `src/testing/`, and io_uring for the h2
    endpoints on Linux. Entry 46 holds unchanged: an endpoint waits only in the loop's tick.

    The alternative refused: keep `poll` for h2, as entry 58 had it. The h2 endpoints passed
    h2spec and interop on it. The owner chose one loop model over leaving the endpoints on two.

84. **After the TLS provider fails, the suite says where the CONNECTION_CLOSE can go.** Ruled by
    the owner on 2026-09-24, for https://github.com/c4milo/colibri/issues/59. It amends
    [invariant 21](invariants.md).

    RFC 9001 §4.8 owes the peer a CONNECTION_CLOSE when TLS fails. A TLS stack that failed keeps
    only the write keys the close needs, and wipes every read key. chapulin keeps one close per
    level, and drops that level's write keys once it has sealed it. colibri's own record still
    counted those levels as available, so the send failed with `NoSpaceLeft`, no close went out,
    and the peer waited for its idle timeout.
    - The connection records the failure (`tls_failed`).
    - From then on, every `send` and `receive` asks the suite's `keys_available` about each level
      colibri still counts as available. It marks `lost` each one the suite no longer holds
      (`take_lost`).
    - A lost level seals and opens nothing, as a discarded one does. The difference is that
      colibri told the suite to forget nothing.
    - Before a failure, a level the suite drops is still the suite's defect, which invariant 21's
      assertions at `seal` and `open` catch.
    - `crypto.Suite` is unchanged. The adapter in `src/testing/` seals through chapulin's
      `ch_quic_seal_close` once chapulin's session has failed.

    With the close sent, a failed connection ends alone, and the UDP server serves the next one.
    `tools/quic_aioquic.sh` checks that with two refused handshakes in a row.

    The alternative refused: a thirteenth `crypto.Suite` member, `seal_close`, which colibri would
    call for close packets after a failure. It grows entry 48's vtable, and colibri would still
    need to learn which levels the suite no longer holds.

85. **The QUIC object is built `SUITE=aesgcm`, and every chapulin endpoint checks the object
    against the headers before it starts.** Ruled by the owner on 2026-09-24, relayed by the
    chapulin session, for design §8 step 12's h3spec check.

    RFC 9846 §9.1 makes TLS_AES_128_GCM_SHA256 mandatory to implement, and h3spec's client offers
    AES suites alone. chapulin's `SUITE=aesgcm` adds TLS_AES_128_GCM_SHA256 and
    TLS_AES_256_GCM_SHA384 beside TLS_CHACHA20_POLY1305_SHA256, over QUIC as over TLS. It builds
    only with `AES=hw` and `-DCH_NATIVE_AES`, the builder's statement that the part's AES
    instructions run in constant time (chapulin's INV-26).
    - `build/modules.zig` reads the QUIC headers under `CH_AES_HW` and `CH_SUITE_AES_GCM`, so the
      QUIC object must be the suite build. CLAUDE.md's QUIC check line names it.
    - An object built with other defines exports the same calls and links, and then runs with the
      wrong struct sizes. So each endpoint calls chapulin's `ch_build_matches` before any other
      chapulin call and refuses a mismatch: `chapulin.check_build` for the TLS roles and
      `chapulin_quic_c.check_build` for QUIC.
    - The suite adapter reports chapulin's `CH_EINVAL` at a level whose keys it holds as RFC 9001
      §6.6's confidentiality limit, at any level. An AES-GCM key set meets it at 2^23 packets, and
      the connection answers with a key update at 1-RTT, or with AEAD_LIMIT_REACHED where no
      update is possible.

    The alternative refused: a build option naming the suite, so a ChaCha20-only object still
    links. It keeps two object shapes alive, and only one of them can run h3spec.

86. **colibri exports its ten library modules by name, so a project that depends on it builds
    against them.** Ruled by the owner on 2026-09-25, relayed by the cocuyo session.
    - `build/modules.zig` creates `core`, `wire`, `http`, `tls`, `crypto`, `hpack`, `qpack`,
      `quic`, `h2` and `h3` with `b.addModule`. Each carries the imports design §3 gives it, and a
      dependent reaches it with `dependency.module("quic")`.
    - The simulator, the corpus and the test-only endpoints stay unexported, because they are not
      the library. The tools, pepegrillo, Rotor and the `qifs` vectors are still requested only
      when colibri is the root build.
    - A dependent drives its own connections on its own threads, so the library must keep no
      process-wide mutable state. An audit of the ten modules on this date found none in library
      code: every container-level `var` is test-only except `stream_provider.none_context`, a byte
      nothing writes, whose address is the context of the provider that sends nothing.

    The alternative refused: a dependent that imports colibri's source files by path. It would
    bypass the module graph that keeps `quic` from importing any HTTP module (decision 5).

    `h11` joined them on 2026-09-25, when design §8 step 15a created it, so eleven are exported.
    `tls` joined them on 2026-09-26, when design §8 step 16b created it, so twelve are.

87. **The simulator's h3 trace run logs every variable of `spec/tla/h3_connection`, and TLC checks
    each seed's log is a behavior of the model.** Ruled by the owner on 2026-09-25, for
    https://github.com/c4milo/colibri/issues/58.

    Entry 67's models check a design, not the code that carries it out. A model and its code can
    drift apart unseen. A trace check ties them: colibri runs, and the model must be able to
    take the same path.
    - The simulator's h3 check exchanges field sections of any size, so its state does not map to
      the model's frames. A run of its own, `src/sim/h3_trace_check.zig`, draws its plan to the
      model's rules. Each request is one HEADERS frame and a number of DATA frames of one size,
      and the plan draws the cancels and GOAWAYs.
    - After each step, the run computes all 28 of the model's variables from both endpoints, in
      the model's units, and keeps each state that differs from the one before.
    - One simulator step can take several of the model's steps. So `H3ConnectionTrace.tla` lets
      the model take up to 24 steps between two logged states, and a seed passes when TLC reaches
      the last one.
    - The check runs through `tools/h3_trace.sh` and in `tools/ci.sh` where Java is installed. It
      is not part of `zig build test`, as `zig build tla` is not.

    The alternatives refused, both offered in the issue:
    - Log only the actions, such as an open, a send, a GOAWAY or a reset, and let TLC find the
      state between them. It needs less instrumentation, but the check is weaker: a variable
      colibri gets wrong goes unseen when some path of the model reaches the next action. TLC's
      time per trace also grows with the choices the model leaves open.
    - Check only the flow scope, from the existing h3 check's QPACK counts. The GOAWAY and cancel
      rules would stay checked by the model alone.

88. **colibri builds HTTP/1.1 as h11, client and server.** Ruled by the owner on 2026-09-24 and
    2026-09-25, for https://github.com/c4milo/colibri/issues/60. It amends entry 2.
    - Both roles, for completeness. The server takes on the request smuggling surface of RFC 9112
      §11.2, so every request-parsing check has a test proved by mutation.
    - The name is h11, as h2 and h3 name the other two, in prose, in the module name `src/h11/`
      and as a commit scope.
    - The order is h3, then h2, then h11. RFC 9114 §3.1 lets a client try QUIC with ALPN `h3`
      first, and says clients "SHOULD attempt to use TCP-based versions of HTTP" when that fails.
      The TCP connection's ClientHello offers `h2` and then `http/1.1` (RFC 7301). colibri opens no
      connection, so the caller follows the order, and the test-only client of `src/testing/`
      does.
    - The client pipelines (RFC 9112 §9.3.2). The connection keeps its requests in order and gives
      each response to the oldest one. It does not pipeline after a non-idempotent method until
      that method's final status arrives. When the connection closes, colibri reports which
      requests went unanswered, and the caller opens the next connection, on which the client
      does not pipeline at once.
    - `h11` imports `core`, `http`, `tls` and `deflate`. `tls` lets it attach to a finished
      handshake and check what ALPN selected. Entry 90 moves `deflate` to stdx.
    - Amended by the owner on 2026-09-25, for design §8 step 15d: h11 runs when ALPN selected
      `http/1.1` or selected nothing, and refuses any other selection (RFC 7301 §3.2). RFC 9846
      §4.2.2 has a server ignore an extension it does not recognise, so a server without ALPN
      answers with none, and RFC 9112 §9.7 asks for no ALPN. curl, Go's `net/http`, browsers,
      nginx and h2o all speak HTTP/1.1 on such a connection. The alternative refused: h11 runs
      only when ALPN selected `http/1.1`, as h2 runs only on `h2`. It is the strict side, but h2
      has RFC 9113 §3.3's MUST behind it and h11 has none, and it would refuse every peer that
      does not negotiate ALPN.
    - h11 decodes three transfer codings: `chunked` (RFC 9112 §7.1), `gzip` and `deflate` (§7.2).
      A server answers 501 to any other coding, `compress` included (§6.1). It answers 400 and
      closes the connection when a request's last coding is not `chunked` (§6.3).
    - The test-only endpoints run on Rotor from their first commit (entry 83).
    - The HTTP Garden (https://github.com/narfindustries/http-garden) checks h11's server, ruled
      by the owner on 2026-09-25. It is a differential fuzzer of HTTP/1.1 request streams. It runs
      from `tools/` alone, cloned at a pinned commit into a cache as `tools/interop.sh` clones the
      QUIC Interop Runner, and nothing of it is linked or shipped. Its license is GPL-3.0, which
      reaches no colibri code, because colibri only runs it. It needs Docker.
    - Amended by the owner on 2026-09-25, for design §8 step 15d: the Garden's job publishes the
      images it builds as public images in one package, `ghcr.io/c4milo/colibri-http-garden`,
      tagged by the Garden's commit, so a later run pulls them instead of building every origin
      for hours. The images carry the Garden's GPL-3.0 code and each origin's own; their source is
      the pinned public repositories they are built from. colibri's own image is never published.
      The alternatives offered: the Actions cache, whose 10 GB the push job's Zig caches already
      fill; private images, whose free storage is far smaller than the images; and rebuilding on
      every run.
    - Amended by the owner on 2026-09-28: the clone carries one patch,
      `tools/http_garden/jetty_maven.patch`. The pinned eclipse_jetty image fetches Maven
      4.0.0-rc-5 from dlcdn.apache.org, which no longer serves it, and the patch fetches it from
      archive.apache.org. The alternative offered: leaving jetty out, as the script does with any
      origin whose image no longer builds.

    The alternatives refused for transfer codings, both offered on 2026-09-25:
    - `chunked` alone, refusing the rest. It is the smallest surface, and needs no decoder.
    - `chunked` removed and the other codings passed to the caller still encoded. It moves the
      decoding into every caller, and the server still needs the caller to accept or refuse.

89. **colibri writes its own decoder for the `gzip` and `deflate` codings, in `src/deflate/`.**
    Ruled by the owner on 2026-09-25, for https://github.com/c4milo/colibri/issues/60.
    - The module holds RFC 1951's inflate, the zlib wrapper of RFC 1950 with its Adler-32 check,
      and the gzip wrapper of RFC 1952 with its CRC-32 check. It imports `core` alone, and `h11`
      imports it. The three RFCs are in `docs/rfcs/compression/`.
    - It decodes input that arrives in pieces. Each call takes the octets the caller has, writes
      what it can into the caller's output, and says whether it needs more input or more room. It
      keeps its state and its window of 32,768 octets in storage the caller owns, because a
      deflate distance reaches that far back (RFC 1951 §2).
    - zlib and Wuffs may serve as test oracles and benchmark baselines in `tools/` and `bench/`.
      Neither is linked into the library.

    A survey of the existing decoders is in the issue. Each alternative refused:
    - Zig's `std.compress.flate`. It cannot resume when its input runs out mid-stream, and it
      never compares the checksums it reads, so colibri would hold the whole coded body and check
      the checksums itself.
    - Wuffs, compiled into the library. It fits the model best and decodes at 1.5 to 1.9 times
      zlib's speed in its own benchmark. But it is C, every consumer would compile it, and the
      release colibri would need is an alpha.
    - zlib or zlib-ng, fed from a fixed pool. Both are mature and fuzzed, but they are C, and zlib
      has four CVEs in its decoder or its checksums.
    - zlib-rs or miniz_oxide. Both are Rust, so every consumer would need a Rust toolchain, and
      miniz_oxide has no gzip.
    - libdeflate, tinf and puff. Each needs the whole coded body at once.

    Entry 90 moves this decoder, and the check that proves it, to stdx.

90. **The compression codecs live in stdx, a repository of their own, and colibri imports it.**
    Ruled by the owner on 2026-09-25. It amends entry 89, which put the decoder in `src/deflate/`,
    and entry 35, under which the library imports no package.
    - stdx (https://github.com/c4milo/stdx) holds compression codecs, each with an encoder and a
      decoder: deflate with its zlib and gzip wrappers, zstd and brotli. Other projects want them
      without HTTP, which is entry 3's condition for moving code into a repository of its own.
    - colibri takes stdx as a Zig package pinned by hash. It is the first package the library
      imports, and h11 imports stdx's gzip and deflate decoders for the transfer codings of entry
      88. The package joins CLAUDE.md's list of ruled dependencies in the commit that adds it.
    - stdx keeps colibri's rules: no I/O, no heap, no clock, bounded work per call, a check cited
      to its RFC, and mutations. It never depends on colibri.
    - Design §8 step 14 moves to stdx (https://github.com/c4milo/stdx/issues/1), with zlib and
      Wuffs as its oracles and baselines.

    The alternatives refused:
    - The decoder inside colibri, as entry 89 had it. Another project would have to take an HTTP
      library to get a codec, and encoders and more codecs are coming.
    - stdx holding colibri's `core` as well. Every colibri module would change its imports before
      any codec work, and stdx would carry limits that belong to HTTP.

91. **How h11 uses stdx's gzip and deflate decoders.** Ruled by the owner on 2026-09-25, for
    https://github.com/c4milo/colibri/issues/64. It settles what entries 88 and 90 left open.
    - One compression coding at most on a body: `chunked`, plus at most one of `gzip` or
      `deflate`. RFC 9112 §6.1 lets `Transfer-Encoding` list several codings, and colibri knows of
      no peer that stacks two compression codings. A server answers 501 to more than one, and a
      client fails the response.
    - `deflate` is the zlib format alone, as RFC 9110 §8.4.1.2 defines it. A raw deflate stream
      fails the zlib header check and is refused.
    - h11 caps no decoded size. The decoded octets go into the application's buffers, so colibri's
      memory stays bounded, and the application stops reading at its own limit, as it does for
      any body.
    - A `gzip` body may hold several members (RFC 1952 §2.2). Each member's CRC-32 and length are
      checked.
    - Octets after the coded stream ends inside the body make the message malformed. A server
      answers 400 and closes the connection, and a client fails the response. Octets that belong
      to no coding are a framing disagreement, which is how request smuggling starts.
    - Two verdicts. A server answers 400 and closes for a corrupt body, such as a wrong checksum or
      a malformed block. It answers 501 for a feature it refuses, such as a zlib preset dictionary
      or a window over the limit (RFC 9112 §6.1). A client fails the response and closes the
      connection in both cases.
    - Decoders live in a pool the caller owns, sized by a named limit. h11 takes a slot only while
      a message carries `gzip` or `deflate`, and returns it when the message ends. When the pool is
      empty, a server answers 503 and a client fails the response.
    - The client offers `gzip` and `deflate` only when the caller turns on a connection option.
      Then it sends `TE: gzip, deflate` with `TE` in `Connection` (RFC 9110 §10.1.4). Without the
      option it offers nothing, and it refuses a response that carries either coding, because
      RFC 9112 §7.4 makes `chunked` the only acceptable coding when no `TE` field is sent.

    The alternatives refused:
    - Stacked compression codings, with a named limit on their depth. Each layer costs another
      window of 32,768 octets.
    - Raw deflate accepted by inspecting the first two octets. A corrupt body would then pass as
      raw deflate for longer before it failed.
    - A named limit on each message's decoded size, or on its ratio to the coded size. The ratio
      limit also refuses content that is legitimately repetitive.
    - The first `gzip` member alone, which refuses input RFC 1952 allows.
    - Leftover octets read and dropped, so two parsers can disagree about what a body held.
    - One verdict for every decoder error.
    - A decoder inside every connection. A server holding 10,000 idle connections would spend
      about 400 MB on decoders it rarely uses.
    - Offering the codings on every client connection, or on none.

92. **How an h11 connection runs.** Ruled by the owner on 2026-09-25, for design §8 step 15b.
    - colibri writes a server's error responses itself, as h2 writes its own GOAWAY and
      RST_STREAM. The response carries `Connection: close` and no content, and the connection
      closes after it. The statuses:
      - 400 for a malformed request (RFC 9112 §2.2, §3.2, §5.1, §6.3; RFC 9110 §15.5.1);
      - 414 for a request line longer than `start_line_len_max` (RFC 9112 §3, RFC 9110 §15.5.15);
      - 431 for a head, field section or trailer section past colibri's limits (RFC 6585 §5, now in
        `docs/rfcs/`);
      - 501 for a transfer coding h11 does not decode, when chunked is the final coding (RFC 9112
        §6.1, RFC 9110 §15.6.2, decision 91). A request whose final coding is not chunked gets 400
        whatever codings it names, because RFC 9112 §6.3 makes that 400 a MUST and §6.1's 501 is a
        SHOULD. The owner amended this on 2026-09-26: the HTTP Garden showed colibri answering 501
        to `Transfer-Encoding: xchunked`, where 11 of its origins answer 400 and 12 answer 501;
      - 505 for a major version other than 1 (RFC 9110 §15.6.6).
    - HTTP/1.0 keep-alive is not honoured. An HTTP/1.0 exchange closes after its response, which
      RFC 9112 §9.3 allows. HTTP/1.1 connections persist unless either side sends
      `Connection: close`.
    - A server reads one request at a time. It reads the next request only after it has written
      the final response to the current one, so later pipelined requests stay unread in the
      caller's buffer. Responses go out in order with no queue (RFC 9112 §9.3.2).

    The alternatives refused:
    - The application writes the error response. It gains control of the content, but every
      application would have to handle every refusal the same way.
    - Honouring HTTP/1.0 keep-alive. RFC 9112 Appendix C.2.2 describes how often HTTP/1.0
      implementations get it wrong.
    - Reading pipelined requests ahead, up to a named limit. It allows parallel processing of safe
      methods, at the cost of a queue of pending requests on every connection.
    - Answering an oversized field section with 400, which RFC 9110 §5.4's "appropriate 4xx"
      allows. 431 tells the client which limit it passed.

93. **h2's `write_request` takes an indexing choice for each field line.** Ruled by the owner on
    2026-09-26, for a caller that sends a DNS query in `:path` (RFC 8484) and must keep it out of
    every table on the path (RFC 7541 §7.1.3).
    - `Request.indexing` holds a choice for each pseudo-header field, and `write_request` takes a
      list beside `fields`, one choice a line, or empty for none. h3's `write_request` takes QPACK's
      choices the same way (entry 76).
    - A choice is `without_indexing` or `never_indexed` (RFC 7541 §6.2.2, §6.2.3), and the default
      is `without_indexing`, which every request used before. A request inserts nothing. RFC 7541
      §6.2.1 inserts a line into the dynamic table as the block that carries it is decoded, so a
      request refused after its block was encoded would leave the peer's table short of an entry
      the encoder holds, where `write_request` promises that a refused request changes nothing.
      QPACK's inserts travel on the encoder stream instead, which is why h3 offers `may_insert`.

    The alternatives refused:
    - A choice for `:path` alone. It serves the DNS query, but not `authorization` or `cookie`.
    - Offering `incremental` too. The encoder would have to take back a refused block's inserts,
      which means copying the dynamic table before every request.

94. **colibri links chapulin as its TLS stack and its packet protection.** Ruled by the owner on
    2026-09-26. It amends non-negotiable 2 and entries 8, 9, 10 and 48.

    Every user of colibri had to write the code between a TLS stack and colibri's two vtables, and
    that code is where the choices that decide a connection's security are made: whether the
    server name is checked, which trust anchors and pins apply and against which clock, which ALPN
    is offered, where randomness comes from, and how QUIC's secrets pass from TLS to packet
    protection. One adapter, kept here and run by colibri's interop checks, replaces a copy in
    every consumer. cocuyo asked for it, after keeping its own QUIC adapter and starting a second.
    - chapulin is pinned by commit and hash in `build.zig.zon`, and colibri's build compiles its C
      with the options each configuration needs, so no consumer runs `make` and no object can be
      built against other headers. chapulin has no Zig build yet, and is asked for one. colibri
      does not copy chapulin's Makefile.
    - The adapters in `src/testing/` move into the library, and a user no longer fills
      `tls.Provider` or `crypto.Suite`. Both vtables stay inside colibri, filled by chapulin and by
      the simulator's null provider and null suite. Those null implementations are what let one
      seed replay byte for byte (non-negotiable 5), so they stay test-only and are never packaged.
    - colibri still holds no private key, traffic secret or packet protection key: chapulin holds
      them (entry 48). colibri still reads no clock: the wall-clock time that certificate checks
      need is a value the caller passes (non-negotiable 3). colibri still does no I/O
      (non-negotiable 1).
    - Randomness is the consumer's. chapulin is built with `RAND=extern`, and the program that
      links colibri defines `ch_rand_bytes` and `ch_assert_fail`, each of which an image may define
      once. `ch_rand_bytes` must be safe to call from several threads at once (chapulin's
      `docs/porting.md`). The library's configurations leave `KEYLOG` off, so those two are all a
      program defines; colibri's executables in `src/testing/` define them for themselves, and
      `ch_keylog` too for the test builds that turn `KEYLOG` on.

    The alternatives refused:
    - An optional module beside the library. It kept the library free of a TLS stack and left a
      user free to bring another, but a user who brought none still had nothing that worked.
    - A separate package depending on both colibri and chapulin. It kept colibri's rules as they
      were, and made the supported way to use colibri live outside it.
    - colibri defining `ch_rand_bytes` over a random-bytes callback. A consumer that defines its
      own, as cocuyo does, could then not link colibri at all.
    - Each consumer's own chapulin checkout, as `src/testing/` used until now. Each consumer would
      have to pick chapulin's build options correctly, and `build.h` could only refuse a wrong one.

    Cost: every build of colibri compiles chapulin, no other TLS stack can be used, and the
    library gains its first dependency and its first C. Design §8 step 16 carries the work.

    **Amended by the owner on 2026-09-26.** The part of the adapter that is plain TLS moves into
    chapulin, as a Zig API over its C calls: step 16c's values (`Client`, `Server`, `Trust`,
    `Ticket`), the session storage and its size, driving a handshake, and QUIC's key handover. Any
    Zig program that uses chapulin needs it, HTTP or not, and cocuyo kept an adapter of its own for
    want of one. colibri keeps the glue: its `tls` module fills `tls_provider.Provider` and
    `crypto.Suite` from chapulin's sessions and makes colibri's own checks, such as the ALPN a
    connection attaches with. The refused alternatives were the whole adapter in colibri, as ruled
    above, which leaves every other Zig user of chapulin to write it again, and building it in
    colibri first to move it later, which writes it twice.

    **Amended by the owner on 2026-09-27.** A program passes each session the source its randomness
    comes from, and every draw chapulin makes for that session comes from that source. cocuyo asked
    for it, because its tests replay a connection only when every draw comes from a stream it
    seeds.
    - chapulin gives each session a randomness callback with a context, as `ch_keylog` has a
      context. The `start` of each `tls` session takes the source and passes it through.
    - A session with no source does not start, and nothing falls back to another source.
    - colibri's objects then call no `ch_rand_bytes`. A program defines that hook only for a
      chapulin object of its own, and still defines `ch_assert_fail`. It landed with chapulin
      `e4b9c6f`'s `RAND=session`, and non-negotiable 2 changed with it.
    - `start` takes the source as a `tls.Random`, which `src/tls/values.zig` names. That file is
      the one under `src/` the determinism lint lets name `std.Random`, as the owner ruled the same
      day: colibri takes the source from its caller, and makes and draws from no generator.

    The alternatives refused:
    - colibri keeping the source in the session and making it the thread's current source around
      each call into chapulin, with a draw function the program's `ch_rand_bytes` calls. It needs no
      chapulin change, but every call into chapulin sets and restores a thread-local, and a call
      left unwrapped stops the program when it draws.
    - The program's `ch_rand_bytes` as the only source. A caller that needs its draws per
      connection wraps the provider and must know which calls draw, which breaks with no error when
      chapulin moves a draw.

    Cost: every caller passes a source to `start`, and chapulin changes how its objects draw.

95. **h11 counts body octets the caller sends from its own buffer.** Ruled by the owner on
    2026-09-26, for a caller that already holds a large body in a buffer of its own, such as an
    object store client sending segments of several MiB.
    - `Connection.count_body(len)` counts `len` octets against the body the head declared, as
      `write_body` does, and writes nothing. The caller sends those octets itself, next, before
      any other octet of the connection: in cleartext from its buffer, and over TLS through
      `connection_tls.encrypt` from the same buffer.
    - It serves a body with a Content-Length, a body the close ends, and a tunnel. A chunked body
      refuses it with `BodyChunked`, because each chunk needs a size line before its data (RFC
      9112 §7.1), and colibri writes that line.
    - `write_body` and `count_body` share one count, so a caller may use both on one body.

    The alternatives refused:
    - `write_body` alone, which copies every octet of the body into the output buffer. The caller
      already holds the octets, and the copy reads and writes each of them once more.
    - A call that returns the octets to send as a list of slices, the caller's among them. A body
      with a Content-Length has no framing, so the list would hold one slice, the caller's own.
    - A chunked form that writes a chunk's size line, counts the caller's octets, and writes the
      CRLF after them. No caller needs it yet.

    Cost: colibri cannot check that the octets counted are the octets sent, or that they go out
    next. A caller that counts one thing and sends another frames the message wrongly, which is
    how request smuggling starts.

96. **`examples/` holds programs a dependent writes, run on Rotor's loop over an in-memory link.**
    Ruled by the owner on 2026-09-26, who asked for examples like chapulin's and for them to use
    Rotor and memory. It amends decision 58, which gave Rotor to `src/testing/` alone.
    - Each example is a program that imports the library modules by the names a dependent uses
      (decision 86). `zig build examples` builds and runs every one, and `tools/ci.sh` runs that
      step, so an example that stops working fails CI.
    - A client and a server run in one process, each on its own Rotor loop. What one side sends is
      copied into the other side's queue in memory, and a message posted between the loops says
      how many octets arrived (`examples/link.zig`). The instant colibri takes is the one the
      side's loop read at its last tick.
    - The examples open no socket, so `src/testing/` stays the one directory that does. Rotor is
      still a lazy package that only colibri's own build requests, and the library imports it
      nowhere.
    - h11 and h2 come first, in cleartext. Examples over TLS, QUIC and h3 need chapulin, which
      design §8 step 16 links into the library.

    The alternatives refused:
    - Programs over real sockets that CI builds and never runs, as chapulin's are. They show a
      whole program, but a broken one passes CI, and they would make a second directory open
      sockets.
    - Octets passed between the two sides with no loop at all. It is shorter, but it shows no
      program's shape: where the loop, the time and colibri's calls meet.

97. **The library's TLS module is `tls`, and the vtable it fills is `tls_provider`.** Ruled by the
    owner on 2026-09-26, for design §8 step 16b.
    - The module a program imports for TLS and for QUIC's handshake and packet protection is
      `tls`, the name Go's `crypto/tls`, Node's `tls` and Zig's `std.crypto.tls` give theirs. It
      fills colibri's vtables from chapulin's sessions; step 16c's values are chapulin's, as
      entry 94's amendment rules, and `tls` passes them through.
    - The provider vtable the module was named for until now becomes `tls_provider`. h2, h11,
      quic and sim import it, and a program imports it only to name the type. The HTTP modules do
      not import `tls`: a program makes a session there and hands its provider to the connection,
      so a cleartext program never links chapulin, and sim's null providers fill the same vtable.
    - The TCP object carries `SUITE=aesgcm`, so a server that offers only AES-GCM connects; RFC
      9846 §9.1 makes TLS_AES_128_GCM_SHA256 mandatory to implement. The build picks `AES=hw`,
      with the builder's statement `CH_NATIVE_AES`, on a target whose features include the AES
      instructions, and `AES=soft` on any other.
    - The TCP object sets chapulin's `TX_RECORD` to 16384, TLS's largest record plaintext (RFC
      9846 §5.1), once chapulin offers the option, so a large body takes a record per 16 KiB.

    The alternatives refused:
    - chapulin's adapter inside the vtable's module. Every program that imports h2, h11 or quic
      would link chapulin, a cleartext one included, and would have to define its two hooks.
    - `ssl`, the Python, Erlang and Java name, for a module that speaks TLS 1.3 alone.
    - `AES=hw` everywhere, which refuses to build for a target without the AES instructions.
    - ChaCha20-Poly1305 alone on TCP, which a server offering only AES-GCM refuses.

    **Amended by the owner on 2026-09-26.** chapulin's Zig API gives each object types of its own:
    two instances of one dependency make two modules, and a type in one is not a type in the
    other. So step 16c's values are colibri's, and `tls` no longer passes chapulin's through.
    - `tls` defines the values once and converts them, once per object, into that object's
      chapulin values. They go into a configuration the caller owns, which every session of the
      object borrows.
    - The lists are copied into arrays at chapulin's limits, `CH_WEBPKI_ANCHOR_MAX` and
      `CH_ALPN_MAX`. That is one copy per object at setup and none per connection. The same
      values then configure h11, h2 and h3, as 16c rules.
    - A server identity types its keys. An ECDSA P-256 private key is `*const [32]u8` and its
      public key `*const [64]u8`, so a key of the wrong size fails to compile. An RSA-PSS private
      key stays `*const anyopaque`, because chapulin's `ch_rsa_priv` is a type of each object.

    The alternative refused: `tls` re-exporting each object's chapulin module, so a program writes
    one literal per object in chapulin's types. It copies nothing, but a program that speaks h2 and
    h3 configures both, with C element types such as `ch_trust_anchor`.

    **Confirmed by the owner on 2026-09-27**, for a constraint found in design §8 step 16b: an object
    built for a target without the AES instructions carries `SUITE=chacha`, and holds
    TLS_CHACHA20_POLY1305_SHA256 alone.
    - chapulin refuses `SUITE=aesgcm` with `AES=soft`, whose S-box is indexed with the key (its
      `ct.h`, INV-26).
    - ChaCha20-Poly1305 is also the faster AEAD in software. chapulin's `bench/aead.sh` timed a
      1200-octet seal on an AMD EPYC 7763 under Linux, built by gcc 13.3 at `-O2`: 6.04 ns per
      octet for ChaCha20-Poly1305, and 135 for AES-128-GCM over `AES=soft`. chapulin's
      `docs/quic.md` holds the run, under "What the AES axis costs in time, measured".

    The alternative refused: AES-GCM in software on those targets. chapulin lets no software AES
    hold a traffic key, and its table cipher sealed 17 to 23 times slower than ChaCha20-Poly1305
    in that run.

    Cost: on such a target, colibri connects to no server that offers AES-GCM alone.

98. **h11 decodes a coded body into a buffer the caller passes to `receive`.** Ruled by the owner
    on 2026-09-26, for design §8 step 15c. It settles how decision 91's decoded octets reach the
    application.
    - `receive(input, decoded)` takes the buffer, and stdx's decoder writes straight into it. Each
      `data` event of a body carrying `gzip` or `deflate` is a slice of it, valid until the caller
      passes it again. A caller that places no decoder pool passes it empty.
    - The pool holds decoders alone: `h11.coding.Pool(count)`, 43,216 octets a decoder, which the
      caller places and gives each connection in `Options.decoders`. `DefaultPool` holds
      `decoders_default`, 16, in 691,472 octets. The caller prepares it with
      `storage().reset(features)` and chooses the features, `Features.detect()` or
      `Features.target()`, so colibri never asks the CPU itself.
    - The reason is copies. stdx writes each decoded octet once, and at the end of each call copies
      the call's last 32,768 octets into its window. Into the caller's own buffer that is about one
      write per octet, with no copy out, and a larger buffer means fewer calls.

    The alternatives refused:
    - A 16 KiB output block in each pool slot, with `receive` unchanged. Every caller's call stays
      as it was, but each decoded octet costs two or three writes: the decode, the window's copy of
      the whole block, and the caller's copy out. Each slot also grows by the block.
    - A decoded buffer in each connection. Idle connections would hold buffers they rarely use,
      which is what decision 91's pool exists to avoid.

    Cost: every h11 caller passes a second argument, an empty slice when it places no pool.

99. **colibri's runs of the QUIC Interop Runner count the client's connection attempts as
    handshakes.** Ruled by the owner on 2026-09-27, for
    [#72](https://github.com/c4milo/colibri/issues/72).

    The runner counts a handshake for each distinct Source Connection ID of the server's Initial
    packets. quic-go's server drops a connection it has heard nothing from for 5 seconds, and it
    starts a second one when the client's next Initial arrives. So `handshakeloss` counted 51
    handshakes where colibri's client made 50 connections. Design §8 step 9e's runner notes hold
    the evidence.
    - `tools/quic_interop/count_handshakes.patch` has the runner's `_count_handshakes` count the
      distinct Destination Connection IDs of the client's Initial packets that have packet number
      0: one for each connection attempt (RFC 9000 §12.3, §7.2). `tools/interop.sh` applies it to
      the pinned clone.
    - The same change is
      [quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509), for
      [quic-interop-runner#508](https://github.com/quic-interop/quic-interop-runner/issues/508).
      Once it is merged, the pin moves to the merge and the patch goes.

    The alternatives refused:
    - Leave the count as it is. `handshakeloss` with colibri as the client against quic-go then
      fails about one run in three, on handshakes that all completed.
    - Lower `rtt_initial_ns` to 100 ms. A model of the case put the failures near 0.1% of runs.
      But RFC 9002 §6.2.2 recommends 333 ms, and the change would reach every user of the library
      for one test's sake.
    - Count the client's Source Connection IDs, or the server's IDs that the client later used.
      quic-go's client uses zero-length connection IDs and switches to a NEW_CONNECTION_ID one
      during the handshake, so both counts are wrong for it.

    Cost: until the upstream change is merged, colibri's runs check a count the public runner does
    not.

    Amended by the owner on 2026-09-27, the same day, after the runner job's first run against
    ngtcp2, neqo and quinn (run 36359234791). The count above found no handshake with ngtcp2's or
    neqo's client, so every case with either failed although each transfer completed. Their first
    Initial packets carried packet numbers 671978432 and 31, which RFC 9000 §21.4 allows: an
    endpoint may skip packet numbers. The patch now counts the Destination Connection IDs the
    client chose for its Initial packets: every one it used, less the Source Connection IDs of the
    server's Initial and Retry packets, which the client uses as its Destination Connection ID
    from then on (RFC 9000 §7.2).
    - On that run's captures, the new count gives the runner's expected number in all 36 pairings
      of `handshake`, `retry`, `resumption` and `handshakeloss` with five clients and four servers.
    - On the twelve `handshakeloss` captures of [#72](https://github.com/c4milo/colibri/issues/72),
      it gives 50 in each. The runner's own count gives 51 in the two where quic-go's server
      dropped a connection.
    - Mutations, both CAUGHT: without the subtraction, `handshake` counts 2 and `retry` 3; without
      the Retry packets, `retry` counts 2.
    - `tools/interop.sh` resets the clone's `testcase.py` to the pinned commit before it applies
      the patch, so a clone that carries the earlier patch takes this one.
    - [quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509)
      carries the same count, and the patch is its commit.

    Amended again by the owner on 2026-09-27. The count above scored 2 for one quic-go handshake
    against quic-go's own server, a pairing colibri's runs do not include. quic-go's server sends
    NEW_CONNECTION_ID in the datagram of its Handshake flight, and quic-go's client sends its last
    Initial packet, an ACK, to one of those IDs. The patch now counts only the Destination
    Connection IDs of client Initial packets that carry CRYPTO data at offset 0, the start of the
    ClientHello, less the Source Connection IDs of the server's Initial and Retry packets.
    - quic-go against itself: `handshake` and `retry` count 1, where the count above gave 2;
      `resumption` and `zerortt` count 2, where it gave 4; `handshakeloss` counts 50, where it
      gave 66.
    - All 151 captures of run 36359234791, and 16 more from this machine, give each test's
      expected number. That includes a colibri `handshakeloss` run the runner's own count
      scores 52.
    - Mutations, all CAUGHT: without the offset test, quic-go's `handshake` counts 2; without the
      subtraction, every `retry` counts 2 or 3; without the Retry packets, every `retry` counts 2.
    - [quic-interop-runner#509](https://github.com/quic-interop/quic-interop-runner/pull/509)
      carries this count, and the patch is its commit.

100. **A version-choosing HTTP client and a server of the same shape, above h11, h2 and h3.**
     Ruled by the owner on 2026-09-27, for
     [#70](https://github.com/c4milo/colibri/issues/70), which cocuyo asked for.
     - Two library modules, `client` and `server`, for HTTP in general and not for DoH: cocuyo
       keeps the DNS half. They are the one place that imports `h11`, `h2` and `h3` together,
       which amends design §3's rule that nothing imports them.
     - They drive colibri's `tls` themselves over TCP and QUIC. They import `tls`, take its
       configurations and a `tls.Random`, run each handshake, and hand out a resumption ticket
       for each transport. A program that uses them links chapulin. One that wants no TLS uses
       the protocol modules directly.
     - The client chooses the version from values the caller passes: the versions to offer,
       what DNS knows (the addresses, and an HTTPS record's `alpn` and `port`, RFC 9460), and a
       fallback delay. It tries h3 first when h3 is offered, and opens TCP when QUIC fails or the
       delay passes, where ALPN chooses h2 or h11. It learns h3 from Alt-Svc (RFC 7838). It never
       resolves a name, and it tells the caller which transport to open, a UDP flow or a TCP
       connection.
     - The server serves h11, h2 and h3 behind the same calls. The transport and ALPN choose each
       connection's version, and whether it advertises h3 with Alt-Svc is a value.
     - Both keep colibri's rules. Octets go in and out tagged by transport, time is a value, and
       the caller owns the memory, with bounds known at build time: concurrent requests, the
       longest body, authority and path. Events are polled, a request can be cancelled by its
       id, and the caller names the response fields it reads.

     The alternatives refused:
     - One module for both roles. A server-only program would carry the client's code in its
       graph.
     - No library module, so each consumer races two HTTP stacks itself, as cocuyo does today.
     - The caller making each TLS session through a callback, so the modules never import `tls`.
       A cleartext program would link no chapulin, but every caller would write the wiring the
       modules exist to hold.
     - One transport at a time, the caller deciding when to fall back. Every caller would write
       the racing cocuyo wants gone.

     Cost: design §3 gains two modules and the edges into `h11`, `h2`, `h3`, `quic` and `tls`, and
     design §8 step 17 builds them.

101. **The client and server code content with stdx's encoders and decoders.** Ruled by the owner
     on 2026-09-27, for [#70](https://github.com/c4milo/colibri/issues/70). It adds content codings
     (RFC 9110 §8.4) to decision 100's modules.
     - The server's configuration names the codings it may apply, in its order of preference, and
       each response says whether its body may be coded. Only the caller knows whether a body
       mixes a secret with octets a peer chose, and a coded length leaks such a secret (RFC 7932
       §12).
     - The server applies the coding the request's `Accept-Encoding` accepts with the highest
       nonzero qvalue, and the configuration's order breaks a tie (RFC 9110 §12.5.3). It codes
       nothing for a request with no `Accept-Encoding`, for an HTTP/1.0 request, for a 206, or
       when its encoder pool is empty. When no coding is acceptable, `identity` included, it sends
       the body uncoded and disregards the field, as RFC 9110 §12.4.1 permits.
     - A coded response gains `Content-Encoding` (RFC 9110 §8.4) and `Vary: accept-encoding`
       (§12.5.5). It loses the caller's `Content-Length`, which would have to count the coded
       octets (§8.6), and a strong `ETag` becomes weak (§8.8.1). A response to HEAD gets the same
       fields and no body (§9.3.2), and a 304 gets the `Vary` and the weak `ETag` alone (§15.4.5).
     - The client offers its configuration's codings in `Accept-Encoding`, unless the caller's
       request carries that field. It takes a decoder from the caller's pool when it sends the
       request, and offers nothing when the pool is empty. It decodes a response whose
       `Content-Encoding` names one coding it offered, reads `x-gzip` as `gzip` (RFC 9110
       §8.4.1.3), and reports the coding it removed. Any other `Content-Encoding` reaches the
       caller as it arrived, with the field. The decoded body must fit the caller's body memory,
       and a corrupt one fails the response. `deflate` is the zlib format alone, as decision 91
       rules for h11's transfer codings.
     - Encoders and decoders live in pools the caller owns, sized by named limits, and a message
       holds one only while it is coded. The caller chooses each encoder's level at build time,
       because stdx's encoder is one type per level.
     - `gzip` and `deflate` come first, because the pinned stdx has both directions. `zstd`
       decoding follows a stdx bump and keeps RFC 9659 §3's window of 8 MB. `zstd` encoding and
       `br` follow when stdx writes them.
     - Request content passes through both modules unchanged. colibri's package exports stdx's
       `codec`, `gzip`, `zlib`, `zstd` and `brotli`, so a caller codes request content, or
       anything else, with the stdx the library pins.

     The alternatives refused:
     - Export stdx's modules alone, and let each caller code bodies. Every caller would write the
       rules above, which decision 100's modules exist to hold.
     - Content codings in h11, h2 and h3. The rules do not depend on the version, so there would
       be three copies, and a program that uses one protocol module would carry coding it may not
       want.
     - An encoder in each connection. An h2 or h3 connection codes several responses at once, and
       an idle connection would hold an encoder it rarely uses. Decision 91's pool avoids the same
       cost for decoders.
     - Coding a response to a request with no `Accept-Encoding`, which RFC 9110 §12.5.3 permits.
       A client that decodes nothing, such as curl without `--compressed`, would receive octets
       it cannot read.
     - Coding every response unless the caller opts out. The caller would have to find every body
       that mixes a secret with a peer's octets, and each one it missed would leak.

     Cost: a coded response has no `Content-Length`, so h11 sends it chunked, and a strong `ETag`
     on it becomes weak. The server's encoder pool is memory the caller places. Design §3 gains
     edges from `client` and `server` into stdx, and design §8 step 17 gains a part.

102. **colibri writes qlog when its caller asks, from the pinned drafts.** Ruled by the owner on
     2026-09-27. The QUIC Interop Runner asks each endpoint for a qlog (entry 28), and colibri's
     had none (design §8 step 9e).
     - `src/qlog/` is a library module that imports `core` alone. `quic` and `h3` import it and
       fill its event records from their own state. It imports no protocol module, so `quic`
       still imports no HTTP module (decision 5), and moving it out later changes only the build.
     - It is written from three Internet-Drafts, pinned in `docs/rfcs/qlog/` with their SHA-256:
       draft-ietf-quic-qlog-main-schema-14, draft-ietf-quic-qlog-quic-events-13 and
       draft-ietf-quic-qlog-h3-events-13. Non-negotiable 10 names RFCs; these three are the
       exception until the RFCs publish. Each events draft's §2.1 has an implementation name its
       event schema with the draft number, so colibri writes
       `urn:ietf:params:qlog:events:quic-13` and `urn:ietf:params:qlog:events:http3-13`.
     - A connection logs only when its caller gives it a log in its options, which is null by
       default. With none, each place that would log costs one branch and writes nothing. This is
       the one exception to CLAUDE.md's rule that nothing logs on the per-frame path, and it is
       off unless the caller turns it on.
     - colibri still owns no I/O. A log is a buffer the caller owns, and colibri appends JSON Text
       Sequences records to it (RFC 7464). The caller writes the records wherever it wants, for
       example to a file under `QLOGDIR` (main schema §12.1). An event that does not fit is
       dropped whole and counted, and never fails the connection.
     - A log never changes what a connection sends. The same seed gives the same datagrams with
       and without one.
     - colibri writes a peer's octets, such as a close reason or an ALPN value, as hexstrings and
       never as text, so every string it writes is its own ASCII and needs no UTF-8 check.

     The alternatives offered:
     - Its own repository, recommended first and withdrawn: decision 3's reason to move code out
       is another project that wants it without colibri, and the only producer of QUIC and HTTP/3
       events among the owner's projects is colibri. The two would change together across two
       pins, and a package cannot import colibri's types.
     - stdx, whose codecs carry no protocol knowledge. Decision 90 kept protocol limits out of it.
     - The test endpoints alone, which would leave a caller of the library with no qlog.
     - A build option, which costs nothing when off but needs a rebuild to turn on, and a
       provider the connection calls for each event. The owner chose a runtime setting.
     - Waiting for the RFCs.

     Cost: a module and two edges in design §3, `quic` → `qlog` and `h3` → `qlog`, and a branch
     at each place a connection logs.

     Amended by the owner on 2026-09-27: a JSON encoder and decoder belong in stdx, beside its
     other codecs, which carry no protocol knowledge (decision 90). `src/qlog/json.zig` stays
     until stdx has them and is deleted then, and `qlog` then imports stdx's `json` in place of
     `core`. The simulator's check that each record parses waits for stdx's decoder, rather than a
     decoder written in colibri.

     Amended by the owner on 2026-09-28, for design §8 step 18d:
     - Each h3 call that writes or reads a frame takes the instant, `now_ns`, as `quic`'s calls do
       (non-negotiable 3), and `write_data_header` becomes a method of the connection that names
       its stream. Refused: logging each h3 event at the instant of `quic`'s last call, which
       would give a frame the caller writes long after that call an earlier time than it had.
     - A HEADERS frame's field name is logged as text when every octet of it is printable ASCII,
       0x20 to 0x7e, and as `name_bytes` otherwise; its value likewise, as `value_bytes`. That is
       h3-events §4.2.2's rule, and text of ASCII alone needs no UTF-8 check, the reason this entry
       gave for hexstrings. Refused: hexstrings for every line, which a viewer shows as hex, and an
       empty list of field lines.

     Amended by the owner on 2026-09-28: qvis, the qlog viewer most people open, reads qlog 0.3
     alone, which draft-ietf-quic-qlog-main-schema-02 and its two events drafts define, so
     `tools/qlog_to_qvis.py` rewrites a colibri log into that form. colibri itself still writes the
     drafts this entry pins. Refused: writing qlog 0.3 from colibri, which would trade the pinned
     drafts for a viewer's, and leaving the logs unreadable in qvis until it catches up.

     Amended by the owner on 2026-09-28: when stdx's JSON module takes the CPU features its vector
     paths may use (stdx's decision 30), `qlog.Log.init` takes them from its caller, who passes
     `Features.detect()` or `Features.target()`, as decision 98 has h11's decoder pool do, so
     colibri never asks the CPU itself. `qlog` then imports stdx's `codec` too. The records are the
     same octets for every value (stdx's invariant 5). Refused: `qlog` calling `Features.target()`
     itself, which keeps `Log.init` as it is but leaves the caller no choice, and gives a build for
     a baseline CPU the scalar paths.

103. **The server over QUIC: one endpoint owns the connections, and the caller keeps each
     response body until the server reports it done.** Ruled by the owner on 2026-09-27, for
     design §8 step 17b and [#70](https://github.com/c4milo/colibri/issues/70).
     - A `server.Endpoint` holds up to a build-time number of QUIC connections. It routes each
       datagram by its first packet's Destination Connection ID (RFC 9000 §5.2), starts a
       connection from a client's Initial (§7.2), and answers Version Negotiation (§6.1) and
       Retry (§8.1.2) itself. It names each request by its connection and its stream. The caller
       passes each datagram with the address it came from, and sends each datagram the endpoint
       writes to the address the endpoint names.
     - A response body stays the caller's until the server reports its request done: over h3, once
       the peer has acknowledged every octet (RFC 9000 §3.1) or the stream was reset. `write_body`
       reads the caller's octets without copying them, and the server keeps only each stream's
       frame headers, as decision 79 has h3's caller do. The same rule holds for h11 and h2,
       which report a request done after the call that writes its last octet, so a caller writes
       one path for every version.

     The alternatives refused:
     - The server copies each body into send buffers the caller places, and frees them as the
       peer acknowledges. It adds a copy per octet, and the buffers cap the octets in flight,
       which decision 57 refused for `quic`.
     - One object per QUIC connection, with helpers that read a datagram's connection ID. Every
       caller would keep the routing table, the IDs NEW_CONNECTION_ID adds included (RFC 9000
       §5.1.1).

     Cost: a caller keeps each response body until its request is done, and the `done` event joins
     the server's events for every version.

104. **An h2 connection model, and a trace check of colibri's h2 against it.** Ruled by the owner
     on 2026-09-27, for [#75](https://github.com/c4milo/colibri/issues/75), after c32cabe found that
     h2's `write_data` let a server send DATA before its response's head (RFC 9113 §8.1). It comes
     before design §8 step 17b.
     - `spec/tla/h2_connection` models a colibri client and server over one connection. It holds
       each stream's state at both endpoints (RFC 9113 §5.1), each message's order in each
       direction (§8.1), RST_STREAM crossing frames in flight (§6.4) and GOAWAY (§6.8). Where §5.1
       leaves a choice, the model takes colibri's. Flow control stays `spec/tla/h2_flow_control`'s.
     - Each rule colibri keeps is a constant, and a configuration that turns one off must find a
       violation. DATA before the final head is one of them.
     - A simulator run acts out a seed's plan with colibri's h2 client and server, as decision 87
       has for h3. The plan draws write calls the connection must refuse as well as ones it takes,
       so a refusal colibri misses shows as a state the model cannot reach. The run logs the
       model's variables after each step, and TLC checks each seed's log is a behavior of the
       model. `tools/h2_trace.sh` runs it, and `tools/ci.sh` runs it where Java is installed.

     The alternatives refused:
     - Trace only the calls the model allows. A trace shows what colibri did, so a refusal it
       misses would never be drawn, and c32cabe's bug would have passed.
     - Model h11's order and pipelining (RFC 9112 §9.3) in the same step. It would add assurance,
       and hold back design §8 step 17b longest.
     - Model h2 after step 17b. Step 17a's server rests on h2, and 17b touches h3 and QUIC, not h2.

     Cost: step 17b waits for the h2 check.

105. **A model of the client's exchanges, and a trace check of the client against it.** Ruled by
     the owner on 2026-09-28, for [#70](https://github.com/c4milo/colibri/issues/70), after design
     §8 step 17d's tests found two faults in the client over QUIC. A shut-down connection never
     closed, because it owed a GOAWAY it never sent. A failed connection left each stream holding
     its exchange's octets, so no `finished` event came. No model covered the client.
     - `spec/tla/client_exchanges` models the exchanges the client carries to one origin over QUIC
       and TCP. Each exchange runs from `request` to its one `finished` event, or to its cancel.
       The model holds the connection that carries it, whether a QUIC stream may still read its
       octets (RFC 9000 §3.1), and whether a server processed it. Each connection runs from its
       handshake to its `closed` event. The choice between them is design §8 step 17d's: QUIC
       first, TCP when QUIC fails or the fallback delay passes, and an exchange the server
       refused unprocessed moves to another connection.
     - Its safety property says each exchange is reported once, and never while a stream holds
       its octets. An exchange is `refused` only when no server processed it, and no request is
       processed by two servers. A connection reports `closed` only once it holds no exchange.
       Its liveness property says every exchange made ends, and every connection opened reports
       its close once the caller shuts the client down.
     - Each rule colibri keeps is a constant, and a configuration that turns one off must find a
       violation. The two faults are two of the rules.
     - Step 17d's simulator run, which loses, delays and refuses QUIC, logs the model's variables
       after each step, and TLC checks each seed's log is a behavior of the model, as decisions 87
       and 104 have for h3 and h2. A log that stops early is still a behavior, so the run also
       requires every seed to end with each exchange finished and each connection closed.
       `tools/client_trace.sh` runs it, and `tools/ci.sh` runs it where Java is installed.

     The alternatives refused:
     - Model one connection's exchanges and leave out the choice. It would cover the two faults.
       It would leave the moves between connections to tests, and a move is where a request can
       be processed twice.
     - Tests alone. A test checks the sequences its author wrote. TLC checks every sequence the
       model allows within its bounds, and the trace check holds colibri to the model.

     Cost: step 17d gains a model and a trace run, and step 17b waits longer.

106. **colibri's runs of the QUIC Interop Runner pass a rebinding test's new path once the client
     answers any PATH_CHALLENGE sent on it.** Ruled by the owner on 2026-09-28, for
     [#78](https://github.com/c4milo/colibri/issues/78).

     The runner's `rebind-port`, `rebind-addr` and `connectionmigration` cases take the
     PATH_CHALLENGE in the server's first packet on each new path, and fail unless the client
     answers that one. When that packet is lost, the server sends a new PATH_CHALLENGE with new
     data (RFC 9000 §13.3), and the client answers it, but the case still fails. The weekly run
     of 2026-09-28 failed `rebind-port` with colibri on both sides this way: the simulator's
     25-packet queue dropped that packet. Design §8 step 9e's runner notes hold the evidence.
     - `tools/quic_interop/rebind_challenges.patch` has the check record every PATH_CHALLENGE the
       server sends on each new path, and pass the path once the client answers any of them. The
       rule that the first packet on a new path carries a PATH_CHALLENGE stays.
       `tools/interop.sh` applies it to the pinned clone.
     - The same change is
       [quic-interop-runner#511](https://github.com/quic-interop/quic-interop-runner/pull/511), for
       [quic-interop-runner#510](https://github.com/quic-interop/quic-interop-runner/issues/510).
       Once it is merged, the pin moves to the merge and the patch goes.

     The alternatives refused:
     - Leave the check as it is, and keep #78 open as a known flake. The rebinding cases then fail
       now and then on paths the client did validate: 1 of the 18 colibri ran in on 2026-09-28,
       and 3 of 12 on 2026-09-27.
     - Send the change upstream without the patch. colibri's runs keep failing until it is merged.

     Cost: until the upstream change is merged, colibri's runs check a rule the public runner does
     not.
