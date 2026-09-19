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
     key schedule private. RFC 8446 does not require that of a TLS API — its §7.1 only defines the
     key schedule — so it is colibri's choice and not a citation.
   - *QUIC mode*, for h3: `set_transport_params`/`peer_transport_params` (the
     `quic_transport_parameters` extension, codepoint 0x39, RFC 9001 §8.2), `provide_handshake`
     and `write_handshake` per encryption level carrying unframed handshake-message bytes (§4.1.3),
     `on_secret(level, direction, secret, aead_id, kdf_hash)` (§4.1.4), `hkdf_expand_label` as a
     primitive (§5.1), `negotiated_alpn`, `handshake_complete`, and `take_alert` returning an
     `AlertDescription` value rather than a record (§4.8).

   Both modes also carry `export_keying_material`, RFC 8446 §7.5's exporter, which is the one
   operation RFC 8446 gives a standard interface.

   Cost: every consumer supplies a stack, and colibri cannot ship a working client on its own.
   Gain: colibri never links a TLS stack, never holds a private key, never chooses a suite, and
   the deterministic simulator substitutes a null provider of its own. RFC 8446 specifies no API
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
   new provider API rather than exporter calls, and it is what "no record layer" costs.

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
      `crypto.Suite` (entry 9), so they belong to the caller. Taking them means widening the vtable
      with a many-sample mask call and a precomputed extract handle, which is a decision nobody has
      taken.
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

34. **The regression check has two layers, because there is no CI here.** The cheap layer runs
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
