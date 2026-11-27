# Decision 8: The TLS provider is a caller-supplied vtable with no production implementation in this tree

[All decisions](../decisions.md) · Section: [What the caller supplies](../decisions.md#what-the-caller-supplies)

Two modes, because the two protocols need different things from TLS, and RFC 9001 §3 is explicit
about why: QUIC "takes over the responsibilities of the TLS record layer".
- *Record mode*, for h2: `handshake_read`/`handshake_write`, `encrypt_record`,
  `writable_len` and `encrypt_parts` (decision 139), `decrypt_record`, `negotiated_alpn`, `handshake_complete`, `take_alert`, `send_close_notify`,
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
provider, and the gain above, a library that links no TLS stack, is given up. Since decision
174, colibri reads chapulin as `stdx.crypto` and pins no chapulin of its own.
