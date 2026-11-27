# Decision 147: A server's identities are one shape for every signature algorithm, and ML-DSA-87 is one

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-02, for https://github.com/c4milo/colibri/issues/115 (design §8 step
33c). chapulin `2b0c5c9e` (its decision 180) gives every host server object a third identity slot,
`mldsa87`, and signs with it first whenever the client offers it and the slot is set, then with
ECDSA P-256, then with RSA-PSS. colibri had one type for each of chapulin's slots. The owner asked
why the keys did not share one shape, as `cipher_suites` names suites by their code points.

The rulings:
1. One shape. `tls.SignatureScheme` names a key's algorithm by its SignatureScheme code
   point (RFC 9846 §4.3.3). `tls.Key` holds the scheme and the key pair in room for the
   largest key, and `wipe` zeroes its secret. `tls.Identity` is a chain and the key it
   names. `tls.Server.identities` holds at most one identity for each scheme, and chapulin
   chooses among them. `tls.pem.key` reads a PEM key into a `tls.Key` and takes its scheme
   from the key's PKCS #8 algorithm.
2. `EcdsaP256Identity`, `RsaPssIdentity`, `P256Key`, `pem.p256_key` and the two fields
   `Server.ecdsa_p256` and `Server.rsa_pss` go. The next release breaks each program that
   names them (decision 115).
3. RSA-PSS comes back as a scheme when chapulin reads an RSA key from PEM. The owner asked
   chapulin for that call on 2026-11-02. Until then a server signs with ECDSA P-256 and
   ML-DSA-87 alone. No program, check or example used `rsa_pss`.
4. The ML-DSA-87 code point, 0x0906, is draft-ietf-tls-mldsa-05 §3's, an Internet-Draft
   submitted to the IESG. colibri pins it in `docs/rfcs/mldsa/` until an RFC publishes it, as
   decisions 102 and 134 pin theirs. RFC 9881 gives the key's forms and its sizes: a public
   key of 2,592 bytes (§4) and an expanded private key of 4,896 (§6).

Alternatives that lost:
- One type for each algorithm, `MlDsa87Identity` and `MlDsa87Key` beside the P-256 names.
  Nothing breaks, but each new algorithm adds two names and a field.
- RSA-PSS kept without PEM, through chapulin's opaque key, which no file fills and no test
  checks.
- Step 33c waiting for the RFC. The key exchange of step 33a ships without it.

Amended on 2026-11-03 (design §8 step 33d). chapulin `965668d2` (its decision 184) reads an
RSA key from PEM with `ch_rsa_key_from_pem`, so ruling 3 is met:
- `tls.SignatureScheme` gains `rsa_pss_rsae_sha256`, 0x0804 (RFC 9846 §4.3.3).
- `tls.pem.key` reads a PKCS #8 rsaEncryption key of two primes and the exponent 65537. It
  copies chapulin's key into the room of a `tls.Key`, whose private room is aligned to a
  machine word for it. chapulin signs once at load and verifies, so a key that does not
  match the leaf is refused there.
- The owner ruled that every server object outside chapulin's `PROFILE=cnsa2` exports the
  call, device objects too.

Cost: a `tls.Key` holds 7,488 bytes and its scheme, even for a P-256 key of 96. chapulin's
server accept takes 28,752 bytes of stack on arm64, where it took 12,752, whether or not an
ML-DSA-87 identity is set.
